import angr
import re
import os
import json
import networkx as nx
import logging

from capstone.x86_const import X86_OP_MEM, X86_OP_IMM, X86_OP_REG
from angr.knowledge_plugins.functions.function import Function

from .kernel import KernelObject, Kernel

SPOT_FUNC = 0
SPOT_ADDR = 1
SPOT_TYPE = 2
SPOT_SIG  = 3

logger = logging.getLogger(__name__)

class Report:
    '''
	Analyze a kasan report
	'''

    # list in order (priority)
    TYPE_NONE = 0
    TYPE_STORE = 1
    TYPE_MEMSET = 2
    TYPE_STRCPY = 3
    TYPE_MEMCPY = 4

    # TODO: what about arithmetic instructions??
    EXIT_CONDITION_INSNS = ["cmp", "test"]

    Name2Type = {
        "strcpy": TYPE_STRCPY,
        "memcpy": TYPE_MEMCPY,
        "memset": TYPE_MEMSET,
        "csum_partial_copy_generic": TYPE_MEMCPY,
    }

    Type2Name = ["None", "STORE", "MEMSET", "STRCPY", "MEMCPY"]

    Signatures = {
        "csum_partial_copy_generic": {
            "src": "0",
            "dst": "1",
            "len": "2"
        },
    }

    def __init__(self, reports, kernel):
        self._kernel = kernel
        self._reports = reports
        self._graphs = dict()
        self._funCall = None
        # self._oobs = dict()

    def getType(self, funcName):
        if funcName in Report.Name2Type:
            return Report.Name2Type[funcName]
        return Report.TYPE_STORE

    def getTypeName(self, v):
        return Report.Type2Name[v]

    def getSignature(self, func):
        if func in Report.Signatures:
            return Report.Signatures[func]
        return None

    def analyze(self):
        tgtfunc = [each for each in Report.Name2Type]

        def get_node(nodes, addr):
            for node in nodes:
                if node.addr == addr:
                    return node
            return None

        spots = list()
        for report in self._reports:
            funCall = None
            retType = Report.TYPE_NONE
            ips = report["ip"]
            func = None
            # Extract the proper return address(ip)
            for ip in ips:
                func = self._kernel.find_symbol(ip)
                if func is None:
                    raise ValueError("UNknown function at 0x%x" % ip)
                if func.name.startswith("__asan"):
                    continue
                if func.name in ["check_memory_region", "kasan_report"]:
                    continue
                if func.name in tgtfunc:
                    retType = self.getType(func.name)
                    funCall = func.name
                    continue
                break

            if func.name not in self._graphs:
                cfg = self._kernel.getFunctionCFG(func.name)
                func_cfg = cfg.functions[func.rebased_addr]
                if func_cfg is None:
                    raise ValueError("Construct cfg failed")
                self._graphs[func.name] = func_cfg.transition_graph
            graph = self._graphs[func.name]

            target = 0
            target_node = get_node(graph.nodes, ip)
            if target_node is None:
                raise ValueError("Failed to find the node")

            preds = [
                x for x in graph.predecessors(target_node)
                if x.size is not None
            ]

            # Check if the previous instruction is a string related function call 
            for pred in preds:
                block = self._kernel.getBlock(preds[0].addr)
                inst = block.capstone.insns[-1]
                if inst.mnemonic == 'call':
                    if inst.operands[0].type != X86_OP_IMM:
                        continue
                    target_addr = inst.operands[0].value.imm & 0xffffffffffffffff
                    sym = self._kernel.find_symbol(target_addr)
                    if sym.name not in tgtfunc:
                        continue
                    funCall = sym.name
                    target = inst.address
                    fun_addr = int(inst.op_str, 16)
                    sym = self._kernel.find_symbol(fun_addr, fuzzy=False)
                    retType = self.getType(sym.name)
                    self._funCall = sym.name
                    break
                # TODO: check function call name

            if not funCall:
                # Search forward to extract the memory operation instruction

                def get_next(graph, node):
                    succs = [
                        x for x in graph.successors(node) if x.size is not None
                    ]
                    if len(succs) != 1:
                        # raise ValueError("Multiple successors")
                        return None
                    return succs[0]

                block = self._kernel.getBlock(target_node.addr)
                count = 3
                stack_registers = ['rsp', 'rbp']
                while count > 0:
                    for cs_insn in block.capstone.insns:
                        if len(cs_insn.operands) != 2:
                            continue
                        # Assume x86
                        # check if the first operand is a memory address
                        operand = cs_insn.operands[0]
                        # TODO: check the argument to see if it's a match
                        if operand.type == X86_OP_MEM:
                            if operand.value.mem.base != 0 and \
                             cs_insn.reg_name(operand.value.mem.base) in stack_registers:
                                continue
                            if operand.value.mem.index != 0 and \
                             cs_insn.reg_name(operand.value.mem.index) in stack_registers:
                                continue
                            if cs_insn.mnemonic not in ["cmp", "test"]:
                                # Check if it is just a read
                                target = cs_insn.address
                            else:
                                target = 0
                            break
                    if target:
                        retType = Report.TYPE_STORE
                        break
                    target_node = get_next(graph, target_node)
                    # If we cannot find a load, usually it's a read operation
                    if target_node is None:
                        break
                    block = self._kernel.getBlock(target_node.addr)
                    count -= 1

            if target:
                print("Func: %s, Spot: 0x%x, Type: %s" %
                        (func.name, target, self.getTypeName(retType)))
            if funCall:
                spots.append((func.name, target, retType, self.getSignature(funCall)))
            else:
                spots.append((func.name, target, retType, self.getSignature(func.name)))

        report, spot = self.pickCandidate(self._reports, spots)
        if spot is None:
            return list(), list(), list(), 0
        if spot[SPOT_TYPE] != Report.TYPE_STORE and not self.checkoverlap(
                report, spot, spots):
            return [spot], list(), list(), report["len"]
        return self.pickMulCandidates(self._reports, spots)
        # return [], [], [], Report.TYPE_NONE

    def checkoverlap(self, report, spot, spots):
        addr, size = report["addr"], report["len"]
        # if size > 8:
        # 	return False
        for i in range(len(self._reports)):
            new_addr, new_spot, new_size = self._reports[i]["addr"], spots[i][
                SPOT_ADDR], self._reports[i]["len"]
            if new_spot != spot[SPOT_ADDR]:
                if new_addr <= addr and new_addr + new_size > addr:
                    return True
                if new_addr >= addr and new_addr < addr + size:
                    return True
                if new_addr + new_size == addr:
                    return True
                if addr + size == new_addr:
                    return True
        return False

    def pickCandidate(self, reports, spots):
        if len(reports) == 0:
            return None, None

        retReport, retSpot = reports[0], spots[0]
        for i in range(1, len(reports)):
            # print(reports[i], spots[i])
            addr, typ, spot, size = reports[i]["addr"], spots[i][
                SPOT_TYPE], spots[i][SPOT_ADDR], reports[i]["len"]
            if spot == 0:  # failed to find it or it's a read operation
                continue
            if typ > retSpot[SPOT_TYPE]:
                retReport, retSpot = reports[i], spots[i]
                continue
            if typ == retSpot[SPOT_TYPE] and size > retReport["len"]:
                retReport, retSpot = reports[i], spots[i]
                continue
            if retSpot[SPOT_ADDR] == 0:
                retReport, retSpot = reports[i], spots[i]
                continue
        return retReport, retSpot

    # if the addresses are extracted from KASAN report directly,
    # it's likely we miss some OOB operations when they overwrite something
    # within a valid object.
    # def detectloop(self, addrs):
    #     size = len(addrs)
    #     if size < 2:
    #         return False

    #     addrs = sorted(addrs)
    #     counter = 1
    #     diff = addrs[1] - addrs[0]
    #     for i in range(1, size):
    #         tmp = addrs[i] - addrs[i - 1]
    #         if tmp != diff:
    #             if counter > 1:
    #                 return True
    #             diff = tmp
    #             counter = 1
    #         else:
    #             counter += 1

    #     if counter > 1:
    #         return True
    #     return False

    def getExitCondition(self, funcName, tgtAddr):
        sym = self._kernel.find_symbol(funcName)
        graph = self._graphs[funcName]

        def get_node(nodes, addr):
            for node in nodes:
                if node.addr == addr:
                    return node
            return None

        def create_dominate(dom, idom, start):
            if start in dom:
                return dom[start]
            ret = [start]
            if start in idom:
                for node in idom[start]:
                    if node == start:
                        continue
                    ret += create_dominate(dom, idom, node)
            dom[start] = ret
            return ret

        def dominate(dom, dominator, node):
            return node in dom[dominator]

        def getInnermostLoop(graph, head, tail):
            loop = [head]
            stack = [tail]
            while len(stack) > 0:
                node = stack.pop()
                if node in loop:
                    continue
                loop.append(node)
                for pred in graph.predecessors(node):
                    if pred not in loop:
                        stack.append(pred)
            return loop

        def getCurLoop(loops, addr):
            for loop in loops:
                for node in loop:
                    if node.addr <= addr < node.addr + node.size:
                        return loop
            return None

        def getExitBlocks(graph, loop):
            exitblocks = set()
            for node in loop[1:]:
                for succ in graph.successors(node):
                    if succ not in loop and \
                     not isinstance(succ, Function):
                        exitblocks.add(node)
            for succ in graph.successors(loop[0]):
                if succ not in loop and \
                 not isinstance(succ, Function):
                    exitblocks.add(loop[0])
            return list(exitblocks)

        start_node = get_node(graph.nodes, sym.rebased_addr)
        idom_pair = nx.immediate_dominators(graph, start_node)
        # reverse it
        idom = dict()
        for node, dominator in idom_pair.items():
            if dominator not in idom:
                idom[dominator] = list()
            idom[dominator].append(node)

        dom = dict()
        create_dominate(dom, idom, start_node)
        alloops = list()
        for node in graph.nodes:
            for succ in graph.successors(node):
                if dominate(dom, succ, node):
                    # find a back edge
                    loop = getInnermostLoop(graph, succ, node)
                    alloops.append(loop)
        loop = getCurLoop(alloops, tgtAddr)
        if loop is None:
            return None

        exitblocks = getExitBlocks(graph, loop)
        if len(exitblocks) > 1:
            raise ValueError("More than one exit block")
        elif len(exitblocks) == 0:
            raise ValueError("Failed to find exit block")
        # Get block with disassebled assembly
        block = self._kernel.getBlock(exitblocks[0].addr)
        insns = block.capstone.insns

        def isCmp(insn):
            if any([
                    insn.mnemonic == each
                    for each in Report.EXIT_CONDITION_INSNS
            ]):
                return True
            return False

        for i in range(len(insns) - 1, -1, -1):
            insn = insns[i]
            if isCmp(insn):
                return insn
        return None

    def getExitStatement(self, targets):
        '''
		if we have multiple addresses wherer OOB occurs, we might want to
		aumatically choose some exit points that let the S2E analysis stop
		'''
        if len(targets) == 0:
            return []

        exits = []
        # case 1: all targets within the same function
        funcName = None
        isSameFunc = True
        for target in targets:
            sym = self._kernel.find_symbol(target[SPOT_ADDR], fuzzy=True)
            if sym is None:
                raise ValueError("UNknown function at 0x%x" %
                                 target[SPOT_ADDR])
            if funcName is None:
                funcName = sym.name
            elif funcName != sym.name:
                isSameFunc = False
                break
        if isSameFunc:
            insns = self._kernel.getExitInsns(funcName)
            for insn in insns:
                exits.append(insn.address)
        if len(exits) == 0:
            print("Error: OOB are not all in the same function")
        else:
            # successful
            return exits

        # 2: choose the last function
        target = targets[-1]
        sym = self._kernel.find_symbol(target[SPOT_ADDR])
        print("choose the last function %s" % sym.name)
        insns = self._kernel.getExitInsns(sym.name)
        for insn in insns:
            exits.append(insn.address)
        if len(exits) == 0:
            print("Error: Failed to find any exit")

        return exits

    def pickMulCandidates(self, reports, spots):
        if len(reports) == 1:
            return [spots[0]], [], [], reports[0]["len"]

        targets, conditions = [], []
        oobs = dict()
        for report, spot in zip(reports, spots):
            addr, tgt = report["addr"], spot[SPOT_ADDR]
            if tgt == 0:  # special case for zero
                continue
            if tgt not in oobs:
                oobs[tgt] = [addr]
            else:
                oobs[tgt].append(addr)
        done = [0]
        total_size = 0
        for report, spot in zip(reports, spots):
            total_size += report["len"]
            tgt = spot[SPOT_ADDR]
            if tgt in done:
                continue
            done.append(tgt)
            insn = self.getExitCondition(spot[SPOT_FUNC], tgt)
            if insn is not None:
                print("loop detected at 0x%x" % (tgt))
                print("find exit condition for 0x%x: 0x%x" %
                      (tgt, insn.address))
                conditions.append((tgt, insn.address))
            targets.append(spot)

        exits = self.getExitStatement(targets)
        return targets, exits, conditions, total_size

