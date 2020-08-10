import angr
import json
import re
import struct
import subprocess

from capstone.x86_const import X86_OP_MEM, X86_OP_IMM
from .gdb import GDBHelper

clean = lambda x, k: x[x.index(k):]
strip = lambda x, k: x[x.index(k) + len(k):]
boolean = lambda x: "true" if x else "false"


class KernelObject:
    def __init__(self, key, line):
        self._key = key
        self._item = json.loads(strip(line, key))

    @property
    def json(self):
        return self._item

    def getNum(self, num):
        if num > 65536: return hex(num)
        return str(num)

    def getList(self, l):
        ret = "["
        for i, each in enumerate(l):
            if i != 0:
                ret += ", "
            ret += self.getStr(each)
        ret += "]"
        return ret

    def getDict(self, d):
        ret = "{"
        index = 0
        for k, v in d.items():
            if index != 0:
                ret += ", "
            ret += ("%s: %s" % (k, self.getStr(v)))
            index += 1
        ret += "}"
        return ret

    def getStr(self, v):
        if isinstance(v, int):
            return self.getNum(v)
        elif isinstance(v, list):
            return self.getList(v)
        elif isinstance(v, dict):
            return self.getDict(v)
        else:
            return str(v)

    def save(self, path):
        with open(path, 'w') as f:
            json.dump(self._item, f)

    @staticmethod
    def load(path):
        with open(path) as f:
            return KernelObject('', f.readline())

    def __str__(self):
        return self._key + " " + self.getStr(self._item)

    def __getattr__(self, k):
        return self._item[k]

    def __contains__(self, key):
        return key in self._item


class Kernel:
    Interrupt_Functions = ["update_fast_timekeeper", "apic_timer_interrupt"]
    FUNCNAME = 0
    ADDRESS = 1

    def __init__(self, vmlinux):
        self.proj = angr.Project(vmlinux,
                                 load_options={"auto_load_libs": False})
        self.gdbhelper = GDBHelper(vmlinux)
        # private
        self._kasan_report = 0
        self._kasan_ret = 0

    def getStructOffset(self, struct_name, field_name):
        cmd = "p &((struct %s *)0)->%s" % (struct_name, field_name)
        ret = self.gdbhelper.commandstr(cmd)
        m = re.search('0x[0-9a-f]+', ret)
        if m:
            return int(m.group(0), 16)
        return 0

    def check_output(self, args):
        completed = subprocess.run(args, stdout=subprocess.PIPE)
        return completed.stdout

    def searchInstruction(self,
                          start,
                          end,
                          instruction,
                          funCall=None,
                          exact=False):
        while start < end:
            block = self.getBlock(start)
            if len(block.capstone.insns) == 0:
                start += 2
                continue
            inst = block.capstone.insns[0]
            if exact:
                if inst.mnemonic == instruction.mnemonic and \
                 inst.op_str == instruction.op_str:
                    return start
            elif funCall is not None:
                if inst.mnemonic == 'call' and \
                 funCall == self.getTarget(inst.operands[0], Kernel.FUNCNAME):
                    return start
            else:
                if inst.mnemonic != instruction.mnemonic:
                    start += inst.size
                    continue
                if len(inst.operands) != len(instruction.operands):
                    start += inst.size
                    continue
                Found = True
                for i in range(len(inst.operands)):
                    op, op2 = inst.operands[i], instruction.operands[i]
                    if op.type != op2.type:
                        Found = False
                        break
                    if op.size != op2.size:
                        Found = False
                        break
                if Found:
                    return start
            start += inst.size
        return 0

    def getTarget(self, operand, addrOrname=ADDRESS):
        if operand.type != X86_OP_IMM:
            return 0
        target = operand.value.imm & 0xffffffffffffffff
        if addrOrname == Kernel.ADDRESS:
            return target
        else:
            sym = self.find_symbol(target)
            if sym:
                return sym.name
            return 0

    def getKasanReport(self):
        if self._kasan_ret != 0 or self._kasan_report != 0:
            return self._kasan_report, self._kasan_ret

        kasan_report = self.find_symbol("__kasan_report")
        if kasan_report is None:
            kasan_report = self.find_symbol("kasan_report")
        start = kasan_report.rebased_addr
        end = start + kasan_report.size
        kasan_report, kasan_ret = 0, 0
        while start < end:
            block = self.getBlock(start)
            if len(block.capstone.insns) == 0:
                start += 2
                continue
            inst = block.capstone.insns[0]
            # first check
            if inst.mnemonic == "jne":
                kasan_report = start + inst.size
                kasan_ret = self.getTarget(inst.operands[0])
                break
            elif inst.mnemonic == "je":
                kasan_report = self.getTarget(inst.operands[0])
                kasan_ret = start + inst.size
                break
            start += inst.size

        self._kasan_report, self._kasan_ret = kasan_report, kasan_ret
        return kasan_report, kasan_ret

    def instVisitor(self, funcName, handler):
        sym = self.find_symbol(funcName)
        if sym is None:
            return
        start = sym.rebased_addr
        end = start + sym.size
        cur = start
        while cur < end:
            block = self.getBlock(cur)
            cur += block.size
            for insn in block.capstone.insns:
                ret = handler(insn)
                if ret:
                    return

    def resolve_addr(self, addr):
        func = self.proj.loader.find_symbol(addr, fuzzy=True)
        if func:
            return "%s+%d" % (func.name, addr - func.rebased_addr)
        else:
            return hex(addr)

    def find_symbol(self, addr, fuzzy=True):
        return self.proj.loader.find_symbol(addr, fuzzy)

    def func_start(self, name):
        func = self.proj.loader.find_symbol(name)
        if func:
            return func.rebased_addr
        return 0

    def getFunctionCFG(self, func):
        symbol = self.find_symbol(func)
        if symbol is None:
            return None
        return self.proj.analyses.CFGEmulated(context_sensitivity_level=0,
                                              starts=[symbol.rebased_addr],
                                              call_depth=0,
                                              normalize=True)

    def getExitInsns(self, addr):
        exits = []
        sym = self.find_symbol(addr)
        if sym:
            cur = sym.rebased_addr
            while cur < sym.rebased_addr + sym.size:
                block = self.getBlock(cur)
                cur += block.size
                if block.size == 0:
                    # BUG() in kernel
                    print("Warning: empty block at 0x%x" % cur)
                    cur += 2
                for insn in block.capstone.insns:
                    if insn.mnemonic == 'ret':
                        exits.append(insn)
        return exits

    def getBlock(self, addr):
        return self.proj.factory.block(addr)

    def backtrace(self,
                  filepath,
                  counter,
                  ips,
                  depth,
                  avoid=Interrupt_Functions):
        index = 1
        calls = []
        counter -= 1

        def readaddr(f, counter):
            f.seek(counter * 8)
            num = f.read(8)
            if num == "" or not num:
                raise ValueError("Incomplete trace file")
            value = struct.unpack("<Q", num)[0]
            return value

        def findCallsite(f, counter, target):
            # TODO: how to deal with indirect call??
            # FIXME: while we do back tracing, we encounter other functions invoking the same target
            while counter >= 0:
                value = readaddr(f, counter)
                block = self.getBlock(value)
                if len(block.capstone.insns) == 0:
                    counter -= 1
                    continue
                inst = block.capstone.insns[0]
                if inst.mnemonic in ['call', 'jmp']:
                    if inst.operands[0].type != X86_OP_IMM:
                        counter -= 1
                        continue
                    target_addr = inst.operands[
                        0].value.imm & 0xffffffffffffffff
                    if target_addr == target:
                        return counter, value + inst.size  # counter, return address
                counter -= 1
            raise ValueError("Failed to find %x" % target)

        def findEntry(f, counter, target):
            while counter >= 0:
                value = readaddr(f, counter)
                if value == target:
                    return counter
                counter -= 1
            raise ValueError("Faild to find %x" % target)

        with open(filepath, "rb") as f:
            f.seek(counter * 8)
            num = f.read(8)
            if num != "" and num:
                value = struct.unpack("<Q", num)[0]
                print(hex(value))
            cur_addr = value
            for i in range(depth):
                sym = self.find_symbol(cur_addr)
                if sym is None:
                    raise ValueError("Unknown function %x" % cur_addr)
                try:
                    counter = findEntry(f, counter, sym.rebased_addr)
                    while True:
                        counter, retAddr = findCallsite(
                            f, counter, sym.rebased_addr)
                        func = self.find_symbol(retAddr)
                        if func.name in avoid:
                            continue
                        break
                    cur_addr = retAddr
                    calls.append(retAddr)
                except ValueError as e:
                    print(e)
                    break

        for i in range(len(ips)):
            if ips[i] != calls[i]:
                print(ips, calls)
                print("Warning: Inconsistent backtrace")

        return calls

