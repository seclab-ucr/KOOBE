
from aeg.command import Command
from aeg.kernel import Kernel

class parsetraceCommand(Command):
    '''parse trace file'''

    def __init__(self, parser):
        super(parsetraceCommand, self).__init__(parser)
        parser.add_argument("-i",
                            "--image",
                            required=True,
                            action="store",
                            help="path to vmlinux")
        parser.add_argument("-d",
                            "--depth",
                            type=int,
                            default=1,
                            action="store",
                            help="depth of trace")
        parser.add_argument("-e",
                            "--entry",
                            action="store",
                            help="entry function")
        parser.add_argument("--exit", action="store", help="exit function")
        parser.add_argument("-f", "--file", required=True, help="trace file")
        parser.add_argument("--skip", type=int, help="skip n lines")
        parser.add_argument("-s",
                            "--sweep",
                            default=False,
                            action="store_true",
                            help="sweep")
        parser.add_argument("--line",
                            type=int,
                            default=0,
                            help="how many lines to parse")

    def skipinterrupt(self, kernel, addrs, index):
        while index < len(addrs):
            addr = addrs[index]
            index += 1
            # if addr == 0xffffffff81fdbdd7:
            # 	return index
            block = kernel.getBlock(addr)
            if len(block.capstone.insns) == 0:
                # print(hex(addr))
                return index
            insn = block.capstone.insns[0]
            if 'iret' in insn.mnemonic:
                return index
            # for insn in block.capstone.insns:
            # 	if insn.mnemonic == 'iretq':
            # 		return index

    def tracewalk(self, kernel, addrs, index, depth, indent=0):
        apic_timer_interrupt = self.func_start("apic_timer_interrupt")

        if index >= len(addrs):
            return
        addr = addrs[index]
        index += 1
        func = kernel.find_symbol(addr, fuzzy=True)
        func_start = func.rebased_addr
        func_end = func.rebased_addr + func.size

        if func.name.startswith("__asan"):
            return index
        print("%s%s: %x-%x" % ('  ' * indent, func.name, func_start, func_end))

        prev_block = None
        cur_block = kernel.getBlock(addr)

        def getInsn(insns, addr):
            for insn in insns:
                if insn.address == addr:
                    return insn
            return insns[-1]

        while True:
            match = True
            # print("%x-%x" % (cur_block.addr, cur_block.addr + cur_block.size))
            for insn in cur_block.capstone.insns:
                if insn.address != addr:
                    match = False
                    break
                addr = addrs[index]
                index += 1
                if index >= len(addrs):
                    break

            prev_block = cur_block
            if index >= len(addrs):
                return None
            # print("0x%x" % addr)
            if func_start <= addr < func_end:
                cur_block = kernel.getBlock(addr)
            else:
                insn = getInsn(cur_block.capstone.insns, addr)
                # print(insn, hex(addr), hex(addrs[index]))
                if addr == apic_timer_interrupt:  # apic_timer_interrupt
                    index = self.skipinterrupt(kernel, addrs, index)
                    addr = addrs[index]
                    index += 1
                    if func_start <= addr < func_end:
                        cur_block = kernel.getBlock(addr)
                        continue

                if insn.mnemonic == 'ret':
                    break
                else:
                    if depth > 1:
                        index = self.tracewalk(kernel, addrs, index, depth - 1,
                                               indent + 1)
                    else:
                        # skip this function call
                        try:
                            index = addrs.index(insn.address + insn.size,
                                                index)
                        except ValueError as e:
                            index = None
                    if index is None:
                        break
                    next_insn = insn.address + insn.size
                    if addrs[index] != next_insn:
                        # print("0x%x != 0x%x" % (addrs[index], next_insn))
                        try:
                            index = addrs.index(next_insn, index)
                        except ValueError as e:
                            index = None
                        if index is None:
                            break
                    cur_block = kernel.getBlock(next_insn)
                    addr = addrs[index]
                    index += 1
        # print("return %x" % addrs[index])
        if index is None:
            return None
        return index - 1

    def trace(self, kernel, path, depth=1, start=None, end=None, skip=0):
        addrs = list()
        count = 0
        if isinstance(start, str):
            if start.startswith("0x"):
                start = int(start, 16)
            else:
                sym = kernel.find_symbol(start)
                if sym:
                    # print("start at 0x%x" % sym.rebased_addr)
                    start = sym.rebased_addr
                else:
                    start = None

        if start is None:
            return

        print("start: 0x%x" % start)
        if end:
            print("end: 0x%x" % end)
        with open(path) as f:
            found = False
            for line in f:
                if not line.startswith("0x"):
                    continue
                if count < skip:
                    count += 1
                    continue
                addr = int(line.strip(), 16)
                if count % 300000 == 0:
                    print("0x%x" % addr)
                count += 1
                if start and addr == start:
                    found = True
                if end and addr == end:
                    return self.tracewalk(kernel, addrs, 0, depth)
                if found:
                    addrs.append(addr)
        return self.tracewalk(kernel, addrs, 0, depth)

    def sweeptrace(self, kernel, path, depth=1, start=None, end=None, num=0, skip=0):
        if isinstance(start, str):
            if start.startswith("0x"):
                start = int(start, 16)
            else:
                sym = kernel.find_symbol(start)
                if sym:
                    # print("start at 0x%x" % sym.rebased_addr)
                    start = sym.rebased_addr
                else:
                    start = None

        if start is None:
            return

        print("start: 0x%x" % start)
        if end:
            if isinstance(end, str):
                if end.startswith("0x"):
                    end = int(end, 16)
            print("end: 0x%x" % end)
        count = 0
        cur_func = None
        prev_func = None
        with open(path) as f:
            found = False
            for line in f:
                if not line.startswith("0x"):
                    continue
                if count < skip:
                    count += 1
                    continue
                addr = int(line.strip(), 16)
                count += 1
                if start and addr == start:
                    found = True
                if end and addr == end:
                    return
                if num and count == start + num:
                    return
                if found:
                    if cur_func and \
                     cur_func.rebased_addr <= addr < cur_func.rebased_addr + cur_func.size:
                        continue
                    sym = kernel.find_symbol(addr)
                    if sym:
                        if sym == cur_func:
                            continue
                        cur_func = sym
                        if cur_func.name.startswith("__asan"):
                            continue
                        if cur_func.name == prev_func:
                            continue
                        print(cur_func.name)
                        prev_func = cur_func.name

    def run(self, args):
        num = 0 if not args.skip else args.skip
        kernel = Kernel(args.image)
        if args.sweep:
            print(args.line, type(args.line))
            self.sweeptrace(kernel, args.file,
                              depth=args.depth,
                              start=args.entry,
                              end=args.exit,
                              num=args.line,
                              skip=num)
        else:
            self.trace(kernel, args.file,
                         depth=args.depth,
                         start=args.entry,
                         skip=num)
