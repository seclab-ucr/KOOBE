import struct
import json
import os
import re

from aeg.command import ProjectCommand
from aeg.kernel import Kernel, KernelObject
from aeg.util import genSolution, findSolutions, findLayoutSyscall

class parselogCommand(ProjectCommand):
    '''parse s2e debug.txt file'''
    Caches = {
        16: 4096,
        32: 4096,
        64: 4096,
        96: 4096,
        128: 4096,
        192: 4096,
        256: 16384,
        512: 16384,
        1024: 32768,
        2048: 32768,
        4096: 32768,
        8192: 32768
    }

    def __init__(self, parser):
        super(parselogCommand, self).__init__(parser)
        parser.add_argument('-t',
                            dest='trace',
                            action='store_true',
                            default=False,
                            help="Analyze trace file")
        parser.add_argument("--keep",
                            action='store_true',
                            default=False,
                            help="keep instructions")
        parser.add_argument('-r',
                            dest='report',
                            action='store_true',
                            default=False,
                            help="retrieve KASAN report")
        parser.add_argument('-o',
                            dest='object',
                            action='store_true',
                            default=False,
                            help="retrieve lifetime of an object")
        parser.add_argument("-i",
                            "--image",
                            action="store",
                            help="path to vmlinux")
        parser.add_argument("--reserve",
                            action="store_true",
                            default=False,
                            help="reserve the order")
        parser.add_argument("--filter_size", type=int, help="only of size x")
        parser.add_argument("--constraint",
                            default=False,
                            action="store_true",
                            help="show constraint distribution")
        parser.add_argument("--cap",
                            default=False,
                            action="store_true",
                            help="show capability")
        parser.add_argument("--solution",
                            default=False,
                            action="store_true",
                            help="count solutions")
        parser.add_argument("--file", action="store", help="file path")
        parser.add_argument("--version", help="Linux kernel version", default="4.9.3")

    def getSize(self, size):
        ret = 8192
        if size > 8192:
            return (size + 8191) // 8192
        for v in ParseLogCommand.Caches:
            if v >= size and v < ret:
                ret = v
        return ret

    def run(self, args):
        super(parselogCommand, self).run(args)

        debugfile = self.last_execution_file("debug.txt")
        if args.file:
            debugfile = args.file

        if args.trace:
            tracefile = self.last_execution_file("KernelExecutionTracer.dat")
            self.handletrace(tracefile, args.keep)
        elif args.report:
            self.handlereport(debugfile, args.image)
        elif args.object:
            self.handletraceobject(args, debugfile)
        elif args.constraint:
            self.handleconstraint(args, debugfile, args.image)
        elif args.cap:
            self.showcap()
        elif args.solution:
            self.countSolution(args, debugfile)

    def handleconstraint(self, args, path, vmlinux):
        print("parsing file %s" % path)
        if vmlinux is None:
            print("Require vmlinux")
            return
        kernel = Kernel(vmlinux)
        with open(path) as f:
            start = False
            dist = dict()
            for line in f:
                if "constraints for symbolic memory index" in line:
                    start = True
                if "constraints for loops" in line:
                    break
                if start:
                    m = re.search('(0x[0-9a-f]+): (0x[0-9a-f])', line)
                    if m:
                        pc = int(m.group(1), 16)
                        num = int(m.group(2), 16)
                        dist[pc] = num
            dist_func = dict()
            for pc, num in dist.items():
                sym = kernel.find_symbol(pc)
                if sym:
                    if sym.name in dist_func:
                        dist_func[sym.name] += num
                    else:
                        dist_func[sym.name] = num
            total = 0
            sorted_list = sorted(dist_func.items(), key=lambda x: x[1])
            for name, num in sorted_list:
                total += num
                print("%s: %d" % (name, num))
            print("total: %d" % total)

    def handletrace(self, path, keep=False):
        print("parsing file %s" % path)
        last_value = 0
        with open(path, "rb") as f:
            num = f.read(8)
            while num != "" and num:
                value = struct.unpack("<Q", num)[0]
                if keep or last_value != value:
                    print(hex(value))
                    last_value = value
                num = f.read(8)

    def showcap(self):
        cap_file = self.workdir_file("capability")
        backup_file = self.workdir_file("capability.backup")
        print("parsing file %s" % cap_file)
        self.execute(["cp", cap_file, backup_file])
        with open(backup_file, "rb") as f:
            size = f.read(4)
            if len(size) > 0:
                n = struct.unpack("<I", size)[0]
                for i in range(n):
                    b = f.read(2 + 1 + 1)
                    if len(b) == 0:
                        break
                    offset, payload, mask = struct.unpack("<HBB", b)
                    print("%d: 0x%x %x" % (offset, payload, mask))
            size = f.read(4)
            if len(size) > 0:
                n = struct.unpack("<I", size)[0]
                for i in range(n):
                    b = f.read(8)
                    if len(b) == 0:
                        break
                    ip = struct.unpack("<Q", b)[0]
                    print("0x%x" % ip)
            magic = f.read(4)
            if magic != b'\xef\xbe\xad\xde':
                return
            # size = f.read(4)
            # if len(size) > 0:
            #     n = struct.unpack("<I", size)[0]
            #     test = list()
            #     for i in range(n):
            #         num = f.read(4)
            #         if len(num) == 0:
            #             break
            #         val = struct.unpack("<I", num)[0]
            #         test.append(val)
            #     print("%d: %s" % (n, str(test)))
        self.execute(["rm", backup_file])

    def handlereport(self, path, vmlinux=None):
        print("parsing file %s" % path)
        kernel = None
        if vmlinux:
            kernel = Kernel(vmlinux)
        with open(path) as f:
            for line in f:
                if "[KASAN]" in line:
                    item = KernelObject("[KASAN]", line)
                    print(str(item))
                    if kernel is None: continue
                    if "ip" in item:
                        for addr in item.ip:
                            print(kernel.resolve_addr(addr))

    def handletraceobject(self, args, path):
        print("parsing file %s" % path)
        keys = ["[Create]", "[Access]", "[Delete]", "[object]"]

        def getItem(line):
            item = json.loads(line)

        with open(path) as f:
            items = dict()
            for line in f.readlines():
                if '[syscall]' in line and args.reserve:
                    print(line[line.index('[syscall]'):])
                if '[KASAN-CONFIRM]' in line and args.reserve:
                    print(str(KernelObject('[KASAN-CONFIRM]', line)))
                for each in keys:
                    if each in line:
                        item = KernelObject(each, line)
                        if args.filter_size:
                            if "size" not in item:
                                continue
                            if self.getSize(item.size) != args.filter_size:
                                continue
                        if args.reserve:
                            print(str(item))
                            continue
                        base = item.base
                        if base not in items:
                            items[base] = list()
                        items[base].append(item)
            for k, records in items.items():
                print("Object: 0x%x" % k)
                for record in records:
                    print(str(record))

    def countSolution(self, args, path):
        solutions = findSolutions(path)
        if len(solutions) == 0:
            return

        layout = self.loads(self.workdir_file("layout.json"))
        vuln = self.loads(self.workdir_file("vuln.json"))
        if not layout:
            layout = findLayoutSyscall(self.last_execution_file('debug.txt'),
                       self.workdir_file("layout.json"))
            if layout is None:
                return

        workdir = self.getConfig("workdir")
        if workdir is None:
            workdir = self.project_dir
        genSolution(solutions, layout, vuln, workdir)

