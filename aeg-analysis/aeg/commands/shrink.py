
from aeg.command import Command
from aeg.kernel import Kernel

class shrinkCommand(Command):
    '''shrink trace file'''

    def __init__(self, parser):
        super(shrinkCommand, self).__init__(parser)
        parser.add_argument("-i",
                            "--image",
                            required=True,
                            action="store",
                            help="path to vmlinux")
        parser.add_argument("-f", "--file", required=True, action="store", help="path to the trace file")
        parser.add_argument("-e",
                            "--entry",
                            action="store",
                            help="entry function")

    def shrink(self, kernel, path, target):
        if target.startswith("0x"):
            target = int(target, 16)
        else:
            sym = kernel.find_symbol(target)
            if sym:
                target = sym.rebased_addr
            else:
                target = None
        if target is None:
            return

        with open(path) as f, open("trace.out", "w") as output:
            found = False
            for line in f:
                if not line.startswith("0x"):
                    continue
                addr = int(line.strip()[:-1], 16)
                if addr == target:
                    found = True
                if found:
                    output.write(line)

    def run(self, args):
        kernel = Kernel(args.image)
        self.shrink(kernel, args.file, args.entry)

