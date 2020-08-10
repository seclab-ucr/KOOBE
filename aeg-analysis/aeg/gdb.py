from subprocess import Popen, PIPE, STDOUT, TimeoutExpired

import time
import pexpect


class GDBHelper:
    def __init__(self, vmlinux):
        self._vmlinux = vmlinux
        self._prompt = "gdbbot"

    def command(self, cmd):
        ret = list()
        try:
            init = [
                "gdb", self._vmlinux, "-ex",
                "set prompt %s" % self._prompt
            ]
            gdb = Popen(init, stdout=PIPE, stdin=PIPE, stderr=PIPE)
            outs, errs = gdb.communicate(cmd.encode(), timeout=10)
            start = False
            for line in outs.decode().split("\n"):
                # print(line)
                if line.startswith(self._prompt):
                    start = True
                if self._prompt + "quit" in line:
                    break
                if start:
                    if line.startswith(self._prompt):
                        line = line[len(self._prompt):]
                    ret.append(line)
            gdb.kill()
        except TimeoutExpired:
            self.gdb.kill()
        return ret

    def commands(self, cmds):
        ret = list()
        try:
            init = [
                "gdb", self._vmlinux, "-ex",
                "\"set prompt %s\"" % self._prompt
            ]
            gdb = pexpect.spawn(' '.join(init))
            gdb.expect(self._prompt)
            for cmd in cmds:
                gdb.sendline(cmd)
                gdb.expect(self._prompt)
            outs = gdb.before
            gdb.close()
            for line in outs.decode().split("\n"):
                ret.append(line.strip())
        except pexpect.TIMEOUT:
            gdb.close()
        return ret

    def commandstr(self, cmd):
        ret = self.command(cmd)
        return ''.join(ret)


if __name__ == '__main__':
    gdb = GDBHelper(
        "/media/weiteng/ubuntu/Workspace/syzkaller/linux/linux-next/vmlinux")
    # out = gdb.command("p &((struct task_struct *)0)->xxxx")
    # out = gdb.commands(["b crypto/dh_helper.c:21", "info b"])
    out = gdb.commandstr(
        "python print([hex(x.pc) for x in gdb.decode_line(\"crypto/dh_helper.c:21\")[1]])"
    )
    print(out)
