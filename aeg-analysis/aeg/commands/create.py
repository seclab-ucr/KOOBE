import os
import subprocess
import logging
import re
import json

from aeg.command import ProjectCommand
from aeg.util import create_project

logger = logging.getLogger(__name__)


class createCommand(ProjectCommand):
    '''create a new aeg project and run'''

    def __init__(self, parser):
        super(createCommand, self).__init__(parser)
        parser.add_argument("-i",
                            "--image",
                            required=True,
                            help="image")
        parser.add_argument("-c", "--code", help="path to the syzbot PoC")
        parser.add_argument("-w",
                            "--workdir",
                            default="workdir",
                            help="path to the workdir")
        parser.add_argument("--vmlinux", help="path to the vmlinux")
        parser.add_argument("--version", default="4.9.3", help="Linux kernel version")

        # Other options
        parser.add_argument("--threaded", action="store_true", default=False, help="PoC requires multiple threads")

    def create_poc(self, code_path, sandbox=None, workdir="workdir"):
        gopath = self.getEnv("GOPATH")
        bin_path = os.path.join(gopath, "src", "github.com", "google",
                                "syzkaller", "bin", "syz-prog2c")
        cmds = [bin_path, "-prog", code_path, "-s2e"]
        if sandbox == "namespace":
            cmds += ["-sandbox", sandbox, "-tmpdir"]
        logger.debug("convert to c code: %s" % " ".join(cmds))
        ret_path = os.path.join(workdir, "poc.c")
        with open(ret_path, "w") as fp:
            subprocess.run(cmds, stdout=fp, check=True)
        return ret_path

    def compile_poc(self, code_path, workdir="workdir", threaded=False):
        binary_path = os.path.join(workdir, "poc")
        header = "-I%s/source/s2e/guest/common/include/s2e" % self.s2edir()
        cmds = ["gcc", code_path, "-o", binary_path, header]
        if threaded:
            cmds += ["-lpthread"]
        with open(os.path.join(workdir, "make.sh"), "w") as fp:
            fp.write(" ".join(cmds))
        logger.debug("compile PoC: %s" % " ".join(cmds))
        subprocess.run(cmds, check=True)
        return binary_path

    def generate_candidates(self, vmlinux):
        cmds = ["python", "main.py", "pahole", "-i", vmlinux, "--known"]
        logger.debug("generate target candidates: %s" % " ".join(cmds))
        subprocess.run(cmds, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

    def getOptions(self, code_path):
        opts = {"Threaded": False, "sandbox": "none"}
        with open(code_path, "r") as fp:
            for line in fp:
                if not line.startswith("#"):
                    continue
                line = line[1:]
                try:
                    opt = json.loads(line)
                    opts.update(opt)
                except:
                    pass
        return opts

    def run(self, args):
        super(createCommand, self).run(args)
        logger.debug("using workdir: %s" % args.workdir)
        # setup
        try:
            os.mkdir(args.workdir)
        except OSError:
            pass
        workdir = os.path.abspath(args.workdir)
        # remove previous temporary results
        self.remove(os.path.join(workdir, "vuln.json"))
        self.remove(os.path.join(workdir, "reports.json"))
        self.remove(os.path.join(workdir, "layout.json"))

        options = self.getOptions(args.code)
        if args.threaded:
            options["Threaded"] = True

        code_path = self.create_poc(args.code, workdir=workdir)
        binary_path = self.compile_poc(code_path, workdir=workdir, threaded=options["Threaded"])
        create_project(args.project, args.image, binary_path)
        self.generate_candidates(args.vmlinux)

        project_json = self.project_config()
        project_json["vmlinux"] = self.getFullPath(args.vmlinux)
        project_json["workdir"] = self.getFullPath(args.workdir)
        project_json["syz"]     = self.getFullPath(args.code)
        project_json["version"] = args.version
        project_json["options"] = options
        self.save_project_config(project_json)

