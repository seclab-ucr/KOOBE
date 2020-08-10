import logging
import os
import psutil
import json
import shutil
import re

from subprocess import Popen, run, TimeoutExpired, STDOUT

from aeg.command import ProjectCommand, RET_TIMEOUT
from aeg.util import find_vulnerable_object, find_vulnerablility_sites, findLayoutSyscall, findSolutions, genSolution, create_project
from aeg.kernel import Kernel

logger = logging.getLogger(__name__)

class runCommand(ProjectCommand):
    '''run s2e analysis'''

    MAXIMUM_TIMES = 5

    def __init__(self, parser):
        super(runCommand, self).__init__(parser)
        parser.add_argument('--timeout', type=int, default=0, help="time limit for launching S2E")
        parser.add_argument('--findVuln', action="store_true", default=False, help="phase 1: identify the vuln obj")
        parser.add_argument('--findSites', action="store_true", default=False, help="phase 2: identify all the vuln sites")
        parser.add_argument('--findTarget', action="store_true", default=False, help="phase 3: search for matching target objects")
        parser.add_argument('--exploit', action="store_true", default=False, help="Generate exploits after successfully producing exploit strategies")
        parser.add_argument('--fuzz', action="store_true", default=False, help="Fuzz the PoC")

        # Some other options
        parser.add_argument('--threaded', action="store_true", default=False, help="indicate if the PoC requires multiple threads (e.g., race condition)")
        parser.add_argument('--clear', action="store_true", default=False, help="clear all the temporary files")

    def findProcess(self, output):
        with open(output, "r") as fp:
            for line in fp:
                if "Observe KASAN_REPORT" in line:
                    return line.split(":")[-1].strip()
        return None

    def find_targets(self, project, vmlinux, workdir, timeout, threaded=False):
        if not os.path.isfile(os.path.join(workdir, "reports.json")):
            logger.error("no reports.json found, please run with --findSites")
            return False

        logger.debug("Phase 3: search all target matching capability...")
        extra_process = []
        count = runCommand.MAXIMUM_TIMES if threaded else 1
        while count > 0:
            cmds = ["python", "main.py", "genconf", "-p", project, "-i", vmlinux, "-e", "-m", "3"]
            if len(extra_process) > 0:
                cmds += ["--pids", ",".join(extra_process)]
            logger.debug("Patch the config: %s" % " ".join(cmds))
            run(cmds, check=True)

            tmpfile = os.path.join(workdir, "tmp")
            ret = self.launch_s2e(tmpfile, timeout=timeout)
            if ret != 0 and ret != RET_TIMEOUT:
                return False
            pid = self.findProcess(tmpfile)
            if pid is not None:
                if pid not in extra_process:
                    extra_process.append(pid)
                    continue

            layout = findLayoutSyscall(tmpfile, os.path.join(workdir, "layout.json"))
            if layout is None:
                logger.error("failed to extract syscall and layout information")
                count -= 1
                continue

            # save capability
            cap_file = os.path.join(workdir, "cap")
            if os.path.exists(cap_file):
                syz = self.getConfig("syz")
                syz = os.path.basename(syz)
                name = syz[:-4]
                new_cap = os.path.join(workdir, "%s.cap" % name)
                shutil.move(cap_file, new_cap)

            solutions = findSolutions(tmpfile)
            if len(solutions) == 0:
                return False

            logger.debug("start to generate exploit strategies...")
            vulnObj = self.loads(os.path.join(workdir, "vuln.json"))
            if vulnObj is None:
                logger.error("failed to load the vuln.json")
                return False
            # FIXME: add version
            genSolution(solutions, layout, vulnObj, workdir)
            return True
        return False

    def find_sites(self, project, vmlinux, workdir, timeout, threaded=False):
        if not os.path.isfile(os.path.join(workdir, "vuln.json")):
            logger.error("no vuln.json found, please run with --findVuln first")
            return False

        logger.debug("Phase 2: locate all the vulnerability sites...")
        extra_process = []
        count = runCommand.MAXIMUM_TIMES if threaded else 1
        while count > 0:
            cmds = ["python", "main.py", "genconf", "-p", project, "-i", vmlinux, "-e", "-m", "2"]
            if len(extra_process) > 0:
                cmds += ["--pids", ",".join(extra_process)]
            logger.debug("Patch the config: %s" % " ".join(cmds))
            run(cmds, check=True)

            tmpfile = os.path.join(workdir, "tmp")
            # continue to execute even if timeout is raised
            ret = self.launch_s2e(tmpfile, timeout=timeout)
            if ret != 0 and ret != RET_TIMEOUT:
                return False
            pid = self.findProcess(tmpfile)
            if pid is not None:
                if pid not in extra_process:
                    extra_process.append(pid)
                    continue

            kernel = Kernel(vmlinux)
            reports = find_vulnerablility_sites(tmpfile, kernel, os.path.join(workdir, "reports.json"))
            if len(reports) == 0:
                logger.error("failed to find any sites")
                count -= 1
                continue
            logger.debug("find vulnerability sites: %s" % str(reports))
            return True
        return False

    def find_vuln(self, project, vmlinux, workdir, timeout, threaded=False):
        logger.debug("Phase 1: locate the vulnerable object ...")
        extra_process = []
        count = runCommand.MAXIMUM_TIMES if threaded else 1
        while count > 0:
            cmds = ["python", "main.py", "genconf",  "-p", project, "-i", vmlinux, "-e", "-m", "1"]
            if len(extra_process) > 0:
                cmds += ["--pids", ",".join(extra_process)]
            logger.debug("Patch the config:  %s" % " ".join(cmds))
            run(cmds, check=True)

            tmpfile = os.path.join(workdir, "tmp")
            if self.launch_s2e(tmpfile, timeout=timeout) != 0:
                return False
            pid = self.findProcess(tmpfile)
            if pid is not None:
                if pid not in extra_process:
                    extra_process.append(pid)
                    continue
            
            item = find_vulnerable_object(tmpfile, os.path.join(workdir, "vuln.json"))
            if item is None:
                logger.debug("failed to locate the vulnerable object")
                count -= 1
                continue

            logger.debug("succeed to locate the vulnerable object")
            return True
        return False

    def generate_exploit(self, workdir, syz):
        gopath = self.getEnv("GOPATH")
        prog2c = os.path.join(gopath, "src", "github.com", "google", "syzkaller", "bin", "syz-prog2c")
        cmds = [prog2c, "-prog", syz, "-exp", "-json"]
        success = []
        total = 0
        for name in os.listdir(workdir):
            if name.startswith("ans_") and name.endswith(".json"):
                total += 1
                execs = cmds + [os.path.join(workdir, name)]
                target = name[len("ans_"):-len(".json")]
                output = os.path.join(workdir, "exp_%s.c" % target)
                logger.debug("Execute: %s > %s" % (" ".join(cmds), output))
                with open(output, "w") as fp:
                    proc = Popen(execs, stdout=fp)
                    proc.wait()
                    if proc.returncode == 0:
                        success.append(output)
                        logger.debug("Successfully generate one exploit: %s" % output)
                    else: os.remove(output)
        logger.info("Successfully generate %d exploits out of %d candidates" % (len(success), total))
        for each in success:
            logger.info(each)

    def clear(self, workdir):
        for name in os.listdir(workdir):
            if name.endswith(".syz"):
                continue
            if name.startswith("exp_"):
                continue
            if name.startswith("."):
                continue
            if name.endswith(".md"):
                continue
            path = os.path.join(workdir, name)
            os.remove(path)

    def genSyscalls(self, dictPath):
        if os.path.exists(dictPath):
            with open(dictPath, "r") as fp:
                return json.load(fp)

        # collect all system calls
        kernel = os.path.dirname(self.getConfig("vmlinux"))
        if ".tmp-output" in kernel:
            # Kernel source code is not here.
            kernel = os.path.join(self.getEnv("S2EDIR"), "source", "s2e-linux-kernel", "linux-4.9.3")
        logger.debug("Search syscalls in %s..." % kernel)
        cmds = ["grep", "-r", "^SYSCALL_DEFINE", kernel]
        output = self.check_output(cmds)
        syscalls = {}
        for line in output.split(b'\n'):
            if len(line) == 0: continue
            filepath, definition = line.decode('utf-8').split(":")
            m = re.search('SYSCALL_DEFINE\d\((\w+),', definition)
            if not m: continue
            func = m.group(1)
            names = filepath.split('/')
            index = names.index("s2e-linux-kernel")
            names = names[index+2:]
            cur = syscalls
            for name in names:
                if name not in cur:
                    cur[name] = {}
                cur = cur[name]
            cur[func] = True
        # save it
        with open(dictPath, "w") as f:
            logger.debug("generate syscall defs: %s" % dictPath)
            json.dump(syscalls, f, indent=2)
        return syscalls

    def checkEnabled(self, syscalls):
        gopath = self.getEnv("GOPATH")
        bin_path = os.path.join(gopath, "src", "github.com", "google",
                "syzkaller", "bin", "syz-enable")
        cmds = [bin_path, "-enable", ",".join(syscalls)]
        output = self.check_output(cmds)
        ret = set()
        for line in output.split(b'\n'):
            if len(line) == 0: continue
            ret.add(line.decode('utf-8'))
        return ret

    def getSyscalls(self, workdir):
        syz = self.getConfig("syz")
        funcs = []
        with open(syz, "r") as fp:
            for line in fp:
                if line.startswith("#"):
                    continue
                m = re.search('=?(\s+)?(\w+)(\$\w+)?\(', line)
                if m:
                    func = m.group(2)
                    funcs.append(func)
        logger.debug("Found syscalls %s" % ",".join(funcs))

        def lookup(func, syscalls):
            found = False
            if func in syscalls:
                ret = syscalls[func]
                if isinstance(ret, bool):
                    return syscalls

            for name, values in syscalls.items():
                if isinstance(values, bool):
                    break
                ret = lookup(func, values)
                if ret:
                    return ret
            return None

        syscalls = self.genSyscalls(os.path.join(workdir, "syscalls.dict"))
        enabled = set(funcs)
        for func in funcs:
            ret = lookup(func, syscalls)
            if ret is None:
                logger.error("Failed to locate the func %s" % func)
                continue
            for each, _ in ret.items():
                enabled.add(each)
        enabled = self.checkEnabled(enabled)
        return ",".join(map(lambda x: "\"%s\"" % x, enabled))


    def fuzzing(self, workdir, project, vmlinux):
        # Create instances
        image = self.getConfig("image")
        binary = os.path.join(self.getEnv("GOPATH"), "src", "github.com", "google", "syzkaller", "bin", "linux_amd64", "syz-fuzzer")
        for i in range(1):
            name = "syzkaller-%d" % i
            create_project(name, image, binary)
            # patch config
            project_path = os.path.join(self.project_path(name), "project.json")
            cfg = self.loads(project_path)
            old_cfg = self.project_config()
            cfg["vmlinux"] = old_cfg["vmlinux"]
            cfg["workdir"] = old_cfg["workdir"]
            with open(project_path, "w") as f:
                json.dump(cfg, f, indent=4)

            cmds = ["python", "main.py", "genconf", "-i", vmlinux, "-p", name, "--syzkaller", "-s", project]
            logger.debug("Patch the config:  %s" % " ".join(cmds))
            run(cmds, check=True)

        fuzz_cfg = os.path.join(workdir, "syzkaller.cfg")
        template = os.path.join("template", "syzkaller.cfg")
        kernel = os.path.dirname(self.getConfig("vmlinux"))
        with open(template, "r") as f:
            content = f.read()
            content = content.replace("{{WORKDIR}}", workdir)
            content = content.replace("{{KERNEL}}", kernel)
            content = content.replace("{{ENABLE_SYSCALLS}}", self.getSyscalls(workdir))
            content = content.replace("{{SANDBOX}}", self.getOption("sandbox", "none"))
        with open(fuzz_cfg, "w") as f:
            f.write(content)

        # prepare seeds
        logger.debug("preparing seeds...")
        seeds_dir = os.path.join(workdir, "seeds")
        try: os.mkdir(seeds_dir)
        except: pass
        for name in os.listdir(workdir):
            if name.endswith(".syz"):
                shutil.copy(os.path.join(workdir, name),
                        os.path.join(seeds_dir, name))
        # produce corpus
        gopath = self.getEnv("GOPATH")
        db_path = os.path.join(gopath, "src", "github.com", "google", 
                "syzkaller", "bin", "syz-db")
        cmds = [db_path, "pack", seeds_dir, os.path.join(workdir, "corpus.db")]
        logger.debug("producing corpus: %s" % " ".join(cmds))
        run(cmds, check=True)

        # start fuzzing
        manager = os.path.join(gopath, "src", "github.com", "google",
            "syzkaller", "bin", "syz-manager")
        cmds = [manager, "-config", fuzz_cfg]
        logger.debug(" ".join(cmds))
        logger.debug("start fuzzing, enjoy!")
        run(cmds)

    def run(self, args):
        super(runCommand, self).run(args)
        project_cfg = self.project_config()
        vmlinux_path = project_cfg["vmlinux"]
        workdir = project_cfg["workdir"]
        threaded = self.getOption("Threaded", False)
        if args.threaded: threaded = True

        timeout = None if args.timeout == 0 else args.timeout
        if args.findVuln:
            self.find_vuln(args.project, vmlinux_path, workdir, timeout, threaded=threaded)
        elif args.findSites:
            self.find_sites(args.project, vmlinux_path, workdir, timeout, threaded=threaded)
        elif args.findTarget:
            self.find_targets(args.project, vmlinux_path, workdir, timeout, threaded=threaded)
        elif args.exploit:
            self.generate_exploit(workdir, project_cfg["syz"])
        elif args.fuzz:
            self.fuzzing(workdir, args.project, vmlinux_path)
        elif args.clear:
            self.clear(workdir)

