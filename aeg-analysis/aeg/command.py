import os
import json
import subprocess
import sys
import logging
import psutil

from subprocess import TimeoutExpired, STDOUT

logger = logging.getLogger(__name__)

RET_INTERRUPT = -1
RET_TIMEOUT   = -2

class Command(object):
    def __init__(self, _parser):
        self.parser = _parser
        self.parser.add_argument('-v',
                                 "--verbose",
                                 default=False,
                                 action="store_true",
                                 help="only for debug purpose")

    def run(self, args):
        self.parser.print_usage()

    def remove(self, filename):
        if os.path.exists(filename):
            try: os.remove(filename)
            except: pass

    def check_argument(self, key, args):
        if hasattr(args, key):
            return True
        self.parser.print_help()
        print("require %s" % key)
        sys.exit(1)

    def getEnv(self, name):
        v = os.environ.get(name)
        if not v:
            print("please set the environment variable %s" % name)
            sys.exit(1)
        return v

    def s2edir(self):
        return self.getEnv("S2EDIR")

    def execute(self, args):
        subprocess.run(args, check=True)

    def check_output(self, args):
        completed = subprocess.run(args, stdout=subprocess.PIPE)
        return completed.stdout

    def getFullPath(self, path, isdir=False):
        fullPath = os.path.abspath(path)
        if not os.path.exists(fullPath):
            logger.error("%s does not exist" % path)
            sys.exit(1)
        if isdir:
            if not os.path.isdir(fullpath):
                logger.error("%s is not dir" % path)
                sys.exit(1)
        return fullPath
        

class ProjectCommand(Command):
    def __init__(self, parser):
        super(ProjectCommand, self).__init__(parser)
        parser.add_argument("-p",
                            "--project",
                            dest='project',
                            required=True,
                            help="project path")
        self.project_dir = None

    def loads(self, path):
        if not os.path.exists(path):
            return None
        with open(path) as f:
            return json.load(f)

    def project_path(self, name):
        path = name
        if not os.path.isdir(path):
            # project name
            s2e_dir = self.s2edir()
            path = os.path.join(s2e_dir, "projects", path)
        return path

    def last_execution_file(self, filename):
        if self.project_dir is None:
            print("invalid project dir")
            exit(1)

        return os.path.join(self.project_dir, "s2e-last", filename)

    def project_file(self, filename):
        if self.project_dir is None:
            print("invalid project dir")
            exit(1)

        return os.path.join(self.project_dir, filename)

    def workdir_file(self, filename):
        workdir = self.getConfig("workdir")
        if workdir:
            return os.path.join(workdir, filename)
        # Default workdir is the project dir
        return self.project_file(filename)

    def project_config(self):
        path = self.project_file("project.json")
        return self.loads(path)

    def save_project_config(self, cfg):
        path = self.project_file("project.json")
        with open(path, "w") as f:
            json.dump(cfg, f, indent=4)

    def getConfig(self, key):
        cfg = self.project_config()
        if cfg is not None and key in cfg:
            return cfg[key]
        return None

    def getOption(self, key, default_value):
        opts = self.getConfig("options")
        if opts:
            if key in opts:
                return opts[key]
        return default_value
    
    def launch_s2e(self, output, timeout=600):
        with open(output, "w") as fp:
            logger.debug("launch s2e at %s" % self.project_dir)
            proc = subprocess.Popen([self.project_file("launch-s2e.sh")], stdout=fp, stderr=STDOUT, cwd=self.project_dir)
            ret = 0
            try:
                proc.communicate(timeout=timeout)
            except TimeoutExpired:
                logger.debug("launch s2e timeout")
                ret = RET_TIMEOUT
            except KeyboardInterrupt:
                logger.debug("Ctrl-C interrupt")
                ret = RET_INTERRUPT
            finally:
                if proc and proc.returncode is None:
                    parent = psutil.Process(proc.pid)
                    for child in parent.children(recursive=True):
                        child.kill()
                    proc.terminate()
                    proc.wait()
            return ret

    def run(self, args):
        self.project_dir = self.project_path(args.project)

