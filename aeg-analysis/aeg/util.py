
import os
import logging
import json
import shlex
import subprocess

from aeg.kernel import KernelObject

logger = logging.getLogger(__name__)

def create_project(name, image, binary, force=True):
    source = "source %s/%s/bin/activate" % (os.environ.get("WORKDIR"), os.environ.get("KOOBE"))
    cmds = ["s2e", "new_project", "-n", name, "-i", image]
    if force:
        cmds += ["-f"]
    cmds += [binary]
    commands = shlex.split('/bin/bash -c "%s && %s"' % (source, " ".join(cmds)))
    logger.debug("create new project: %s" % " ".join(cmds))
    subprocess.run(commands, check=True)

def findSolutions(filepath):
    solutions = list()
    with open(filepath) as f:
        content = f.readlines()
        i = 0
        total = 0
        while i < len(content):
            line = content[i]
            if 'KernelInstructionTracer: {"solution' in line:
                index = line.index('{"solution')
                line = line[index:]
                succeed = False
                while not succeed:
                    try:
                        solution = json.loads(line)
                        succeed = True
                    except Exception as e:
                        i += 1
                        line += content[i]
                solutions.append(solution)
            i += 1

    logger.debug("Totoal : %d" % len(solutions))
    return solutions


def genSolution(solutions, layout, vulnObj, outdir, version="4.9.3"):
    for solution in solutions:
        solution.update(layout)
        allocator = vulnObj["Allocator"]
        if allocator == "slab":
            allocator = "kmalloc_%d" % solution["size"]
        solution["allocVuln"] = allocator
        solution["version"] = version
        if "solutions" in solution and len(solution["solutions"]) == 1:
            solution["solution"] = solution["solutions"][0]
            del solution["solutions"]
        solution_path = os.path.join(outdir, "ans_%s.json" % solution["target"])
        logger.debug("Find one target %s" % solution["target"])
        with open(solution_path, "w") as output:
            json.dump(solution, output)


def findLayoutSyscall(filepath, output=None):
    with open(filepath) as f:
        ret = dict()
        for line in f:
            if "[LAYOUT]" in line:
                item = KernelObject("[LAYOUT]", line)
                ret.update(item.json)
            if "[SYSCALLS]" in line:
                item = KernelObject("[SYSCALLS]", line)
                ret.update(item.json)
        if output:
            with open(output, "w") as out:
                json.dump(ret, out)
        return ret
    return None

def find_vulnerablility_sites(output, kernel, filepath, save=True):
    if not os.path.isfile(output):
        logger.error("%s does not exist" % output)
        return []

    reports = list()
    with open(output, "r") as fp:
        for line in fp:
            if "[KASAN]" in line:
                try:
                    item = KernelObject("[KASAN]", line)
                    reports.append(item.json)
                except:
                    continue
        for report in reports:
            ips = report["ip"]
            if len(ips) <= 1:
                raise Exception("Callstack is not recovered completely")
    if save:
        with open(filepath, "w") as fp:
            json.dump(reports, fp)
    return reports

def find_vulnerable_object(output,  filepath):
    if not os.path.isfile(output):
        logger.error("%s does not exist" % output)
        return None

    with open(output, "r") as fp:
        counter = 0
        for line in fp:
            if "[KASAN]" in line:
                item = KernelObject("[KASAN]", line)
                logger.debug(item.json)
                counter += 1
            if "[KASAN-CONFIRM]" in line:
                item = KernelObject("[KASAN-CONFIRM]", line)
                logger.debug(item.json)

            if "[Busy Object]" in line:
                item = KernelObject("[Busy Object]", line)
                item.save(filepath)
                logger.debug(str(item))
                if counter > 1:
                    logger.warning("Observe %d KASAN report before it, please found the root cause" % (counter - 1))
                return item

        if counter > 0:
            raise Exception("Observe %d KASAN report but failed to locate the vuln object" % counter)

    raise Exception("Failed to find the vulnerable object!")

