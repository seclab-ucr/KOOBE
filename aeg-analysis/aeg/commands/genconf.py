import angr
import re
import os
import json
import logging

from capstone.x86_const import X86_OP_MEM, X86_OP_IMM, X86_OP_REG

from aeg.command import Command, ProjectCommand
from aeg.commands.pahole import Pahole
from aeg.kernel import KernelObject, Kernel
from aeg.slapp import slpp as lua
from aeg.report import Report, SPOT_FUNC, SPOT_ADDR, SPOT_TYPE, SPOT_SIG
from aeg.util import find_vulnerable_object, find_vulnerablility_sites, findLayoutSyscall

logger = logging.getLogger(__name__)
boolean = lambda x: "true" if x else "false"

class genconfCommand(ProjectCommand):
    '''generate s2e config file'''

    def __init__(self, parser):
        super(genconfCommand, self).__init__(parser)
        parser.add_argument("-i",
                            "--image",
                            required=True,
                            action="store",
                            help="path to vmlinux")
        parser.add_argument("-m",
                            "--mode",
                            type=int,
                            default=1,
                            help="exploit analysis mode")
        parser.add_argument('-o',
                            "--object",
                            default=False,
                            action="store_true",
                            help="track object lifecycle")
        parser.add_argument('-a',
                            "--access",
                            default=False,
                            action="store_true",
                            help="track access to some objects")
        parser.add_argument('-r',
                            "--race",
                            type=int,
                            help="limit the number of races")
        parser.add_argument('-e',
                            "--exploit",
                            action="store_true",
                            default=False,
                            help="plugins for exploit")
        parser.add_argument("--trackroot",
                            default=False,
                            action="store_true",
                            help="check operations of kernel")
        parser.add_argument("--validate",
                            default=False,
                            action="store_true",
                            help="config for validation")
        parser.add_argument('-c',
                            "--concrete",
                            default=False,
                            action="store_true",
                            help="no symbolic values")
        parser.add_argument('-d',
                            "--debug",
                            default=False,
                            action="store_true",
                            help="debug constriant")
        parser.add_argument("--check_heap",
                            default=False,
                            action="store_true",
                            help="help to develop fengshui")
        parser.add_argument("--nosymalloc",
                            default=False,
                            action="store_true",
                            help="no symbolic allocation")
        parser.add_argument("--force",
                            default=False,
                            action="store_true",
                            help="force to reload")
        parser.add_argument("--syzkaller",
                            default=False,
                            action="store_true",
                            help="config for syzkaller")
        parser.add_argument("-s", "--source", help="syzkaller: source project")
        parser.add_argument("--smap",
                            default=False,
                            action="store_true",
                            help="enable smap")
        parser.add_argument("--pids", help="extra pids to track, separated with comma")

    def getMainPlugin(self, args):
        if args.exploit:
            return "KernelInstructionTracer"
        return "ObjectAnalyzer"

    def Disassembler(self):
        config = ''
        config += ("\n")
        config += ('add_plugin("Disassembler")\n')
        config += '''pluginsConfig.Disassembler = {
    logLevel = "debug"
}\n'''
        return config

    def ProgramMonitor(self):
        config = ''
        config += ('add_plugin("ProgramMonitor")\n')
        config += ('''pluginsConfig.ProgramMonitor = {
    loadstart = false
}\n''')
        return config

    def OptionPlugin(self, args, hasheader=True):
        if args.race:
            if args.mode == 2:
                args.concrete = True

        config = ''
        if hasheader:
            config += 'add_plugin("OptionsManager")\n'
        config += 'pluginsConfig.OptionsManager = {\n'
        config += ('''    -- execution mode
    mode = %d,\n''' % args.mode)
        config += '    racecondition = %s,\n' % boolean(args.race)
        if args.race:
            config += ('    racelimit = %d,\n' % args.race)
        else:
            config += ('    -- racelimit = 250,\n')
        config += '    -- track allocation and release of all object\n'
        config += '    track_object = %s,\n' % boolean(args.object
                                                       or args.validate)
        config += '    -- track access to symbolic pointers\n'
        config += '    trackaccess = %s,\n' % boolean(args.access)
        config += '    -- validate our new POC\n'
        config += '    validate = %s,\n' % boolean(args.validate)
        config += '    -- Dont have symbolic variable in the POC, fallback to KASAN\n'
        config += '    concrete = %s, \n' % boolean(args.nosymalloc)
        # other options
        config += '    -- smap = %s,\n' % boolean(args.smap)
        config += '}\n'
        return config

    def KernelInstructionTracer(self, kernel, args):
        config = ''
        config += ("\n")
        config += ('add_plugin("KernelInstructionTracer")\n')
        config += ('pluginsConfig.KernelInstructionTracer = ')
        reports = list()
        # if 2 <= args.mode <= 3 and not args.check_heap:
        if args.mode == 3 and not args.check_heap:
            report_file = self.workdir_file("reports.json")
            if os.path.exists(report_file):
                with open(report_file) as f:
                    reports = json.loads(f.read())
            else:
                print("Analyzing file %s..." % report_file)
                path = self.last_execution_file("debug.txt")
                reports = find_vulnerablility_sites(path, kernel, report_file, args.mode == 3)

        report = Report(reports, kernel)
        targets, exits, conditions, total_size = report.analyze()
        if args.mode == 2:
            # We are only interested in targets
            exits, conditions = list(), dict()
        if total_size > 4096:
            print("Too much overwritten data, need to check it?")
        data = dict()
        # targets
        data["targets"] = list()
        for each in targets:
            logger.debug("choose target 0x%x" % each[SPOT_ADDR])
            data["targets"].append(each[SPOT_ADDR])
        # exits
        data["exits"] = list()
        for each in exits:
            data["exits"].append(each)
        # conditions
        count = 0
        conds = dict()
        for tgt, cond in conditions:
            conds["con_%d" % count] = {"target": tgt, "condition": cond}
            count += 1
        data["conditions"] = conds
        # annotation
        data["annotations"] = {"fun_0": {"pc": 0x0, "onExecute": "track"}}
        # type -- 1: store 2: memset 3: strcpy 4: memcpy
        spots = dict()
        for i, spot in enumerate(targets):
            spot_cfg = {"addr": spot[SPOT_ADDR], "type": spot[SPOT_TYPE]}
            signature = spot[SPOT_SIG]
            if signature:
                spot_cfg["signature"] = signature
            spots["spot_%d" % i] = spot_cfg
        data["spots"] = spots
        data["debug"] = args.debug
        # syscalls
        syscalls = dict()
        addr = kernel.func_start("entry_SYSCALL_64")
        if addr != 0:
            syscalls["entry_SYSCALL_64"] = addr
        else:
            print("Failed to get address of entry_SYSCALL_64\n")
        data["syscall"] = syscalls
        data["workdir"] = self.getConfig("workdir")
        if data["workdir"] is None:
            data["workdir"] = self.project_dir
        config += lua.encode(data) + '\n'
        return config

    def Instrumentor(self, args):
        if args.source is None:
            raise ValueError("no source project provided")
        kernel = Kernel(args.image)
        source_cfg = self.loads(
            os.path.join(self.project_path(args.source), "project.json"))
        cfg = dict()
        cfg['workdir'] = self.getConfig("workdir")
        # cfg['sourcedir'] = self.project_path(args.source)
        cfg['logLevel'] = "debug"
        cfg['check_kasan'] = True

        vuln = self.loads(self.workdir_file("vuln.json"))
        if vuln['Symbolic']:
            cfg['vul_size'] = 0
        else:
            cfg['vul_size'] = Pahole.getSize(vuln['Size'])

        cfg['allocSite'] = vuln['Callsite']

        cfg['kasan'], cfg['kasan_ret'] = kernel.getKasanReport()
        cfg['repro'] = False
        cfg['ranges'] = []

        content = "add_plugin(\"Instrumentor\")\n"
        content += "pluginsConfig.Instrumentor = %s" % lua.encode(cfg)
        return content

    def AllocManager(self, args, kernel, vuln=None):
        config = ''
        alloc_func = [{
            'funcName': '__get_free_pages',
            'args': 2,
            'type': 1,
            'sizeArg': 1
        }, {
            'funcName': '__kmalloc',
            'args': 2,
            'type': 1,
            'sizeArg': 0
        }, {
            'funcName': '__kmalloc_track_caller',
            'args': 3,
            'type': 1,
            'sizeArg': 0
        }, {
            'funcName': 'kfree',
            'args': 1,
            'type': 2,
            'sizeArg': 0
        }, {
            'funcName': 'kmem_cache_free',
            'args': 2,
            'type': 2,
            'sizeArg': 1
        }, {
            'funcName': '__kmalloc_node_track_caller',
            'args': 4,
            'type': 1,
            'sizeArg': 0
        }, {
            'funcName': 'kmem_cache_alloc',
            'args': 2,
            'type': 3,
            'sizeArg': 0
        }, {
            'funcName': '__kmalloc_node',
            'args': 3,
            'type': 1,
            'sizeArg': 0
        }]

        cfg = dict()
        if vuln and not args.race:
            cfg["symbolicptr"] = True
            cfg["symbolic"] = {
                "obj_0": {
                    "callsite": vuln.Callsite,
                    "size": vuln.Size,
                }
            }

        funCfg = dict()
        for i, func in enumerate(alloc_func):
            symbol = kernel.find_symbol(func['funcName'])
            if symbol:
                func["address"] = symbol.rebased_addr
            funCfg["fun_%d" % i] = func
        cfg["functions"] = funCfg
        # object_size: size without metadata
        # size: size with padding/metadata
        cfg["slab_offset"] = kernel.getStructOffset("kmem_cache", "object_size")
        cfg["name_offset"] = kernel.getStructOffset("kmem_cache", "name")
        config += ('\n')
        config += ('add_plugin("AllocManager")\n')
        config += ('pluginsConfig.AllocManager = %s\n' % lua.encode(cfg))
        return config

    def KernelFunctionModels(self, args, kernel):
        config = ''
        if not os.path.exists("template/functions.json"):
            raise Exception("template/functions.json does not exist")

        with open("template/functions.json", "r") as f:
            data = json.load(f)
            kernel_func = data["model"]
            constraints = data["avoid"]
            skipFuncs = data["skip"]

        config += ("\n")
        config += '''add_plugin("KernelFunctionModels")
pluginsConfig.KernelFunctionModels = {
    functions = {},
    constraints = {},
    skips = {},
}
g_KernelFunctionModels_function = {}
g_KernelFunctionModels_constraint = {}
g_KernelFunctionModels_skip = {}
safe_load('kernelModels.lua')
pluginsConfig.KernelFunctionModels.functions = g_KernelFunctionModels_function
pluginsConfig.KernelFunctionModels.constraints = g_KernelFunctionModels_constraint
pluginsConfig.KernelFunctionModels.skips = g_KernelFunctionModels_skip
'''
        modelsPath = self.project_file("kernelModels.lua")
        if os.path.exists(modelsPath):
            return config

        g_KernelFunctionModels_function = dict()
        for i, func in enumerate(kernel_func):
            funCfg = dict()
            funCfg.update(func)
            symbol = kernel.find_symbol(func['funcName'])
            if symbol:
                funCfg["address"] = symbol.rebased_addr
            else:
                print("Failed to parse the function %s" % func['funcName'])
                continue
            g_KernelFunctionModels_function["fun_%d" % i] = funCfg

        g_KernelFunctionModels_constraint = dict()
        project_json = self.project_config()
        if "constraints" in project_json:
            constraints += project_json["constraints"]
        for i, c in enumerate(constraints):
            funCfg = {'funcName': c}
            symbol = kernel.find_symbol(c)
            if not symbol:
                print("Failed to parse the function %s" % c)
                continue
            else:
                funCfg["entry"] = symbol.rebased_addr
                funCfg["exit"] = symbol.rebased_addr + symbol.size - 1
            g_KernelFunctionModels_constraint["fun_%d" % i] = funCfg

        g_KernelFunctionModels_skip = dict()
        for i, c in enumerate(skipFuncs):
            funCfg = {'funcName': c}
            subconfig = ('        fun_%d = {\n' % i)
            symbol = kernel.find_symbol(c)
            if not symbol:
                print("Failed to parse the function %s" % c)
                continue
            else:
                funCfg["entry"] = symbol.rebased_addr
                funCfg["exit"] = symbol.rebased_addr + symbol.size - 1
            g_KernelFunctionModels_skip["fun_%d" % i] = funCfg

        with open(modelsPath, "w") as f:
            f.write("g_KernelFunctionModels_function = %s\n" %
                    lua.encode(g_KernelFunctionModels_function))
            f.write("g_KernelFunctionModels_constraint = %s\n" %
                    lua.encode(g_KernelFunctionModels_constraint))
            f.write("g_KernelFunctionModels_skip = %s\n" %
                    lua.encode(g_KernelFunctionModels_skip))

        return config

    def KernelAddressSanitizer(self, kernel):
        config = ''
        kasan_func = [
            'check_memory_region', '__asan_store1', '__asan_store2',
            '__asan_store4', '__asan_store8', '__asan_store16',
            '__asan_storeN', '__asan_load1', '__asan_load2', '__asan_load4',
            '__asan_load8', '__asan_load16', '__asan_loadN'
        ]
        Additional_checks = ['csum_partial_copy_generic']
        config += ("\n")
        config += ('add_plugin("KernelAddressSanitizer")\n')
        config += ('pluginsConfig.KernelAddressSanitizer = ')
        cfg = dict()
        funcsCfg = dict()
        for i, func in enumerate(kasan_func):
            funcCfg = dict()
            name = "fun_%d" % i
            symbol = kernel.find_symbol(func)
            if not symbol:
                print("Cannot find symbol for %s" % func)
                continue
            else:
                funcCfg["funcName"] = func
                funcCfg["entry"] = symbol.rebased_addr
                funcCfg["exit"] = symbol.rebased_addr + symbol.size - 1
            funcsCfg[name] = funcCfg
        cfg["functions"] = funcsCfg
        checks = dict()
        for func in Additional_checks:
            symbol = kernel.find_symbol(func)
            if not symbol:
                print("Cannot find symbol for %s" % func)
                continue
            else:
                checks[func] = symbol.rebased_addr
        cfg["checks"] = checks
        cfg["kasan_report"], cfg["kasan_ret"] = kernel.getKasanReport()
        config += lua.encode(cfg)
        config += ('\n')
        return config

    def PcMonitor(self, args, kernel):
        data = dict()
        data["recordTrace"] = False
        data["trackroot"] = args.trackroot
        kasan_report, _ = kernel.getKasanReport()
        if kasan_report:
            data["kasan_report"] = kasan_report
        else:
            print("Failed to parse kasan report\n")
        data["pid_offset"] = kernel.getStructOffset("task_struct", "pid")
        data["tgid_offset"] = kernel.getStructOffset("task_struct", "tgid")
        data["limitcount"] = 300000
        data["debuginst"] = False
        data["hookadc"] = False
        if args.pids:
            pids = [int(each) for each in args.pids.split(',')]
            data["pids"] = pids

        config = ''
        config += ("\n")
        config += ('add_plugin("PcMonitor")\n')
        config += ('pluginsConfig.PcMonitor = %s\n' % lua.encode(data))
        return config

    def ObjectAnalyzer(self, kernel):
        # TODO: add information about the memory layout we want
        config = ''
        config += ("\n")
        config += ('add_plugin("ObjectAnalyzer")\n')
        config += ('pluginsConfig.ObjectAnalyzer = {\n')
        # conditions
        config += ('    conditions = {\n')
        config += ('    },\n')
        # syscalls
        config += ('    syscall = {\n')
        symbol = kernel.find_symbol("entry_SYSCALL_64")
        if symbol:
            config += ('        entry_SYSCALL_64 = 0x%x,\n' %
                       symbol.rebased_addr)
        else:
            config += ('        -- entry_SYSCALL_64 = ?,\n')
        config += ('    }\n')
        config += ('}\n')
        return config

    def addfunction(self, args):
        refine = '''function track(state, pc)
--     plg = g_s2e:getPlugin("%s")
--     local addr = plg:readRegister(state, "r12")
--     plg:findObject(state, addr)
end\n''' % self.getMainPlugin(args)

        return refine

    def loadconfig(self, filename):
        path = self.project_file(filename)
        backup = self.project_file(filename + ".backup")
        if os.path.exists(backup):
            path = backup
        with open(path) as f:
            content = ''.join(f.readlines())
            if not os.path.exists(backup):
                with open(backup, "w") as f:
                    f.write(content)
            return content

    def saveconfig(self, content, filename):
        path = self.project_file(filename)
        with open(path, 'w') as f:
            f.write(content)

    def getPluginConfig(self, name, content, hasheader=True):
        try:
            start = content.index("pluginsConfig.%s" % name)
            index = content.index('{', start)
            if not hasheader:
                start = index
            count = 1
            for i in range(index + 1, len(content)):
                if content[i] == '{':
                    count += 1
                elif content[i] == '}':
                    count -= 1
                if count == 0:
                    return content[start:i + 1]
        except ValueError as e:
            pass
        return None

    def remove_plugins(self, content, to_be_removed):
        plugins = re.findall('add_plugin\\(\"(\S+)\"\\)', content)
        for plugin in plugins:
            try:
                if plugin not in to_be_removed:
                    continue
                index = content.index('add_plugin(\"%s\")' % plugin)
                content = content[:index] + "-- " + content[index:]
            except ValueError as e:
                pass
        return content

    def patch_plugins(self, content):
        try:
            index = content.index("pluginsConfig.%s" %
                                  "ModuleExecutionDetector")
            index = content.index('{', index)
            content = content[:index + 1] + '''\n    mod_1 = {
        moduleName = "vmlinux",
        kernelMode = true,
    },\n''' + content[index + 1:]
        except ValueError as e:
            pass
        return content

    def patch_launch(self, args):
       content = self.loadconfig("launch-s2e.sh")
       replacement = "export S2E_CONFIG=${ENV_DIR}/projects/%s/s2e-config.lua" % args.project
       content = content.replace("export S2E_CONFIG=s2e-config.lua",
                                 replacement, 1)
       content = content.replace("QEMU_MEMORY=", "QEMU_MEMORY=1024M #", 2)
       if args.syzkaller:
           content = content.replace(
               "-serial file:serial.txt",
               "-serial stdio -net user,host=10.0.2.10", 2)
       self.saveconfig(content, "launch-s2e.sh")

    def patch_bootstrap(self, args):
        if not args.force and os.path.exists(
                self.project_file("bootstrap.sh.backup")):
            return
        content = self.loadconfig("bootstrap.sh")

        if args.syzkaller:
            replacement = '''set -x
sudo ip link set enp0s3 up
sudo /sbin/dhclient'''
            content = content.replace("set -x", replacement, 1)
            replacement = 'execute "{{TARGET}}"'
            content = content.replace('execute "./syz-fuzzer"', replacement, 1)
            replacement = "sudo ./${TARGET} 2>&1"
            content = content.replace("./${TARGET}  > /dev/null 2> /dev/null",
                                      replacement, 1)
            replacement = "# sudo swapoff -a"
            content = content.replace("sudo swapoff -a", replacement, 1)
            # 			replacement = '''${S2EGET} "syz-fuzzer"
            # ${S2EGET} "syz-executor"
            # ${S2EGET} "syz-execprog"'''
            content = content.replace('${S2EGET} "syz-fuzzer"', "{{GETFILE}}",
                                      1)
            content = content.replace('prepare_target "${TARGET}"',
                                      "# prepare_target", 1)

        if args.syzkaller:
            path = self.project_file("bootstrap.sh.template")
        else:
            path = self.project_file("bootstrap.sh")
        with open(path, 'w') as f:
            f.write(content)

    def copy_template(self, filename):
        path = self.project_file(filename)
        if os.path.exists(path):
            return

        template_path = os.path.join("template", filename)
        if not os.path.exists(template_path):
            print("not in the same directory of template")
            exit(1)
        with open(template_path) as finput, open(path, "w") as foutput:
            for line in finput:
                foutput.write(line)

    def patch_candidate(self):
        filename = "candidates.lua"
        path = self.project_file(filename)
        if os.path.exists(path):
            return

        template_path = os.path.join("template", filename)
        if not os.path.exists(template_path):
            print("not in the same directory of template")
            exit(1)
        if not os.path.exists(filename):
            print("Please use command pahole to generate targets first")
            exit(1)
        with open(template_path) as finput, \
          open(filename) as fobject,  \
          open(path, "w") as foutput:
            content = finput.read()
            targets = fobject.read()
            content = content.replace("{{TARGET_OBJECTS}}", targets)
            foutput.write(content)

    def validate(self, args):
        path = self.project_file("s2e-config.lua")
        with open(path) as f:
            content = f.read()
            plugin_cfg = self.getPluginConfig("OptionsManager", content)
            new_cfg = self.OptionPlugin(args, hasheader=False)
            index = content.index(plugin_cfg)
            content = content[:index] + new_cfg + content[index +
                                                          len(plugin_cfg):]

        self.saveconfig(content, "s2e-config.lua")

    def exploit(self, args):
        content = self.loadconfig("s2e-config.lua")

        to_be_removed = [
            "ExecutionTracer", "ModuleTracer", "TranslationBlockCoverage",
            "StaticFunctionModels", "LuaCoreEvents", "MultiSearcher",
            "CUPASearcher", "TestCaseGenerator"
        ]
        content = self.remove_plugins(content, to_be_removed)
        content = self.patch_plugins(content)

        kernel = Kernel(args.image)
        content += '\n\n'
        content += self.OptionPlugin(args)
        content += self.Disassembler()
        content += self.ProgramMonitor()
        content += self.PcMonitor(args, kernel)
        content += self.KernelAddressSanitizer(kernel)

        if args.mode == 4:
            # TODO: copy cap file
            path = self.workdir_file("layout.json")
            if not os.path.exists(path):
                layout = findLayoutSyscall(
                    self.last_execution_file('debug.txt'),
                    self.work_file("layout.json"))

        if args.mode != 1 and not args.nosymalloc:
            # try to parse the log file and extract information of the vul object
            vuln_path = self.workdir_file("vuln.json")
            if os.path.exists(vuln_path):
                content += self.AllocManager(args, kernel,
                                             KernelObject.load(vuln_path))
            else:
                path = self.last_execution_file('debug.txt')
                item = find_vulnerable_object(path, vuln_path)
                content += self.AllocManager(args, kernel, item)
        else:
            content += self.AllocManager(args, kernel)
        content += self.KernelFunctionModels(args, kernel)
        if args.exploit:
            content += self.KernelInstructionTracer(kernel, args)
        else:
            content += self.ObjectAnalyzer(kernel)
        content += self.addfunction(args)
        content += ('dofile(\'candidates.lua\')\n')

        if args.verbose:
            print(content)
            exit(1)

        self.patch_candidate()

        self.saveconfig(content, "s2e-config.lua")

        self.patch_bootstrap(args)

    def addPluginConfig(self, plugin, content):
        cfg = "\npluginsConfig.%s = {}" % plugin
        index = None
        try:
            s = "add_plugin(\"%s\")" % plugin
            index = content.index(s) + len(s)
            content = content[:index] + cfg + content[index:]
            return content
        except ValueError as e:
            try:
                s = "pluginsConfig = {}"
                index = content.index(s) + len(s)
                content = content[:index] + cfg + content[index:]
                return content
            except ValueError as e:
                raise e
        return content

    def addEntryToPlugin(self, content, plugin, key, value):
        cfg = self.getPluginConfig(plugin, content, hasheader=False)
        if not cfg:
            content = self.addPluginConfig(plugin, content)
            return self.addEntryToPlugin(content, plugin, key, value)

        data = lua.decode(cfg)
        data[key] = value
        new_cfg = lua.encode(data)
        new_cfg = "pluginsConfig.%s = %s" % (plugin, new_cfg)
        try:
            cfg = self.getPluginConfig(plugin, content, hasheader=True)
            index = content.index(cfg)
            content = content[:index] + new_cfg + content[index + len(cfg):]
            return content
        except ValueError as e:
            pass
        return content

    def syzkaller(self, args):
        content = self.loadconfig("s2e-config.lua")

        to_be_removed = [
            "MemUtils", "ExecutionTracer", "ModuleTracer",
            "TranslationBlockCoverage", "StaticFunctionModels",
            "LuaCoreEvents", "MultiSearcher", "CUPASearcher",
            "TestCaseGenerator", "WebServiceInterface",
            "ModuleExecutionDetector", "ForkLimiter",
            "ProcessExecutionDetector", "ModuleMap", "MemoryMap",
            "StaticFunctionModels", "LinuxMonitor", "KeyValueStore",
            "LuaBindings"
        ]
        content = self.remove_plugins(content, to_be_removed)
        replacement = "dofile('%s')" % self.project_file('library.lua')
        content = content.replace("dofile('library.lua')", replacement, 1)
        replacement = "safe_load('%s')" % self.project_file('models.lua')
        content = content.replace("safe_load('models.lua')", replacement, 1)
        try:
            index = content.index("pluginsConfig.HostFiles = {")
            index = content.index("baseDirs = {", index) + len("baseDirs = {")
            syzkaller_path = os.path.join(
                self.getEnv("GOPATH"),
                "src/github.com/google/syzkaller/bin/linux_amd64")
            content = content[:index] + ('\n        "%s",' %
                                         syzkaller_path) + content[index:]
        except ValueError as e:
            pass
        for plugin in ["HostFiles", "BaseInstructions", "Vmi", "CorePlugin"]:
            content = self.addEntryToPlugin(content, plugin, "logLevel",
                                            "none")
        content = self.addEntryToPlugin(content, "Vmi", "modules", dict())
        content = self.addEntryToPlugin(content, "BaseInstructions",
                                        "restrict", False)

        content += '\n\n'
        content += self.Disassembler()
        content += self.Instrumentor(args)
        self.saveconfig(content, "s2e-config.lua")

        self.patch_bootstrap(args)
        

    def run(self, args):
        super(genconfCommand, self).run(args)
        if args.image:
            fullpath = os.path.abspath(args.image)
            project_json = self.project_config()
            project_json["vmlinux"] = fullpath
            self.save_project_config(project_json)
            args.image = fullpath

        if args.race:
            args.nosymalloc = True

        if args.check_heap:
            args.mode = 2
            args.exploit = True
            args.object = True
            args.trackroot = True
            args.nosymalloc = True

        if args.mode != 1 and args.exploit is None:
            setattr(args, 'exploit', True)

        if not args.exploit:
            setattr(args, 'object', True)

        self.patch_launch(args)

        if args.validate:
            args.mode = 3
            self.validate(args)
            return

        if args.exploit:
            self.exploit(args)
            return

        if args.syzkaller:
            self.syzkaller(args)
            return

        print("Done")

