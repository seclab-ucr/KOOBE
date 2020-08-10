import os
import json

from aeg.command import Command


class patchCommand(Command):
    '''patch linux source code'''

    def __init__(self, parser):
        super(patchCommand, self).__init__(parser)
        parser.add_argument("-d",
                            "--dest",
                            required=True,
                            help="destination Linux source code")
        parser.add_argument("-c", "--config", help="config json file")

    def loadfile(self, path):
        with open(path) as f:
            return f.read()

    def savefile(self, path, content):
        with open(path, "w") as f:
            f.write(content)

    def insert_before(self, content, match_str, insert_str):
        try:
            index = content.index(match_str)
            content = content[:index] + insert_str + content[index:]
            return content
        except ValueError as e:
            return None

    def insert_after(self, content, match_str, insert_str):
        try:
            index = content.index(match_str)
            if not match_str.endswith('\n'):
                index = content.index('\n', index + len(match_str))  # new line
                content = content[:index + 1] + insert_str + content[index +
                                                                     1:]
                return content
            content = content[:index + len(match_str)] + insert_str + content[
                index + len(match_str):]
            return content
        except ValueError as e:
            return None

    def replace(self, content, match_str, replace_str):
        try:
            index = content.index(match_str)
            content = content[:index] + replace_str + content[index +
                                                              len(match_str):]
            return content
        except ValueError as e:
            return None

    def insert_between(self, content, before_str, after_str, insert_str):
        try:
            start, end = 0, len(content)
            count = 10
            while end > start + len(
                    before_str) + 5 and count != 0:  # extra characters
                start = content.index(before_str, start + len(before_str))
                end = content.index(after_str, start)
                count -= 1
            if count == 0:
                return None
            if not before_str.endswith('\n'):
                start = content.index('\n', start + len(before_str))
                content = content[:start + 1] + insert_str + content[start +
                                                                     1:]
                return content
            content = content[:start + len(before_str)] + insert_str + content[
                start + len(before_str)]
            return content
        except ValueError as e:
            return None

    def patch_kconfig(self, path):
        filename = os.path.join(path, "arch", "x86", "Kconfig")
        content = self.loadfile(filename)
        toAdd = 'source "kernel/s2e/Kconfig"'
        if toAdd in content:
            return
        content += "\n%s\n" % toAdd
        self.savefile(filename, content)

    def patch_config(self, path):
        filename = os.path.join(path, '.config')
        content = self.loadfile(filename)
        content += '\nCONFIG_DEBUG_INFO=y\n'
        content += 'CONFIG_KASAN_INLINE=y\n'
        content += 'CONFIG_KASAN=y\n'
        content += 'CONFIG_HAVE_ARCH_KASAN=y\n'
        content += 'CONFIG_USER_NS=y\n'

    def run(self, args):
        fullpath = os.path.abspath(args.dest)
        prefix = os.path.join(self.s2edir(), "source", "s2e", "s2e-linux-kernel")
        self.patch_kconfig(args.dest)
        # default filepath
        config_filepath = os.path.join(prefix, "config.json")
        if args.config:
            config_filepath = args.config

        with open(config_filepath, "r") as f:
            config = json.loads(f.read())
            for filename, ops in config["files"].items():
                filepath = os.path.join(fullpath, filename)
                print("patching %s... " % filepath)
                if not os.path.exists(filepath):
                    print("Can not found the file")
                    continue
                content = self.loadfile(filepath)
                for op in ops:
                    if op['op'] == "insert_before":
                        content = self.insert_before(content,
                                                     op['context_before'],
                                                     op['content'])
                    elif op['op'] == "insert_after":
                        content = self.insert_after(content,
                                                    op['context_after'],
                                                    op['content'])
                    elif op['op'] == "replace":
                        content = self.replace(content, op['context'],
                                               op['content'])
                    elif op['op'] == "insert_between":
                        content = self.insert_between(content,
                                                      op['context_before'],
                                                      op['context_after'],
                                                      op['content'])
                    if content is None:
                        print("patch %s failed: " % filepath, op)
                        break
                if content is not None:
                    self.savefile(filepath, content)
