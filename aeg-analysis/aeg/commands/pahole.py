import re
import subprocess
import json
import os

from aeg.command import Command

######################## Helper functions ########################
DEBUG = False ### set this to True to see output from pdebug
def pdebug(*args, **kwargs):
    if not DEBUG:
        return
    print( "[DEBUG] "+" ".join(map(str,args)), **kwargs)
def perror(*args, **kwargs):
    raise Exception("[ERROR] "+" ".join(map(str,args)), **kwargs)
##################################################################

class CommonStruct:
    def __init__(self, name, lines, pahole):
        self._pahole = pahole
        self._fields = list()
        self._type = name
        self._name = ''
        self._offset = -1
        self._size = 0

        line = lines[-1].strip()
        m = re.search('(.+)/\*\s(.+)\s+\*/', line)
        if not m:
            return
        offsetInfo = m.group(2).strip()
        cols = offsetInfo.split()
        if len(cols) == 2:
            try:
                if cols[0].find(":") >= 0:
                    self._offset = int(cols[0][0:cols[0].find(":")])
                    self._size = int(cols[1])
                else:
                    self._offset = int(cols[0])
                    self._size = int(cols[1])
            except ValueError:
                perror("[ERROR] Bad format in line: `"+line+"`")
        elif len(cols) == 1:
            self._size = int(cols[0])
        elif len(cols) == 3:
            try:
                self._offset = int(cols[0][0:cols[0].rfind(':')])
                self._size = int(cols[2])
            except:
                perror("Bad format in line: `"+line+"`")
        else:
            perror("[ERROR] Unknown format in line: `"+line+"`")

    def getOffsetInfo(self):
        return self._offset, self._size

    def isVariable(self):
        if len(self._fields) == 0:
            return False
        return self._fields[-1].isVariable()

    def hasFunctionPointer(self, recursive=4):
        if recursive == 0:
            return False
        for field in self._fields:
            if field.hasFunctionPointer(recursive):
                return True
        return False

    def hasReferCounter(self, index=0):
        if index == -1:
            for field in self._fields:
                if field.hasReferCounter(index):
                    return True
            return False
        if 0 <= index < len(self._fields):
            if self._fields[index].hasReferCounter(index):
                return True
        return False

    def getRepr(self, showFunc=True, indent=0, recursive=2):
        content = "%s %s:\n" % (self._type, self._name)
        if recursive == 0:
            return content

        for field in self._fields:
            if showFunc:
                content += "%s%s%s\n" % (
                    " " * 4 * indent, "[*] " if field.hasFunctionPointer() else
                    "    ", field.getRepr(showFunc, indent + 1, recursive - 1))
            else:
                content += "    %s\n" % str(field)
        return content

    def getStructType(self):
        return self._name

    def getCandidates(self, offset=0):
        items = list()
        origin_offset = offset
        # offset = 0
        for field in self._fields:
            off, size = field.getOffsetInfo()
            # print(off, size, offset)
            if off != -1:
                offset = off + origin_offset
            if field.hasFunctionPointer():
                # gen a target
                items += field.getCandidates(offset)
            if field.hasReferCounter(-1):
                items += field.getCandidates(offset)
            offset += size
        return items


class Union(CommonStruct):
    def __init__(self, lines, pahole):
        super(Union, self).__init__("Union", lines, pahole)

        content = None
        start = False
        count = 0
        for line in lines[1:-1]:
            if start:
                content.append(line)
                if '{' in line:
                    count += 1
                if '}' in line:
                    count -= 1
                if count == 0:
                    start = False
                    self._fields.append(Struct(content, self._pahole))
                continue
            if not start and line.strip() == "struct {":
                content = [line]
                start = True
                count = 1
                continue
            if ';' in line:
                self._fields.append(Field(line, self._pahole))

    def __str__(self):
        return "Union"


Type2Int = {"refcnt": 1, "pointer": 2, "function": 3}
Type2Values = {
    "refcnt": '\\x01\\x00\\x00\\x00',
    "pointer": '\\x00\\x00\\x00\\x00\\x00\\x80\\xff\\xff',
    "function": '\\x00\\x00\\x00\\x00\\xff\\xff\\xff\\xff'
}


class Enum(CommonStruct):
    def __init__(self, lines, pahole):
        super(Enum, self).__init__("Enum", lines, pahole)
        self._name = "enum"


class Field:
    def __init__(self, line, pahole):
        self._pahole = pahole
        self._isPointer = False
        self._reference = None
        self._isFunction = False
        self._variableSize = False
        self._referCounter = False
        self._needResolve = None
        self._offset = -1
        self._size = 0

        line = line.strip()
        if DEBUG:
            self._line = line
        m = re.search('(.+)/\*\s(.+)\s+\*/', line)
        if m is None:
            self._type = "Alignment"
            self._name = line[0:line.find(" ")]
            self._reference = None
            pdebug("Encountered alignment declaration with line: `"+line+"`")
            return
        
        define = m.group(1).strip()
        offsetInfo = m.group(2).strip()
        cols = offsetInfo.split()
        if ':' in offsetInfo:
            self._size = int(cols[-1])
        else:
            if len(cols) == 2:
                self._offset = int(cols[0])
                self._size = int(cols[1])
            elif len(cols) == 1:
                self._size = int(cols[0])
            else:
                perror("Error")
        if '*' in define:
            self._isPointer = True
        if define[define.find(" "):].strip().startswith("(*"):
            self._type = "Function"
            self._name = ' '.join(define.split())
            self._isFunction = True
        else:
            if define.endswith(';'):
                define = define[:-1]
            cols = define.split()
            self._type = ' '.join(cols[:-1])
            self._name = cols[-1]
            for i, each in enumerate(cols):
                if each == 'struct':
                    name = cols[i + 1]
                    self._reference = self._pahole.find(name)
                    if self._reference is None:
                        self._needResolve = name

            if '[0]' in self._name:
                self._variableSize = True
            if cols[0] in ['atomic_t', 'refcount_t']:
                self._referCounter = True

    def getOffsetInfo(self):
        return self._offset, self._size

    def isVariable(self):
        return self._variableSize

    def resolve(self):
        if self._needResolve:
            self._reference = self._pahole.find(self._needResolve)
            if self._reference is not None:
                self._needResolve = None

    def hasFunctionPointer(self, recursive=4):
        self.resolve()

        if self._isFunction:
            return True
        if recursive == 0:
            return False
        if recursive and self._reference:
            return self._reference.hasFunctionPointer(recursive - 1)
        return False

    def hasReferCounter(self, index):
        # self.resolve()

        if self._referCounter:
            return True
        # if not self._isPointer and self._reference:
        # 	if self._reference.hasReferCounter(index):
        #		return True
        return False

    def getCandidates(self, offset=0):
        self.resolve()

        # if offset != 0 :
        # 	return []
        # print(self._type + ' ' + self._name)
        if self._referCounter:
            return [{
                'offset': offset,
                'payload': '\\x00',
                'type': "refcnt",
                "field": self.getFieldName()
            }]
        if self._isFunction:
            return [{
                'offset': offset,
                'payload': '\\xef\\xbe\\xad\\xde\\xef\\xbe\\xad\\xde',
                'type': "function",
                "field": self.getFieldName()
            }]
        if self._isPointer and self._reference:
            return [{
                'offset': offset,
                'payload': '\\x40\\x10\\x80\\x76\\x00\\x80\\xff\\xff',
                'type': "pointer",
                "field": self.getFieldName()
            }]
        if not self._isPointer and self._reference:
            return self._reference.getCandidates(offset)
        return []

    def getFieldName(self):
        if self._isFunction:
            if "()" in self._name:
                # special function declaration
                return self._name.split()[-1]
            start = self._name.index('(*')
            end = self._name.index(')')
            return self._name[start+2:end]
        return self._name

    def getRepr(self, showFunc=True, indent=0, recursive=2):
        self.resolve()
        # content = '%s %s' % (self._type, self._name)
        content = '%s %s %d %d' % (self._type, self._name, self._offset,
                                   self._size)
        if recursive and self._reference and self.hasFunctionPointer():
            content += "\n%s%s" % (" " * 4 * indent,
                                   self._reference.getRepr(
                                       showFunc, indent, recursive))
        return content

    def __str__(self):
        return self._type + ' ' + self._name


class Struct(CommonStruct):
    def __init__(self, lines, pahole):
        super(Struct, self).__init__("struct", lines, pahole)

        m = re.search("struct (.+) {", lines[0])
        if m:
            self._name = m.group(1)
        else:
            self._name = "Anonymous"
        self._fields = list()
        content = None
        start = False
        count = 0
        structype = None
        for line in lines[1:-1]:
            line = line.strip()
            if start:
                content.append(line)
                if '{' in line:
                    count += 1
                if '}' in line:
                    count -= 1
                if count == 0:
                    start = False
                    if structype == "union":
                        self._fields.append(Union(content, self._pahole))
                    elif structype == "struct":
                        self._fields.append(Struct(content, self._pahole))
                    elif structype == "enum":
                        self._fields.append(Enum(content, self._pahole))
                continue
            if not start:
                found = False
                if line == "union {":
                    found = True
                    structype = "union"
                elif line == "struct {":
                    found = True
                    structype = "struct"
                elif line == "enum {":
                    found = True
                    structype = "enum"
                if found:
                    content = [line]
                    start = True
                    count = 1
                    continue
            if ';' in line:
                self._fields.append(Field(line, self._pahole))

    def getName(self):
        return self._name

    def __str__(self):
        content = "struct %s:\n" % self._name
        for field in self._fields:
            content += "    %s\n" % str(field)
        return content


class Pahole:
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

    def __init__(self, vmlinux):
        self._vmlinux = vmlinux
        self._bins = dict()
        self._structs = dict()
        self._special = dict()
        self._callchain = dict()

    @staticmethod
    def getSize(size):
        ret = 8192
        if size > 8192:
            return (size + 8191) // 8192
        for v in Pahole.Caches:
            if v >= size and v < ret:
                ret = v
        return ret

    def getStructSize(self, _name):
        for size, objs in self._bins.items():
            for name, orig_size in objs:
                if name == _name:
                    return orig_size
        return 0

    def getStructRoundSize(self, name):
        return self.getSize(self.getStructSize(name))

    def find(self, name):
        if name in self._structs:
            return self._structs[name]
        return None

    def analyzeSize(self):
        complete = subprocess.run(["pahole", "-s", "--structs", self._vmlinux],
                                  stdout=subprocess.PIPE)
        total_num_obj = 0
        for line in complete.stdout.split(b'\n'):
            cols = line.split()
            if len(cols) != 3:
                continue
            name, size, holes = str(cols[0],
                                    'utf-8'), int(cols[1]), int(cols[2])
            esize = self.getSize(size)
            if esize not in self._bins:
                self._bins[esize] = list()
            self._bins[esize].append((name, size))
            total_num_obj += 1
        pdebug("Found %d objects in size analysis!" % total_num_obj)

    def analyzeType(self):
        complete = subprocess.run(["pahole", "--structs", self._vmlinux],
                                  stdout=subprocess.PIPE)
        start = False
        content = None
        for line in complete.stdout.split(b'\n'):
            line = str(line, 'utf-8')
            if not start and line.startswith("struct "):
                start = True
                content = [line]
                continue
            if start:
                m = re.search("\}( ?__attribute__\((.+)\))?\;", line)
                #if line.startswith('};'):
                if m is not None and len(line) > 0:
                    struct = Struct(content, self)
                    self._structs[struct.getName()] = struct
                    start = False
                    if struct.isVariable():
                        self._special[struct.getName()] = struct
                else:
                    if len(line) > 0:
                        content.append(line)
        pdebug("Found %d objects in type analysis!" % len(self._structs))

    def getOffsetInfo(self, className):
        complete = subprocess.run(["pahole", "-C", className, self._vmlinux],
                                  stdout=subprocess.PIPE)
        content = list()
        lines = complete.stdout.split(b'\n')
        for line in lines[1:-1]:
            line = str(line, 'utf-8').strip()
            m = re.search('(.+)/\*\s+(\d+)\s+(\d+)\s+\*/', line)
            if m:
                content.append((m.group(1), int(m.group(2)), int(m.group(3))))
        return content

    def search(self, args):
        targets = list()

        if args.size:
            size = self.getSize(args.size)
            if size not in self._bins:
                return
            for name, _ in self._bins[size]:
                struct = self._structs[name]
                targets.append(struct)
            for name, struct in self._special.items():
                if self.getStructSize(name) < size:
                    targets.append(struct)
        elif args.clazz:
            struct = self.find(args.clazz)
            if struct:
                targets.append(struct)
        else:
            for size, objs in self._bins.items():
                for name, _ in objs:
                    struct = self._structs[name]
                    targets.append(struct)

        targets = self.filter(targets, args)
        recursive = 2
        if args.recursive:
            recursive = args.recursive

        results = list()

        known_objs = list()
        if args.known:
            with open("template/known.json") as f:
                known_objs = json.load(f)
                known_objs = known_objs["target"]

        for struct in targets:
            items = struct.getCandidates()
            if len(items) == 0:
                continue
            counter = 0
            found = False
            for item in items:
                typ = item['type']
                if args.filter_counter and typ != 'refcnt':
                    continue
                if args.filter_function and typ != 'function':
                    continue
                if args.filter_offset is not None and item[
                        'offset'] != args.filter_offset:
                    continue
                if len(known_objs) != 0:
                    found = False
                    for name, fields in known_objs.items():
                        if struct.getName() != name:
                            continue
                        if item['field'] not in fields:
                            continue
                        found = True
                    if not found:
                        continue

                item['values'] = Type2Values[typ]
                item['type'] = Type2Int[typ]
                item['name'] = '%s_%s' % (struct.getName(), item['field'])
                item['size'] = self.getStructRoundSize(struct.getName())
                item['variable'] = struct.isVariable()
                counter += 1
                results.append(item)
                found = True
            if not found:
                continue
            if args.quiet:
                print(struct.getName())
            else:
                print(struct.getRepr(showFunc=True, recursive=recursive))
            if args.verbose and args.filter_syscall:
                print(self._callchain[struct.getName()])

        # heap metadata
        for v in Pahole.Caches:
            if v > 2048:
                continue
            item = dict()
            item['type'] = Type2Int["pointer"]
            item['size'] = v
            item['name'] = 'kmalloc_%d' % v
            item['variable'] = False
            item['values'] = Type2Values["pointer"]
            item['payload'] = '\\x40\\x10\\x80\\x76\\x00\\x80\\xff\\xff'
            item['offset'] = 0
            item['field'] = "freelist"
            results.append(item)

        with open('targets.json', 'w') as f:
            json.dump(results, f)
        with open('candidates.lua', 'w') as f:
            f.write('TargetObjects = {\n')
            f.write(
                '  -- 1: refcnt, 2: data pointer, 3: func pointer,  4: custom\n'
            )
            for each in results:
                if each['variable']:
                    continue
                f.write('''  %s = {
    type = %d,
    offset = %d,
    size = %d,
    payload = "%s",
    hasvalue = true,
    values = "%s",
    allocator = "slab",
  },\n''' % (each['name'], each['type'], each['offset'], each['size'],
                each['payload'], each['values']))
            f.write('}\n')
        print("We found %d candidates in total" % len(results))

    def filter(self, targets, args):
        ret = []

        if args.filter_counter:
            for target in targets:
                if target.hasReferCounter(index=-1):
                    ret.append(target)

            targets = ret
            ret = []

        # if args.filter_function:
        recursive = 5
        if args.recursive:
            recursive = args.recursive
        for target in targets:
            if target.hasFunctionPointer(recursive=recursive):
                ret.append(target)

        targets = ret
        ret = []

        if args.filter_syscall:
            if os.path.exists("callchain.json"):
                with open("callchain.json") as f:
                    self._callchain = json.load(f)
                for target in targets:
                    if target.getStructType() in self._callchain:
                        ret.append(target)

                targets = ret
                ret = []

        return targets

    def test(self, n):
        count = 0
        for _, struct in self._structs.items():
            print(str(struct))
            count += 1
            if count >= n:
                break


class paholeCommand(Command):
    '''pahole utility'''

    def __init__(self, parser):
        super(paholeCommand, self).__init__(parser)
        parser.add_argument("-i",
                            "--image",
                            required=True,
                            action="store",
                            help="path to vmlinux")
        parser.add_argument("-s",
                            "--size",
                            type=int,
                            help="size of the target object")
        parser.add_argument("-c",
                            "--clazz",
                            action="store",
                            help="show struct")
        parser.add_argument("-r",
                            "--recursive",
                            type=int,
                            help="multi-layer struct presentation")
        parser.add_argument("--ref_recursive",
                            type=int,
                            help="reference counter")
        parser.add_argument("--filter_counter",
                            default=False,
                            action="store_true",
                            help="only take care reference counter")
        parser.add_argument("--filter_function",
                            default=False,
                            action="store_true",
                            help="has function pointer")
        parser.add_argument("--filter_syscall",
                            default=False,
                            action="store_true",
                            help="has syscall to allocate")
        parser.add_argument("-q",
                            "--quiet",
                            default=False,
                            action="store_true",
                            help="quiet mode")
        parser.add_argument("--filter_offset",
                            type=int,
                            help="overwrite at specific offset")
        parser.add_argument("--known",
                            default=False,
                            action="store_true",
                            help="only known objects")

    def run(self, args):
        pahole = Pahole(args.image)
        pahole.analyzeSize()
        pahole.analyzeType()
        pahole.search(args)
        # print(pahole.getOffsetInfo("cred"))
        # pahole.test(50)
