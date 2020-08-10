import functools


############ Useful Command ####################
# list funcName: show line of code
# info function funcName:
# info types typeName
################################################
def warn(text):
    print(text)


def locatefunc(name):
    pass


def is_alive():
    """Check if GDB is running."""
    ret = ""
    try:
        if not gdb.selected_thread():
            return False
        ret = gdb.execute("x/x 0", False, True)
    except:
        # Temporary solution, any elegant way to do it??
        if "Remote connection closed" in ret:
            return False
    return True


def only_if_gdb_running(f):
    """Decorator wrapper to check if GDB is running."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if is_alive():
            return f(*args, **kwargs)
        else:
            warn("No debugging session active")

    return wrapper


class PoolCmd(gdb.Command):
    """Check heap layout"""
    def __init__(self):
        super(PoolCmd, self).__init__("pool", gdb.COMMAND_USER)
        self._malloc_sizes = None

    @only_if_gdb_running
    def invoke(self, args, from_tty):
        args = args.split()
        index = -1
        print("pool", args)
        if len(args) >= 1:
            index = int(args[0])
        if not self._malloc_sizes:
            (self._malloc_sizes,
             isMethodObj) = gdb.lookup_symbol("malloc_sizes")
        i = 0
        caches = self._malloc_sizes.value()
        while True:
            cache = caches[i]
            i += 1
            if cache['cs_cachep'] == 0:
                break
            if index != -1 and cache['cs_size'] != index:
                continue
            print("cs_size: %d cs_cachep: 0x%x" %
                  (cache['cs_size'], cache['cs_cachep']))
            j = 0
            while True:
                kmem_list = cache['cs_cachep']['nodelists'][j]
                j += 1
                if kmem_list == 0:
                    break


offsetof = lambda stype, field: int(stype[field].bitpos / 8)


class InspectCmd(gdb.Command):
    """introspect"""
    def __init__(self):
        super(InspectCmd, self).__init__("inspect", gdb.COMMAND_USER)
        self._kmem_caches = None
        self._uint64_t = gdb.lookup_type('uint64_t')
        self._kmem_cache_pointer = gdb.lookup_type(
            'struct kmem_cache').pointer()
        # FIXME: how to get the offset
        self._list_offset = offsetof(self._kmem_cache_pointer, "list")

    @only_if_gdb_running
    def invoke(self, args, from_tty):
        args = args.split()
        if len(args) == 0:
            return
        cmd = args[0]
        if cmd == 'caches':
            name = None
            if len(args) > 1:
                name = args[1]
            if self._kmem_caches is None:
                self._kmem_caches, _ = gdb.lookup_symbol("slab_caches")
            if self._kmem_caches is None:
                raise Exception("No slab_caches")
            head = self._kmem_caches.value()
            pos = self._kmem_caches.value()['prev'].cast(
                self._uint64_t) - self._list_offset
            pos = pos.cast(self._kmem_cache_pointer)
            obj = pos.dereference()
            count = 500
            while obj['list'] != head:
                print("%s: %s" % (pos, obj['name']))
                if name == obj['name'].string():
                    print(obj)
                pos = obj['list']['prev'].cast(
                    self._uint64_t) - self._list_offset
                pos = pos.cast(self._kmem_cache_pointer)
                obj = pos.dereference()
                count -= 1
                if count == 0:
                    raise Exception("Error")


class SearchTypeCmd(gdb.Command):
    """Search for specific type of objects"""
    def __init__(self):
        super(SearchTypeCmd, self).__init__("stype", gdb.COMMAND_USER)
        self._cache_type_table = None

    def invoke(self, args, from_tty):
        self.dont_repeat()
        args = args.split()
        if 1 <= len(args) <= 2:
            try:
                min_size = int(args[0])
                max_size = int(args[1]) if len(args) == 2 else -1
                if min_size > max_size and max_size != -1:
                    raise Exception("Arguments Error")
            except Exception as e:
                raise e
        else:
            raise Exception("Arguments Error")

        if not self._cache_type_table:
            results = gdb.execute("info types", False, True)
            self._cache_type_table = self.extractType(results.split('\n'))
            print("Found %d struct in total" % len(typs))

        for name in self._cache_type_table:
            sym = gdb.lookup_type(name)
            if max_size == -1 and sym.sizeof == min_size:
                print("[AEG: %s size: %d]" % (name, sym.sizeof))
            elif max_size != -1 and min_size <= sym.sizeof <= max_size:
                print("[AEG: %s size: %d]" % (name, sym.sizeof))

    def extractType(self, lines):
        typs = list()
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("struct"):
                typ = line[0:-1]
                typs.append(typ)
            elif line.startswith("typedef struct"):
                while not line.startswith("} "):
                    i += 1
                    line = lines[i]
                typ = line[len("} "):-1]
                typs.append(typ)
            i += 1
        return typs


if __name__ == '__main__':
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")

    SearchTypeCmd()  # initialization
    PoolCmd()
    InspectCmd()
