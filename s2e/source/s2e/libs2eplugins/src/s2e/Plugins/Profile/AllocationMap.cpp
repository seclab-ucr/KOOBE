#include <klee/Expr.h>
#include <klee/util/ExprTemplates.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "AllocationMap.h"
#include "util.h"

using namespace klee;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(AllocManager, "Kernel memory allocation management",
                  "AllocManager", "KernelFunctionModels", "OptionsManager");

void AllocManager::initialize() {
    m_kernelFunc = s2e()->getPlugin<models::KernelFunctionModels>();
    m_options = s2e()->getPlugin<OptionsManager>();

    m_kmem_caches[PAGE_ALLOCATOR] = kmem_cache(0, "page");
    m_kmem_caches[SLAB_ALLOCATOR] = kmem_cache(0, "slab");

    initializeConfiguration();
}

void AllocManager::initializeConfiguration() {
    bool ok = false;
    ConfigFile *cfg = s2e()->getConfig();
    ConfigFile::string_list funcList =
        cfg->getListKeys(getConfigKey() + ".functions");

    if (funcList.size() == 0) {
        getWarningsStream() << "no functions configured\n";
    }

    foreach2(it, funcList.begin(), funcList.end()) {
        std::stringstream s;
        s << getConfigKey() << ".functions." << *it << ".";

        MemFunctionCfg func;
        func.funcName = cfg->getString(s.str() + "funcName", "", &ok);
        EXIT_ON_ERROR(ok, "You must specify " + s.str() + "funcName");

        func.address = cfg->getInt(s.str() + "address", -1, &ok);
        EXIT_ON_ERROR(ok, "You must specify " + s.str() + "address");

        func.type = cfg->getInt(s.str() + "type", 0, &ok);
        EXIT_ON_ERROR(ok, "You must specify " + s.str() + "type");

        func.sizeArg = cfg->getInt(s.str() + "sizeArg", 0, &ok);
        EXIT_ON_ERROR(func.type != FUNC_ALLOCATE || ok,
                      "You must specify " + s.str() + "type");

        m_hookfuncs.insert({func.address, func});
    }

    ConfigFile::integer_list sizeList = cfg->getIntegerList("AlignedSizes");
    foreach2(it, sizeList.begin(), sizeList.end()) {
        alignedSize.push_back(*it);
    }
    sort(alignedSize.begin(), alignedSize.end()); // sort

    slab_offset = cfg->getInt(getConfigKey() + ".slab_offset", 0, &ok);
    EXIT_ON_ERROR(ok, "You must specify slab_offset");
    name_offset = cfg->getInt(getConfigKey() + ".name_offset", 0, &ok);
    EXIT_ON_ERROR(ok, "You must specify name_offset");

    // adjust options with respect to their relationship
    bool init_obj = false;
    switch (m_options->mode) {
    case MODE_PRE_ANALYSIS:
        break;
    case MODE_ANALYSIS:
        init_obj = true;
        break;
    case MODE_RESOLVE:
        init_obj = true;
        break;
    }

    if (init_obj) {
        ConfigFile::string_list objList =
            cfg->getListKeys(getConfigKey() + ".symbolic");
        foreach2(it, objList.begin(), objList.end()) {
            std::stringstream s;
            s << getConfigKey() << ".symbolic." << *it << ".";
            AllocCfg obj;
            ConfigFile::integer_list backtrace;
            backtrace = cfg->getIntegerList(s.str() + "callsite", backtrace, &ok);
            for (auto addr : backtrace)
                obj.backtrace.push_back(addr);
            EXIT_ON_ERROR(ok, "You must specify " + s.str() + "callsite");

            unsigned size = cfg->getInt(s.str() + "size", 0, &ok);
            obj.arg = E_CONST(size, Expr::Int32);
            EXIT_ON_ERROR(ok, "You must specify " + s.str() + "size");

            m_vulobjs.push_back(obj);
        }
    }
}

void AllocManager::registerHandler(PcMonitor *PcMonitor,
                                   S2EExecutionState *state, uint64_t cr3) {
    // Functions to hook
    foreach2(it, m_hookfuncs.begin(), m_hookfuncs.end()) {
        getDebugStream() << "Hook Function: " << it->second.funcName << " at "
                         << hexval(it->second.address) << "\n";
        // we already filter out any other process at PcMonitor, it's ok not to
        // give
        // cr3 here
        PcMonitor::CallSignalPtr CallSignal =
            PcMonitor->getCallSignal(state, it->second.address, cr3);
        CallSignal->connect(sigc::mem_fun(*this, &AllocManager::onFunctionCall),
                            ALLOCATE_PRIORITY);
    }
}

/*
 * Extract the base address of a symbolic pointer.
 * Fail if the base address is not a symbolic value.
 */
bool AllocManager::getBaseAddr(S2EExecutionState *state, ref<Expr> dstExpr,
                               uint64_t &base_addr) {
    ref<ReadExpr> sym_base;
    std::string prefix = "alc_";
    if (isa<ConstantExpr>(dstExpr)) {
        return false;
    }

    if (findSymBase(dstExpr, sym_base, prefix)) {
        std::string name = sym_base->getUpdates()->getRoot()->getName();
        base_addr = getValueFromName(name, prefix);
        return true;
    }
    return false;
}

void AllocManager::onFunctionCall(S2EExecutionState *state, PcMonitorState *fns,
                                  uint64_t pc) {
    MemFunctionCfg cfg = m_hookfuncs[pc];

    uint64_t val, kcache;
    AllocCfg alloc;
    kmem_cache cache;
    switch (cfg.type) {
    case FUNC_ALLOCATE:
        alloc.funcName = cfg.funcName;
        alloc.allocator = getAllocator(cfg.funcName);
        alloc.arg = m_kernelFunc->readSymArgument(state, cfg.sizeArg, true);
        if (!m_kernelFunc->dump_stack(state, state->regs()->getSp(), 0, alloc.backtrace, 2)) {
            getWarningsStream(state) << "Failed to retrieve the backtrace\n";
        }

        // we need to retrieve the return value
        PCMON_REGISTER_RETURN_A(state, fns, AllocManager::onFunctionRet, alloc);
        break;
    case SLAB_ALLOCATE:
        alloc.funcName = cfg.funcName;
        m_kernelFunc->readArgument(state, cfg.sizeArg, kcache, true);
        alloc.allocator = kcache;
        if (m_kmem_caches.find(kcache) != m_kmem_caches.end()) {
            val = m_kmem_caches[kcache].object_size;
        } else {
            m_kernelFunc->readMemory(state, kcache + name_offset,
                                     sizeof(target_ulong) * CHAR_BIT, val,
                                     false);
            cache.name = m_kernelFunc->readString(state, val);
            m_kernelFunc->readMemory(state, kcache + slab_offset,
                                     sizeof(unsigned int) * CHAR_BIT, val,
                                     false);
            cache.object_size = val;
            m_kmem_caches[kcache] = cache;
            getDebugStream(state) << "create kmem_cache: " << cache.name << "\n";
        }
        alloc.arg = E_CONST(val, Expr::Int64);
        if (!m_kernelFunc->dump_stack(state, state->regs()->getSp(), 0, alloc.backtrace, 2)) {
            getWarningsStream(state) << "Failed to retrieve the backtrace\n";
        }

        PCMON_REGISTER_RETURN_A(state, fns, AllocManager::onFunctionRet, alloc);
        break;
    case FUNC_FREE:
        if (m_options->track_access) {
            uint64_t base_addr;
            ref<Expr> dstAddr =
                m_kernelFunc->readSymArgument(state, cfg.sizeArg, false);
            if (!getBaseAddr(state, dstAddr, base_addr)) {
                uint64_t ip = getRetAddr(state);
                getDebugStream(state)
                    << "[Delete] {\"base\": "
                    << std::to_string(readExpr<uint64_t>(state, dstAddr))
                    << ", \"callsite\": " << std::to_string(ip) << "}\n";
            }
        }

        m_kernelFunc->readArgument(state, cfg.sizeArg, val, true);
        if (val == 0) {
            break;
        }
        if (m_options->track_object) {
            std::stringstream ss;
            ss << "[object] {";
            ss << "\"op\": \"free\", \"base\": " << std::to_string(val);
            ss << "}\n";
            getDebugStream(state) << ss.str() << "\n";
            onRelease.emit(state, val);
        }
        erase(state, val);
        break;
    }
}

void AllocManager::onFunctionRet(S2EExecutionState *state, AllocCfg cfg) {
    uint64_t ret;

    // Ret value from kmalloc
    m_kernelFunc->getRetValue(state, ret);
    if (ret == 0) { // malloc failed
        return;
    }

    // getDebugStream(state) << "Return from " << cfg.funcName << " with " <<
    // cfg.allocator << ": " << hexval(ret) << "\n";
    insert(cfg.funcName, ret, cfg.arg, cfg.allocator);
    callsites[ret] = cfg.backtrace;

    if (m_options->track_object) {
        std::stringstream ss;
        ss << "[object] {";
        ss << "\"op\": \"alloc\", \"base\": " << std::to_string(ret);
        ss << ", \"site\": " << std::to_string(cfg.backtrace[0]);
        ss << ", \"alloc\": \"" << getAllocator(cfg.allocator) << "\"";
        ss << ", \"size\": "
           << std::to_string(readExpr<uint64_t>(state, cfg.arg));
        ss << "}\n";
        getDebugStream(state) << ss.str();
        onAllocate.emit(state, &cfg, ret);
    }

    if (!m_options->concrete) {
        for (auto obj : m_vulobjs) {
            bool match = true;
            if (obj.backtrace.size() != cfg.backtrace.size())
                continue;
            for (int i = 0; i < obj.backtrace.size(); i++)
                if (obj.backtrace[i] != cfg.backtrace[i]) {
                    match = false;
                    break;
                }
            if (!match)
                continue;
            
            // check if size matches
            uint64_t width = readExpr<uint64_t>(state, cfg.arg);
            uint64_t size = getSize(cfg.funcName, width);
            uint64_t vuln_size = dyn_cast<ConstantExpr>(obj.arg)->getZExtValue();
            getDebugStream(state)
                << "size: " << hexval(size)
                << ", required: " << hexval(vuln_size) << "\n";

            if (vuln_size != 0 && size != vuln_size)
                return;

            std::stringstream ss;
            ss << "alc_" << hexval(ret);
            ref<Expr> sym = m_kernelFunc->makeSymbolic(
                state, CPU_OFFSET(regs[R_EAX]), ss.str(), true);
            getDebugStream(state) << "Make return value symbolic"
                                  << "\n";
         
            // Add constraint on this memory
            AlloConstraint.addConstraint(
                E_EQ(sym, E_CONST(ret, sizeof(target_ulong) * CHAR_BIT)));

            if (m_options->track_access) {
                uint64_t size = readExpr<uint64_t>(state, cfg.arg);
                getDebugStream(state)
                    << "[Create] "
                    << "{\"base\": " << std::to_string(ret) << ", \"len\": " << size
                    << ", \"callsite\": " << std::to_string(cfg.backtrace[0]) << "}\n";
            }
        }
    }
}

// Call this function right after a function is invoked
target_ulong AllocManager::getRetAddr(S2EExecutionState *state) {
    target_ulong addr;
    bool ok = m_kernelFunc->readStack(state, 0, 0, addr);
    EXIT_ON_ERROR(ok, "Something wrong when getting ret addr");
    return addr;
}

void AllocManager::insert(uint64_t addr, uint64_t width, uint64_t alloc) {
    allocMap.insert(std::make_pair(addr, AllocObj(width, alloc)));
}

void AllocManager::insert(uint64_t addr, ref<Expr> width, uint64_t alloc) {
    allocMap.insert(std::make_pair(addr, AllocObj(width, alloc)));
}

void AllocManager::insert(std::string funcName, uint64_t addr, uint64_t width,
                          uint64_t alloc) {
    uint64_t size = getSize(funcName, width);
    insert(addr, size, alloc);
}

void AllocManager::insert(std::string funcName, uint64_t addr, ref<Expr> width,
                          uint64_t alloc) {
    // keep in oder
    auto it = sequences.rbegin();
    if (it == sequences.rend()) {
        // We haven't started yet.
        return;
    } else {
        it->push_back(addr);
    }

    if (isa<ConstantExpr>(width)) {
        ConstantExpr *expr = dyn_cast<ConstantExpr>(width);
        uint64_t value = expr->getZExtValue();
        insert(funcName, addr, value, alloc);
        return;
    }
    ref<Expr> size = getSize(funcName, width);
    insert(addr, size, alloc);
}

void AllocManager::erase(S2EExecutionState *state, uint64_t addr) {
    auto it = allocMap.find(addr);
    if (it == allocMap.end()) {
        return;
    }

    // FIXME: How to do it efficiently
    bool found = false;
    foreach2(iter, sequences.begin(), sequences.end()) {
        foreach2(itt, iter->begin(), iter->end()) {
            if (*itt == addr) {
                iter->erase(itt);
                found = true;
                break;
            }
        }
        if (found) {
            break;
        }
    }

    if (m_options->mode == MODE_PRE_ANALYSIS) {
        AllocObj obj = it->second;
        freeMap.insert({addr, obj});
    }
    allocMap.erase(it);
}

uint64_t AllocManager::getAllocator(std::string funcName) {
    if (funcName == "__get_free_pages") {
        return PAGE_ALLOCATOR;
    }
    return SLAB_ALLOCATOR;
}

uint64_t AllocManager::getSize(std::string funcName, uint64_t size) {
    if (funcName == "__get_free_pages") {
        return (1 << size) * PAGE_SIZE;
    } else {
        return size;
    }
}

ref<Expr> AllocManager::getSize(std::string funcName, ref<Expr> size) {
    if (funcName == "__get_free_pages") {
        return ShlExpr::create(
            E_CONST(PAGE_SIZE, sizeof(target_ulong) * CHAR_BIT), size);
    } else {
        return size;
    }
}

uint64_t AllocManager::roundSize(uint64_t size) {
    uint64_t maximum = 8192;
    if (size > maximum) {
        return (size / 4096 + ((size & 0x1000) == 0 ? 0 : 1)) * 4096;
    } else {
        for (auto it : alignedSize) {
            if (it >= size) {
                return it;
            }
        }
        return 0;
    }
}

uint64_t AllocManager::lowerSize(uint64_t size) {
    uint64_t maximum = 8192;
    if (size > maximum) {
        return ((maximum - 1) / 4096) * 4096;
    } else {
        uint64_t last = 0;
        for (auto it : alignedSize) {
            if (it >= size) {
                return last;
            }
            last = it;
        }
        return 0;
    }
}

void AllocManager::print(Plugin *plugin) {
    plugin->getDebugStream() << "Allocation: " << allocMap.size() << "\n";
    for (auto it = allocMap.begin(); it != allocMap.end(); ++it) {
        if (it->second.tag == AllocObj::CONCRETE) {
            plugin->getDebugStream()
                << hexval(it->first) << ": " << it->second.width << "\n";
        } else {
            plugin->getDebugStream() << hexval(it->first) << ": "
                                     << "sym"
                                     << "\n";
        }
    }
}

bool AllocManager::get(S2EExecutionState *state, uint64_t addr,
                           AllocObj &obj, bool concretize) {
    auto it = allocMap.find(addr);
    if (it == allocMap.end()) {
        return false;
    }

    if (concretize) {
        this->concretize(state, it->second);
    }
    obj = it->second;
    return true;
}

bool AllocManager::getFreeObj(S2EExecutionState *state, uint64_t addr,
                                  AllocObj &obj, bool concretize) {
    auto it = freeMap.find(addr);
    if (it == freeMap.end()) {
        return false;
    }

    if (concretize) {
        this->concretize(state, it->second);
    }
    obj = it->second;
    return true;
}

void AllocManager::concretize(S2EExecutionState *state, AllocObj &obj) {
    if (obj.tag == AllocObj::SYMBOLIC && obj.width == 0) {
        ConstantExpr *expr =
            dyn_cast<ConstantExpr>(state->concolics->evaluate(obj.sym_width));
        assert(expr && "Failed to concretize");
        obj.width = expr->getZExtValue();
    }
}

// We want to know the heap layout, basically we have two solution
// getAggregate: One implemented below assumes that objects with the same size are contiguous.
// getWidelength: Another way we can consider is to collect all objects
// potential to be allocated in contiguous memory,
// because we want to take into account race condition where different syscalls
// interleave with each other and our
// sequences are out of order. Race condition is somewhat complex. If we want to
// tackle this, we could introducing thread ID.
AllocObj AllocManager::getWidelength(S2EExecutionState *state, uint64_t addr) {
    auto it = allocMap.find(addr);
    assert(it != allocMap.end());

    AllocObj ret(it->second);
    concretize(state, ret);
    ret.width = roundSize(ret.width);

    while (++it != allocMap.end()) {
        if (addr + ret.width != it->first) { // non-contiguous memory addresses
            return ret;
        }

        AllocObj next(it->second);
        concretize(state, next);
        next.width = roundSize(next.width);
        ret += next;
    }
    return ret;
}

// Method 2
// If the size of vulneralbe object is variable, the objects we consider should
// also have the new size.
// Note: update the objects of old_size with new_size
AllocObj AllocManager::getAggregate(S2EExecutionState *state, uint64_t addr,
                                    unsigned new_size) {
    auto it = allocMap.find(addr);
    unsigned old_size = roundSize(it->second.width);
    unsigned counter = 1;
    assert(it != allocMap.end());

    AllocObj ret(it->second);
    concretize(state, ret);
    ret.width = roundSize(new_size);
    // ret.width = roundSize(ret.width);

    // only consider objects allocated after the target one, but still within
    // the execution of the same syscall
    bool found = false;
    for (auto seq : sequences) {
        for (auto itt : seq) {
            if (itt == addr) {
                found = true;
                continue;
            }
            if (found) {
                AllocObj obj;
                if (!get(state, itt, obj)) {
                    continue;
                }

                // Check the allocators are the same or not
                if (obj.allocator != ret.allocator) {
                    continue;
                }

                concretize(state, obj); // concetize obj and round up width
                obj.width = roundSize(obj.width); // update width
                switch (obj.tag) {
                case AllocObj::SYMBOLIC:
                    // check whether the symbolic value can equal new_size
                    if (old_size ==
                        obj.width) { // object of the same old rounded size
                        obj.width = new_size;
                        ret += obj;
                        counter++;
                    }
                    break;
                case AllocObj::CONCRETE:
                    if (new_size == obj.width) { // object of the same new size
                        ret += obj;
                        counter++;
                    }
                    break;
                }
            }
        }
        if (found) {
            break;
        }
    }
    g_s2e->getDebugStream()
        << "Found " << std::to_string(counter) << " objects with the same size "
        << std::to_string(new_size) << "\n";
    return ret;
}

bool AllocManager::getLayout(S2EExecutionState *state, uint64_t addr,
                             std::vector<unsigned> &layout) {
    auto it = allocMap.find(addr);
    unsigned size = roundSize(it->second.width);
    assert(it != allocMap.end());

    AllocObj ret(it->second);
    concretize(state, ret);
    ret.width = roundSize(ret.width);

    bool found = false;
    for (auto seq : sequences) {
        for (auto itt : seq) {
            if (itt == addr) {
                found = true;
                break;
            }
        }

        if (found) {
            for (auto itt : seq) {
                if (itt == addr) {
                    layout.push_back(0);
                    continue;
                }
                AllocObj obj;
                if (!get(state, itt, obj)) {
                    continue;
                }

                if (obj.allocator != ret.allocator) {
                    continue;
                }
                concretize(state, obj); // concetize obj and round up width
                switch (obj.tag) {
                case AllocObj::SYMBOLIC:
                    if (size == roundSize(obj.width)) {
                        layout.push_back(1);
                    }
                    break;
                case AllocObj::CONCRETE:
                    layout.push_back(roundSize(obj.width));
                    break;
                }
            }
            break;
        }
    }
    return true;
}

// syscall analyze
bool AllocManager::getSyscallIndex(uint64_t addr, unsigned &allocIndex,
                                   unsigned &defIndex,
                                   std::vector<unsigned> &syscalls) {
    unsigned index = 0;
    bool found = false;
    for (auto seq : sequences) {
        for (auto itt : seq) {
            if (itt == addr) {
                allocIndex = index;
                found = true;
                break;
            }
        }
        if (found)
            break;
        ++index;
    }
    if (!found)
        return false;

    defIndex = m_defIndex;
    if (m_defIndex == -1)
        return false;

    syscalls.clear();
    syscalls.insert(syscalls.end(), m_syscalls.begin(), m_syscalls.end());

    return true;
}

// find the nearest object in the busy list
uint64_t AllocManager::find(S2EExecutionState *state, uint64_t addr) {
    auto it = allocMap.lower_bound(addr); // it->first >= addr
    if (it->first == addr) {
        return addr;
    } else if (it == allocMap.begin()) {
        return 0;
    }

    --it;
    if (it->second.tag == AllocObj::SYMBOLIC) {
        concretize(state, it->second);
    }
    uint64_t width = it->second.width;
    if (addr >= it->first) {
        if (addr >= it->first + width) {
            g_s2e->getDebugStream(state) << "Out of bound address found!!!\n";
        }
        return it->first;
    }

    return 0; // Fail to find
}
} // namespace plugins
} // namespace s2e
