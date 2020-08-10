#ifndef S2E_PLUGINS_ALLOCATIONMAP_H
#define S2E_PLUGINS_ALLOCATIONMAP_H

#include <klee/util/ExprTemplates.h>
#include <s2e/ConfigFile.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <llvm/Support/raw_ostream.h>

#include "KernelFunctionModels.h"
#include "Options.h"
#include "PcMonitor.h"

// #include <tr1/unordered_map>

namespace s2e {
namespace plugins {

#define FUNC_ALLOCATE 1
#define FUNC_FREE 2
#define SLAB_ALLOCATE 3

struct AllocObj {
    enum Tag { CONCRETE, SYMBOLIC } tag;
    uint64_t allocator;
#define PAGE_ALLOCATOR 0
#define SLAB_ALLOCATOR 1
    // uint64_t address;
    uint64_t width;
    // symbolic width
    klee::ref<klee::Expr> sym_width;

    AllocObj(): tag(CONCRETE), allocator(0), width(0), sym_width(E_CONST(0, klee::Expr::Int64)) {}
    AllocObj(uint64_t size, uint64_t alloc)
        : tag(CONCRETE), allocator(alloc), width(size),
          sym_width(E_CONST(size, klee::Expr::Int64)) {}
    AllocObj(klee::ref<klee::Expr> size, uint64_t alloc)
        : tag(SYMBOLIC), allocator(alloc), width(0), sym_width(size) {}
    AllocObj(AllocObj const &obj)
        : tag(obj.tag), allocator(obj.allocator), width(obj.width),
          sym_width(obj.sym_width) {}
    // both object must have concrete width
    AllocObj &operator+=(AllocObj &other) {
        width += other.width;
        sym_width = klee::AddExpr::create(sym_width, other.sym_width);
        if (other.tag == AllocObj::SYMBOLIC)
            tag = other.tag;
        return *this;
    }
    friend llvm::raw_ostream &operator<<(llvm::raw_ostream &os,
                                         const AllocObj &obj) {
        switch (obj.tag) {
        case AllocObj::CONCRETE:
            os << "Concrete: ";
            break;
        case AllocObj::SYMBOLIC:
            os << "Symbolic: ";
            break;
        default:
            break;
        }
        os << obj.width << " ";
        os << obj.sym_width;
        switch (obj.allocator) {
        case PAGE_ALLOCATOR:
            os << " page ";
            break;
        case SLAB_ALLOCATOR:
            os << " slab ";
            break;
        default:
            os << " custom ";
            break;
        }
        return os;
    }
};

struct AllocCfg {
    uint64_t allocator;
    std::string funcName;
    klee::ref<klee::Expr> arg; // symbolic value of size
    std::vector<target_ulong> backtrace;
};

// typedef std::tr1::unordered_map<uint64_t, AllocObj> AllocMap;
typedef std::map<uint64_t, AllocObj> AllocMap;

class AllocManager : public Plugin {
    S2E_PLUGIN

    struct MemFunctionCfg {
        uint64_t address;
        uint8_t type;
        uint8_t sizeArg;      // which arugment represent size
        std::string funcName; // allocation function name
    };
    typedef std::map<uint64_t, MemFunctionCfg> HookFunctions;

    struct kmem_cache {
        unsigned object_size;
        std::string name;
        kmem_cache() {}
        kmem_cache(unsigned _size, std::string _name)
            : object_size(_size), name(_name) {}
    };

  private:
    models::KernelFunctionModels *m_kernelFunc;
    OptionsManager *m_options;
    unsigned slab_offset;
    unsigned name_offset;

    AllocMap allocMap;
    AllocMap freeMap;
    std::map<target_ulong, std::vector<target_ulong>> callsites;
    std::vector<std::vector<uint64_t>> sequences; // record allocation in order
    const uint64_t PAGE_SIZE = 0x1000;
    std::vector<uint64_t> alignedSize;
    std::map<uint64_t, kmem_cache> m_kmem_caches;

    HookFunctions m_hookfuncs;
    std::vector<AllocCfg> m_vulobjs;
    // we should put it somewhere else
    std::vector<unsigned> m_syscalls;
    unsigned m_defIndex = -1;

  public:
    AllocManager(S2E *s2e) : Plugin(s2e){};
    ~AllocManager(){};
    void initialize();
    void registerHandler(PcMonitor *PcMonitor, S2EExecutionState *state,
                         uint64_t cr3);

    void newlist(unsigned sysnum) {
        std::vector<uint64_t> list;
        sequences.push_back(list);
        m_syscalls.push_back(sysnum);
    }
    void recordSyscall() {
        if (m_defIndex == -1) {
            m_defIndex = m_syscalls.size() - 1;
        }
    }

    uint64_t roundSize(uint64_t size);
    uint64_t lowerSize(uint64_t size);

    uint64_t find(S2EExecutionState *state, uint64_t addr);
    void concretize(S2EExecutionState *state, AllocObj &obj);
 
    bool getCallsite(uint64_t addr, std::vector<target_ulong> &addrs) {
        auto it = callsites.find(addr);
        if (it != callsites.end()) {
            addrs.insert(addrs.begin(), it->second.begin(), it->second.end());
            return true;
        }
        return false;
    }

    bool getFreeObj(S2EExecutionState *state, uint64_t addr, AllocObj &obj,
                        bool concretize = false);
    bool get(S2EExecutionState *state, uint64_t addr, AllocObj &obj,
                 bool concretize = false);
    AllocObj getWidelength(S2EExecutionState *state, uint64_t addr);
    AllocObj getAggregate(S2EExecutionState *state, uint64_t addr,
                          unsigned new_size);
    bool getBaseAddr(S2EExecutionState *state, ref<Expr> dstExpr,
                     uint64_t &base_addr);
    bool getLayout(S2EExecutionState *state, uint64_t addr,
                   std::vector<unsigned> &layout);

    std::string getAllocator(AllocObj &obj) {
        return m_kmem_caches[obj.allocator].name;
    }
    std::string getAllocator(uint64_t alloc) {
        return m_kmem_caches[alloc].name;
    }

    bool getSyscallIndex(uint64_t addr, unsigned &allocIndex,
                         unsigned &defIndex, std::vector<unsigned> &syscalls);

    void print(Plugin *plugin);

    // signals
    sigc::signal<void, S2EExecutionState *, AllocCfg *,
                 uint64_t> // base address of the object
        onAllocate;

    sigc::signal<void, S2EExecutionState *,
                 uint64_t> // base address of the object
        onRelease;

  private:
    void initializeConfiguration();

    void onFunctionCall(S2EExecutionState *state, PcMonitorState *fns,
                        uint64_t pc);
    void onFunctionRet(S2EExecutionState *state, AllocCfg cfg);

    void insert(uint64_t addr, uint64_t width, uint64_t alloc);
    void insert(uint64_t addr, klee::ref<klee::Expr> width, uint64_t alloc);
    void insert(std::string funcName, uint64_t addr, uint64_t width,
                uint64_t alloc);
    void insert(std::string funcName, uint64_t addr,
                klee::ref<klee::Expr> width, uint64_t alloc);
    void erase(S2EExecutionState *state, uint64_t addr);
    uint64_t getSize(std::string funcName, uint64_t size);
    klee::ref<klee::Expr> getSize(std::string funcName,
                                  klee::ref<klee::Expr> size);
    uint64_t getAllocator(std::string funcName);

    target_ulong getRetAddr(S2EExecutionState *state);

  public:
    ConstraintManager AlloConstraint;

    AllocMap::iterator allocBegin() { return allocMap.begin(); }

    AllocMap::iterator allocEnd() { return allocMap.end(); }

    AllocMap::iterator freeBegin() { return freeMap.begin(); }

    AllocMap::iterator freeEnd() { return freeMap.end(); }
};
}
}
#endif
