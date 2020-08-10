#include <s2e/S2E.h>

#include "Kasan.h"
#include "util.h"

using namespace klee;

namespace s2e {
namespace plugins {

// #define DEBUG_KASAN

S2E_DEFINE_PLUGIN(KernelAddressSanitizer, "kernel address sanitizer",
                  "KernelAddressSanitizer", "KernelFunctionModels",
                  "AllocManager", "OptionsManager", "LinuxMonitor");

#define DEFAULT_STACK_DEPTH 2
#define REPORT_STACK_DEPTH 3

void KernelAddressSanitizer::initialize() {
    m_kernelFunc = s2e()->getPlugin<models::KernelFunctionModels>();
    m_allocManager = s2e()->getPlugin<AllocManager>();
    m_options = s2e()->getPlugin<OptionsManager>();
    m_linuxMonitor = s2e()->getPlugin<LinuxMonitor>();
    m_pcMonitor = s2e()->getPlugin<PcMonitor>();
    assert(m_linuxMonitor && "Only support Linux");

    initializeConfiguration();
    getDebugStream() << "Mode: " << m_options->mode << "\n";

    switch (m_options->mode) {
    case MODE_PRE_ANALYSIS:
        // m_handlers["kasan_report"] = &KernelAddressSanitizer::handleReport;
        break;
    case MODE_ANALYSIS:
    case MODE_RESOLVE:
        // m_handlers["kasan_report"] = &KernelAddressSanitizer::handleReport;
        m_handlers["__asan_store1"] = &KernelAddressSanitizer::handleStore1;
        m_handlers["__asan_store2"] = &KernelAddressSanitizer::handleStore2;
        m_handlers["__asan_store4"] = &KernelAddressSanitizer::handleStore4;
        m_handlers["__asan_store8"] = &KernelAddressSanitizer::handleStore8;
        m_handlers["__asan_store16"] = &KernelAddressSanitizer::handleStore16;
        m_handlers["__asan_storeN"] = &KernelAddressSanitizer::handleStoreN;
        m_handlers["check_memory_region"] =
            &KernelAddressSanitizer::handleCheckMemoryRegion;
        if (!m_options->write_only) {
            m_handlers["__asan_load1"] = &KernelAddressSanitizer::handleLoad1;
            m_handlers["__asan_load2"] = &KernelAddressSanitizer::handleLoad2;
            m_handlers["__asan_load4"] = &KernelAddressSanitizer::handleLoad4;
            m_handlers["__asan_load8"] = &KernelAddressSanitizer::handleLoad8;
            m_handlers["__asan_load16"] = &KernelAddressSanitizer::handleLoad16;
            m_handlers["__asan_loadN"] = &KernelAddressSanitizer::handleLoadN;
        }
        m_additionChecks["csum_partial_copy_generic"] =
            &KernelAddressSanitizer::handleCsumPartialCopyGeneric;
        break;
    default:
        break;
    }
}

void KernelAddressSanitizer::initializeConfiguration() {
    bool ok = false;
    ConfigFile *cfg = s2e()->getConfig();
    ConfigFile::string_list funcList =
        cfg->getListKeys(getConfigKey() + ".functions");

    if (funcList.size() == 0) {
        getWarningsStream() << "no functions configured\n";
        // exit(1);
    }

    foreach2(it, funcList.begin(), funcList.end()) {
        std::stringstream s;
        s << getConfigKey() << ".functions." << *it;

        std::string funcName = cfg->getString(s.str() + ".funcName", "", &ok);
        EXIT_ON_ERROR(ok, "You must specify funcName");
        uint64_t entry = cfg->getInt(s.str() + ".entry", 0, &ok);
        EXIT_ON_ERROR(ok, "You must specify entry");
        uint64_t exitAddr = cfg->getInt(s.str() + ".exit", 0, &ok);
        EXIT_ON_ERROR(ok, "You must specify exit");

        m_funcMap[funcName] = entry;
        m_ranges[exitAddr] = entry;
    }

    funcList = cfg->getListKeys(getConfigKey() + ".checks");
    foreach2(it, funcList.begin(), funcList.end()) {
        std::stringstream s;
        s << getConfigKey() << ".checks." << *it;
        uint64_t address = cfg->getInt(s.str(), 0, &ok);
        EXIT_ON_ERROR(ok, "You must specify " + s.str());
        m_checkMap[*it] = address;
    }

    m_kasanReport = cfg->getInt(getConfigKey() + ".kasan_report", 0, &ok);
    EXIT_ON_ERROR(ok, "You must specify kasan_report")
    m_kasanRet = cfg->getInt(getConfigKey() + ".kasan_ret", 0, &ok);
    m_symbolicoverflow =
        cfg->getBool(getConfigKey() + ".checksymbol", true, &ok);
}

void KernelAddressSanitizer::registerHandler(PcMonitor *PcMonitor,
                                             S2EExecutionState *state,
                                             uint64_t cr3) {
    foreach2(it, m_funcMap.begin(), m_funcMap.end()) {
        // we already filter out any other process at PcMonitor, it's ok not to
        // give
        // cr3 here
        PcMonitor::CallSignalPtr CallSignal =
            PcMonitor->getCallSignal(state, it->second, cr3);
        auto itt = m_handlers.find(it->first);
        if (itt == m_handlers.end()) {
            continue;
        }
        getDebugStream() << "Hook Function: " << it->first << " at "
                         << hexval(it->second) << "\n";
        CallSignal->connect(
            sigc::bind(sigc::mem_fun(*this, &KernelAddressSanitizer::onCall),
                       (*itt).second),
            KASAN_PRIORITY);
    }

    foreach2(it, m_checkMap.begin(), m_checkMap.end()) {
        PcMonitor::CallSignalPtr CallSignal =
            PcMonitor->getCallSignal(state, it->second, cr3);
        auto itt = m_additionChecks.find(it->first);
        if (itt == m_additionChecks.end()) {
            continue;
        }
        getDebugStream() << "Check Function: " << it->first << " at "
                         << hexval(it->second) << "\n";
        CallSignal->connect(
            sigc::bind(sigc::mem_fun(*this, &KernelAddressSanitizer::onCheck),
                       (*itt).second),
            KASAN_PRIORITY);
    }

    // KASAN report
    PcMonitor::CallSignalPtr Callsignal =
        PcMonitor->getCallSignal(state, m_kasanReport, cr3);
    Callsignal->connect(
        sigc::mem_fun(*this, &KernelAddressSanitizer::handleReport),
        KASAN_PRIORITY);
}

void KernelAddressSanitizer::onCall(S2EExecutionState *state,
                                    PcMonitorState *pcs, uint64_t pc,
                                    KernelAddressSanitizer::OpHandler handler) {
    // skip these functions because they will introduce more constraints that we
    // dont want
    if (m_options->mode == MODE_RESOLVE) {
        state->bypassFunction(0);
        throw CpuExitException();
    }

    bool result = ((*this).*handler)(state, pc);
    if (!result) {
        // report here
        // set timer to stop execution
        m_options->halt = true;
    }
}

void KernelAddressSanitizer::onCheck(
    S2EExecutionState *state, PcMonitorState *pcs, uint64_t pc,
    KernelAddressSanitizer::OpHandler handler) {
    // bool result =
    if (m_options->mode == MODE_RESOLVE) {
        return;
    }

    ((*this).*handler)(state, pc);
}

// determine the type of the memory address given the layout of the kernel space
// 0000000000000000 - 00007fffffffffff (=47 bits) user space, different per mm
// ffff880000000000 - ffffc7ffffffffff (=64 TB) direct mapping of all phys.
// memory
// ffffffff80000000 - ffffffff9fffffff (=512 MB)  kernel text mapping, from phys
// 0
// We don't consider stack vaiable here. Stack address should be taken care of
// before.
MemoryType getMemType(uint64_t addr) {
    if (addr < 4096) {
        return NULL_ADDR;
    } else if (addr < 0x7fffffffffff) {
        return USER_ADDR;
    } else if (addr < 0xffffffff80000000) {
        return HEAP_ADDR;
    } else {
        return GLOBAL_ADDR;
    }
}

bool KernelAddressSanitizer::getPossibleBaseAddrs(S2EExecutionState *state,
                                                  ref<Expr> dstExpr) {
    uint64_t base_addr = 0;
    if (!m_allocManager->getBaseAddr(state, dstExpr, base_addr)) {
        ref<ConstantExpr> base;
        ConstraintManager variableConstraints;

        // Solution two: Assign zero to all symbolic variables
        std::set<ReadExpr *> collection;
        collectRead(dstExpr, collection);
        foreach2(it, collection.begin(), collection.end()) {
            variableConstraints.addConstraint(
                E_EQ(*it, E_CONST(0, Expr::Int8)));
        }

        if (!findMin(state, variableConstraints, dstExpr, base,
                     state->concolics)) {
            getDebugStream(state) << "Failed to get the minimum value of edi\n";
            exit(1);
        }

        getDebugStream(state) << "Min address for dst: " << base << "\n";
        base_addr = base->getZExtValue();
    }
    if (!base_addr) {
        m_allocManager->print(this);
    }
    getDebugStream(state) << "Base addr: " << hexval(base_addr) << "\n";
    assert(base_addr && "Failed to get base address from allocManager");

    // Find one in busy list
    uint64_t objAddr = m_allocManager->find(state, base_addr);
    if (objAddr == 0) {
        getDebugStream(state)
            << "Failed to find obj for " << hexval(base_addr) << "\n";
        return false;
    }
    std::vector<target_ulong> backtrace;
    if (!m_allocManager->getCallsite(objAddr, backtrace)) {
        getDebugStream(state)
            << "Failed to find callsite for " << hexval(objAddr) << "\n";
        return false;
    }
    AllocObj vul_obj;
    if (!m_allocManager->get(state, objAddr, vul_obj)) {
        return false;
    }

    m_allocManager->concretize(state, vul_obj);
    getDebugStream(state) << "Vul address: " << hexval(objAddr) << "\n";

    if (base_addr > objAddr + vul_obj.width + 1024) {
        getDebugStream(state) << "The vuln object it found looks incorrect!\n";
        return false;
    }

    std::stringstream ss;
    ss << "[Busy Object] {";
    ss << "\"Callsite\": [";
    for (int i = 0; i < backtrace.size(); i++) {
        if (i != 0) ss << ", ";
        ss << std::to_string(backtrace[i]);
    }
    ss << "], \"Size\": " << std::to_string(vul_obj.width);
    ss << ", \"Allocator\": \"" << m_allocManager->getAllocator(vul_obj)
       << "\"";
    ss << ", \"Symbolic\": "
       << (vul_obj.tag == AllocObj::SYMBOLIC ? "true" : "false") << "}\n";

    getDebugStream(state) << ss.str();
    return true;
}

// unsigned long addr, size_t size, bool is_write, unsigned long ip
void KernelAddressSanitizer::handleReport(S2EExecutionState *state,
                                          PcMonitorState *pcs, uint64_t pc) {

    if (m_options->mode == MODE_PRE_ANALYSIS) {
        if (m_options->write_only) {
            uint64_t isWrite;
            m_kernelFunc->readArgument(state, 2, isWrite, false);
            if (!isWrite) {
                return;
            }
        }

        ref<Expr> addr = m_kernelFunc->readSymArgument(state, 0, false);
        ref<Expr> size = m_kernelFunc->readSymArgument(state, 1, false);
        uint64_t ip;
        m_kernelFunc->readArgument(state, 3, ip, false);
        getDebugStream(state) << "DstExpr: " << addr << "\n";
        getDebugStream(state) << "SizeExpr: " << size << "\n";
        getDebugStream(state) << "ip: " << hexval(ip) << "\n";
        report(state, readExpr<uint64_t>(state, addr),
               readExpr<uint64_t>(state, size), false, false, REPORT_STACK_DEPTH, 0);

        // check if it's a heap object
        uint64_t concrete_addr = readExpr<uint64_t>(state, addr);
        switch (getMemType(concrete_addr)) {
        case HEAP_ADDR:
            getDebugStream(state) << "[KASAN-CAUSE] heap-memory-access\n";
            break; // continue to execute
        case NULL_ADDR:
            getDebugStream(state) << "[KASAN-CAUSE] null-ptr-deref\n";
            return;
        case USER_ADDR:
            getDebugStream(state) << "[KASAN-CAUSE] user-memory-access\n";
            return;
        case GLOBAL_ADDR:
            getDebugStream(state) << "[KASAN-CAUSE] global-memory-access\n";
            return;
        case STACK_ADDR:
            getDebugStream(state) << "[KASAN-CAUSE] stack-memory-access\n";
            return;
        }

        if (!getPossibleBaseAddrs(state, addr)) {
            return;
        }

        uint64_t pid = m_linuxMonitor->getPid(state);
        getDebugStream(state) << "Pid: " << pid << "\n";
        s2e()->getExecutor()->terminateState(*state,
                                             "Stop tracing at the target");
    } else if (m_options->mode == MODE_ANALYSIS) {
        uint64_t addr, size, ip;
        m_kernelFunc->readArgument(state, 0, addr, false);
        m_kernelFunc->readArgument(state, 1, size, false);
        m_kernelFunc->readArgument(state, 3, ip, false);
        if (m_options->concrete) {
            // Try to use our heuristics to get the base address
            m_vulAddr = m_vulAddr ? m_vulAddr : addr;
            report(state, addr, size, true, false, REPORT_STACK_DEPTH, 0);
            // we jump out of the normal control flow later, so handle everything here.
        }
        m_confirmCounter++;
        getDebugStream(state)
            << "[KASAN-CONFIRM] {\"Addr\": " << std::to_string(addr)
            << ", \"ip\": " << std::to_string(ip) << "}\n";
        // we may want to stop
        m_options->halt = true;
        if (m_confirmCounter > m_reportCounter) {
            m_confirmCounter -= m_reportCounter;
            if (m_confirmCounter > m_options->max_kasan) {
                s2e()->getExecutor()->terminateState(*state,
                                                     "Stop tracing on KASAN");
            }
        }
        m_reportCounter = 0;

        // We dont need report
        skipKasan(state);
    } else if (m_options->mode == MODE_RESOLVE) {
        // skip these functions because they will introduce more constraints that we dont want
        skipKasan(state);
    }
    return;
}

bool KernelAddressSanitizer::report(S2EExecutionState *state, uint64_t dstAddr,
                                    uint64_t len, bool reliable, bool isWrite,
                                    unsigned depth, uint64_t stack) {
    std::vector<target_ulong> stacks;
    bool ok = m_kernelFunc->dump_stack(state, stack, 0, stacks, depth);
    if (!ok)
        return false;

    std::stringstream ss;
    ss << "[KASAN] {";
    ss << "\"ip\": [";
    for (unsigned i = 0; i < stacks.size(); i++) {
        if (i != 0) {
            ss << ", ";
        }
        ss << std::to_string(stacks[i]);
    }
    ss << "], ";
    if (stacks.size() !=
        depth) { // our simple heuristic failed to retrieve backtrace
        ss << "\"counter\": " << std::to_string(m_pcMonitor->getCounter())
           << ", ";
    }

    ss << "\"addr\": " << std::to_string(dstAddr) << ", ";
    ss << "\"len\": " << std::to_string(len) << ", ";
    ss << "\"reliable\": " << (reliable ? "true" : "false") << ", ";
    ss << "\"write\": " << (isWrite ? "true" : "false");
    ss << "}\n";
    m_reportCounter++;
    getDebugStream(state) << ss.str();
    return ok;
}

bool KernelAddressSanitizer::reportAccess(S2EExecutionState *state,
                                          uint64_t baseAddr, uint64_t dstAddr,
                                          unsigned len, bool isWrite,
                                          unsigned depth) {
    std::vector<target_ulong> stacks;
    bool ok = m_kernelFunc->dump_stack(state, 0, 0, stacks, depth);
    if (!ok)
        return false;

    std::stringstream ss;
    ss << "[Access] {";
    ss << "\"base\": " << std::to_string(baseAddr) << ", ";
    ss << "\"offset\": " << std::to_string(dstAddr - baseAddr) << ", ";
    ss << "\"len\": " << std::to_string(len) << ", ";
    ss << "\"isWrite\": " << (isWrite ? "true" : "false") << ", ";
    ss << "\"ip\": [";
    for (unsigned i = 0; i < stacks.size(); i++) {
        if (i != 0) {
            ss << ", ";
        }
        ss << std::to_string(stacks[i]);
    }
    ss << "]";
    ss << "}\n";
    getDebugStream(state) << ss.str();
    return ok;
}

bool KernelAddressSanitizer::checkMemory(S2EExecutionState *state,
                                         unsigned size, bool isWrite,
                                         uint64_t ret_ip) {
#ifdef DEBUG_KASAN
    getDebugStream() << "Check memory at address " << hexval(ret_ip) << "\n";
#endif

    ref<Expr> dstExpr = m_kernelFunc->readSymArgument(state, 0, false);
    uint64_t base_addr;
    if (m_allocManager->getBaseAddr(state, dstExpr, base_addr)) {
        uint64_t dstAddr = readExpr<uint64_t>(state, dstExpr);
        AllocObj obj;
        if (!m_allocManager->get(state, base_addr, obj, true)) {
            return true;
        }

        if (m_options->track_access) {
            reportAccess(state, base_addr, dstAddr, size, isWrite,
                         DEFAULT_STACK_DEPTH);
        }

        if (base_addr + obj.width < dstAddr + size) {
            m_vulAddr = m_vulAddr ? m_vulAddr : base_addr;
            getDebugStream(state) << "Dst: " << hexval(dstAddr)
                                  << " with size: " << hexval(size) << "\n";
            report(state, dstAddr, size, true, isWrite, DEFAULT_STACK_DEPTH, state->regs()->getSp());
            return false;
        }
        ref<Expr> len = E_CONST(size, 64);
        // It's time consuming, so we'd better not to check every time we
        // encounter a seen pc address.
        if (m_visit.find(ret_ip) == m_visit.end() &&
            !checkSymMemory(state, dstExpr, len, obj, base_addr)) {
            m_vulAddr = m_vulAddr ? m_vulAddr : base_addr;
            getDebugStream(state)
                << "Potential Overflow-- Dst: " << hexval(dstAddr)
                << " with size: " << hexval(size) << "\n";
            // getDebugStream(state) << dstExpr << "\n";
            report(state, dstAddr, size, false, isWrite, DEFAULT_STACK_DEPTH, state->regs()->getSp());
            m_visit.insert({ret_ip, true});
            return false;
        }
        m_visit.insert({ret_ip, true});
    }
    return true;
}

bool KernelAddressSanitizer::checkMemoryRegion(S2EExecutionState *state,
                                               ref<Expr> &dstExpr,
                                               ref<Expr> &size, bool isWrite,
                                               uint64_t ret_ip) {
#ifdef DEBUG_KASAN
    getDebugStream() << "Check memory region at " << hexval(ret_ip) << "\n";
#endif

    uint64_t base_addr;
    if (m_allocManager->getBaseAddr(state, dstExpr, base_addr)) {
        uint64_t dstAddr = readExpr<uint64_t>(state, dstExpr);
        uint64_t len = readExpr<uint64_t>(state, size);
        AllocObj obj;
        if (!m_allocManager->get(state, base_addr, obj, true)) {
            return true;
        }

        if (m_options->track_access) {
            reportAccess(state, base_addr, dstAddr, len, isWrite,
                         DEFAULT_STACK_DEPTH);
        }

        if (base_addr + obj.width < dstAddr + len) {
            m_vulAddr = m_vulAddr ? m_vulAddr : base_addr;
            getDebugStream(state) << "Dst: " << hexval(dstAddr)
                                  << " with size: " << hexval(len) << "\n";
            report(state, dstAddr, len, true, isWrite, DEFAULT_STACK_DEPTH, state->regs()->getSp());
            return false;
        }
        if (m_visit.find(ret_ip) != m_visit.end() &&
            !checkSymMemory(state, dstExpr, size, obj, base_addr)) {
            m_vulAddr = m_vulAddr ? m_vulAddr : base_addr;
            getDebugStream(state)
                << "Potential Overflow-- Dst: " << hexval(dstAddr)
                << " with size: " << hexval(len) << "\n";
            // getDebugStream(state) << dstExpr << "\n";
            // getDebugStream(state) << size << "\n";
            report(state, dstAddr, len, false, isWrite, DEFAULT_STACK_DEPTH, state->regs()->getSp());
            m_visit.insert({ret_ip, true});
            return false;
        }
        m_visit.insert({ret_ip, true});
    }
    return true;
}

// check potential overflow
bool KernelAddressSanitizer::checkSymMemory(S2EExecutionState *state,
                                            ref<Expr> &dstExpr, ref<Expr> &size,
                                            AllocObj &obj, uint64_t base_addr) {
    if (!m_symbolicoverflow) {
        return true;
    }

    Solver *solver = getSolver(state);
    bool ok;
    // (ReadLSB w64 0x0 v1_alc_0xffff88000a515900_1)
    // Add constraint for this
    ref<Expr> condition;
    ConstraintManager manager;
    for (auto c : m_allocManager->AlloConstraint) {
        manager.addConstraint(c);
    }
    for (auto c : state->constraints()) {
        manager.addConstraint(c);
    }

    if (obj.tag == AllocObj::CONCRETE) {
        condition = E_LT(E_CONST(base_addr + obj.width, 64),
                         AddExpr::create(dstExpr, size));
    } else {
        ref<Expr> len = alignExpr(obj.sym_width, Expr::Int64);
        condition = E_LT(
            AddExpr::create(obj.sym_width, E_CONST(base_addr, Expr::Int64)),
            AddExpr::create(dstExpr, size));
    }

    if (!solver->mayBeTrue(Query(manager, condition), ok)) {
        getDebugStream() << "Error on constraint solving\n";
        exit(1);
    }

    if (ok) {
        getDebugStream(state) << "base: " << hexval(base_addr) << "\n";
        getDebugStream(state)
            << "Width: " << obj.sym_width << ", " << hexval(obj.width) << "\n";
    }

    return !ok;
}

bool KernelAddressSanitizer::handleStore1(S2EExecutionState *state,
                                          uint64_t pc) {
    KASAN_RET_IP

    return checkMemory(state, 1, true, ret_ip);
}

bool KernelAddressSanitizer::handleStore2(S2EExecutionState *state,
                                          uint64_t pc) {
    KASAN_RET_IP

    return checkMemory(state, 2, true, ret_ip);
}

bool KernelAddressSanitizer::handleStore4(S2EExecutionState *state,
                                          uint64_t pc) {
    KASAN_RET_IP

    return checkMemory(state, 4, true, ret_ip);
}

bool KernelAddressSanitizer::handleStore8(S2EExecutionState *state,
                                          uint64_t pc) {
    KASAN_RET_IP

    return checkMemory(state, 8, true, ret_ip);
}

bool KernelAddressSanitizer::handleStore16(S2EExecutionState *state,
                                           uint64_t pc) {
    KASAN_RET_IP

    return checkMemory(state, 16, true, ret_ip);
}

bool KernelAddressSanitizer::handleStoreN(S2EExecutionState *state,
                                          uint64_t pc) {
    KASAN_RET_IP

    ref<Expr> dstExpr = m_kernelFunc->readSymArgument(state, 0, false);
    ref<Expr> size = m_kernelFunc->readSymArgument(state, 1, false);
    return checkMemoryRegion(state, dstExpr, size, true, ret_ip);
}

bool KernelAddressSanitizer::handleLoad1(S2EExecutionState *state,
                                         uint64_t pc) {
    KASAN_RET_IP

    return checkMemory(state, 1, false, ret_ip);
}

bool KernelAddressSanitizer::handleLoad2(S2EExecutionState *state,
                                         uint64_t pc) {
    KASAN_RET_IP

    return checkMemory(state, 2, false, ret_ip);
}

bool KernelAddressSanitizer::handleLoad4(S2EExecutionState *state,
                                         uint64_t pc) {
    KASAN_RET_IP

    return checkMemory(state, 4, false, ret_ip);
}

bool KernelAddressSanitizer::handleLoad8(S2EExecutionState *state,
                                         uint64_t pc) {
    KASAN_RET_IP

    return checkMemory(state, 8, false, ret_ip);
}

bool KernelAddressSanitizer::handleLoad16(S2EExecutionState *state,
                                          uint64_t pc) {
    KASAN_RET_IP

    return checkMemory(state, 16, false, ret_ip);
}

bool KernelAddressSanitizer::handleLoadN(S2EExecutionState *state,
                                         uint64_t pc) {
    KASAN_RET_IP

    ref<Expr> dstExpr = m_kernelFunc->readSymArgument(state, 0, false);
    ref<Expr> size = m_kernelFunc->readSymArgument(state, 1, false);
    return checkMemoryRegion(state, dstExpr, size, false, ret_ip);
}

// addr, size, write, ret_ip
bool KernelAddressSanitizer::handleCheckMemoryRegion(S2EExecutionState *state,
                                                     uint64_t pc) {
    uint64_t isWrite;
    m_kernelFunc->readArgument(state, 2, isWrite, false);
    if (isWrite || !m_options->write_only) {
        KASAN_RET_IP

        ref<Expr> dstExpr = m_kernelFunc->readSymArgument(state, 0, false);
        ref<Expr> size = m_kernelFunc->readSymArgument(state, 1, false);
        return checkMemoryRegion(state, dstExpr, size, isWrite, ret_ip);
    }
    return true;
}

// rdi: source, rsi: destination, edx: len, ecx: csum, r8: src_err_ptr, r9:
// dst_err_ptr
bool KernelAddressSanitizer::handleCsumPartialCopyGeneric(
    S2EExecutionState *state, uint64_t pc) {
    KASAN_RET_IP

    ref<Expr> dstExpr = m_kernelFunc->readSymArgument(state, 1, false);
    ref<Expr> size = m_kernelFunc->readSymArgument(state, 2, false);
    bool result = checkMemoryRegion(state, dstExpr, size, true, ret_ip);
    if (!m_options->write_only) {
        ref<Expr> srcExpr = m_kernelFunc->readSymArgument(state, 0, false);
        if (!checkMemoryRegion(state, srcExpr, size, false, ret_ip)) {
            result = false;
        }
    }
    return result;
}

void KernelAddressSanitizer::decideAddConstraint(uint64_t pc,
                                                 bool *allowConstraint) {
    if (m_options->mode != MODE_RESOLVE || !allowConstraint) {
        return; // remain the same
    }

    auto it = m_ranges.lower_bound(pc);
    if (it == m_ranges.end()) {
        return;
    }
    if (pc >= it->second) {
        *allowConstraint = false;
    }
}
} // namespace plugins
} // namespace s2e
