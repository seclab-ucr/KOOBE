#ifndef S2E_PLUGINS_KASAN_H
#define S2E_PLUGINS_KASAN_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>

#include "AllocationMap.h"
#include "Disassembler.h"
#include "KernelFunctionModels.h"
#include "Options.h"
#include "PcMonitor.h"
#include "util.h"

namespace s2e {
namespace plugins {

enum MemoryType { NULL_ADDR, USER_ADDR, HEAP_ADDR, STACK_ADDR, GLOBAL_ADDR };

class KernelAddressSanitizer : public Plugin {
    S2E_PLUGIN

  private:
    typedef bool (KernelAddressSanitizer::*OpHandler)(S2EExecutionState *state,
                                                      uint64_t pc);
    typedef llvm::StringMap<OpHandler> HandlerMap;

    models::KernelFunctionModels *m_kernelFunc;
    AllocManager *m_allocManager;
    OptionsManager *m_options;
    LinuxMonitor *m_linuxMonitor;
    PcMonitor *m_pcMonitor;

    uint64_t m_vulAddr = 0;
    // unsigned m_kasandepth = 0;
    uint64_t m_kasanReport = 0;
    uint64_t m_kasanRet = 0;

    bool m_symbolicoverflow = true;
    models::ConstraintRanges m_ranges;
    std::map<uint64_t, bool> m_visit;

    // statistics
    unsigned m_confirmCounter = 0;
    unsigned m_reportCounter = 0;

  public:
    KernelAddressSanitizer(S2E *s2e) : Plugin(s2e) {}
    ~KernelAddressSanitizer() {}
    void initialize();

    std::map<std::string, uint64_t> m_funcMap, m_checkMap;
    HandlerMap m_handlers;
    HandlerMap m_additionChecks;

    void registerHandler(PcMonitor *PcMonitor, S2EExecutionState *state,
                         uint64_t cr3);
    void onCall(S2EExecutionState *state, PcMonitorState *pcs, uint64_t pc,
                KernelAddressSanitizer::OpHandler handler);
    void onCheck(S2EExecutionState *state, PcMonitorState *pcs, uint64_t pc,
                 KernelAddressSanitizer::OpHandler handler);
    void decideAddConstraint(uint64_t pc, bool *allowConstraint);

  private:
    void initializeConfiguration();

    bool getPossibleBaseAddrs(S2EExecutionState *state, ref<Expr> dstExpr);

    bool report(S2EExecutionState *state, uint64_t dstAddr, uint64_t len,
                bool reliable, bool isWrite, unsigned depth, uint64_t stack);
    bool reportAccess(S2EExecutionState *state, uint64_t baseAddr,
                      uint64_t dstAddr, unsigned len, bool isWrite,
                      unsigned depth);

    void handleReport(S2EExecutionState *state, PcMonitorState *pcs,
                      uint64_t pc);
    bool handleStore1(S2EExecutionState *state, uint64_t pc);
    bool handleStore2(S2EExecutionState *state, uint64_t pc);
    bool handleStore4(S2EExecutionState *state, uint64_t pc);
    bool handleStore8(S2EExecutionState *state, uint64_t pc);
    bool handleStore16(S2EExecutionState *state, uint64_t pc);
    bool handleStoreN(S2EExecutionState *state, uint64_t pc);
    bool handleLoad1(S2EExecutionState *state, uint64_t pc);
    bool handleLoad2(S2EExecutionState *state, uint64_t pc);
    bool handleLoad4(S2EExecutionState *state, uint64_t pc);
    bool handleLoad8(S2EExecutionState *state, uint64_t pc);
    bool handleLoad16(S2EExecutionState *state, uint64_t pc);
    bool handleLoadN(S2EExecutionState *state, uint64_t pc);

    bool handleCheckMemoryRegion(S2EExecutionState *state, uint64_t pc);
    bool checkMemory(S2EExecutionState *state, unsigned size, bool isWrite,
                     uint64_t ret_ip);
    bool checkMemoryRegion(S2EExecutionState *state, ref<Expr> &dstExpr,
                           ref<Expr> &size, bool isWrite, uint64_t ret_ip);
    bool checkSymMemory(S2EExecutionState *state, ref<Expr> &dstExpr,
                        ref<Expr> &size, AllocObj &obj, uint64_t base_addr);

    // Additional check due to lack of instrumentation in assembly code
    bool handleCsumPartialCopyGeneric(S2EExecutionState *state, uint64_t pc);

    void inline skipKasan(S2EExecutionState *state) {
        if (m_kasanRet != 0) { // rewind stack status
            state->regs()->setPc(m_kasanRet);
        } else {
            state->bypassFunction(0);
        }
        throw CpuExitException();
    }
};

// It's only valid when a call instruction is invoked/executed.
// So it assumes the sp register points to the return address.
#define KASAN_RET_IP                                                           \
    target_ulong ret_ip;                                                       \
    if (!m_kernelFunc->readStack(state, 0, 0, ret_ip)) {                       \
        return true;                                                           \
    }
}
}
#endif
