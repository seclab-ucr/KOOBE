#ifndef S2E_PLUGINS_KERNELFUNCTIONMODELS_H
#define S2E_PLUGINS_KERNELFUNCTIONMODELS_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/Models/BaseFunctionModels.h>
#include <s2e/Plugins/OSMonitors/Support/MemUtils.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutionStateRegisters.h>
#include <s2e/S2EExecutor.h>

#include <llvm/ADT/StringMap.h>

#include "Options.h"
#include "PcMonitor.h"
#include "ProgramMonitor.h"

namespace s2e {
namespace plugins {
namespace models {

struct FunctionModelCfg {
    uint64_t address;
    unsigned argNum;
    unsigned concretize;
    std::string funcName;
};

// typedef std::vector<HookFunctionCfg> HookFunctions;
typedef std::map<uint64_t, FunctionModelCfg> KernelFunctions;
typedef std::map<uint64_t, uint64_t> ConstraintRanges;

class KernelFunctionModels : public BaseFunctionModels {
    S2E_PLUGIN

  public:
    unsigned eliminate = 0;

  private:
    OptionsManager *m_options;

    typedef bool (KernelFunctionModels::*OpHandler)(S2EExecutionState *state,
                                                    uint64_t pc);
    typedef llvm::StringMap<OpHandler> HandlerMap;

    HandlerMap m_handlers;
    KernelFunctions m_kernelfunc;
    ConstraintRanges m_ranges;
    std::map<uint64_t, bool> m_skipFuncs;

    unsigned m_Regs[6] = {
#ifdef TARGET_X86_64
        // mapping from index of parameter to offset of register
        CPU_OFFSET(regs[R_EDI]), CPU_OFFSET(regs[R_ESI]),
        CPU_OFFSET(regs[R_EDX]), CPU_OFFSET(regs[R_ECX]), CPU_OFFSET(regs[8]),
        CPU_OFFSET(regs[9])
#endif
    };

    void initializeConfiguration();

    void onCall(S2EExecutionState *state, PcMonitorState *pcs, uint64_t pc,
                KernelFunctionModels::OpHandler handler);
    void onSkip(S2EExecutionState *state, PcMonitorState *pcs, uint64_t pc);

    bool handleCopyUser(S2EExecutionState *state, uint64_t pc);
    bool handleStrlen(S2EExecutionState *state, uint64_t pc);
    bool handleMemcpy(S2EExecutionState *state, uint64_t pc);
    bool handleCsumPartialCopyGeneric(S2EExecutionState *state, uint64_t pc);
    bool handleStrncmp(S2EExecutionState *state, uint64_t pc);
    bool handleDoCsum(S2EExecutionState *state, uint64_t pc);

  public:
    KernelFunctionModels(S2E *s2e) : BaseFunctionModels(s2e) {}
    ~KernelFunctionModels() {}

    void initialize();

    void registerHandler(PcMonitor *PcMonitor, S2EExecutionState *state,
                         uint64_t cr3);

    // Utility
    std::string readString(S2EExecutionState *state, target_ulong addr,
                           unsigned MAXSIZE = 128);
    bool strlenConcrete(S2EExecutionState *state, uint64_t stringAddr,
                        size_t &len);
    bool strlenSymbolic(S2EExecutionState *state, uint64_t stringAddr,
                        klee::ref<klee::Expr> &size);
    klee::ref<klee::Expr> makeSymbolic(S2EExecutionState *state,
                                       unsigned offset, std::string name,
                                       bool makeConcolic);
    bool makeConcrete(S2EExecutionState *state, target_ulong addr,
                      unsigned size);

    // Function Hooking Related (Might architecture specific)
    klee::ref<klee::Expr> readSymArgument(S2EExecutionState *state,
                                          unsigned param, bool concretize);
    klee::ref<klee::Expr> readSymRegister(S2EExecutionState *state,
                                          unsigned offset, unsigned size,
                                          bool concretize);
    ref<Expr> readSymMemory(S2EExecutionState *state, target_ulong addr,
                            unsigned size, bool concretize);
    bool readMemory(S2EExecutionState *state, target_ulong addr, unsigned size,
                    uint64_t &arg, bool concretize);
    bool readRegister(S2EExecutionState *state, unsigned offset, unsigned size,
                      uint64_t &arg, bool concretize);
    bool readArgument(S2EExecutionState *state, unsigned param, uint64_t &arg,
                      bool concretize);
    void getRetValue(S2EExecutionState *state, uint64_t &arg);
    unsigned getArgumentOffset(unsigned param) {
        assert(param < 6);
        return m_Regs[param];
    }
    bool readStack(S2EExecutionState *state, target_ulong stack, unsigned index,
                   target_ulong &arg);
    bool dump_stack(S2EExecutionState *state, target_ulong stack, target_ulong frame, std::vector<target_ulong> &addrs, unsigned depth);

    // allow adding new constraints
    void decideAddConstraint(uint64_t pc, bool *allowConstraint);
};
}
}
}
#endif
