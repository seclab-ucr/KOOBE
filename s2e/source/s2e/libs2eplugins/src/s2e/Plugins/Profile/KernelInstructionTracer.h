#ifndef S2E_PLUGINS_KERNELINSTRUCTIONTRACER_H
#define S2E_PLUGINS_KERNELINSTRUCTIONTRACER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Lua/LuaPlugin.h>
#include <s2e/Plugins/Models/BaseFunctionModels.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutionStateRegisters.h>

#include "AllocationMap.h"
#include "Disassembler.h"
#include "Evaluation.h"
#include "Kasan.h"
#include "KernelFunctionModels.h"
#include "PcMonitor.h"
#include "ProgramMonitor.h"
#include "Tracer.h"
#include "loopGuard.h"

namespace s2e {
namespace plugins {

// typedef std::vector<HookFunctionCfg> HookFunctions;
typedef std::map<uint64_t, std::vector<OOB_Operation>> Overflows;

class KernelInstructionTracer : public BaseTracer,
                                public LoopGuard,
                                public Plugin {
    S2E_PLUGIN

  public:
    KernelInstructionTracer(S2E *s2e)
        : BaseTracer(s2e, getConfigKey()), LoopGuard(s2e, getConfigKey()),
          Plugin(s2e) {}
    ~KernelInstructionTracer();

    void initialize();

  private:
    Disassembler *m_Disasm;
    AllocManager *m_AllocManager;

    ConfigFile::integer_list m_targetAddrs;
    std::map<uint64_t, Spot> m_spots;
    bool m_refineconstraint = true;
    std::string m_capfile;
    std::string m_workdir;

    // OOB occurs at multiple places
    bool m_multispots = false;
    Overflows
        m_overflows; // OOB target --> all operations (including dst, size,
    // and payload)
    unsigned m_order = 0;

    // Registered Callback
    void onTarget(S2EExecutionState *state, PcMonitorState *pcs, uint64_t pc);
    void onExit(S2EExecutionState *state, PcMonitorState *pcs, uint64_t pc);
    void onHalt(S2EExecutionState *state);
    void onSegFault(S2EExecutionState *state, uint64_t pid, uint64_t pc);

    // void onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t
    // pid, const std::string &ImageFileName);
    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);
    void onStateForkDecide(S2EExecutionState *state, bool *allowForking);
    void onSyscall(S2EExecutionState *state, PcMonitorState *fns, uint64_t pc);

    // Initialize configuration
    void initializeConfiguration();

    void dump(S2EExecutionState *state);
    void dumpOperations(S2EExecutionState *state,
                        std::vector<OOB_Operation> &allops, uint64_t base,
                        uint64_t left, uint64_t size);

    // Find solution/Generate test case
    bool eliminate_contradition(S2EExecutionState *state,
                                klee::ConstraintManager &manager,
                                klee::ConstraintManager &origin, bool tune);
    bool validate(S2EExecutionState *state, klee::ref<klee::Expr> dstExpr,
                  uint64_t srcAddr, klee::ref<klee::Expr> data,
                  klee::ref<klee::Expr> len);
    bool solve(S2EExecutionState *state, klee::ref<klee::Expr> dstExpr,
               uint64_t srcAddr, klee::ref<klee::Expr> data,
               klee::ref<klee::Expr> len);
    int Evaluate_Once(S2EExecutionState *state, klee::ConstraintManager &origin,
                      std::string &target, uint64_t base_addr,
                      AllocObj &vul_obj, unsigned vul_size, int offset, int len,
                      klee::ref<klee::Expr> &dstExpr, uint64_t srcAddr,
                      klee::ref<klee::Expr> &dataExpr,
                      klee::ref<klee::Expr> &lenExpr, uint8_t *payload,
                      int type);
    int Evaluate_Once_Solution(S2EExecutionState *state,
                               klee::ConstraintManager &manager,
                               klee::ref<klee::Expr> lenExpr, unsigned vul_size,
                               int len, uint8_t *payload, std::string &target,
                               klee::UpdateListPtr &data_ul, klee::ArrayPtr &array,
                               std::vector<unsigned char> &concrete_raw_data,
                               int type, uint64_t index, bool solve);

    bool resolveMemcpy(S2EExecutionState *state, Spot spot);
    bool resolveStrcpy(S2EExecutionState *state, Spot spot);
    bool resolveStore(S2EExecutionState *state, Spot spot);
    bool resolveMultiStore(S2EExecutionState *state);

    bool iterativeSolve(S2EExecutionState *state, uint64_t base_addr, std::vector<OOB_Operation> &allops);
    int iterativeSolve_one(S2EExecutionState *state,
                           klee::ConstraintManager &origin, std::string &target,
                           uint64_t base_addr, AllocObj &vul_obj,
                           unsigned vul_size, int offset, int len,
                           uint8_t *payload, std::vector<OOB_Operation> &allops,
                           int type);

    bool solveWithCapability(S2EExecutionState *state,
                             std::vector<Capability> &cap);
    int solveCapability_once(S2EExecutionState *state,
                             std::vector<Capability> &cap, std::string &target,
                             unsigned vul_size, int offset, int len,
                             uint8_t *payload, int type);

    bool exitWithDistribution(S2EExecutionState *state);
    void resolveMultiStoreOnExit(S2EExecutionState *state);

    bool applyOperations(S2EExecutionState *state, uint64_t model_len,
                         uint64_t model_diff, UpdateListPtr &data_ul,
                         Capability &cap);

    uint64_t roundSize(uint64_t size);
    bool getCandidate(uint64_t &vul_size, bool isVariable,
                      std::string allocator, int &offset, uint8_t **pointer,
                      uint64_t &len);
    bool getCurCandidate(std::string &name);
    bool getValues(uint8_t **pointer, uint64_t &len);

    bool CheckOverflow(S2EExecutionState *state, Spot spot);
    bool findbase(S2EExecutionState *state, klee::ref<klee::Expr> &addr,
                  uint64_t &base_addr);

    void printLayout(S2EExecutionState *state, uint64_t base_addr);
    void printSyscalls(S2EExecutionState *state, uint64_t base_addr);
};
}
}
#endif
