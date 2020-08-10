#ifndef S2E_PLUGINS_LOOPGUARD_H
#define S2E_PLUGINS_LOOPGUARD_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Lua/LuaPlugin.h>
#include <s2e/Plugins/Models/BaseFunctionModels.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutionStateRegisters.h>

#include "Disassembler.h"
#include "PcMonitor.h"

namespace s2e {
namespace plugins {

struct Guard {
    klee::ref<klee::Expr> value;
    klee::ref<klee::Expr> expcount; // Expected Execution Count
    uint64_t concrete;              // concrete value
    uint64_t diff;
    unsigned onCmp, onAccess;

    Guard()
        : value(klee::ref<klee::Expr>(0)), expcount(klee::ref<klee::Expr>(0)),
          concrete(0), diff(0), onCmp(0), onAccess(0) {}
    void reset() {
        value = klee::ref<klee::Expr>(0);
        expcount = klee::ref<klee::Expr>(0);
        concrete = diff = 0;
        onCmp = onAccess = 0;
    }
};
typedef std::map<uint64_t, Guard *> GuardTable;

class LoopGuard {
  private:
    S2E *m_s2e;
    std::string m_key;
    Disassembler *m_disasm;

  public:
    LoopGuard(S2E *s2e, std::string key) : m_s2e(s2e), m_key(key) {}

  protected:
    void initialGuard();
    void registerGuard(PcMonitor *PcMonitor, S2EExecutionState *state,
                       uint64_t cr3);

    void onCondition(S2EExecutionState *state, PcMonitorState *pcs,
                     uint64_t pc);
    void onAccess(S2EExecutionState *state, PcMonitorState *pcs, uint64_t pc);

    void resolveLoop();

    // Loop Guard
    std::map<uint64_t, uint64_t> m_loopguards; // OOB target --> exit condition
    GuardTable m_guardtable; // exit condition --> guard variable

  public:
    std::map<uint64_t, uint64_t> getLoopGuards() { return m_loopguards; }
    GuardTable getGuardTable() { return m_guardtable; }
};
}
}

#endif
