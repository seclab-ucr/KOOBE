#ifndef S2E_PLUGINS_TRACER_H
#define S2E_PLUGINS_TRACER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Lua/LuaPlugin.h>
#include <s2e/Plugins/Models/BaseFunctionModels.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutionStateRegisters.h>

#include "AllocationMap.h"
#include "Disassembler.h"
#include "Evaluation.h"
#include "Kasan.h"
#include "KernelFunctionModels.h"
#include "Options.h"
#include "PcMonitor.h"
#include "ProgramMonitor.h"

namespace s2e {
namespace plugins {

class BaseTracer : public ILuaPlugin {
  private:
    S2E *m_s2e;
    std::string m_key;

  public:
    BaseTracer(S2E *s2e, std::string key) : m_s2e(s2e), m_key(key) {}
    ~BaseTracer(){};

    void initializeTracer();
    void registerTracer(S2EExecutionState *state, uint64_t cr3);
    void killState(S2EExecutionState *state, std::string msg);

    template <class T, typename RET, typename... PARAM_TYPES>
    void registerSyscall(S2EExecutionState *state, uint64_t cr3, T &obj,
                         RET (T::*f)(PARAM_TYPES...)) {
        bool ok = false;
        ConfigFile *cfg = m_s2e->getConfig();
        ConfigFile::string_list funcList = cfg->getListKeys(m_key + ".syscall");
        foreach2(it, funcList.begin(), funcList.end()) {
            std::stringstream s;
            s << m_key << ".syscall." << *it;
            uint64_t address = cfg->getInt(s.str(), -1, &ok);
            EXIT_ON_ERROR(ok, "You must specify " + s.str() + "address");

            PcMonitor::CallSignalPtr callsignal =
                m_PcMonitor->getCallSignal(state, address, cr3);
            callsignal->connect(sigc::mem_fun<T, RET, PARAM_TYPES...>(obj, f),
                                SYSCALL_PRIORITY);
        }
    }

    virtual int getLuaPlugin(lua_State *L);

  protected:
    PcMonitor *m_PcMonitor;
    models::KernelFunctionModels *m_KernelFunc;
    ProcessExecutionDetector *m_procDetector;
    ModuleExecutionDetector *m_modDetector;
    ProgramMonitor *m_ProgMonitor;
    OSMonitor *m_OSmonitor;
    OptionsManager *m_options;
    KernelAddressSanitizer *m_Kasan;

    bool m_registered = false;
    bool m_debugconstraints = false;
    // Addresses where we add constraint (fork spot)
    std::vector<std::pair<uint64_t, ref<Expr>>> m_conditions;
    std::vector<uint16_t> m_labels;
    std::map<uint64_t, uint16_t> thread_counters; // thread id -> counter

    // User Interactive
    std::map<uint64_t, std::string> m_annotations; // pc: onExecute

    //
    bool onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);

    // utility
    void skipInstruction(S2EExecutionState *state);
    void dump(S2EExecutionState *state);

  private:
    // Registered Callback
    void onAnnotate(S2EExecutionState *state, PcMonitorState *pcs, uint64_t pc);
    void onStateForkDecide(S2EExecutionState *state, bool *allowForking);
    void onConstraint(S2EExecutionState *state, klee::ref<klee::Expr> condition,
                      bool *allow);
    void onNewIter(S2EExecutionState *state);
};
}
}
#endif
