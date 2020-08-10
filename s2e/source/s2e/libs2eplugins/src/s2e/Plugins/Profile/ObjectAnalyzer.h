#ifndef S2E_PLUGINS_OBJECTANALYZER_H
#define S2E_PLUGINS_OBJECTANALYZER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Lua/LuaPlugin.h>
#include <s2e/Plugins/Models/BaseFunctionModels.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutionStateRegisters.h>

#include "AllocationMap.h"
#include "PcMonitor.h"
#include "Tracer.h"
#include "loopGuard.h"

namespace s2e {
namespace plugins {

class ObjectAnalyzer : public BaseTracer, public LoopGuard, public Plugin {
    S2E_PLUGIN

  public:
    ObjectAnalyzer(S2E *s2e)
        : BaseTracer(s2e, getConfigKey()), LoopGuard(s2e, getConfigKey()),
          Plugin(s2e) {}
    ~ObjectAnalyzer() {}
    void initialize();

  private:
    AllocManager *m_allocManager;

    unsigned m_offset, m_size;
    std::string m_payload;

    void evaluate(S2EExecutionState *state, uint64_t addr, AllocObj &obj);
    void onAllocate(S2EExecutionState *state, AllocCfg *cfg, uint64_t addr);
    void onRelease(S2EExecutionState *state, uint64_t addr);
    void onStateKill(S2EExecutionState *state);
    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);

    void initializeConfiguration();
};
}
}
#endif