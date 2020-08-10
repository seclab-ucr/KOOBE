#ifndef S2E_PLUGINS_PROGRAMMONITOR_H
#define S2E_PLUGINS_PROGRAMMONITOR_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>

namespace s2e {
namespace plugins {

class ProgramMonitor : public Plugin, public IPluginInvoker {
    S2E_PLUGIN

  public:
    ProgramMonitor(S2E *s2e) : Plugin(s2e) {}
    ~ProgramMonitor() {}

    void initialize();
    virtual void handleOpcodeInvocation(S2EExecutionState *state,
                                        uint64_t guestDataPtr,
                                        uint64_t guestDataSize);

    bool isStart() { return m_onStart; }

  private:
    OSMonitor *m_monitor;
    ProcessExecutionDetector *m_procDetector;

    bool m_onStart = false;
    bool m_flush_tbs = false;

    void inline Start() { m_onStart = true; }
    void inline Stop() { m_onStart = false; }
    // handle custom command
    void handleCommand(S2EExecutionState *state, unsigned char cmd);

  public:
    sigc::signal<void, S2EExecutionState *> onMark;
    sigc::signal<void, S2EExecutionState *> onExit;
};
}
}
#endif
