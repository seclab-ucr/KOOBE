#include <s2e/S2E.h>

#include "ProgramMonitor.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ProgramMonitor, "Receive command from program",
                  "ProgramMonitor", "ProcessExecutionDetector", "OSMonitor");

void ProgramMonitor::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_procDetector = s2e()->getPlugin<ProcessExecutionDetector>();

    bool ok;
    bool loadAtstart =
        s2e()->getConfig()->getBool(getConfigKey() + ".loadstart", false, &ok);
    if (loadAtstart) {
        getDebugStream() << "Load at start...\n";
        Start();
    }
}

// Handler custom command
void ProgramMonitor::handleCommand(S2EExecutionState *state,
                                   unsigned char cmd) {
    switch (cmd) {
    case 's': // start to monitor
        if (!m_flush_tbs) {
            // Flush the tlb to allow to register callback to instructions that may have passed translation phase.
            se_tb_safe_flush();
            m_flush_tbs = true;
        }

        m_procDetector->trackPid(state, m_monitor->getPid(state));
        Start();
        getDebugStream(state) << "Start Monitoring...\n";
        break;
    case 'e': // end of monitoring
        Stop();
        getDebugStream(state) << "Stop Monitoring...\n";

        onExit.emit(state);
        s2e()->getExecutor()->terminateState(*state, "Stop tracing at the end");
        break;
    case 'm': // TODO: mark of new iteration for race condition
        onMark.emit(state);
        break;
    }
}

void ProgramMonitor::handleOpcodeInvocation(S2EExecutionState *state,
                                            uint64_t guestDataPtr,
                                            uint64_t guestDataSize) {
    unsigned char cmd;
    switch (guestDataSize) {
    case 1:
        if (!state->mem()->read(guestDataPtr, &cmd, 1)) {
            getWarningsStream(state) << "Cound not read transmitted data\n";
            exit(1);
        }
        handleCommand(state, cmd);
        break;
    default:
        getWarningsStream(state) << "Unsupported command\n";
        exit(1);
    }
}
} // namespace plugins
} // namespace s2e
