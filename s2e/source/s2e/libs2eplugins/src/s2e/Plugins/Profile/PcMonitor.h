#ifndef S2E_PLUGINS_PCMONITOR_H
#define S2E_PLUGINS_PCMONITOR_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/S2EExecutionState.h>

#include <tr1/unordered_map>

#include "Disassembler.h"
#include "ProgramMonitor.h"

namespace s2e {
namespace plugins {

#define OPTION_MEM_READ 1
#define OPTION_MEM_WRITE 2
#define OPTION_MEM_READ_OR_WRITE (OPTION_MEM_READ | OPTION_MEM_WRITE)

class OSMonitor;
class PcMonitorState;

class PcMonitor : public Plugin {
    S2E_PLUGIN
  public:
    PcMonitor(S2E *s2e) : Plugin(s2e) {}
    ~PcMonitor();
    void initialize();

    typedef sigc::signal<void, S2EExecutionState *> ReturnSignal;
    typedef sigc::signal<void, S2EExecutionState *, PcMonitorState *, uint64_t>
        CallSignal;
    typedef std::shared_ptr<ReturnSignal> ReturnSignalPtr;
    typedef std::shared_ptr<CallSignal> CallSignalPtr;

    CallSignalPtr getCallSignal(S2EExecutionState *state, uint64_t eip,
                              uint64_t cr3 = 0);

    bool isTracked(S2EExecutionState *state, uint64_t pc);

    // on translation signal
    void shutdown();

    uint64_t inline getCounter() { return counter; }

  private:
    bool m_trackroot = false;
    unsigned limitcount;
    bool m_debuginst = false;
    bool m_hookadc = false;

    const uint64_t KERNEL_START = 0xffff880000000000;
    uint64_t KASAN_REPORT;

    unsigned pid_offset, tgid_offset;
    std::map<unsigned, bool> m_pids;

    ProcessExecutionDetector *m_procDetector;
    Disassembler *m_disasm;
    ProgramMonitor *m_progMonitor;
    OSMonitor *m_monitor;
    uint64_t counter = 0;

    // signal function
    sigc::connection m_fc1, m_fc2, m_fc3;

    // Instruction Trace
    typedef std::vector<uint64_t> InsTrace;
    InsTrace m_traceBuffer;
    FILE *m_LogFile;
    bool recordTrace = false;
    void flushTrace();
    void appendTrace(uint64_t p);
    void createNewTraceFile();

    volatile bool m_initialized = false;

    void slotRet(S2EExecutionState *state, uint64_t pc);
    void onInstructionExecution(S2EExecutionState *state, uint64_t pc);
    void slotTranslateJumpStart(ExecutionSignal *signal,
                                S2EExecutionState *state, TranslationBlock *,
                                uint64_t, int jump_type);
    void onTranslateInstruction(ExecutionSignal *signal,
                                S2EExecutionState *state, TranslationBlock *tb,
                                uint64_t pc);
    void onMonitorLoad(S2EExecutionState *state);
    void initializeConfiguration();

    void onBsrInstruction(S2EExecutionState *state, uint64_t pc);
    void onBsfInstruction(S2EExecutionState *state, uint64_t pc);
    void onAdcInstruction(S2EExecutionState *state, uint64_t pc);

    bool inline isKernelPC(uint64_t pc) { return pc >= KERNEL_START; }
    bool isHooked(uint64_t pc);

  protected:
    friend class PcMonitorState;
};

class PcMonitorState : public PluginState {

    struct CallDescriptor {
        uint64_t cr3;
        // TODO: add sourceModuleID and targetModuleID
        // Consider threadID?
        PcMonitor::CallSignalPtr signal;
    };

    struct ReturnDescriptor {
        // S2EExecutionState *state;
        uint64_t cr3;
        // TODO: add sourceModuleID and targetModuleID
        PcMonitor::ReturnSignalPtr signal;
    };
    typedef std::tr1::unordered_multimap<uint64_t, CallDescriptor>
        CallDescriptorsMap;
    typedef std::tr1::unordered_multimap<uint64_t, ReturnDescriptor>
        ReturnDescriptorsMap;

    CallDescriptorsMap m_callDescriptors;
    // CallDescriptorsMap m_newCallDescriptors;
    ReturnDescriptorsMap m_returnDescriptors;

    PcMonitor *m_plugin;

    /* Get a signal that is emitted on function calls. Passing eip = 0 means
       any function, and cr3 = 0 means any cr3 */
    PcMonitor::CallSignalPtr getCallSignal(uint64_t eip, uint64_t cr3 = 0);

    void slotCall(S2EExecutionState *state, uint64_t pc);
    void slotRet(S2EExecutionState *state, uint64_t pc, bool emitSignal);

  public:
    PcMonitorState();
    virtual ~PcMonitorState();
    virtual PcMonitorState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);
    void registerReturnSignal(S2EExecutionState *state,
                              PcMonitor::ReturnSignalPtr &sig);

    friend class PcMonitor;
};

#define PCMON_REGISTER_RETURN(state, fns, func)             \
    {                                                       \
        auto returnSignal = new PcMonitor::ReturnSignal();  \
        auto retSigPtr = std::shared_ptr<PcMonitor::ReturnSignal>(returnSignal);  \
        returnSignal->connect(sigc::mem_fun(*this, &func));  \
        fns->registerReturnSignal(state, retSigPtr);  \
    }

#define PCMON_REGISTER_RETURN_A(state, fns, func, ...)                         \
    {                                                                          \
        auto returnSignal = new PcMonitor::ReturnSignal();                                  \
        auto retSigPtr = std::shared_ptr<PcMonitor::ReturnSignal>(returnSignal);  \
        returnSignal->connect(                                                  \
            sigc::bind(sigc::mem_fun(*this, &func), __VA_ARGS__));             \
        fns->registerReturnSignal(state, retSigPtr);                        \
    }
}
}
#endif
