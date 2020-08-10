///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <iostream>

#include "PcMonitor.h"
#include "util.h"

namespace s2e {
namespace plugins {

// As opposed to FunctionMonitor, this plugin only monitor specific function
// given in the configuration file
S2E_DEFINE_PLUGIN(PcMonitor, "Function calls/returns monitoring plugin",
                  "PcMonitor", "ProcessExecutionDetector", "Disassembler",
                  "ProgramMonitor", "OSMonitor");

void PcMonitor::initialize() {
    m_procDetector = s2e()->getPlugin<ProcessExecutionDetector>();
    m_disasm = s2e()->getPlugin<Disassembler>();
    m_progMonitor = s2e()->getPlugin<ProgramMonitor>();
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    m_traceBuffer.reserve(1024);
    createNewTraceFile();
    initializeConfiguration();

    m_fc1 = m_procDetector->onMonitorLoad.connect(
        sigc::mem_fun(*this, &PcMonitor::onMonitorLoad));
    m_fc2 = s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
        sigc::mem_fun(*this, &PcMonitor::onTranslateInstruction));
    m_fc3 = s2e()->getCorePlugin()->onTranslateJumpStart.connect(
        sigc::mem_fun(*this, &PcMonitor::slotTranslateJumpStart));
}

void PcMonitor::initializeConfiguration() {
    bool ok = false;
    ConfigFile *cfg = s2e()->getConfig();
    recordTrace = cfg->getBool(getConfigKey() + ".recordTrace", false, &ok);
    m_trackroot = cfg->getBool(getConfigKey() + ".trackroot", false, &ok);
    limitcount = cfg->getInt(getConfigKey() + ".limitcount", 300000, &ok);
    m_debuginst = cfg->getBool(getConfigKey() + ".debuginst", false, &ok);
    m_hookadc = cfg->getBool(getConfigKey() + ".hookadc", false, &ok);
    // KERNEL_START = cfg->getInt(getConfigKey() + ".kernelstart",
    // 0xffff880000000000, &ok);
    KASAN_REPORT = cfg->getInt(getConfigKey() + ".kasan_report", -1, &ok);
    if (ok) {
        pid_offset = cfg->getInt(getConfigKey() + ".pid_offset", -1, &ok);
        EXIT_ON_ERROR(ok, "PID_OFFSET");
        tgid_offset = cfg->getInt(getConfigKey() + ".tgid_offset", -1, &ok);
        EXIT_ON_ERROR(ok, "TGID_OFFSET");
    }

    ConfigFile::integer_list pids;
    pids = cfg->getIntegerList(getConfigKey() + ".pids", pids, &ok);
    foreach2(it, pids.begin(), pids.end()) { m_pids.insert({*it, true}); }
}

void PcMonitor::shutdown() {
    m_fc1.disconnect();
    m_fc2.disconnect();
    m_fc3.disconnect();
}

PcMonitor::~PcMonitor() {
    if (m_LogFile) {
        flushTrace();
        fclose(m_LogFile);
    }
}

void PcMonitor::onMonitorLoad(S2EExecutionState *state) {
    m_initialized = true;
}

void PcMonitor::onTranslateInstruction(ExecutionSignal *signal,
                                       S2EExecutionState *state,
                                       TranslationBlock *tb, uint64_t pc) {
    // only trace those code in kernel space
    if (isKernelPC(pc)) {
        if (m_progMonitor->isStart()) {
            if (isHooked(pc)) {
                signal->connect(
                    sigc::mem_fun(*this, &PcMonitor::onInstructionExecution));
            }

            cs_insn *insn = m_disasm->getInst(state, pc);
            if (insn == NULL) return;

            std::string mnemonic(insn->mnemonic);
            if (mnemonic == "bsr") {
                signal->connect(sigc::mem_fun(*this, &PcMonitor::onBsrInstruction));
            } else if (mnemonic == "bsf") {
                signal->connect(sigc::mem_fun(*this, &PcMonitor::onBsfInstruction));  
            } else if (mnemonic == "adc") {
                signal->connect(sigc::mem_fun(*this, &PcMonitor::onAdcInstruction));
            }
        }
    }
}

bool PcMonitor::isHooked(uint64_t pc) {
    if (recordTrace)
        return true;

    if (pc == KASAN_REPORT)
        return true;

    auto states = s2e()->getExecutor()->getStates();
    for (auto each : states) {
        S2EExecutionState *s2eState = static_cast<S2EExecutionState*>(each);
        DECLARE_PLUGINSTATE(PcMonitorState, s2eState);
        if (plgState->m_callDescriptors.find(pc) != plgState->m_callDescriptors.end()){
            return true;
        }
    }
    return false;
}

bool PcMonitor::isTracked(S2EExecutionState *state, uint64_t pc) {
    if (!m_progMonitor->isStart()) {
        return false;
    }

    uint64_t pid = m_monitor->getPid(state);
    if (m_pids.find(pid) != m_pids.end()) {
        return true;
    }

    if (m_trackroot /* && pid < 100*/) {
        return true;
    }

    if (!m_procDetector->isTracked(state, pid)) {
        if (pc == KASAN_REPORT) {
            // Miss this report
            getDebugStream(state) << "Observe KASAN_REPORT " << hexval(pc)
                                  << " with pid: " << pid << "\n";
            getDebugStream() << "[DEBUG] {\"pid\": " << pid
                             << ", \"msg\": \"kasan report\"}\n";
            s2e()->getExecutor()->terminateState(
                *state, "Missing OOB, please enable root");
        }
        return false;
    }

    return true;
}

void PcMonitor::slotTranslateJumpStart(ExecutionSignal *signal,
                                       S2EExecutionState *state,
                                       TranslationBlock *, uint64_t pc,
                                       int jump_type) {
    if (!m_initialized) {
        return;
    }

    if (!isKernelPC(pc)) {
        return;
    }

    if (jump_type == JT_RET || jump_type == JT_LRET) {
        signal->connect(sigc::mem_fun(*this, &PcMonitor::slotRet));
    }
}

void PcMonitor::onBsrInstruction(S2EExecutionState *state, uint64_t pc) {
    if (!isTracked(state, pc)) {
        return;
    }
    m_disasm->doBsr(state, pc);
}

void PcMonitor::onBsfInstruction(S2EExecutionState *state, uint64_t pc) {
    if (!isTracked(state, pc)) 
        return;
    m_disasm->doBsf(state, pc);
}

void PcMonitor::onAdcInstruction(S2EExecutionState *state, uint64_t pc) {
    if (!m_hookadc) {
        return;
    }
    if (!isTracked(state, pc)) {
        return;
    }
    m_disasm->concretize(state, pc);
}

void PcMonitor::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {
    if (!isTracked(state, pc)) {
        return;
    }

    if (m_debuginst) {
        static auto prevTime = getmilliseconds() / 1000;
        auto curTime = getmilliseconds() / 1000;
        if (curTime - prevTime > 10) {
            getDebugStream() << "Last Instruction Takes too much time!!\n";
            getDebugStream()
                << std::to_string(counter) << " " << hexval(pc) << "\n";
            dumpState(state);
        }
        prevTime = curTime;
    }

    if (recordTrace) {
        appendTrace(pc);
        if (counter % limitcount == 0) {
            getDebugStream(state)
                << std::to_string(counter) << " " << hexval(pc) << "\n";
            // counter = 0;
        }
        counter++;
    }

    DECLARE_PLUGINSTATE(PcMonitorState, state);
    return plgState->slotCall(state, pc);
}

//
// Function Monitor
//
PcMonitor::CallSignalPtr PcMonitor::getCallSignal(S2EExecutionState *state,
                                                uint64_t eip, uint64_t cr3) {
    DECLARE_PLUGINSTATE(PcMonitorState, state);

    return plgState->getCallSignal(eip, cr3);
}

void PcMonitor::slotRet(S2EExecutionState *state, uint64_t pc) {
    if (!isTracked(state, pc)) {
        return;
    }

    DECLARE_PLUGINSTATE(PcMonitorState, state);

    return plgState->slotRet(state, pc, true);
}
///
/// Instruction Trace
///
void PcMonitor::flushTrace() {
    if (m_traceBuffer.size() == 0) {
        return;
    }

    uint64_t *allItems = &m_traceBuffer[0];
    if (fwrite(allItems, sizeof(uint64_t) * m_traceBuffer.size(), 1,
               m_LogFile) != 1) {
        assert(false);
    }
    m_traceBuffer.clear();
}

void PcMonitor::appendTrace(uint64_t p) {
    if (m_traceBuffer.size() == m_traceBuffer.capacity()) { // full
        flushTrace();
    }
    m_traceBuffer.push_back(p);
}

void PcMonitor::createNewTraceFile() {
    std::string m_fileName =
        s2e()->getOutputFilename("KernelExecutionTracer.dat");
    m_LogFile = fopen(m_fileName.c_str(), "wb");
    if (!m_LogFile) {
        getWarningsStream() << "Could not create KernelExecutionTracer.dat\n";
        exit(-1);
    }
}

// plugin state
PcMonitorState::PcMonitorState() {}
PcMonitorState::~PcMonitorState() {}

PcMonitorState *PcMonitorState::clone() const {
    PcMonitorState *ret = new PcMonitorState(*this);
    assert(ret->m_returnDescriptors.size() == m_returnDescriptors.size());
    return ret;
}

PluginState *PcMonitorState::factory(Plugin *p, S2EExecutionState *s) {
    PcMonitorState *ret = new PcMonitorState();
    ret->m_plugin = static_cast<PcMonitor *>(p);
    return ret;
}

PcMonitor::CallSignalPtr PcMonitorState::getCallSignal(uint64_t eip,
                                                     uint64_t cr3) {
    std::pair<CallDescriptorsMap::iterator, CallDescriptorsMap::iterator>
        range = m_callDescriptors.equal_range(eip);

    for (CallDescriptorsMap::iterator it = range.first; it != range.second;
         ++it) {
        if (it->second.cr3 == cr3)
            return it->second.signal;
    }

    auto signal = new PcMonitor::CallSignal();
    auto sigPtr = std::shared_ptr<PcMonitor::CallSignal>(signal);
    CallDescriptor descriptor = {cr3, sigPtr};
    CallDescriptorsMap::iterator it =
        m_callDescriptors.insert(std::make_pair(eip, descriptor));

    return it->second.signal;
}

void PcMonitorState::slotCall(S2EExecutionState *state, uint64_t pc) {
    if (m_callDescriptors.find(pc) == m_callDescriptors.end()) {
        return;
    }

    if (!m_callDescriptors.empty()) {
        std::pair<CallDescriptorsMap::iterator, CallDescriptorsMap::iterator>
            range;
        target_ulong cr3 = state->regs()->getPageDir();
        range = m_callDescriptors.equal_range(pc);
        for (CallDescriptorsMap::iterator it = range.first; it != range.second;
             ++it) {
            CallDescriptor &cd = it->second;
            if (it->second.cr3 == (uint64_t)-1 || it->second.cr3 == cr3) {
                cd.signal->emit(state, this, pc);
            }
        }
    }
}

void PcMonitorState::registerReturnSignal(S2EExecutionState *state,
                                          PcMonitor::ReturnSignalPtr &sig) {
    if (sig->empty()) {
        return;
    }

    target_ulong esp;

    bool ok =
        state->regs()->read(CPU_OFFSET(regs[R_ESP]), &esp, sizeof esp, false);
    if (!ok) {
        m_plugin->getWarningsStream(state)
            << "Function call with symbolic ESP!\n"
            << "  EIP=" << hexval(state->regs()->getPc())
            << " CR3=" << hexval(state->regs()->getPageDir()) << '\n';
        return;
    }

    uint64_t cr3 = state->regs()->getPageDir();
    ReturnDescriptor descriptor = {cr3, sig};
    m_returnDescriptors.insert(std::make_pair(esp, descriptor));
}

/**
 *  When emitSignal is false, this function simply removes all the return
 * descriptors
 * for the current stack pointer. This can be used when a return handler
 * manually changes the
 * program counter and/or wants to exit to the cpu loop and avoid being called
 * again.
 *
 *  Note: all the return handlers will be erased if emitSignal is false, not
 * just the one
 * that issued the call. Also note that it not possible to return from the
 * handler normally
 * whenever this function is called from within a return handler.
 */
void PcMonitorState::slotRet(S2EExecutionState *state, uint64_t pc,
                             bool emitSignal) {
    target_ulong cr3 = state->regs()->read<target_ulong>(CPU_OFFSET(cr[3]));

    target_ulong esp;
    bool ok = state->regs()->read(CPU_OFFSET(regs[R_ESP]), &esp,
                                  sizeof(target_ulong), false);
    if (!ok) {
        target_ulong eip = state->regs()->read<target_ulong>(CPU_OFFSET(eip));

        m_plugin->getWarningsStream(state)
            << "Function return with symbolic ESP!" << '\n'
            << "  EIP=" << hexval(eip) << " CR3=" << hexval(cr3) << '\n';
        return;
    }

    if (m_returnDescriptors.empty()) {
        return;
    }

    // m_plugin->getDebugStream() << "ESP AT RETURN " <<  hexval(esp) <<
    //        " EmitSignal=" << emitSignal << "\n";

    bool finished = true;
    do {
        finished = true;
        std::pair<ReturnDescriptorsMap::iterator,
                  ReturnDescriptorsMap::iterator>
            range = m_returnDescriptors.equal_range(esp);
        for (ReturnDescriptorsMap::iterator it = range.first;
             it != range.second; ++it) {

            if (it->second.cr3 == cr3 || it->second.cr3 == (uint64_t)-1) {
                if (emitSignal) {
                    it->second.signal->emit(state);
                }
                m_returnDescriptors.erase(it);
                finished = false;
                break;
            }
        }
    } while (!finished);
}
} // namespace plugins
} // namespace s2e
