#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Lua/LuaS2EExecutionState.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <klee/Expr.h>
#include <klee/util/ExprTemplates.h>

#include <algorithm>

#include "KernelInstructionTracer.h"
#include "LuaKernel.h"
#include "util.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(KernelInstructionTracer, "Track Instructions in Kernel",
                  "KernelInstructionTracer", "ProcessExecutionDetector",
                  "PcMonitor", "Disassembler", "KernelFunctionModels",
                  "OptionsManager");

void KernelInstructionTracer::initialize() {
    // Initialize extension first
    initializeTracer();
    initialGuard();

    m_Disasm = s2e()->getPlugin<Disassembler>();
    m_AllocManager = s2e()->getPlugin<AllocManager>();
    assert(m_Disasm);
    assert(m_AllocManager);

    initializeConfiguration();

    m_modDetector->onModuleLoad.connect(
        sigc::mem_fun(*this, &KernelInstructionTracer::onModuleLoad));
    m_ProgMonitor->onExit.connect(sigc::mem_fun(
        *this, &KernelInstructionTracer::resolveMultiStoreOnExit));

    LinuxMonitor *linux = s2e()->getPlugin<LinuxMonitor>();
    if (linux) {
        linux->onSegFault.connect(
            sigc::mem_fun(*this, &KernelInstructionTracer::onSegFault));
    } // else other systems
    getDebugStream() << "S2E: {\"start\": " << std::to_string(getmilliseconds())
                     << "}\n";
}

void KernelInstructionTracer::initializeConfiguration() {
    bool ok = false;
    ConfigFile *cfg = s2e()->getConfig();

    // m_targetAddr = cfg->getInt(getConfigKey() + ".target", -1, &ok);
    m_targetAddrs =
        cfg->getIntegerList(getConfigKey() + ".targets", m_targetAddrs, &ok);
    EXIT_ON_ERROR((m_options->mode != MODE_ANALYSIS) || ok,
                  "You must specify " + getConfigKey() + ".targets");
    m_refineconstraint =
        cfg->getBool(getConfigKey() + ".refineconstraint", true, &ok);
    m_capfile = cfg->getString(getConfigKey() + ".capfile", "", &ok);
    m_workdir = cfg->getString(getConfigKey() + ".workdir", "", &ok);
    m_multispots = m_targetAddrs.size() > 1;

    // initialize the signature of our target function
    std::string key = getConfigKey() + ".spots";
    ConfigFile::string_list spotList = cfg->getListKeys(key, &ok);
    EXIT_ON_ERROR((m_options->mode != MODE_ANALYSIS) || ok,
                  "You must specify spots");
    foreach2(it, spotList.begin(), spotList.end()) {
        Spot spot;
        std::stringstream ss;
        ss << key << "." << *it;
        uint64_t addr = cfg->getInt(ss.str() + ".addr", 0, &ok);
        if (std::find(m_targetAddrs.begin(), m_targetAddrs.end(), addr) ==
            m_targetAddrs.end()) {
            assert(false && "Unknown address");
        }
        spot.type = cfg->getInt(ss.str() + ".type", 0, &ok);
        EXIT_ON_ERROR(ok, "You must specify type");
        spot.sig.defaultValue(spot.type);
        if (spot.type > TYPE_STORE) {
            uint64_t param = cfg->getInt(ss.str() + ".signature.src", 0, &ok);
            if (ok)
                spot.sig.src = param;
            param = cfg->getInt(ss.str() + ".signature.dst", 0, &ok);
            if (ok)
                spot.sig.dst = param;
            param = cfg->getInt(ss.str() + ".signature.len", 0, &ok);
            if (ok)
                spot.sig.len = param;
        }
        m_spots.insert({addr, spot});
    }
}

KernelInstructionTracer::~KernelInstructionTracer() {}

//
// Instruction instrumentation
//

void KernelInstructionTracer::onTarget(S2EExecutionState *state,
                                       PcMonitorState *pcs, uint64_t pc) {
    if (std::find(m_targetAddrs.begin(), m_targetAddrs.end(), pc) !=
        m_targetAddrs.end()) {
        assert(state->constraints().size() == m_conditions.size() &&
               "mismatch constraint number");
        if (m_spots.find(pc) == m_spots.end()) {
            assert(false && "No spot info found");
        }
        m_AllocManager->recordSyscall();

        Spot spot = m_spots[pc];
        bool success = false;
        uint64_t start = getmilliseconds();
        getDebugStream() << "S2E: {\"target\": " << std::to_string(start) << "}\n";
        if (m_options->mode == MODE_RESOLVE) {
            switch (spot.type) {
            case TYPE_MEMCPY:
                success = resolveMemcpy(state, spot);
                break;
            case TYPE_STRCPY:
                success = resolveStrcpy(state, spot);
                break;
            case TYPE_STORE:
                success = resolveStore(state, spot);
                break;
            case TYPE_MEMSET:
            default:
                assert(false && "Not supported yet");
                break;
            }
        } else if (m_options->mode == MODE_ANALYSIS) {
            skipInstruction(state);
            return;
        } else {
            assert(false);
        }
        // shutdown();
        if (success) {
            if (m_multispots) {
                skipInstruction(state);
                return;
            }
            getDebugStream(state)
                << "Avoid adding " << hexval(m_KernelFunc->eliminate)
                << " constraints\n";
            getDebugStream(state)
                << "Stop tracing at the target " << hexval(pc) << "\n";

            uint64_t end = getmilliseconds();
            getDebugStream(state)
                << "Solving time: " << std::to_string(end - start) << "\n";
            s2e()->getExecutor()->terminateState(*state,
                                                 "Stop tracing at the target");
        }
    }
}

// The program is about the exit, this is the last chance to solve the
// constraints
void KernelInstructionTracer::resolveMultiStoreOnExit(
    S2EExecutionState *state) {
    if (m_options->mode == MODE_RESOLVE) { // only when it's needed
        uint64_t start = getmilliseconds();
        resolveMultiStore(state);
        uint64_t end = getmilliseconds();

        getDebugStream(state)
            << "Avoid adding " << hexval(m_KernelFunc->eliminate)
            << " constraints\n";
        getDebugStream(state)
            << "Solving time: " << std::to_string(end - start) << "\n";
    }
}

void KernelInstructionTracer::onExit(S2EExecutionState *state,
                                     PcMonitorState *pcs, uint64_t pc) {
    uint64_t start = getmilliseconds();
    if (m_options->mode == MODE_RESOLVE) {
        // terminate no matter what's the result
        // TODO: make sure we only exit when overflow happens! Add a flag?
        if (!resolveMultiStore(state)) {
            return; // race condition failed, continue to run
        }
    } else {
        killState(state, "Stop tracing at the exit");
        return;
    }
    uint64_t end = getmilliseconds();

    getDebugStream(state) << "Avoid adding " << hexval(m_KernelFunc->eliminate)
                          << " constraints\n";
    getDebugStream(state) << "Stop tracing at the target " << hexval(pc)
                          << "\n";
    getDebugStream(state) << "Solving time: " << std::to_string(end - start)
                          << "\n";
    killState(state, "Stop tracing at the exit");
}

///
/// Hook Functions
///
void KernelInstructionTracer::onModuleLoad(S2EExecutionState *state,
                                           const ModuleDescriptor &module) {
    // Check if it's the process we want to track
    if (!BaseTracer::onModuleLoad(state, module)) {
        return;
    }

    if (m_options->mode == MODE_SOLVE) {
        std::vector<Capability> caps;
        if (m_capfile != "" && fileExists(m_capfile)) {
            Capability cap;
            restoreState(cap, m_capfile);
            caps.push_back(cap);
            getDebugStream() << "Loading cap: " << m_capfile << "\n";
            getDebugStream()
                << "Constraints: " << cap.constraints.size() << "\n";
        } else {
            for (int i = 0;; i++) {
                std::stringstream fileName;
                fileName << "cap_" << i;
                std::string path = fileName.str();
                if (!fileExists(path)) {
                    break;
                }
                getDebugStream() << "Loading cap: " << path << "\n";

                Capability cap;
                restoreState(cap, path);
                caps.push_back(cap);
                getDebugStream()
                    << "Constraints: " << cap.constraints.size() << "\n";
            }
        }
        solveWithCapability(state, caps);
        killState(state, "Finishing...");
        return;
    }

    // annotation points
    registerTracer(state, -1);

    PcMonitor::CallSignalPtr callsignal;
    // target points
    if (m_options->mode == MODE_RESOLVE || m_options->mode == MODE_ANALYSIS) {
        for (auto addr : m_targetAddrs) {
            callsignal = m_PcMonitor->getCallSignal(state, addr,
                                                    -1 /*module.AddressSpace*/);
            callsignal->connect(
                sigc::mem_fun(*this, &KernelInstructionTracer::onTarget),
                ONTARGET_PRIORITY);
        }
    }

    // Enable following plugins
    m_Kasan->registerHandler(m_PcMonitor, state, -1 /*module.AddressSpace*/);
    m_AllocManager->registerHandler(m_PcMonitor, state,
                                    -1 /*module.AddressSpace*/);

    // system call to hook
    // filter syscall invoked by other process
    registerSyscall(state, -1 /*module.AddressSpace*/, *this,
                    &KernelInstructionTracer::onSyscall);

    if (m_options->mode != MODE_RESOLVE) {
        return;
    }

    // Exit points
    ConfigFile::integer_list exitAddrs =
        s2e()->getConfig()->getIntegerList(getConfigKey() + ".exits");
    for (auto addr : exitAddrs) {
        getDebugStream(state) << "onExit: " << hexval(addr) << "\n";
        callsignal =
            m_PcMonitor->getCallSignal(state, addr, module.AddressSpace);
        callsignal->connect(
            sigc::mem_fun(*this, &KernelInstructionTracer::onExit),
            ONEXIT_PRIORITY);
    }

    if (exitAddrs.size() > 0) {
        m_multispots = true;
    }
    registerGuard(m_PcMonitor, state, -1);
    if (m_guardtable.size() > 0) {
        // loop
        m_multispots = true;
    }
}

void KernelInstructionTracer::onHalt(S2EExecutionState *state) {
    static unsigned counter = 0;
    if (counter == 2) {
        killState(state, "Stop tracing after timeout");
    }
    counter++;
}

void KernelInstructionTracer::onSegFault(S2EExecutionState *state, uint64_t pid,
                                         uint64_t pc) {
    std::stringstream ss;
    ss << "crash:" << hexval(pid) << ":" << hexval(pc);
    killState(state, "Stop tracing at Segment fault");
}

void KernelInstructionTracer::onSyscall(S2EExecutionState *state,
                                        PcMonitorState *fns, uint64_t pc) {
    if (m_options->halt && m_options->racecondition) {
        onHalt(state);
    }
    target_ulong rax =
        state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_EAX]));
    std::stringstream ss;
    ss << "[syscall] index: " << rax;
    if (m_options->racecondition) {
        uint64_t tid = m_OSmonitor->getTid(state);
        ss << ", tid: " << std::to_string(tid);
    }
    ss << "\n";
    getDebugStream(state) << ss.str();
    m_AllocManager->newlist(rax);
}

// Utility
void UpdateVector(S2EExecutionState *state, ref<Expr> payload, unsigned offset,
                  std::vector<uint8_t> &data, std::vector<bool> &flags) {
    unsigned bytes = payload->getWidth() / CHAR_BIT;
    for (unsigned i = 0; i < bytes; i++) {
        ref<Expr> charExpr = E_EXTR(payload, i * CHAR_BIT, Expr::Int8);
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(charExpr)) {
            data[offset + i] = CE->getZExtValue();
            flags[offset + i] = false;
        } else {
            data[offset + i] = readExpr<uint64_t>(state, charExpr);
            flags[offset + i] = true;
        }
    }
}

void KernelInstructionTracer::dumpOperations(
    S2EExecutionState *state,
    std::vector<OOB_Operation> &allops,
    uint64_t base, uint64_t left,
    uint64_t size) {

    std::vector<uint8_t> data(size);
    std::vector<bool> flags(size);
    for (unsigned i = 0; i < size; i++) {
        data.push_back(0);
        flags.push_back(false);
    }
    for (auto &op : allops) {
        uint64_t addr = readExpr<uint64_t>(state, op.dst);
        unsigned index = addr - left;

        Spot spot = m_spots[op.pc];
        uint64_t concrete_len = readExpr<uint64_t>(state, op.len);
        if (spot.type == TYPE_STORE) {
            ref<Expr> orig_data;
            switch (m_Disasm->getInsGroup(state, op.pc)) {
            case INS_GROUP_MOV:
                UpdateVector(state, op.payload, index, data, flags);
                break;
            case INS_GROUP_ARITH:
                orig_data = state->mem()->read(addr, concrete_len * Expr::Int8);
                switch (m_Disasm->getInsType(state, op.pc)) {
                case INS_ARITH_XOR:
                    orig_data = XorExpr::create(orig_data, op.payload);
                    break;
                case INS_ARITH_ADD:
                    orig_data = AddExpr::create(orig_data, op.payload);
                    break;
                case INS_ARITH_SUB:
                    orig_data = E_SUB(orig_data, op.payload);
                    break;
                case INS_ARITH_AND:
                    orig_data = E_AND(orig_data, op.payload);
                    break;
                case INS_ARITH_OR:
                    orig_data = E_OR(orig_data, op.payload);
                    break;
                case INS_ARITH_SHL:
                    orig_data = ShlExpr::create(orig_data, op.payload);
                    break;
                case INS_ARITH_INVALID:
                    assert(false && "Invalid arithmentic operation");
                    break;
                default:
                    assert(false && "Unsupported Operation");
                    break;
                }
                UpdateVector(state, orig_data, index, data, flags);
                break;
            default:
                assert(false && "Unknown group type of instruction");
                break;
            }
        } else if (spot.type == TYPE_MEMCPY || spot.type == TYPE_STRCPY) {
            UpdateVector(state, op.payload, index, data, flags);
        } else if (spot.type == TYPE_MEMSET) {
            assert(false && "Unsupported yet");
        }
    }

    unsigned index = 0;
    std::stringstream ss;
    char buf[17] = {0};
    const unsigned length = 16;
    while (index < size) {
        unsigned i;
        ss << hexval(index + left - base, 4, false) << " ";
        for (i = 0; i < length; i++) {
            if (i + index >= size) {
                break;
            }
            ss << hexval(data[index + i], 2, false) << " ";
            buf[i] = (flags[index + i] ? 'S' : 'C');
        }
        for (; i < length; i++) {
            buf[i] = '.';
            ss << "   ";
        }
        ss << std::string(buf) << "\n";
        index += length;
    }
    getDebugStream() << ss.str();
}

} // namespace plugins
} // namespace s2e
