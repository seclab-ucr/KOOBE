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

#include "LuaKernel.h"
#include "Tracer.h"
#include "util.h"

namespace s2e {
namespace plugins {

void BaseTracer::initializeTracer() {
    m_PcMonitor = m_s2e->getPlugin<PcMonitor>();
    m_KernelFunc = m_s2e->getPlugin<models::KernelFunctionModels>();
    m_modDetector = m_s2e->getPlugin<ModuleExecutionDetector>();
    m_procDetector = m_s2e->getPlugin<ProcessExecutionDetector>();
    m_OSmonitor = static_cast<OSMonitor *>(m_s2e->getPlugin("OSMonitor"));
    m_ProgMonitor = m_s2e->getPlugin<ProgramMonitor>();
    m_options = m_s2e->getPlugin<OptionsManager>();
    m_Kasan = m_s2e->getPlugin<KernelAddressSanitizer>();
    assert(m_PcMonitor);
    assert(m_KernelFunc);
    assert(m_modDetector);
    assert(m_procDetector);
    assert(m_OSmonitor);
    assert(m_ProgMonitor);
    assert(m_options);
    assert(m_Kasan);

    m_s2e->getCorePlugin()->onStateForkDecide.connect(
        sigc::mem_fun(*this, &BaseTracer::onStateForkDecide));
    m_s2e->getCorePlugin()->onConstraint.connect(
        sigc::mem_fun(*this, &BaseTracer::onConstraint));
    m_ProgMonitor->onMark.connect(sigc::mem_fun(*this, &BaseTracer::onNewIter));

    lua_State *L = m_s2e->getConfig()->getState();
    Lunar<LuaKernel>::Register(L);

    // initialize configuration
    bool ok = false;
    ConfigFile *cfg = m_s2e->getConfig();

    // User annotations
    ConfigFile::string_list annotations =
        cfg->getListKeys(m_key + ".annotations");
    foreach2(it, annotations.begin(), annotations.end()) {
        std::stringstream s;
        s << m_key << ".annotations." << *it << ".";
        uint64_t pc = cfg->getInt(s.str() + "pc", 0, &ok);
        EXIT_ON_ERROR(ok, "You must specify " + s.str() + "pc");
        std::string funcName = cfg->getString(s.str() + "onExecute", "", &ok);
        EXIT_ON_ERROR(ok, "You must specify " + s.str() + "onExecute");
        m_annotations[pc] = funcName;
    }

    m_debugconstraints = cfg->getBool(m_key + ".debug", false, &ok);
}

int BaseTracer::getLuaPlugin(lua_State *L) {
    LuaKernel *kernel = new LuaKernel();
    LuaKernel **c =
        static_cast<LuaKernel **>(lua_newuserdata(L, sizeof(LuaKernel *)));
    *c = kernel;
    luaL_getmetatable(L, "LuaKernel");
    lua_setmetatable(L, -2);
    return 1;
}

void BaseTracer::onAnnotate(S2EExecutionState *state, PcMonitorState *pcs,
                            uint64_t pc) {
    auto it = m_annotations.find(pc);
    if (it == m_annotations.end()) {
        return;
    }

    m_s2e->getDebugStream(state) << "[Annotation]: " << hexval(pc) << "\n";
    std::string funcName = it->second;
    lua_State *L = m_s2e->getConfig()->getState();
    LuaS2EExecutionState luaS2EState(state);
    lua_getglobal(L, funcName.c_str());
    Lunar<LuaS2EExecutionState>::push(L, &luaS2EState);
    lua_pushinteger(L, pc);
    lua_call(L, 2, 0);
}

void BaseTracer::registerTracer(S2EExecutionState *state, uint64_t cr3) {
    // PC addresses to hook
    PcMonitor::CallSignalPtr callsignal; // = m_PcMonitor->getCallSignal(state,
                                       // m_targetAddr, module.AddressSpace);
    // annotation points
    foreach2(it, m_annotations.begin(), m_annotations.end()) {
        callsignal = m_PcMonitor->getCallSignal(state, it->first, cr3);
        callsignal->connect(sigc::mem_fun(*this, &BaseTracer::onAnnotate),
                            ANNOTATION_PRIORITY);
        m_s2e->getDebugStream(state)
            << "Annotate " << hexval(it->first) << "\n";
    }

    m_KernelFunc->registerHandler(m_PcMonitor, state, cr3);
}

void BaseTracer::onStateForkDecide(S2EExecutionState *state,
                                   bool *allowForking) {
    *allowForking = false;
    return;
}

void BaseTracer::onConstraint(S2EExecutionState *state,
                              klee::ref<klee::Expr> condition, bool *allow) {
    uint64_t pc = state->regs()->getPc();

    *allow = true;
    m_KernelFunc->decideAddConstraint(pc, allow);
    m_Kasan->decideAddConstraint(pc, allow);

    if (*allow) {
        // m_forkAddrs.push_back(std::make_pair(pc, state->constraints().size()));
        m_conditions.push_back({pc, condition});
        if (m_options->racecondition) {
            uint64_t tid = m_OSmonitor->getTid(state);
            auto it = thread_counters.find(tid);
            if (it == thread_counters.end()) {
                m_labels.push_back(0);
            } else {
                // Always choose the constraint with the largest label at the
                // same pc.
                // May have equal label (e.g., 0)
                m_labels.push_back(it->second);
            }
        }
    }
}

void BaseTracer::onNewIter(S2EExecutionState *state) {
    uint64_t tid = m_OSmonitor->getTid(state);
    if (thread_counters.find(tid) == thread_counters.end()) {
        thread_counters[tid] =
            1; // start from 1, zero is reserved for other syscalls
    } else {
        thread_counters[tid]++;
    }
}

//
// Return True if we need to register
//
bool BaseTracer::onModuleLoad(S2EExecutionState *state,
                              const ModuleDescriptor &module) {
    m_s2e->getDebugStream() << "onModuleLoad: " << module.Pid << "\n";
    if (!m_procDetector->isTracked(state, module.Pid)) {
        m_s2e->getDebugStream() << "It's not tracked\n";
        return false;
    }
    // Make sure we only register once
    if (m_registered) {
        return false;
    }
    m_registered = true;
    return true;
}

void BaseTracer::killState(S2EExecutionState *state, std::string msg) {
    m_s2e->getDebugStream(state) << msg << "\n";
    m_s2e->getExecutor()->terminateState(*state, "Stop tracing on demand");
}

void BaseTracer::dump(S2EExecutionState *state) {
    // klee::ref<klee::Expr> exp = state->regs()->read(offset, 64);
    // compactPrint(exp, ss);
    // exp.dump();
    // ss << exp << "\n";
    m_s2e->getDebugStream(state)
        << "Constraint size: " << state->constraints().size() << "\n";
    m_s2e->getDebugStream(state)
        << "My Constraint size: " << m_conditions.size() << "\n";
    unsigned index = m_conditions.size() - 1;
    unsigned count = 0;
    for (auto c : state->constraints()) {
        ref<Expr> expr = m_conditions[index].second;
        if (c.compare(expr)) {
            m_s2e->getDebugStream(state) << "index: " << count << "\n";
            m_s2e->getDebugStream(state)
                << "addr: " << hexval(m_conditions[index].first);
            m_s2e->getDebugStream(state) << c << "\n";
            m_s2e->getDebugStream(state) << expr << "\n";
            exit(1);
        }
        index--;
        count++;
    }
    exit(1);
}

void BaseTracer::skipInstruction(S2EExecutionState *state) {
    TranslationBlock *tb = state->getTb();
    uint64_t pc = state->regs()->getPc();
    uint64_t next_pc = pc + tb_get_instruction_size(tb, pc);
    assert(next_pc != pc);

    state->regs()->setPc(next_pc);
    throw CpuExitException();
}
} // namespace plugins
} // namespace s2e
