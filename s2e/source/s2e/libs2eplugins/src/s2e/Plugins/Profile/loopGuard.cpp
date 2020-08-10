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

#include "Options.h"
#include "loopGuard.h"
#include "util.h"

namespace s2e {
namespace plugins {

void LoopGuard::initialGuard() { m_disasm = m_s2e->getPlugin<Disassembler>(); }

void LoopGuard::registerGuard(PcMonitor *PcMonitor, S2EExecutionState *state,
                              uint64_t cr3) {
    ConfigFile *cfg = m_s2e->getConfig();
    bool ok;
    // Loop guards
    ConfigFile::string_list conditionAddrs =
        cfg->getListKeys(m_key + ".conditions");
    foreach2(it, conditionAddrs.begin(), conditionAddrs.end()) {
        std::stringstream s;
        s << m_key << ".conditions." << *it << ".";
        uint64_t target = cfg->getInt(s.str() + "target", -1, &ok);
        EXIT_ON_ERROR(ok, "You must specify " + s.str() + "target");
        uint64_t condAddr = cfg->getInt(s.str() + "condition", -1, &ok);
        EXIT_ON_ERROR(ok, "You must specify " + s.str() + "condition");

        // establish mapping relationship
        m_loopguards[target] = condAddr;
        // initialize guard table
        if (m_guardtable.find(condAddr) != m_guardtable.end()) {
            // check if we already register it
            continue;
        }
        Guard *guard = new Guard();
        m_guardtable[condAddr] = guard;

        PcMonitor::CallSignalPtr callsignal =
            PcMonitor->getCallSignal(state, condAddr, cr3);
        callsignal->connect(sigc::mem_fun(*this, &LoopGuard::onCondition),
                            ONGUARD_PRIORITY);
        // record count of access
        callsignal = PcMonitor->getCallSignal(state, target, cr3);
        callsignal->connect(sigc::mem_fun(*this, &LoopGuard::onAccess),
                            ONGUARD_PRIORITY);

        m_s2e->getDebugStream(state) << "onCondition " << hexval(target) << ": "
                                     << hexval(condAddr) << "\n";
    }
}

void LoopGuard::onAccess(S2EExecutionState *state, PcMonitorState *pcs,
                         uint64_t pc) {
    auto it = m_loopguards.find(pc);
    assert(it != m_loopguards.end() && "No target in loop guards!");
    auto itt = m_guardtable.find(it->second);
    assert(itt != m_guardtable.end() && "No exit in guard table!");
    Guard *guard = itt->second;
    assert(guard != NULL && "Null Guard");
    guard->onAccess++;
}

void LoopGuard::onCondition(S2EExecutionState *state, PcMonitorState *pcs,
                            uint64_t pc) {
    Guard *guard = m_guardtable[pc];
    assert(guard != NULL && "Null Guard on Condition");
    guard->onCmp++;
    // FIXME: is it guaranteed that we always have two operands??
    ref<Expr> first = alignExpr(m_disasm->readOperand(state, pc, 0));
    ref<Expr> second = alignExpr(m_disasm->readOperand(state, pc, 1));
    // m_s2e->getDebugStream(state) << E_SUB(first, second) << "\n";
    ref<Expr> subExpr = E_SUB(first, second);

    if (guard->value.isNull()) {
        // first iteration
        guard->value = subExpr;
        guard->concrete = readExpr<uint64_t>(state, guard->value);
    } else {
        // update
        uint64_t new_value = readExpr<uint64_t>(state, subExpr);
        uint64_t diff = new_value - guard->concrete;
        m_s2e->getDebugStream(state) << "Diff: " << hexval(diff) << "\n";
        // assign the diff value at first time and check it for the rest times
        if (guard->diff == 0) {
            guard->diff = diff;
        } else {
            // check if the diff is consistent
            // TODO: what to do here? remove it from the table? It might
            // indicate a
            // new loop
            assert(guard->diff == diff && "Is it really a loop?");
        }
        guard->concrete = new_value;
    }
}

// FIXME: ops
void LoopGuard::resolveLoop() {
    foreach2(it, m_guardtable.begin(), m_guardtable.end()) {
        Guard *guard = it->second;
        Expr::Width width = guard->value->getWidth();
        // EEC = (first - last) / -diff + 1
        assert(guard->onAccess == guard->onCmp ||
               guard->onAccess + 1 == guard->onCmp);
        guard->expcount = SDivExpr::create(
                E_SUB(guard->value, E_CONST(guard->concrete, width)),
                E_CONST(-guard->diff, width));
        if (guard->onAccess == guard->onCmp) {
            guard->expcount = AddExpr::create(E_CONST(1, width), guard->expcount);
        }
    }
}
} // namespace plugins
} // namespace s2e
