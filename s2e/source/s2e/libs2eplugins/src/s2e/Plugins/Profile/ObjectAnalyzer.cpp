#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "Evaluation.h"
#include "ObjectAnalyzer.h"
#include "util.h"

using namespace klee;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ObjectAnalyzer, "Analyze one specific structure",
                  "ObjectAnalyzer", "AllocManager", "ModuleExecutionDetector",
                  "ProcessExecutionDetector");

void ObjectAnalyzer::initialize() {
    initializeTracer();
    initialGuard();

    m_allocManager = s2e()->getPlugin<AllocManager>();

    // m_allocManager->onAllocate.connect(sigc::mem_fun(*this,
    // &ObjectAnalyzer::onAllocate));
    m_allocManager->onRelease.connect(
        sigc::mem_fun(*this, &ObjectAnalyzer::onRelease));
    m_modDetector->onModuleLoad.connect(
        sigc::mem_fun(*this, &ObjectAnalyzer::onModuleLoad));

    s2e()->getCorePlugin()->onStateKill.connect(
        sigc::mem_fun(*this, &ObjectAnalyzer::onStateKill));

    initializeConfiguration();
}

void ObjectAnalyzer::initializeConfiguration() {
    bool ok;
    ConfigFile *cfg = s2e()->getConfig();
    m_offset = cfg->getInt(getConfigKey() + ".offset", 0, &ok);
    EXIT_ON_ERROR(ok, "You must specify offset");
    m_size = cfg->getInt(getConfigKey() + ".size", 0, &ok);
    EXIT_ON_ERROR(ok, "You msut specify size");
    m_payload = cfg->getString(getConfigKey() + ".payload", "", &ok);
    EXIT_ON_ERROR(ok, "You must specify payload");
}

void ObjectAnalyzer::onModuleLoad(S2EExecutionState *state,
                                  const ModuleDescriptor &module) {
    // Check if it's the process we want to track
    if (!BaseTracer::onModuleLoad(state, module)) {
        return;
    }

    registerTracer(state, -1);
    registerGuard(m_PcMonitor, state, -1);

    m_allocManager->registerHandler(m_PcMonitor, state, -1);
}

void ObjectAnalyzer::evaluate(S2EExecutionState *state, uint64_t addr,
                              AllocObj &obj) {
    ConstraintManager origin;
    filterconstraint2(state, m_conditions, m_labels, origin);
    combineManager(origin, m_allocManager->AlloConstraint);

    // (lowerBound, elen]
    unsigned elen = m_allocManager->roundSize(m_size);
    unsigned lowerbound = m_allocManager->lowerSize(m_size);
    ConstraintManager manager;
    unsigned len;
    switch (obj.tag) {
    case AllocObj::SYMBOLIC:
        // check size
        manager.addConstraint(E_LE(obj.sym_width, E_CONST(elen, Expr::Int64)));
        manager.addConstraint(
            E_LT(E_CONST(lowerbound, Expr::Int64), obj.sym_width));
        if (!eliminate_contradition(state, manager, origin, true)) {
            getDebugStream(state) << "Invalid constraint set\n";
            return;
        }
        if (!constraint_check(state, manager)) {
            getDebugStream(state)
                << "Failed constraint check! The size doesn't match\n";
            return;
        }

        len = readExpr<unsigned>(state, obj.sym_width);
        getDebugStream(state) << "Concrete length: " << hexval(len) << "\n";
        if (m_offset + m_payload.size() > len) {
            getDebugStream(state)
                << "Please adjust the size of the target object\n";
            return;
        }
        break;
    case AllocObj::CONCRETE:
        getDebugStream(state)
            << "Concrete length: " << hexval(obj.width) << "\n";
        if (lowerbound >= obj.width || obj.width > elen) {
            getDebugStream(state) << "The size doesn't match\n";
            return;
        }
        if (m_offset + m_payload.size() > obj.width) {
            getDebugStream(state) << "Payload + offset > len?? Please fix it\n";
            return;
        }
        break;
    }

    const char *payload = m_payload.c_str();
    for (unsigned i = 0; i < m_payload.size(); i++) {
        ref<Expr> charExpr =
            state->mem()->read(addr + m_offset + i, Expr::Int8);
        if (!addconstraint_check(
                state, manager,
                E_EQ(E_CONST(payload[i], Expr::Int8), charExpr))) {
            getDebugStream(state) << "Invalid constraint on payload\n";
            return;
        }
    }

    // Finally solve those constraint and generate a test case
    std::stringstream output;
    std::vector<std::vector<unsigned char>> values;
    ArrayVec objects;
    output << "{";

    if (!solution(state, manager, objects, values, output)) {
        if (m_debugconstraints) {
            identify_contraditory(state, manager, m_conditions,
                                  manager.head()->expr(), true);
        }
        getDebugStream(state) << "Cannot solve the constraints\n";
        return;
    }
    output << "}";
    getDebugStream(state) << output.str() << "\n";
}

void ObjectAnalyzer::onAllocate(S2EExecutionState *state, AllocCfg *cfg,
                                uint64_t addr) {}

void ObjectAnalyzer::onRelease(S2EExecutionState *state, uint64_t addr) {
    AllocObj obj;
    if (m_allocManager->get(state, addr, obj, true)) {
        evaluate(state, addr, obj);
    }
}

void ObjectAnalyzer::onStateKill(S2EExecutionState *state) {
    // check object status
    foreach2(it, m_allocManager->allocBegin(), m_allocManager->allocEnd()) {
        uint64_t addr = it->first;
        AllocObj obj = it->second;
        evaluate(state, addr, obj);
    }
}
} // namespace plugins
} // namespace s2e
