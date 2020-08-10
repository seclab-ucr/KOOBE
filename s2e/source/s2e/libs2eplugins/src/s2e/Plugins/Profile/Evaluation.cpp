#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <klee/Executor.h>
#include <klee/Expr.h>
#include <klee/SolverManager.h>
#include <klee/util/ExprTemplates.h>

#include <capstone/capstone.h>
#include <queue>

#include "Disassembler.h"
#include "Evaluation.h"
#include "KernelInstructionTracer.h"
#include "util.h"

using namespace klee;

// #define DETECT_CONFLICT 1

namespace s2e {
namespace plugins {

#define ABS_DIFF(a, b) (a > b ? (a - b) : (b - a))
#define OVERFLOW_FAIL "[OVERFLOW FAIL]"

bool solveWithCapability(S2EExecutionState *state,
                         std::vector<Capability> &caps);

void printResult(std::string name, std::vector<unsigned char> &array) {
    std::stringstream ss;
    ss << name << ": ";
    for (auto c : array) {
        ss << hexval(c) << " ";
    }
    g_s2e->getDebugStream() << ss.str() << "\n";
}

bool skip(S2EExecutionState *state, uint64_t pc, csh &handler, cs_insn *insn) {
    cs_detail *detail = insn->detail;
#ifdef TARGET_X86_64
    for (unsigned i = 0; i < detail->x86.op_count; i++) {
        cs_x86_op *op = &(detail->x86.operands[i]);
        if (op->type == X86_OP_MEM) {
            return true;
        }
    }

    // shl/div/adc/cmov/imul
    if (!strncmp("shl", insn->mnemonic, 3)) {
        return true;
    }

#else
    assert(detail && false && "Unsupported target!!");
#endif
    return false;
}

bool isJmp(S2EExecutionState *state, uint64_t pc, csh &handler, cs_insn *insn) {
    if (!strncmp("j", insn->mnemonic, 1)) {
        return true;
    }
    return false;
}

void inline copyConstraint(ConstraintManager &to, ConstraintManager &from) {
    for (auto c : from) {
        to.addConstraint(c);
    }
}

/*
 * S2E add constraints when the memory index is symbolic.
 * However, it also introduces the problem of overconstaint.
 * We simply find out all such constraint and remove them from our final set.
 */
unsigned addToCorpus(std::map<uint64_t, std::vector<ref<Expr>>> &reference,
                     uint64_t pc, ref<Expr> &expr) {
    unsigned duplicate = 0;
    // eliminate redundancy
    if (reference.find(pc) == reference.end()) {
        std::vector<ref<Expr>> list;
        reference[pc] = list;
    }
    bool found = false;
    for (auto each : reference[pc]) {
        const ref<Expr> e = expr;
        if (!each.compare(e)) {
            found = true;
            duplicate++;
            break;
        }
    }
    if (!found) {
        reference[pc].push_back(expr);
    }
    return duplicate;
}

bool filterconstraint(S2EExecutionState *state,
                      std::vector<std::pair<uint64_t, ref<Expr>>> &constraints,
                      std::vector<uint16_t> labels,
                      ConstraintManager &manager) {
    bool shouldskip;
    bool error;
    unsigned counter = 0;
    Disassembler *m_disas = g_s2e->getPlugin<Disassembler>();

    g_s2e->getDebugStream(state) << "Total: " << constraints.size() << "\n";
    std::vector<std::pair<uint64_t, ref<Expr>>> new_conditions;
    if (labels.size() > 0) { // for race condition
        std::map<uint64_t, uint16_t> cond_labels;
        for (unsigned i = 0; i < constraints.size(); i++) {
            uint16_t label = labels[i];
            uint64_t addr = constraints[i].first;
            if (label == 0) {
                continue;
            }
            auto it = cond_labels.find(addr);
            if (it == cond_labels.end()) {
                cond_labels[addr] = label;
            } else if (it->second < label) {
                cond_labels[addr] = label;
            }
        }
        for (unsigned i = 0; i < constraints.size(); i++) {
            uint16_t label = labels[i];
            uint64_t addr = constraints[i].first;
            ref<Expr> c = constraints[i].second;
            if (label == 0) {
                new_conditions.push_back({addr, c});
                continue;
            }
            // FIXME: find(addr) - 1 <= label which allows we keeping the
            // constraints collected from the last two iteration
            if (cond_labels.find(addr)->second == label) {
                new_conditions.push_back({addr, c});
            } else {
                counter++;
            }
        }
    } else {
        // just copy
        new_conditions = constraints;
    }

    g_s2e->getDebugStream() << "Eliminate " << std::to_string(counter)
                            << " constraints for duplicated iteration\n";
    counter = 0;

    std::vector<std::pair<uint64_t, ref<Expr>>> iconditions;
    for (unsigned i = 0; i < new_conditions.size(); i++) {
        shouldskip = false;
        uint64_t addr = new_conditions[i].first;
        ref<Expr> c = new_conditions[i].second;
        if (c->getKind() == Expr::Eq) {
            ref<Expr> expr = c->getKid(0);
            if (isa<ConstantExpr>(expr)) {
                shouldskip = m_disas->getDetail(state, addr, skip, &error);
                if (error) {
                    shouldskip = false;
                }
            }
        }
        if (!shouldskip) {
            iconditions.push_back({addr, c});
        } else {
            counter++;
        }
    }
    g_s2e->getDebugStream() << "Eliminate " << std::to_string(counter)
                            << " constraints for symbolic memory index\n";
    counter = 0;

    // eliminate constraint on for-loop
    // find consecutive constraints for the same pc
    // FIXME: what about nested-loop?
    unsigned duplicate = 0;
    std::map<uint64_t, std::vector<ref<Expr>>> reference;
    std::vector<std::pair<uint64_t, ref<Expr>>> loopConds;
    unsigned i = 0;
    for (; i < iconditions.size(); i++) {
        uint64_t cur_pc = iconditions[i].first;
        bool isloop = m_disas->getDetail(state, cur_pc, isJmp, &error, false);
        if (isloop) {
            loopConds.push_back({cur_pc, iconditions[i].second});
        } else {
            static int left = 5;
            if (left-- > 0) {
                g_s2e->getDebugStream()
                    << "Constraint for non-branch case at " << hexval(cur_pc)
                    << " " << iconditions[i].second << "\n";
            }
            duplicate += addToCorpus(reference, cur_pc, iconditions[i].second);
        }
    }

    g_s2e->getDebugStream() << "start to find loop...\n";
    unsigned total = loopConds.size();
    i = 0;
    while (i < total) {
        uint64_t cur_pc = loopConds[i].first;
        unsigned j = i + 1;
        for (; j < total; j++) {
            if (loopConds[j].first != cur_pc) {
                break;
            }
        }
        if (j - i > 3) { // at least three consecutive constraint on the same pc
            counter += (j - i);
            i = j;
            g_s2e->getDebugStream()
                << "Detect constraints on for-loop: " << hexval(cur_pc) << "\n";
            continue;
        }

        duplicate +=
            addToCorpus(reference, loopConds[i].first, loopConds[i].second);
        ++i;
    };

    unsigned loop = 0;
    foreach2(it, reference.begin(), reference.end()) {
        g_s2e->getDebugStream()
            << hexval(it->first) << ": " << hexval(it->second.size()) << "\n";
        for (auto c : it->second) {
            ref<Expr> newExpr = rebuildExpr(c);
            manager.addConstraint(newExpr);
        }
    }

    g_s2e->getDebugStream() << "Eliminate " << std::to_string(counter + loop)
                            << " constraints for loops\n";
    g_s2e->getDebugStream() << "Eliminate " << std::to_string(duplicate)
                            << " duplicate constraints\n";
    g_s2e->getDebugStream()
        << "Remaining " << std::to_string(manager.size()) << " constraints\n";
    return true;
}

bool real_solve(S2EExecutionState *state, ConstraintManager &manager,
                const ArrayVec &objects,
                std::vector<std::vector<unsigned char>> &values) {

    auto solver = SolverManager::solver(*state);
    double queryCost;
    g_s2e->getDebugStream(state) << "get initial value\n";
    if (!solver->getInitialValues(manager, objects, values, queryCost)) {
        g_s2e->getDebugStream() << "Unable to generate a solution\n";
        return false;
    }
    return true;
}

void tuneSolution(S2EExecutionState *state, ConstraintManager &manager,
                  std::map<std::string, const ArrayPtr> &selected,
                  std::vector<std::vector<unsigned char>> &values,
                  Assignment *assignment) {

    g_s2e->getDebugStream(state) << "tune solution!\n";
    auto solver = getSolver(state);

    ArrayVec objects;
    foreach2(it, selected.begin(), selected.end()) {
        objects.push_back(it->second);
    }

    unsigned i = 0;
    foreach2(it, selected.begin(), selected.end()) {
        const ArrayPtr arr = it->second;
        std::string name = it->first;
        if (name.find("alc_") != std::string::npos || // skip allocation
            name.find("tmp_") != std::string::npos) { // skip temporal variable
            ++i;
            continue;
        }

        unsigned start = 0, left = 0, right = 0;
        unsigned stride = 4;
        // check every 4 bytes at a time, if something goes wrong, fall back to
        // one-byte comparison and then recover 4 byte comparison, and so on so forth
        for (; start < arr->getSize();) {
            uint64_t value = 0, solution_value = 0, bits = 0;
            for (left = right = start;
                 right < left + stride && right < arr->getSize();
                 right++, bits += 8) {
                ref<Expr> e = assignment->evaluate(arr, right);
                if (!isa<ConstantExpr>(e)) {
                    g_s2e->getDebugStream(state)
                        << "Error: Failed to get concrete value\n";
                    exit(1);
                }
                uint8_t val = dyn_cast<ConstantExpr>(e)->getZExtValue();
                g_s2e->getDebugStream(state)
                    << hexval(values[i][right]) << ": " << hexval(val) << "\n";
                value |= ((uint64_t)val << bits);
                solution_value |= ((uint64_t)values[i][right] << bits);
            }

            auto update_list = UpdateList::create(arr, 0);
            ref<Expr> expr =
                readArray(update_list, E_CONST(left, Expr::Int32), stride);
            ref<Expr> condi = E_EQ(expr, E_CONST(value, CHAR_BIT * stride));
            if (value == solution_value) {
                manager.addConstraint(condi);
                g_s2e->getDebugStream(state) << name << " skip " << left
                                             << " to " << (right - 1) << "\n";
                start = right;
            } else {
                bool ok = false;
                solver->mayBeTrue(Query(manager, condi), ok);
                if (ok) {
                    manager.addConstraint(condi);
                    g_s2e->getDebugStream(state)
                        << name << " update " << left << " to " << (right - 1)
                        << "\n";
                    std::vector<std::vector<unsigned char>> new_values;
                    if (real_solve(state, manager, objects, new_values)) {
                        for (unsigned m = 0; m < values.size(); m++) {
                            for (unsigned n = 0; n < values[m].size(); n++) {
                                values[m][n] = new_values[m][n];
                            }
                        }
                    }
                    start = right;
                } else {
                    g_s2e->getDebugStream(state)
                        << name << " cannot update " << left << " to "
                        << (right - 1) << "\n";
                    if (stride == 4) {
                        stride = 1; // try again with one byte a time
                        continue;
                    }
                    start = right;
                }
            }

            if (stride == 1 && start % 4 == 0) {
                stride = 4; // recover stride after we process 4 bytes
            }
        }
        ++i;
    }
}

void generateSolution(Solution &results, std::stringstream &output) {
    g_s2e->getDebugStream() << "\nTrial:\n";

    bool first = true;
    output << "{";
    for (auto each : results) {
        std::string variable = getVariableName(each.first);
        if (variable.size() <= 0) {
            if (each.first.find("tmp_") != std::string::npos) {
                printResult(each.first, each.second);
            }
            continue;
        }
        if (!first) {
            output << ",\n";
        }
        output << "\"" << variable << "\": ";
        output << "[";
        first = true;
        for (auto c : each.second) {
            if (!first) {
                output << ", ";
            }
            first = false;
            output << std::to_string(c);
        }
        output << "]";
    }
    output << "}";
}

bool solution(S2EExecutionState *state, ConstraintManager &manager,
              std::map<std::string, const ArrayPtr> &selected,
              Assignment *assignment, ArrayVec &objects,
              std::vector<std::vector<unsigned char>> &values,
              std::stringstream &output, bool tune) {
    g_s2e->getDebugStream(state) << "Get solution!\n";
    foreach2(it, selected.begin(), selected.end()) {
        objects.push_back(it->second);
    }

    if (!real_solve(state, manager, objects, values)) {
        return false;
    }

    if (tune) {
        tuneSolution(state, manager, selected, values, assignment);
    }

    Solution results;
    unsigned i = 0;
    foreach2(it, selected.begin(), selected.end()) {
        // g_s2e->getDebugStream() << it->first << "\n";
        results.push_back({it->first, values[i]});
        ++i;
    }

    generateSolution(results, output);
    return true;
}

bool solution(S2EExecutionState *state, ConstraintManager &manager,
              ArrayVec &objects,
              std::vector<std::vector<unsigned char>> &values,
              std::stringstream &output, bool tune) {
    // sometimes (e.g., race condition) we have multiple symbols corresponding
    // to the same memory address, we can simply pick the latest one. 
    // Note that one memory address only has one name (specified in poc).
    std::map<std::string, const ArrayPtr> selected;
    selectSymbols(state, selected);
    return solution(state, manager, selected, state->concolics, objects, values,
                    output, tune);
}

uint64_t whereit(std::vector<std::pair<uint64_t, ref<Expr>>> &constraints,
                 ref<Expr> expr) {
    for (unsigned i = 0; i < constraints.size(); i++) {
        ref<Expr> c = constraints[i].second;
        if (!c.compare(expr)) {
            return constraints[i].first;
        }
    }
    return 0;
}

void identify_contraditory(
    S2EExecutionState *state, ConstraintManager &manager,
    std::vector<std::pair<uint64_t, ref<Expr>>> &constraints, ref<Expr> expr,
    bool isCondition) {

    auto solver = getSolver(state);
    ConstraintManager tmp_manager;

    // unsigned counter = 0;
    bool ok;
    g_s2e->getDebugStream(state) << "Expr: " << expr << "\n";
    for (auto c : manager) {
        g_s2e->getDebugStream(state)
            << hexval(whereit(constraints, c)) << ": " << c << "\n";
        tmp_manager.addConstraint(c);
        if (isCondition) {
            if (!solver->mayBeTrue(Query(tmp_manager, expr), ok)) {
                g_s2e->getDebugStream() << "Unable to get a possible value"
                                        << "\n";
                return;
            }
        } else {
            ref<ConstantExpr> ret;
            if (!solver->getValue(Query(tmp_manager, expr), ret)) {
                g_s2e->getDebugStream() << "Unable to get a possible value"
                                        << "\n";
                return;
            }
            g_s2e->getDebugStream(state) << "Possible Value: " << ret << "\n";
        }

        if (!ok) {
            g_s2e->getDebugStream() << "Can not be true"
                                    << "\n";
            exit(1);
        }
    }

    return;
}

bool inline checkConsistency(S2EExecutionState *state,
                             ConstraintManager &manager, ref<Expr> expr) {
    // Check that the added constraint is consistent with
    // the existing path constraints
    bool truth;
    auto solver = getSolver(state);
    if (!solver->mayBeTrue(Query(manager, expr), truth)) {
        g_s2e->getWarningsStream() << "Unable to solve it!\n";
        exit(1);
    }
    return truth;
}

/*
 * Check if it's ok to add the new constraint
 */
bool addconstraint_check(S2EExecutionState *state, ConstraintManager &manager,
                         ref<Expr> expr, bool validate) {
    // do not add false condition
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(expr)) {
        if (!CE->isTrue()) {
            return false;
        }
    }

    if (validate) {
        if (!checkConsistency(state, manager, expr)) {
            return false;
        }
    }

    manager.addConstraint(expr);
    return true;
}

bool KernelInstructionTracer::eliminate_contradition(S2EExecutionState *state,
                                                     ConstraintManager &manager,
                                                     ConstraintManager &origin,
                                                     bool tune) {
#ifdef DETECT_CONFLICT
    auto solver = getSolver(state);
    bool ok;
    unsigned count = 0;
    ConstraintManager filter;

    for (auto c : origin) {
        // skip particular constraints contradictory to our new constraints
        if (!solver->mayBeTrue(Query(manager, c), ok)) {
            g_s2e->getDebugStream() << "Unable to get a possible value"
                                    << "\n";
            exit(1);
        }
        if (ok || !tune) {
            filter.addConstraint(c);
        }
        if (!ok) {
            count++;
            g_s2e->getDebugStream(state)
                << "Found contradictory constraints: " << c << "\n";
            // Do not eliminate the following constraints
            for (auto each : m_AllocManager->AlloConstraint) {
                if (!each.compare(c)) {
                    getDebugStream(state)
                        << "Cannot eliminate constraint on allocation\n";
                    return false;
                }
            }
        }
    }
    g_s2e->getDebugStream(state)
        << "Found " << hexval(count) << " contraditory constraints in total\n";
    if (count > 0) {
        return false;
    }
    // combine filtered constriant
    for (auto c : filter) {
        manager.addConstraint(c);
    }
#else
    for (auto c : origin) {
        manager.addConstraint(c);
    }
#endif
    return true;
}

/*
 * Check if we have a valid constraint set
 */
bool constraint_check(S2EExecutionState *state, ConstraintManager &manager) {
    bool ok;
    auto solver = getSolver(state);
    // Test if we have a valid contraint set before we try to get a possible
    // value (because it would crash)
    if (!solver->mayBeTrue(Query(manager, manager.head()->expr()), ok)) {
        return false;
    }
    if (!ok) {
        return false;
    }
    return true;
}

void analyze_expr(S2EExecutionState *state, ref<Expr> expr, uint64_t minimum) {
    std::set<klee::ReadExpr *> collection;
    std::stringstream ss;
    unsigned count = 0;

    if (isa<ConstantExpr>(expr)) {
        return;
    }

    collectRead(expr, collection);
    std::map<std::string, uint8_t> hashtable;
    ss << "Related variable [";
    foreach2(it, collection.begin(), collection.end()) {
        std::string name = (*it)->getUpdates()->getRoot()->getName();
        std::string sym = getVariableName(name);
        if (sym.size() == 0) {
            continue;
        }
        if (hashtable.find(sym) != hashtable.end()) {
            continue;
        }
        if (count != 0)
            ss << ", ";
        count++;
        ss << sym;
        hashtable[sym] = 0;
    }
    ss << "]\n";

    bool ok;
    auto solver = getSolver(state);
    ConstraintManager manager;
    // TODO: add upper bound for the expr
    ref<Expr> lowerBound = E_LE(E_CONST(minimum, Expr::Int64), expr);
    ref<Expr> upperBound = E_LE(expr, E_CONST(minimum + 64, Expr::Int64));
    bool res = solver->mayBeTrue(Query(manager, lowerBound), ok);
    if (res && ok) {
        manager.addConstraint(lowerBound);
        res = solver->mayBeTrue(Query(manager, upperBound), ok);
        if (res && ok) {
            manager.addConstraint(upperBound);
        }
        ArrayVec objects;
        std::vector<std::vector<unsigned char>> values;
        solution(state, manager, objects, values, ss, false);
    }
    g_s2e->getDebugStream() << ss.str() << "\n";
}

bool KernelInstructionTracer::findbase(S2EExecutionState *state,
                                       ref<Expr> &addr, uint64_t &base_addr) {
    ref<ReadExpr> sym_base;
    std::string prefix = "alc_";
    if (findSymBase(addr, sym_base, prefix)) {
        getDebugStream(state) << "Sym addr: " << sym_base << "\n";
        std::string name = sym_base->getUpdates()->getRoot()->getName();
        base_addr = getValueFromName(name, prefix);
        getDebugStream(state) << "Get Base addr: " << hexval(base_addr) << "\n";
        assert(base_addr && "Failed to get value from symbol name");
    } else {
        ref<ConstantExpr> base;
        ConstraintManager variableConstraints;
        // The offset can not be negative.
        // Heuristics: Assign zero to all symbolic variables
        std::set<ReadExpr *> collection;
        collectRead(addr, collection);
        foreach2(it, collection.begin(), collection.end()) {
            variableConstraints.addConstraint(
                E_EQ(*it, E_CONST(0, Expr::Int8)));
        }

        if (!findMin(state, variableConstraints, addr, base,
                     state->concolics)) {
            getDebugStream(state) << "Failed to get the minimum value of edi\n";
            exit(1);
        }

        getDebugStream(state) << "Min address for dst: " << base << "\n";
        base_addr = m_AllocManager->find(state, base->getZExtValue());
        assert(base_addr && "Failed to get base address from allocManager");
    }
    return true;
}

bool KernelInstructionTracer::exitWithDistribution(S2EExecutionState *state) {
    // show distribution of constraint so that we can fine tune it
    ConstraintManager origin;
    filterconstraint(state, m_conditions, m_labels, origin);

    s2e()->getExecutor()->terminateState(*state,
                                         "Stop tracing at race condition");
    return false;
}

bool KernelInstructionTracer::CheckOverflow(S2EExecutionState *state,
                                            Spot spot) {
    static unsigned counter = 0;

    if (spot.type == TYPE_STRCPY) {
        uint64_t srcAddr, dstAddr = 0;
        ref<Expr> dstExpr;
        m_KernelFunc->readArgument(state, spot.sig.src, srcAddr, false);
        dstExpr = m_KernelFunc->readSymArgument(state, spot.sig.dst, false);
        dstAddr = readExpr<uint64_t>(state, dstExpr);

        // Calculate the string length
        uint64_t len = 0;
        if (!m_KernelFunc->strlenConcrete(state, srcAddr, len)) {
            getDebugStream(state) << "Failed to find NULL char in string "
                                  << hexval(srcAddr) << "\n";
            return false;
        }

        uint64_t base_addr;
        if (!findbase(state, dstExpr, base_addr)) {
            getWarningsStream(state) << "Failed to find the base address\n";
            m_AllocManager->print(this);
            exit(1);
        }

        AllocObj vul_obj;
        if (!m_AllocManager->get(state, base_addr, vul_obj, true)) {
            return false;
        }

        if (dstAddr + (len + 1) > base_addr + vul_obj.width) { // out-of-bound
            return true;
        }
    } else if (spot.type == TYPE_MEMCPY || spot.type == TYPE_MEMSET) {
        uint64_t dstAddr, len, base_addr;
        m_KernelFunc->readArgument(state, spot.sig.len, len, false);
        ref<Expr> dstExpr =
            m_KernelFunc->readSymArgument(state, spot.sig.dst, false);
        dstAddr = readExpr<uint64_t>(state, dstExpr);

        if (!findbase(state, dstExpr, base_addr)) {
            getWarningsStream(state) << "Failed to find the base address\n";
            m_AllocManager->print(this);
            exit(1);
        }

        AllocObj vul_obj;
        if (!m_AllocManager->get(state, base_addr, vul_obj, true)) {
            return false;
        }
        if (dstAddr + len > base_addr + vul_obj.width) { // out-of-bound
            return true;
        }
    } else if (spot.type == TYPE_STORE) {
#ifdef TARGET_X86_64
        uint64_t pc = state->regs()->getPc();
        // DWORD PTR [r14-0x18],0x0
        cs_insn *insn = m_Disasm->getInst(state, pc, true);
        cs_detail *detail = insn->detail;
        cs_x86_op op = detail->x86.operands[0];
        uint64_t len = op.size;
        ref<Expr> dstExpr = m_Disasm->getMemAddr(state, &op);
        cs_free(insn, 1);

        uint64_t base_addr;
        if (!findbase(state, dstExpr, base_addr)) {
            getWarningsStream(state) << "Failed to find the base address\n";
            m_AllocManager->print(this);
            exit(1);
        }

        AllocObj vul_obj;
        if (!m_AllocManager->get(state, base_addr, vul_obj, true)) {
            return false;
        }

        uint64_t dstAddr = readExpr<uint64_t>(state, dstExpr);
        if (dstAddr + len > base_addr + vul_obj.width) {
            return true;
        }
#endif
    } else {
        assert(false || "Unknown type of overflow");
    }

    getDebugStream(state) << "race failed: " << std::to_string(counter) << "\n";
    if (counter == m_options->racelimit) {
        // In race condition situation, we have to check overflow a large amount of times.
        getDebugStream(state) << "Stop tracing after too many failture\n";
        exitWithDistribution(state);
    }
    counter++;
    return false;
}

bool KernelInstructionTracer::validate(S2EExecutionState *state,
                                       ref<Expr> dstExpr, uint64_t srcAddr,
                                       ref<Expr> data, ref<Expr> len) {

    uint64_t elen = readExpr<uint64_t>(state, len);
    std::vector<uint8_t> bytes;
    m_AllocManager->print(this);
    getDebugStream(state) << "Dest: " << dstExpr << "\n";
    if (srcAddr != 0) {
        dumpMemory(state, srcAddr, elen, bytes);
    } else {
        getDebugStream(state) << data << "\n";
    }

    return true;
}

bool KernelInstructionTracer::solve(S2EExecutionState *state, ref<Expr> dstExpr,
                                    uint64_t srcAddr, ref<Expr> data,
                                    ref<Expr> len) {

    if (m_options->validate) {
        validate(state, dstExpr, srcAddr, data, len);
        killState(state, "Stop tracing after validation");
        exit(0);
    }

    getDebugStream(state) << "Start to solve\n";
    // Add constraints
    ConstraintManager origin;
    filterconstraint(
        state, m_conditions, m_labels,
        origin); // filter out constraint introduced by symbolic memory index
    getDebugStream(state) << "Filter constraints\n";
    // Add constraint for symbolic memory address
    // combineManager(origin, m_AllocManager->AlloConstraint);

    uint64_t base_addr;
    if (!findbase(state, dstExpr, base_addr)) {
        getWarningsStream(state) << "Failed to find the base address\n";
        exit(1);
    }

    AllocObj obj;
    if (!m_AllocManager->get(state, base_addr, obj, true)) {
        getWarningsStream(state) << "Failed to get the vuln object\n";
        exit(1);
    }

    uint64_t origin_size = obj.width;
    getDebugStream(state) << "Base addr: " << hexval(base_addr) << "\n";
    getDebugStream(state) << obj << "\n";
    if (srcAddr != 0) {
        std::vector<uint8_t> dump_bytes;
        dumpMemory(state, srcAddr, readExpr<uint64_t>(state, len), dump_bytes);
        getDebugStream(state)
            << "Dump Memory with size of " << hexval(dump_bytes.size()) << "\n";
    }
    printLayout(state, base_addr);
    printSyscalls(state, base_addr);

    std::string tmp_file = m_workdir + "/cap";
    Capability cap;
    std::vector<OOB_Operation> allops;
    OOB_Operation op;
    dstExpr = rebuildExpr(dstExpr);
    op.dst = dstExpr;
    op.payload = data;
    op.len = len;
    saveState(state, cap, origin, allops, m_loopguards, m_guardtable, obj,
              base_addr, m_spots, m_AllocManager->getAllocator(obj), tmp_file, m_workdir);

    // if (!m_options->resolve) {
    //     return true;
    // }

    while (true) {
        uint64_t v_size = m_AllocManager->roundSize(origin_size), t_len;
        int t_offset;
        uint8_t *payload;
        bool success = getCandidate(v_size, obj.tag == AllocObj::SYMBOLIC,
                                    m_AllocManager->getAllocator(obj), t_offset,
                                    &payload, t_len);
        if (!success) {
            getDebugStream(state) << hexval(v_size) << "\n";
            getDebugStream(state) << "End of search\n";
            return false;
        }
        getDebugStream(state)
            << "offset: " << t_offset << ", len: " << t_len
            << ", size: " << v_size << ", payload: " << hexval(payload)
            << ", alloc: " << m_AllocManager->getAllocator(obj) << "\n";
        getDebugStream(state) << "payload: " << hexval(payload[0]) << " \n";

        // Add constraints regarding the target object
        std::string target;
        if (!getCurCandidate(target)) {
            getDebugStream(state) << "Cannot get Target object: \n";
            continue;
        }
        getDebugStream(state) << "Target: " << target << "\n";
        ConfigFile *cfg = s2e()->getConfig();
        std::stringstream key;
        bool ok = true;
        key << "TargetObjects." << target << ".";
        int type = cfg->getInt(key.str() + "type", TYPE_CUSTOM, &ok);
        EXIT_ON_ERROR(ok, "You must specify type!");

        uint64_t start_time = getmilliseconds();
        int err = NO_ERROR_FAIL;
        uint8_t kernel_address[8] = {0x40, 0x10, 0x80, 0x76,
                                     0,    0x80, 0xff, 0xff};
        uint8_t user_address[8] = {0, 0, 0, 0, 0, 0x80, 0, 0};
        if (type == TYPE_REFCNT) {
            err = Evaluate_Once(state, origin, target, base_addr, obj, v_size,
                                t_offset, 4, dstExpr, srcAddr, data, len,
                                payload, OVERWRITE_REFCNT);
        } else if (type == TYPE_DATA_POINTER) {
            // mmap range: 0x10000 - 0x800000000000
            // first two byte can be any value
            // user space address
            if (!m_options->enable_smap) {
                err = Evaluate_Once(state, origin, target, base_addr, obj,
                                    v_size, t_offset, 8, dstExpr, srcAddr, data,
                                    len, &user_address[0],
                                    OVERWRITE_DATA_POINTER_USER);
            }
            // kernel space address
            if (err == NO_ERROR_FAIL) {
                err = Evaluate_Once(state, origin, target, base_addr, obj,
                                    v_size, t_offset, 8, dstExpr, srcAddr, data,
                                    len, &kernel_address[0],
                                    OVERWRITE_DATA_POINTER_KERNEL);
            }
        } else if (type == TYPE_CUSTOM || type == TYPE_FUNC_POINTER) {
            ConstraintManager manager;
            err = Evaluate_Once(state, origin, target, base_addr, obj, v_size,
                                t_offset, t_len, dstExpr, srcAddr, data, len,
                                payload, OVERWRITE_FUNC_POINTER);
        }
        start_time = getmilliseconds() - start_time;
        getDebugStream() << "S2E: {\"time\": " << std::to_string(start_time)
                         << "}"
                         << "\n";
    }
}

int KernelInstructionTracer::Evaluate_Once_Solution(
    S2EExecutionState *state, ConstraintManager &manager, ref<Expr> lenExpr,
    unsigned vul_size, int len, uint8_t *payload, std::string &target,
    UpdateListPtr &data_ul, ArrayPtr &array,
    std::vector<unsigned char> &concrete_raw_data, int type,
    uint64_t index /* index = dstloc - base_addr - model_diff; */,
    bool solve = true) {
    // instead of adding new constraint on the payload, we convert them into an
    // objective function and search for
    // the minimum without any breakage of the underlying constraint solver.
    ref<Expr> lossExpr;
    ref<Expr> payloadExpr;
    if (type & OVERWRITE_DATA_POINTER_USER) {
        payloadExpr = readArray(data_ul, E_CONST(index, Expr::Int32),
                                sizeof(target_ulong));
        // 0x10000 <= X < 0x80000000000
        ref<ConstantExpr> min_user = E_CONST(0x10000, Expr::Int64);
        ref<ConstantExpr> max_user = E_CONST(0x80000000000, Expr::Int64);
        ref<ConstantExpr> zeroExpr = E_CONST(0, Expr::Int64);
        ref<ConstantExpr> oneExpr = E_CONST(1, Expr::Int64);
        lossExpr = E_ITE(E_LE(min_user, payloadExpr), zeroExpr,
                         AddExpr::create(E_SUB(min_user, payloadExpr),
                                         E_CONST(1, Expr::Int64)));
        lossExpr = AddExpr::create(
            lossExpr,
            E_ITE(E_LT(payloadExpr, max_user), zeroExpr,
                  AddExpr::create(E_SUB(payloadExpr, max_user), oneExpr)));
    } else if (type & OVERWRITE_REFCNT) {
        payloadExpr = readArray(data_ul, E_CONST(index, Expr::Int32), 4);
        lossExpr = alignExpr(payloadExpr, Expr::Int64);
    } else {
        payloadExpr = readArray(data_ul, E_CONST(index, Expr::Int32), len);
        lossExpr = E_CONST(0, Expr::Int64);
        for (unsigned i = 0; i < len; i++) {
            ref<Expr> charExpr =
                ReadExpr::create(data_ul, E_CONST(index + i, Expr::Int32));
            ref<Expr> payloadChar = E_CONST(payload[i], Expr::Int8);
            ref<Expr> onechange =
                E_ITE(E_LT(charExpr, payloadChar), E_SUB(payloadChar, charExpr),
                      E_SUB(charExpr, payloadChar));
            lossExpr = AddExpr::create(lossExpr, E_ZE(onechange, Expr::Int64));
        }
    }

    // identify_contraditory(state, manager, m_conditions, E_EQ(lossExpr, E_CONST(0, Expr::Int64)), true);

    ref<ConstantExpr> min_loss;
    getDebugStream(state) << "Test:" << target << "\n";
    if (!findMin(state, manager, lossExpr, min_loss, NULL)) {
        getDebugStream(state)
            << "Failed to get the minimum value of changeExpr\n";
        return NO_ERROR_FAIL;
    }

    getDebugStream(state) << "Minimum changeExpr: " << min_loss << "\n";
    if (min_loss->getZExtValue() != 0) {
        return NO_ERROR_FAIL;
    }

    if (solve) {
        manager.addConstraint(E_EQ(lossExpr, min_loss));

        // Find minimum for length
        ref<ConstantExpr> min_len;
        if (!findMin(state, manager, lenExpr, min_len, NULL)) {
            getDebugStream(state)
                << "Failed to get the minimum value for margin"
                << "\n";
            return NO_ERROR_FAIL;
        }
        getDebugStream(state) << min_len << "\n";
        manager.addConstraint(E_EQ(lenExpr, min_len));
        getDebugStream(state) << "Add constraints for length\n";

        // solve the constraints
        std::stringstream output;
        std::vector<std::vector<unsigned char>> values;
        ArrayVec objects;
        output << "{\"solution\": ";
        if (!solution(state, manager, objects, values, output)) {
            getDebugStream(state) << "Cannot solve the constraints\n";
            return NO_ERROR_FAIL;
        }
        output << ",\n\"target\": \"" << target << "\"";
        output << ", \"size\": " << std::to_string(vul_size);

        Assignment assignment = Assignment(objects, values);
        assignment.add(array, concrete_raw_data);

        getDebugStream(state)
            << "Change: " << assignment.evaluate(lossExpr) << "\n";
        getDebugStream(state)
            << "Length: " << assignment.evaluate(lenExpr) << "\n";

        getDebugStream(state) << "Found a solution\n";
        if (type & OVERWRITE_POINTER) {
            std::stringstream pointer;
            pointer << "0x";
            for (int i = 7; i >= 0; i--) {
                int _index = index + i;
                ref<Expr> charExpr =
                    ReadExpr::create(data_ul, E_CONST(_index, Expr::Int32));
                ref<ConstantExpr> res =
                    dyn_cast<ConstantExpr>(assignment.evaluate(charExpr));
                pointer << hexval(res->getZExtValue(), 2, false);
            }
            output << ",\n\"pointer\": \"" << pointer.str() << "\"";
        }

        output << "}";
        getDebugStream(state) << output.str() << "\n";

    }
    return NO_ERROR_SUCCEED;
}

int KernelInstructionTracer::Evaluate_Once(
    S2EExecutionState *state, ConstraintManager &origin, std::string &target,
    uint64_t base_addr, AllocObj &vul_obj, unsigned vul_size, int offset,
    int len, ref<Expr> &dstExpr, uint64_t srcAddr, ref<Expr> &dataExpr,
    ref<Expr> &lenExpr, uint8_t *payload, int type) {
    ConstraintManager manager;
    if (vul_obj.tag == AllocObj::SYMBOLIC) {
        getDebugStream(state) << "Vulnerable object has variable length"
                              << vul_obj.sym_width << "\n";
        getDebugStream(state)
            << state->concolics->evaluate(vul_obj.sym_width) << "\n";
        // Deal with unaligned size
        uint64_t lowerbound = m_AllocManager->lowerSize(vul_size);
        manager.addConstraint(
            E_LE(vul_obj.sym_width, E_CONST(vul_size, Expr::Int64)));
        manager.addConstraint(
            E_LT(E_CONST(lowerbound, Expr::Int64), vul_obj.sym_width));
        getDebugStream(state) << "Length shoud be in the range " << lowerbound
                              << "-" << vul_size << "\n";
    } else {
        if (m_AllocManager->roundSize(vul_obj.width) != vul_size) {
            getDebugStream(state) << "Mismatched size\n";
            return ERROR_MISMATCH_SIZE;
        }
    }
    getDebugStream(state) << "Add constraints for vulnerable object\n";
    // Add constraint for the destination address
    // Depending on the type of fengshui, we might need to know other objects
    // adjacent to the vulnerable obj.
    // obj = m_AllocManager->getWidelength(state, base_addr);
    uint64_t elen = vul_size;
    if (m_options->fengshui == FENGSHUI_TYPE_NORMAL) {
        AllocObj obj = m_AllocManager->getAggregate(state, base_addr,
                                                    vul_size); // new_size
        elen = obj.width;
    }
    getDebugStream(state) << "elen: " << hexval(elen) << "\n";

    // If the offset is negative, it means that we want to overwrite something
    // within the vulnerable object.
    // Thus, we don't need to care about other objects between the vulnerable
    // and target objects.
    // manager.addConstraint(E_EQ(dstExpr, E_SUB(E_CONST(base_addr + elen +
    // t_offset, Expr::Int64), padding)));
    uint64_t dstloc = base_addr + offset + (offset >= 0 ? elen : vul_size);
    uint64_t dstAddr = readExpr<uint64_t>(state, dstExpr);
    uint64_t minimum_len = dstloc + len - dstAddr;
    getDebugStream(state)
        << "The distance between dst addr and target addr is: "
        << hexval(minimum_len) << "\n";

    // only eliminate those contraints contradictory to our new ones related to length,
    // because usually we have the issue of over-constraint due to optimization
    // in string related function (e.g. strcpy, memcpy, copy_from_user)
    if (!eliminate_contradition(state, manager, origin, m_refineconstraint)) {
        getDebugStream(state) << "Invalid constraint set\n";
        return NO_ERROR_FAIL;
    }
    getDebugStream(state) << "Combine constraints\n";

    if (!constraint_check(state, manager)) {
        getDebugStream(state) << "Failed constraint check\n";
        getDebugStream(state) << "DstAddr can not reach the target object!\n";
        return NO_ERROR_FAIL;
    }
    getDebugStream(state) << "Pass constraint check so far!\n";

    // Opt: check if the size is possible

    std::vector<ref<ConstantExpr>> raw_data;
    uint64_t model_len =
        (offset >= 0
             ? elen + m_options->max_length
             : vul_size); // combination of the vulnerable and target objects
    uint64_t model_diff = 0;
    if (model_len > 2 * m_options->max_length) { // the size of the vulnerable
                                                 // object is too large
        model_diff = model_len - 2 * m_options->max_length;
        model_len = 2 * m_options->max_length;
    }
    model_len += 8; // plus 8 dummy bytes

    std::vector<unsigned char> concrete_raw_data;
    getDebugStream(state) << "real length: " << hexval(model_len) << "\n";
    for (unsigned i = 0; i < model_len; i++) {
        raw_data.push_back(E_CONST(0, Expr::Int8));
        concrete_raw_data.push_back(0);
    }

    // initialize target object
    uint8_t *tgt_values;
    uint64_t tgt_len;
    if (!getValues(&tgt_values, tgt_len)) {
        getDebugStream() << "You must specify values\n";
        exit(1);
    }
    for (int i = 0; i < tgt_len; i++) {
        concrete_raw_data[dstloc - base_addr + i - model_diff] = tgt_values[i];
        raw_data[dstloc - base_addr + i - model_diff] =
            E_CONST(tgt_values[i], Expr::Int8);
    }

    unsigned realen = readExpr<uint64_t>(state, lenExpr);
    ref<Expr> index =
        SubExpr::create(dstExpr, E_CONST(base_addr + model_diff, Expr::Int64));
    if (!addconstraint_check(
            state, manager,
            E_GE(dstExpr, E_CONST(base_addr + model_diff, Expr::Int64)),
            true)) {
        getDebugStream(state) << "Dst < base_addr + model_diff\n";
        analyze_expr(state, dstExpr, dstloc);
        return NO_ERROR_FAIL;
    }

    auto array = Array::create("tmp_payload", raw_data.size(), &raw_data[0],
                               &raw_data[raw_data.size()], "tmp_payload");
    if (realen < m_options->max_length / 4) {
        // general solution
        // initialization
        auto data_ul = UpdateList::create(array, 0);
        for (int i = 0; i < realen; i++) {
            ref<Expr> charExpr;
            if (srcAddr == 0) {
                charExpr = E_EXTR(dataExpr, i * CHAR_BIT, Expr::Int8);
            } else {
                charExpr = state->mem()->read(srcAddr + i, Expr::Int8);
            }
            if (charExpr.isNull()) {
                return ERROR_REACH_TARGET;
            }
            ref<Expr> _index =
                E_ITE(E_GT(lenExpr, E_CONST(i, lenExpr->getWidth())),
                      AddExpr::create(index, E_CONST(i, Expr::Int64)),
                      // E_SUB(op.dst, E_CONST(base_addr + model_diff - i,
                      // Expr::Int64)),
                      E_CONST(model_len - 8, Expr::Int64));
            updateArray(data_ul, _index, charExpr);
        }
        return Evaluate_Once_Solution(state, manager, lenExpr, vul_size, len,
                                      payload, target, data_ul, array,
                                      concrete_raw_data, type,
                                      dstloc - base_addr - model_diff, true);
    } else {
        // Binary search
        unsigned left = 0, right = realen;
        unsigned mid;
        int err;
        bool found_solution = false;
        while (left < right) {
            mid = (left + right) / 2;
            auto data_ul = UpdateList::create(array, 0);
            for (int i = 0; i < mid; i++) {
                ref<Expr> charExpr;
                if (srcAddr == 0) {
                    charExpr = E_EXTR(dataExpr, i * CHAR_BIT, Expr::Int8);
                } else {
                    charExpr = state->mem()->read(srcAddr + i, Expr::Int8);
                }
                if (charExpr.isNull()) {
                    return ERROR_REACH_TARGET;
                }
                updateArray(data_ul, E_CONST(i, Expr::Int64), charExpr);
            }
            ConstraintManager tmp_manager(manager);
            ref<Expr> midExpr = E_CONST(mid, Expr::Int64);
            tmp_manager.addConstraint(E_LE(lenExpr, midExpr));
            tmp_manager.addConstraint(
                E_GE(lenExpr, E_CONST(left, Expr::Int64)));
            err = Evaluate_Once_Solution(
                state, tmp_manager, midExpr, vul_size, len, payload, target,
                data_ul, array, concrete_raw_data, type,
                dstloc - base_addr - model_diff, false);
            if (err == NO_ERROR_SUCCEED) {
                right = mid;
                found_solution = true;
            } else {
                left = mid + 1;
            }
            getDebugStream()
                << "left: " << left << ", right: " << right << "\n";
        }
        if (!found_solution) {
            return NO_ERROR_FAIL;
        } else {
            auto data_ul = UpdateList::create(array, 0);
            for (int i = 0; i < right; i++) {
                ref<Expr> charExpr;
                if (srcAddr == 0) {
                    charExpr = E_EXTR(dataExpr, i * CHAR_BIT, Expr::Int8);
                } else {
                    charExpr = state->mem()->read(srcAddr + i, Expr::Int8);
                }
                if (charExpr.isNull()) {
                    return ERROR_REACH_TARGET;
                }
                updateArray(data_ul, E_CONST(i, Expr::Int64), charExpr);
            }
            manager.addConstraint(E_EQ(lenExpr, E_CONST(right, Expr::Int64)));
            return Evaluate_Once_Solution(
                state, manager, E_CONST(right, Expr::Int64), vul_size, len,
                payload, target, data_ul, array, concrete_raw_data, type,
                dstloc - base_addr - model_diff, true);
        }
    }
}

bool KernelInstructionTracer::resolveMemcpy(S2EExecutionState *state,
                                            Spot spot) {
    if (!m_multispots) {
        // check overflow at the end for multispot
        if (!CheckOverflow(state, spot)) {
            getDebugStream(state) << "overflow failed\n";
            return false;
        }
    }

    std::stringstream ss;
    ref<Expr> dstExpr =
        m_KernelFunc->readSymArgument(state, spot.sig.dst, false);
    ss << "dstExpr: " << dstExpr << "\n";
    uint64_t srcAddr = 0;
    m_KernelFunc->readArgument(state, spot.sig.src, srcAddr, false);
    ss << "src: " << hexval(srcAddr) << "\n";
    ref<Expr> lenExpr =
        m_KernelFunc->readSymArgument(state, spot.sig.len, false);
    ss << "lenExpr: " << lenExpr << "\n";
    getDebugStream(state) << ss.str() << "\n";

    if (!m_multispots) {
        if (!solve(state, dstExpr, srcAddr, ref<Expr>(), lenExpr)) {
            getDebugStream(state) << "Cannot find a solution!\n";
            return true;
        }
    } else {
        uint64_t pc = state->regs()->getPc();
        unsigned size = readExpr<uint64_t>(state, lenExpr);
        if (size == 0) {
            return true;
        }
        if (size > m_options->max_length * 2) {
            size = m_options->max_length * 2;
        }
        OOB_Operation operation;
        operation.dst = dstExpr;
        operation.payload = state->mem()->read(srcAddr, size * Expr::Int8);
        operation.len = lenExpr;
        operation.order = m_order++;
        operation.pc = pc;
        if (m_overflows.find(pc) == m_overflows.end()) {
            std::vector<OOB_Operation> list;
            list.push_back(operation);
            m_overflows.insert({pc, list});
        } else {
            m_overflows[pc].push_back(operation);
        }
    }

    return true;
}

bool KernelInstructionTracer::resolveStrcpy(S2EExecutionState *state,
                                            Spot spot) {
    if (!m_multispots) {
        // check overflow at the end for multispot
        if (!CheckOverflow(state, spot)) {
            getDebugStream(state) << "overflow failed\n";
            return false;
        }
    }

    std::stringstream ss;
    ref<Expr> dstExpr =
        m_KernelFunc->readSymArgument(state, spot.sig.dst, false);
    ss << "dstExpr: " << dstExpr << "\n";
    uint64_t srcAddr = 0;
    m_KernelFunc->readArgument(state, spot.sig.src, srcAddr, false);
    ss << "srcAddr" << hexval(srcAddr) << "\n";

    // Calculate the string length
    ref<Expr> src_len = E_CONST(0, 64);
    if (!m_KernelFunc->strlenSymbolic(state, srcAddr, src_len)) {
        getDebugStream(state)
            << "Failed to get length of string " << hexval(srcAddr) << "\n";
        exit(1);
    }
    ss << "len:\n" << src_len << "\n";
    getDebugStream(state) << ss.str() << "\n";

    if (!m_multispots) {
        if (!solve(state, dstExpr, srcAddr, ref<Expr>(), src_len)) {
            getDebugStream(state) << "Cannot find a solution!\n";
            return true;
        }
    } else {
        uint64_t pc = state->regs()->getPc();
        uint64_t size = readExpr<uint64_t>(state, src_len);
        if (size > m_options->max_length * 2) {
            size = m_options->max_length * 2;
        }
        OOB_Operation operation;
        operation.dst = dstExpr;
        operation.payload = state->mem()->read(srcAddr, size * Expr::Int8);
        operation.len = src_len;
        operation.order = m_order++;
        operation.pc = pc;
        if (m_overflows.find(pc) == m_overflows.end()) {
            std::vector<OOB_Operation> list;
            list.push_back(operation);
            m_overflows.insert({pc, list});
        } else {
            m_overflows[pc].push_back(operation);
        }
    }

    return true;
}

bool KernelInstructionTracer::resolveStore(S2EExecutionState *state,
                                           Spot spot) {
    if (!m_multispots) {
        // check overflow at the end for multispot
        if (!CheckOverflow(state, spot)) {
            getDebugStream(state) << "overflow failed\n";
            return false;
        }
    }

    uint64_t pc = state->regs()->getPc();
    cs_insn *insn = m_Disasm->getInst(state, pc, true);
    cs_detail *detail = insn->detail;
    if (detail) {
#ifdef TARGET_X86_64
        // operand one should be memory address
        if (detail->x86.op_count != 2) {
            getWarningsStream(state)
                << "Target instuction doesnt have two operands\n";
            exit(1);
        }
        cs_x86_op dst = detail->x86.operands[0];
        if (dst.type != X86_OP_MEM) {
            getWarningsStream(state)
                << "Destination address is not a memory address\n";
            exit(1);
        }
        ref<Expr> dstExpr = m_Disasm->getMemAddr(state, &dst);
        // getDebugStream(state) << hexval(pc) << ": " << dstExpr << "\n";

        uint8_t len = dst.size;
        // getDebugStream(state) << "Size: " << std::to_string(len) << "\n";

        ref<Expr> payload = m_Disasm->readOperand(state, pc, 1);
        if (!m_multispots) {
            if (!solve(state, dstExpr, 0, payload, E_CONST(len, 64))) {
                getDebugStream(state) << "Cannot find a solution!\n";
                return true;
            }
        } else {
            // collect payload
            OOB_Operation operation;
            operation.dst = dstExpr;
            operation.payload = payload;
            operation.len = E_CONST(len, Expr::Int64);
            operation.order = m_order++;
            operation.pc = pc;
            if (m_overflows.find(pc) == m_overflows.end()) {
                // first
                std::vector<OOB_Operation> list;
                list.push_back(operation);
                m_overflows.insert({pc, list});
            } else {
                m_overflows[pc].push_back(operation);
            }
        }
#else
        assert(false && "Unsupported target!!");
#endif
    }
    cs_free(insn, 1);
    return true;
}

bool KernelInstructionTracer::applyOperations(S2EExecutionState *state,
                                              uint64_t model_len,
                                              uint64_t model_diff,
                                              UpdateListPtr &data_ul,
                                              Capability &cap) {

    std::map<uint64_t, unsigned> indices;
    uint64_t base_addr = cap.vuln.vul_base;
    for (auto &op : cap.ops) {
        ref<Expr> index;
        if (cap.loopguards.find(op.pc) != cap.loopguards.end()) {
            ref<Expr> EEC = cap.guardtable[cap.loopguards[op.pc]]->expcount;
            if (indices.find(op.pc) == indices.end()) {
                indices[op.pc] = 0;
            } else {
                indices[op.pc]++;
            }

            index = E_ITE(
                E_GT(EEC, E_CONST(indices[op.pc], EEC->getWidth())),
                E_SUB(op.dst, E_CONST(base_addr + model_diff, Expr::Int64)),
                E_CONST(model_len - 8, Expr::Int64));
        } else {
            index = E_SUB(op.dst, E_CONST(base_addr + model_diff, Expr::Int64));
        }
        // index = rebuildExpr(index);

        Spot spot = cap.spots[op.pc];
        int concrete_len = readExpr<uint64_t>(cap.assignment, op.len);
        if (concrete_len > 2 * m_options->max_length) {
            concrete_len = 2 * m_options->max_length;
        }

        if (spot.type == TYPE_STORE) {
            ref<Expr> orig_data;
            switch (m_Disasm->getInsGroup(state, op.pc)) {
            case INS_GROUP_MOV:
                // comment this just for testing
                updateArray(data_ul, index, op.payload);
                break;
            case INS_GROUP_ARITH:
                orig_data = readArray(data_ul, index, concrete_len);
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
                updateArray(data_ul, index, orig_data);
                break;
            default:
                assert(false && "Unknown group type of instruction");
                break;
            }
        } else if (spot.type == TYPE_MEMCPY || spot.type == TYPE_STRCPY) {
            if (isa<ConstantExpr>(op.len)) {
                updateArray(data_ul, index, op.payload);
            } else {
                for (int i = 0; i < concrete_len; i++) {
                    index = E_ITE(E_GT(op.len, E_CONST(i, op.len->getWidth())),
                                  E_SUB(op.dst, E_CONST(cap.vuln.vul_base +
                                                            model_diff - i,
                                                        Expr::Int64)),
                                  E_CONST(model_len - 8, Expr::Int64));
                    ref<Expr> charExpr =
                        E_EXTR(op.payload, i * CHAR_BIT, Expr::Int8);
                    updateArray(data_ul, index, charExpr);
                }
            }
        } else if (spot.type == TYPE_MEMSET) {
            assert(false && "Unsupported yet");
            exit(1);
        }
    }
    return true;
}

bool KernelInstructionTracer::resolveMultiStore(S2EExecutionState *state) {
    static unsigned counter = 0;
    getDebugStream(state) << "Resolve Multistore\n";
    // Step 1: resolve all loop counters
    resolveLoop();

    // check if overflow happen and retrieve the base address
    bool race_succeed = false;
    uint64_t base_addr;
    foreach2(it, m_overflows.begin(), m_overflows.end()) {
        for (auto &each : it->second) {
            uint64_t dstAddr = readExpr<uint64_t>(state, each.dst);
            if (!findbase(state, each.dst, base_addr)) {
                continue;
            }
            AllocObj vul_obj;
            if (!m_AllocManager->get(state, base_addr, vul_obj, true)) {
                continue;
            }

            uint64_t concrete_len = readExpr<uint64_t>(state, each.len);
            if (dstAddr + concrete_len > base_addr + vul_obj.width) {
                race_succeed = true;
                break;
            }
        }
        if (race_succeed) {
            break;
        }
    }

    // clean up
    if (!race_succeed) {
        counter++;
        getDebugStream(state)
            << OVERFLOW_FAIL << std::to_string(counter) << "\n";
        if (m_options->racecondition && counter == m_options->racelimit) {
            getDebugStream(state) << "Stop tracing after too many failture\n";
            exitWithDistribution(state);
            return false;
        }
        foreach2(it, m_guardtable.begin(), m_guardtable.end()) {
            it->second->reset();
        }
        foreach2(it, m_overflows.begin(), m_overflows.end()) {
            it->second.clear();
        }
        return false;
    }

    // eliminate irrelevant writes
    Overflows new_overflows;
    AllocObj vul_obj;
    if (!m_AllocManager->get(state, base_addr, vul_obj, true)) {
        return false;
    }

    foreach2(it, m_overflows.begin(), m_overflows.end()) {
        std::vector<OOB_Operation> list;
        for (auto &each : it->second) {
            uint64_t base;
            if (!findbase(state, each.dst, base)) {
                continue;
            }
            if (base != base_addr) {
                continue;
            }
            if (m_loopguards.find(it->first) == m_loopguards.end()) {
                // remove ones that didn't overflow
                // TODO: consider symbolic length
                // if (ConstantExpr *CE = dyn_cast<ConstantExpr>(each.dst)) {
                //     if (CE->getZExtValue() + each.len <= base_addr +
                //     vul_obj.width) {
                //         continue;
                //     }
                // }
            }
            list.push_back(each);
        }
        new_overflows.insert({it->first, list});
    }

    // Get boundary of all writes
    uint64_t left = (uint64_t)-1, right = 0; // boundary for our UpdateList
    std::vector<OOB_Operation> allops;
    ref<Expr> dstExpr = ref<Expr>(0); // left boundary
    foreach2(it, new_overflows.begin(), new_overflows.end()) {
        for (auto &op : it->second) {
            allops.push_back(op);
            uint64_t dst = readExpr<uint64_t>(state, op.dst);
            uint64_t concrete_len = readExpr<uint64_t>(state, op.len);
            getDebugStream(state)
                << "PC: " << hexval(it->first) << " Dst: " << hexval(dst)
                << " size: " << op.len << "\n";
            if (left > dst) {
                left = dst;
                dstExpr = op.dst; // choose the symbolic value with the smallest address
                getDebugStream(state) << "Left: " << hexval(left) << "\n";
            }
            if (right < dst + concrete_len) {
                right = dst + concrete_len;
                getDebugStream(state) << "Right: " << hexval(right) << "\n";
            }
        }
    }
    // sort operations in order
    sort(allops.begin(), allops.end(), OOB_Operation::ascendInorder);
    getDebugStream(state) << "Calculate left side boundary\n";

    uint64_t size = right - left;
    getDebugStream(state) << "Size: " << hexval(size) << "\n";
    getDebugStream(state) << "Dst: " << dstExpr << "\n";

    if (!findbase(state, dstExpr, base_addr)) {
        getWarningsStream(state) << "Failed to find the base address\n";
        exit(1);
    }

    dumpOperations(state, allops, base_addr, left, size);

    if (!iterativeSolve(state, base_addr, allops)) {
        return true;
    }
    return true;
}

bool KernelInstructionTracer::iterativeSolve(
    S2EExecutionState *state, uint64_t base_addr,
    std::vector<OOB_Operation> &allops) {
    getDebugStream(state) << "Start iterative solving...\n";

    ConstraintManager origin;
    filterconstraint(state, m_conditions, m_labels, origin);
    getDebugStream(state) << "Filter constraints\n";
    // Add constraint for symbolic memory address
    // combineManager(origin, m_AllocManager->AlloConstraint);

    AllocObj obj;
    if (!m_AllocManager->get(state, base_addr, obj, true)) {
        return false;
    }

    getDebugStream(state) << "Base addr: " << hexval(base_addr) << "\n";
    getDebugStream(state) << obj << "\n";
    printLayout(state, base_addr);
    printSyscalls(state, base_addr);

    // save state
    std::string tmp_file = m_workdir + "/cap";
    Capability cap;
    saveState(state, cap, origin, allops, m_loopguards, m_guardtable, obj,
              base_addr, m_spots, m_AllocManager->getAllocator(obj), tmp_file, m_workdir);

    // if (!m_options->resolve) {
    //     return true;
    // }

    std::vector<Capability> caps;
    caps.push_back(cap);
    return solveWithCapability(state, caps);
}

void getLossExpr(UpdateListPtr &data_ul, std::vector<unsigned char> &raw_data,
                 uint8_t *payload, int len, uint64_t base_index, int type,
                 ref<Expr> &lossExpr) {

    ref<Expr> payloadExpr;
    if (type & OVERWRITE_DATA_POINTER_USER) {
        payloadExpr = readArray(data_ul, E_CONST(base_index, Expr::Int32),
                                sizeof(target_ulong));
        // 0x10000 <= X < 0x80000000000
        ref<ConstantExpr> min_user = E_CONST(0x10000, Expr::Int64);
        ref<ConstantExpr> max_user = E_CONST(0x80000000000, Expr::Int64);
        ref<ConstantExpr> zeroExpr = E_CONST(0, Expr::Int64);
        ref<ConstantExpr> oneExpr = E_CONST(1, Expr::Int64);
        lossExpr = E_ITE(E_LE(min_user, payloadExpr), zeroExpr,
                         AddExpr::create(E_SUB(min_user, payloadExpr),
                                         E_CONST(1, Expr::Int64)));
        lossExpr = AddExpr::create(
            lossExpr,
            E_ITE(E_LT(payloadExpr, max_user), zeroExpr,
                  AddExpr::create(E_SUB(payloadExpr, max_user), oneExpr)));
    } else if (type & OVERWRITE_REFCNT) {
        payloadExpr = readArray(data_ul, E_CONST(base_index, Expr::Int32), 4);
        lossExpr = alignExpr(payloadExpr, Expr::Int64);
    } else {
        payloadExpr = readArray(data_ul, E_CONST(base_index, Expr::Int32), len);
        lossExpr = E_CONST(0, Expr::Int64);
        for (unsigned i = 0; i < len; i++) {
            ref<Expr> charExpr =
                ReadExpr::create(data_ul, E_CONST(base_index + i, Expr::Int32));
            ref<Expr> payloadChar = E_CONST(payload[i], Expr::Int8);
            // FIXME: bit-wise change?
            // raw_data < payload?
            ref<Expr> onechange;
            // if (raw_data[base_index+i] <= payload[i]) {
            // onechange = E_SUB(payloadChar, charExpr);
            onechange = E_ITE(
                E_LE(charExpr, payloadChar), E_SUB(payloadChar, charExpr),
                E_CONST(0xff, Expr::Int8)); // E_SUB(charExpr, payloadChar));
            // } else {
            // 	onechange = E_SUB(charExpr, payloadChar);
            // onechange = E_ITE(E_LE(payloadChar, charExpr),
            // 				E_SUB(charExpr, payloadChar),
            // 				E_CONST(0xff, Expr::Int8));
            // }
            lossExpr = AddExpr::create(lossExpr, E_ZE(onechange, Expr::Int64));
        }
    }
}

int KernelInstructionTracer::solveCapability_once(S2EExecutionState *state,
                                                  std::vector<Capability> &caps,
                                                  std::string &target,
                                                  unsigned vul_size, int offset,
                                                  int len, uint8_t *payload,
                                                  int type) {

    std::vector<ConstraintManager> managers;
    for (unsigned i = 0; i < caps.size(); i++) {
        // Add constraint for the size of the vulnerable object
        Capability &cap = caps[i];
        ConstraintManager manager;
        if (cap.vuln.symbolic) {
            getDebugStream(state) << "Vulnerable object has variable length"
                                  << cap.vuln.sym_width << "\n";
            getDebugStream(state)
                << cap.assignment->evaluate(cap.vuln.sym_width) << "\n";
            // Deal with unaligned size
            uint64_t lowerbound = m_AllocManager->lowerSize(vul_size);
            manager.addConstraint(
                E_LE(cap.vuln.sym_width, E_CONST(vul_size, Expr::Int64)));
            manager.addConstraint(
                E_LT(E_CONST(lowerbound, Expr::Int64), cap.vuln.sym_width));
            getDebugStream(state) << "Length shoud be in the range "
                                  << lowerbound << "-" << vul_size << "\n";
        } else {
            if (roundSize(cap.vuln.width) != vul_size) {
                getDebugStream(state) << "Mismatched size\n";
                return ERROR_MISMATCH_SIZE;
            }
        }
        managers.push_back(manager);
    }
    getDebugStream(state) << "Add constraints for vulnerable object\n";

    // Add constraint for the destination address
    uint64_t elen = vul_size;
    getDebugStream(state) << "Aggreated size: " << hexval(elen) << "\n";

    for (unsigned i = 0; i < caps.size(); i++) {
        if (!eliminate_contradition(state, managers[i], caps[i].constraints,
                                    m_refineconstraint)) {
            getDebugStream(state) << "Invalid constraint set\n";
            return NO_ERROR_FAIL;
        }
        getDebugStream(state) << "Combine constraints\n";

        if (!constraint_check(state, managers[i])) {
            getDebugStream(state) << "Failed constraint check\n";
            return NO_ERROR_FAIL;
        }
    }
    getDebugStream(state) << "Pass constraint check so far!\n";

    std::vector<ref<ConstantExpr>> raw_data;
    std::vector<unsigned char> concrete_raw_data;
    uint64_t model_len =
        (offset >= 0 ? elen + m_options->max_length : vul_size);
    uint64_t model_diff = 0, base_index;
    if (model_len > 2 * m_options->max_length) {
        model_diff = model_len - 2 * m_options->max_length;
        model_len = 2 * m_options->max_length;
    }
    model_len += 8; // plus 8 dummy bytes
    base_index = offset + (offset >= 0 ? elen : vul_size) - model_diff;
    // init array
    getDebugStream(state) << "real length: " << hexval(model_len) << "\n";
    for (unsigned i = 0; i < model_len; i++) {
        raw_data.push_back(E_CONST(0, Expr::Int8));
        concrete_raw_data.push_back(0);
    }

    // initialize target object
    uint8_t *tgt_values;
    uint64_t tgt_len;
    if (!getValues(&tgt_values, tgt_len)) {
        getDebugStream() << "You must specify values\n";
        exit(1);
    }

    for (int i = 0; i < tgt_len; i++) {
        concrete_raw_data[base_index + i] = tgt_values[i];
        raw_data[base_index + i] = E_CONST(tgt_values[i], Expr::Int8);
    }

    unsigned iter = 0;
    uint64_t change = 0, old_change = 0;
    bool found = false;
    std::stringstream output;
    output << "{\"solutions\": [";
    do {
        old_change = change;
        uint64_t best_loss = -1;
        unsigned best_cap = -1;
        for (unsigned i = 0; i < caps.size(); i++) {
            auto array =
                Array::create("tmp_payload", raw_data.size(), &raw_data[0],
                              &raw_data[raw_data.size()], "tmp_payload");
            auto data_ul = UpdateList::create(array, 0);
            applyOperations(state, model_len, model_diff, data_ul, caps[i]);
            getDebugStream(state) << "Apply operations\n";

            ref<Expr> lossExpr;
            getLossExpr(data_ul, concrete_raw_data, payload, len, base_index,
                        type, lossExpr);

            ref<ConstantExpr> min_loss;
            getDebugStream(state) << "Test\n:";
            ConstraintManager tmp;
            copyConstraint(tmp, managers[i]);

            getDebugStream() << "Start to find Min\n";
            if (!findMin(state, tmp, lossExpr, min_loss, NULL, best_loss,
                         !m_options->reusable)) {
                getDebugStream(state)
                    << "Failed to get the minimum value of changeExpr\n";
                return NO_ERROR_FAIL;
            }
            getDebugStream(state) << "Minimum changeExpr: " << min_loss << "\n";
            if (i == 0 || min_loss->getZExtValue() < best_loss) {
                best_cap = i;
                best_loss = min_loss->getZExtValue();
            }

            // No need to check others
            if (best_loss == 0) {
                break;
            }
        }

        if (best_loss && !m_options->reusable) {
            break;
        }

        // solve the constraints
        getDebugStream(state) << "Choose cap " << best_cap << " with loss "
                              << hexval(best_loss) << "\n";
        Capability &cap = caps[best_cap];
        auto array = Array::create("tmp_payload", raw_data.size(), &raw_data[0],
                                   &raw_data[raw_data.size()], "tmp_payload");
        auto data_ul = UpdateList::create(array, 0);
        applyOperations(state, model_len, model_diff, data_ul, cap);

        ref<Expr> lossExpr;
        getLossExpr(data_ul, concrete_raw_data, payload, len, base_index, type,
                    lossExpr);

        ConstraintManager tmp;
        copyConstraint(tmp, managers[best_cap]);
        tmp.addConstraint(E_EQ(lossExpr, E_CONST(best_loss, Expr::Int64)));

        // search for minimum length
        std::map<uint64_t, bool> visited;
        for (auto &op : cap.ops) {
            if (visited.find(op.pc) != visited.end()) {
                continue;
            }

            ref<ConstantExpr> min_len;
            if (cap.loopguards.find(op.pc) != cap.loopguards.end()) {
                ref<Expr> EEC = cap.guardtable[cap.loopguards[op.pc]]->expcount;
                visited[op.pc] = true;
                if (!findMin(state, tmp, EEC, min_len, cap.assignment)) {
                    getDebugStream()
                        << "Failed to get the minimum value for length\n";
                    return NO_ERROR_FAIL;
                }
                tmp.addConstraint(E_EQ(EEC, min_len));
                continue;
            }

            // FIXME: include all spots
            Spot spot = cap.spots[op.pc];
            if (spot.type == TYPE_MEMCPY || spot.type == TYPE_STRCPY) {
                if (!findMin(state, tmp, op.len, min_len, cap.assignment)) {
                    getDebugStream()
                        << "Failed to get the minimum value for length\n";
                    return NO_ERROR_FAIL;
                }
                tmp.addConstraint(E_EQ(op.len, min_len));
            }
            visited[op.pc] = true;
        }

        ArrayVec objects;
        std::vector<std::vector<unsigned char>> values;
        if (iter != 0) {
            output << ",\n";
        }
        if (!solution(state, tmp, cap.symbols, cap.assignment, objects, values,
                      output, true)) {
            getDebugStream(state) << "Cannot solve the constraints\n";
            break;
        }

        Assignment assignment = Assignment(objects, values);
        assignment.add(array, concrete_raw_data);

        for (unsigned i = 0; i < len; i++) {
            // apply all the operations to update the array
            // extract every byte from data_ul and save the concrete value??
            unsigned index = base_index + i;
            ref<Expr> charExpr =
                ReadExpr::create(data_ul, E_CONST(index, Expr::Int32));
            uint8_t v;
            if (ConstantExpr *CE = dyn_cast<ConstantExpr>(charExpr)) {
                v = CE->getZExtValue();
            } else {
                ref<Expr> res = assignment.evaluate(charExpr);
                if (ConstantExpr *CE = dyn_cast<ConstantExpr>(res)) {
                    v = CE->getZExtValue();
                } else {
                    getDebugStream(state) << charExpr << "\n";
                    assert(false && "Failed to evalute!");
                }
            }
            raw_data[index] = E_CONST(v, Expr::Int8);
            concrete_raw_data[index] = v;
            getDebugStream(state) << "Evaluate: " << hexval(v) << "\n";
        }

        change = best_loss;
        if (change == 0) {
            found = true;
            getDebugStream(state) << "Found a solution\n";
            output << "],\n\"target\": \"" << target << "\"";
            output << ", \"size\": " << std::to_string(vul_size);

            if (type & OVERWRITE_POINTER) {
                std::stringstream pointer;
                pointer << "0x";
                for (int i = 7; i >= 0; i--) {
                    int index = base_index + i;
                    ref<Expr> charExpr =
                        ReadExpr::create(data_ul, E_CONST(index, Expr::Int32));
                    ref<ConstantExpr> res =
                        dyn_cast<ConstantExpr>(assignment.evaluate(charExpr));
                    pointer << hexval(res->getZExtValue(), 2, false);
                }
                output << ",\n\"pointer:\": \"" << pointer.str() << "\"";
            }

            output << "}";
            getDebugStream(state) << output.str() << "\n";

            // Save solution in file
            // std::string ans_file = s2e()->getOutputFilename("Answer.json");
            // FILE *answer = fopen(ans_file.c_str(), "w");
            // fwrite(output.str().c_str(), 1, output.str().size(), answer);
            // fclose(answer);
            // break;
            return NO_ERROR_SUCCEED;
        }
        iter++;
    } while ((change < old_change || iter == 1) && m_options->reusable);

    return NO_ERROR_FAIL;
}

bool KernelInstructionTracer::solveWithCapability(
    S2EExecutionState *state, std::vector<Capability> &caps) {
    if (caps.size() == 0) {
        return true;
    }

    // FIXME: check consistency beetween caps
    Capability &cap = caps[0];
    while (true) {
        // start with one candidate
        uint64_t v_size = m_AllocManager->roundSize(cap.vuln.width), t_len;
        int t_offset;
        uint8_t *payload;
        bool success =
            getCandidate(v_size, cap.vuln.symbolic, cap.vuln.allocator,
                         t_offset, &payload, t_len);
        if (!success) {
            getDebugStream(state) << "End of search\n";
            return true;
        }
        getDebugStream(state)
            << "offset: " << t_offset << ", len: " << t_len
            << ", size: " << v_size << ", payload: " << hexval(payload)
            << ", alloc: " << cap.vuln.allocator << "\n";
        getDebugStream(state) << "payload: " << hexval(payload[0]) << " \n";

        std::string target;
        if (!getCurCandidate(target)) {
            getDebugStream(state) << "Cannot get target object\n";
            continue;
        }
        getDebugStream(state) << "Target: " << target << "\n";
        ConfigFile *cfg = s2e()->getConfig();
        std::stringstream key;
        bool ok = true;
        key << "TargetObjects." << target;
        int type = cfg->getInt(key.str() + ".type", TYPE_CUSTOM, &ok);
        EXIT_ON_ERROR(ok, "You must specify type!");

        uint64_t start_time = getmilliseconds();
        int err = NO_ERROR_FAIL;
        uint8_t kernel_address[8] = {0x40, 0x10, 0x80, 0x76,
                                     0,    0x80, 0xff, 0xff};
        uint8_t user_address[8] = {0, 0, 0, 0, 0, 0x80, 0, 0};
        if (type == TYPE_REFCNT) {
            err = solveCapability_once(state, caps, target, v_size, t_offset, 4,
                                       payload, OVERWRITE_REFCNT);
        } else if (type == TYPE_DATA_POINTER) {
            // mmap range: 0x10000 - 0x800000000000
            // user space address
            if (!m_options->enable_smap) {
                err = solveCapability_once(state, caps, target, v_size,
                                           t_offset, 8, &user_address[0],
                                           OVERWRITE_DATA_POINTER_USER);
            }
            // kernel space address
            if (err == NO_ERROR_FAIL) {
                err = solveCapability_once(state, caps, target, v_size,
                                           t_offset, 8, &kernel_address[0],
                                           OVERWRITE_DATA_POINTER_KERNEL);
            }
        } else if (type == TYPE_CUSTOM || type == TYPE_FUNC_POINTER) {
            err = solveCapability_once(state, caps, target, v_size, t_offset,
                                       t_len, payload, OVERWRITE_FUNC_POINTER);
        }
        start_time = getmilliseconds() - start_time;
        getDebugStream() << "S2E: {\"time\": " << std::to_string(start_time)
                         << "}"
                         << "\n";
    }
}

void KernelInstructionTracer::printSyscalls(S2EExecutionState *state,
                                            uint64_t base_addr) {
    std::vector<unsigned> syscalls;
    unsigned allocIndex, defIndex;
    m_AllocManager->getSyscallIndex(base_addr, allocIndex, defIndex, syscalls);

    std::stringstream ss;
    ss << "[SYSCALLS] {";
    ss << "\"allocIndex\": " << std::to_string(allocIndex);
    ss << ", \"defIndex\": " << std::to_string(defIndex);
    ss << ", \"syscalls\": [";
    for (int i = 0; i < syscalls.size(); i++) {
        if (i > 0) {
            ss << ", ";
        }
        ss << std::to_string(syscalls[i]);
    }
    ss << "]}";
    getDebugStream() << ss.str() << "\n";
}

void KernelInstructionTracer::printLayout(S2EExecutionState *state,
                                          uint64_t base_addr) {
    std::vector<unsigned> layout;
    m_AllocManager->getLayout(state, base_addr, layout);

    std::stringstream ss;
    int i = 0;
    ss << "[LAYOUT] {\"layout\": [";
    for (auto each : layout) {
        if (i > 0) {
            ss << ", ";
        }
        i++;
        ss << std::to_string(each);
    }
    ss << "]}";
    getDebugStream() << ss.str() << "\n";
}
} // namespace plugins
} // namespace s2e
