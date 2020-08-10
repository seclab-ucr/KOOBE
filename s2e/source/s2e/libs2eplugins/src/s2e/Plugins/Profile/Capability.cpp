
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>

#include "Evaluation.h"
#include "Serialize.h"

using namespace klee;

namespace s2e {
namespace plugins {

#define DEBUG_CAPSUMMARY

// Capability related
void genSymbolValue(S2EExecutionState *state, Capability &cap, ref<Expr> &expr,
                    SymbolValue &value) {
    // length and offset should not more that 2048
    // value is a single byte
    auto pair =
        findMinMax(state, cap.constraints, expr, cap.assignment, 0, 2048);
    ref<Expr> res = cap.assignment->evaluate(expr);
    value.min = pair.first;
    value.max = pair.second;
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(res)) {
        value.value = CE->getZExtValue();
    }
}

void genCapSummary(S2EExecutionState *state, Capability &cap,
                   std::map<uint64_t, Summary> &summaries) {
    std::map<uint64_t, unsigned> indices;
    for (auto &op : cap.ops) {
        Summary sum;
        if (cap.loopguards.find(op.pc) != cap.loopguards.end()) {
            if (indices.find(op.pc) != indices.end()) {
                continue;
            }
            indices[op.pc] = 0;
            ref<Expr> offset =
                E_SUB(op.dst, E_CONST(cap.vuln.vul_base, Expr::Int64));
            ref<Expr> EEC = cap.guardtable[cap.loopguards[op.pc]]->expcount;
            ref<Expr> length = MulExpr::create(EEC, op.len);
            genSymbolValue(state, cap, offset, sum.offset);
            genSymbolValue(state, cap, length, sum.length);
            summaries[op.pc] = sum;
            // omit value for loops
            continue;
        }

        ref<Expr> offset =
            E_SUB(op.dst, E_CONST(cap.vuln.vul_base, Expr::Int64));
        genSymbolValue(state, cap, offset, sum.offset);
        genSymbolValue(state, cap, op.len, sum.length);
        uint64_t concrete_len = readExpr<uint64_t>(cap.assignment, op.len);
        for (uint64_t i = 0; i < concrete_len && i < 2048; i++) {
            ref<Expr> byte = E_EXTR(op.payload, i * CHAR_BIT, Expr::Int8);
            SymbolValue tmp;
            genSymbolValue(state, cap, byte, tmp);
            sum.values.push_back(tmp);
        }
        summaries[op.pc] = sum;
    }
#ifdef DEBUG_CAPSUMMARY
    std::stringstream ss;
    for (auto it : summaries) {
        ss << "PC: " << hexval(it.first) << "\n";
        it.second.print(ss);
    }
    g_s2e->getDebugStream() << ss.str();
#endif
}

#define UNKNOWN 3
int compareSymbolValue(SymbolValue &a, SymbolValue &b) {
    if (a.min == b.min && a.max == b.max) {
        return 1;
    }
    if (a.min >= b.min && a.max <= b.max) {
        return 0;
    }
    if (a.min <= b.min && a.max >= b.max) {
        return 2;
    }

    return UNKNOWN;
}
/*
 *	Return:
 *  -1: a is less than or equal to b
 * 1:   a is larger than b
 * 0: cannot compare
 */
int compareSummary(Summary &a, Summary &b) {
    // a < b 
    if (compareSymbolValue(a.offset, b.offset) <= 1 &&
        compareSymbolValue(a.length, b.length) <= 1) {
        if (a.values.size() <= b.values.size()) {
            bool found = false;
            for (unsigned i = 0; i < a.values.size(); i++) {
                if (compareSymbolValue(a.values[i], b.values[i]) > 1) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                // special case
                if (a.length.value > b.length.value) {
                    return 1;
                }
                return -1;
            }
        }
        return 0;
    }
    // a > b
    if (compareSymbolValue(a.offset, b.offset) >= 1 &&
        compareSymbolValue(a.length, b.length) >= 1) {
        if (a.values.size() >= b.values.size()) {
            bool found = false;
            for (unsigned i = 0; i < b.values.size(); i++) {
                if (compareSymbolValue(a.values[i], b.values[i]) <= 1) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return 1;
            }
        }
        return 0;
    }
    return 0;
}

bool isNewCapability(S2EExecutionState *state, Capability &cap, std::string workdir) {
    // Load database
    std::string database = workdir + "/database";
    CapSummary caps;
    std::map<uint64_t, Spot> spots;
    std::map<uint64_t, Summary> new_cap;
    {
        if (fileExists(database)) {
            std::ifstream ifs(database, std::ifstream::binary);
            deserialize(ifs, caps, spots);
        }
    }

    genCapSummary(state, cap, new_cap);
    bool isNew = false;
    for (auto &it : caps) {
        auto pos = new_cap.find(it.first);
        if (pos == new_cap.end()) {
            continue;
        }
        Summary new_sum = new_cap[it.first];
        bool insert = true;
        for (auto itt = it.second.begin(); itt != it.second.end();) {
            int res = compareSummary(new_sum, *itt);
            if (res < 0) {
                insert = false;
                break;
            } else if (res > 0) {
                it.second.erase(itt);
            } else {
                ++itt;
            }
        }
        if (insert) {
            isNew = true;
            it.second.push_back(new_sum);
        }
        new_cap.erase(pos);
    }

    // New vulnerability points
    for (auto it : new_cap) {
        std::vector<Summary> summaries;
        summaries.push_back(it.second);
        caps.insert({it.first, summaries});
        isNew = true;
    }

    for (auto it : cap.spots) {
        if (spots.find(it.first) == spots.end()) {
            spots.insert({it.first, it.second});
        }
    }

    {
        std::ofstream ofs(database, std::ofstream::binary);
        serialize(ofs, caps, spots);
        // save all vuln points
        // std::stringstream ss;
        // ss << "{\"Addrs\": [";
        // foreach2(it, spots.begin(), spots.end()) {
        //     if (it != spots.begin()) {
        //         ss << ", ";
        //     }
        //     ss << std::to_string(it->first);
        // }
        // ss << "]}";
        // std::ofstream vulns("addrs.json");
        // vulns.write(ss.str().c_str(), ss.str().size());
    }
    return isNew;
}

// save and restore state
bool saveState(S2EExecutionState *state, Capability &cap,
               ConstraintManager &manager, std::vector<OOB_Operation> &ops,
               std::map<uint64_t, uint64_t> &loopguards, GuardTable &guardtable,
               AllocObj vul_obj, uint64_t base_addr,
               std::map<uint64_t, Spot> &spots, std::string allocator,
               std::string filepath, std::string workdir) {

    cap.constraints = manager;
    selectSymbols(state, cap.symbols);
    cap.assignment = state->concolics;
    cap.ops = ops;
    cap.loopguards = loopguards;
    cap.guardtable = guardtable;
    cap.spots = spots;

    cap.vuln.symbolic = vul_obj.tag == AllocObj::Tag::SYMBOLIC;
    cap.vuln.allocator = allocator;
    cap.vuln.vul_base = base_addr;
    cap.vuln.width = vul_obj.width;
    cap.vuln.sym_width = vul_obj.sym_width;

    for (auto & it : cap.ops) {
        it.dst = rebuildExpr(it.dst);
    }

    if (!isNewCapability(state, cap, workdir)) {
        g_s2e->getDebugStream() << "The capability is duplicate!\n";
        return true;
    }

    {
        std::ofstream ofs(filepath, std::ofstream::binary);
        g_s2e->getDebugStream() << "start to serialize\n";
        serialize_init();
        serialize(ofs, cap);
    }

    {
        // std::ifstream ifs(filepath, std::ifstream::binary);
        // // ref<Expr> expr;
        // // deserialize(ifs, expr);
        // Capability temp;
        // deserialize(ifs, temp);
        // for (auto expr : temp.constraints) {
        // 	g_s2e->getDebugStream(state) << "Restore: " << expr << "\n";
        // }
    }
    return true;
}

bool restoreState(Capability &cap, std::string filepath) {
    std::ifstream ifs(filepath, std::ifstream::binary);
    deserialize_init();
    deserialize(ifs, cap);
    return true;
}

}
}
