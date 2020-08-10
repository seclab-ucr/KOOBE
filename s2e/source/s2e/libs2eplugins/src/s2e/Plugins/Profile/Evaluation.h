#ifndef S2E_PLUGINS_EVALUATION_H
#define S2E_PLUGINS_EVALUATION_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Utils.h>

#include <klee/Expr.h>
#include <klee/Solver.h>

#include "loopGuard.h"
#include "AllocationMap.h"

namespace s2e {
namespace plugins {

// list in order (priority)
#define TYPE_NONE 0
#define TYPE_STORE 1
#define TYPE_MEMSET 2
#define TYPE_STRCPY 3
#define TYPE_MEMCPY 4
#define TYPE_MEMMOVE 5

#define TYPE_REFCNT 1
#define TYPE_DATA_POINTER 2
#define TYPE_FUNC_POINTER 3
#define TYPE_CUSTOM 4

#define OVERWRITE_REFCNT 1
#define OVERWRITE_DATA_POINTER_USER (1 << 1)
#define OVERWRITE_DATA_POINTER_KERNEL (1 << 2)
#define OVERWRITE_DATA_POINTER                                                 \
    (OVERWRITE_DATA_POINTER_USER | OVERWRITE_DATA_POINTER_KERNEL)
#define OVERWRITE_FUNC_POINTER_USER (1 << 3)
#define OVERWRITE_FUNC_POINTER_KERNEL (1 << 4)
#define OVERWRITE_FUNC_POINTER                                                 \
    (OVERWRITE_FUNC_POINTER_USER | OVERWRITE_FUNC_POINTER_KERNEL)
#define OVERWRITE_CUSTOM (1 << 5)
#define OVERWRITE_POINTER (OVERWRITE_DATA_POINTER | OVERWRITE_FUNC_POINTER)

// ERROR CODE
#define NO_ERROR_SUCCEED 1
#define NO_ERROR_FAIL (1 << 2)
#define ERROR_MISMATCH_SIZE (1 << 3)
#define ERROR_REACH_TARGET (1 << 4)
#define ERROR_INVALID_OFFSET (1 << 5)
#define SUCCEED_OR_HALT                                                        \
    (NO_ERROR_SUCCEED | ERROR_MISMATCH_SIZE | ERROR_REACH_TARGET |             \
     ERROR_INVALID_OFFSET)

struct Signature {
    uint8_t src;
    uint8_t dst;
    uint8_t len;
    void defaultValue(unsigned type) {
        switch (type) {
        case TYPE_STRCPY:
            dst = 0;
            src = 1;
            len = (uint8_t)-1;
            break;
        case TYPE_MEMCPY:
        case TYPE_MEMSET:
            dst = 0;
            src = 1;
            len = 2;
            break;
        case TYPE_STORE:
        case TYPE_NONE:
        default:
            src = dst = len = (uint8_t)-1;
            break;
        }
    }
};

struct Spot {
    unsigned type;
    Signature sig;
};

struct OOB_Operation {
    klee::ref<klee::Expr> dst;
    klee::ref<klee::Expr> payload;
    klee::ref<klee::Expr> len;
    // unsigned len;
    unsigned order;
    uint64_t pc;
    static bool ascendInorder(OOB_Operation a, OOB_Operation b) {
        return a.order < b.order;
    }
    bool ascendInaddr(OOB_Operation a, OOB_Operation b) {
        return a.dst < b.dst;
    }
};

struct Capability {
    klee::ConstraintManager constraints;
    std::map<std::string, const klee::ArrayPtr> symbols;
    Assignment *assignment;
    struct {
        bool symbolic;
        std::string allocator;
        uint64_t vul_base;
        uint64_t width;
        klee::ref<klee::Expr> sym_width;
    } vuln;
    std::vector<OOB_Operation> ops;
    std::map<uint64_t, uint64_t> loopguards;
    GuardTable guardtable;
    std::map<uint64_t, Spot> spots;
};

// Capability summary for fuzzing
struct SymbolValue {
    uint64_t min, max;
    uint64_t value; // concrete value

    void print(std::stringstream &ss) {
        ss << "Min: " << min << ", Max: " << max << ", Value: " << value
           << "\n";
    }
};

struct Summary {
    SymbolValue offset, length;
    std::vector<SymbolValue> values;

    void print(std::stringstream &ss) {
        ss << "Offset ";
        offset.print(ss);
        ss << "Length ";
        length.print(ss);
        ss << "Values: [\n";
        for (auto it : values) {
            it.print(ss);
        }
        ss << "]\n";
    }
};

typedef std::map<uint64_t, std::vector<Summary>> CapSummary;

typedef std::vector<std::pair<std::string, std::vector<unsigned char>>>
    Solution;
bool filterconstraint2(
    S2EExecutionState *state,
    std::vector<std::pair<uint64_t, klee::ref<klee::Expr>>> &constraints,
    std::vector<uint16_t> labels, klee::ConstraintManager &manager);

void inline combineManager(klee::ConstraintManager &manager,
                           klee::ConstraintManager &origin) {
    for (auto c : origin) {
        manager.addConstraint(c);
    }
}

bool eliminate_contradition(S2EExecutionState *state,
                            klee::ConstraintManager &manager,
                            klee::ConstraintManager &origin, bool tune = true);
bool constraint_check(S2EExecutionState *state,
                      klee::ConstraintManager &manager);
bool addconstraint_check(S2EExecutionState *state,
                         klee::ConstraintManager &manager,
                         klee::ref<klee::Expr> expr, bool validate = false);
bool solution(S2EExecutionState *state, klee::ConstraintManager &manager,
              ArrayVec &objects,
              std::vector<std::vector<unsigned char>> &values,
              std::stringstream &output, bool tune = true);
void identify_contraditory(
    S2EExecutionState *state, klee::ConstraintManager &manager,
    std::vector<std::pair<uint64_t, klee::ref<klee::Expr>>> &constraints,
    klee::ref<klee::Expr> expr, bool isCondition);

bool saveState(S2EExecutionState *state, Capability &cap,
               klee::ConstraintManager &manager,
               std::vector<OOB_Operation> &ops,
               std::map<uint64_t, uint64_t> &loopguards, GuardTable &guardtable,
               AllocObj vul_obj, uint64_t base_addr,
               std::map<uint64_t, Spot> &spots, std::string allocator,
               std::string filepath, std::string workdir);
bool restoreState(Capability &cap, std::string filepath);

}
}
#endif
