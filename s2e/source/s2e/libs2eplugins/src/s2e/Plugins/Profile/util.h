#ifndef S2E_PLUGINS_UTILITY_H
#define S2E_PLUGINS_UTILITY_H

#include <s2e/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Utils.h>

#include <klee/Expr.h>
#include <klee/util/ExprTemplates.h>

#include <sys/stat.h>
#include <time.h>

namespace s2e {
namespace plugins {

#define DEFAULT_WIDTH (sizeof(target_ulong) * CHAR_BIT)

extern klee::Solver *g_Solver;
inline klee::Solver *getSolver(S2EExecutionState *state) {
    auto solver = klee::SolverManager::solver(*state)->solver;
    // if (g_Solver == NULL) {
    //     g_Solver = Z3Solver::createResetSolver();
    // }
    // if (solver == NULL) {
    //     g_s2e->getDebugStream() << "Solver is NULL\n";
    // }
    return solver;
}

template <typename T>
T inline readExpr(klee::Assignment *assignment, klee::ref<klee::Expr> &expr) {
    if (klee::ConstantExpr *CE = dyn_cast<klee::ConstantExpr>(expr)) {
        return CE->getZExtValue(sizeof(T) * CHAR_BIT);
    }
    klee::ref<klee::Expr> tmp = assignment->evaluate(expr);
    if (klee::ConstantExpr *CE = dyn_cast<klee::ConstantExpr>(tmp)) {
        return CE->getZExtValue(sizeof(T) * CHAR_BIT);
    }
    assert(false && "Unable to get concrete value");
    exit(-1);
    return 0;
}

template <typename T>
T inline readExpr(S2EExecutionState *state, klee::ref<klee::Expr> &expr) {
    return readExpr<T>(state->concolics, expr);
}

klee::ref<klee::Expr> readArray(klee::UpdateListPtr &array,
                                klee::ref<klee::Expr> index, unsigned bytes);
bool updateArray(klee::UpdateListPtr &array, klee::ref<klee::Expr> index,
                 klee::ref<klee::Expr> data);

klee::ref<klee::Expr> inline alignExpr(
    klee::ref<klee::Expr> expr, klee::Expr::Width width = DEFAULT_WIDTH) {
    if (expr->getWidth() > width) {
        return E_EXTR(expr, 0, width);
    } else if (expr->getWidth() < width) {
        return E_ZE(expr, width);
    }
    return expr;
}

bool inline updateArray(S2EExecutionState *state, klee::UpdateList &array,
                        klee::ref<klee::Expr> index, uint64_t srcAddr,
                        unsigned len) {
    index = alignExpr(index, klee::Expr::Int32);
    for (unsigned i = 0; i < len; i++) {
        klee::ref<klee::Expr> addr =
            klee::AddExpr::create(index, E_CONST(i, index->getWidth()));
        klee::ref<klee::Expr> srcData =
            state->mem()->read(srcAddr + i, klee::Expr::Int8);
        if (srcData.isNull()) {
            return false;
        }
        array.extend(addr, srcData);
    }
    return true;
}

#define EXIT_ON_ERROR(ok, msg)                          \
    if (!(ok)) {                                        \
        g_s2e->getWarningsStream() << (msg) << "\n";    \
        exit(-1);                                       \
    }

klee::ref<klee::Expr> rebuildExpr(klee::ref<klee::Expr> expr, unsigned depth=0);
std::string getName(std::string symbol_name, std::string prefix);
std::string getVariableName(std::string symbol_name);
std::string getOriginName(std::string symbol_name);
uint64_t getValueFromName(std::string symbol_name, std::string prefix);
bool findSymBase(klee::ref<klee::Expr> expr, klee::ref<klee::ReadExpr> &ret,
                 std::string prefix);
void collectRead(klee::ref<klee::Expr> expr,
                 std::set<klee::ReadExpr *> &collection, unsigned depth = 0);
void selectSymbols(S2EExecutionState *state,
                   std::map<std::string, const klee::ArrayPtr> &selected);

bool findMin(S2EExecutionState *state, klee::ConstraintManager manager,
             klee::ref<klee::Expr> expr, klee::ref<klee::ConstantExpr> &ret,
             klee::Assignment *assignment, uint64_t minimum = 0,
             bool isZero = false);
std::pair<uint64_t, uint64_t> findMinMax(S2EExecutionState *state, klee::ConstraintManager &manager, klee::ref<klee::Expr> &expr, klee::Assignment *assignment, uint64_t minimum, uint64_t maximum);


uint64_t inline getmilliseconds() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((uint64_t)tv.tv_sec) * 1000 + ((uint64_t)tv.tv_usec / 1000);
}

bool inline fileExists(const std::string &file) {
    struct stat buf;
    return (stat(file.c_str(), &buf) == 0);
}

void dumpMemory(S2EExecutionState *state, uint64_t address, unsigned size, std::vector<uint8_t> &bytes);
void dumpState(S2EExecutionState *state);

// KERNEL functions
inline unsigned short from32to16(unsigned a) {
    unsigned short b = a >> 16;
    asm("addw %w2,%w0\n\t"
        "adcw $0,%w0\n"
        : "=r"(b)
        : "0"(b), "r"(a));
    return b;
}

inline unsigned add32_with_carry(unsigned a, unsigned b) {
    asm("addl %2,%0\n\t"
        "adcl $0,%0"
        : "=r"(a)
        : "0"(a), "r"(b));
    return a;
}
}
}
#endif
