#include <s2e/S2E.h>
#include <s2e/cpu.h>

#include "util.h"

using namespace klee;

namespace s2e {
namespace plugins {

Solver *g_Solver = NULL;

// Index must be 32-Width long
ref<Expr> readArray(UpdateListPtr &array, ref<Expr> index, unsigned bytes) {
    ref<Expr> ret;
    assert(bytes > 0);
    // assumes little-endian
    if (ConstantExpr *ci = dyn_cast<ConstantExpr>(index)) {
        uint64_t value = ci->getZExtValue();
        ret = ReadExpr::create(array, E_CONST(value, Expr::Int32));
        for (unsigned i = 1; i < bytes; i++) {
            ret = ConcatExpr::create(
                ReadExpr::create(array, E_CONST(value + i, Expr::Int32)), ret);
        }
    } else {
        index = alignExpr(index, Expr::Int32);
        ret = ReadExpr::create(array, index);
        for (unsigned i = 1; i < bytes; i++) {
            ret = ConcatExpr::create(
                ReadExpr::create(
                    array,
                    AddExpr::create(index, E_CONST(i, index->getWidth()))),
                ret);
        }
    }
    return ret;
}

// data may have length larger than 64 bits
bool updateArray(UpdateListPtr &array, ref<Expr> index, ref<Expr> data) {
    unsigned bytes = data->getWidth() / CHAR_BIT;
    std::vector<ref<Expr>> payload;
    if (bytes == 1) {
        payload.push_back(data);
    } else {
        for (unsigned i = 0; i < bytes; i++) {
            ref<Expr> charExpr = E_EXTR(data, i * CHAR_BIT, Expr::Int8);
            payload.push_back(charExpr);
        }
    }

    // Update array one byte at a time
    index = alignExpr(index, Expr::Int32);
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(index)) {
        uint64_t value = CE->getZExtValue();
        for (unsigned i = 0; i < bytes; i++) {
            ref<Expr> addr = E_CONST(value + i, Expr::Int32);
            array->extend(addr, payload[i]);
        }
    } else {
        for (unsigned i = 0; i < bytes; i++) {
            ref<Expr> addr =
                AddExpr::create(index, E_CONST(i, index->getWidth()));
            array->extend(addr, payload[i]);
        }
    }
    return true;
}

//
// Expression Manipluation
//
std::string getName(std::string symbol_name, std::string prefix) {
    size_t start = symbol_name.find(prefix);
    if (start == std::string::npos) {
        return "";
    }
    size_t end = symbol_name.rfind('_');
    std::string name = symbol_name.substr(start, end - start);
    return name;
}

std::string getVariableName(std::string symbol_name) {
    std::string symbol = getName(symbol_name, "local_");
    if (symbol.size() > 0)
        return symbol;
    symbol = getName(symbol_name, "ptr_");
    return symbol;
}

std::string getOriginName(std::string symbol_name) {
    size_t start = symbol_name.find('_');
    if (start == std::string::npos) {
        return symbol_name;
    }
    size_t end = symbol_name.rfind('_');
    std::string name = symbol_name.substr(start + 1, end - start - 1);
    return name;
}

uint64_t getValueFromName(std::string symbol_name, std::string prefix) {
    std::string symbol = getName(symbol_name, prefix);
    if (symbol.size() == 0)
        return 0;

    std::string addr =
        symbol.substr(prefix.size() + 2); // 2 more characters for "0x"
    uint64_t value;
    sscanf(addr.c_str(), "%lx", &value);
    return value;
}

void collectRead(ref<Expr> expr, std::set<ReadExpr *> &collection,
                 unsigned depth) {
    ref<Expr> ee;
    // const Array *arry;
    // avoid infinity recursive
    static std::set<unsigned> visited;
    if (depth == 0) {
        visited.clear();
    }
    unsigned hash = expr->hash();
    if (visited.find(hash) != visited.end()) {
        return;
    }
    visited.insert(hash);

    switch (expr->getKind()) {
    case Expr::Extract:
        collectRead(dyn_cast<ExtractExpr>(expr)->getExpr(), collection,
                    depth + 1);
        break;
    case Expr::Constant:
        break;
    case Expr::Read:
        collection.insert(dyn_cast<ReadExpr>(expr));
        break;
    default:
        for (unsigned i = 0; i < expr->getNumKids(); i++) {
            collectRead(expr->getKid(i), collection, depth + 1);
        }
        break;
    }
}

bool findSymBase(ref<Expr> expr, ref<ReadExpr> &ret, std::string prefix) {
    std::set<ReadExpr *> collection;
    collectRead(expr, collection);
    foreach2(it, collection.begin(), collection.end()) {
        std::string name = (*it)->getUpdates()->getRoot()->getName();
        size_t pos = name.find(prefix);
        if (pos == std::string::npos) {
            continue;
        }
        ret = *it;
        return true;
    }
    return false;
}

bool compactprint(ref<Expr> &expr) {
    if (expr->getKind() == Expr::Eq) {
        ref<Expr> expr1 = expr->getKid(0);
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(expr1)) {
            if (CE->getZExtValue() == 0) {
                ref<Expr> expr2 = expr->getKid(1);
                if (expr2->getKind() == Expr::And) {
                    return true;
                }
            }
        }
    }
    return false;
}

void selectSymbols(S2EExecutionState *state,
                   std::map<std::string, const ArrayPtr> &selected) {
    std::map<std::string, std::pair<std::string, const ArrayPtr>> symbol_names;
    for (unsigned i = 0; i != state->symbolics.size(); i++) {
        std::string name = state->symbolics[i]->getName();
        std::string variable = state->symbolics[i]->getRawName();
        symbol_names.insert(
            {variable,
             {name, state->symbolics[i]}}); // always take the latest symbol
    }

    foreach2(it, symbol_names.begin(), symbol_names.end()) {
        selected.insert(it->second);
    }
}

uint64_t getValue(Solver *solver, ConstraintManager &manager,
                  Assignment *assignment, ref<Expr> &expr) {
    uint64_t ret;
    if (assignment != NULL) {
        ref<Expr> result = assignment->evaluate(expr);
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(result)) {
            ret = CE->getZExtValue();
        } else {
            assert(false && "Concolic evaluation failed");
        }
    } else {
        ref<ConstantExpr> result;
        if (solver->getValue(Query(manager, expr), result)) {
            ret = result->getZExtValue();
        } else {
            assert(false && "Symbolic evaluation failed");
        }
    }
    return ret;
}

static ref<Expr> rebuildRead(ref<ReadExpr> expr) {
    std::string name = expr->getUpdates()->getRoot()->getRawName();
    size_t start = name.find("alc_");
    if (start == std::string::npos) {
        return expr;
    }
    std::string addr = name.substr(6); // 2 more characters for "0x"
    uint64_t value;
    sscanf(addr.c_str(), "%lx", &value);

    ref<Expr> index = expr->getIndex();
    if (ConstantExpr *ce = dyn_cast<ConstantExpr>(index)) {
        unsigned c_index = ce->getZExtValue();
        value = value >> (c_index * 8);
        return E_CONST(value & 0xff, Expr::Int8);
    }
    return expr;
}

ref<Expr> rebuildExpr(ref<Expr> expr, unsigned depth) {
    static ExprHashMap<ref<Expr>> visited;
    if (depth == 0) visited.clear();

    if (isa<ConstantExpr>(expr))
        return expr;

    auto it = visited.find(expr);
    if (it != visited.end()) {
        return it->second;
    }

    ref<Expr> kids[4];
    ref<Expr> res;
    unsigned i;
    switch (expr->getKind()) {
        case Expr::Read:
            res = rebuildRead(dyn_cast<ReadExpr>(expr));
            break;
        default:
            for (i = 0; i < expr->getNumKids(); i++) {
                kids[i] = rebuildExpr(expr->getKid(i), depth+1);
            }
            res = expr->rebuild(kids);
            break;
    }
    // g_s2e->getDebugStream() << "Prev: " << expr << "\n";
    // g_s2e->getDebugStream() << "New: " << res << "\n";
    visited.insert(std::make_pair(expr, res));
    return res;
}

bool findMin(S2EExecutionState *state, ConstraintManager manager,
             ref<Expr> expr, ref<ConstantExpr> &ret, Assignment *assignment,
             uint64_t minimum, bool isZero) {
    Expr::Width width = expr->getWidth();
    Solver *solver = getSolver(state);
    uint64_t min;

    if (width == 1) {
        Solver::Validity result;
        if (!solver->evaluate(Query(manager, expr), result))
            assert(0 && "computeValidity failed");
        switch (result) {
        case Solver::True:
            min = 1;
            break;
        case Solver::False:
            min = 0;
            break;
        default:
            min = 0;
            break;
        }
    } else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(expr)) {
        min = CE->getZExtValue();
    } else {
        // fast path
        if (isZero) {
            g_s2e->getDebugStream() << "Fast path for findMin\n";
            bool res;
            auto query = Query(manager, ConstantExpr::create(0, Expr::Bool));
            if (solver == NULL) {
                g_s2e->getDebugStream() << "NULL solver\n";
            }
            bool success = solver->mayBeTrue(
                query.withExpr(E_EQ(expr, E_CONST(0, width))), res);
            assert(success && "Unhandled solver failure");
            ret = res ? E_CONST(0, width) : E_CONST(1, width);
            return true;
        }

        // binary search for # of useful bits
        uint64_t lo = 0, hi, mid;
        hi = getValue(solver, manager, assignment, expr);

        while (lo < hi) {
            mid = lo + (hi - lo) / 2;
            bool res = false;
            bool success;
            if (mid == 0) {
                success = solver->mayBeTrue(
                    Query(manager, E_EQ(expr, E_CONST(0, width))), res);
            } else {
                success = solver->mayBeTrue(
                    Query(manager, E_LE(expr, E_CONST(mid, width))), res);
            }

            assert(success && "Unhandled solver failure");
            (void)success;

            if (res) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
            if (minimum != 0 && lo > minimum) {
                break;
            }
        }
        min = lo;
    }

    ret = E_CONST(min, width);
    return true;
}

std::pair<uint64_t, uint64_t> findMinMax(S2EExecutionState *state,
                                         ConstraintManager &manager,
                                         ref<Expr> &expr,
                                         Assignment *assignment,
                                         uint64_t minimum, uint64_t maximum) {
    uint64_t min, max;
    Expr::Width width = expr->getWidth();
    Solver *solver = getSolver(state);
    if (width == 1) {
        Solver::Validity result;
        if (!solver->evaluate(Query(manager, expr), result))
            assert(0 && "computeValidity failed");
        switch (result) {
        case Solver::True:
            min = max = 1;
            break;
        case Solver::False:
            min = max = 0;
            break;
        default:
            min = 0;
            max = 1;
            break;
        }
    } else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(expr)) {
        min = max = CE->getZExtValue();
    } else {
        uint64_t lo, hi, mid;
        uint64_t concrete = getValue(solver, manager, assignment, expr);
        // binary search for min
        lo = minimum == 0 ? 0 : minimum;
        hi = (maximum != 0 && maximum < concrete) ? maximum : concrete;
        while (lo < hi) {
            mid = lo + (hi - lo) / 2;
            bool res, success;
            success = solver->mayBeTrue(
                Query(manager, E_LE(expr, E_CONST(mid, width))), res);
            assert(success && "Unhandled solver failture");
            (void)success;

            if (res) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        min = lo;
        // binary search for max
        lo = (minimum != 0 && minimum > concrete) ? minimum : concrete;
        hi = (maximum != 0 && maximum < bits64::maxValueOfNBits(width))
                 ? maximum
                 : bits64::maxValueOfNBits(width);
        while (lo < hi) {
            mid = lo + (hi - lo) / 2;
            bool res, success;
            success = solver->mustBeTrue(
                Query(manager, E_LE(expr, E_CONST(mid, width))), res);
            assert(success && "Unhandled solver failure");
            (void)success;

            if (res) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        max = lo;
    }
    return std::make_pair(min, max);
}

void dumpMemory(S2EExecutionState *state, uint64_t address, unsigned size, std::vector<uint8_t> &bytes) {

    unsigned index = 0;
    std::stringstream ss;
    char buf[17] = {0};
    const unsigned length = 16;

    if (size > 4096) {
        size = 4096;
    }
    while (index < size) {
        unsigned i;
        ss << hexval(index, 4, false) << " ";
        for (i = 0; i < length; i++) {
            if (i + index >= size) {
                break;
            }
            ref<Expr> charExpr =
                state->mem()->read(address + index + i, Expr::Int8);
            if (ConstantExpr *CE = dyn_cast<ConstantExpr>(charExpr)) {
                buf[i] = 'C';
                ss << hexval(CE->getZExtValue(), 2, false) << " ";
                bytes.push_back(CE->getZExtValue());
            } else {
                buf[i] = 'S';
                uint8_t val = readExpr<uint8_t>(state, charExpr);
                ss << hexval(val, 2, false) << " ";
                bytes.push_back(val);
            }
        }
        for (; i < length; i++) {
            buf[i] = '.';
            ss << "   ";
        }
        ss << std::string(buf) << "\n";
        index += length;
    }
    g_s2e->getDebugStream() << ss.str();
}

void dumpState(S2EExecutionState *state) {
    static char regs[8][4] = {"eax", "ecx", "edx", "ebx",
                              "esp", "ebp", "esi", "edi"};
    for (unsigned i = 0; i < 8; i++) {
        unsigned offset = CPU_OFFSET(regs[0]) + i * sizeof(target_ulong);
        ref<Expr> expr =
            state->regs()->read(offset, sizeof(target_ulong) * CHAR_BIT);
        g_s2e->getDebugStream() << regs[i] << ":\n";
        g_s2e->getDebugStream() << expr << "\n";
    }
}

} // namespace plugins
} // namespace s2e
