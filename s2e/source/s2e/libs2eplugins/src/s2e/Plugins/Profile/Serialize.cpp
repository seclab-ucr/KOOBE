#include "Serialize.h"
#include "AllocationMap.h"
#include "KernelInstructionTracer.h"
#include "loopGuard.h"

// #define DEBUG_SERIALIZER

using namespace klee;

namespace s2e {
namespace plugins {

#define IFS_READ(ifs, var) ifs.read((char *)&(var), sizeof(var))
#define OFS_WRITE(ofs, var) ofs.write((char *)&(var), sizeof(var))

void serialize(std::ofstream &ofs, ConstantExpr *expr);
bool deserialize(std::ifstream &ifs, ref<ConstantExpr> &expr);
bool deserialize(std::ifstream &ifs, OOB_Operation &op);
void serialize(std::ofstream &ofs, SymbolValue &value);
bool deserialize(std::ifstream &ifs, SymbolValue &value);
void serialize(std::ofstream &ofs, Summary &sum);
bool deserialize(std::ifstream &ifs, Summary &sum);
void serialize(std::ofstream &ofs, Spot &spot);
bool deserialize(std::ifstream &ifs, Spot &spot);

// Pointer Cache
typedef uint32_t GUID;
static GUID GID_COUNTER = 0;
static std::map<GUID, void *> obj_cache; // object ID -> pointer
static std::map<void *, GUID> gid_cache; // pointer -> object ID

void serialize_init() {
    GID_COUNTER = 0;
    gid_cache.clear();
}

void deserialize_init() { obj_cache.clear(); }

void inline addGid(GUID id, void *p) { gid_cache.insert({p, id}); }

bool inline getGId(void *p, GUID &id) {
    auto it = gid_cache.find(p);
    if (it == gid_cache.end()) {
        id = GID_COUNTER++;
        addGid(id, p);
        return false;
    } else {
        id = it->second;
        return true;
    }
}

void inline addObject(GUID id, void *p) { obj_cache.insert({id, p}); }

void inline *getObject(GUID id) {
    auto it = obj_cache.find(id);
    if (it == obj_cache.end()) {
        return NULL;
    } else {
        return it->second;
    }
}

bool inline isCached(std::ofstream &ofs, void *p) {
    GUID id;
    bool cached = getGId(p, id);
    OFS_WRITE(ofs, id);
    return cached;
}

#define GET_OBJECT_GID(ifs)                                                    \
    GUID id;                                                                   \
    void *obj;                                                                 \
    IFS_READ(ifs, id);                                                         \
    obj = getObject(id)

#define SERIALIZE_PRIMITIVE(_class)                                            \
    void inline serialize(std::ofstream &ofs, const _class &v) {               \
        OFS_WRITE(ofs, v);                                                     \
    }

#define DESERIALIZE_PRIMITIVE(_class)                                          \
    bool inline deserialize(std::ifstream &ifs, _class &v) {                   \
        IFS_READ(ifs, v);                                                      \
        return true;                                                           \
    }

#define DEF_PRIMITIVE_SERIALIZE(_class)                                        \
    SERIALIZE_PRIMITIVE(_class)                                                \
    DESERIALIZE_PRIMITIVE(_class)

DEF_PRIMITIVE_SERIALIZE(uint64_t)
DEF_PRIMITIVE_SERIALIZE(unsigned char)

template <typename T>
void serialize(std::ofstream &ofs, const std::vector<T> &vector) {
    unsigned size = vector.size();
    OFS_WRITE(ofs, size);
    for (auto each : vector) {
        serialize(ofs, each);
    }
}

template <typename T>
void serialize(std::ofstream &ofs, const std::vector<ref<T>> &vector) {
    unsigned size = vector.size();
    OFS_WRITE(ofs, size);
    for (auto each : vector) {
        serialize(ofs, each.get());
    }
}

// special case for base clas
void serialize(std::ofstream &ofs, const std::vector<ref<Expr>> &vector) {
    unsigned size = vector.size();
    OFS_WRITE(ofs, size);
    for (auto each : vector) {
        serialize(ofs, each);
    }
}

template <typename T>
bool deserialize(std::ifstream &ifs, std::vector<T> &vector) {
    unsigned size;
    IFS_READ(ifs, size);
    for (unsigned i = 0; i < size; i++) {
        T each;
        deserialize(ifs, each);
        vector.push_back(each);
    }
    return true;
}

// AllocObj
void serialize(std::ofstream &ofs, const AllocObj &obj) {
    int tag = static_cast<int>(obj.tag);
    uint64_t allocator = obj.allocator;
    uint64_t width = obj.width;
    ref<Expr> sym_width = obj.sym_width;

    OFS_WRITE(ofs, tag);
    OFS_WRITE(ofs, allocator);
    OFS_WRITE(ofs, width);
    serialize(ofs, sym_width);
}

AllocObj deserialize_allocobj(std::ifstream &ifs) {
    int tag;
    uint64_t allocator, width;
    ref<Expr> sym_width;

    IFS_READ(ifs, tag);
    IFS_READ(ifs, allocator);
    IFS_READ(ifs, width);
    deserialize(ifs, sym_width);

    auto t = static_cast<AllocObj::Tag>(tag);
    if (t == AllocObj::Tag::CONCRETE) {
        return AllocObj(width, allocator);
    } else {
        return AllocObj(sym_width, allocator);
    }
}

// OOB_Operation
void serialize(std::ofstream &ofs, const OOB_Operation &op) {
    OFS_WRITE(ofs, op.order);
    OFS_WRITE(ofs, op.pc);

    serialize(ofs, op.dst);
    serialize(ofs, op.payload);
    serialize(ofs, op.len);
}

bool deserialize(std::ifstream &ifs, OOB_Operation &op) {
    IFS_READ(ifs, op.order);
    IFS_READ(ifs, op.pc);
    deserialize(ifs, op.dst);
    deserialize(ifs, op.payload);
    deserialize(ifs, op.len);
    return true;
}

// string
void serialize(std::ofstream &ofs, const std::string &str) {
    unsigned size = str.size();
    OFS_WRITE(ofs, size);
    if (size > 0) {
        ofs.write(str.c_str(), size);
    }
}

void deserialize(std::ifstream &ifs, std::string &str) {
    unsigned size;
    char *tmp;
    IFS_READ(ifs, size);
    tmp = new char[size + 1];
    if (size > 0) {
        ifs.read(tmp, size);
    }
    tmp[size] = '\0';
    str = tmp;
    delete[] tmp;
}

// ConstantExpr
void serialize(std::ofstream &ofs, ConstantExpr *expr) {

    Expr::Width w = expr->getWidth();
    uint64_t v = expr->getZExtValue(w);

    OFS_WRITE(ofs, w);
    OFS_WRITE(ofs, v);
}

bool deserialize(std::ifstream &ifs, ref<ConstantExpr> &expr) {
    Expr::Width w;
    uint64_t v;
    IFS_READ(ifs, w);
    IFS_READ(ifs, v);

    expr = E_CONST(v, w);
    return true;
}

// NotOptimizedExpr
// void serialize(std::ofstream &ofs, NotOptimizedExpr *expr) {
//     ref<Expr> src = expr->getSrc();
//     return serialize(ofs, src);
// }
//
// bool deserialize(std::ifstream &ifs, ref<NotOptimizedExpr> &expr) {
//     ref<Expr> src;
//     if (deserialize(ifs, src)) {
//         expr = dyn_cast<NotOptimizedExpr>(NotOptimizedExpr::create(src));
//         return true;
//     } else {
//         expr = ref<NotOptimizedExpr>(0);
//         return false;
//     }
// }

// Array
void serialize(std::ofstream &ofs, const ArrayPtr &arr) {
    const std::string rawName = arr->getRawName();
    const std::string name = arr->getName();
    unsigned size = arr->getSize();
    const std::vector<ref<ConstantExpr>> values = arr->getConstantValues();
    void *pointer = (void *)(arr.get());

    if (!isCached(ofs, (void *)pointer)) {
        serialize(ofs, rawName);
        serialize(ofs, name);
        OFS_WRITE(ofs, size);
        serialize(ofs, values);
    }
}

ArrayPtr deserialize_array(std::ifstream &ifs) {
    GET_OBJECT_GID(ifs);

    if (obj == NULL) {
        std::string rawName, name;
        unsigned size;
        std::vector<ref<ConstantExpr>> values;

        deserialize(ifs, rawName);
        deserialize(ifs, name);
        IFS_READ(ifs, size);
        deserialize(ifs, values);

        ArrayPtr ret = Array::create(name, size, &values[0],
                                     &values[values.size()], rawName);
        addObject(id, (void *)(ret.get()));
        return ret;
    } else {
        return ArrayPtr((Array *)obj);
    }
}

// UpdateNode
void serialize(std::ofstream &ofs, const UpdateNodePtr &node, unsigned depth) {
    if (depth == 0) {
        return;
    }

    const UpdateNodePtr next = node->getNext();
    ref<Expr> index = node->getIndex();
    ref<Expr> value = node->getValue();
    // serialize next first, so we can reconstruct in reverse order
    serialize(ofs, next, depth - 1);
    serialize(ofs, index);
    serialize(ofs, value);
}

// UpdateList
void serialize(std::ofstream &ofs, const UpdateListPtr &updates) {
    const ArrayPtr root = updates->getRoot();
    const UpdateNodePtr head = updates->getHead();
    unsigned size = updates->getSize();

    OFS_WRITE(ofs, size);
    serialize(ofs, root);
    serialize(ofs, head, size);
}

UpdateListPtr deserialize_updatelist(std::ifstream &ifs) {
    unsigned size;
    IFS_READ(ifs, size);

    ArrayPtr root = deserialize_array(ifs);
    UpdateListPtr ret = UpdateList::create(root, NULL);
    while (size-- > 0) {
        ref<Expr> index, value;
        deserialize(ifs, index);
        deserialize(ifs, value);
        ret->extend(index, value);
    }
    return ret;
}

// ReadExpr
void serialize(std::ofstream &ofs, ReadExpr *expr) {
    const UpdateListPtr updatelist = expr->getUpdates();
    ref<Expr> index = expr->getIndex();
    serialize(ofs, updatelist);
    serialize(ofs, index);
}

bool deserialize(std::ifstream &ifs, ref<ReadExpr> &expr) {
    UpdateListPtr updatelist = deserialize_updatelist(ifs);
    ref<Expr> index;
    deserialize(ifs, index);

    ref<Expr> tmp = ReadExpr::create(updatelist, index);
    expr = dyn_cast<ReadExpr>(tmp);
    return true;
}

// SelectExpr
void serialize(std::ofstream &ofs, SelectExpr *expr) {
    ref<Expr> cond = expr->getCondition();
    ref<Expr> trueExpr = expr->getTrue();
    ref<Expr> falseExpr = expr->getFalse();

    serialize(ofs, cond);
    serialize(ofs, trueExpr);
    serialize(ofs, falseExpr);
}

bool deserialize(std::ifstream &ifs, ref<SelectExpr> &expr) {
    ref<Expr> cond, trueExpr, falseExpr;
    deserialize(ifs, cond);
    deserialize(ifs, trueExpr);
    deserialize(ifs, falseExpr);

    ref<Expr> tmp = E_ITE(cond, trueExpr, falseExpr);
    expr = dyn_cast<SelectExpr>(tmp);
    return true;
}

// ConcatExpr
void serialize(std::ofstream &ofs, ConcatExpr *expr) {
    ref<Expr> left = expr->getLeft();
    ref<Expr> right = expr->getRight();

    serialize(ofs, left);
    serialize(ofs, right);
}

bool deserialize(std::ifstream &ifs, ref<ConcatExpr> &expr) {
    ref<Expr> left, right;
    deserialize(ifs, left);
    deserialize(ifs, right);

    ref<Expr> tmp = ConcatExpr::create(left, right);
    expr = dyn_cast<ConcatExpr>(tmp);
    return true;
}

// ExtractExpr
void serialize(std::ofstream &ofs, ExtractExpr *expr) {
    ref<Expr> src = expr->getExpr();
    unsigned off = expr->getOffset();
    Expr::Width w = expr->getWidth();

    OFS_WRITE(ofs, off);
    OFS_WRITE(ofs, w);
    serialize(ofs, src);
}

bool deserialize(std::ifstream &ifs, ref<ExtractExpr> &expr) {
    ref<Expr> src;
    unsigned off;
    Expr::Width w;

    IFS_READ(ifs, off);
    IFS_READ(ifs, w);
    deserialize(ifs, src);

    ref<Expr> tmp = E_EXTR(src, off, w);
    expr = dyn_cast<ExtractExpr>(tmp);
    return true;
}

// NotExpr
void serialize(std::ofstream &ofs, NotExpr *expr) {
    ref<Expr> src = expr->getExpr();
    serialize(ofs, src);
}

bool deserialize(std::ifstream &ifs, ref<NotExpr> &expr) {
    ref<Expr> src;
    deserialize(ifs, src);
    ref<Expr> tmp = E_NOT(src);
    expr = dyn_cast<NotExpr>(tmp);
    return true;
}

// Cast: SExt & ZExt
#define CAST_EXPR_SERIALIZE(_class_kind)                                       \
    void serialize(std::ofstream &ofs, _class_kind##Expr *expr) {              \
        ref<Expr> src = expr->getSrc();                                        \
        Expr::Width w = expr->getWidth();                                      \
        OFS_WRITE(ofs, w);                                                     \
        serialize(ofs, src);                                                   \
    }

#define CAST_EXPR_DESERIALIZE(_class_kind)                                     \
    bool deserialize(std::ifstream &ifs, ref<_class_kind##Expr> &expr) {       \
        ref<Expr> src;                                                         \
        Expr::Width w;                                                         \
        IFS_READ(ifs, w);                                                      \
        deserialize(ifs, src);                                                 \
        ref<Expr> tmp = _class_kind##Expr::create(src, w);                     \
        expr = dyn_cast<_class_kind##Expr>(tmp);                               \
        return true;                                                           \
    }
CAST_EXPR_SERIALIZE(SExt)
CAST_EXPR_DESERIALIZE(SExt)
CAST_EXPR_SERIALIZE(ZExt)
CAST_EXPR_DESERIALIZE(ZExt)

// Arithmetic: Add, Sub, Mul, UDiv, SDiv, URem, SRem, And, Or, Xor, Shl, LShr,
// AShr
#define ARITHMETIC_EXPR_SERIALIZE(_class_kind)                                 \
    void serialize(std::ofstream &ofs, _class_kind##Expr *expr) {              \
        ref<Expr> left = expr->getLeft();                                      \
        ref<Expr> right = expr->getRight();                                    \
        serialize(ofs, left);                                                  \
        serialize(ofs, right);                                                 \
    }

#define ARITHMETIC_EXPR_DESERIALIZE(_class_kind)                               \
    bool deserialize(std::ifstream &ifs, ref<_class_kind##Expr> &expr) {       \
        ref<Expr> left, right;                                                 \
        deserialize(ifs, left);                                                \
        deserialize(ifs, right);                                               \
        ref<Expr> tmp = _class_kind##Expr::create(left, right);                \
        expr = dyn_cast<_class_kind##Expr>(tmp);                               \
        return true;                                                           \
    }

#define ARITHMETIC_EXPR_DEF(_class_kind)                                       \
    ARITHMETIC_EXPR_SERIALIZE(_class_kind)                                     \
    ARITHMETIC_EXPR_DESERIALIZE(_class_kind)

ARITHMETIC_EXPR_DEF(Add)
ARITHMETIC_EXPR_DEF(Sub)
ARITHMETIC_EXPR_DEF(Mul)
ARITHMETIC_EXPR_DEF(UDiv)
ARITHMETIC_EXPR_DEF(SDiv)
ARITHMETIC_EXPR_DEF(URem)
ARITHMETIC_EXPR_DEF(SRem)
ARITHMETIC_EXPR_DEF(And)
ARITHMETIC_EXPR_DEF(Or)
ARITHMETIC_EXPR_DEF(Xor)
ARITHMETIC_EXPR_DEF(Shl)
ARITHMETIC_EXPR_DEF(LShr)
ARITHMETIC_EXPR_DEF(AShr)

// Compare: Eq, Ne, Ult, Ule, Ugt, Uge, Slt, Sle, Sgt, Sge
// #define COMPARISON_EXPR_SERIALIZE(_class_kind)	\
// void serialize(std::ofstream & ofs, _class_kind##Expr * expr) {  \
//
// }
//
// #define COMPARISON_EXPR_DESERIALIZE(_class_kind)  \
// bool deserialize(std::ifstream & ifs, ref<_class_kind##Expr> & expr) {	\
// 	return true;	\
// }
//
// #define COMPARISON_EXPR_DEF(_class_kind)	\
// COMPARISON_EXPR_SERIALIZE(_class_kind)	\
// COMPARISON_EXPR_DESERIALIZE(_class_kind)
#define COMPARISON_EXPR_DEF(_class_kind) ARITHMETIC_EXPR_DEF(_class_kind)
COMPARISON_EXPR_DEF(Eq)
COMPARISON_EXPR_DEF(Ne)
COMPARISON_EXPR_DEF(Ult)
COMPARISON_EXPR_DEF(Ule)
COMPARISON_EXPR_DEF(Ugt)
COMPARISON_EXPR_DEF(Uge)
COMPARISON_EXPR_DEF(Slt)
COMPARISON_EXPR_DEF(Sle)
COMPARISON_EXPR_DEF(Sgt)
COMPARISON_EXPR_DEF(Sge)

#define EXPR_SERIALIZE_CASE(_class_kind)                                       \
    case Expr::Kind::_class_kind:                                              \
        serialize(ofs, dyn_cast<_class_kind##Expr>(expr));                     \
        break;

// Expr
void serialize(std::ofstream &ofs, const ref<Expr> &expr) {
    void *ptr = (void *)expr.get();
    if (isCached(ofs, ptr)) {
        return;
    }

    const bool isNull = expr.isNull();
    OFS_WRITE(ofs, isNull);
    if (isNull) {
        return;
    }

    Expr::Kind kind = expr->getKind();
    auto v = static_cast<int>(kind);
    OFS_WRITE(ofs, v);

    switch (kind) {
    case Expr::Kind::InvalidKind:
        break;
        EXPR_SERIALIZE_CASE(Constant)
        // EXPR_SERIALIZE_CASE(NotOptimized)
        EXPR_SERIALIZE_CASE(Read)
        EXPR_SERIALIZE_CASE(Select)
        EXPR_SERIALIZE_CASE(Concat)
        EXPR_SERIALIZE_CASE(Extract)
        EXPR_SERIALIZE_CASE(Not)
        EXPR_SERIALIZE_CASE(ZExt)
        EXPR_SERIALIZE_CASE(SExt)
        EXPR_SERIALIZE_CASE(Add)
        EXPR_SERIALIZE_CASE(Sub)
        EXPR_SERIALIZE_CASE(Mul)
        EXPR_SERIALIZE_CASE(UDiv)
        EXPR_SERIALIZE_CASE(SDiv)
        EXPR_SERIALIZE_CASE(URem)
        EXPR_SERIALIZE_CASE(SRem)
        EXPR_SERIALIZE_CASE(And)
        EXPR_SERIALIZE_CASE(Or)
        EXPR_SERIALIZE_CASE(Xor)
        EXPR_SERIALIZE_CASE(Shl)
        EXPR_SERIALIZE_CASE(LShr)
        EXPR_SERIALIZE_CASE(AShr)
        EXPR_SERIALIZE_CASE(Eq)
        EXPR_SERIALIZE_CASE(Ne)
        EXPR_SERIALIZE_CASE(Ult)
        EXPR_SERIALIZE_CASE(Ule)
        EXPR_SERIALIZE_CASE(Ugt)
        EXPR_SERIALIZE_CASE(Uge)
        EXPR_SERIALIZE_CASE(Slt)
        EXPR_SERIALIZE_CASE(Sle)
        EXPR_SERIALIZE_CASE(Sgt)
        EXPR_SERIALIZE_CASE(Sge)
    default:
        g_s2e->getWarningsStream() << "Unknown Expr!\n";
        break;
    }
}

// Template for dispatching
template <typename T>
bool inline Deserialize(std::ifstream &ifs, GUID id, ref<Expr> &expr) {
    ref<T> tmp;
    bool res = deserialize(ifs, tmp);
    expr = tmp;
    addObject(id, (void *)(expr.get()));
    return res;
}

#define EXPR_DESERIALIZE_CASE(_class_kind)                                     \
    case Expr::Kind::_class_kind:                                              \
        return Deserialize<_class_kind##Expr>(ifs, id, expr);

bool deserialize(std::ifstream &ifs, ref<Expr> &expr) {
    GET_OBJECT_GID(ifs);
    if (obj != NULL) {
        expr = ref<Expr>((Expr *)obj);
        return true;
    }

    bool isNull;
    IFS_READ(ifs, isNull);
    if (isNull) {
        expr = ref<Expr>(0);
        return true;
    }

    int v;
    IFS_READ(ifs, v);
    Expr::Kind kind = static_cast<Expr::Kind>(v);

    switch (kind) {
    case Expr::Kind::InvalidKind:
        break;
        EXPR_DESERIALIZE_CASE(Constant)
        // EXPR_DESERIALIZE_CASE(NotOptimized)
        EXPR_DESERIALIZE_CASE(Read)
        EXPR_DESERIALIZE_CASE(Select)
        EXPR_DESERIALIZE_CASE(Concat)
        EXPR_DESERIALIZE_CASE(Extract)
        EXPR_DESERIALIZE_CASE(Not)
        EXPR_DESERIALIZE_CASE(ZExt)
        EXPR_DESERIALIZE_CASE(SExt)
        EXPR_DESERIALIZE_CASE(Add)
        EXPR_DESERIALIZE_CASE(Sub)
        EXPR_DESERIALIZE_CASE(Mul)
        EXPR_DESERIALIZE_CASE(UDiv)
        EXPR_DESERIALIZE_CASE(SDiv)
        EXPR_DESERIALIZE_CASE(URem)
        EXPR_DESERIALIZE_CASE(SRem)
        EXPR_DESERIALIZE_CASE(And)
        EXPR_DESERIALIZE_CASE(Or)
        EXPR_DESERIALIZE_CASE(Xor)
        EXPR_DESERIALIZE_CASE(Shl)
        EXPR_DESERIALIZE_CASE(LShr)
        EXPR_DESERIALIZE_CASE(AShr)
        EXPR_DESERIALIZE_CASE(Eq)
        EXPR_DESERIALIZE_CASE(Ne)
        EXPR_DESERIALIZE_CASE(Ult)
        EXPR_DESERIALIZE_CASE(Ule)
        EXPR_DESERIALIZE_CASE(Ugt)
        EXPR_DESERIALIZE_CASE(Uge)
        EXPR_DESERIALIZE_CASE(Slt)
        EXPR_DESERIALIZE_CASE(Sle)
        EXPR_DESERIALIZE_CASE(Sgt)
        EXPR_DESERIALIZE_CASE(Sge)
    default:
        g_s2e->getWarningsStream() << "Unknown Expr!\n";
        break;
    }
    return false;
}

// ConstraintManager
void serialize(std::ofstream &ofs, ConstraintManager &manager) {
    size_t size = manager.size();
    size_t index = 0;
    OFS_WRITE(ofs, size);
    for (auto &c : manager) {
#ifdef DEBUG_SERIALIZER
        g_s2e->getDebugStream()
            << std::to_string(index) << "/" << std::to_string(size) << "\n";
        g_s2e->getDebugStream() << "Serialize: " << c << "\n";
#endif
        index++;
        serialize(ofs, c);
    }
}

bool deserialize(std::ifstream &ifs, ConstraintManager &manager) {
    size_t size;
    IFS_READ(ifs, size);
    if (ifs) {
        for (size_t i = 0; i < size; i++) {
            ref<Expr> expr;
            deserialize(ifs, expr);
            manager.addConstraint(expr);
        }
        return true;
    }
    return false;
}

// Guard
void serialize(std::ofstream &ofs, Guard *guard) {
    serialize(ofs, guard->value);
    serialize(ofs, guard->expcount);
    OFS_WRITE(ofs, guard->concrete);
    OFS_WRITE(ofs, guard->diff);
}

bool deserialize(std::ifstream &ifs, Guard &guard) {
    deserialize(ifs, guard.value);
    deserialize(ifs, guard.expcount);
    IFS_READ(ifs, guard.concrete);
    IFS_READ(ifs, guard.diff);
    return true;
}

// Signature
void serialize(std::ofstream &ofs, Signature &sig) {
    OFS_WRITE(ofs, sig.src);
    OFS_WRITE(ofs, sig.dst);
    OFS_WRITE(ofs, sig.len);
}

bool deserialize(std::ifstream &ifs, Signature &sig) {
    IFS_READ(ifs, sig.src);
    IFS_READ(ifs, sig.dst);
    IFS_READ(ifs, sig.len);
    return true;
}

// Spot
void serialize(std::ofstream &ofs, Spot &spot) {
    OFS_WRITE(ofs, spot.type);
    serialize(ofs, spot.sig);
}

bool deserialize(std::ifstream &ifs, Spot &spot) {
    IFS_READ(ifs, spot.type);
    deserialize(ifs, spot.sig);
    return true;
}

template <typename K, typename V>
void serialize(std::ofstream &ofs, std::map<K, V> &objs) {
    unsigned size = objs.size();
    OFS_WRITE(ofs, size);
    for (auto it : objs) {
        serialize(ofs, it.first);
        serialize(ofs, it.second);
    }
}

template <typename K, typename V>
void deserialize(std::ifstream &ifs, std::map<K, V> &objs) {
    unsigned size;
    IFS_READ(ifs, size);
    for (unsigned i = 0; i < size; i++) {
        K key;
        V value;
        deserialize(ifs, key);
        deserialize(ifs, value);
        objs.insert({key, value});
    }
}

void deserialize(std::ifstream &ifs,
                 std::map<std::string, const ArrayPtr> &objs) {
    unsigned size;
    IFS_READ(ifs, size);
    for (unsigned i = 0; i < size; i++) {
        std::string key;
        deserialize(ifs, key);
        ArrayPtr value = deserialize_array(ifs);
        objs.insert({key, value});
    }
}

void deserialize(std::ifstream &ifs,
                 std::map<ArrayPtr, std::vector<unsigned char>> &bindings_ty) {
    unsigned size;
    IFS_READ(ifs, size);
    for (unsigned i = 0; i < size; i++) {
        std::vector<unsigned char> val;
        ArrayPtr key = deserialize_array(ifs);
        deserialize(ifs, val);
        bindings_ty.insert({key, val});
    }
}

// GuardTable
void deserialize(std::ifstream &ifs, GuardTable &table) {
    unsigned size;
    IFS_READ(ifs, size);
    for (unsigned i = 0; i < size; i++) {
        uint64_t pc;
        IFS_READ(ifs, pc);
        Guard *guard = new Guard();
        deserialize(ifs, *guard);
        table.insert({pc, guard});
    }
}

void serialize(std::ofstream &ofs, klee::Assignment::bindings_ty &bindings) {
    unsigned size = bindings.size();
    OFS_WRITE(ofs, size);
    for (auto it : bindings) {
        serialize(ofs, it.first);
        serialize(ofs, it.second);
    }
}

// Assignment
void serialize(std::ofstream &ofs, Assignment *assignment) {
    serialize(ofs, assignment->bindings);
}

Assignment *deserialize_assignment(std::ifstream &ifs) {
    std::map<ArrayPtr, std::vector<unsigned char>> bindings_ty;
    deserialize(ifs, bindings_ty);

    Assignment *assign = new Assignment();
    for (auto it : bindings_ty) {
        assign->add(it.first, it.second);
    }
    return assign;
}

// Capability
void serialize(std::ofstream &ofs, Capability &cap) {
    g_s2e->getDebugStream() << "Serializing constraintManager...\n";
    serialize(ofs, cap.constraints);
    g_s2e->getDebugStream() << "Serializing arguments...\n";
    serialize(ofs, cap.symbols);
    // FIXME: only save those used array
    g_s2e->getDebugStream() << "Serializing assignment...\n";
    serialize(ofs, cap.assignment);
    OFS_WRITE(ofs, cap.vuln.symbolic);
    serialize(ofs, cap.vuln.allocator);
    OFS_WRITE(ofs, cap.vuln.vul_base);
    OFS_WRITE(ofs, cap.vuln.width);
    serialize(ofs, cap.vuln.sym_width);
    serialize(ofs, cap.ops);
    serialize(ofs, cap.loopguards);
    serialize(ofs, cap.guardtable);
    serialize(ofs, cap.spots);
}

bool deserialize(std::ifstream &ifs, Capability &cap) {
    deserialize(ifs, cap.constraints);
    deserialize(ifs, cap.symbols);
    cap.assignment = deserialize_assignment(ifs);
    IFS_READ(ifs, cap.vuln.symbolic);
    deserialize(ifs, cap.vuln.allocator);
    IFS_READ(ifs, cap.vuln.vul_base);
    IFS_READ(ifs, cap.vuln.width);
    deserialize(ifs, cap.vuln.sym_width);
    deserialize(ifs, cap.ops);
    deserialize(ifs, cap.loopguards);
    deserialize(ifs, cap.guardtable);
    deserialize(ifs, cap.spots);
    return true;
}

// Capability Summary for fuzzing
void serialize(std::ofstream &ofs, SymbolValue &value) {
    OFS_WRITE(ofs, value.min);
    OFS_WRITE(ofs, value.max);
    OFS_WRITE(ofs, value.value);
}

bool deserialize(std::ifstream &ifs, SymbolValue &value) {
    IFS_READ(ifs, value.min);
    IFS_READ(ifs, value.max);
    IFS_READ(ifs, value.value);
    return true;
}

void serialize(std::ofstream &ofs, Summary &sum) {
    serialize(ofs, sum.offset);
    serialize(ofs, sum.length);
    serialize(ofs, sum.values);
}

bool deserialize(std::ifstream &ifs, Summary &sum) {
    deserialize(ifs, sum.offset);
    deserialize(ifs, sum.length);
    deserialize(ifs, sum.values);
    return true;
}

void serialize(std::ofstream &ofs, CapSummary &caps) {
    unsigned size = caps.size();
    OFS_WRITE(ofs, size);
    for (auto each : caps) {
        OFS_WRITE(ofs, each.first);
        serialize(ofs, each.second);
    }
}

bool deserialize(std::ifstream &ifs, CapSummary &caps) {
    unsigned size;
    IFS_READ(ifs, size);
    for (unsigned i = 0; i < size; i++) {
        uint64_t pc;
        std::vector<Summary> summaries;
        IFS_READ(ifs, pc);
        deserialize(ifs, summaries);
        caps.insert({pc, summaries});
    }
    return true;
}

void serialize(std::ofstream &ofs, CapSummary &caps,
               std::map<uint64_t, Spot> &spots) {
    serialize(ofs, caps);
    serialize(ofs, spots);
}

bool deserialize(std::ifstream &ifs, CapSummary &caps,
                 std::map<uint64_t, Spot> &spots) {
    deserialize(ifs, caps);
    deserialize(ifs, spots);
    return true;
}

} // namespace plugins
} // namespace s2e
