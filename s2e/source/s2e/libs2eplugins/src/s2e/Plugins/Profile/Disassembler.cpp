#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <klee/util/ExprTemplates.h>

#include <capstone/capstone.h>
#include <string>

#include "Disassembler.h"
#include "util.h"

using namespace klee;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(Disassembler, "Helper to disassemble binary code",
                  "Disassembler",
                  // Dependencies
);

void Disassembler::initialize() {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &m_handler) != CS_ERR_OK) {
        getDebugStream() << "Fail to init capstone"
                         << "\n";
        exit(-1);
    }
    m_insn = cs_malloc(m_handler);
}

const std::map<unsigned, Disassembler::reg> Disassembler::registerMap = {
    // 8 bits
    {X86_REG_AL, {CPU_OFFSET(regs[R_EAX]), 8, "al"}},
    {X86_REG_BL, {CPU_OFFSET(regs[R_EBX]), 8, "bl"}},
    {X86_REG_CL, {CPU_OFFSET(regs[R_ECX]), 8, "cl"}},
    {X86_REG_DL, {CPU_OFFSET(regs[R_EDX]), 8, "dl"}},
    {X86_REG_SIL, {CPU_OFFSET(regs[R_ESI]), 8, "sil"}},
    {X86_REG_DIL, {CPU_OFFSET(regs[R_EDI]), 8, "dil"}},
    {X86_REG_BPL, {CPU_OFFSET(regs[R_EBP]), 8, "bpl"}},
    {X86_REG_SPL, {CPU_OFFSET(regs[R_ESP]), 8, "spl"}},
    {X86_REG_R8B, {CPU_OFFSET(regs[8]), 8, "r8b"}},
    {X86_REG_R9B, {CPU_OFFSET(regs[9]), 8, "r9b"}},
    {X86_REG_R10B, {CPU_OFFSET(regs[10]), 8, "r10b"}},
    {X86_REG_R11B, {CPU_OFFSET(regs[11]), 8, "r11b"}},
    {X86_REG_R12B, {CPU_OFFSET(regs[12]), 8, "r12b"}},
    {X86_REG_R13B, {CPU_OFFSET(regs[13]), 8, "r13b"}},
    {X86_REG_R14B, {CPU_OFFSET(regs[14]), 8, "r14b"}},
    {X86_REG_R15B, {CPU_OFFSET(regs[15]), 8, "r15b"}},
    // 16 bits
    {X86_REG_AX, {CPU_OFFSET(regs[R_EAX]), 16, "ax"}},
    {X86_REG_BX, {CPU_OFFSET(regs[R_EBX]), 16, "bx"}},
    {X86_REG_CX, {CPU_OFFSET(regs[R_ECX]), 16, "cx"}},
    {X86_REG_DX, {CPU_OFFSET(regs[R_EDX]), 16, "dx"}},
    {X86_REG_SI, {CPU_OFFSET(regs[R_ESI]), 16, "si"}},
    {X86_REG_DI, {CPU_OFFSET(regs[R_EDI]), 16, "di"}},
    {X86_REG_BP, {CPU_OFFSET(regs[R_EBP]), 16, "bp"}},
    {X86_REG_SP, {CPU_OFFSET(regs[R_ESP]), 16, "sp"}},
    {X86_REG_R8W, {CPU_OFFSET(regs[8]), 16, "r8w"}},
    {X86_REG_R9W, {CPU_OFFSET(regs[9]), 16, "r9w"}},
    {X86_REG_R10W, {CPU_OFFSET(regs[10]), 16, "r10w"}},
    {X86_REG_R11W, {CPU_OFFSET(regs[11]), 16, "r11w"}},
    {X86_REG_R12W, {CPU_OFFSET(regs[12]), 16, "r12w"}},
    {X86_REG_R13W, {CPU_OFFSET(regs[13]), 16, "r13w"}},
    {X86_REG_R14W, {CPU_OFFSET(regs[14]), 16, "r14w"}},
    {X86_REG_R15W, {CPU_OFFSET(regs[15]), 16, "r15w"}},
   // 32 bits
    {X86_REG_EAX, {CPU_OFFSET(regs[R_EAX]), 32, "eax"}},
    {X86_REG_EBX, {CPU_OFFSET(regs[R_EBX]), 32, "ebx"}},
    {X86_REG_ECX, {CPU_OFFSET(regs[R_ECX]), 32, "ecx"}},
    {X86_REG_EDX, {CPU_OFFSET(regs[R_EDX]), 32, "edx"}},
    {X86_REG_ESI, {CPU_OFFSET(regs[R_ESI]), 32, "esi"}},
    {X86_REG_EDI, {CPU_OFFSET(regs[R_EDI]), 32, "edi"}},
    {X86_REG_EBP, {CPU_OFFSET(regs[R_EBP]), 32, "ebp"}},
    {X86_REG_ESP, {CPU_OFFSET(regs[R_ESP]), 32, "esp"}},
    {X86_REG_EIP, {CPU_OFFSET(eip), 32, "eip"}},
    {X86_REG_R8D, {CPU_OFFSET(regs[8]), 32, "r8d"}},
    {X86_REG_R9D, {CPU_OFFSET(regs[9]), 32, "r9d"}},
    {X86_REG_R10D, {CPU_OFFSET(regs[10]), 32, "r10d"}},
    {X86_REG_R11D, {CPU_OFFSET(regs[11]), 32, "r11d"}},
    {X86_REG_R12D, {CPU_OFFSET(regs[12]), 32, "r12d"}},
    {X86_REG_R13D, {CPU_OFFSET(regs[13]), 32, "r13d"}},
    {X86_REG_R14D, {CPU_OFFSET(regs[14]), 32, "r14d"}},
    {X86_REG_R15D, {CPU_OFFSET(regs[15]), 32, "r15d"}},
    // 64 bits
    {X86_REG_RAX, {CPU_OFFSET(regs[R_EAX]), 64, "rax"}},
    {X86_REG_RBX, {CPU_OFFSET(regs[R_EBX]), 64, "rbx"}},
    {X86_REG_RCX, {CPU_OFFSET(regs[R_ECX]), 64, "rcx"}},
    {X86_REG_RDX, {CPU_OFFSET(regs[R_EDX]), 64, "rdx"}},
    {X86_REG_RSI, {CPU_OFFSET(regs[R_ESI]), 64, "rsi"}},
    {X86_REG_RDI, {CPU_OFFSET(regs[R_EDI]), 64, "rdi"}},
    {X86_REG_RBP, {CPU_OFFSET(regs[R_EBP]), 64, "rbp"}},
    {X86_REG_RSP, {CPU_OFFSET(regs[R_ESP]), 64, "rsp"}},
    {X86_REG_RIP, {CPU_OFFSET(eip), 64, "rip"}},
    {X86_REG_R8, {CPU_OFFSET(regs[8]), 64, "r8"}},
    {X86_REG_R9, {CPU_OFFSET(regs[9]), 64, "r9"}},
    {X86_REG_R10, {CPU_OFFSET(regs[10]), 64, "r10"}},
    {X86_REG_R11, {CPU_OFFSET(regs[11]), 64, "r11"}},
    {X86_REG_R12, {CPU_OFFSET(regs[12]), 64, "r12"}},
    {X86_REG_R13, {CPU_OFFSET(regs[13]), 64, "r13"}},
    {X86_REG_R14, {CPU_OFFSET(regs[14]), 64, "r14"}},
    {X86_REG_R15, {CPU_OFFSET(regs[15]), 64, "r15"}},
};

std::map<std::string, INS_ARITH_TYPE> Disassembler::instructionMap = {
    {"add", INS_ARITH_ADD}, {"xor", INS_ARITH_XOR},  {"sub", INS_ARITH_SUB},
    {"shl", INS_ARITH_SHL}, {"sar", INS_ARITH_ASHR}, {"shr", INS_ARITH_LSHR},
    {"or", INS_ARITH_OR},   {"and", INS_ARITH_AND},  {"dec", INS_ARITH_DEC}};

Disassembler::~Disassembler() {
    cs_free(m_insn, 1);
    cs_close(&m_handler);
}

/*
 * caller is responsible for releasing the memory
 */
cs_insn *Disassembler::getInst(S2EExecutionState *state, uint64_t pc,
                               bool detailed) {
    // Maximum size of a instruction
    // TODO: add fallback mechainsm
    size_t size = 16;
    uint8_t buffer[16];
    const uint8_t *code = reinterpret_cast<const uint8_t *>(buffer);
    bool ok = state->mem()->read(pc, buffer, size);
    if (!ok) {
        g_s2e->getWarningsStream(state) << "Failed to read memory at " << hexval(pc) << "\n";
        return NULL;
    }

    if (detailed) {
        // It's the caller's responsibility to release the memory.
        cs_option(m_handler, CS_OPT_DETAIL, CS_OPT_ON);
        cs_insn *all_insn;
        size_t count = cs_disasm(m_handler, code, size, pc, 1, &all_insn);
        cs_option(m_handler, CS_OPT_DETAIL, CS_OPT_OFF);
        if (count == 0)
            return NULL;
        return &all_insn[0];
    } else {
        // We use local memory, no extra allocation.
        if (cs_disasm_iter(m_handler, &code, &size, &pc, m_insn)) {
            return m_insn;
        }
    }
    return NULL; // Probably custom instruction
}

bool Disassembler::getDetail(S2EExecutionState *state, uint64_t pc,
                             DetailCallback callback, bool *error,
                             bool detailed) {
    cs_insn *insn = getInst(state, pc, detailed);
    if (insn == NULL) {
        *error = true;
        return false;
    }
    *error = false;

    bool result = callback(state, pc, m_handler, insn); // not gonna return here
    if (detailed) {
        freeInstruction(insn);
    }
    return result;
}

// All registers
// rax eax ax al
// rbx ebx bx bl
// rcx ecx cx cl
// rdx edx dx dl
// rsi esi si sil
// rdi edi di dil
// rbp ebp bp bpl
// rsp esp sp spl
// r8  r8d r8w r8b
// r9  r9d r9w r9b
// ...
// r15 r15d r15w r15b

// always return expression with size of target_ulong
ref<Expr> Disassembler::getMemAddr(S2EExecutionState *state, cs_x86_op *op) {
    assert(op->type == X86_OP_MEM);
    ref<Expr> result = E_CONST(0, sizeof(target_ulong) * CHAR_BIT);
    unsigned size, offset;
    if (op->mem.base != X86_REG_INVALID) {
        offset = getRegOffset(op->mem.base, size);
        assert(offset != (unsigned)-1);
        result = state->regs()->read(offset, size);
    }
    if (op->mem.index != X86_REG_INVALID) {
        offset = getRegOffset(op->mem.index, size);
        assert(offset != (unsigned)-1);
        if (op->mem.scale == 1) {
            result = AddExpr::create(result, state->regs()->read(offset, size));
        } else {
            result = AddExpr::create(
                result, MulExpr::create(state->regs()->read(offset, size),
                                        E_CONST(op->mem.scale, size)));
        }
    }
    if (op->mem.disp != 0) {
        result = AddExpr::create(
            alignExpr(result, sizeof(target_ulong) * CHAR_BIT),
            E_CONST(op->mem.disp, sizeof(target_ullong) * CHAR_BIT));
    } else {
        result = alignExpr(result, sizeof(target_ulong) * CHAR_BIT);
    }
    return result;
}

ref<Expr> Disassembler::readOperand(S2EExecutionState *state, cs_x86_op *op) {
    ref<Expr> result;
    unsigned size, offset;
    target_ulong addr;
    switch (op->type) {
    case X86_OP_MEM:
        result = getMemAddr(state, op);
        addr = readExpr<target_ulong>(state, result);
        result = state->mem()->read(addr, op->size * 8);
        break;
    case X86_OP_REG:
        offset = getRegOffset(op->reg, size);
        assert(offset != (unsigned)-1);
        result = state->regs()->read(offset, op->size * 8);
        break;
    case X86_OP_IMM:
        // exp: adc r15d, -1 (4 bytes)
        result = E_CONST(bits64::truncateToNBits(op->imm, op->size * 8), op->size * 8);
        break;
    default:
        assert(false && "Unknown type of operand");
        break;
    }
    return result;
}

uint64_t Disassembler::readConcreteOperand(S2EExecutionState *state,
                                           cs_x86_op *op) {
    unsigned size, offset;
    uint64_t result, addr;
    switch (op->type) {
    case X86_OP_MEM:
        addr = getConcreteMemAddr(state, op);
        if (!state->mem()->read(addr, &result, op->size)) {
            return -1;
        }
        return result;
    case X86_OP_REG:
        offset = getRegOffset(op->reg, size);
        if (!state->regs()->read(offset, &result, op->size)) {
            return -1;
        }
        return result;
    case X86_OP_IMM:
        return op->imm;
    default:
        assert(false && "Unknown type of operand");
        break;
    }
}

bool Disassembler::writeConcreteOperand(S2EExecutionState *state, cs_x86_op *op, uint64_t value) {
    unsigned offset, size;
    target_ulong addr;
    switch (op->type) {
    case X86_OP_MEM:
        addr = getConcreteMemAddr(state, op);
        if (!state->mem()->write(addr, &value, op->size)) {
            return false;
        }
        break;
    case X86_OP_REG:
        offset = getRegOffset(op->reg, size);
#ifdef DISASSEMBLER_DEBUG
        g_s2e->getDebugStream(state) << "concretize " << cs_reg_name(m_handler, op->reg) << " at offset " << offset << "\n";
#endif
        if (!state->regs()->write(offset, &value, op->size)) {
            return false;
        }
        break;
    case X86_OP_IMM:
    default:
        break;
    }
    return true;
}

bool Disassembler::writeOperand(S2EExecutionState *state, cs_x86_op *op, ref<Expr> &expr) {
    state->jumpToSymbolicCpp();

    unsigned offset, size;
    target_ulong addr;
    switch (op->type) {
    case X86_OP_MEM:
        addr = getConcreteMemAddr(state, op);
        if (!state->mem()->write(addr, expr)) {
            g_s2e->getDebugStream(state) << "Failed to write symbolic value to " << hexval(addr) << "\n";
            return false;
        }
        break;
    case X86_OP_REG:
        offset = getRegOffset(op->reg, size);
        if (!state->regs()->write(offset, expr)) {
            g_s2e->getDebugStream(state) << "Failed to write symbolic value to  reg " << offset << "\n";
            return false;
        }
        break;
    case X86_OP_IMM:
    default:
        break;
    }
    return true;
}

INS_GROUP Disassembler::getInsGroup(S2EExecutionState *state, uint64_t pc) {
    INS_GROUP ret;
    cs_insn *insn = getInst(state, pc, false);
    if (!strcmp(insn->mnemonic, "mov")) {
        ret = INS_GROUP_MOV;
    } else if (instructionMap.find(insn->mnemonic) != instructionMap.end()) {
        ret = INS_GROUP_ARITH;
    } else {
        ret = INS_GROUP_UNKNOWN;
    }
    return ret;
}

INS_ARITH_TYPE Disassembler::getInsType(S2EExecutionState *state, uint64_t pc) {
    cs_insn *insn = getInst(state, pc, false);
    auto it = instructionMap.find(insn->mnemonic);
    if (it != instructionMap.end()) {
        return it->second;
    }
    return INS_ARITH_INVALID;
}

void Disassembler::doBsr(S2EExecutionState *state, uint64_t pc) {
#ifdef DISASSEMBLER_DEBUG
    g_s2e->getDebugStream(state) << "handle bsr at " << hexval(pc) << "\n";
#endif

    cs_insn *insn = getInst(state, pc, true);
    if (insn == NULL) return;

    cs_detail *detail = insn->detail;
    cs_x86_op *src_op = &(detail->x86.operands[1]);
    ref<Expr> src = readOperand(state, src_op);
    if (isa<ConstantExpr>(src)) {
        freeInstruction(insn);
        return;
    }
    
    const ref<Expr> OneBitExpr = E_CONST(1, Expr::Bool);
    const unsigned width = src_op->size * 8;
    ref<Expr> retExpr = E_CONST(width, width);
    for (unsigned nr = 0; nr < width; nr++) {
        ref<Expr> bitExpr = E_EXTR(src, nr, 1);
        retExpr = E_ITE(E_EQ(bitExpr, OneBitExpr), E_CONST(nr, width), retExpr);
    }
    // FIXME: set zflag
    bool succeed = writeOperand(state, &(detail->x86.operands[0]), retExpr);

    freeInstruction(insn);
    if (succeed) {
        skipInstruction(state, pc);
    }
    return;
}

void Disassembler::doBsf(S2EExecutionState *state, uint64_t pc) {
#ifdef DISASSEMBLER_DEBUG
    g_s2e->getDebugStream(state) << "handle bsf at " << hexval(pc) << "\n";
#endif
    
    cs_insn *insn = getInst(state, pc, true);
    if (insn == NULL) return;

    cs_detail *detail = insn->detail;
    cs_x86_op *src_op = &(detail->x86.operands[1]);
    ref<Expr> src = readOperand(state, src_op);
    if (isa<ConstantExpr>(src)) {
        freeInstruction(insn);
        return;
    }

    const ref<Expr> OneBitExpr = E_CONST(1, Expr::Bool);
    const unsigned width = src_op->size * 8;
    ref<Expr> retExpr = E_CONST(width, width);
    for (unsigned nr = width - 1; nr-- > 0; ) {
        ref<Expr> bitExpr = E_EXTR(src, nr, 1);
        retExpr = E_ITE(E_EQ(bitExpr, OneBitExpr), E_CONST(nr, width), retExpr);
    }
    // FIXME: set zflag
    bool succeed = writeOperand(state, &(detail->x86.operands[0]), retExpr);

    freeInstruction(insn);
    if (succeed) {
        skipInstruction(state, pc);
    }
    return;
}

void Disassembler::concretize(S2EExecutionState *state, uint64_t pc) {
    cs_insn *insn = getInst(state, pc, true);
    if (insn == NULL) return;

#ifdef DISASSEMBLER_DEBUG
    g_s2e->getDebugStream(state) << "concretize instruction at " << hexval(pc) << " with " << insn->op_str << "\n";
#endif

    cs_detail *detail = insn->detail;
    for (unsigned i = 0; i < detail->x86.op_count; i++) {
        cs_x86_op *src = &(detail->x86.operands[i]);
        ref<Expr> val = readOperand(state, src);
        getDebugStream(state) << "Value : " << val << "\n";
        if (!isa<ConstantExpr>(val)) {
            g_s2e->getDebugStream(state) << "not a constant\n";
            uint64_t concrete_val = readExpr<uint64_t>(state, val);
            writeConcreteOperand(state, src, concrete_val);
        }
    }

    freeInstruction(insn);
    return;
}

} // namespace plugins
} // namespace s2e
