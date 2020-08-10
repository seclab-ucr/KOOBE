#ifndef S2E_PLUGINS_DISASSEMBLER_H
#define S2E_PLUGINS_DISASSEMBLER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutor.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutionStateRegisters.h>
#include <s2e/cpu.h>

#include <capstone/capstone.h>

#include "util.h"

namespace s2e {
namespace plugins {

#define NONE_MEMORY 0
#define READ_MEMORY 1
#define WRITE_MEMORY 2
#define UNKNOWN_MEMORY 4

enum INS_GROUP { INS_GROUP_MOV, INS_GROUP_ARITH, INS_GROUP_UNKNOWN };

enum INS_ARITH_TYPE {
    INS_ARITH_INVALID,
    INS_ARITH_ADD,
    INS_ARITH_AND,
    INS_ARITH_XOR,
    INS_ARITH_OR,
    INS_ARITH_SUB,
    INS_ARITH_SHL,
    INS_ARITH_LSHR,
    INS_ARITH_ASHR,
    INS_ARITH_MUL,
    INS_ARITH_SDIV,
    INS_ARITH_UDIV,
    INS_ARITH_UREM,
    INS_ARITH_SREM,
    INS_ARITH_DEC,
};

typedef bool (*DetailCallback)(S2EExecutionState *, uint64_t, csh &, cs_insn *);

class Disassembler : public Plugin {
    S2E_PLUGIN

  public:
    Disassembler(S2E *s2e) : Plugin(s2e) {}
    ~Disassembler();

    void initialize();

  private:
    csh m_handler;
    cs_insn *m_insn; // reduce redundant allocation

    typedef struct reg {
        unsigned offset, size;
        std::string name;
    } reg;

    static const std::map<unsigned, reg> registerMap;
    static std::map<std::string, INS_ARITH_TYPE> instructionMap;

  public:
    cs_insn *getInst(S2EExecutionState *state, uint64_t pc,
                     bool detailed = false);
    bool getDetail(S2EExecutionState *state, uint64_t pc,
                   DetailCallback callback, bool *error, bool detailed = true);
    inline void freeInstruction(cs_insn* all_insn, size_t count = 1) {
        cs_option(m_handler, CS_OPT_DETAIL, CS_OPT_OFF);
        if (all_insn != NULL) cs_free(all_insn, count);
    }

    klee::ref<klee::Expr> readOperand(S2EExecutionState *state, cs_x86_op *op);
    inline klee::ref<klee::Expr> readOperand(S2EExecutionState *state, uint64_t pc, unsigned index) {
        cs_insn *insn = getInst(state, pc, true);
        if (insn == NULL) exit(1);
        cs_detail *detail = insn->detail;
        assert(detail && "Failed to disassemble");
        assert(detail->x86.op_count > index);
        cs_x86_op op = detail->x86.operands[index];
        auto ret = readOperand(state, &op);
        freeInstruction(insn);
        return ret;
    }

    uint64_t readConcreteOperand(S2EExecutionState *state, cs_x86_op *op);
    bool writeOperand(S2EExecutionState *state, cs_x86_op *op, klee::ref<klee::Expr> &expr);
    bool writeConcreteOperand(S2EExecutionState *state, cs_x86_op *op, uint64_t value);
    klee::ref<klee::Expr> getMemAddr(S2EExecutionState *state, cs_x86_op *op);
    inline target_ulong getConcreteMemAddr(S2EExecutionState *state, cs_x86_op *op) {
        klee::ref<klee::Expr> res = getMemAddr(state, op);
        return readExpr<target_ulong>(state, res);
    }


    INS_GROUP getInsGroup(S2EExecutionState *state, uint64_t pc);
    INS_ARITH_TYPE getInsType(S2EExecutionState *state, uint64_t pc);

    inline unsigned getRegOffset(unsigned regId, unsigned &size) {
        auto it = registerMap.find(regId);
        if (it == registerMap.end()) {
            return -1;
        }
        reg r = it->second;
        size = r.size;
        return r.offset; 
    }

    inline unsigned getRegOffset(std::string name, unsigned &size) {
        for (auto it : registerMap) {
            if (name == it.second.name) {
                size = it.second.size;
                return it.second.offset;
            }
        }
        return -1;
    }

    inline void skipInstruction(S2EExecutionState *state, uint64_t pc) {
        TranslationBlock *tb = state->getTb();
        uint64_t next_pc = pc + tb_get_instruction_size(tb, pc);
        assert(next_pc != pc);
        state->regs()->setPc(next_pc);
        throw CpuExitException();
    }

    void doBsr(S2EExecutionState *state, uint64_t pc);
    void doBsf(S2EExecutionState *state, uint64_t pc);
    void concretize(S2EExecutionState *state, uint64_t pc);
};
}
}
#endif
