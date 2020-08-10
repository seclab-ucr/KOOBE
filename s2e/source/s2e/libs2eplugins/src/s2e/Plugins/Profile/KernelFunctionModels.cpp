#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>
#include <s2e/function_models/commands.h>

#include <klee/util/ExprTemplates.h>

#include <klee/Expr.h>

#include "KernelFunctionModels.h"
#include "Options.h"
#include "util.h"

using namespace klee;

namespace s2e {
namespace plugins {
namespace models {

S2E_DEFINE_PLUGIN(KernelFunctionModels,
                  "Plugin that implements models for kernel functions",
                  "KernelFunctionModels", "MemUtils");

void KernelFunctionModels::initialize() {
    m_memutils = s2e()->getPlugin<MemUtils>();
    m_options = s2e()->getPlugin<OptionsManager>();

    m_handlers["copy_user_generic_unrolled"] =
        &KernelFunctionModels::handleCopyUser;
    m_handlers["strlen"] = &KernelFunctionModels::handleStrlen;
    m_handlers["__memcpy"] = &KernelFunctionModels::handleMemcpy;
    m_handlers["csum_partial_copy_generic"] =
        &KernelFunctionModels::handleCsumPartialCopyGeneric;
    m_handlers["strncmp"] = &KernelFunctionModels::handleStrncmp;
    m_handlers["do_csum"] = &KernelFunctionModels::handleDoCsum;
    initializeConfiguration();
}

void KernelFunctionModels::initializeConfiguration() {
    bool ok = false;
    ConfigFile *cfg = s2e()->getConfig();
    ConfigFile::string_list funcList =
        cfg->getListKeys(getConfigKey() + ".functions");

    if (funcList.size() == 0) {
        getWarningsStream() << "no functions configured\n";
    }
    foreach2(it, funcList.begin(), funcList.end()) {
        std::stringstream s;
        s << getConfigKey() << ".functions." << *it << ".";

        FunctionModelCfg func;
        func.funcName = cfg->getString(s.str() + "funcName", "", &ok);
        EXIT_ON_ERROR(ok, "You must specify " + s.str() + "funcName" + "\n");
        func.address = cfg->getInt(s.str() + "address", -1, &ok);
        EXIT_ON_ERROR(ok, "You must specify " + s.str() + "address" + "\n");
        func.argNum = cfg->getInt(s.str() + "args", -1, &ok);
        EXIT_ON_ERROR(ok, "You must specify " + s.str() + "args" + "\n");
        func.concretize = cfg->getInt(s.str() + "concretize", 0, &ok);

        m_kernelfunc.insert({func.address, func});
    }

    ConfigFile::string_list constraintList =
        cfg->getListKeys(getConfigKey() + ".constraints");
    if (constraintList.size() == 0) {
        getWarningsStream() << "no constraint configured\n";
    }

    foreach2(it, constraintList.begin(), constraintList.end()) {
        std::stringstream s;
        s << getConfigKey() << ".constraints." << *it << ".";
        uint64_t entryAddr, exitAddr;
        entryAddr = cfg->getInt(s.str() + "entry", -1, &ok);
        EXIT_ON_ERROR(ok, "You must specify " + s.str() + "entry" + "\n");
        exitAddr = cfg->getInt(s.str() + "exit", -1, &ok);
        EXIT_ON_ERROR(ok, "You must specify " + s.str() + "exit" + "\n");

        m_ranges[exitAddr] = entryAddr;

        std::string funcName = cfg->getString(s.str() + "funcName", "", &ok);
        getDebugStream() << "Avoid constraints within function " << funcName
                         << "\n";
    }

    ConfigFile::string_list skipFuncList =
        cfg->getListKeys(getConfigKey() + ".skips");
    foreach2(it, skipFuncList.begin(), skipFuncList.end()) {
        std::stringstream s;
        s << getConfigKey() << ".skips." << *it << ".";
        uint64_t entryAddr = cfg->getInt(s.str() + "entry", -1, &ok);
        EXIT_ON_ERROR(ok, "You must specify " + s.str() + "entry" + "\n");

        m_skipFuncs.insert({entryAddr, true});
    }
}

void KernelFunctionModels::registerHandler(PcMonitor *PcMonitor,
                                           S2EExecutionState *state,
                                           uint64_t cr3) {
    foreach2(it, m_kernelfunc.begin(), m_kernelfunc.end()) {
        // we already filter out any other process at PcMonitor,
        // it's ok not to give cr3 here
        PcMonitor::CallSignalPtr CallSignal =
            PcMonitor->getCallSignal(state, it->second.address, cr3);
        auto itt = m_handlers.find(it->second.funcName);
        if (itt == m_handlers.end()) {
            continue;
        }
        getDebugStream() << "Hook Function: " << it->second.funcName << " at "
                         << hexval(it->second.address) << "\n";
        CallSignal->connect(
            sigc::bind(sigc::mem_fun(*this, &KernelFunctionModels::onCall),
                       (*itt).second),
            KERNEL_MODEL_PRIORITY);
    }

    foreach2(it, m_skipFuncs.begin(), m_skipFuncs.end()) {
        // FIXME: also skip for other processes?
        PcMonitor::CallSignalPtr CallSignal =
            PcMonitor->getCallSignal(state, it->first, -1);
        getDebugStream() << "Skip Function at " << hexval(it->first) << "\n";
        CallSignal->connect(sigc::mem_fun(*this, &KernelFunctionModels::onSkip),
                            KERNEL_MODEL_PRIORITY);
    }
}

void KernelFunctionModels::onCall(S2EExecutionState *state, PcMonitorState *pcs,
                                  uint64_t pc,
                                  KernelFunctionModels::OpHandler handler) {
    // FIXME: bool handled = false;
    bool handled = ((*this).*handler)(state, pc);
    if (handled) {
        state->bypassFunction(0);
        // TODO: test it?
        // if (state->isRunningConcrete()) {
        throw CpuExitException(); // why we need this?
                                  // }
    } else {
        // getDebugStream(state) << "Handling function at PC " << hexval(pc) <<
        // "
        // failed, falling back to original code\n";
    }
}

void KernelFunctionModels::onSkip(S2EExecutionState *state, PcMonitorState *pcs,
                                  uint64_t pc) {
    state->bypassFunction(0);
    throw CpuExitException();
}

ref<Expr> KernelFunctionModels::makeSymbolic(S2EExecutionState *state,
                                             unsigned offset, std::string name,
                                             bool makeConcolic) {
    ref<Expr> symb;

    // generate a name for the symbol
    // https://groups.google.com/forum/#!searchin/s2e-dev/jumpToSymbolicCpp|sort:date/s2e-dev/59EFhJD1Kos/VGEHPha0RKAJ
    state->jumpToSymbolicCpp();

    if (makeConcolic) {
        target_ulong value;

        if (!state->regs()->read(offset, &value, sizeof(target_ulong), false)) {
            getWarningsStream(state)
                << "Can not concretize/read symbolic value at " << offset
                << ". System state not modified"
                << "\n";
            return ref<Expr>(0);
        }
        symb = state->createSymbolicValue<target_ulong>(name, value);
        // symb = state->createConcolicValue<uint8_t>(name, (uint8_t)value);
        if (!state->regs()->write(offset, symb)) {
            getWarningsStream(state) << "Can not write symbolic value at "
                                     << offset << ". System state not modified"
                                     << "\n";
        }
        return symb;
        // state->regs()->writeSymbolicRegionUnsafe(offset, symb);
    } else {
        getWarningsStream(state) << "Not implemented yet"
                                 << "\n";
        return ref<Expr>(0);
    }
}

bool KernelFunctionModels::makeConcrete(S2EExecutionState *state,
                                        target_ulong addr, unsigned size) {
    for (unsigned i = 0; i < size; i++) {
        ref<Expr> charExpr = state->mem()->read(addr + i, Expr::Int8);
        if (charExpr.isNull()) {
            return false;
        }
        if (!isa<ConstantExpr>(charExpr)) {
            uint8_t value = readExpr<uint8_t>(state, charExpr);
            if (!state->mem()->write(addr + i, &value, 1)) {
                getWarningsStream(state)
                    << "Failed to write concrete to memory\n";
                exit(1);
            }
        }
    }
    return true;
}

bool KernelFunctionModels::readStack(S2EExecutionState *state,
                                     target_ulong stack, unsigned index,
                                     target_ulong &arg) {
    target_ulong ret;

    uint64_t addr;
    if (stack == 0) {
        addr = state->regs()->getSp() + index * sizeof(target_ulong);
    } else {
        addr = stack + index * sizeof(target_ulong);
    }

    // First check if argument is symbolic
    ref<Expr> readArg =
        state->mem()->read(addr, sizeof(target_ulong) * CHAR_BIT);
    if (!isa<ConstantExpr>(readArg)) {
        getDebugStream(state) << "Argument " << index << " at " << hexval(addr)
                              << " is symbolic\n";
        return false;
    }

    // If not, read concrete value
    bool ok = state->readPointer(addr, ret);

    if (!ok) {
        getDebugStream(state) << "Failed to read argument " << index << " at "
                              << hexval(addr) << "\n";
        return false;
    }

    arg = ret;
    return true;
}

/*
 * We rely on rbp to unwind stack, which maybe not precise.
 */
bool KernelFunctionModels::dump_stack(S2EExecutionState *state,
                                      target_ulong stack, target_ulong frame,
                                      std::vector<target_ulong> &addrs,
                                      unsigned depth) {
    if (addrs.size() >= depth) {
        return true;
    }

    if (stack != 0) {
        target_ulong ip;
        if (!readStack(state, stack, 0, ip))
            return false;
        addrs.push_back(ip);
    }

    if (frame == 0) {
        frame = state->regs()->getBp();
    }

    stack = frame + sizeof(target_ulong);
    if (!readStack(state, frame, 0, frame))
        return false;

    // check if the frame pointer is valid
    if (frame <= stack || frame >= stack + 4096) {
        return true;
    }

    return dump_stack(state, stack, frame, addrs, depth);
}

// size: width
bool KernelFunctionModels::readMemory(S2EExecutionState *state,
                                      target_ulong addr, unsigned size,
                                      uint64_t &arg, bool concretize) {
    uint64_t ret = 0;
    ref<Expr> expr = state->mem()->read(addr, size);
    if (expr.isNull()) {
        return false;
    }
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(expr)) {
        ret = CE->getZExtValue();
    } else {
        ref<Expr> value = state->concolics->evaluate(expr);
        if (!isa<ConstantExpr>(value)) {
            return false;
        }
        if (concretize) {
            if (!state->mem()->write(addr,
                                     value)) { // safer to write constant expr
                                               // instead of concrete value
                getWarningsStream(state)
                    << "Failed to write concrete value to memory\n";
                exit(1); // comment this if needed
                return false;
            }
        }
        ret = dyn_cast<ConstantExpr>(value)->getZExtValue();
    }
    arg = ret;
    return true;
}

ref<Expr> KernelFunctionModels::readSymMemory(S2EExecutionState *state,
                                              target_ulong addr, unsigned size,
                                              bool concretize) {
    ref<Expr> ret = state->mem()->read(addr, size);
    if (concretize && !isa<ConstantExpr>(ret)) {
        ref<Expr> value = state->concolics->evaluate(ret);
        if (!state->mem()->write(addr, value)) {
            getWarningsStream(state)
                << "Failed to write concrete value to memory\n";
            exit(1);
        }
    }
    return ret;
}

// size: Expr::Width
bool KernelFunctionModels::readRegister(S2EExecutionState *state,
                                        unsigned offset, unsigned size,
                                        uint64_t &arg, bool concretize) {
    target_ulong ret = 0;
    ref<Expr> expr = state->regs()->read(offset, size);
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(expr)) {
        ret = CE->getZExtValue();
    } else {
        ref<Expr> value = state->concolics->evaluate(expr);
        if (!isa<ConstantExpr>(value)) {
            return false;
        }
        if (concretize) {
            if (!state->regs()->write(offset, value)) {
                getWarningsStream(state)
                    << "Failed to write concrete value to register"
                    << "\n";
                exit(1);
                return false;
            }
            // When we concretize a symbolic value, we also get a new constraint
            // here.
            // It appears that the above solution doesn't add a new constraint,
            // so I
            // guess it's better than:
            // m_forkAddrs.push_back(std::make_pair(state->regs()->getPc(),
            // state->constraints.size()));
            // ret = state->regs()->read<target_ulong>(offset);
        }
        ret = dyn_cast<ConstantExpr>(value)->getZExtValue();
    }
    arg = ret;
    return true;
}

ref<Expr> KernelFunctionModels::readSymRegister(S2EExecutionState *state,
                                                unsigned offset, unsigned size,
                                                bool concretize) {
    ref<Expr> ret = state->regs()->read(offset, size);
    if (concretize) {
        if (!isa<ConstantExpr>(ret)) {
            ref<Expr> value = state->concolics->evaluate(ret);
            if (!state->regs()->write(offset, value)) {
                getWarningsStream(state)
                    << "Failed to write concrete value to register"
                    << "\n";
                exit(1);
            }
        }
    }
    return ret;
}

bool KernelFunctionModels::readArgument(S2EExecutionState *state,
                                        unsigned param, uint64_t &arg,
                                        bool concretize) {
#ifdef TARGET_X86_64
    if (param > 6) {
        getWarningsStream() << "Cannot get this argument: " << param << "\n";
        exit(-1);
    }
#endif

    unsigned offset = m_Regs[param];
    return readRegister(state, offset, sizeof(target_ulong) * CHAR_BIT, arg,
                        concretize);
}

ref<Expr> KernelFunctionModels::readSymArgument(S2EExecutionState *state,
                                                unsigned param,
                                                bool concretize) {
    ref<Expr> ret;
#ifdef TARGET_X86_64
    if (param > 6) {
        getWarningsStream() << "Cannot get this argument: " << param << "\n";
        exit(-1);
    }

    unsigned offset = m_Regs[param];
    ret = readSymRegister(state, offset, sizeof(target_ulong) * CHAR_BIT,
                          concretize);
#endif

    return ret;
}

void KernelFunctionModels::getRetValue(S2EExecutionState *state,
                                       uint64_t &arg) {
    target_ulong ret = 0;
    unsigned offset = CPU_OFFSET(regs[R_EAX]);
    klee::ref<klee::Expr> value =
        state->regs()->read(CPU_OFFSET(regs[R_EAX]), sizeof(target_ulong) * 8);
    if (isa<klee::ConstantExpr>(value)) {
        ret = state->regs()->read<target_ulong>(offset);
    }
    arg = ret;
    return;
}

bool KernelFunctionModels::handleCopyUser(S2EExecutionState *state,
                                          uint64_t pc) {

    getDebugStream(state) << "HandleCopyUser at " << hexval(pc) << "\n";
#ifdef TARGET_X86_64
    ref<Expr> len = state->regs()->read(CPU_OFFSET(regs[R_EDX]),
                                        sizeof(target_ulong) * CHAR_BIT);
    if (!isa<ConstantExpr>(len)) {
        // FIXME: what about symbolic address
        // ref<Expr> to = state->regs()->read(CPU_OFFSET(regs[R_EDI]),
        // sizeof(target_ulong) * CHAR_BIT);
        // ref<Expr> from = state->regs()->read(CPU_OFFSET(regs[R_ESI]),
        // sizeof(target_ulong) * CHAR_BIT);
        uint64_t to =
            state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_EDI]));
        uint64_t from =
            state->regs()->read<target_ulong>(CPU_OFFSET(regs[R_ESI]));
        ref<Expr> value = state->concolics->evaluate(len);

        if (!isa<ConstantExpr>(value)) {
            getDebugStream(state) << "Failed to concretize the length"
                                  << "\n";
            return false;
        }
        uint64_t size = dyn_cast<ConstantExpr>(value)->getZExtValue();
        getDebugStream(state) << hexval(to) << " " << hexval(from) << " " << len
                              << " " << value << "\n";

        for (unsigned i = 0; i < size; i++) {
            ref<Expr> srcCharExpr = m_memutils->read(state, from + i);
            if (srcCharExpr.isNull()) {
                return false;
            }
            if (!state->mem()->write(to + i, srcCharExpr)) {
                getDebugStream(state)
                    << "Failed to write to destination string.\n";
                return false;
            }
        }
        // update registers
        uint64_t eax = 0, edx = 0;
        if (!state->regs()->write(CPU_OFFSET(regs[R_EAX]), &eax,
                                  sizeof(uint64_t)) ||
            !state->regs()->write(CPU_OFFSET(regs[R_EDX]), &edx,
                                  sizeof(uint64_t))) {
            getDebugStream(state) << "Failed to write result to eax or edx\n";
            exit(1);
        }
        to += size;
        from += size;
        if (!state->regs()->write(CPU_OFFSET(regs[R_EDI]), &to,
                                  sizeof(uint64_t)) ||
            !state->regs()->write(CPU_OFFSET(regs[R_ESI]), &from,
                                  sizeof(uint64_t))) {
            getDebugStream(state) << "Failed to write result to rdi or rsi"
                                  << "\n";
            exit(1);
        }
        return true;
    }
    return false;
#else
    return false;
#endif
}

// read concrete string from memory without concretizing it
std::string KernelFunctionModels::readString(S2EExecutionState *state,
                                             target_ulong addr,
                                             unsigned MAXSIZE) {
    unsigned len = 0;
    std::string ret;
    // FIXME: alloc memory for string with size larger than 128
    for (; len < MAXSIZE; len++) {
        ref<Expr> charExpr = m_memutils->read(state, addr + len);
        if (charExpr.isNull()) {
            getDebugStream(state)
                << "Failed to read char at " << hexval(addr + len) << "\n";
            return "";
        }

        uint8_t val = readExpr<uint8_t>(state, charExpr);
        if (val == 0) {
            break;
        }
        ret = ret + (char)(val);
    }
    return ret;
}

bool KernelFunctionModels::strlenConcrete(S2EExecutionState *state,
                                          uint64_t stringAddr, size_t &len) {
    for (len = 0; len < MAX_STRLEN; len++) {
        ref<Expr> charExpr = m_memutils->read(state, stringAddr + len);
        if (charExpr.isNull()) {
            getDebugStream(state) << "Failed to read char at "
                                  << hexval(stringAddr + len) << "\n";
            return false;
        }
        ref<Expr> res = state->concolics->evaluate(charExpr);
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(res)) {
            if (CE->getZExtValue() == 0) {
                break;
            }
        }
    }

    if (len == MAX_STRLEN) {
        return false;
    }
    return true;
}

bool KernelFunctionModels::strlenSymbolic(S2EExecutionState *state,
                                          uint64_t stringAddr,
                                          ref<Expr> &size) {
    size_t len;
    if (!strlenConcrete(state, stringAddr, len)) {
        return false;
    }

    if (len > 2 * m_options->max_length) {
        len = 2 * m_options->max_length;
    }

    const Expr::Width width = state->getPointerSize() * CHAR_BIT;
    const ref<Expr> nullByteExpr = E_CONST('\0', Expr::Int8);

    size = E_CONST(len, width);

    for (int nr = len - 1; nr >= 0; nr--) {
        ref<Expr> charExpr = m_memutils->read(state, stringAddr + nr);
        if (charExpr.isNull()) {
            getDebugStream(state)
                << "Failed to read char " << nr << " of string "
                << hexval(stringAddr) << "\n";
            return false;
        }

        size = E_ITE(E_EQ(charExpr, nullByteExpr), E_CONST(nr, width), size);
    }

    return true;
}

bool KernelFunctionModels::handleStrlen(S2EExecutionState *state, uint64_t pc) {
    if (state->isRunningConcrete()) { // FIXME
        return false;
    }

    uint64_t stringAddr;
    readArgument(state, 0, stringAddr, false);

    // Only handle the case where the string is symbolic
    // FIXME: we only inspect the first byte, is it okay?
    ref<Expr> charExpr = m_memutils->read(state, stringAddr);
    if (isa<ConstantExpr>(charExpr)) {
        return false;
    }

    size_t len;
    ref<Expr> retExpr;
    if (!strlenConcrete(state, stringAddr, len)) {
        getDebugStream(state) << "Failed to find NULL char in string\n";
        return false;
    }

    const Expr::Width width = sizeof(target_ulong) * CHAR_BIT;
    const ref<Expr> nullByteExpr = E_CONST('\0', Expr::Int8);

    retExpr = E_CONST(len, width);

    for (int nr = len - 1; nr >= 0; nr--) {
        ref<Expr> charExpr = m_memutils->read(state, stringAddr + nr);
        if (charExpr.isNull()) {
            getDebugStream(state)
                << "Failed to read char " << nr << " of string "
                << hexval(stringAddr) << "\n";
            return false;
        }

        retExpr =
            E_ITE(E_EQ(charExpr, nullByteExpr), E_CONST(nr, width), retExpr);
    }

    // Write result back
    if (!state->regs()->write(CPU_OFFSET(regs[R_EAX]), retExpr)) {
        getDebugStream(state) << "Failed to write result to rax"
                              << "\n";
        exit(1);
    }

    return true;
}

bool KernelFunctionModels::handleMemcpy(S2EExecutionState *state, uint64_t pc) {
    // Only handle it when necessary (i.e. the length is symbolic)
    ref<Expr> len = readSymArgument(state, 2, false);
    if (isa<ConstantExpr>(len)) {
        return false;
    }
    // if (state->isRunningConcrete()) {
    //     return false;
    // }

    // Read function arguments
    uint64_t memAddrs[2];
    for (int i = 0; i < 2; i++) {
        readArgument(state, i, memAddrs[i], false);
    }

    uint64_t numBytes;
    readArgument(state, 2, numBytes, false);

    // Assemble the memory copy expression
    ref<Expr> retExpr;
    if (memcpyHelper(state, memAddrs, numBytes, retExpr)) {
        if (!state->regs()->write(CPU_OFFSET(regs[R_EAX]), retExpr)) {
            getDebugStream(state) << "Failed to write result to rax"
                                  << "\n";
            exit(1);
        }
        return true;
    } else {
        return false;
    }
}

/*
 * https://elixir.bootlin.com/linux/v4.9.3/source/arch/x86/lib/csum-copy_64.S#L48
 * The function may runs in concrete mode at the beginning, and then switch to
 * concolic mode when it encounters a memory address containning symbolic value.
 * We concretize the result as the symbolic checksum seems to be useless in our
 * project.
 * Even concolic execution is extremely slow when going through this function
 * because the accumulated
 * constraints are so complex.
 */
bool KernelFunctionModels::handleCsumPartialCopyGeneric(
    S2EExecutionState *state, uint64_t pc) {
    getDebugStream(state) << "Handle csum_partial_copy_generic\n";

    // if (state->isRunningConcrete()) {
    //     return false;
    // }

    uint64_t src, dst, elen, isum;
    readArgument(state, 0, src, false);
    readArgument(state, 1, dst, false);
    readArgument(state, 2, elen, false);
    readArgument(state, 3, isum, false);
    // TODO: We ignore 4th and 5th arguments here
    // readArgument(state, 5, src_err_ptr, false);
    // readArgument(state, 6, dst_err_ptr, false);
    getDebugStream(state) << "src: " << hexval(src) << "\n";
    getDebugStream(state) << "dst: " << hexval(dst) << "\n";

    uint64_t result = (isum & 0xffffffff) + (isum >> 32);
    uint64_t remain = elen;
    unsigned i = 0;
    for (; i < remain; i += 4) {
        uint32_t dword;
        ref<Expr> srcDwordExpr = m_memutils->read(state, src, Expr::Int32);
        if (srcDwordExpr.isNull()) {
            return false;
        }
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(srcDwordExpr)) {
            dword = CE->getZExtValue(32);
            if (!state->mem()->write(dst, &dword, sizeof(uint32_t))) {
                getDebugStream(state) << "Failed to read.\n";
                return false;
            }
        } else {
            dword = readExpr<uint32_t>(state, srcDwordExpr);
            if (!state->mem()->write(dst, srcDwordExpr)) {
                getDebugStream(state)
                    << "Failed to write to destination string.\n";
                return false;
            }
        }

        result += dword;
        src += 4;
        dst += 4;
    }
    remain = remain & 0x3;
    if (remain & 0x2) {
        uint16_t word;
        ref<Expr> srcWordExpr = m_memutils->read(state, src, Expr::Int16);
        if (srcWordExpr.isNull()) {
            return false;
        }
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(srcWordExpr)) {
            word = CE->getZExtValue(16);
            if (!state->mem()->write(dst, &word, sizeof(uint16_t))) {
                getDebugStream(state) << "Failed to read.\n";
                return false;
            }
        } else {
            word = readExpr<uint16_t>(state, srcWordExpr);
            if (!state->mem()->write(dst, srcWordExpr)) {
                getDebugStream(state)
                    << "Failed to write to destination string.\n";
                return false;
            }
        }

        result += word;
        src += 2;
        dst += 2;
    }
    remain = remain & 0x1;
    if (remain) { // copy last byte
        uint8_t byte;
        ref<Expr> srcByteExpr = m_memutils->read(state, src, Expr::Int8);
        if (srcByteExpr.isNull()) {
            return false;
        }
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(srcByteExpr)) {
            byte = CE->getZExtValue(8);
            if (!state->mem()->write(dst, &byte, sizeof(uint8_t))) {
                getDebugStream(state) << "Failed to read.\n";
                return false;
            }
        } else {
            byte = readExpr<uint8_t>(state, srcByteExpr);
            if (!state->mem()->write(dst, srcByteExpr)) {
                getDebugStream(state)
                    << "Failed to write to destination string.\n";
                return false;
            }
        }

        result += byte;
        src += 1;
        dst += 1;
    }

    result = (result & 0xffffffff) + (result >> 32);
    result = (result & 0xffffffff) +
             (result >> 32); // A small chance that it would overflow
    getDebugStream(state) << "checksum: " << hexval(result) << "\n";
    getDebugStream(state) << hexval(src) << "\n";
    getDebugStream(state) << hexval(dst) << "\n";

    if (!state->regs()->write(CPU_OFFSET(regs[R_EAX]), &result,
                              sizeof(uint64_t))) {
        getDebugStream(state) << "Failed to write result to rax"
                              << "\n";
        return false;
    }
    uint64_t zero = 0;
    if (!state->regs()->write(CPU_OFFSET(regs[R_ECX]), &zero,
                              sizeof(uint64_t))) {
        getDebugStream(state) << "Failed to write result to rcx"
                              << "\n";
        return false;
    }
    if (!state->regs()->write(CPU_OFFSET(regs[R_EDI]), &src,
                              sizeof(uint64_t)) ||
        !state->regs()->write(CPU_OFFSET(regs[R_ESI]), &dst,
                              sizeof(uint64_t))) {
        getDebugStream(state) << "Failed to write result to rdi or rsi"
                              << "\n";
        exit(1);
    }

    return true;
}

bool KernelFunctionModels::handleStrncmp(S2EExecutionState *state,
                                         uint64_t pc) {
    if (state->isRunningConcrete()) { // FIXME
        return false;
    }

    uint64_t srcAddr, dstAddr, count;
    readArgument(state, 0, srcAddr, false);
    readArgument(state, 1, dstAddr, false);
    readArgument(state, 2, count, false);

    const Expr::Width width = sizeof(target_ulong) * CHAR_BIT;
    const ref<Expr> nullByteExpr = E_CONST(0, Expr::Int8);
    const ref<Expr> zeroExpr = E_CONST(0, width);
    const ref<Expr> oneExpr = E_CONST(1, width);
    const ref<Expr> negoneExpr = E_CONST((uint64_t)-1, width);
    ref<Expr> retExpr = E_CONST(0, width);

    for (int nr = count - 1; nr >= 0; nr--) {
        ref<Expr> charExpr[2];
        charExpr[0] = m_memutils->read(state, srcAddr + nr);
        if (charExpr[0].isNull()) {
            getDebugStream(state) << "Failed to read in strncmp\n";
            return false;
        }
        charExpr[1] = m_memutils->read(state, dstAddr + nr);
        if (charExpr[1].isNull()) {
            getDebugStream(state) << "Failed to read in strncmp\n";
            return false;
        }
        if (nr == count - 1) {
            ref<Expr> cmpExpr =
                E_ITE(E_LT(charExpr[0], charExpr[1]), negoneExpr, oneExpr);
            retExpr = E_ITE(E_EQ(charExpr[0], charExpr[1]), zeroExpr, cmpExpr);
        } else {
            ref<Expr> cmpExpr =
                E_ITE(E_LT(charExpr[0], charExpr[1]), negoneExpr, oneExpr);
            retExpr =
                E_ITE(E_EQ(charExpr[0], charExpr[1]),
                      E_ITE(E_EQ(charExpr[0], nullByteExpr), zeroExpr, retExpr),
                      cmpExpr);
        }
    }

    // Write result back
    if (!state->regs()->write(CPU_OFFSET(regs[R_EAX]), retExpr)) {
        getDebugStream(state) << "Failed to write result to rax"
                              << "\n";
        exit(1);
    }
    return true;
}

bool KernelFunctionModels::handleDoCsum(S2EExecutionState *state, uint64_t pc) {

    uint64_t src, len;
    readArgument(state, 0, src, false);
    readArgument(state, 1, len, false);

    unsigned odd, count;
    unsigned long result = 0;
    uint64_t value = 0;
    if (len != 0) {
        odd = 1 & src;
        if (odd) {
            if (!readMemory(state, src, Expr::Int8, value, false)) {
                return false;
            }
            result = value << 8;
            len--;
            src++;
        }
        count = len >> 1;
        if (count) {
            if (2 & src) {
                if (!readMemory(state, src, Expr::Int16, value, false)) {
                    return false;
                }
                result += value;
                count--;
                len -= 2;
                src += 2;
            }
            count >>= 1;
            if (count) {
                while (count) {
                    if (!readMemory(state, src, Expr::Int32, value, false)) {
                        return false;
                    }
                    result += value;
                    count--;
                    len -= 4;
                    src += 4;
                }
            }
            if (len & 2) {
                if (!readMemory(state, src, Expr::Int16, value, false)) {
                    return false;
                }
                result += value;
                src += 2;
            }
        }
        if (len & 1) {
            if (!readMemory(state, src, Expr::Int8, value, false)) {
                return false;
            }
            result += value;
        }
        result = add32_with_carry(result >> 32, result & 0xffffffff);
        if (odd) {
            result = from32to16(result);
            result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
        }
    }

    if (!state->regs()->write(CPU_OFFSET(regs[R_EAX]), &result,
                              sizeof(result))) {
        getDebugStream(state) << "Failed to write result to rax"
                              << "\n";
        return false;
    }
    return true;
}

/*
 * Forbid new contraint in certain functions in order to resolve overconstraint
 */
void KernelFunctionModels::decideAddConstraint(uint64_t pc,
                                               bool *allowConstraint) {
    auto it = m_ranges.lower_bound(pc);
    if (it == m_ranges.end()) {
        return;
    }
    if (pc >= it->second) {
        *allowConstraint = false;
        eliminate++;
    }
}
} // namespace models
} // namespace plugins
} // namespace s2e
