#include <s2e/S2E.h>
#include <s2e/cpu.h>

#include "Instrumentor.h"
#include "Serialize.h"
#include "util.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(Instrumentor, "Kernel dynamic instrumentor",
                  "Instrumentor", );

#define DEBUG_INSTRUMENTOR

void Instrumentor::initialize() {
    m_disasm = s2e()->getPlugin<Disassembler>();
    initializeConfiguration();
    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
        sigc::mem_fun(*this, &Instrumentor::onTranslateInstruction));
}

void Instrumentor::initializeConfiguration() {
    ConfigFile *cfg = s2e()->getConfig();
    bool ok;
    ConfigFile::integer_list backtrace;
    backtrace = cfg->getIntegerList(getConfigKey() + ".allocSite", backtrace, &ok);
    EXIT_ON_ERROR(ok, "You must specify allocSite");
    for (auto addr : backtrace)
        m_allocSite.push_back(addr);

    // Make sure we pass the first checks but do not change the sp
    m_kasanReport = cfg->getInt(getConfigKey() + ".kasan", -1, &ok);
    EXIT_ON_ERROR(ok, "You must specify kasan");
    m_kasanRet = cfg->getInt(getConfigKey() + ".kasan_ret", -1, &ok);

    m_check_kasan = cfg->getBool(getConfigKey() + ".check_kasan", true, &ok);
    vul_size = cfg->getInt(getConfigKey() + ".vul_size", 0, &ok);
    EXIT_ON_ERROR(ok, "You must speicfy vul_size");
    m_workdir = cfg->getString(getConfigKey() + ".workdir", m_workdir, &ok);
    EXIT_ON_ERROR(ok, "You must speicfy workdir");
    m_repro = cfg->getBool(getConfigKey() + ".repro", false, &ok);
    EXIT_ON_ERROR(ok, "You must specify repro");

    ConfigFile::integer_list ranges;
    ranges = cfg->getIntegerList(getConfigKey() + ".ranges", ranges, &ok);
    for (auto off : ranges)
        m_ranges.insert(off);

    // init
    std::string database = m_workdir + "/database";
    if (!fileExists(database)) {
        EXIT_ON_ERROR(false, "database does not exist");
    } else {
        std::ifstream ifs(database, std::ifstream::binary);
        deserialize(ifs, m_summaries, m_spots);

        for (auto it : m_spots) {
            m_targetAddrs.insert(it.first);
#ifdef DEBUG_INSTRUMENTOR
            getDebugStream() << "Monitor: " << hexval(it.first) << "\n";
#endif
        }
    }

    loadCapability();
    memset(m_curtest, 0, MAX_OVERWRITE_LEN);
    check_newvalue();
}

void Instrumentor::onTranslateInstruction(ExecutionSignal *signal,
                                          S2EExecutionState *state,
                                          TranslationBlock *tb, uint64_t pc) {
    if (pc == m_allocSite[0]) {
        signal->connect(sigc::mem_fun(*this, &Instrumentor::onAllocate));
    } else if (pc == m_kasanReport) {
        signal->connect(sigc::mem_fun(*this, &Instrumentor::onKasanReport));
    } else if (m_targetAddrs.find(pc) != m_targetAddrs.end()) {
        signal->connect(sigc::mem_fun(*this, &Instrumentor::onTarget));
    }
}

void Instrumentor::onAllocate(S2EExecutionState *state, uint64_t pc) {
    uint64_t addr = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_EAX]));
    if (m_allocSite.size() > 1) {
        target_ulong frame = state->regs()->getBp();
        target_ulong stack = frame + sizeof(target_ulong);
        target_ulong rsp = state->regs()->getSp();
        if (frame >= rsp && frame < rsp + 4096) { // valid
            target_ulong ret;
            bool ok = state->readPointer(stack, ret);
            // getDebugStream(state) << "Get return addr " << hexval(ret) << "\n";
            if (ok && ret != m_allocSite[1])
                return;
        }
    }
    if (addr != 0) {
        m_allocate.push_back(addr);
    }
}

uint64_t Instrumentor::getVulObject(uint64_t target) {
    uint64_t res = 0;
    for (auto addr : m_allocate) {
        if (addr <= target && addr > res) {
            res = addr;
        }
    }
    return res;
}

// KASAN
void Instrumentor::onKasanReport(S2EExecutionState *state, uint64_t pc) {
    uint64_t ip = readArgument(state, 3);

    if (m_ips.find(ip) == m_ips.end()) {
        // find new spot
        m_captype |= CAP_SPOT;
        m_ips.insert(ip);
    }

    m_kasanDetected = true;
    // prevent kasan output to boost fuzzing
    bypassFunction(state);
}

// on OOB
void Instrumentor::report(uint64_t dst, uint64_t len,
                          std::vector<uint8_t> &data, std::string op,
                          uint64_t pc) {
    std::stringstream ss;
    uint64_t vul_obj = getVulObject(dst);
    uint64_t offset = dst - vul_obj;
    if (offset > MAX_OBJECT_SIZE) {
        return;
    } else {
        // getDebugStream() << hexval(pc) << ": " << hexval(dst) << "-" << hexval(vul_obj) << " : " << std::to_string(len) << "\n";
        std::vector<Summary> &sums = m_summaries[pc];
        bool isLoop = sums[0].values.size() == 0;
        if (!isLoop) {
            bool newOffset = true, newLength = true;
            for (auto sum : sums) {
                if (offset >= sum.offset.min && offset <= sum.offset.max) {
                    newOffset = false;
                }
                if (len >= sum.length.min && len <= sum.length.max) {
                    newLength = false;
                }
            }
            if (newOffset) {
                m_captype |= CAP_OFFSET;
            }
            if (newLength) {
                m_captype |= CAP_LENGTH;
            }
        }

        for (unsigned i = 0; i < len; i++) {
            // FIXME: respect op??
            if (offset + i < vul_size) {
                continue;
            }
            if (m_ranges.size() > 0 && 
                    m_ranges.find(offset + i) == m_ranges.end()) {
                continue;
            }

            m_curwrite.insert(offset + i);
            auto it = m_caps.find(offset + i);
            if (it == m_caps.end()) {
                Capability cap;
                cap.payload = data[i];
                cap.mask = 0;
                m_caps[offset + i] = cap;
                // if (isLoop) {
                    m_captype |= CAP_OFFSET; // new offset
                // }
                continue;
            }
            Capability &cap = it->second;
            uint8_t diff = cap.payload ^ data[i];
            bool newValue = false;
            if (diff & (~cap.mask)) {
                newValue = true;
                cap.mask |= diff;
            }
            if (newValue && !isLoop) {
                for (auto sum : sums) {
                    if (i < sum.values.size()) {
                        if (data[i] >= sum.values[i].min &&
                                data[i] <= sum.values[i].max) {
                            newValue = false;
                        }
                    }
                }
            }
            if (newValue)
                m_captype |= CAP_VALUES;
            m_curtest[i] = data[i];
        }
    }
    // ss << "{";
    // ss << "\"vul\": " << std::to_string(vul_obj);
    // ss << ", \"op\": " << op;
    // ss << ", \"addr\": " << std::to_string(dst) << ", \"len\": " <<
    // std::to_string(data.size());
    // ss << ", \"data\": [";
    // for (unsigned i = 0; i < data.size(); i++) {
    //     if (i != 0) {
    //         ss << ", ";
    //     }
    //     ss << std::to_string(data[i]);
    // }
    // ss << "]";
    // ss << "}";
    // getDebugStream() << "[S2E] " << ss.str() << "\n";
    // s2e()->flushOutputStreams();
}

void Instrumentor::resolveMemcpy(S2EExecutionState *state, Spot spot,
                                 uint64_t pc) {
    uint64_t dst = readArgument(state, spot.sig.dst);
    uint64_t src = readArgument(state, spot.sig.src);
    uint64_t len = readArgument(state, spot.sig.len);
    uint8_t value;
    std::vector<uint8_t> data;
    for (unsigned i = 0; i < len; i++) {
        if (!state->mem()->read(src + i, &value)) {
            break;
        }
        // TODO: alway use zero for mamcpy and strcpy???
        // check offset??
        data.push_back(value);
    }
    report(dst, len, data, "memcpy", pc);
}

void Instrumentor::resolveStrcpy(S2EExecutionState *state, Spot spot,
                                 uint64_t pc) {
    uint64_t dst = readArgument(state, spot.sig.dst);
    uint64_t src = readArgument(state, spot.sig.src);
    uint8_t value;
    std::vector<uint8_t> data;
    for (unsigned i = 0;; i++) {
        if (!state->mem()->read(src + i, &value)) {
            break;
        }
        if (value == 0) {
            break;
        }
        data.push_back(value);
    }
    report(dst, data.size(), data, "strcpy", pc);
}

void Instrumentor::resolveStore(S2EExecutionState *state, Spot spot,
                                uint64_t pc) {
    cs_insn *insn = m_disasm->getInst(state, pc, true);
    cs_detail *detail = insn->detail;
    if (detail) {
#ifdef TARGET_X86_64
        if (detail->x86.op_count != 2) {
            return;
        }
        cs_x86_op dst = detail->x86.operands[0];
        if (dst.type != X86_OP_MEM) {
            return;
        }
        uint64_t dstAddr = m_disasm->getConcreteMemAddr(state, &dst);
        unsigned len = dst.size;
        uint64_t payload =
            m_disasm->readConcreteOperand(state, &(detail->x86.operands[1]));
        std::vector<uint8_t> data;
        for (unsigned i = 0; i < len; i++) {
            data.push_back(payload & 0xff);
            payload = payload >> 8;
        }
        report(dstAddr, len, data, insn->mnemonic, pc);
#endif
    }
    cs_free(insn, 1);
}

void Instrumentor::onTarget(S2EExecutionState *state, uint64_t pc) {
    // TODO: check new capability
    if (m_check_kasan && !m_kasanDetected) {
        return;
    }
    // getWarningsStream() << "On target " << hexval(pc) << "\n";
    if (m_spots.find(pc) != m_spots.end()) {
        Spot spot = m_spots[pc];
        switch (spot.type) {
        case TYPE_MEMCPY:
            resolveMemcpy(state, spot, pc);
            break;
        case TYPE_STRCPY:
            resolveStrcpy(state, spot, pc);
            break;
        case TYPE_STORE:
            resolveStore(state, spot, pc);
            break;
        case TYPE_MEMSET:
        default:
            assert(false && "Not supported yet");
            break;
        }
    }
    if (!m_repro) {
        skipInstruction(state);
    }
}

// interaction
void Instrumentor::handleSimpleCommand(S2EExecutionState *state, uint8_t cmd) {
    switch (cmd) {
    case 's': // start a program
        getDebugStream() << "program starts\n";
        m_allocate.clear();
        m_kasanDetected = false;
        memset(m_curtest, 0, MAX_OVERWRITE_LEN);
        m_curwrite.clear();
        // m_captype = 0;
        break;
    case 'e':
        break;
    default:
        break;
    }
}

bool Instrumentor::check_newvalue() {
    bool isNew = false;
    XXH32_hash_t hash = XXH32(&m_curtest[0], MAX_OVERWRITE_LEN, 0);
    if (m_corpus.find(hash) == m_corpus.end()){
        m_corpus.insert(hash);
        isNew = true;
    }
    memset(m_curtest, 0, MAX_OVERWRITE_LEN);
    return isNew;
}

void Instrumentor::genCrash() {
    std::stringstream ss;
    ss << "WARNING: {";
    ss << "\"size\": " << std::to_string(m_curwrite.size());
    ss << ", \"offset\": [";
    bool first = true;
    for (auto each : m_curwrite) {
        if (!first) {
            ss << ", ";
        }
        ss << std::to_string(each);
        first = false;
    }
    ss << "], \"values\": [";
    first = true;
    foreach2(it, m_caps.begin(), m_caps.end()) {
        Capability &cap = it->second;
        if (!first) {
            ss << ", ";
        }
        ss << std::to_string(cap.payload);
        first = false;
    }
    ss << "]}";
    getWarningsStream() << ss.str() << "\n";
    s2e()->flushOutputStreams();
}

void Instrumentor::handleComplexCommand(S2EExecutionState *state, void *_cmd,
                                        uint64_t guestDataPtr,
                                        uint64_t guestDataSize) {

    INTRUMENT_COMMAND &cmd = *(INTRUMENT_COMMAND *)_cmd;
    switch (cmd.Command) {
    case INSTRUMENT_ECHO:
        break;
    case INSTRUMENT_QUERY:
        if (m_repro) {
            // getWarningsStream() << "Generate crash info....\n";
            genCrash();
        }
        cmd.query.size = m_curwrite.size();
        if (cmd.query.size > m_maxlen) {
            m_maxlen = cmd.query.size;
            // m_captype |= CAP_LENGTH;
        }
        if (check_newvalue()) {
            m_captype |= CAP_VALUES;
        }
        cmd.query.type = m_captype;
        getDebugStream() << "Flag: " << hexval(m_captype) << ", size: " << cmd.query.size << "\n";
        m_captype = 0;
        m_curwrite.clear();
        if (!state->mem()->write(guestDataPtr, &cmd, guestDataSize)) {
            getDebugStream() << "Failed to write to user address\n";
        }
        if (m_testcases % 100 == 0) {
            // For debug purpose
            saveCapability();
        }
        m_testcases++;
        break;
    default:
        break;
    }
}

void Instrumentor::handleOpcodeInvocation(S2EExecutionState *state,
                                          uint64_t guestDataPtr,
                                          uint64_t guestDataSize) {
    if (guestDataSize == 0) {
        return;
    }

    uint8_t cmd[guestDataSize];
    memset(cmd, 0, guestDataSize);

    if (!state->mem()->read(guestDataPtr, cmd, guestDataSize)) {
        getDebugStream(state) << "Failed to read instruction memory\n";
        return;
    }

    if (guestDataSize == 1) {
        handleSimpleCommand(state, cmd[0]);
    } else {
        handleComplexCommand(state, cmd, guestDataPtr, guestDataSize);
    }
}

// Utility
void Instrumentor::skipInstruction(S2EExecutionState *state) {
    TranslationBlock *tb = state->getTb();
    uint64_t pc = state->regs()->getPc();
    uint64_t next_pc = pc + tb_get_instruction_size(tb, pc);
    assert(next_pc != pc);

    state->regs()->setPc(next_pc);
    throw CpuExitException();
}

void Instrumentor::saveCapability() {
    std::string ans_file = m_workdir + "/capability";
    FILE *answer = fopen(ans_file.c_str(), "wb");
    if (answer == NULL) {
        getDebugStream() << "Failed to open file " << ans_file << "\n";
    }
    // getDebugStream() << "File path " << ans_file << "\n";
    uint32_t size = m_caps.size();
    fwrite(&size, 1, sizeof(size), answer);
    foreach2(it, m_caps.begin(), m_caps.end()) {
        uint16_t offset = it->first;
        Capability &cap = it->second;
        fwrite(&offset, 1, sizeof(offset), answer);
        fwrite(&cap, 1, sizeof(cap), answer);
    }
    size = m_ips.size();
    fwrite(&size, 1, sizeof(size), answer);
    foreach2(it, m_ips.begin(), m_ips.end()) {
        uint64_t ip = *it;
        fwrite(&ip, 1, sizeof(ip), answer);
    }

    uint32_t magic = 0xdeadbeef;
    fwrite(&magic, 1, sizeof(uint32_t), answer);

    size = m_corpus.size();
    fwrite(&size, 1, sizeof(size), answer);
    for (auto it : m_corpus) {
        XXH32_hash_t hash = it;
        fwrite(&hash, 1, sizeof(XXH32_hash_t), answer);
    }

    fclose(answer);
}

void Instrumentor::loadCapability() {
    std::string ans_file = m_workdir + "/capability";
    FILE *answer = fopen(ans_file.c_str(), "rb");
    if (answer == NULL) {
        // getDebugStream() << "Failed to open file " << ans_file << "\n";
        return;
    }
    uint32_t size, n;
    if ((n = fread(&size, 1, sizeof(size), answer)) != sizeof(size)) {
        getDebugStream() << "Failed to deserialize\n";
        return;
    }
    for (unsigned i = 0; i < size; i++) {
        uint16_t offset;
        Capability cap;
        if ((n = fread(&offset, 1, sizeof(offset), answer)) != sizeof(offset)) {
            break;
        }
        if ((n = fread(&cap, 1, sizeof(cap), answer)) != sizeof(cap)) {
            break;
        }
        m_caps.insert({offset, cap});
    }
    if ((n = fread(&size, 1, sizeof(size), answer)) != sizeof(size)) {
        getDebugStream() << "Failed to deserialize\n";
        return;
    }
    for (unsigned i = 0; i < size; i++) {
        uint64_t ip;
        if ((n = fread(&ip, 1, sizeof(ip), answer)) != sizeof(ip)) {
            break;
        }
        m_ips.insert(ip);
    }

    uint32_t magic;
    if ((n = fread(&magic, 1, sizeof(magic), answer)) != sizeof(magic)) {
        getDebugStream() << "Failed to deserialize\n";
        return;
    }
    if (magic != 0xdeadbeef) {
        getDebugStream() << "Failed to deserialize\n";
        return;
    }

    if ((n = fread(&size, 1, sizeof(size), answer)) != sizeof(size)) {
        getDebugStream() << "Failed to deserialize\n";
        return;
    }
    for (unsigned i = 0; i < size; i++) {
        XXH32_hash_t hash;
        if ((n = fread(&hash, 1, sizeof(XXH32_hash_t), answer)) != sizeof(XXH32_hash_t)) {
            break;
        }
        m_corpus.insert(hash);
    }
    fclose(answer);
}

} // namespace plugins
} // namespace s2e
