#ifndef S2E_PLUGINS_INSTRUMENTOR_H
#define S2E_PLUGINS_INSTRUMENTOR_H

#include <s2e/ConfigFile.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/instrument.h>

#include "Disassembler.h"
#include "KernelInstructionTracer.h"

#define XXH_STATIC_LINKING_ONLY
#include "xxhash/xxhash.h"

namespace s2e {
namespace plugins {

class Instrumentor : public Plugin, public IPluginInvoker {
    S2E_PLUGIN

  public:
    Instrumentor(S2E *s2e) : Plugin(s2e){};
    ~Instrumentor(){};

    void initialize();
    void initializeConfiguration();

    void onTranslateInstruction(ExecutionSignal *signal,
                                S2EExecutionState *state, TranslationBlock *tb,
                                uint64_t pc);

    virtual void handleOpcodeInvocation(S2EExecutionState *state,
                                        uint64_t guestDataPtr,
                                        uint64_t guestDataSize);

  private:
    Disassembler *m_disasm;
    std::string m_workdir;

    // typedef boost::circular_buffer<uint64_t> PartialAllocator;
    std::vector<uint64_t> m_allocate;
    std::vector<target_ulong> m_allocSite;
    uint64_t m_kasanReport;
    uint64_t m_kasanRet;
    bool m_check_kasan = false;
    bool m_kasanDetected = false;
    bool m_repro = false;

    std::set<uint64_t> m_targetAddrs;
    std::map<uint64_t, Spot> m_spots;
    CapSummary m_summaries;
    std::set<uint16_t> m_ranges;

    unsigned m_Regs[6] = {
#ifdef TARGET_X86_64
        // mapping from index of parameter to offset of register
        CPU_OFFSET(regs[R_EDI]), CPU_OFFSET(regs[R_ESI]),
        CPU_OFFSET(regs[R_EDX]), CPU_OFFSET(regs[R_ECX]), CPU_OFFSET(regs[8]),
        CPU_OFFSET(regs[9])
#endif
    };

    uint64_t getVulObject(uint64_t target);
    void onAllocate(S2EExecutionState *state, uint64_t pc);
    void onKasanReport(S2EExecutionState *state, uint64_t pc);
    void onTarget(S2EExecutionState *state, uint64_t pc);

    void report(uint64_t dst, uint64_t len, std::vector<uint8_t> &data,
                std::string op, uint64_t pc);
    void resolveMemcpy(S2EExecutionState *state, Spot spot, uint64_t pc);
    void resolveStrcpy(S2EExecutionState *state, Spot spot, uint64_t pc);
    void resolveStore(S2EExecutionState *state, Spot spot, uint64_t pc);

    void skipInstruction(S2EExecutionState *state);
    target_ulong inline readArgument(S2EExecutionState *state, unsigned param) {
        unsigned offset = m_Regs[param];
        return state->regs()->read<target_ulong>(offset);
    }

    void inline bypassFunction(S2EExecutionState *state) {
        if (m_kasanRet != -1) { // rewind stack status
            state->regs()->setPc(m_kasanRet);
        } else {
            state->bypassFunction(0);
        }
        throw CpuExitException();
    }

    void handleComplexCommand(S2EExecutionState *state, void *_cmd,
                              uint64_t guestDataPtr, uint64_t guestDataSize);
    void handleSimpleCommand(S2EExecutionState *state, uint8_t cmd);

  public:
    struct Capability {
        uint8_t payload;
        uint8_t mask;
    };

  private:
#define MAX_OBJECT_SIZE   4096
#define MAX_OVERWRITE_LEN 1024
#define CAP_OFFSET 1
#define CAP_VALUES 2
#define CAP_SPOT 4
#define CAP_LENGTH 8
    std::map<uint16_t, Capability> m_caps;
    uint8_t m_captype = 0; // 0: init, 1: new offset, 2: values change, 4: new
                           // spot, 8: new length

    std::unordered_set<uint64_t> m_ips;
    std::set<XXH32_hash_t> m_corpus;
    unsigned char m_curtest[MAX_OVERWRITE_LEN];
    std::set<uint16_t> m_curwrite;
    uint16_t m_maxlen = 0;
    unsigned vul_size = 0;

    // std::unordered_set<std::string> m_values;
    // uint8_t m_hash[MAX_OBJECT_SIZE];

    int num_to_bits[16] = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};
    unsigned inline countBits(uint8_t num) {
        return num_to_bits[num & 0xf] + num_to_bits[num >> 4];
    }
    // std::string hash();
    bool check_newvalue();
    void genCrash();

    uint64_t m_testcases = 0;
    void saveCapability();
    void loadCapability();
};
}
}
#endif
