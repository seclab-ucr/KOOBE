#ifndef S2E_PLUGINS_OPTIONS_H
#define S2E_PLUGINS_OPTIONS_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

// Priority of all plugins
#define ANNOTATION_PRIORITY 20
#define ONGUARD_PRIORITY 10
#define ONTARGET_PRIORITY 9
#define ONEXIT_PRIORITY 9
#define KASAN_PRIORITY 8
#define ALLOCATE_PRIORITY 7
#define KERNEL_MODEL_PRIORITY 6
#define SYSCALL_PRIORITY 5

#define MODE_PRE_ANALYSIS 1
#define MODE_ANALYSIS 2
#define MODE_RESOLVE 3
#define MODE_SOLVE 4

#define FENGSHUI_TYPE_NORMAL 1
#define FENGSHUI_TYPE_FRAGMENTATION 2

class OptionsManager : public Plugin {
    S2E_PLUGIN

  public:
    OptionsManager(S2E *s2e) : Plugin(s2e) {}

    void initialize();

    bool racecondition;
    unsigned mode;
    unsigned fengshui;
    unsigned racelimit;
    bool resolve; // continue to evaluate after saving cap

    // KASAN
    bool write_only;
    bool track_access;
    unsigned max_kasan;

    // global options shared across plugin (readable and writable)
    bool halt = false;
    bool concrete = false;

    // constraint solving
    unsigned margin;
    bool reusable = false;

    // validate POC
    bool validate = false;

    // object record
    bool track_object;

    // bypassing SMAP
    bool enable_smap = false;

    // maximum length of an object
    unsigned max_length = 2048;
};
}
}

#endif
