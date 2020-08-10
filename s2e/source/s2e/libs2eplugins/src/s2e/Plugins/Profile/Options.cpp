#include <s2e/S2E.h>

#include "Options.h"
#include "util.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(OptionsManager, "Manage Options", "OptionsManger");

void OptionsManager::initialize() {
    bool ok = false;
    ConfigFile *cfg = s2e()->getConfig();
    const std::string key = getConfigKey();

    mode = cfg->getInt(key + ".mode", 0, &ok);
    EXIT_ON_ERROR(ok, "You must specify " + key + ".mode");
    racecondition = cfg->getBool(key + ".racecondition", false, &ok);
    fengshui = cfg->getInt(key + ".fengshui", 1, &ok);

    write_only = cfg->getBool(key + ".writeonly", false, &ok);
    track_access = cfg->getBool(key + ".trackaccess", false, &ok);

    racelimit = cfg->getInt(key + ".racelimit", 500, &ok);
    concrete = cfg->getBool(key + ".concrete", false, &ok);

    margin = cfg->getInt(key + ".margin", -1, &ok);
    reusable = cfg->getBool(key + ".reusable", false, &ok);

    validate = cfg->getBool(key + ".validate", false, &ok);

    track_object = cfg->getBool(key + ".track_object", false, &ok);

    enable_smap = cfg->getBool(key + ".smap", false, &ok);

    max_length = cfg->getInt(key + ".max_length", 2048, &ok);
    max_kasan = cfg->getInt(key + ".maxkasan", 12, &ok);

    resolve = cfg->getBool(key + ".resolve", false, &ok);

    getDebugStream() << "Mode: " << mode << "\n";
    switch (mode) {
    case MODE_PRE_ANALYSIS:
    case MODE_ANALYSIS:
        break;
    case MODE_RESOLVE:
        break;
    }
}
} // namespace plugins
} // namespace s2e
