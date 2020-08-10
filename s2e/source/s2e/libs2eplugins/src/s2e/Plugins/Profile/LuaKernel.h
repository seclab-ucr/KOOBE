#ifndef S2E_PLUGINS_LUAKERNEL_H
#define S2E_PLUGINS_LUAKERNEL_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/Profile/Tracer.h>

#include "Evaluation.h"

namespace s2e {
namespace plugins {

class LuaKernel {

  public:
    static const char className[];
    static Lunar<LuaKernel>::RegType methods[];

    // LuaKernel(lua_State *L) : m_kernel(nullptr) {}

    LuaKernel(lua_State *L) {}
    LuaKernel() {}

    int readRegister(lua_State *L);
    int readMemory(lua_State *L);
    int findObject(lua_State *L);

  private:
    S2EExecutionState *getState(lua_State *L);
};
}
}
#endif
