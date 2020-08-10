#include <s2e/S2E.h>

#include "KernelInstructionTracer.h"

namespace s2e {
namespace plugins {

/*
 * Lua API
 */
uint64_t KernelInstructionTracer::roundSize(uint64_t size) {
    lua_State *L = s2e()->getConfig()->getState();
    lua_getglobal(L, "roundSize");
    lua_pushinteger(L, size);
    lua_call(L, 1, 1);
    uint64_t res = lua_tointeger(L, -1);
    lua_pop(L, 1);
    return res;
}

bool KernelInstructionTracer::getCurCandidate(std::string &name) {
    lua_State *L = s2e()->getConfig()->getState();
    lua_getglobal(L, "getCurCandidate");
    lua_call(L, 0, 2);
    bool success = lua_toboolean(L, -2);
    if (!success) {
        goto Exit;
    }
    name = std::string(lua_tostring(L, -1));
Exit:
    lua_pop(L, 2);
    return success;
}

bool KernelInstructionTracer::getCandidate(uint64_t &vul_size, bool isVariable,
                                           std::string allocator, int &offset,
                                           uint8_t **pointer, uint64_t &len) {
    lua_State *L = s2e()->getConfig()->getState();
    lua_getglobal(L, "getCandidate");
    lua_pushinteger(L, vul_size);         // size
    lua_pushboolean(L, isVariable);       // isVariable
    lua_pushstring(L, allocator.c_str()); // allocator
    lua_call(L, 3, 5);
    bool success = lua_toboolean(L, -5) != 0;
    // if (!success) {
    //     goto Exit;
    // }
    int codetype;
    uint8_t *payload;

    offset = lua_tointeger(L, -4);
    codetype = lua_type(L, -3);
    len = lua_tointeger(L, -2);
    vul_size = lua_tointeger(L, -1);
    if (codetype == LUA_TSTRING)
        payload = (uint8_t *)lua_tostring(L, -3);
    else {
        payload = (uint8_t *)lua_touserdata(L, -3);
    }
    *pointer = payload;

    // Exit:
    lua_pop(L, 5);
    return success;
}

bool KernelInstructionTracer::getValues(uint8_t **pointer, uint64_t &len) {
    lua_State *L = s2e()->getConfig()->getState();
    lua_getglobal(L, "getValues");
    lua_call(L, 0, 3);
    bool success = lua_toboolean(L, -3);
    if (!success) {
        goto Exit;
    }

    int codetype;
    uint8_t *payload;
    codetype = lua_type(L, -2);
    if (codetype == LUA_TSTRING)
        payload = (uint8_t *)lua_tostring(L, -2);
    else {
        payload = (uint8_t *)lua_touserdata(L, -2);
    }
    *pointer = payload;
    len = lua_tointeger(L, -1);

Exit:
    lua_pop(L, 3);
    return success;
}
} // namespace plugins
} // namespace s2e