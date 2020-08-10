#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <s2e/Plugins/Lua/LuaS2EExecutionState.h>

#include "AllocationMap.h"
#include "Disassembler.h"
#include "LuaKernel.h"
#include "util.h"

namespace s2e {
namespace plugins {

const char LuaKernel::className[] = "LuaKernel";

Lunar<LuaKernel>::RegType LuaKernel::methods[] = {
    LUNAR_DECLARE_METHOD(LuaKernel, readRegister),
    LUNAR_DECLARE_METHOD(LuaKernel, readMemory),
    LUNAR_DECLARE_METHOD(LuaKernel, findObject),
    {0, 0}};

S2EExecutionState *LuaKernel::getState(lua_State *L) {
    void *data = luaL_checkudata(L, 1, "LuaS2EExecutionState");
    if (!data) {
        g_s2e->getDebugStream() << "Incorrect lua invocation\n";
        return nullptr;
    }
    LuaS2EExecutionState **ls = reinterpret_cast<LuaS2EExecutionState **>(data);
    return (*ls)->getState();
}

// @parameters:
// 1. name of register
int LuaKernel::readRegister(lua_State *L) {
    S2EExecutionState *state = getState(L);
    assert(state);

    std::string regstr = luaL_checkstring(L, 2);
    Disassembler *disasm = g_s2e->getPlugin<Disassembler>();
    assert(disasm);

    unsigned size;
    unsigned offset = disasm->getRegOffset(regstr, size);
    ref<Expr> expr = state->regs()->read(offset, size);
    g_s2e->getDebugStream(state) << "Expr: " << expr << "\n";

    uint64_t concrete = readExpr<uint64_t>(state, expr);
    g_s2e->getDebugStream(state) << "Concrete: " << hexval(concrete) << "\n";

    lua_pushinteger(L, concrete);
    return 1;
}

int LuaKernel::readMemory(lua_State *L) {
    S2EExecutionState *state = getState(L);
    assert(state);

    long address = (long)luaL_checkinteger(L, 2);
    long size = (long)luaL_checkinteger(L, 3);
    std::vector<uint8_t> bytes(size);

    unsigned index = 0;
    std::stringstream ss;
    char buf[17] = {0};
    const unsigned length = 16;
    while (index < size) {
        unsigned i;
        for (i = 0; i < length; i++) {
            if (i + index >= size) {
                break;
            }
            ref<Expr> charExpr =
                state->mem()->read(address + index + i, Expr::Int8);
            if (ConstantExpr *CE = dyn_cast<ConstantExpr>(charExpr)) {
                buf[i] = 'C';
                ss << hexval(CE->getZExtValue(), 2, false) << " ";
                bytes.push_back(CE->getZExtValue());
            } else {
                buf[i] = 'S';
                uint8_t val = readExpr<uint8_t>(state, charExpr);
                ss << hexval(val, 2, false) << " ";
                bytes.push_back(val);
            }
        }
        for (; i < length; i++) {
            buf[i] = '.';
            ss << "   ";
        }
        ss << std::string(buf) << "\n";
        index += length;
    }
    g_s2e->getDebugStream() << ss.str();

    luaL_Buffer buff;
    luaL_buffinit(L, &buff);
    luaL_addlstring(&buff, (char *)bytes.data(), size * sizeof(uint8_t));
    luaL_pushresult(&buff);

    return 1;
}

int LuaKernel::findObject(lua_State *L) {
    S2EExecutionState *state = getState(L);
    assert(state);

    uint64_t addr = luaL_checkinteger(L, 2);
    AllocManager *alloc = g_s2e->getPlugin<AllocManager>();
    assert(alloc);

    uint64_t base_addr = alloc->find(state, addr);
    if (!base_addr) {
        g_s2e->getDebugStream(state) << "Failed to find the base address\n";
        return 0;
    }

    AllocObj obj;
    if (!alloc->get(state, base_addr, obj, true)) {
        return 0;
    }

    std::vector<target_ulong> backtrace;
    if (!alloc->getCallsite(base_addr, backtrace)) {
        g_s2e->getWarningsStream(state) << "Failed to find callsite for " << hexval(base_addr) << "\n";
        return 0;
    }

    std::stringstream ss;
    ss << "[Busy Object] {";
    ss << "\"Callsite\": [";
    for (int i = 0; i < backtrace.size(); i++) {
        if (i != 0) ss << ", ";
        ss << std::to_string(backtrace[i]);
    }
    ss << "], \"Size\": " << std::to_string(obj.width);
    ss << ", \"Allocator\": \"" << alloc->getAllocator(obj) << "\"";
    ss << ", \"Symbolic\": "
       << (obj.tag == AllocObj::SYMBOLIC ? "true" : "false") << "}\n";
    g_s2e->getDebugStream(state) << ss.str();
    return 1;
}


} // namespace plugins
} // namespace s2e
