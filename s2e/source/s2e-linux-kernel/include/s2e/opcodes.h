/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2010, Dependable Systems Laboratory, EPFL
/// Copyright (c) 2016 Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to
/// deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in
/// all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
/// FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
/// THE
/// SOFTWARE.

#ifndef S2E_OPCODES_H
#define S2E_OPCODES_H

#ifdef __cplusplus
extern "C" {
#endif

// clang-format off

#define BASE_S2E_CHECK          0x00
#define BASE_S2E_MAKE_SYMBOLIC  0x03
#define BASE_S2E_IS_SYMBOLIC    0x04
#define BASE_S2E_GET_PATH_ID    0x05
#define BASE_S2E_KILL_STATE     0x06
#define BASE_S2E_PRINT_EXPR     0x07
#define BASE_S2E_PRINT_MEM      0x08
#define BASE_S2E_ENABLE_FORK    0x09
#define BASE_S2E_DISABLE_FORK   0x0A
#define BASE_S2E_INVOKE_PLUGIN  0x0B
#define BASE_S2E_ASSUME         0x0C
#define BASE_S2E_ASSUME_DISJ    0x0D
#define BASE_S2E_ASSUME_RANGE   0x0E
#define BASE_S2E_YIELD          0x0F
#define BASE_S2E_PRINT_MSG      0x10
#define BASE_S2E_MAKE_CONCOLIC  0x11
#define BASE_S2E_BEGIN_ATOMIC   0x12
#define BASE_S2E_END_ATOMIC     0x13
#define BASE_S2E_CONCRETIZE     0x20
#define BASE_S2E_EXAMPLE        0x21
#define BASE_S2E_STATE_COUNT    0x30
#define BASE_S2E_INSTANCE_COUNT 0x31
#define BASE_S2E_SLEEP          0x32
#define BASE_S2E_WRITE_BUFFER   0x33
#define BASE_S2E_GET_RANGE      0x34
#define BASE_S2E_CONSTR_CNT     0x35
#define BASE_S2E_HEX_DUMP       0x36
#define BASE_S2E_CHECK_PLUGIN   0x40
#define BASE_S2E_SET_TIMER_INT  0x50
#define BASE_S2E_SET_APIC_INT   0x51
#define BASE_S2E_GET_OBJ_SZ     0x52
#define BASE_S2E_CLEAR_TEMPS    0x53
#define BASE_S2E_FORK_COUNT     0x54

// Maximum S2E opcode allowed
#define BASE_S2E_MAX_OPCODE     0x70

// clang-format on

#ifdef __cplusplus
}
#endif

#endif
