///
/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2010-2017, Dependable Systems Laboratory, EPFL
/// Copyright (c) 2017, Cyberhaven
///
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are met:
///     * Redistributions of source code must retain the above copyright
///       notice, this list of conditions and the following disclaimer.
///     * Redistributions in binary form must reproduce the above copyright
///       notice, this list of conditions and the following disclaimer in the
///       documentation and/or other materials provided with the distribution.
///     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
///       names of its contributors may be used to endorse or promote products
///       derived from this software without specific prior written permission.
///
/// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
/// AND
/// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
/// IMPLIED
/// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
/// DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE
/// LIABLE
/// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
/// DAMAGES
/// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
/// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
/// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
/// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
/// THIS
/// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef S2E_CUSTOM_INSTRUCTIONS_H
#define S2E_CUSTOM_INSTRUCTIONS_H

#include <stdarg.h>

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <inttypes.h>
#endif

#include "opcodes.h"

// clang-format off

#define _S2E_INSTRUCTION_COMPLEX(val1, val2)            \
    ".byte 0x0F, 0x3F\n"                                \
    ".byte 0x00, " #val1 ", " #val2 ", 0x00\n"          \
    ".byte 0x00, 0x00, 0x00, 0x00\n"

// This layer of indirection is required so that the arguments are expanded
// before being "stringified"
#define S2E_INSTRUCTION_COMPLEX(val1, val2)             \
    _S2E_INSTRUCTION_COMPLEX(val1, val2)

#define S2E_INSTRUCTION_SIMPLE(val)                     \
    _S2E_INSTRUCTION_COMPLEX(val, 0x00)

#ifdef __x86_64__
#define S2E_INSTRUCTION_REGISTERS_COMPLEX(val1, val2)   \
    "push %%rbx\n"                                      \
    "mov %%rdx, %%rbx\n"                                \
    _S2E_INSTRUCTION_COMPLEX(val1, val2)                \
    "pop %%rbx\n"
#else
#define S2E_INSTRUCTION_REGISTERS_COMPLEX(val1, val2)   \
    "pushl %%ebx\n"                                     \
    "movl %%edx, %%ebx\n"                               \
    _S2E_INSTRUCTION_COMPLEX(val1, val2)                \
    "popl %%ebx\n"
#endif

#define S2E_INSTRUCTION_REGISTERS_SIMPLE(val)           \
    S2E_INSTRUCTION_REGISTERS_COMPLEX(val, 0x00)

///
/// \brief Forces a read of each byte in the specified string
///
/// This ensures that the memory pages occupied by the string are paged in memory before passing them to S2E, which
/// cannot page in memory by itself.
///
/// \param[in] string String to page into memory
///
static inline void __s2e_touch_string(volatile const char *string) {
    while (*string) {
        ++string;
    }
}

///
/// \brief Forces a read of each byte in the specified buffer
///
/// This ensures that the memory pages occupied by the buffer are paged in memory before passing them to S2E, which
/// cannot page in memory by itself.
///
/// \param[in] buffer Buffer to page into memory
/// \param[in] size Number of bytes in the buffer
///
static inline void __s2e_touch_buffer(volatile void *buffer, unsigned size) {
    unsigned i;
    volatile char *b = (volatile char *) buffer;
    for (i = 0; i < size; ++i) {
        *b; ++b;
    }
}

///
/// \brief Get the S2E version
///
/// \return The S2E version or 0 when running without S2E
///
static inline int s2e_check(void) {
    int version;
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_CHECK)
        : "=a" (version)  : "a" (0)
    );
    return version;
}

//
// These functions allow you to print messages and symbolic values to the S2E log file. This is useful for debugging
//

///
/// \brief Print a message to the S2E log
///
/// \param[in] message The message to print
///
static inline void s2e_message(const char *message) {
    __s2e_touch_string(message);
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_PRINT_MSG)
        : : "a" (message)
    );
}

///
/// \brief Print a format string as an S2E message
///
/// \param[in] format The format string
/// \param[in] ... Arguments to the format string
/// \return The number of characters printed
///
static int s2e_printf(const char *format, ...) {
    char buffer[512];
    va_list args;
    int ret;

    va_start(args, format);
    ret = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    s2e_message(buffer);

    return ret;
}

//
// These functions control symbolic and concolic values, allowing you to create symbolic values and concretize them
//

///
/// \brief Fill a buffer with unconstrained symbolic values
///
/// \param[out] buf The buffer to make symbolic
/// \param[in] size The buffer's size
/// \param[in] name A descriptive name for the buffer
///
static inline void s2e_make_symbolic(void *buf, int size, const char *name) {
    __s2e_touch_string(name);
    __s2e_touch_buffer(buf, size);
    __asm__ __volatile__(
        S2E_INSTRUCTION_REGISTERS_SIMPLE(BASE_S2E_MAKE_SYMBOLIC)
        : : "a" (buf), "d" (size), "c" (name) : "memory"
    );
}

///
/// \brief Terminate the currently-executing state
///
/// \param[in] status Exit code
/// \param[in] message The message to print upon exiting
///
static inline void s2e_kill_state(int status, const char *message) {
    __s2e_touch_string(message);
    __asm__ __volatile__(
        S2E_INSTRUCTION_REGISTERS_SIMPLE(BASE_S2E_KILL_STATE)
        : : "a" (status), "d" (message)
    );
}

///
/// \brief Prevent the searcher from switching states unless the current state dies
///
/// \c s2e_end_atomic should be called to reenable the searcher to switch states.
///
static inline void s2e_begin_atomic(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_BEGIN_ATOMIC)
    );
}

///
/// \brief Reenable the searcher to switch states
///
/// Used together with \c s2e_begin_atomic
///
static inline void s2e_end_atomic(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_END_ATOMIC)
    );
}

///
/// \brief Enable all APIC interrupts in the guest
///
static inline void s2e_enable_all_apic_interrupts(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_SET_APIC_INT)
    );
}

///
/// \brief Disable all APIC interrupts in the guest
///
static inline void s2e_disable_all_apic_interrupts(void) {
    __asm__ __volatile__(
        S2E_INSTRUCTION_COMPLEX(BASE_S2E_SET_APIC_INT, 0x01)
    );
}

///
/// \brief Check if a plugin has been loaded
///
/// \param[in] pluginName Name of the plugin to check
/// \return 1 if the plugin is loaded, 0 otherwise
///
static inline int s2e_plugin_loaded(const char *pluginName) {
    int result;
    __s2e_touch_string(pluginName);
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_CHECK_PLUGIN)
        : "=a" (result) : "a" (pluginName)
    );

    return result;
}

///
/// \brief Send data to a given plugin
///
/// \param[in] pluginName The plugin to send the data to
/// \param[in] data The data to send
/// \param[in] dataSize Number of bytes to send
/// \return 0 on success or an error code on failure
///
static inline int s2e_invoke_plugin(const char *pluginName, void *data, uint32_t dataSize) {
    int result;
    __s2e_touch_string(pluginName);
    __s2e_touch_buffer(data, dataSize);
    __asm__ __volatile__(
        S2E_INSTRUCTION_SIMPLE(BASE_S2E_INVOKE_PLUGIN)
        : "=a" (result) : "a" (pluginName), "c" (data), "d" (dataSize) : "memory"
    );

    return result;
}

// clang-format on

#endif
