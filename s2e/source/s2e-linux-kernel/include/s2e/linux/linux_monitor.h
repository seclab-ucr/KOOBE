/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2017, Dependable Systems Laboratory, EPFL
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to
/// deal in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
/// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
/// THE OFTWARE.

#ifndef S2E_LINUX_MONITOR_H
#define S2E_LINUX_MONITOR_H

#include <linux/sched.h>

#include <s2e/s2e.h>

#include "commands.h"

/* These are declared in kernel/s2e/vars.c */
extern char s2e_linux_monitor_enabled;
extern struct task_struct *s2e_current_task;

static inline void s2e_linux_process_load(pid_t pid, const char *path)
{
	struct S2E_LINUXMON_COMMAND cmd = {0};
	cmd.version = S2E_LINUXMON_COMMAND_VERSION;
	cmd.Command = LINUX_PROCESS_LOAD;
	cmd.currentPid = pid;

	cmd.ProcessLoad.process_path = path;
	s2e_invoke_plugin("LinuxMonitor", &cmd, sizeof(cmd));
}

static inline void s2e_linux_module_load(const char *path, uint64_t pid, uint64_t entry_point,
					 const struct S2E_LINUXMON_PHDR_DESC *phdr, size_t phdr_size)
{
	struct S2E_LINUXMON_COMMAND cmd = {0};
	cmd.version = S2E_LINUXMON_COMMAND_VERSION;
	cmd.Command = LINUX_MODULE_LOAD;
	cmd.currentPid = pid;

	cmd.ModuleLoad.module_path = path;
	cmd.ModuleLoad.entry_point = entry_point;
	cmd.ModuleLoad.phdr = (uintptr_t)phdr;
	cmd.ModuleLoad.phdr_size = phdr_size;

	s2e_invoke_plugin("LinuxMonitor", &cmd, sizeof(cmd));
}

static inline void s2e_linux_segfault(pid_t pid, uint64_t pc, uint64_t address, uint64_t fault)
{
	struct S2E_LINUXMON_COMMAND cmd = {0};
	cmd.version = S2E_LINUXMON_COMMAND_VERSION;
	cmd.Command = LINUX_SEGFAULT;
	cmd.currentPid = pid;
	cmd.SegFault.pc = pc;
	cmd.SegFault.address = address;
	cmd.SegFault.fault = fault;

	s2e_invoke_plugin("LinuxMonitor", &cmd, sizeof(cmd));
}

static inline void s2e_linux_trap(pid_t pid, uint64_t pc, int trapnr, int signr, long error_code)
{
	struct S2E_LINUXMON_COMMAND cmd = {0};
	cmd.version = S2E_LINUXMON_COMMAND_VERSION;
	cmd.Command = LINUX_TRAP;
	cmd.currentPid = pid;

	cmd.Trap.pc = pc;
	cmd.Trap.trapnr = trapnr;
	cmd.Trap.signr = signr;
	cmd.Trap.error_code = error_code;

	s2e_invoke_plugin("LinuxMonitor", &cmd, sizeof(cmd));
}

static inline void s2e_linux_process_exit(pid_t pid, uint64_t code)
{
	struct S2E_LINUXMON_COMMAND cmd = {0};
	cmd.version = S2E_LINUXMON_COMMAND_VERSION;
	cmd.Command = LINUX_PROCESS_EXIT;
	cmd.currentPid = pid;
	cmd.ProcessExit.code = code;

	s2e_invoke_plugin("LinuxMonitor", &cmd, sizeof(cmd));
}

static inline void s2e_linux_init(uint64_t page_offset, uint64_t start_kernel, uint64_t current_task_address,
				  uint64_t task_struct_pid_offset, uint64_t task_struct_tgid_offset)
{
	struct S2E_LINUXMON_COMMAND cmd = {0};
	cmd.version = S2E_LINUXMON_COMMAND_VERSION;
	cmd.Command = LINUX_INIT;
	cmd.currentPid = -1;
	cmd.Init.page_offset = page_offset;
	cmd.Init.start_kernel = start_kernel;
	cmd.Init.current_task_address = current_task_address;
	cmd.Init.task_struct_pid_offset = task_struct_pid_offset;
	cmd.Init.task_struct_tgid_offset = task_struct_tgid_offset;

	s2e_invoke_plugin("LinuxMonitor", &cmd, sizeof(cmd));
}

static inline void s2e_linux_kernel_panic(const char *msg, unsigned msg_size)
{
	struct S2E_LINUXMON_COMMAND cmd = {0};
	cmd.version = S2E_LINUXMON_COMMAND_VERSION;
	cmd.Command = LINUX_KERNEL_PANIC;
	cmd.currentPid = -1;
	cmd.Panic.message = (uintptr_t)msg;
	cmd.Panic.message_size = msg_size;

	s2e_invoke_plugin("LinuxMonitor", &cmd, sizeof(cmd));
}

static inline void s2e_linux_mmap(pid_t pid, unsigned long addr, unsigned long len, unsigned long prot,
				  unsigned long flag, unsigned long pgoff)
{
	struct S2E_LINUXMON_COMMAND cmd = {0};
	cmd.version = S2E_LINUXMON_COMMAND_VERSION;
	cmd.Command = LINUX_MEMORY_MAP;
	cmd.currentPid = pid;
	cmd.MemMap.address = addr;
	cmd.MemMap.size = len;
	cmd.MemMap.prot = prot;
	cmd.MemMap.flag = flag;
	cmd.MemMap.pgoff = pgoff;

	s2e_invoke_plugin("LinuxMonitor", &cmd, sizeof(cmd));
}

static inline void s2e_linux_unmap(pid_t pid, unsigned long start, unsigned long end)
{
	struct S2E_LINUXMON_COMMAND cmd = {0};
	cmd.version = S2E_LINUXMON_COMMAND_VERSION;
	cmd.Command = LINUX_MEMORY_UNMAP;
	cmd.currentPid = pid;
	cmd.MemUnmap.start = start;
	cmd.MemUnmap.end = end;

	s2e_invoke_plugin("LinuxMonitor", &cmd, sizeof(cmd));
}

static inline void s2e_linux_mprotect(pid_t pid, unsigned long start, unsigned long len, unsigned long prot)
{
	struct S2E_LINUXMON_COMMAND cmd = {0};
	cmd.version = S2E_LINUXMON_COMMAND_VERSION;
	cmd.Command = LINUX_MEMORY_PROTECT;
	cmd.currentPid = pid;
	cmd.MemProtect.start = start;
	cmd.MemProtect.size = len;
	cmd.MemProtect.prot = prot;

	s2e_invoke_plugin("LinuxMonitor", &cmd, sizeof(cmd));
}

#endif
