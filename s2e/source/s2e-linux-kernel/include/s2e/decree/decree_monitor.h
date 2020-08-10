/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2015-2019, Cyberhaven
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
/// THE SOFTWARE.

#ifndef S2E_DECREE_MONITOR_H
#define S2E_DECREE_MONITOR_H

#include <linux/mm.h>
#include <linux/sched.h>

#include <s2e/s2e.h>

#include "commands.h"

/* This is declared in kernel/s2e/vars.c */
extern char s2e_decree_monitor_enabled;

/* TODO: avoid duplication with LinuxMonitor */
static inline void s2e_decree_process_load(pid_t pid, const char *path)
{
	struct S2E_DECREEMON_COMMAND cmd = {0};
	cmd.version = S2E_DECREEMON_COMMAND_VERSION;
	cmd.Command = DECREE_PROCESS_LOAD;
	cmd.currentPid = pid;

	cmd.ProcessLoad.process_path = path;
	s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
}

static inline void s2e_decree_module_load(const char *path, uint64_t pid, uint64_t entry_point,
					  const struct S2E_LINUXMON_PHDR_DESC *phdr, size_t phdr_size)
{
	struct S2E_DECREEMON_COMMAND cmd = {0};
	cmd.version = S2E_DECREEMON_COMMAND_VERSION;
	cmd.Command = DECREE_MODULE_LOAD;
	cmd.currentPid = pid;

	cmd.ModuleLoad.module_path = path;
	cmd.ModuleLoad.entry_point = entry_point;
	cmd.ModuleLoad.phdr = (uintptr_t)phdr;
	cmd.ModuleLoad.phdr_size = phdr_size;

	s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
}

static inline void s2e_decree_segfault(pid_t pid, const char *name, uint64_t pc, uint64_t address, uint64_t fault)
{
	if (s2e_decree_monitor_enabled) {
		struct S2E_DECREEMON_COMMAND cmd = {0};
		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.Command = DECREE_SEGFAULT;
		cmd.currentPid = pid;
		strncpy(cmd.currentName, name, sizeof(cmd.currentName));
		cmd.SegFault.pc = pc;
		cmd.SegFault.address = address;
		cmd.SegFault.fault = fault;

		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
	}
}

static inline void s2e_decree_write_data(pid_t pid, const char *name, int fd, const void *buf, size_t *buf_size,
					 size_t *size_expr)
{
	if (s2e_decree_monitor_enabled) {
		struct S2E_DECREEMON_COMMAND cmd = {0};
		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.Command = DECREE_WRITE_DATA;
		cmd.currentPid = pid;
		strncpy(cmd.currentName, name, sizeof(cmd.currentName));
		cmd.WriteData.fd = fd;
		cmd.WriteData.buffer = (uintptr_t)buf;
		cmd.WriteData.buffer_size_addr = (uintptr_t)buf_size;
		cmd.WriteData.size_expr_addr = (uintptr_t)size_expr;

		__s2e_touch_buffer(buf, *buf_size);
		__s2e_touch_buffer(buf_size, sizeof(*buf_size));
		__s2e_touch_buffer(size_expr, sizeof(*size_expr));
		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
	}
}

static inline void s2e_decree_read_data(pid_t pid, const char *name, int fd, const void *buf, size_t buf_size,
					size_t *size_expr, size_t *res)
{
	if (s2e_decree_monitor_enabled) {
		struct S2E_DECREEMON_COMMAND cmd = {0};
		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.Command = DECREE_READ_DATA;
		cmd.currentPid = pid;
		strncpy(cmd.currentName, name, sizeof(cmd.currentName));
		cmd.Data.fd = fd;
		cmd.Data.buffer = (uintptr_t)buf;
		cmd.Data.buffer_size = buf_size;
		cmd.Data.size_expr_addr = (uintptr_t)size_expr;
		cmd.Data.result_addr = (uintptr_t)res;

		__s2e_touch_buffer(buf, buf_size);
		__s2e_touch_buffer(size_expr, sizeof(*size_expr));
		__s2e_touch_buffer(res, sizeof(*res));
		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
	}
}

static inline void s2e_decree_read_data_post(pid_t pid, const char *name, int fd, const void *buf, size_t buf_size)
{
	if (s2e_decree_monitor_enabled) {
		struct S2E_DECREEMON_COMMAND cmd = {0};
		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.Command = DECREE_READ_DATA_POST;
		cmd.currentPid = pid;
		strncpy(cmd.currentName, name, sizeof(cmd.currentName));
		cmd.DataPost.fd = fd;
		cmd.DataPost.buffer = (uintptr_t)buf;
		cmd.DataPost.buffer_size = buf_size;

		__s2e_touch_buffer(buf, buf_size);
		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
	}
}

static inline int s2e_decree_waitfds(pid_t pid, const char *name, int nfds, int has_timeout, uint64_t tv_sec,
				     uint64_t tv_nsec, int *invoke_orig)
{
	if (s2e_decree_monitor_enabled) {
		struct S2E_DECREEMON_COMMAND cmd = {0};
		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.Command = DECREE_FD_WAIT;
		cmd.currentPid = pid;
		strncpy(cmd.currentName, name, sizeof(cmd.currentName));
		cmd.FDWait.has_timeout = has_timeout;
		cmd.FDWait.tv_sec = tv_sec;
		cmd.FDWait.tv_nsec = tv_nsec;
		cmd.FDWait.nfds = nfds;
		cmd.FDWait.invoke_orig = *invoke_orig;
		cmd.FDWait.result = nfds;

		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));

		*invoke_orig = cmd.FDWait.invoke_orig;

		return cmd.FDWait.result;
	} else {
		return 0;
	}
}

static inline void s2e_decree_random(pid_t pid, const char *name, void *buf, size_t buf_size)
{
	if (s2e_decree_monitor_enabled) {
		struct S2E_DECREEMON_COMMAND cmd = {0};
		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.Command = DECREE_RANDOM;
		cmd.currentPid = pid;
		strncpy(cmd.currentName, name, sizeof(cmd.currentName));
		cmd.Random.buffer = (uintptr_t)buf;
		cmd.Random.buffer_size = buf_size;

		__s2e_touch_buffer(buf, buf_size);
		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
	}
}

static inline int s2e_get_cfg_bool(pid_t pid, const char *name, char *key)
{
	if (s2e_decree_monitor_enabled) {
		struct S2E_DECREEMON_COMMAND cmd = {0};
		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.Command = DECREE_GET_CFG_BOOL;
		cmd.currentPid = pid;
		strncpy(cmd.currentName, name, sizeof(cmd.currentName));
		cmd.GetCfgBool.key_addr = (uintptr_t)key;

		__s2e_touch_string(key);
		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));

		return cmd.GetCfgBool.value;
	} else {
		return 1;
	}
}

static inline void s2e_decree_handle_symbolic_allocate_size(pid_t pid, const char *name, unsigned long *size)
{
	if (s2e_decree_monitor_enabled) {
		struct S2E_DECREEMON_COMMAND cmd = {0};
		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.Command = DECREE_HANDLE_SYMBOLIC_ALLOCATE_SIZE;
		cmd.currentPid = pid;
		strncpy(cmd.currentName, name, sizeof(cmd.currentName));
		cmd.SymbolicSize.size_addr = (uintptr_t)size;

		__s2e_touch_buffer(size, sizeof(*size));
		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
	}
}

static inline void s2e_decree_handle_symbolic_transmit_buffer(pid_t pid, const char *name, void **buf, size_t *size)
{
	if (s2e_decree_monitor_enabled) {
		struct S2E_DECREEMON_COMMAND cmd = {0};
		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.Command = DECREE_HANDLE_SYMBOLIC_TRANSMIT_BUFFER;
		cmd.currentPid = pid;
		strncpy(cmd.currentName, name, sizeof(cmd.currentName));
		cmd.SymbolicBuffer.ptr_addr = (uintptr_t)buf;
		cmd.SymbolicBuffer.size_addr = (uintptr_t)size;

		__s2e_touch_buffer(buf, sizeof(*buf));
		__s2e_touch_buffer(size, sizeof(*size));
		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
	}
}

static inline void s2e_decree_handle_symbolic_receive_buffer(pid_t pid, const char *name, void **buf, size_t *size)
{
	if (s2e_decree_monitor_enabled) {
		struct S2E_DECREEMON_COMMAND cmd = {0};
		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.Command = DECREE_HANDLE_SYMBOLIC_RECEIVE_BUFFER;
		cmd.currentPid = pid;
		strncpy(cmd.currentName, name, sizeof(cmd.currentName));
		cmd.SymbolicBuffer.ptr_addr = (uintptr_t)buf;
		cmd.SymbolicBuffer.size_addr = (uintptr_t)size;

		__s2e_touch_buffer(buf, sizeof(*buf));
		__s2e_touch_buffer(size, sizeof(*size));
		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
	}
}

static inline void s2e_decree_handle_symbolic_random_buffer(pid_t pid, const char *name, void **buf, size_t *size)
{
	if (s2e_decree_monitor_enabled) {
		struct S2E_DECREEMON_COMMAND cmd = {0};
		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.Command = DECREE_HANDLE_SYMBOLIC_RANDOM_BUFFER;
		cmd.currentPid = pid;
		strncpy(cmd.currentName, name, sizeof(cmd.currentName));
		cmd.SymbolicBuffer.ptr_addr = (uintptr_t)buf;
		cmd.SymbolicBuffer.size_addr = (uintptr_t)size;

		__s2e_touch_buffer(buf, sizeof(*buf));
		__s2e_touch_buffer(size, sizeof(*size));
		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
	}
}

static inline void s2e_decree_copy_to_user(pid_t pid, const char *name, void *to, const void *from, long n, int done,
					   long ret)
{
	if (s2e_decree_monitor_enabled) {
		struct S2E_DECREEMON_COMMAND cmd = {0};
		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.Command = DECREE_COPY_TO_USER;
		cmd.currentPid = pid;
		strncpy(cmd.currentName, name, sizeof(cmd.currentName));
		cmd.CopyToUser.user_addr = (uintptr_t)to;
		cmd.CopyToUser.addr = (uintptr_t)from;
		cmd.CopyToUser.count = (uintptr_t)n;
		cmd.CopyToUser.done = done;
		cmd.CopyToUser.ret = ret;

		if (done && ret > 0) {
			__s2e_touch_buffer(to, ret);
			__s2e_touch_buffer(from, ret);
		}
		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
	}
}

static inline uint64_t s2e_vm_flags(unsigned long vm_flags)
{
	uint64_t f = 0;
	if (vm_flags & VM_READ) {
		f |= S2E_DECREEMON_VM_READ;
	}
	if (vm_flags & VM_WRITE) {
		f |= S2E_DECREEMON_VM_WRITE;
	}
	if (vm_flags & VM_EXEC) {
		f |= S2E_DECREEMON_VM_EXEC;
	}
	return f;
}

static inline void s2e_decree_update_memory_map(pid_t pid, const char *name, struct mm_struct *mm)
{
	if (s2e_decree_monitor_enabled) {
		int vm_count, i;
		struct vm_area_struct *vma;
		struct S2E_DECREEMON_VMA *data;
		struct S2E_DECREEMON_COMMAND cmd = {0};

		down_read(&mm->mmap_sem);
		vm_count = 0;
		for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
			vm_count++;
		}
		up_read(&mm->mmap_sem);

		data = kmalloc(vm_count * sizeof(struct S2E_DECREEMON_VMA), GFP_KERNEL);
		if (!data) {
			s2e_message("Could not allocate memory for memory map\n");
			return;
		}

		down_read(&mm->mmap_sem);
		for (vma = mm->mmap, i = 0; vma != NULL; vma = vma->vm_next, i++) {
			data[i].start = vma->vm_start;
			data[i].end = vma->vm_end;
			data[i].flags = s2e_vm_flags(vma->vm_flags);
		}
		up_read(&mm->mmap_sem);

		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.Command = DECREE_UPDATE_MEMORY_MAP;
		cmd.currentPid = pid;
		strncpy(cmd.currentName, name, sizeof(cmd.currentName));
		cmd.UpdateMemoryMap.count = vm_count;
		cmd.UpdateMemoryMap.buffer = (uintptr_t)data;

		__s2e_touch_buffer(data, vm_count * sizeof(struct S2E_DECREEMON_VMA));
		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));

		kfree(data);
	}
}

static inline void s2e_decree_do_set_args(pid_t pid, const char *name,
					  struct S2E_DECREEMON_COMMAND_SET_CB_PARAMS *params)
{
	if (s2e_decree_monitor_enabled) {
		struct S2E_DECREEMON_COMMAND cmd = {0};

		cmd.Command = DECREE_SET_CB_PARAMS;
		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.currentPid = pid;
		strncpy(cmd.currentName, name, sizeof(cmd.currentName));

		cmd.CbParams = *params;

		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
		/* Copy results back */
		*params = cmd.CbParams;
	}
}

static inline void s2e_decree_init(uint64_t page_offset, uint64_t start_kernel, uint64_t task_struct_pid_offset)
{
	if (s2e_decree_monitor_enabled) {
		struct S2E_DECREEMON_COMMAND cmd = {0};

		cmd.Command = DECREE_INIT;
		cmd.version = S2E_DECREEMON_COMMAND_VERSION;
		cmd.currentPid = -1;
		cmd.Init.page_offset = page_offset;
		cmd.Init.start_kernel = start_kernel;
		cmd.Init.task_struct_pid_offset = task_struct_pid_offset;

		s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
	}
}

static inline void s2e_decree_kernel_panic(const char *msg, unsigned msg_size)
{
	struct S2E_DECREEMON_COMMAND cmd = {0};
	cmd.version = S2E_DECREEMON_COMMAND_VERSION;
	cmd.Command = DECREE_KERNEL_PANIC;
	cmd.currentPid = -1;
	cmd.Panic.message = (uintptr_t)msg;
	cmd.Panic.message_size = msg_size;

	s2e_invoke_plugin("DecreeMonitor", &cmd, sizeof(cmd));
}

#endif
