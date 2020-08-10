/*
 * linux/fs/binfmt_cgc.c
 * Copyright (c) 2014 Jason L. Wright (jason@thought.net)
 *
 * Functions/module to load binaries targetting the DARPA Cyber Grand Challenge.
 * CGCOS binaries most thoroughly resemble static ELF binaries, thus this
 * code is derived from:
 *
 * linux/fs/binfmt_elf.c
 *
 * These are the functions used to load ELF format executables as used
 * on SVr4 machines.  Information on the format may be found in the book
 * "UNIX SYSTEM V RELEASE 4 Programmers Guide: Ansi C and Programming Support
 * Tools".
 *
 * Copyright 1993, 1994: Eric Youngdale (ericy@cais.com).
 */

#include <asm/page.h>
#include <asm/param.h>
#include <asm/uaccess.h>
#include <crypto/algapi.h>
#include <crypto/rng.h>
#include <linux/binfmts.h>
#include <linux/compiler.h>
#include <linux/coredump.h>
#include <linux/elf.h>
#include <linux/elfcore.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/highuid.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/personality.h>
#include <linux/ptrace.h>
#include <linux/random.h>
#include <linux/regset.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/utsname.h>
#include <linux/vmalloc.h>

#include <s2e/decree/decree_monitor.h>
#include <s2e/s2e.h>

#ifndef user_long_t
#define user_long_t long
#endif
#ifndef user_siginfo_t
#define user_siginfo_t siginfo_t
#endif

#ifndef PR_REG_SIZE
#define PR_REG_SIZE(S) sizeof(S)
#endif

#ifndef PRSTATUS_SIZE
#define PRSTATUS_SIZE(S) sizeof(S)
#endif

#ifndef PR_REG_PTR
#define PR_REG_PTR(S) (&((S)->pr_reg))
#endif

#ifndef SET_PR_FPVALID
#define SET_PR_FPVALID(S, V) ((S)->pr_fpvalid = (V))
#endif

#if 0
#define DEBUG_CGC
#endif

#define CGC_MAGIC_PAGE 0x4347c000
#define CGC_MIN_PAGE_SIZE 4096
#define CGC_MIN_ALIGN CGC_MIN_PAGE_SIZE

#define CGC_PAGESTART(_v) ((_v) & ~(unsigned long)(CGC_MIN_ALIGN - 1))
#define CGC_PAGEOFFSET(_v) ((_v) & (CGC_MIN_ALIGN - 1))
#define CGC_PAGEALIGN(_v) (((_v) + CGC_MIN_ALIGN - 1) & ~(CGC_MIN_ALIGN - 1))

struct cgc_params {
	int skip_rng;
};

static int load_cgcos_binary(struct linux_binprm *);
static int cgc_core_dump(struct coredump_params *);
static int cgc_parse_args(struct linux_binprm *, struct cgc_params *);
static int cgc_parse_arg(struct linux_binprm *, const char *,
			 struct cgc_params *);

static void s2e_decree_set_args(int *skip_rng);

static int flag_relaxed_headers __read_mostly = 0;

/* The CGC Executable File Header */
#define CI_NIDENT 16
typedef struct CGC32_hdr {
	uint8_t ci_mag0;    /* 0x7f */
	uint8_t ci_mag1;    /* 'C' */
	uint8_t ci_mag2;    /* 'G' */
	uint8_t ci_mag3;    /* 'C' */
	uint8_t ci_class;   /* 1 */
	uint8_t ci_data;    /* 1 */
	uint8_t ci_version; /* 1 */
	uint8_t ci_osabi;   /* 'C' */
	uint8_t ci_abivers; /* 1 */
	uint8_t ci_pad[7];
	uint16_t c_type;      /* Must be 2 for executable */
	uint16_t c_machine;   /* Must be 3 for i386 */
	uint32_t c_version;   /* Must be 1 */
	uint32_t c_entry;     /* Entry point */
	uint32_t c_phoff;     /* Program Header offset */
	uint32_t c_shoff;     /* Section Header offset */
	uint32_t c_flags;     /* Must be 0 */
	uint16_t c_ehsize;    /* CGC header's size */
	uint16_t c_phentsize; /* Program header entry size */
	uint16_t c_phnum;     /* # program header entries */
	uint16_t c_shentsize; /* Section header entry size */
	uint16_t c_shnum;     /* # section header entries */
	uint16_t c_shstrndx;  /* sect header # of str table */
} CGC32_hdr;

/* The CGC Executable Program Header */
typedef struct CGC32_phdr {
	uint32_t p_type;      /* Section type */
#define PT_NULL 0	     /* Unused header */
#define PT_LOAD 1	     /* Segment is loaded into mem */
#define PT_PHDR 6	     /* Program header tbl itself */
#define PT_CGCPOV2 0x6ccccccc /* CFE Type 2 PoV flag sect */
	uint32_t p_offset;    /* Offset into the file */
	uint32_t p_vaddr;     /* Virtial program address */
	uint32_t p_paddr;     /* Set to zero */
	uint32_t p_filesz;    /* Section bytes in the file */
	uint32_t p_memsz;     /* Section bytes in memory */
	uint32_t p_flags;     /* section flags */
#define CPF_X (1 << 0)	/* Mapped executable */
#define CPF_W (1 << 1)	/* Mapped writeable */
#define CPF_R (1 << 2)	/* Mapped readable */
	/* Acceptable flag combinations are:
	 *	CPF_R
	 *	CPF_R|CPF_W
	 *	CPF_R|CPF_X
	 *	CPF_R|CPF_W|CPF_X
	 */

	uint32_t p_align; /* Bytes at which to align the
			   * section in memory.
			   * 0 or 1:	no alignment
			   * 4:		32bit alignment
			   * 4096:	page alignment
			   */
} CGC32_Phdr;

static struct linux_binfmt cgcos_format = {
	.module = THIS_MODULE,
	.load_binary = load_cgcos_binary,
	.load_shlib = NULL,
	.core_dump = cgc_core_dump,
	.min_coredump = PAGE_SIZE,
};

#define BAD_ADDR(x) ((unsigned long)(x) >= TASK_SIZE)

static unsigned long cgc_map(struct file *filep, struct CGC32_phdr *phdr,
			     int prot, int type,
			     struct S2E_LINUXMON_COMMAND_MEMORY_MAP *mmap_desc);
static int set_brk(unsigned long, unsigned long);
static int padzero(unsigned long);
static unsigned long vma_dump_size(struct vm_area_struct *, unsigned long);

struct memelfnote {
	const char *name;
	int type;
	unsigned int datasz;
	void *data;
};

struct elf_note_info {
	struct elf_thread_core_info *thread;
	struct memelfnote psinfo;
	struct memelfnote signote;
	struct memelfnote auxv;
	struct memelfnote files;
	user_siginfo_t csigdata;
	size_t size;
	int thread_notes;
};

struct elf_thread_core_info {
	struct elf_thread_core_info *next;
	struct task_struct *task;
	struct elf_prstatus prstatus;
	struct memelfnote notes[0];
};

static int fill_note_info(struct elfhdr *, int, struct elf_note_info *,
			  const siginfo_t *, struct pt_regs *);
static size_t get_note_info_size(struct elf_note_info *);
static int write_note_info(struct elf_note_info *, struct coredump_params *);
static int writenote(struct memelfnote *, struct coredump_params *);
static void fill_elf_note_phdr(struct elf_phdr *, int, loff_t);
static void fill_note(struct memelfnote *, const char *, int, unsigned int,
		      void *);
static void fill_elf_header(struct elfhdr *, int, u16, u32);
static int fill_thread_core_info(struct elf_thread_core_info *,
				 const struct user_regset_view *, long,
				 size_t *);
static void fill_prstatus(struct elf_prstatus *, struct task_struct *, long);
static int notesize(struct memelfnote *);
static int fill_psinfo(struct elf_prpsinfo *, struct task_struct *,
		       struct mm_struct *);
static void fill_auxv_note(struct memelfnote *, struct mm_struct *);
static void fill_siginfo_note(struct memelfnote *, user_siginfo_t *,
			      const siginfo_t *);
static void do_thread_regset_writeback(struct task_struct *,
				       const struct user_regset *);
static int fill_files_note(struct memelfnote *);
static void free_note_info(struct elf_note_info *);

static int load_cgcos_binary(struct linux_binprm *bprm)
{
	struct CGC32_hdr hdr;
	int ret = -ENOEXEC, i;
	struct CGC32_phdr *phdrs = NULL;
	struct S2E_LINUXMON_PHDR_DESC *elf_phdr = NULL;
	size_t elf_phdr_size;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned int sz;
	struct pt_regs *regs = current_pt_regs();
	unsigned long bss, brk;
	struct cgc_params pars;

	if (s2e_decree_monitor_enabled) {
		s2e_decree_process_load(current->pid, bprm->interp);
	}

	memset(&pars, 0, sizeof(pars));

	if (sizeof(hdr) > BINPRM_BUF_SIZE) {
		ret = kernel_read(bprm->file, 0, (char *)&hdr, sizeof(hdr));
		if (ret != sizeof(hdr)) {
			if (ret >= 0)
				ret = -EIO;
			goto out;
		}
	} else
		memcpy(&hdr, bprm->buf, sizeof(hdr));

	if (hdr.ci_mag0 != 0x7f || hdr.ci_mag1 != 'C' || hdr.ci_mag2 != 'G' ||
	    hdr.ci_mag3 != 'C' || hdr.ci_class != 1 || hdr.ci_data != 1 ||
	    hdr.ci_version != 1 || hdr.ci_osabi != 'C' || hdr.ci_abivers != 1 ||
	    hdr.c_type != 2 || hdr.c_machine != 3 || hdr.c_version != 1 ||
	    hdr.c_flags != 0 || hdr.c_phentsize != sizeof(struct CGC32_phdr) ||
	    hdr.c_phnum < 1 || hdr.c_phnum > 65536U / sizeof(struct CGC32_phdr))
		goto out;

	if (!bprm->file->f_op->mmap)
		goto out;

	sz = hdr.c_phnum * sizeof(struct CGC32_phdr);
	phdrs = kmalloc(sz, GFP_KERNEL);
	if (!phdrs) {
		ret = -ENOMEM;
		goto out;
	}

	elf_phdr_size = sizeof(*elf_phdr) * hdr.c_phnum;
	elf_phdr = kmalloc(elf_phdr_size, GFP_KERNEL);
	if (!elf_phdr) {
		ret = -ENOMEM;
		goto out;
	}

	memset(elf_phdr, 0, elf_phdr_size);

	ret = kernel_read(bprm->file, hdr.c_phoff, (char *)phdrs, sz);
	if (ret != sz) {
		if (ret >= 0)
			ret = -EIO;
		goto out;
	}

	current->cgc_max_transmit = 0;
	current->cgc_max_receive = 0;

	/* need to parse the arguments  */
	if ((ret = cgc_parse_args(bprm, &pars)) != 0)
		goto out;

	if ((ret = flush_old_exec(bprm)) != 0)
		goto out;

	/**
	 * notify S2E about the args that have been set,
	 * and give a chance to override them
	 */
	s2e_decree_set_args(&pars.skip_rng);

	/* point of no return */
	current->mm->def_flags = 0;

	current->personality = PER_CGCOS;

	{
		struct rlimit new_rlim = {8 * 1024 * 1024, 8 * 1024 * 1024};
		do_prlimit(current, RLIMIT_STACK, &new_rlim, NULL);
	}

	setup_new_exec(bprm);

	if ((ret = setup_arg_pages(bprm, 0xbaaab000, EXSTACK_ENABLE_X)) < 0)
		goto out_kill;

	current->mm->start_stack = bprm->p;

	current->signal->maxrss = 0;
	current->min_flt = current->signal->min_flt = 0;

	bss = brk = 0;
	start_code = ~0UL;
	end_code = start_data = end_data = 0;

	for (i = 0; i < hdr.c_phnum; i++) {
		struct CGC32_phdr *phdr = &phdrs[i];

		int prot, flags;
		unsigned long k;

		struct S2E_LINUXMON_PHDR_DESC *s2e_ppnt = &elf_phdr[i];
		s2e_ppnt->index = i;
		s2e_ppnt->vma = 0;
		s2e_ppnt->p_type = phdr->p_type;
		s2e_ppnt->p_offset = phdr->p_offset;
		s2e_ppnt->p_vaddr = phdr->p_vaddr;
		s2e_ppnt->p_paddr = phdr->p_paddr;
		s2e_ppnt->p_filesz = phdr->p_filesz;
		s2e_ppnt->p_memsz = phdr->p_memsz;
		s2e_ppnt->p_flags = phdr->p_flags;
		s2e_ppnt->p_align = phdr->p_align;

		switch (phdr->p_type) {
		case PT_NULL:
		case PT_LOAD:
		case PT_PHDR:
		case PT_CGCPOV2:
			break;
		default:
			printk(KERN_INFO "invalid phdr->p_type 0x%x\n",
			       phdr->p_type);
			ret = -ENOEXEC;
			if (unlikely(flag_relaxed_headers))
				continue;
			else
				goto out_kill;
		}

		if (phdr->p_type != PT_LOAD || phdr->p_memsz == 0)
			continue;

		prot = 0;
		if (phdr->p_flags & CPF_R)
			prot |= PROT_READ;
		else {
			ret = -EINVAL;
			goto out_kill;
		}

		if (phdr->p_flags & CPF_W)
			prot |= PROT_WRITE;
		if (phdr->p_flags & CPF_X)
			prot |= PROT_EXEC;

		flags = MAP_PRIVATE | MAP_DENYWRITE | MAP_FIXED;

		if (phdr->p_vaddr < start_code)
			start_code = phdr->p_vaddr;
		if (start_data < phdr->p_vaddr)
			start_data = phdr->p_vaddr;

		/*
		 * Check to see if the section's size will overflow the
		 * allowed task size. Note that p_filesz must always be
		 * <= p_memsz so it is only necessary to check p_memsz.
		 */
		if (BAD_ADDR(phdr->p_vaddr) || phdr->p_filesz > phdr->p_memsz ||
		    phdr->p_memsz > TASK_SIZE ||
		    TASK_SIZE - phdr->p_memsz < phdr->p_vaddr) {
			/* set_brk can never work. avoid overflows. */
			ret = -EINVAL;
			goto out_kill;
		}

		k = cgc_map(bprm->file, phdr, prot, flags, &s2e_ppnt->mmap);
		if (BAD_ADDR(k)) {
			ret = IS_ERR((void *)k) ? PTR_ERR((void *)k) : -EINVAL;
			goto out_kill;
		}

		s2e_ppnt->vma = k;

		k = phdr->p_vaddr + phdr->p_filesz;
		if (k > bss)
			bss = k;
		if ((phdr->p_flags & CPF_X) && end_code < k)
			end_code = k;
		if (end_data < k)
			end_data = k;

		k = phdr->p_vaddr + phdr->p_memsz;
		if (k > brk)
			brk = k;
	}

	/* We deal with zero'd regions in cgc_map() */
	bss = brk;

	/* Calling set_brk effectively mmaps the pages that we need
	 * for the bss and break sections.
	 */
	ret = set_brk(bss, brk);
	if (ret) {
		send_sig(SIGKILL, current, 0);
		goto out;
	}
	if (likely(bss != brk) && unlikely(padzero(bss))) {
		send_sig(SIGSEGV, current, 0);
		ret = -EFAULT; /* Nobody gets to see this, but.. */
		goto out;
	}

	if (BAD_ADDR(hdr.c_entry)) {
		force_sig(SIGSEGV, current);
		ret = -EINVAL;
		goto out;
	}

	set_binfmt(&cgcos_format);
	install_exec_creds(bprm);

	/* N.B. passed_fileno might not be initialized? */
	current->mm->arg_end = current->mm->arg_start;
	current->mm->end_code = end_code;
	current->mm->start_code = start_code;
	current->mm->start_data = start_data;
	current->mm->end_data = end_data;
	current->mm->start_stack = bprm->p;

	{
		int cpu = get_cpu();

		for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++) {
			current->thread.tls_array[i].a = 0;
			current->thread.tls_array[i].b = 0;
		}
		load_TLS(&current->thread, cpu);
		put_cpu();
	}

#ifdef ELF_PLAT_INIT
	/*
	 * The ABI may specify that certain registers be set up in special
	 * ways (on i386 %edx is the address of a DT_FINI function, for
	 * example.  In addition, it may also specify (eg, PowerPC64 ELF)
	 * that the e_entry field is the address of the function descriptor
	 * for the startup routine, rather than the address of the startup
	 * routine itself.  This macro performs whatever initialization to
	 * the regs structure is required as well as any relocations to the
	 * function descriptor entries when executing dynamically links apps.
	 */
	ELF_PLAT_INIT(regs, reloc_func_desc);
#endif

	disable_TSC();
	disable_PCE();

	{
		unsigned long addr, i, v;
		struct vm_area_struct *vma;

		ret = 0;
		down_read(&current->mm->mmap_sem);
		vma = find_vma(current->mm, CGC_MAGIC_PAGE);
		if (vma != NULL && vma->vm_start <= CGC_MAGIC_PAGE)
			ret = -EFAULT;
		up_read(&current->mm->mmap_sem);
		if (ret != 0)
			goto out_kill;

		addr = vm_mmap(
			NULL, CGC_MAGIC_PAGE, PAGE_SIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_FIXED,
			0);
		if (BAD_ADDR(addr)) {
			ret = -EFAULT;
			goto out_kill;
		}

		for (i = 0; i < PAGE_SIZE; i += sizeof(v)) {
			if (current->cgc_rng) {
				ret = crypto_rng_get_bytes(current->cgc_rng,
							   (u8 *)&v, sizeof(v));
				if (ret < 0)
					goto out_kill;
			} else
				get_random_bytes(&v, sizeof(v));

			if (copy_to_user((void __user *)(addr + i), &v,
					 sizeof(v))) {
				ret = -EFAULT;
				goto out_kill;
			}
		}

		/* page finally becomes R/O in image of binary */
		down_write(&current->mm->mmap_sem);
		vma = find_vma(current->mm, addr);
		vma->vm_flags &= ~(VM_WRITE | VM_MAYWRITE | VM_MAYEXEC);
		vma->vm_page_prot = pgprot_modify(vma->vm_page_prot,
						  vm_get_page_prot(VM_READ));
		change_protection(vma, addr, addr + PAGE_SIZE,
				  vma->vm_page_prot, 0, 0);
		up_write(&current->mm->mmap_sem);
		regs->cx = CGC_MAGIC_PAGE;

		while (pars.skip_rng) {
			u8 rnd;

			if (current->cgc_rng) {
				ret = crypto_rng_get_bytes(current->cgc_rng,
							   &rnd, sizeof(rnd));
				if (ret < 0)
					return (ret);
			} else {
				/* there's really no point in this... */
				get_random_bytes(&rnd, sizeof(rnd));
			}

			s2e_printf("skiprng: %#d", rnd);

			pars.skip_rng -= sizeof(rnd);
		}
	}

	flush_signal_handlers(current, 1);
	current->sighand->action[SIGPIPE - 1].sa.sa_handler = SIG_IGN;
	set_dumpable(current->mm, SUID_DUMP_USER);

	start_thread(regs, hdr.c_entry, bprm->p);
	set_user_gs(regs, __USER_DS);
	regs->fs = __USER_DS;
	ret = 0;
out:
	if (ret == 0 && s2e_decree_monitor_enabled) {
		s2e_decree_module_load(bprm->interp, current->pid, hdr.c_entry,
				       elf_phdr, elf_phdr_size);
		s2e_decree_update_memory_map(current->pid, current->comm,
					     current->mm);
	}
	if (phdrs)
		kfree(phdrs);

	if (elf_phdr)
		kfree(elf_phdr);

	return (ret);

out_kill:
	send_sig(SIGKILL, current, 0);
	goto out;
}

/**
 * This function lets DecreeMonitor initialize CB parameters.
 * It is called after the existing command line arguments
 * have been parsed.
 */
static void s2e_decree_set_args(int *skip_rng)
{
	struct S2E_DECREEMON_COMMAND_SET_CB_PARAMS params = {0};

	params.cgc_max_transmit = current->cgc_max_transmit;
	params.cgc_max_receive = current->cgc_max_receive;
	params.skip_rng_count = *skip_rng;
	params.cgc_seed_ptr = (uintptr_t)current->cgc_seed;
	params.cgc_seed_len = current->cgc_seed_len;

	s2e_decree_do_set_args(current->pid, current->comm, &params);

	/* Write back new param values */
	current->cgc_max_transmit = params.cgc_max_transmit;
	current->cgc_max_receive = params.cgc_max_receive;
	*skip_rng = params.skip_rng_count;

	/* Reset random number generator */
	if (params.cgc_seed_len) {
		int ret;

		if (params.cgc_seed_len > sizeof(params.cgc_seed)) {
			s2e_kill_state(-1,
				       "Length of seed exceeds buffer size");
		}

		if (current->cgc_rng) {
			crypto_free_rng(current->cgc_rng);
		}

		current->cgc_rng = crypto_alloc_rng("ansi_cprng", 0, 0);
		if (!current->cgc_rng) {
			s2e_kill_state(-1, "Could not allocate rng");
		}

		ret = crypto_rng_reset(current->cgc_rng, params.cgc_seed,
				       params.cgc_seed_len);
		if (ret < 0) {
			s2e_kill_state(-1, "Could not reset rng");
		}
	}

	/* Don't need the stored seed anymore */
	if (current->cgc_seed) {
		kfree(current->cgc_seed);
		current->cgc_seed_len = 0;
		current->cgc_seed = NULL;
	}
}

static int cgc_parse_args(struct linux_binprm *bprm, struct cgc_params *pars)
{
	int i, err = 0;

	for (i = 1; i < bprm->argc; i++) {
		const char __user *arg;
		char *str;
		int len;

		if (get_user(arg, bprm->argv + i))
			return (-EFAULT);

		len = strnlen_user(arg, MAX_ARG_STRLEN);
		if (len == 0)
			return (-EFAULT);
		if (len > MAX_ARG_STRLEN)
			return (-E2BIG);

		str = kmalloc(len + 1, GFP_KERNEL);
		if (!str)
			return (-ENOMEM);

		if (copy_from_user(str, arg, len)) {
			kfree(str);
			return (-EFAULT);
		}

		str[len] = '\0';
		err = cgc_parse_arg(bprm, str, pars);
		kfree(str);
		if (err)
			break;
	}

	return (err);
}

static int cgc_parse_arg(struct linux_binprm *bprm, const char *arg,
			 struct cgc_params *pars)
{
	const char seed_name[] = "seed=", schedule_name[] = "sched=",
		   skiprng_name[] = "skiprng=",
		   max_transmit_name[] = "max_transmit=",
		   max_receive_name[] = "max_receive=";

	s2e_printf("Parsing arg %s\n", arg);

	/* sched=policy,priority */
	if (strncmp(arg, schedule_name, strlen(schedule_name)) == 0) {
		int args[3];
		char *rs;
		struct sched_param par;

		memset(&par, 0, sizeof(par));
		rs = get_options(arg + strlen(schedule_name),
				 sizeof(args) / sizeof(args[0]), args);

		if (*rs != '\0' || args[0] != 2)
			return (-EINVAL);
		par.sched_priority = args[2];
		return sched_setscheduler_nocheck(current, args[1], &par);
	}

	if (strncmp(arg, seed_name, strlen(seed_name)) == 0) {
		/* create per process rng and seed it */
		char *seed = NULL;
		int seedlen = strlen(arg) - strlen(seed_name);
		int ret = 0;

		/*
		 * This would take care of multiple seed arguments.
		 */
		if (current->cgc_seed) {
			kfree(current->cgc_seed);
			current->cgc_seed = 0;
			current->cgc_seed_len = 0;
		}

		if (current->cgc_rng) {
			crypto_free_rng(current->cgc_rng);
			current->cgc_rng = NULL;
		}

		if (seedlen & 1) {
			ret = -EINVAL;
			goto out_seed;
		}

		seedlen /= 2;
		seed = kmalloc(seedlen, GFP_KERNEL);
		if (seed == NULL) {
			ret = -ENOMEM;
			goto out_seed;
		}

		if (hex2bin(seed, arg + strlen(seed_name), seedlen)) {
			ret = -EINVAL;
			goto out_seed;
		}

		current->cgc_rng = crypto_alloc_rng("ansi_cprng", 0, 0);
		if (current->cgc_rng == NULL) {
			ret = -ENOMEM;
			goto out_seed;
		}

		ret = crypto_rng_reset(current->cgc_rng, seed, seedlen);
		if (ret >= 0)
			ret = 0;

		current->cgc_seed_len = seedlen;
		current->cgc_seed = seed;

		return ret;

	out_seed:
		kfree(seed);
		return (ret);
	}

	/* skiprng=nbytes */
	if (strncmp(arg, skiprng_name, strlen(skiprng_name)) == 0) {
		int args[2];
		char *rs;

		rs = get_options(arg + strlen(skiprng_name),
				 sizeof(args) / sizeof(args[0]), args);

		if (*rs != '\0' || args[0] != 1 || args[1] < 0)
			return (-EINVAL);
		pars->skip_rng = args[1];
		return (0);
	}

	/* max_receive=bytes */
	if (strncmp(arg, max_receive_name, strlen(max_receive_name)) == 0) {
		int args[2];
		char *rs;

		rs = get_options(arg + strlen(max_receive_name),
				 sizeof(args) / sizeof(args[0]), args);

		if (*rs != '\0' || args[0] != 1 || args[1] < 0)
			return (-EINVAL);
		current->cgc_max_receive = args[1];
		return (0);
	}

	/* max_transmit=bytes */
	if (strncmp(arg, max_transmit_name, strlen(max_transmit_name)) == 0) {
		int args[2];
		char *rs;

		rs = get_options(arg + strlen(max_transmit_name),
				 sizeof(args) / sizeof(args[0]), args);

		if (*rs != '\0' || args[0] != 1 || args[1] < 0)
			return (-EINVAL);

		current->cgc_max_transmit = args[1];
		return (0);
	}

	return (0);
}

static int set_brk(unsigned long start, unsigned long end)
{
	start = CGC_PAGEALIGN(start);
	end = CGC_PAGEALIGN(end);
	if (end > start) {
		unsigned long addr;
		addr = vm_brk(start, end - start);
		if (BAD_ADDR(addr))
			return addr;
	}
	current->mm->start_brk = current->mm->brk = end;
	return 0;
}

static unsigned long cgc_map(struct file *filep, struct CGC32_phdr *phdr,
			     int prot, int type,
			     struct S2E_LINUXMON_COMMAND_MEMORY_MAP *mmap_desc)
{
	unsigned long addr, zaddr;
	unsigned long lo, hi;
	unsigned long off = 0;
	unsigned long size = 0;

	if (phdr->p_filesz == 0 && phdr->p_memsz == 0)
		return 0;
	if (phdr->p_filesz > 0) {
		off = CGC_PAGESTART(phdr->p_offset);
		size = CGC_PAGEALIGN(phdr->p_filesz +
				     CGC_PAGEOFFSET(phdr->p_vaddr));
		/* map in the part of the binary corresponding to filesz */
		addr = vm_mmap(filep, CGC_PAGESTART(phdr->p_vaddr), size, prot,
			       type, off);
		if (BAD_ADDR(addr))
			return (addr);
		lo = CGC_PAGEALIGN(phdr->p_vaddr + phdr->p_filesz);
		hi = CGC_PAGEALIGN(phdr->p_vaddr + phdr->p_memsz);
	} else {
		// for 0 filesz, we have to include the first page as bss.
		lo = CGC_PAGESTART(phdr->p_vaddr + phdr->p_filesz);
		hi = CGC_PAGEALIGN(phdr->p_vaddr + phdr->p_memsz);
	}

	/* map anon pages for the rest (no prefault) */
	if ((hi - lo) > 0) {
		off = 0;
		size = hi - lo;
		zaddr = vm_mmap(NULL, lo, size, prot, type | MAP_ANONYMOUS,
				off);
		if (BAD_ADDR(zaddr))
			return (zaddr);
	}

	lo = phdr->p_vaddr + phdr->p_filesz;
	hi = CGC_PAGEALIGN(phdr->p_vaddr + phdr->p_memsz);
	if ((hi - lo) > 0) {
		if (clear_user((void __user *)lo, hi - lo)) {
			/*
			 * This bss-zeroing can fail if the ELF
			 * file specifies odd protections. So
			 * we don't check the return value
			 */
		}
	}

	mmap_desc->address = addr;
	mmap_desc->size = size;
	mmap_desc->prot = prot;
	mmap_desc->flag = type;
	mmap_desc->pgoff = off;

	return (addr);
}

/* We need to explicitly zero any fractional pages
   after the data section (i.e. bss).  This would
   contain the junk from the file that should not
   be in memory
 */
static int padzero(unsigned long bss)
{
	unsigned long nbyte;

	nbyte = CGC_PAGEOFFSET(bss);
	if (nbyte) {
		nbyte = CGC_MIN_ALIGN - nbyte;
		if (clear_user((void __user *)bss, nbyte))
			return -EFAULT;
	}
	return 0;
}

static int cgc_core_dump(struct coredump_params *cprm)
{
	int dumped = 0, reset_fs = 0;
	mm_segment_t fs;
	int segs;
	struct vm_area_struct *vma;
	struct elfhdr *elf = NULL;
	loff_t offset = 0, dataoff;
	struct elf_note_info info = {};
	struct elf_phdr *phdr4note = NULL;
	struct elf_shdr *shdr4extnum = NULL;
	Elf_Half e_phnum;
	elf_addr_t e_shoff;

	elf = kmalloc(sizeof(*elf), GFP_KERNEL);
	if (!elf)
		goto out;

	segs = current->mm->map_count;
	segs += elf_core_extra_phdrs();
	segs++; /* notes section */

	e_phnum = segs > PN_XNUM ? PN_XNUM : segs;

	if (!fill_note_info(elf, e_phnum, &info, cprm->siginfo, cprm->regs))
		goto out;

	dumped = 1;
	fs = get_fs();
	set_fs(KERNEL_DS);
	reset_fs = 1;

	offset += sizeof(*elf);
	offset += segs * sizeof(struct elf_phdr);

	{
		size_t sz = get_note_info_size(&info);

		sz += elf_coredump_extra_notes_size();
		phdr4note = kmalloc(sizeof(*phdr4note), GFP_KERNEL);
		if (!phdr4note)
			goto out;

		fill_elf_note_phdr(phdr4note, sz, offset);
		offset += sz;
	}

	dataoff = offset = roundup(offset, ELF_EXEC_PAGESIZE);

	for (vma = current->mm->mmap; vma != NULL; vma = vma->vm_next)
		offset += vma_dump_size(vma, cprm->mm_flags);

	e_shoff = offset;

	if (e_phnum == PN_XNUM) {
		shdr4extnum = kmalloc(sizeof(*shdr4extnum), GFP_KERNEL);
		if (!shdr4extnum)
			goto out;

		elf->e_shoff = e_shoff;
		elf->e_shentsize = sizeof(*shdr4extnum);
		elf->e_shnum = 1;
		elf->e_shstrndx = SHN_UNDEF;

		memset(shdr4extnum, 0, sizeof(*shdr4extnum));

		shdr4extnum->sh_type = SHT_NULL;
		shdr4extnum->sh_size = elf->e_shnum;
		shdr4extnum->sh_link = elf->e_shstrndx;
		shdr4extnum->sh_info = segs;
	}

	offset = dataoff;

#ifndef EI_ABIVERSION
/* kernel elf.h is missing this defn */
#define EI_ABIVERSION 8
#endif

	elf->e_ident[EI_MAG0] = 0x7f;
	elf->e_ident[EI_MAG1] = 'C';
	elf->e_ident[EI_MAG2] = 'G';
	elf->e_ident[EI_MAG3] = 'C';
	elf->e_ident[EI_OSABI] = 'C';
	elf->e_ident[EI_ABIVERSION] = 1;

	if (!dump_emit(cprm, elf, sizeof(*elf)))
		goto out;

	if (phdr4note && !dump_emit(cprm, phdr4note, sizeof(*phdr4note)))
		goto out;

	/* Write program headers for segments dump */
	for (vma = current->mm->mmap; vma != NULL; vma = vma->vm_next) {
		struct elf_phdr phdr;

		phdr.p_type = PT_LOAD;
		phdr.p_offset = offset;
		phdr.p_vaddr = vma->vm_start;
		phdr.p_paddr = 0;
		phdr.p_filesz = vma_dump_size(vma, cprm->mm_flags);
		phdr.p_memsz = vma->vm_end - vma->vm_start;
		offset += phdr.p_filesz;
		phdr.p_flags = vma->vm_flags & VM_READ ? PF_R : 0;
		if (vma->vm_flags & VM_WRITE)
			phdr.p_flags |= PF_W;
		if (vma->vm_flags & VM_EXEC)
			phdr.p_flags |= PF_X;
		phdr.p_align = ELF_EXEC_PAGESIZE;

		if (!dump_emit(cprm, &phdr, sizeof(phdr)))
			goto out;
	}

	if (!elf_core_write_extra_phdrs(cprm, offset))
		goto out;

	/* write out the notes section */
	if (!write_note_info(&info, cprm))
		goto out;

	if (elf_coredump_extra_notes_write(cprm))
		goto out;

	/* Align to page */
	if (!dump_skip(cprm, dataoff - cprm->written))
		goto out;

	for (vma = current->mm->mmap; vma != NULL; vma = vma->vm_next) {
		unsigned long addr;
		unsigned long end;

		end = vma->vm_start + vma_dump_size(vma, cprm->mm_flags);

		for (addr = vma->vm_start; addr < end; addr += PAGE_SIZE) {
			struct page *page;
			int stop;

			page = get_dump_page(addr);
			if (page) {
				void *kaddr = kmap(page);
				stop = !dump_emit(cprm, kaddr, PAGE_SIZE);
				kunmap(page);
				page_cache_release(page);
			} else
				stop = !dump_skip(cprm, PAGE_SIZE);
			if (stop)
				goto out;
		}
	}

	if (!elf_core_write_extra_data(cprm))
		goto out;

	if (e_phnum == PN_XNUM) {
		if (!dump_emit(cprm, shdr4extnum, sizeof(*shdr4extnum)))
			goto out;
	}

out:
	free_note_info(&info);
	if (reset_fs)
		set_fs(fs);
	if (shdr4extnum)
		kfree(shdr4extnum);
	if (phdr4note)
		kfree(phdr4note);
	if (elf)
		kfree(elf);
	return (dumped);
}

static void free_note_info(struct elf_note_info *info)
{
	struct elf_thread_core_info *threads = info->thread;
	while (threads) {
		unsigned int i;
		struct elf_thread_core_info *t = threads;
		threads = t->next;
		WARN_ON(t->notes[0].data && t->notes[0].data != &t->prstatus);
		for (i = 1; i < info->thread_notes; ++i)
			kfree(t->notes[i].data);
		kfree(t);
	}
	kfree(info->psinfo.data);
	vfree(info->files.data);
}

static void fill_elf_note_phdr(struct elf_phdr *phdr, int sz, loff_t offset)
{
	phdr->p_type = PT_NOTE;
	phdr->p_offset = offset;
	phdr->p_vaddr = 0;
	phdr->p_paddr = 0;
	phdr->p_filesz = sz;
	phdr->p_memsz = 0;
	phdr->p_flags = 0;
	phdr->p_align = 0;
}

static int fill_psinfo(struct elf_prpsinfo *psinfo, struct task_struct *p,
		       struct mm_struct *mm)
{
	const struct cred *cred;
	unsigned int i, len;

	/* first copy the parameters from user space */
	memset(psinfo, 0, sizeof(struct elf_prpsinfo));

	len = mm->arg_end - mm->arg_start;
	if (len >= ELF_PRARGSZ)
		len = ELF_PRARGSZ - 1;
	if (copy_from_user(&psinfo->pr_psargs,
			   (const char __user *)mm->arg_start, len))
		return -EFAULT;
	for (i = 0; i < len; i++)
		if (psinfo->pr_psargs[i] == 0)
			psinfo->pr_psargs[i] = ' ';
	psinfo->pr_psargs[len] = 0;

	rcu_read_lock();
	psinfo->pr_ppid = task_pid_vnr(rcu_dereference(p->real_parent));
	rcu_read_unlock();
	psinfo->pr_pid = task_pid_vnr(p);
	psinfo->pr_pgrp = task_pgrp_vnr(p);
	psinfo->pr_sid = task_session_vnr(p);

	i = p->state ? ffz(~p->state) + 1 : 0;
	psinfo->pr_state = i;
	psinfo->pr_sname = (i > 5) ? '.' : "RSDTZW"[i];
	psinfo->pr_zomb = psinfo->pr_sname == 'Z';
	psinfo->pr_nice = task_nice(p);
	psinfo->pr_flag = p->flags;
	rcu_read_lock();
	cred = __task_cred(p);
	SET_UID(psinfo->pr_uid, from_kuid_munged(cred->user_ns, cred->uid));
	SET_GID(psinfo->pr_gid, from_kgid_munged(cred->user_ns, cred->gid));
	rcu_read_unlock();
	strncpy(psinfo->pr_fname, p->comm, sizeof(psinfo->pr_fname));

	return 0;
}

static void fill_auxv_note(struct memelfnote *note, struct mm_struct *mm)
{
	elf_addr_t *auxv = (elf_addr_t *)mm->saved_auxv;
	int i = 0;
	do
		i += 2;
	while (auxv[i - 2] != AT_NULL);
	fill_note(note, "CORE", NT_AUXV, i * sizeof(elf_addr_t), auxv);
}

static void fill_siginfo_note(struct memelfnote *note, user_siginfo_t *csigdata,
			      const siginfo_t *siginfo)
{
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	copy_siginfo_to_user((user_siginfo_t __user *)csigdata, siginfo);
	set_fs(old_fs);
	fill_note(note, "CORE", NT_SIGINFO, sizeof(*csigdata), csigdata);
}

static void fill_note(struct memelfnote *note, const char *name, int type,
		      unsigned int sz, void *data)
{
	note->name = name;
	note->type = type;
	note->datasz = sz;
	note->data = data;
}

static int notesize(struct memelfnote *en)
{
	int sz;

	sz = sizeof(struct elf_note);
	sz += roundup(strlen(en->name) + 1, 4);
	sz += roundup(en->datasz, 4);

	return sz;
}

static void fill_prstatus(struct elf_prstatus *prstatus, struct task_struct *p,
			  long signr)
{
	prstatus->pr_info.si_signo = prstatus->pr_cursig = signr;
	prstatus->pr_sigpend = p->pending.signal.sig[0];
	prstatus->pr_sighold = p->blocked.sig[0];
	rcu_read_lock();
	prstatus->pr_ppid = task_pid_vnr(rcu_dereference(p->real_parent));
	rcu_read_unlock();
	prstatus->pr_pid = task_pid_vnr(p);
	prstatus->pr_pgrp = task_pgrp_vnr(p);
	prstatus->pr_sid = task_session_vnr(p);
	if (thread_group_leader(p)) {
		struct task_cputime cputime;

		/*
		 * This is the record for the group leader.  It shows the
		 * group-wide total, not its individual thread total.
		 */
		thread_group_cputime(p, &cputime);
		cputime_to_timeval(cputime.utime, &prstatus->pr_utime);
		cputime_to_timeval(cputime.stime, &prstatus->pr_stime);
	} else {
		cputime_t utime, stime;

		task_cputime(p, &utime, &stime);
		cputime_to_timeval(utime, &prstatus->pr_utime);
		cputime_to_timeval(stime, &prstatus->pr_stime);
	}
	cputime_to_timeval(p->signal->cutime, &prstatus->pr_cutime);
	cputime_to_timeval(p->signal->cstime, &prstatus->pr_cstime);
}

static int fill_thread_core_info(struct elf_thread_core_info *t,
				 const struct user_regset_view *view,
				 long signr, size_t *total)
{
	unsigned int i;

	/*
	 * NT_PRSTATUS is the one special case, because the regset data
	 * goes into the pr_reg field inside the note contents, rather
	 * than being the whole note contents.  We fill the reset in here.
	 * We assume that regset 0 is NT_PRSTATUS.
	 */
	fill_prstatus(&t->prstatus, t->task, signr);
	(void)view->regsets[0].get(t->task, &view->regsets[0], 0,
				   PR_REG_SIZE(t->prstatus.pr_reg),
				   PR_REG_PTR(&t->prstatus), NULL);

	fill_note(&t->notes[0], "CORE", NT_PRSTATUS, PRSTATUS_SIZE(t->prstatus),
		  &t->prstatus);
	*total += notesize(&t->notes[0]);

	do_thread_regset_writeback(t->task, &view->regsets[0]);

	/*
	 * Each other regset might generate a note too.  For each regset
	 * that has no core_note_type or is inactive, we leave t->notes[i]
	 * all zero and we'll know to skip writing it later.
	 */
	for (i = 1; i < view->n; ++i) {
		const struct user_regset *regset = &view->regsets[i];
		do_thread_regset_writeback(t->task, regset);
		if (regset->core_note_type && regset->get &&
		    (!regset->active || regset->active(t->task, regset))) {
			int ret;
			size_t size = regset->n * regset->size;
			void *data = kmalloc(size, GFP_KERNEL);
			if (unlikely(!data))
				return 0;
			ret = regset->get(t->task, regset, 0, size, data, NULL);
			if (unlikely(ret))
				kfree(data);
			else {
				if (regset->core_note_type != NT_PRFPREG)
					fill_note(&t->notes[i], "LINUX",
						  regset->core_note_type, size,
						  data);
				else {
					SET_PR_FPVALID(&t->prstatus, 1);
					fill_note(&t->notes[i], "CORE",
						  NT_PRFPREG, size, data);
				}
				*total += notesize(&t->notes[i]);
			}
		}
	}

	return 1;
}

static int fill_note_info(struct elfhdr *elf, int phdrs,
			  struct elf_note_info *info, const siginfo_t *siginfo,
			  struct pt_regs *regs)
{
	struct task_struct *dump_task = current;
	const struct user_regset_view *view = task_user_regset_view(dump_task);
	struct elf_thread_core_info *t;
	struct elf_prpsinfo *psinfo;
	struct core_thread *ct;
	unsigned int i;

	info->size = 0;
	info->thread = NULL;

	psinfo = kmalloc(sizeof(*psinfo), GFP_KERNEL);
	if (psinfo == NULL) {
		info->psinfo.data = NULL; /* So we don't free this wrongly */
		return 0;
	}

	fill_note(&info->psinfo, "CORE", NT_PRPSINFO, sizeof(*psinfo), psinfo);

	/*
	 * Figure out how many notes we're going to need for each thread.
	 */
	info->thread_notes = 0;
	for (i = 0; i < view->n; ++i)
		if (view->regsets[i].core_note_type != 0)
			++info->thread_notes;

	/*
	 * Sanity check.  We rely on regset 0 being in NT_PRSTATUS,
	 * since it is our one special case.
	 */
	if (unlikely(info->thread_notes == 0) ||
	    unlikely(view->regsets[0].core_note_type != NT_PRSTATUS)) {
		WARN_ON(1);
		return 0;
	}

	/*
	 * Initialize the ELF file header.
	 */
	fill_elf_header(elf, phdrs, view->e_machine, view->e_flags);

	/*
	 * Allocate a structure for each thread.
	 */
	for (ct = &dump_task->mm->core_state->dumper; ct; ct = ct->next) {
		t = kzalloc(offsetof(struct elf_thread_core_info,
				     notes[info->thread_notes]),
			    GFP_KERNEL);
		if (unlikely(!t))
			return 0;

		t->task = ct->task;
		if (ct->task == dump_task || !info->thread) {
			t->next = info->thread;
			info->thread = t;
		} else {
			/*
			 * Make sure to keep the original task at
			 * the head of the list.
			 */
			t->next = info->thread->next;
			info->thread->next = t;
		}
	}

	/*
	 * Now fill in each thread's information.
	 */
	for (t = info->thread; t != NULL; t = t->next)
		if (!fill_thread_core_info(t, view, siginfo->si_signo,
					   &info->size))
			return 0;

	/*
	 * Fill in the two process-wide notes.
	 */
	fill_psinfo(psinfo, dump_task->group_leader, dump_task->mm);
	info->size += notesize(&info->psinfo);

	fill_siginfo_note(&info->signote, &info->csigdata, siginfo);
	info->size += notesize(&info->signote);

	fill_auxv_note(&info->auxv, current->mm);
	info->size += notesize(&info->auxv);

	if (fill_files_note(&info->files) == 0)
		info->size += notesize(&info->files);

	return 1;
}

static int writenote(struct memelfnote *men, struct coredump_params *cprm)
{
	struct elf_note en;
	en.n_namesz = strlen(men->name) + 1;
	en.n_descsz = men->datasz;
	en.n_type = men->type;

	return dump_emit(cprm, &en, sizeof(en)) &&
	       dump_emit(cprm, men->name, en.n_namesz) && dump_align(cprm, 4) &&
	       dump_emit(cprm, men->data, men->datasz) && dump_align(cprm, 4);
}

static void fill_elf_header(struct elfhdr *elf, int segs, u16 machine,
			    u32 flags)
{
	memset(elf, 0, sizeof(*elf));

	memcpy(elf->e_ident, ELFMAG, SELFMAG);
	elf->e_ident[EI_CLASS] = ELF_CLASS;
	elf->e_ident[EI_DATA] = ELF_DATA;
	elf->e_ident[EI_VERSION] = EV_CURRENT;
	elf->e_ident[EI_OSABI] = ELF_OSABI;

	elf->e_type = ET_CORE;
	elf->e_machine = machine;
	elf->e_version = EV_CURRENT;
	elf->e_phoff = sizeof(struct elfhdr);
	elf->e_flags = flags;
	elf->e_ehsize = sizeof(struct elfhdr);
	elf->e_phentsize = sizeof(struct elf_phdr);
	elf->e_phnum = segs;
}

static size_t get_note_info_size(struct elf_note_info *info)
{
	return info->size;
}

static int write_note_info(struct elf_note_info *info,
			   struct coredump_params *cprm)
{
	bool first = 1;
	struct elf_thread_core_info *t = info->thread;

	do {
		int i;

		if (!writenote(&t->notes[0], cprm))
			return 0;

		if (first && !writenote(&info->psinfo, cprm))
			return 0;
		if (first && !writenote(&info->signote, cprm))
			return 0;
		if (first && !writenote(&info->auxv, cprm))
			return 0;
		if (first && info->files.data && !writenote(&info->files, cprm))
			return 0;

		for (i = 1; i < info->thread_notes; ++i)
			if (t->notes[i].data && !writenote(&t->notes[i], cprm))
				return 0;

		first = 0;
		t = t->next;
	} while (t);

	return 1;
}

static void do_thread_regset_writeback(struct task_struct *task,
				       const struct user_regset *regset)
{
	if (regset->writeback)
		regset->writeback(task, regset, 1);
}

#define MAX_FILE_NOTE_SIZE (4 * 1024 * 1024)
/*
 * Format of NT_FILE note:
 *
 * long count     -- how many files are mapped
 * long page_size -- units for file_ofs
 * array of [COUNT] elements of
 *   long start
 *   long end
 *   long file_ofs
 * followed by COUNT filenames in ASCII: "FILE1" NUL "FILE2" NUL...
 */
static int fill_files_note(struct memelfnote *note)
{
	struct vm_area_struct *vma;
	unsigned count, size, names_ofs, remaining, n;
	user_long_t *data;
	user_long_t *start_end_ofs;
	char *name_base, *name_curpos;

	/* *Estimated* file count and total data size needed */
	count = current->mm->map_count;
	size = count * 64;

	names_ofs = (2 + 3 * count) * sizeof(data[0]);
alloc:
	if (size >= MAX_FILE_NOTE_SIZE) /* paranoia check */
		return -EINVAL;
	size = round_up(size, PAGE_SIZE);
	data = vmalloc(size);
	if (!data)
		return -ENOMEM;

	start_end_ofs = data + 2;
	name_base = name_curpos = ((char *)data) + names_ofs;
	remaining = size - names_ofs;
	count = 0;
	for (vma = current->mm->mmap; vma != NULL; vma = vma->vm_next) {
		struct file *file;
		const char *filename;

		file = vma->vm_file;
		if (!file)
			continue;
		filename = d_path(&file->f_path, name_curpos, remaining);
		if (IS_ERR(filename)) {
			if (PTR_ERR(filename) == -ENAMETOOLONG) {
				vfree(data);
				size = size * 5 / 4;
				goto alloc;
			}
			continue;
		}

		/* d_path() fills at the end, move name down */
		/* n = strlen(filename) + 1: */
		n = (name_curpos + remaining) - filename;
		remaining = filename - name_curpos;
		memmove(name_curpos, filename, n);
		name_curpos += n;

		*start_end_ofs++ = vma->vm_start;
		*start_end_ofs++ = vma->vm_end;
		*start_end_ofs++ = vma->vm_pgoff;
		count++;
	}

	/* Now we know exact count of files, can store it */
	data[0] = count;
	data[1] = PAGE_SIZE;
	/*
	 * Count usually is less than current->mm->map_count,
	 * we need to move filenames down.
	 */
	n = current->mm->map_count - count;
	if (n != 0) {
		unsigned shift_bytes = n * 3 * sizeof(data[0]);
		memmove(name_base - shift_bytes, name_base,
			name_curpos - name_base);
		name_curpos -= shift_bytes;
	}

	size = name_curpos - (char *)data;
	fill_note(note, "CORE", NT_FILE, size, data);
	return 0;
}

static unsigned long vma_dump_size(struct vm_area_struct *vma,
				   unsigned long mm_flags)
{
#define FILTER(type) (mm_flags & (1UL << MMF_DUMP_##type))

	if (vma->vm_flags & VM_DONTDUMP)
		return 0;

	/* Hugetlb memory check */
	if (vma->vm_flags & VM_HUGETLB) {
		if ((vma->vm_flags & VM_SHARED) && FILTER(HUGETLB_SHARED))
			goto whole;
		if (!(vma->vm_flags & VM_SHARED) && FILTER(HUGETLB_PRIVATE))
			goto whole;
		return 0;
	}

	/* Do not dump I/O mapped devices or special mappings */
	if (vma->vm_flags & VM_IO)
		return 0;

	/* By default, dump shared memory if mapped from an anonymous file. */
	if (vma->vm_flags & VM_SHARED) {
		if (file_inode(vma->vm_file)->i_nlink == 0
			    ? FILTER(ANON_SHARED)
			    : FILTER(MAPPED_SHARED))
			goto whole;
		return 0;
	}

	/* Dump segments that have been written to.  */
	if (vma->anon_vma && FILTER(ANON_PRIVATE))
		goto whole;
	if (vma->vm_file == NULL)
		return 0;

	if (FILTER(MAPPED_PRIVATE))
		goto whole;

	/*
	 * If this looks like the beginning of a DSO or executable mapping,
	 * check for an ELF header.  If we find one, dump the first page to
	 * aid in determining what was mapped here.
	 */
	if (FILTER(ELF_HEADERS) && vma->vm_pgoff == 0 &&
	    (vma->vm_flags & VM_READ)) {
		u32 __user *header = (u32 __user *)vma->vm_start;
		u32 word;
		mm_segment_t fs = get_fs();
		/*
		 * Doing it this way gets the constant folded by GCC.
		 */
		union {
			u32 cmp;
			char elfmag[SELFMAG];
		} magic;
		BUILD_BUG_ON(SELFMAG != sizeof word);
		magic.elfmag[EI_MAG0] = ELFMAG0;
		magic.elfmag[EI_MAG1] = ELFMAG1;
		magic.elfmag[EI_MAG2] = ELFMAG2;
		magic.elfmag[EI_MAG3] = ELFMAG3;
		/*
		 * Switch to the user "segment" for get_user(),
		 * then put back what elf_core_dump() had in place.
		 */
		set_fs(USER_DS);
		if (unlikely(get_user(word, header)))
			word = 0;
		set_fs(fs);
		if (word == magic.cmp)
			return PAGE_SIZE;
	}

#undef FILTER

	return 0;

whole:
	return vma->vm_end - vma->vm_start;
}

/*
 * Every entry in the systen tables is described by this structure.
 */
struct sysent {
	void *se_syscall; /* function to call */
	short se_nargs;   /* number of aguments */

	/*
	 * Theses are only used for syscall tracing.
	 */
	char *se_name; /* name of function */
	char *se_args; /* how to print the argument list */
};

/* This comes from arch/x86/include/asm/ptrace.h */
/*
struct pt_regs {
	unsigned long ebx;
	unsigned long ecx;
	unsigned long edx;
	unsigned long esi;
	unsigned long edi;
	unsigned long ebp;
	unsigned long eax;
	unsigned long ds;
	unsigned long es;
	unsigned long fs;
	unsigned long gs;
	unsigned long orig_eax;
	unsigned long eip;
	unsigned long cs;
	unsigned long flags;
	unsigned long esp;
	unsigned long ss;
};
*/

#define eax ax
#define ebx bx
#define ecx cx
#define edx dx
#define esi si
#define edi di
#define ebp bp

#ifndef MAP_ANON
#define MAP_ANON MAP_ANONYMOUS
#endif

/*
 * Types for syscall pointers.
 */
typedef asmlinkage int (*syscallv_t)(void);
typedef asmlinkage int (*syscall1_t)(int);
typedef asmlinkage int (*syscall2_t)(int, int);
typedef asmlinkage int (*syscall3_t)(int, int, int);
typedef asmlinkage int (*syscall4_t)(int, int, int, int);
typedef asmlinkage int (*syscall5_t)(int, int, int, int, int);

/*
 * Marcos to call syscall pointers.
 */
#define SYSCALL_VOID(sys) ((syscallv_t)(sys))();
#define SYSCALL_1ARG(sys, regs) ((syscall1_t)(sys))((regs)->ebx)
#define SYSCALL_2ARG(sys, regs) ((syscall2_t)(sys))((regs)->ebx, (regs)->ecx)
#define SYSCALL_3ARG(sys, regs)                                                \
	((syscall3_t)(sys))((regs)->ebx, (regs)->ecx, (regs)->edx)
#define SYSCALL_4ARG(sys, regs)                                                \
	((syscall4_t)(sys))((regs)->ebx, (regs)->ecx, (regs)->edx, (regs)->esi)
#define SYSCALL_5ARG(sys, regs)                                                \
	((syscall5_t)(sys))((regs)->ebx, (regs)->ecx, (regs)->edx,             \
			    (regs)->esi, (regs)->edi)

static int asmlinkage cgcos_allocate(unsigned long len, unsigned long prot,
				     void __user **addr);
static int asmlinkage cgcos_deallocate(unsigned long ptr, size_t len);
static int asmlinkage cgcos_random(char __user *buf, size_t count,
				   size_t __user *rnd_out);
static int asmlinkage cgcos_transmit(int fd, char __user *buf, size_t count,
				     size_t __user *tx_bytes);
static int asmlinkage cgcos_receive(int fd, char __user *buf, size_t count,
				    size_t __user *rx_bytes);
static int asmlinkage cgcos_fdwait(int nfds, fd_set __user *readfds,
				   fd_set __user *writefds,
				   struct timeval __user *timeout,
				   int __user *readyfds);
void asmlinkage cgcos_syscall(int segment, struct pt_regs *regs);
void asmlinkage cgcos_sysenter(int segment, struct pt_regs *regs);
void cgcos_syscall_dummy(int, struct pt_regs *);

static void cgcos_dispatch(struct pt_regs *regs, const struct sysent *ap);

/**
 * We wrap writes to user space in order to trace them in the cgc monitor plugin
 */
long s2e_copy_to_user(void __user *to, const void *from, long n)
{
	long ret;
	if (s2e_decree_monitor_enabled) {
		s2e_decree_copy_to_user(current->pid, current->comm, to, from,
					n, 0, 0);
	}
	ret = copy_to_user(to, from, n);
	if (s2e_decree_monitor_enabled) {
		s2e_decree_copy_to_user(current->pid, current->comm, to, from,
					n, 1, ret);
	}
	return ret;
}

static int asmlinkage cgcos_fdwait(int nfds, fd_set __user *readfds,
				   fd_set __user *writefds,
				   struct timeval __user *timeout,
				   int __user *readyfds)
{
	struct timespec end_time, *to = NULL;
	struct timeval tv;
	int res, invoke_orig;

	if (readyfds != NULL &&
	    !access_ok(VERIFY_WRITE, readyfds, sizeof(*readyfds)))
		return (-EFAULT);

	if (timeout != NULL) {
		if (copy_from_user(&tv, timeout, sizeof(tv)))
			return (-EFAULT);

		to = &end_time;
		tv.tv_sec = tv.tv_sec + (tv.tv_usec / USEC_PER_SEC);
		tv.tv_usec %= USEC_PER_SEC;
		tv.tv_usec -= tv.tv_usec % 10000; /* gate to 0.01s */
		tv.tv_usec *= NSEC_PER_USEC;

		if (poll_select_set_timeout(to, tv.tv_sec, tv.tv_usec))
			return (-EINVAL);
	}

	if (s2e_decree_monitor_enabled) {
		invoke_orig = 1;
		if (timeout != NULL) {
			res = s2e_decree_waitfds(current->pid, current->comm,
						 nfds, true, to->tv_sec,
						 to->tv_nsec, &invoke_orig);
		} else {
			res = s2e_decree_waitfds(current->pid, current->comm,
						 nfds, false, to->tv_sec,
						 to->tv_nsec, &invoke_orig);
		}
		if (invoke_orig) {
			res = core_sys_select(nfds, readfds, writefds, NULL,
					      to);
		}
	} else {
		res = core_sys_select(nfds, readfds, writefds, NULL, to);
	}

	if (res == -ERESTARTNOHAND)
		res = -EINTR;

	if (res < 0)
		return (res);
	if (readyfds != NULL &&
	    s2e_copy_to_user(readyfds, &res, sizeof(*readyfds)))
		return (-EFAULT);
	return (0);
}

static int asmlinkage cgcos_allocate(unsigned long len, unsigned long exec,
				     void __user **addr)
{
	unsigned int res;
	int prot = PROT_READ | PROT_WRITE;

	if (exec)
		prot |= PROT_EXEC;

	if (addr != NULL && !access_ok(VERIFY_WRITE, addr, sizeof(*addr)))
		return (-EFAULT);

	if (s2e_decree_monitor_enabled) {
		s2e_decree_handle_symbolic_allocate_size(current->pid,
							 current->comm, &len);
	}

	res = vm_mmap(NULL, 0, len, prot, MAP_ANON | MAP_PRIVATE, 0);
	if (IS_ERR_VALUE(res))
		return (res);
	if (addr != NULL && s2e_copy_to_user(addr, &res, sizeof(*addr))) {
		vm_munmap(res, len);
		return (-EFAULT);
	}
	if (s2e_decree_monitor_enabled) {
		s2e_decree_update_memory_map(current->pid, current->comm,
					     current->mm);
	}
	return (0);
}

int asmlinkage cgcos_random(char __user *buf, size_t count,
			    size_t __user *rnd_out)
{
	size_t i, size;
	uint32_t randval;
	int ret;

	current->cgc_bytes = 0;
	if (rnd_out != NULL &&
	    !access_ok(VERIFY_WRITE, rnd_out, sizeof(*rnd_out)))
		return (-EFAULT);

	if (s2e_decree_monitor_enabled) {
		s2e_decree_handle_symbolic_random_buffer(
			current->pid, current->comm, (void **)&buf, &count);
	}

	for (i = 0; i < count; i += sizeof(randval)) {
		size = min(count - i, sizeof(randval));

		if (current->cgc_rng) {
			ret = crypto_rng_get_bytes(current->cgc_rng,
						   (u8 *)&randval, size);
			if (ret < 0)
				return (ret);
		} else
			get_random_bytes(&randval, size);
		if (s2e_copy_to_user(&buf[i], &randval, size))
			return (-EFAULT);
		current->cgc_bytes += size;
	}

	if (s2e_decree_monitor_enabled) {
		// either replace everything with symbolic data, or make values
		// concolic
		s2e_decree_random(current->pid, current->comm, buf, count);
	}

	if (rnd_out != NULL &&
	    s2e_copy_to_user(rnd_out, &count, sizeof(*rnd_out)))
		return (-EFAULT);

	return 0;
}

static int asmlinkage cgcos_deallocate(unsigned long ptr, size_t len)
{
	if ((ptr + len) <= CGC_MAGIC_PAGE ||
	    ptr >= (CGC_MAGIC_PAGE + PAGE_SIZE)) {
		int res = vm_munmap(ptr, len);
		if (res == 0 && s2e_decree_monitor_enabled) {
			s2e_decree_update_memory_map(
				current->pid, current->comm, current->mm);
		}
		return res;
	}
	return -EINVAL;
}

int asmlinkage cgcos_transmit(int fd, char __user *buf, size_t count,
			      size_t __user *tx_bytes)
{
	int res = 0;
	size_t count_orig;

	current->cgc_bytes = 0;
	if (tx_bytes != NULL &&
	    !access_ok(VERIFY_WRITE, tx_bytes, sizeof(*tx_bytes)))
		return (-EFAULT);
	if (current->cgc_max_transmit != 0 && current->cgc_max_transmit < count)
		count = current->cgc_max_transmit;

	count_orig = count; // remember original symbolic size

	if (s2e_decree_monitor_enabled) {
		s2e_decree_handle_symbolic_transmit_buffer(
			current->pid, current->comm, (void **)&buf, &count);
	}

	if (count != 0) {
		res = sys_write(fd, buf, count);
		if (res < 0) {
			return (res);
		}

		if (s2e_decree_monitor_enabled) {
			// res becomes symbolic if count_orig was symbolic
			s2e_decree_write_data(current->pid, current->comm, fd,
					      buf, &res, &count_orig);
		}
	}

	current->cgc_bytes = res;
	if (tx_bytes != NULL &&
	    s2e_copy_to_user(tx_bytes, &res, sizeof(*tx_bytes)))
		return (-EFAULT);
	return (0);
}

int asmlinkage cgcos_receive(int fd, char __user *buf, size_t count,
			     size_t __user *rx_bytes)
{
	int res = 0;
	int invoke_orig = 1;

	current->cgc_bytes = 0;
	if (rx_bytes != NULL &&
	    !access_ok(VERIFY_WRITE, rx_bytes, sizeof(*rx_bytes)))
		return (-EFAULT);
	if (current->cgc_max_receive != 0 && current->cgc_max_receive < count)
		count = current->cgc_max_receive;

	if (s2e_decree_monitor_enabled) {
		invoke_orig = s2e_get_cfg_bool(current->pid, current->comm,
					       "invokeOriginalSyscalls");
	}

	if (invoke_orig) {
		if (count != 0) {
			res = sys_read(fd, buf, count);
			if (res < 0) {
				return (res);
			}

			if (s2e_decree_monitor_enabled) {
				s2e_decree_read_data_post(current->pid,
							  current->comm, fd,
							  buf, res);
			}
		}
	} else {
		size_t count_orig = count; // remember original symbolic size

		s2e_decree_handle_symbolic_receive_buffer(
			current->pid, current->comm, (void **)&buf, &count);

		if (count != 0) {
			void *kbuf;

			kbuf = kmalloc(count, GFP_KERNEL);
			if (!kbuf) {
				s2e_message(
					"Could not allocate memory for read\n");
				return -EFAULT;
			}

			// res becomes symbolic if count_orig was symbolic
			s2e_decree_read_data(current->pid, current->comm, fd,
					     kbuf, count, &count_orig, &res);

			if (s2e_copy_to_user(buf, kbuf, count)) {
				kfree(kbuf);
				return (-EFAULT);
			}

			kfree(kbuf);
		}
	}

	current->cgc_bytes = res;
	if (rx_bytes != NULL &&
	    s2e_copy_to_user(rx_bytes, &res, sizeof(*rx_bytes)))
		return (-EFAULT);
	return (0);
}

int asmlinkage cgcos_terminate(int code)
{
	complete_and_exit(NULL, (code & 0xff) << 8);
	return (0);
}

static const struct sysent cgcos_syscall_table[] = {
	{NULL, 0, "nosys", ""},			   /* 0 */
	{cgcos_terminate, 1, "terminate", "d"},    /* 1 */
	{cgcos_transmit, 4, "transmit", "dpdp"},   /* 2 */
	{cgcos_receive, 4, "receive", "dpdp"},     /* 3 */
	{cgcos_fdwait, 5, "fdwait", "dxxxp"},      /* 4 */
	{cgcos_allocate, 3, "allocate", "xxp"},    /* 5 */
	{cgcos_deallocate, 2, "deallocate", "xd"}, /* 6 */
	{cgcos_random, 3, "random", "xdp"},	/* 7 */
};

unsigned int cgcos_get_personality(void) { return current->personality; }

void cgcos_syscall_dummy(int segment, struct pt_regs *regs)
{
	/*
	 * this exists to appease the compiler, cgcos_syscall is called
	 * directly from entry_32.S.
	 */
	regs->eax = -ENOSYS;
}

#define CGC_EBADF 1
#define CGC_EFAULT 2
#define CGC_EINVAL 3
#define CGC_ENOMEM 4
#define CGC_ENOSYS 5
#define CGC_EPIPE 6

unsigned long cgc_map_err(struct pt_regs *regs)
{
	switch (regs->eax) {
	case 0:
		return 0;
	case -EBADF:
		return CGC_EBADF;
	case -EFAULT:
		return CGC_EFAULT;
	case -EINVAL:
		return CGC_EINVAL;
	case -ENOMEM:
		return CGC_ENOMEM;
	case -ENOSYS:
		return CGC_ENOSYS;
	case -EPIPE:
		return CGC_EPIPE;
	case -EINTR:
	case -ERESTARTSYS:
	case -ERESTARTNOINTR:
	case -ERESTARTNOHAND:
	case -ERESTART_RESTARTBLOCK:
		regs->ip -= 2;
		return regs->orig_ax;
	}
	return CGC_EINVAL;
}

void asmlinkage cgcos_sysenter(int segment, struct pt_regs *regs)
{
	siginfo_t info;

	info.si_signo = SIGILL;
	info.si_errno = 0;
	info.si_code = ILL_ILLOPN;
	info.si_addr = (void __user *)regs->ip;
	send_sig_info(SIGKILL, &info, current);
}

void asmlinkage cgcos_syscall(int segment, struct pt_regs *regs)
{
	unsigned int sysno = regs->orig_ax;

#ifdef DEBUG_CGC
	printk(KERN_ALERT "cgcos_syscall reached for syscall %d\n", sysno);
#endif
	if (sysno == 0 || sysno >= ARRAY_SIZE(cgcos_syscall_table))
		regs->eax = -ENOSYS;
	else
		cgcos_dispatch(regs, &cgcos_syscall_table[sysno]);
	regs->eax = cgc_map_err(regs);
}

void cgcos_dispatch(struct pt_regs *regs, const struct sysent *ap)
{
	int error;

	switch (ap->se_nargs) {
	case 0:
		error = SYSCALL_VOID(ap->se_syscall);
		break;
	case 1:
		error = SYSCALL_1ARG(ap->se_syscall, regs);
		break;
	case 2:
		error = SYSCALL_2ARG(ap->se_syscall, regs);
		break;
	case 3:
		error = SYSCALL_3ARG(ap->se_syscall, regs);
		break;
	case 4:
		error = SYSCALL_4ARG(ap->se_syscall, regs);
		break;
	case 5:
		error = SYSCALL_5ARG(ap->se_syscall, regs);
		break;
	default:
		printk(KERN_INFO
		       "Unsupported ABI length %d for call 0x%lx (%s)\n",
		       ap->se_nargs, regs->eax, ap->se_name);
		error = -ENOSYS;
	}

	regs->eax = error;
}

static struct exec_domain cgcos_exec_domain = {
	name : "CGCOS",
	handler : cgcos_syscall_dummy,
	pers_low : PER_CGCOS &PER_MASK,
	pers_high : PER_CGCOS &PER_MASK,
	signal_map : NULL,
	signal_invmap : NULL,
	err_map : NULL,
	socktype_map : NULL,
	sockopt_map : NULL,
	af_map : NULL,
	module : THIS_MODULE
};

static struct ctl_table cgc_sys_table[] = {
	{
		.procname = "relaxed_headers",
		.data = &flag_relaxed_headers,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{}};

static struct ctl_table cgc_root_table[] = {
	{
		.procname = "cgc", .mode = 0555, .child = cgc_sys_table,
	},
	{}};

static struct ctl_table_header *cgc_sysctls;

static int __init init_cgcos_binfmt(void)
{
	int err;

	cgc_sysctls = register_sysctl_table(cgc_root_table);
	register_binfmt(&cgcos_format);
	err = register_exec_domain(&cgcos_exec_domain);
	if (err)
		unregister_binfmt(&cgcos_format);
	return (err);
}

static void __exit exit_cgcos_binfmt(void)
{
	unregister_exec_domain(&cgcos_exec_domain);
	unregister_binfmt(&cgcos_format);
	unregister_sysctl_table(cgc_sysctls);
}

core_initcall(init_cgcos_binfmt);
module_exit(exit_cgcos_binfmt);
MODULE_LICENSE("Dual BSD/GPL");
