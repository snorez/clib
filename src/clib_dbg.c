/*
 * TODO
 * Copyright (C) 2018  zerons
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include "../include/clib_dbg.h"

/*
 * *NOTE* capstone used here
 * need 32bit and 64bit libraries in /usr/lib32 and /usr/lib64
 * so download .deb files at
 * http://www.capstone-engine.org/download/3.0.4/ubuntu-14.04/
 * and install 32bit then copy the lib files in /usr/lib to /usr/lib32
 * then install 64bit
 */

/*
 * useful when you use your own signal handler
 * this function doesn't print the lib function cause they
 * Do Not have a regular start *push r(e)bp, mov r(e)bp, r(e)sp, leave, ret
 * *USE* '-rdynamic -ldl -lcapstone' options when compile and link
 *
 * TODO: if dli_sname is NULL, try to resolve the loadable file and
 * find static funcs
 */
static uint8_t bits_def;
static LIST_HEAD(elf_syms_def);
static uint8_t *bits;
static struct list_head *elf_syms;
void clib_dladdr_start(struct list_head *_head, uint8_t *_bits)
{
	elf_syms = _head;
	bits = _bits;
	INIT_LIST_HEAD(elf_syms);
}

void clib_dladdr(void *addr, Dl_info *info)
{
	dladdr(addr, info);
	if (info->dli_sname)
		return;

	int diff = -1;
	struct _elf_sym_full *t = NULL;
	elf_get_syms((char *)info->dli_fname, elf_syms, bits);

	struct _elf_sym_full *tmp;
	list_for_each_entry(tmp, elf_syms, sibling) {
		if ((*bits == 32) &&
			(ELF32_ST_TYPE(tmp->data.sym0.st_info) != STT_FUNC))
			continue;
		if ((*bits == 64) &&
			(ELF64_ST_TYPE(tmp->data.sym1.st_info) != STT_FUNC))
			continue;
		void *handle = dlopen(info->dli_fname, RTLD_NOW | RTLD_NOLOAD);
		tmp->load_addr = dlsym(handle, tmp->name);
		/* TODO, get the real load_addr */
		if (!tmp->load_addr) {
			if (*bits == 32) {
				if (!handle)
					tmp->load_addr = (void *)(
						(long)tmp->data.sym0.st_value);
				else
					tmp->load_addr = (void *)(
						(long)info->dli_fbase +
						(long)tmp->data.sym0.st_value);
			} else if (*bits == 64) {
				if (!handle)
					tmp->load_addr = (void *)(
						(long)tmp->data.sym1.st_value);
				else
					tmp->load_addr = (void *)(
						(long)info->dli_fbase +
						(long)tmp->data.sym1.st_value);
			}
		}
		if (tmp->load_addr < addr) {
			if (diff == -1)
				diff = addr - tmp->load_addr;
			else if (diff > (addr - tmp->load_addr)) {
				diff = addr - tmp->load_addr;
				t = tmp;
			}
		}
	}

	if (t) {
		info->dli_sname = t->name;
		info->dli_saddr = t->load_addr;
	}
}

void clib_dladdr_end(void)
{
	elf_drop_syms(elf_syms);
	return;
}

#ifndef CONFIG_BT_DEPTH
#define BT_DEPTH	0x10
#else
#define	BT_DEPTH	(CONFIG_BT_DEPTH)
#endif

static void print_bt_info(ucontext_t *uc)
{
	int i = 0;
#ifdef __x86_64__
	uint64_t current_rip, current_rbp;
	current_rbp = uc->uc_mcontext.gregs[REG_RBP];
	current_rip = uc->uc_mcontext.gregs[REG_RIP];

	Dl_info dlinfo;
	while (current_rbp && current_rip) {
		if ((current_rbp > 0x0000800000000000) ||
			(current_rip > 0x0000800000000000)) {
			fprintf(stderr, "stack overflow?\n");
			break;
		}

		clib_dladdr_start(&elf_syms_def, &bits_def);
		clib_dladdr((void *)current_rip, &dlinfo);
		fprintf(stderr, "[0x%016lx]: %s|%s|0x%016lx\n", current_rip,
			dlinfo.dli_fname,
			dlinfo.dli_sname, (long)dlinfo.dli_saddr);
		clib_dladdr_end();
		if (*((uint64_t *)current_rbp) < current_rbp)
			break;
		current_rip = *((uint64_t *)current_rbp+1);
		current_rbp = *((uint64_t *)current_rbp);
		i++;
		if (i == BT_DEPTH)
			break;
	}
#endif
#ifdef __i386__
	uint32_t current_ebp, current_eip;
	current_ebp = uc->uc_mcontext.gregs[REG_EBP];
	current_eip = uc->uc_mcontext.gregs[REG_EIP];

	Dl_info dlinfo;
	while (current_eip && current_ebp) {
		clib_dladdr_start(&elf_syms_def, &bits_def);
		clib_dladdr((void *)current_eip, &dlinfo);
		fprintf(stderr, "[0x%08lx]: %s|%s|0x%08lx\n", current_eip,
			dlinfo.dli_fname,
			dlinfo.dli_sname, dlinfo.dli_saddr);
		clib_dladdr_end();
		current_eip = *((uint32_t *)current_ebp+1);
		current_ebp = *((uint32_t *)current_ebp);
		i++;
		if (i == BT_DEPTH)
			break;
	}
#endif
}

static void dump_regs(ucontext_t *uc)
{
	fprintf(stderr, "INFO REGISTERS:\n");
#ifdef __x86_64__
	fprintf(stderr, "RAX: 0x%016lx\t",
			(long)(uc->uc_mcontext.gregs[REG_RAX]));
	fprintf(stderr, "RBX: 0x%016lx\t",
			(long)(uc->uc_mcontext.gregs[REG_RBX]));
	fprintf(stderr, "RCX: 0x%016lx\n",
			(long)(uc->uc_mcontext.gregs[REG_RCX]));
	fprintf(stderr, "RDX: 0x%016lx\t",
			(long)(uc->uc_mcontext.gregs[REG_RDX]));
	fprintf(stderr, "RSI: 0x%016lx\t",
			(long)(uc->uc_mcontext.gregs[REG_RSI]));
	fprintf(stderr, "RDI: 0x%016lx\n",
			(long)(uc->uc_mcontext.gregs[REG_RDI]));
	fprintf(stderr, "RBP: 0x%016lx\t",
			(long)(uc->uc_mcontext.gregs[REG_RBP]));
	fprintf(stderr, "RSP: 0x%016lx\t",
			(long)(uc->uc_mcontext.gregs[REG_RSP]));
	fprintf(stderr, "R08: 0x%016lx\n",
			(long)(uc->uc_mcontext.gregs[REG_R8]));
	fprintf(stderr, "R09: 0x%016lx\t",
			(long)(uc->uc_mcontext.gregs[REG_R9]));
	fprintf(stderr, "R10: 0x%016lx\t",
			(long)(uc->uc_mcontext.gregs[REG_R10]));
	fprintf(stderr, "R11: 0x%016lx\n",
			(long)(uc->uc_mcontext.gregs[REG_R11]));
	fprintf(stderr, "R12: 0x%016lx\t",
			(long)(uc->uc_mcontext.gregs[REG_R12]));
	fprintf(stderr, "R13: 0x%016lx\t",
			(long)(uc->uc_mcontext.gregs[REG_R13]));
	fprintf(stderr, "R14: 0x%016lx\n",
			(long)(uc->uc_mcontext.gregs[REG_R14]));
	fprintf(stderr, "R15: 0x%016lx\t",
			(long)(uc->uc_mcontext.gregs[REG_R15]));
	fprintf(stderr, "RIP: 0x%016lx\t",
			(long)(uc->uc_mcontext.gregs[REG_RIP]));
	fprintf(stderr, "FLG: 0x%016lx\n",
			(long)(uc->uc_mcontext.gregs[REG_EFL]));
#endif
#ifdef __i386__
	fprintf(stderr, "EAX: 0x%08lx\t",
			(long)(uc->uc_mcontext.gregs[REG_EAX]));
	fprintf(stderr, "EBX: 0x%08lx\t",
			(long)(uc->uc_mcontext.gregs[REG_EBX]));
	fprintf(stderr, "ECX: 0x%08lx\n",
			(long)(uc->uc_mcontext.gregs[REG_ECX]));
	fprintf(stderr, "EDX: 0x%08lx\t",
			(long)(uc->uc_mcontext.gregs[REG_EDX]));
	fprintf(stderr, "ESI: 0x%08lx\t",
			(long)(uc->uc_mcontext.gregs[REG_ESI]));
	fprintf(stderr, "EDI: 0x%08lx\n",
			(long)(uc->uc_mcontext.gregs[REG_EDI]));
	fprintf(stderr, "EBP: 0x%08lx\t",
			(long)(uc->uc_mcontext.gregs[REG_EBP]));
	fprintf(stderr, "ESP: 0x%08lx\t",
			(long)(uc->uc_mcontext.gregs[REG_ESP]));
	fprintf(stderr, "EIP: 0x%08lx\n",
			(long)(uc->uc_mcontext.gregs[REG_EIP]));
	fprintf(stderr, "FLG: 0x%08lx\n",
			(long)(uc->uc_mcontext.gregs[REG_EFL]));
#endif
}

static void dump_ill(int code)
{
	switch (code) {
	case ILL_ILLOPC:
		fprintf(stderr, "illegal opcode\n");
		break;
	case ILL_ILLOPN:
		fprintf(stderr, "illegal operation\n");
		break;
	case ILL_ILLADR:
		fprintf(stderr, "illegal addr mode\n");
		break;
	case ILL_ILLTRP:
		fprintf(stderr, "illegal trap\n");
		break;
	case ILL_PRVOPC:
		fprintf(stderr, "illegal privilege opcode\n");
		break;
	case ILL_PRVREG:
		fprintf(stderr, "illegal privilege register\n");
		break;
	case ILL_COPROC:
		fprintf(stderr, "illegal cooperate register\n");
		break;
	case ILL_BADSTK:
		fprintf(stderr, "illegal stack error\n");
		break;
	default:
		fprintf(stderr, "SIGILL error: %d\n", code);
	}
}

static void dump_fpe(int code)
{
	switch (code) {
	case FPE_INTDIV:
		fprintf(stderr, "div by zero\n");
		break;
	case FPE_INTOVF:
		fprintf(stderr, "int overflow\n");
		break;
	case FPE_FLTDIV:
		fprintf(stderr, "float div by zero\n");
		break;
	case FPE_FLTOVF:
		fprintf(stderr, "float overflow\n");
		break;
	case FPE_FLTUND:
		fprintf(stderr, "float underflow\n");
		break;
	case FPE_FLTRES:
		fprintf(stderr, "float inaccurate result\n");
		break;
	case FPE_FLTINV:
		fprintf(stderr, "float invalid\n");
		break;
	case FPE_FLTSUB:
		fprintf(stderr, "float subscript out of range\n");
		break;
	default:
		fprintf(stderr, "SIGFPE error: %d\n", code);
	}
}

static void dump_segv(int code)
{
	switch (code) {
	case SEGV_MAPERR:
		fprintf(stderr, "addr not mapped\n");
		break;
	case SEGV_ACCERR:
		fprintf(stderr, "access error\n");
		break;
	default:
		fprintf(stderr, "SIGSEGV error: %d\n", code);
	}
}

static void dump_bus(int code)
{
	switch (code) {
	case BUS_ADRALN:
		fprintf(stderr, "addr not assigned right\n");
		break;
	case BUS_ADRERR:
		fprintf(stderr, "addr not exist\n");
		break;
	case BUS_OBJERR:
		fprintf(stderr, "hardware error\n");
		break;
	default:
		fprintf(stderr, "SIGBUS error: %d\n", code);
	}
}

static struct sigaction new_act;
static struct sigaction old_ill_act;
static struct sigaction old_fpe_act;
static struct sigaction old_segv_act;
static struct sigaction old_bus_act;
static LIST_HEAD(eh_head);
static int clean_mode = 0;
int dbg_mt_mode = 0;

static void print_mt_bt_info(ucontext_t *uc);
static inline void print_bt(ucontext_t *uc)
{
	fprintf(stderr, "Call Stack:\n");
	if (!dbg_mt_mode)
		print_bt_info(uc);
	else
		print_mt_bt_info(uc);
	fprintf(stderr, "\n");
}

static void self_sigact(int signo, siginfo_t *si, void *arg)
{
	int retval = 0;
	if (clean_mode) {
		struct eh_list *tmp;
		list_for_each_entry(tmp, &eh_head, sibling) {
			if ((signo == tmp->signo) &&
				(tmp->for_clean_mode) &&
				(tmp->cb))
				retval = tmp->cb(signo, si, arg);
			if (retval)
				break;
			if (tmp->exclusive)
				break;
		}
		if (!retval)
			return;
	}

	switch (signo) {
	case SIGILL:
		fprintf(stderr, "receive SIGILL:\t");
		dump_ill(si->si_code);
		fprintf(stderr, "instruction addr:");
		break;
	case SIGFPE:
		fprintf(stderr, "receive SIGFPE:\t");
		dump_fpe(si->si_code);
		fprintf(stderr, "instruction addr:");
		break;
	case SIGSEGV:
		fprintf(stderr, "receive SIGSEGV:\t");
		dump_segv(si->si_code);
		fprintf(stderr, "operation addr:");
		break;
	case SIGBUS:
		fprintf(stderr, "receive SIGBUS:\t");
		dump_bus(si->si_code);
		fprintf(stderr, "\t\t");
		break;
	default:
		fprintf(stderr, "receive %d\n", signo);
	}
	fprintf(stderr, "\t=> 0x%016lx:\t", (long)si->si_addr);
#ifdef HAS_CAPSTONE
#ifdef __x86_64__
	disas_single(CS_ARCH_X86, CS_MODE_64,
		(void *)(((ucontext_t *)arg)->uc_mcontext.gregs[REG_RIP]));
#endif
#ifdef __i386__
	disas_single(CS_ARCH_X86, CS_MODE_32,
		(void *)(((ucontext_t *)arg)->uc_mcontext.gregs[REG_EIP]));
#endif
#endif
	fprintf(stderr, "errno: %s\n\n", strerror(si->si_errno));

	dump_regs((ucontext_t *)arg);

	fprintf(stderr, "\n");
	print_bt((ucontext_t *)arg);

	if (!retval) {
		struct eh_list *tmp;
		list_for_each_entry(tmp, &eh_head, sibling) {
			if ((tmp->signo == signo) &&
				(!tmp->for_clean_mode) &&
				(tmp->cb))
				retval = tmp->cb(signo, si, arg);
			if (retval)
				break;
			if (tmp->exclusive)
				break;
		}
	}

	if (signo == SIGILL)
		old_ill_act.sa_handler(signo);
	else if (signo == SIGFPE)
		old_fpe_act.sa_handler(signo);
	else if (signo == SIGSEGV)
		old_segv_act.sa_handler(signo);
	else if (signo == SIGBUS)
		old_bus_act.sa_handler(signo);
	else
		WARN();
}

/*
 * flag true mean that user want the new_eh to be the only one handle the signo
 */
void set_eh(struct eh_list *new_eh)
{
	if (!list_empty(&eh_head)) {
		if (new_eh) {
			if (!new_eh->exclusive)
				list_add_tail(&new_eh->sibling, &eh_head);
			else
				list_add(&new_eh->sibling, &eh_head);
		}
		return;
	}

	if (new_act.sa_sigaction != self_sigact) {
		memset((char *)&new_act, 0, sizeof(struct sigaction));
		memset((char *)&old_ill_act, 0, sizeof(struct sigaction));
		memset((char *)&old_fpe_act, 0, sizeof(struct sigaction));
		memset((char *)&old_segv_act, 0, sizeof(struct sigaction));
		memset((char *)&old_bus_act, 0, sizeof(struct sigaction));

		new_act.sa_flags = SA_SIGINFO | SA_INTERRUPT;
		sigemptyset(&new_act.sa_mask);
		sigaddset(&new_act.sa_mask, SIGILL);
		sigaddset(&new_act.sa_mask, SIGFPE);
		sigaddset(&new_act.sa_mask, SIGSEGV);
		sigaddset(&new_act.sa_mask, SIGBUS);

		new_act.sa_sigaction = self_sigact;
		sigaction(SIGILL, &new_act, &old_ill_act);
		sigaction(SIGFPE, &new_act, &old_fpe_act);
		sigaction(SIGSEGV, &new_act, &old_segv_act);
		sigaction(SIGBUS, &new_act, &old_bus_act);
	}

	if (new_eh) {
		if (!new_eh->exclusive)
			list_add_tail(&new_eh->sibling, &eh_head);
		else
			list_add(&new_eh->sibling, &eh_head);
	}
}

void set_eh_mode(int mode)
{
	clean_mode = mode;
}

void show_bt(void)
{
	ucontext_t uc;
	int err = getcontext(&uc);
	if (err == -1) {
		err_dbg(1, "getcontext err");
		return;
	}

	print_bt(&uc);
}

/*
 * for multi-thread backtrace
 */
LIST_HEAD(clib_dbg_mt_head);
rwlock_t clib_dbg_mt_lock;

static inline unsigned long uc_sp(ucontext_t *uc)
{
	unsigned long ret = 0;
#ifdef __x86_64__
	ret = uc->uc_mcontext.gregs[REG_RSP];
#endif
#ifdef __i386__
	ret = uc->uc_mcontext.gregs[REG_ESP];
#endif
	return ret;
}

static void print_thread_bt_info(struct clib_dbg_mt *t)
{
	fprintf(stderr, "Thread 0x%lx\n", t->tid);
	size_t idx = t->bt_idx;
	while (idx) {
		fprintf(stderr, "%ld: %s\n", idx, t->bt[idx-1]);
		idx--;
	}
}

/* ensure attr->stacksize is zero before call clib_pthread_stack */
static pthread_attr_t attr;
static void print_mt_bt_info(ucontext_t *uc)
{
	write_lock(&clib_dbg_mt_lock);

	int found = 0;
	unsigned long sp = uc_sp(uc);
	void *top, *bot;
	struct clib_dbg_mt *tmp;
	list_for_each_entry(tmp, &clib_dbg_mt_head, sibling) {
		clib_pthread_stack(&attr, tmp->tid, &top, &bot);
		if (!clib_pthread_instack(top, bot, (void *)sp))
			continue;
		found = 1;
		print_thread_bt_info(tmp);
	}

	if (!found) {
		list_for_each_entry(tmp, &clib_dbg_mt_head, sibling)
			print_thread_bt_info(tmp);
	}

	write_unlock(&clib_dbg_mt_lock);
}
