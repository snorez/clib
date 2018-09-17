#include "../include/clib.h"

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
 */
static void print_bt_info(ucontext_t *uc)
{
#ifdef __x86_64__
	uint64_t current_rip, current_rbp;
	current_rbp = uc->uc_mcontext.gregs[REG_RBP];
	current_rip = uc->uc_mcontext.gregs[REG_RIP];

	Dl_info dlinfo;
	while (current_rbp && current_rip) {
		if ((current_rbp > 0x0000800000000000) ||
			(current_rip > 0x0000800000000000)) {
			fprintf(stdout, "stack overflow?\n");
			break;
		}

		dladdr((void *)current_rip, &dlinfo);
		fprintf(stdout, "[%p]: %s|%s|%p\n", (void *)current_rip,
			dlinfo.dli_fname,
			dlinfo.dli_sname, dlinfo.dli_saddr);
		if (*((uint64_t *)current_rbp) < current_rbp)
			break;
		current_rip = *((uint64_t *)current_rbp+1);
		current_rbp = *((uint64_t *)current_rbp);
	}
#endif
#ifdef __i386__
	uint32_t current_ebp, current_eip;
	current_ebp = uc->uc_mcontext.gregs[REG_EBP];
	current_eip = uc->uc_mcontext.gregs[REG_EIP];

	Dl_info dlinfo;
	while (current_eip && current_ebp) {
		dladdr((void *)current_eip, &dlinfo);
		fprintf(stdout, "[%p]: %s|%s|%p\n", (void *)current_eip,
			dlinfo.dli_fname,
			dlinfo.dli_sname, dlinfo.dli_saddr);
		current_eip = *((uint32_t *)current_ebp+1);
		current_ebp = *((uint32_t *)current_ebp);
	}
#endif
}

static void dump_regs(ucontext_t *uc)
{
	fprintf(stdout, "INFO REGISTERS:\n");
#ifdef __x86_64__
	fprintf(stdout, "RAX: %p\t", (void *)(uc->uc_mcontext.gregs[REG_RAX]));
	fprintf(stdout, "RBX: %p\t", (void *)(uc->uc_mcontext.gregs[REG_RBX]));
	fprintf(stdout, "RCX: %p\n",(void *)(uc->uc_mcontext.gregs[REG_RCX]));
	fprintf(stdout, "RDX: %p\t", (void *)(uc->uc_mcontext.gregs[REG_RDX]));
	fprintf(stdout, "RSI: %p\t", (void *)(uc->uc_mcontext.gregs[REG_RSI]));
	fprintf(stdout, "RDI: %p\n",(void *)(uc->uc_mcontext.gregs[REG_RDI]));
	fprintf(stdout, "RBP: %p\t", (void *)(uc->uc_mcontext.gregs[REG_RBP]));
	fprintf(stdout, "RSP: %p\t", (void *)(uc->uc_mcontext.gregs[REG_RSP]));
	fprintf(stdout, "R8: %p\n", (void *)(uc->uc_mcontext.gregs[REG_R8]));
	fprintf(stdout, "R9: %p\t", (void *)(uc->uc_mcontext.gregs[REG_R9]));
	fprintf(stdout, "R10: %p\t", (void *)(uc->uc_mcontext.gregs[REG_R10]));
	fprintf(stdout, "R11: %p\n", (void *)(uc->uc_mcontext.gregs[REG_R11]));
	fprintf(stdout, "R12: %p\t", (void *)(uc->uc_mcontext.gregs[REG_R12]));
	fprintf(stdout, "R13: %p\t", (void *)(uc->uc_mcontext.gregs[REG_R13]));
	fprintf(stdout, "R14: %p\n", (void *)(uc->uc_mcontext.gregs[REG_R14]));
	fprintf(stdout, "R15: %p\t", (void *)(uc->uc_mcontext.gregs[REG_R15]));
	fprintf(stdout, "RIP: %p\t", (void *)(uc->uc_mcontext.gregs[REG_RIP]));
	fprintf(stdout, "RFLAG: %p\n",(void *)(uc->uc_mcontext.gregs[REG_EFL]));
#endif
#ifdef __i386__
	fprintf(stdout, "EAX: %p\t", (void *)(uc->uc_mcontext.gregs[REG_EAX]));
	fprintf(stdout, "EBX: %p\t", (void *)(uc->uc_mcontext.gregs[REG_EBX]));
	fprintf(stdout, "ECX: %p\n", (void *)(uc->uc_mcontext.gregs[REG_ECX]));
	fprintf(stdout, "EDX: %p\t", (void *)(uc->uc_mcontext.gregs[REG_EDX]));
	fprintf(stdout, "ESI: %p\t", (void *)(uc->uc_mcontext.gregs[REG_ESI]));
	fprintf(stdout, "EDI: %p\n", (void *)(uc->uc_mcontext.gregs[REG_EDI]));
	fprintf(stdout, "EBP: %p\t", (void *)(uc->uc_mcontext.gregs[REG_EBP]));
	fprintf(stdout, "ESP: %p\t", (void *)(uc->uc_mcontext.gregs[REG_ESP]));
	fprintf(stdout, "EIP: %p\n", (void *)(uc->uc_mcontext.gregs[REG_EIP]));
	fprintf(stdout, "EFLAG: %p\n",(void *)(uc->uc_mcontext.gregs[REG_EFL]));
#endif
}

static void dump_ill(int code)
{
	switch (code) {
	case ILL_ILLOPC:
		fprintf(stdout, "illegal opcode\n");
		break;
	case ILL_ILLOPN:
		fprintf(stdout, "illegal operation\n");
		break;
	case ILL_ILLADR:
		fprintf(stdout, "illegal addr mode\n");
		break;
	case ILL_ILLTRP:
		fprintf(stdout, "illegal trap\n");
		break;
	case ILL_PRVOPC:
		fprintf(stdout, "illegal privilege opcode\n");
		break;
	case ILL_PRVREG:
		fprintf(stdout, "illegal privilege register\n");
		break;
	case ILL_COPROC:
		fprintf(stdout, "illegal cooperate register\n");
		break;
	case ILL_BADSTK:
		fprintf(stdout, "illegal stack error\n");
		break;
	default:
		fprintf(stdout, "SIGILL error: %d\n", code);
	}
}

static void dump_fpe(int code)
{
	switch (code) {
	case FPE_INTDIV:
		fprintf(stdout, "div by zero\n");
		break;
	case FPE_INTOVF:
		fprintf(stdout, "int overflow\n");
		break;
	case FPE_FLTDIV:
		fprintf(stdout, "float div by zero\n");
		break;
	case FPE_FLTOVF:
		fprintf(stdout, "float overflow\n");
		break;
	case FPE_FLTUND:
		fprintf(stdout, "float underflow\n");
		break;
	case FPE_FLTRES:
		fprintf(stdout, "float inaccurate result\n");
		break;
	case FPE_FLTINV:
		fprintf(stdout, "float invalid\n");
		break;
	case FPE_FLTSUB:
		fprintf(stdout, "float subscript out of range\n");
		break;
	default:
		fprintf(stdout, "SIGFPE error: %d\n", code);
	}
}

static void dump_segv(int code)
{
	switch (code) {
	case SEGV_MAPERR:
		fprintf(stdout, "addr not mapped\n");
		break;
	case SEGV_ACCERR:
		fprintf(stdout, "access error\n");
		break;
	default:
		fprintf(stdout, "SIGSEGV error: %d\n", code);
	}
}

static void dump_bus(int code)
{
	switch (code) {
	case BUS_ADRALN:
		fprintf(stdout, "addr not assigned right\n");
		break;
	case BUS_ADRERR:
		fprintf(stdout, "addr not exist\n");
		break;
	case BUS_OBJERR:
		fprintf(stdout, "hardware error\n");
		break;
	default:
		fprintf(stdout, "SIGBUS error: %d\n", code);
	}
}

static struct sigaction new_act, old_act;
static sigact_func callback;
static void self_sigact(int signo, siginfo_t *si, void *arg)
{
	switch (signo) {
	case SIGILL:
		fprintf(stdout, "receive SIGILL:\t");
		dump_ill(si->si_code);
		fprintf(stdout, "instruction addr:");
		break;
	case SIGFPE:
		fprintf(stdout, "receive SIGFPE:\t");
		dump_fpe(si->si_code);
		fprintf(stdout, "instruction addr:");
		break;
	case SIGSEGV:
		fprintf(stdout, "receive SIGSEGV:\t");
		dump_segv(si->si_code);
		fprintf(stdout, "operation addr:");
		break;
	case SIGBUS:
		fprintf(stdout, "receive SIGBUS:\t");
		dump_bus(si->si_code);
		fprintf(stdout, "\t\t");
		break;
	default:
		fprintf(stdout, "receive %d\n", signo);
	}
	fprintf(stdout, "\t=> %p:\t", si->si_addr);
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
	fprintf(stdout, "errno: %s\n\n", strerror(si->si_errno));

	dump_regs((ucontext_t *)arg);

	fprintf(stdout, "\nCall Stack:\n");
	print_bt_info((ucontext_t *)arg);
	fprintf(stdout, "\n");
	if (callback)
		callback(signo, si, arg);
	old_act.sa_handler(signo);
}

void set_eh(sigact_func func)
{
	memset((char *)&new_act, 0, sizeof(struct sigaction));
	memset((char *)&old_act, 0, sizeof(struct sigaction));
	callback = NULL;

	new_act.sa_flags = SA_SIGINFO | SA_INTERRUPT;
	sigemptyset(&new_act.sa_mask);
	sigaddset(&new_act.sa_mask, SIGILL);
	sigaddset(&new_act.sa_mask, SIGFPE);
	sigaddset(&new_act.sa_mask, SIGSEGV);
	sigaddset(&new_act.sa_mask, SIGBUS);

	new_act.sa_sigaction = self_sigact;
	sigaction(SIGILL, &new_act, &old_act);
	sigaction(SIGFPE, &new_act, &old_act);
	sigaction(SIGSEGV, &new_act, &old_act);
	sigaction(SIGBUS, &new_act, &old_act);

	callback = func;
}
