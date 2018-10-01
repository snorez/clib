#include "../include/clib.h"

static __thread struct sigaction timer_new_sa, timer_old_sa;
static __thread unsigned long timer_sec = 0;
static __thread sigact_func timer_func;
static void loop_timer_func(int signo, siginfo_t *si, void *arg)
{
	timer_func(signo, si, arg);
	alarm(timer_sec);
}
void set_timer(unsigned long sec, sigact_func func, int need_loop)
{
	if (timer_new_sa.sa_flags)
		unset_timer();
	memset(&timer_new_sa, 0, sizeof(timer_new_sa));
	memset(&timer_old_sa, 0, sizeof(timer_old_sa));
	timer_sec = 0;
	timer_func = NULL;

	timer_new_sa.sa_flags = SA_SIGINFO | SA_INTERRUPT;
	sigemptyset(&timer_new_sa.sa_mask);
	sigaddset(&timer_new_sa.sa_mask, SIGALRM);

	if (!need_loop)
		timer_new_sa.sa_sigaction = func;
	else {
		timer_sec = sec;
		timer_func = func;
		timer_new_sa.sa_sigaction = loop_timer_func;
	}
	sigaction(SIGALRM, &timer_new_sa, &timer_old_sa);
	alarm(sec);
}

void unset_timer(void)
{
	alarm(0);
	memset(&timer_new_sa, 0, sizeof(timer_new_sa));
	sigaction(SIGALRM, &timer_old_sa, NULL);
}

static __thread void *process_cur, *process_goal;
static void timer_show_progress(int signo, siginfo_t *si, void *arg)
{
	show_progress(*(unsigned long *)process_cur, *(unsigned long *)process_goal);
}
void set_timer_show_progress(unsigned long sec, void *cur, void *total)
{
	process_cur = cur;
	process_goal = total;
	show_progress(*(unsigned long *)process_cur, *(unsigned long *)process_goal);
	set_timer(sec, timer_show_progress, 1);
}

void unset_timer_show_progress(void)
{
	show_progress(1, 1);
	unset_timer();
}
