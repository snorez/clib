/*
 * this file apply multi-thread timer support
 * for each thread, you can add several timer
 *
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
#include "../include/clib.h"

static LIST_HEAD(timer_head);
static rwlock_t timer_head_lock = RWLOCK_INIT_V;
static int mt_timer_callback_registered = 0;
static int timeout_less = 1;
static void mt_timer_callback(int signo, siginfo_t *si, void *arg)
{
	struct timeval tv_tmp;
	int err = gettimeofday(&tv_tmp, NULL);
	if (err == -1) {
		err_dbg(1, "gettimeofday err");
		return;
	}

	struct clib_timer *tmp;
	read_lock(&timer_head_lock);
	list_for_each_entry(tmp, &timer_head, sibling) {
		if ((tv_tmp.tv_sec - tmp->tv.tv_sec) < tmp->timeout)
			continue;
		if (((tv_tmp.tv_sec - tmp->tv.tv_sec) == tmp->timeout) &&
			(tv_tmp.tv_usec < tmp->tv.tv_usec))
			continue;
		if (tmp->arg)
			tmp->sig_action(signo, si, tmp->arg, 0);
		else
			tmp->sig_action(signo, si, arg, 0);
		memcpy(&tmp->tv, &tv_tmp, sizeof(tv_tmp));
	}
	read_unlock(&timer_head_lock);
	alarm(timeout_less);
}

/*
 * suggest to use self-defined arg, don't use thread-local variables in
 * signal handler
 */
int mt_add_timer(int timeout, clib_timer_func func, void *arg, int timer_id, int imm)
{
	if (unlikely(timeout < 1)) {
		err_dbg(0, "timeout invalid");
		return -1;
	}

	write_lock(&timer_head_lock);
	if (!mt_timer_callback_registered) {
		struct sigaction sa_tmp;
		memset(&sa_tmp, 0, sizeof(sa_tmp));
		sa_tmp.sa_flags = SA_SIGINFO | SA_INTERRUPT;
		sigemptyset(&sa_tmp.sa_mask);
		sigaddset(&sa_tmp.sa_mask, SIGALRM);
		sa_tmp.sa_sigaction = mt_timer_callback;
		sigaction(SIGALRM, &sa_tmp, NULL);
		mt_timer_callback_registered = 1;
		timeout_less = timeout;
	}
	write_unlock(&timer_head_lock);

	struct clib_timer *t;
	t = malloc(sizeof(*t));
	if (!t) {
		err_dbg(0, "malloc err");
		return -1;
	}
	memset(t, 0, sizeof(*t));

	int err = gettimeofday(&t->tv, NULL);
	if (err == -1) {
		err_dbg(0, "gettimeofday err");
		free(t);
		return -1;
	}

	t->sig_action = func;
	t->arg = arg;
	t->threadid = pthread_self();
	t->timeout = timeout;
	t->timer_id = timer_id;
	write_lock(&timer_head_lock);
	list_add_tail(&t->sibling, &timer_head);
	if (timeout_less > timeout)
		timeout_less = timeout;
	write_unlock(&timer_head_lock);

	if (imm)
		t->sig_action(SIGALRM, NULL, t->arg, 0);
	alarm(timeout_less);
	return 0;
}

void mt_del_timer(int timer_id)
{
	pthread_t del_id = pthread_self();

	struct clib_timer *tmp, *next;
	write_lock(&timer_head_lock);
	/* delete the last registered timer */
	list_for_each_entry_safe_reverse(tmp, next, &timer_head, sibling) {
		if (pthread_equal(tmp->threadid, del_id) &&
				(tmp->timer_id == timer_id)) {
			tmp->sig_action(SIGALRM, NULL, tmp->arg, 1);
			list_del(&tmp->sibling);
			free(tmp);
			goto unlock;
		}
	}

unlock:
	write_unlock(&timer_head_lock);
}
