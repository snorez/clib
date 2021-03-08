/*
 * TODO
 *
 * Copyright (C) 2021 zerons
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

#ifndef QEMU_FUZZLIB_H_O9SRDRIE
#define QEMU_FUZZLIB_H_O9SRDRIE

#include "clib.h"

#define	QEMU_BOOTUP_STR0	"Linux version"
#define	QEMU_BOOTUP_STR1	"Command line"
#define	QEMU_BOOTUP_DONE_STR	"syzkaller login:"
#define	QEMU_GUEST_CONN_STR	"Connecting to host..."
#define	QEMU_GUEST_ERR		"Guest error."

enum qemu_fuzzlib_inst_res {
	QEMU_FUZZLIB_INST_INVALID = -1,
	QEMU_FUZZLIB_INST_NOT_TESTED = 0,
	QEMU_FUZZLIB_INST_VALID,
	QEMU_FUZZLIB_INST_BOOM,
};

enum qemu_fuzzlib_mutate_res {
	QEMU_FUZZLIB_MUTATE_ERR = -1,
	QEMU_FUZZLIB_MUTATE_OK = 0,
	QEMU_FUZZLIB_MUTATE_DONE,
};

struct qemu_fuzzlib_inst {
	mutex_t				lock;

	char				*inst_workdir;
	char				*sample_file;
	char				*copied_osimage;
	char				*vmlog;
	ssize_t				vmlog_readpos;
	int				listen_fd;
	int				listen_port;
	int				fwd_port;
	int				res;
	int				reason;
	int				qemu_pid;
	pthread_t			tid;
};

struct qemu_fuzzlib_env {
	char				*user_name;
	u64				user_id;

	char				*qemu_exec_path;
	char				*bzImage_file;
	char				*osimage_file;
	char				*host_id_rsa;
	char				*listen_ip;
	u32				instance_max;
	u32				idle_sec;
	u32				instance_memsz;
	u32				instance_core;
	char				*env_workdir;
	char				*guest_workdir;
	char				*guest_user;
	char				*script_file;
	char				*c_file;
	char				*sample_fname;

	char				*fuzz_db;
	int				(*db_init)(struct qemu_fuzzlib_env *);
	int				(*mutate)(struct qemu_fuzzlib_env *,
						  char *);

	/* XXX: the following fields are automatically generated */
	char				*crash_folder_name;
	char				*temp_folder_name;
	char				*not_tested_folder_name;
	char				*script_fname;
	char				*c_fname;
	u64				total_samples;
	u64				valid_samples;
	u64				crash_cnt;
	u64				not_tested_cnt;
	s64				last_crash_reason;
	struct qemu_fuzzlib_inst	*instances[0];
};

extern void qemu_fuzzlib_env_destroy(struct qemu_fuzzlib_env *env);
extern struct qemu_fuzzlib_env *
qemu_fuzzlib_env_setup(char *user_name, u64 user_id, char *qemu_exec_path,
			char *bzImage_file, char *osimage_file,
			char *host_id_rsa, char *listen_ip, u32 inst_max,
			u32 idle_sec, u32 inst_memsz, u32 inst_core,
			char *env_workdir, char *guest_workdir,
			char *guest_user, char *script_file, char *c_file,
			char *sample_fname, char *fuzz_db,
			int (*db_init)(struct qemu_fuzzlib_env *),
			int (*mutate)(struct qemu_fuzzlib_env *, char *));
extern int qemu_fuzzlib_env_run(struct qemu_fuzzlib_env *env);
extern int qemu_fuzzlib_gen_default_files(char *out_sh, char *out_c);

#endif /* end of include guard: QEMU_FUZZLIB_H_O9SRDRIE */
