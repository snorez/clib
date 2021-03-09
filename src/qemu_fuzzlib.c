/*
 * [*] setup qemu fuzzlib env
 *	* check the args
 *	* alloc a new qemu_fuzzlib_env
 *	* prepare each instance
 * [*] run the fuzzer
 *	* call mutate to generate a new sample
 *	* search an idle instance
 *	* start a new thread, run new sample in the instance
 */
#include "../include/qemu_fuzzlib.h"

static char *default_guest_sh_fname = "default_guest.sh";
static char *default_guest_c_fname = "default_guest.c";
static char *default_guest_sh_content = ""
"#!/bin/bash\n"
"\n"
"# Run: $0 HOST_IP HOST_PORT C_FILENAME SAMPLE_FILENAME\n"
"\n"
"if [[ $# != 4 ]]; then\n"
"\texit 0\n"
"fi\n"
"\n"
"GUEST_C_FILE=$3\n"
"GUEST_SAMPLE_FILE=$4\n"
"GUEST_C_OUT=qemu_fuzzlib_0\n"
"GUEST_SAMPLE_OUT=qemu_fuzzlib_1\n"
"\n"
"sudo -s chmod o+w /dev/kmsg 2>/dev/null\n"
"gcc $GUEST_C_FILE -o $GUEST_C_OUT && gcc $GUEST_SAMPLE_FILE -o $GUEST_SAMPLE_OUT && ./$GUEST_C_OUT $1 $2 $GUEST_SAMPLE_OUT &\n";

/*
 * run as [0] HOST_IP HOST_PORT child_exec_file
 * While trying to connect the host, MUST output the tag.
 *
 * The return value of sample(child_exec_file) can be:
 *	QEMU_FUZZLIB_INST_INVALID
 *	QEMU_FUZZLIB_INST_VALID
 *	QEMU_FUZZLIB_INST_BOOM
 */
static char *default_guest_c_content = ""
"#include <stdio.h>\n"
"#include <stdlib.h>\n"
"#include <string.h>\n"
"#include <unistd.h>\n"
"#include <sys/types.h>\n"
"#include <sys/socket.h>\n"
"#include <fcntl.h>\n"
"#include <sys/stat.h>\n"
"#include <netinet/in.h>\n"
"#include <arpa/inet.h>\n"
"#include <sys/wait.h>\n"
"#include <termios.h>\n"
"#include <syslog.h>\n"
"\n"
"#define	QEMU_GUEST_CONN_STR	\"Connecting to host...\"\n"
"#define	QEMU_GUEST_ERR		\"Guest error.\"\n"
"static char *outdev = \"/dev/kmsg\";\n"
"\n"
"enum qemu_fuzzlib_inst_res {\n"
"	QEMU_FUZZLIB_INST_INVALID = -1,\n"
"	QEMU_FUZZLIB_INST_NOT_TESTED = 0,\n"
"	QEMU_FUZZLIB_INST_VALID,\n"
"	QEMU_FUZZLIB_INST_BOOM,\n"
"};\n"
"\n"
"int write_to_console(char *msg)\n"
"{\n"
"	int fd = open(outdev, O_RDWR | O_APPEND);\n"
"	if (fd == -1) {\n"
"		return -1;\n"
"	}\n"
"\n"
"	if (strstr(msg, \"\\n\")) {\n"
"		write(fd, msg, strlen(msg));\n"
"	} else {\n"
"		char p[strlen(msg)+2];\n"
"		sprintf(p, \"%s\\n\", msg);\n"
"		write(fd, p, strlen(p));\n"
"	}\n"
"\n"
"	close(fd);\n"
"\n"
"	return 0;\n"
"}\n"
"\n"
"int main(int argc, char *argv[])\n"
"{\n"
"	int err = 0;\n"
"	int res[2] = {QEMU_FUZZLIB_INST_NOT_TESTED, 0};\n"
"	int pid;\n"
"	int sock;\n"
"	struct sockaddr_in sa;\n"
"	char *host_ip = NULL;\n"
"	int host_port = 0;\n"
"	char *sample_exec = NULL;\n"
"\n"
"	int _pid;\n"
"	if ((_pid = fork()) < 0) {\n"
"		exit(-1);\n"
"	} else if (_pid > 0) {\n"
"		exit(0);\n"
"	}\n"
"\n"
"	setsid();\n"
"	if ((_pid = fork()) < 0) {\n"
"		exit(-1);\n"
"	} else if (_pid > 0) {\n"
"		exit(0);\n"
"	}\n"
"\n"
"	signal(SIGPIPE, SIG_IGN);\n"
"\n"
"	if ((argc != 4) && (argc != 2)) {\n"
"		write_to_console(QEMU_GUEST_ERR);\n"
"		return -1;\n"
"	}\n"
"\n"
"	if (argc == 4) {\n"
"		host_ip = argv[1];\n"
"		host_port = atoi(argv[2]);\n"
"		sample_exec = argv[3];\n"
"	} else if (argc == 2) {\n"
"		sample_exec = argv[1];\n"
"	}\n"
"\n"
"	if (host_ip) {\n"
"		sock = socket(AF_INET, SOCK_STREAM, 0);\n"
"		if (sock == -1) {\n"
"			write_to_console(QEMU_GUEST_ERR);\n"
"			return -1;\n"
"		}\n"
"\n"
"		memset(&sa, 0, sizeof(sa));\n"
"		sa.sin_family = AF_INET;\n"
"		sa.sin_port = htons(host_port);\n"
"		sa.sin_addr.s_addr = inet_addr(host_ip);\n"
"		write_to_console(QEMU_GUEST_CONN_STR);\n"
"		err = connect(sock, (struct sockaddr *)&sa, sizeof(sa));\n"
"		if (err == -1) {\n"
"			write_to_console(QEMU_GUEST_ERR);\n"
"			return -1;\n"
"		}\n"
"	}\n"
"\n"
"	if ((pid = fork()) < 0) {\n"
"		res[0] = QEMU_FUZZLIB_INST_NOT_TESTED;\n"
"		res[1] = __LINE__;\n"
"	} else if (pid == 0) {\n"
"		err = execl(sample_exec, sample_exec, NULL);\n"
"		if (err == -1) {\n"
"			exit(QEMU_FUZZLIB_INST_NOT_TESTED);\n"
"		}\n"
"		exit(0);\n"
"	} else {\n"
"		int time_usleep = 3000;\n"
"		int timeout_left = time_usleep * 1000;\n"
"		int need_kill = 0;\n"
"		int status = 0;\n"
"		char retval = 0;\n"
"\n"
"		while (1) {\n"
"			err = waitpid(pid, &status, WNOHANG);\n"
"			if (err == pid)\n"
"				break;\n"
"			if (timeout_left <= 0) {\n"
"				need_kill = 1;\n"
"				break;\n"
"			}\n"
"			usleep(time_usleep);\n"
"			timeout_left -= time_usleep;\n"
"		}\n"
"\n"
"		if (need_kill) {\n"
"			res[0] = QEMU_FUZZLIB_INST_BOOM;\n"
"			res[1] = __LINE__;\n"
"		} else if (WIFEXITED(status)) {\n"
"			res[0] = (int)(char)WEXITSTATUS(status);\n"
"			res[1] = __LINE__;\n"
"		} else if (WIFSIGNALED(status)) {\n"
"			char p[0x100];\n"
"			snprintf(p, 0x100, \"%d\\n\", WTERMSIG(status));\n"
"			write_to_console(p);\n"
"			res[0] = QEMU_FUZZLIB_INST_BOOM;\n"
"			res[1] = __LINE__;\n"
"		}\n"
"	}\n"
"\n"
"	if (host_ip) {\n"
"		err = write(sock, res, sizeof(res));\n"
"		if (err == -1) {\n"
"			write_to_console(QEMU_GUEST_ERR);\n"
"			return -1;\n"
"		}\n"
"	} else {\n"
"		fprintf(stderr, \"res[0]: %d, res[1]: %d\\n\", res[0], res[1]);\n"
"	}\n"
"\n"
"	return 0;\n"
"}\n";

static int gen_default_file(char *out, char *content)
{
	int err = 0;
	size_t sz = strlen(content);
	int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
	if (fd == -1) {
		err_dbg(1, "open err");
		return -1;
	}

	err = write(fd, content, sz);
	if (err != sz) {
		if (err == -1)
			err_dbg(1, "write err");
		err = -1;
		goto err_out;
	}

	close(fd);
	return 0;

err_out:
	close(fd);
	return -1;
}

static int gen_default_sh(char *out)
{
	return gen_default_file(out, default_guest_sh_content);
}

static int gen_default_c(char *out)
{
	return gen_default_file(out, default_guest_c_content);
}

int qemu_fuzzlib_gen_default_files(char *out_sh, char *out_c)
{
	int err;

	err = gen_default_sh(out_sh);
	if (err == -1) {
		err_dbg(0, "gen_default_sh err");
		return -1;
	}

	err = gen_default_c(out_c);
	if (err == -1) {
		err_dbg(0, "gen_default_c err");
		return -1;
	}

	return 0;
}

static mutex_t fwd_port_lock;

static struct qemu_fuzzlib_inst *inst_alloc(void)
{
	struct qemu_fuzzlib_inst *inst;
	inst = (struct qemu_fuzzlib_inst *)malloc(sizeof(*inst));
	if (!inst) {
		err_dbg(0, "malloc err");
		return NULL;
	}
	
	memset(inst, 0, sizeof(*inst));

	return inst;
}

static void inst_free(struct qemu_fuzzlib_inst *inst)
{
	free(inst);
	return;
}

static int inst_setup_listener(struct qemu_fuzzlib_inst *inst)
{
	inst->listen_fd = clib_listen_sock(AF_INET, SOCK_STREAM, 0, 1,
						&inst->listen_port);
	if (inst->listen_fd == -1) {
		err_dbg(0, "clib_listen_sock err");
		return -1;
	}

	return 0;
}

static int inst_init(struct qemu_fuzzlib_env *env,
			struct qemu_fuzzlib_inst *inst, char *workdir)
{
	static char *copied_osimage = "osimage.img";
	static char *vmlog = "vm.log";
	char p[PATH_MAX];
	int err = 0;

	if (!inst->sample_file) {
		snprintf(p, PATH_MAX, "%s/%s", workdir, env->sample_fname);
		inst->sample_file = strdup(p);
		if (!inst->sample_file) {
			err_dbg(1, "strdup err");
			return -1;
		}
	}

	if (!inst->copied_osimage) {
		snprintf(p, PATH_MAX, "%s/%s", workdir, copied_osimage);
		inst->copied_osimage = strdup(p);
		if (!inst->copied_osimage) {
			err_dbg(1, "strdup err");
			return -1;
		}

		if (!path_exists(inst->copied_osimage)) {
			err = clib_copy_file(env->osimage_file,
					     inst->copied_osimage, 0);
			if (err < 0) {
				err_dbg(0, "clib_copy_file err");
				return -1;
			}
		}
	}

	if (!inst->vmlog) {
		snprintf(p, PATH_MAX, "%s/%s", workdir, vmlog);
		inst->vmlog = strdup(p);
		if (!inst->vmlog) {
			err_dbg(1, "strdup err");
			return -1;
		}
	}

	err = inst_setup_listener(inst);
	if (err < 0) {
		err_dbg(0, "inst_setup_listener err");
		return -1;
	}

	inst->inst_workdir = workdir;
	inst->res = QEMU_FUZZLIB_INST_NOT_TESTED;
	inst->tid = 0;
	inst->qemu_pid = -1;

	return 0;
}

static __maybe_unused int inst_destroy_child(int pid)
{
	int err = 0;
	err = kill(pid, SIGTERM);
	if (err == -1) {
		err_dbg(1, "kill err");
	}
	waitpid(pid, NULL, 0);
	return err;
}

static int inst_destroy_child_all(int pid)
{
	/*
	 * Use SIGTERM to terminate qemu processes nicely.
	 * SIGKILL will cause the terminal no echo.
	 */
	int err = 0;
	err = killpg(getpgid(pid), SIGTERM);
	if (err == -1) {
		err_dbg(1, "killpg err");
	}
	waitpid(pid, NULL, 0);
	return err;
}

static void inst_destroy(struct qemu_fuzzlib_inst *inst)
{
	BUG_ON(atomic_read(&inst->lock));

	free(inst->inst_workdir);
	free(inst->sample_file);
	free(inst->copied_osimage);
	close(inst->listen_fd);

	inst_free(inst);

	return;
}

static int prepare_launch_args_begin(struct qemu_fuzzlib_env *env,
					struct qemu_fuzzlib_inst *inst,
					char **args)
{
	char p[PATH_MAX];

	args[0] = "/bin/bash";
	args[1] = "-c";

	snprintf(p, PATH_MAX, "%s -m %dG -smp %d -kernel %s -append \"console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0\" -drive file=%s,format=raw -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:%d-:22 -net nic,model=e1000 -enable-kvm -nographic", env->qemu_exec_path, env->instance_memsz, env->instance_core, env->bzImage_file, inst->copied_osimage, inst->fwd_port);
	args[2] = strdup(p);
	if (!args[2]) {
		err_dbg(1, "strdup err");
		return -1;
	}

	args[3] = NULL;

	return 0;
}

static int prepare_launch_args_end(char **args)
{
	free(args[2]);
	return 0;
}

static int inst_vmlog_filter(struct qemu_fuzzlib_env *env,
				struct qemu_fuzzlib_inst *inst,
				char *keystr)
{
	int err = 0;
	char *b, *p;
	if (path_exists(inst->vmlog)) {
		b = clib_loadfile(inst->vmlog, NULL);
		p = b + inst->vmlog_readpos;

		p = strstr(p, keystr);
		if (!p) {
			err = 0;
		} else {
			err = 1;
			inst->vmlog_readpos = p + strlen(keystr) + 1 - b;
		}

		free(b);
	}
	return err;
}

static int inst_launch_qemu(struct qemu_fuzzlib_env *env,
				struct qemu_fuzzlib_inst *inst,
				char **args)
{
	int err = 0;
	int pid;
	int retval;
	int qemu_is_running = 0;
	int qemu_bootup_done = 0;

	if (path_exists(inst->vmlog)) {
		close(open(inst->vmlog, O_WRONLY | O_TRUNC));
	}

	if ((pid = fork()) < 0) {
		err_dbg(1, "fork err");
		return -1;
	} else if (pid == 0) {
		setsid();

		extern char **environ;
		int fd = open(inst->vmlog,
				O_WRONLY | O_CREAT | O_TRUNC,
				S_IRWXU);
		if (fd == -1) {
			err_dbg(1, "open err");
			exit(-1);
		}

		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);

		err = execve(args[0], args, environ);
		if (err == -1) {
			err_dbg(1, "execve err");
			exit(-1);
		}
		exit(0);
	}

	while (1) {
		char *b = NULL;
		if (path_exists(inst->vmlog))
			b = clib_loadfile(inst->vmlog, NULL);

		if (b) {
			if ((!qemu_is_running) &&
			    (strstr(b, QEMU_BOOTUP_STR0) ||
			     strstr(b, QEMU_BOOTUP_STR1))) {
				qemu_is_running = 1;
			}

			if (qemu_is_running && strstr(b, QEMU_BOOTUP_DONE_STR)) {
				qemu_bootup_done = 1;
			}

			free(b);
		}

		if (qemu_bootup_done)
			break;

		if (!qemu_is_running) {
			err = waitpid(pid, &retval, WNOHANG);
			if (err == -1) {
				err_dbg(1, "waitpid err");
			} else if (err == pid) {
				err_dbg(0, "qemu launch err");
				return -1;
			}
		}
	}

	return pid;
}

static int inst_call_system(char *cmd)
{
	errno = 0;
	int err = system(cmd);
	if (err) {
		err_dbg(1, "system err");
		return -1;
	}

	return 0;
}

static int inst_exec_cmd(struct qemu_fuzzlib_env *env,
				struct qemu_fuzzlib_inst *inst,
				char *_cmd)
{
	static u32 cmdsz = 0x1000;
	char cmd[cmdsz];
	snprintf(cmd, cmdsz, "ssh -q -i %s -p %d -o \"StrictHostKeyChecking no\" %s@127.0.0.1 \"%s\"", env->host_id_rsa, inst->fwd_port, env->guest_user, _cmd);
	return inst_call_system(cmd);
}

static int inst_create_workdir(struct qemu_fuzzlib_env *env,
				struct qemu_fuzzlib_inst *inst)
{
	static u32 cmdsz = 0x1000;
	char cmd[cmdsz];
	snprintf(cmd, cmdsz, "mkdir -p %s", env->guest_workdir);
	return inst_exec_cmd(env, inst, cmd);
}

static int inst_upload_file(struct qemu_fuzzlib_env *env,
				struct qemu_fuzzlib_inst *inst,
				char *src)
{
	static u32 cmdsz = 0x1000;
	char cmd[cmdsz];
	snprintf(cmd, cmdsz, "scp -q -i %s -P %d -o \"StrictHostKeyChecking no\" %s %s@127.0.0.1:%s/", env->host_id_rsa, inst->fwd_port, src, env->guest_user, env->guest_workdir);
	return inst_call_system(cmd);
}

static int inst_run_script(struct qemu_fuzzlib_env *env,
				struct qemu_fuzzlib_inst *inst)
{
	static u32 cmdsz = 0x1000;
	char cmd[cmdsz];
	int pid;
	snprintf(cmd, cmdsz, "ssh -q -i %s -p %d -o \"StrictHostKeyChecking no\" %s@127.0.0.1 \"cd %s; chmod +x ./%s; ./%s %s %d %s %s\"",
			env->host_id_rsa, inst->fwd_port, env->guest_user,
			env->guest_workdir, env->script_fname,
			env->script_fname, env->listen_ip, inst->listen_port,
			env->c_fname, env->sample_fname);

	if ((pid = fork()) < 0) {
		return -1;
	} else if (pid == 0) {
		close(0);
		close(1);
		close(2);
		int err = system(cmd);
		exit(err);
	}

	return pid;
}

static int find_valid_fwd_port(struct qemu_fuzzlib_inst *inst)
{
	int sock;
	sock = clib_listen_sock(AF_INET, SOCK_STREAM, 0, 1, &inst->fwd_port);
	if (sock == -1) {
		err_dbg(0, "clib_listen_sock err");
		return -1;
	}

	close(sock);
	return 0;
}

/*
 * Return value:
 *	QEMU_FUZZLIB_INST_NOT_TESTED
 *	others
 */
static int inst_run(struct qemu_fuzzlib_env *env, struct qemu_fuzzlib_inst *inst)
{
	/*
	 * launch the qemu process
	 * upload the files
	 * run the script file
	 * host accept the new connection
	 * wait for the exit code
	 * kill the qemu process
	 * drop the lock on inst
	 */

	static u32 accept_timeout = 9000*1000;
	u32 cur_usleep = 0;
	int err = QEMU_FUZZLIB_INST_NOT_TESTED;
	int test_res[2] = {QEMU_FUZZLIB_INST_NOT_TESTED, 0};
	int need_kill_qemu = 0;
	int run_script_pid;
	int fd;
	char *launch_args[0x30] = {0};

	if (inst->qemu_pid == -1) {
		mutex_lock(&fwd_port_lock);

		err = find_valid_fwd_port(inst);
		if (err < 0) {
			err_dbg(0, "find_valid_fwd_port err");
			err = QEMU_FUZZLIB_INST_NOT_TESTED;
			mutex_unlock(&fwd_port_lock);
			goto out;
		}

		err = prepare_launch_args_begin(env, inst, launch_args);
		if (err < 0) {
			err_dbg(0, "prepare_launch_args_begin err");
			err = QEMU_FUZZLIB_INST_NOT_TESTED;
			mutex_unlock(&fwd_port_lock);
			goto out;
		}

		inst->vmlog_readpos = 0;
		inst->qemu_pid = inst_launch_qemu(env, inst, launch_args);
		mutex_unlock(&fwd_port_lock);
		if (inst->qemu_pid < 0) {
			err_dbg(0, "inst_launch_qemu err");
			err = QEMU_FUZZLIB_INST_NOT_TESTED;
			goto free_out;
		}

		err = inst_create_workdir(env, inst);
		if (err < 0) {
			err_dbg(0, "inst_create_workdir err");
			err = QEMU_FUZZLIB_INST_NOT_TESTED;
			goto kill_out;
		}
	}

	err = inst_upload_file(env, inst, env->script_file);
	if (err < 0) {
		err_dbg(0, "inst_upload_file err");
		err = QEMU_FUZZLIB_INST_NOT_TESTED;
		/* if upload failed, launch qemu again. */
		need_kill_qemu = 1;
		goto kill_out;
	}

	err = inst_upload_file(env, inst, env->c_file);
	if (err < 0) {
		err_dbg(0, "inst_upload_file err");
		err = QEMU_FUZZLIB_INST_NOT_TESTED;
		goto kill_out;
	}

	err = inst_upload_file(env, inst, inst->sample_file);
	if (err < 0) {
		err_dbg(0, "inst_upload_file err");
		err = QEMU_FUZZLIB_INST_NOT_TESTED;
		goto kill_out;
	}

	run_script_pid = inst_run_script(env, inst);
	if (run_script_pid < 0) {
		err_dbg(0, "inst_exec_file err");
		err = QEMU_FUZZLIB_INST_NOT_TESTED;
		goto kill_out;
	}

	while (!inst_vmlog_filter(env, inst, QEMU_GUEST_CONN_STR)) {
		usleep(3);
		cur_usleep += 3;
		if (cur_usleep > accept_timeout) {
			err_dbg(0, "The guest doesn't try to connect host.");
			err = QEMU_FUZZLIB_INST_NOT_TESTED;
			goto kill1_out;
		}

		if (inst_vmlog_filter(env, inst, QEMU_GUEST_ERR)) {
			err_dbg(0, "The guest process failed.");
			err = QEMU_FUZZLIB_INST_NOT_TESTED;
			goto kill1_out;
		}
	}

	fd = accept(inst->listen_fd, NULL, NULL);
	if (fd == -1) {
		need_kill_qemu = 1;
		err_dbg(1, "accept err");
		err = QEMU_FUZZLIB_INST_NOT_TESTED;
		goto kill1_out;
	}

	/*
	 * as of now, the sample is supposed to be running. Just read the
	 * return status.
	 */
	err = read(fd, test_res, sizeof(test_res));
	if (err != sizeof(test_res)) {
		need_kill_qemu = 1;
		test_res[0] = QEMU_FUZZLIB_INST_BOOM;
		test_res[1] = __LINE__;
	}

	err = !(QEMU_FUZZLIB_INST_NOT_TESTED);
	inst->res = test_res[0];
	inst->reason = test_res[1];
	if (inst->res == QEMU_FUZZLIB_INST_BOOM) {
		need_kill_qemu = 1;
	}
	close(fd);

kill1_out:
	(void)inst_destroy_child(run_script_pid);

kill_out:
	if (need_kill_qemu) {
		(void)inst_destroy_child_all(inst->qemu_pid);
		inst->qemu_pid = -1;
	}

free_out:
	if (launch_args[0])
		prepare_launch_args_end(launch_args);

out:
	mutex_unlock(&inst->lock);
	return err;
}

static void *run_inst_in_thread(void *arg)
{
	int err = 0;
	long *args = (long *)arg;
	struct qemu_fuzzlib_env *env;
	struct qemu_fuzzlib_inst *inst;
	int *run, *ready;

	env = (void *)args[0];
	inst = (void *)args[1];
	run = (void *)args[2];
	ready = (void *)args[3];

	while (!*run) {
		usleep(3);
	}

	*ready = 1;

	err = inst_run(env, inst);

	return (void *)(long)err;
}

/*
 * Return value:
 *	-1: the thread is not created.
 *	0: thread is running, check the inst->res for the return code.
 */
static int env_run_inst(struct qemu_fuzzlib_env *env,
			struct qemu_fuzzlib_inst *inst)
{
	int err = 0, run = 0, ready = 0;
	pthread_t tid;
	long arg[4];
	arg[0] = (long)env;
	arg[1] = (long)inst;
	arg[2] = (long)&run;
	arg[3] = (long)&ready;

	err = pthread_create(&tid, NULL, run_inst_in_thread, (void *)arg);
	if (err != 0) {
		err_dbg1(err, "pthread_create err");
		return -1;
	}

	inst->tid = tid;
	run = 1;

	while (!ready) {
		usleep(3);
	}

	return 0;
}

static struct qemu_fuzzlib_env *env_alloc(u64 inst_max)
{
	struct qemu_fuzzlib_env *env;
	u64 sz = sizeof(*env) + inst_max * sizeof(env->instances[0]);

	env = (struct qemu_fuzzlib_env *)malloc(sz);
	if (!env) {
		err_dbg(0, "malloc err");
		return NULL;
	}

	memset(env, 0, sz);

	return env;
}

static void env_free(struct qemu_fuzzlib_env *env)
{
	free(env);
	return;
}

static u64 system_instance_max = 0;
static void get_system_instance_max(void)
{
	system_instance_max = 0x20;
}

static int env_validate_args(char *qemu_exec_path, char *bzImage_file,
				char *osimage_file, char *host_id_rsa,
				u64 inst_max, char *guest_user,
				char *script_file, char *c_file,
				int (*mutate)(struct qemu_fuzzlib_env *, char *))
{
	if ((!abs_path(qemu_exec_path)) || (!path_exists(qemu_exec_path))) {
		err_dbg(0, "%s is not abspath or not exists", qemu_exec_path);
		return -1;
	}

	if ((!abs_path(bzImage_file)) || (!path_exists(bzImage_file))) {
		err_dbg(0, "%s is not abspath or not exists", bzImage_file);
		return -1;
	}

	if ((!abs_path(osimage_file)) || (!path_exists(osimage_file))) {
		err_dbg(0, "%s is not abspath or not exists", osimage_file);
		return -1;
	}

	if ((!abs_path(host_id_rsa)) || (!path_exists(host_id_rsa))) {
		err_dbg(0, "%s is not abspath or not exists", host_id_rsa);
		return -1;
	}

	if (!system_instance_max) {
		get_system_instance_max();
	}
	if (inst_max > system_instance_max) {
		err_dbg(0, "too many instances, max %lld", system_instance_max);
		return -1;
	}

	if (!guest_user) {
		err_dbg(0, "Must specify a system user");
		return -1;
	}

	if (script_file &&
	    ((!abs_path(script_file)) || (!path_exists(script_file)))) {
		err_dbg(0, "%s is not abspath or not exists", script_file);
		return -1;
	}

	if (c_file && ((!abs_path(c_file)) || (!path_exists(c_file)))) {
		err_dbg(0, "%s is not abspath or not exists", c_file);
		return -1;
	}

	if (!mutate) {
		err_dbg(0, "No mutate callback");
		return -1;
	}

	return 0;
}

static int dummy_db_init(struct qemu_fuzzlib_env *env)
{
	env->total_samples = 0;
	env->valid_samples = 0;
	env->crash_cnt = 0;
	return 0;
}

static char *env_set_fname(struct qemu_fuzzlib_env *env, char *fpath)
{
	char *p;
	p = strrchr(fpath, '/');
	if (!p) {
		err_dbg(0, "/ not found in %s", fpath);
		return NULL;
	}

	return p+1;
}

static int env_init(struct qemu_fuzzlib_env *env, char *user_name, u64 user_id,
			char *qemu_exec_path, char *bzImage_file,
			char *osimage_file, char *host_id_rsa, char *listen_ip,
			u32 inst_max, u32 idle_sec, u32 inst_memsz,
			u32 inst_core, char *env_workdir, char *guest_workdir,
			char *guest_user, char *script_file, char *c_file,
			char *sample_fname, char *fuzz_db,
			int (*db_init)(struct qemu_fuzzlib_env *),
			int (*mutate)(struct qemu_fuzzlib_env *, char *))
{
	static char *crash_folder_name = "crash";
	static char *not_tested_folder_name = "not-tested";
	static char *temp_folder_name = "tmp";

	env->user_name = user_name;
	env->user_id = user_id;
	env->qemu_exec_path = qemu_exec_path;
	env->bzImage_file = bzImage_file;
	env->osimage_file = osimage_file;
	env->host_id_rsa = host_id_rsa;
	env->listen_ip = listen_ip;
	env->instance_max = inst_max;
	env->idle_sec = idle_sec;
	env->instance_memsz = inst_memsz;
	env->instance_core = inst_core;
	env->env_workdir = env_workdir;
	env->guest_workdir = guest_workdir;
	env->guest_user = guest_user;
	if (script_file) {
		env->script_file = strdup(script_file);
		if (!env->script_file) {
			err_dbg(1, "strdup err");
			return -1;
		}
	}
	if (c_file) {
		env->c_file = strdup(c_file);
		if (!env->c_file) {
			err_dbg(1, "strdup err");
			return -1;
		}
	}
	env->sample_fname = sample_fname;
	env->fuzz_db = fuzz_db;
	if (db_init) {
		env->db_init = db_init;
	} else {
		env->db_init = dummy_db_init;
	}
	env->mutate = mutate;

	env->crash_folder_name = crash_folder_name;
	env->temp_folder_name = temp_folder_name;
	env->not_tested_folder_name = not_tested_folder_name;

	return env->db_init(env);
}

static int env_prepare_instances(struct qemu_fuzzlib_env *env)
{
	int err = 0;

	for (u64 i = 0; i < env->instance_max; i++) {
		struct qemu_fuzzlib_inst *inst;
		u64 workdir_sz = strlen(env->env_workdir) + 0x20;
		char workdir[workdir_sz], *_workdir;
		snprintf(workdir, workdir_sz, "%s/instance_%llx",
			 env->env_workdir, i);
		_workdir = strdup(workdir);
		if (!_workdir) {
			err_dbg(1, "strdup err");
			err = -1;
			break;
		}

		err = mkdir(_workdir, S_IRWXU);
		if ((err == -1) && (errno != EEXIST)) {
			err_dbg(1, "mkdir err");
			break;
		}

		env->instances[i] = inst_alloc();
		if (!env->instances[i]) {
			err_dbg(0, "inst_alloc err");
			err = -1;
			break;
		}
		inst = env->instances[i];

		err = inst_init(env, inst, _workdir);
		if (err < 0) {
			err_dbg(0, "inst_init err");
			err = -1;
			break;
		}
	}

	return err;
}

static int env_prepare(struct qemu_fuzzlib_env *env)
{
	int err = 0;
	char p[PATH_MAX];

	if (!path_exists(env->env_workdir)) {
		err = mkdir(env->env_workdir, S_IRWXU);
		if ((err == -1) && (errno != EEXIST)) {
			err_dbg(1, "mkdir err");
			return -1;
		}
	}

	err = chdir(env->env_workdir);
	if (err == -1) {
		err_dbg(1, "chdir err");
		return -1;
	}

	if (!path_exists(env->crash_folder_name)) {
		err = mkdir(env->crash_folder_name, S_IRWXU);
		if ((err == -1) && (errno != EEXIST)) {
			err_dbg(1, "mkdir err");
			return -1;
		}
	}

	if (!path_exists(env->temp_folder_name)) {
		err = mkdir(env->temp_folder_name, S_IRWXU);
		if ((err == -1) && (errno != EEXIST)) {
			err_dbg(1, "mkdir err");
			return -1;
		}
	}

	if (!path_exists(env->not_tested_folder_name)) {
		err = mkdir(env->not_tested_folder_name, S_IRWXU);
		if ((err == -1) && (errno != EEXIST)) {
			err_dbg(1, "mkdir err");
			return -1;
		}
	}

	if (!env->script_file) {
		env->script_fname = default_guest_sh_fname;
		snprintf(p, PATH_MAX, "%s/%s/%s", env->env_workdir,
				env->temp_folder_name, env->script_fname);
		env->script_file = strdup(p);
		if (!env->script_file) {
			err_dbg(1, "strdup err");
			return -1;
		}

		err = gen_default_sh(env->script_file);
		if (err == -1) {
			err_dbg(0, "gen_default_sh err");
			return -1;
		}
	} else {
		env->script_fname = env_set_fname(env, env->script_file);
		if (!env->script_fname) {
			err_dbg(0, "env_set_fname err");
			return -1;
		}
	}

	if (!env->c_file) {
		env->c_fname = default_guest_c_fname;
		snprintf(p, PATH_MAX, "%s/%s/%s", env->env_workdir,
				env->temp_folder_name, env->c_fname);
		env->c_file = strdup(p);
		if (!env->c_file) {
			err_dbg(1, "strdup err");
			return -1;
		}

		err = gen_default_c(env->c_file);
		if (err == -1) {
			err_dbg(0, "gen_default_c err");
			return -1;
		}
	} else {
		env->c_fname = env_set_fname(env, env->c_file);
		if (!env->c_fname) {
			err_dbg(0, "env_set_fname err");
			return -1;
		}
	}

	err = env_prepare_instances(env);
	if (err < 0) {
		err_dbg(0, "env_prepare_instances err");
		return -1;
	}

	return 0;
}

static void env_verbose(struct qemu_fuzzlib_env *env)
{
	fprintf(stdout, "[%s]: total: %lld, valid: %lld(%.3f%%), "
			"crash: %lld(reason: %lld)\n",
			env->user_name, env->total_samples, env->valid_samples,
			(double)env->valid_samples * 100 / env->total_samples,
			env->crash_cnt, env->last_crash_reason);
}

static struct qemu_fuzzlib_inst *env_idle_inst(struct qemu_fuzzlib_env *env)
{
	for (u64 i = 0; i < env->instance_max; i++) {
		if (mutex_try_lock(&env->instances[i]->lock)) {
			return env->instances[i];
		}
	}

	return NULL;
}

static int env_idle(struct qemu_fuzzlib_env *env)
{
	for (u64 i = 0; i < env->instance_max; i++) {
		if (mutex_try_lock(&env->instances[i]->lock)) {
			mutex_unlock(&env->instances[i]->lock);
			continue;
		}

		return 0;
	}

	return 1;
}

static int env_save_file_to(char *src, char *workdir, char *folder, u64 idx,
				char *sample_fname)
{
	u64 pathsz;
	int rename = 0;
	int fd_out = -1;
	size_t infile_sz = 0;
	char *inb = NULL;
	int err = 0;

	pathsz = strlen(workdir) + strlen(folder) + 0x18;
	char save_path[pathsz];

	do {
		if (!rename) {
			snprintf(save_path, pathsz, "%s/%s/%lld_%s",
				 workdir, folder, idx, sample_fname);
		} else {
			snprintf(save_path, pathsz, "%s/%s/%lld_%d_%s",
				 workdir, folder, idx, rename, sample_fname);
		}

		if (path_exists(save_path)) {
#if 0
			err_dbg(0, "%s already exists", save_path);
#endif
			rename++;
		} else {
			rename = 0;
		}
	} while (rename);

	fd_out = open(save_path, O_WRONLY | O_CREAT, S_IRWXU);
	if (fd_out == -1) {
		err_dbg(1, "open err");
		return -1;
	}

	inb = clib_loadfile(src, &infile_sz);
	if (!inb) {
		err_dbg(0, "clib_loadfile err");
		err = -1;
		goto err_out;
	}

	err = write(fd_out, inb, infile_sz);
	if (err != infile_sz) {
		err_dbg(1, "write wrong(%d, %ld)", err, infile_sz);
		err = -1;
		goto err_out;
	}

err_out:
	if (inb) {
		free(inb);
		inb = NULL;
	}

	if (fd_out != -1) {
		close(fd_out);
		fd_out = -1;
	}

	return err;
}

static int env_save_crash(struct qemu_fuzzlib_env *env,
			  struct qemu_fuzzlib_inst *inst)
{
	return env_save_file_to(inst->sample_file, env->env_workdir,
				env->crash_folder_name, env->crash_cnt,
				env->sample_fname);
}

static int env_save_not_tested(struct qemu_fuzzlib_env *env,
				struct qemu_fuzzlib_inst *inst)
{
	return env_save_file_to(inst->sample_file, env->env_workdir,
				env->not_tested_folder_name,
				env->not_tested_cnt, env->sample_fname);
}

static int env_acct(struct qemu_fuzzlib_env *env, struct qemu_fuzzlib_inst *inst)
{
	int err = 0;

	env->total_samples++;
	if (inst->res != QEMU_FUZZLIB_INST_INVALID) {
		env->valid_samples++;
	}

	if (inst->res == QEMU_FUZZLIB_INST_BOOM) {
		err = env_save_crash(env, inst);
		env->crash_cnt++;
		env->last_crash_reason = inst->reason;
	}

	return err;
}

static void env_check_inst_res(struct qemu_fuzzlib_env *env,
				struct qemu_fuzzlib_inst *inst, int *updated)
{
	*updated = 0;

	if (!inst->tid)
		return;

	*updated = 1;

	void *retval = (void *)QEMU_FUZZLIB_INST_NOT_TESTED;
	int err = 0;
	err = pthread_join(inst->tid, &retval);
	if (err != 0) {
		err_dbg1(err, "pthread_join err");
	}
	inst->tid = 0;

	/* the thread will return NOT_TESTED or TESTED */
	if ((retval == (void *)QEMU_FUZZLIB_INST_NOT_TESTED) ||
	    (inst->res == QEMU_FUZZLIB_INST_NOT_TESTED)) {
		err = env_save_not_tested(env, inst);
		if (err < 0) {
			err_dbg(0, "env_save_not_tested err");
		} else {
			env->not_tested_cnt++;
		}
	} else {
		err = env_acct(env, inst);
		if (err < 0) {
			err_dbg(0, "env_acct err");
		}
	}
	inst->res = QEMU_FUZZLIB_INST_NOT_TESTED;

	return;
}

void qemu_fuzzlib_env_destroy(struct qemu_fuzzlib_env *env)
{
	for (u64 i = 0; i < env->instance_max; i++) {
		struct qemu_fuzzlib_inst *inst;
		inst = env->instances[i];
		(void)inst_destroy(inst);
		env->instances[i] = NULL;
	}

	free(env->script_file);
	free(env->c_file);
	env_free(env);

	return;
}

struct qemu_fuzzlib_env *
qemu_fuzzlib_env_setup(char *user_name, u64 user_id, char *qemu_exec_path,
			char *bzImage_file, char *osimage_file,
			char *host_id_rsa, char *listen_ip, u32 inst_max,
			u32 idle_sec, u32 inst_memsz, u32 inst_core,
			char *env_workdir, char *guest_workdir,
			char *guest_user, char *script_file, char *c_file,
			char *sample_fname, char *fuzz_db,
			int (*db_init)(struct qemu_fuzzlib_env *),
			int (*mutate)(struct qemu_fuzzlib_env *, char *))
{
	struct qemu_fuzzlib_env *env = NULL;
	int err = 0;

	err = env_validate_args(qemu_exec_path, bzImage_file, osimage_file,
				host_id_rsa, inst_max, guest_user, script_file,
				c_file, mutate);
	if (err < 0) {
		err_dbg(0, "env_validate_args err");
		return NULL;
	}

	env = env_alloc(inst_max);
	if (!env) {
		err_dbg(0, "env_alloc err");
		return NULL;
	}

	err = env_init(env, user_name, user_id, qemu_exec_path, bzImage_file,
			osimage_file, host_id_rsa, listen_ip, inst_max,
			idle_sec, inst_memsz, inst_core, env_workdir,
			guest_workdir, guest_user, script_file, c_file,
			sample_fname, fuzz_db, db_init, mutate);
	if (err < 0) {
		err_dbg(0, "env_init err");
		goto err_out;
	}

	err = env_prepare(env);
	if (err < 0) {
		err_dbg(0, "env_prepare err");
		goto err_out;
	}

	return env;

err_out:
	qemu_fuzzlib_env_destroy(env);
	return NULL;
}

static int env_run_one(struct qemu_fuzzlib_env *env, int *updated)
{
	int err = 0;
	struct qemu_fuzzlib_inst *inst = NULL;
	static u32 times = 0x1000000;

	for (u32 j = 0; j < env->idle_sec; j++) {
		for (u32 i = 0; i < times; i++) {
			inst = env_idle_inst(env);
			if (inst)
				break;
		}
		if (inst)
			break;
		sleep(1);
	}
	if (!inst) {
		fprintf(stderr, "[-] no instance available, must be a bug.\n");
		return 1;
	}

	env_check_inst_res(env, inst, updated);

	err = env->mutate(env, inst->sample_file);
	if (err == QEMU_FUZZLIB_MUTATE_ERR) {
		err_dbg(0, "mutate err");
		mutex_unlock(&inst->lock);
		return 0;
	} else if (err == QEMU_FUZZLIB_MUTATE_DONE) {
		err_dbg(0, "mutate done");
		mutex_unlock(&inst->lock);
		return 1;
	}

	err = env_run_inst(env, inst);
	if (err < 0) {
		err = env_save_not_tested(env, inst);
		if (err < 0) {
			err_dbg(0, "env_save_not_tested err");
		}
		mutex_unlock(&inst->lock);
		return 0;
	}

	return 0;
}

static void wait_for_all_inst(struct qemu_fuzzlib_env *env)
{
	while (1) {
		if (env_idle(env))
			break;
		usleep(1000);
	}
}

int qemu_fuzzlib_env_run(struct qemu_fuzzlib_env *env)
{
	while (1) {
		int updated = 0;
		int do_break = env_run_one(env, &updated);
		if (do_break) {
			break;
		}
		if (updated)
			env_verbose(env);
	}

	wait_for_all_inst(env);

	for (u64 i = 0; i < env->instance_max; i++) {
		int updated = 0;
		env_check_inst_res(env, env->instances[i], &updated);
		if (updated)
			env_verbose(env);
	}

	return 0;
}
