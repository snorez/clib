#include "../include/net.h"
#include "../include/utils.h"

sock *sock_open(int family, int socktype, int protocol)
{
	sock *ret = (sock *)malloc_s(sizeof(sock));
	if (!ret) {
		err_dbg(0, err_fmt("malloc err"));
		return NULL;
	}

	ret->family = family;
	ret->socktype = socktype;
	ret->protocol = protocol;

	ret->sockfd = socket(family, socktype, protocol);
	if (ret->sockfd == -1) {
		err_dbg(1, err_fmt("socket err"));
		goto free_ret;
	}

	ret->offline = 1;
	return ret;

free_ret:
	free(ret);
	return NULL;
}

int sock_close(sock *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	if (file->ailist) {
		unset_ailist_nr(file);
		s_putaddrinfo(file);
	}
	if (file->bkp_ailist) {
		set_ailist_nr(file);
		s_putaddrinfo(file);
	}

	int ret = close(file->sockfd);
	memset(file, 0, sizeof(*file));
	free(file);
	return ret;
}

int set_ailist_nr(sock *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	file->which_ailist = 1;
	return 0;
}

int get_ailist_nr(sock *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	return file->which_ailist;
}

int unset_ailist_nr(sock *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	file->which_ailist = 0;
	return 0;
}

int s_getaddrinfo(sock *file, char *host, char *port, int flag)
{
	if (!file || !host|| !port) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	int which = get_ailist_nr(file);	/* should never be -1 */
	if (!which && file->ailist) {
		err_dbg(0, err_fmt("NOTICE: change target addrinfo"));
		s_putaddrinfo(file);
	}
	if (which && file->bkp_ailist) {
		err_dbg(0, err_fmt("NOTICE: change this addrinfo"));
		s_putaddrinfo(file);
	}

	struct addrinfo hint;
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = file->family;
	hint.ai_socktype = file->socktype;
	hint.ai_protocol = file->protocol;
	hint.ai_flags = flag;

	int err;
	if (!which)
		err = getaddrinfo(host, port, &hint, &file->ailist);
	else
		err = getaddrinfo(host, port, &hint, &file->bkp_ailist);
	if (err != 0) {
		err_dbg(0, err_fmt("getaddrinfo err: %s"), gai_strerror(err));
		err = -1;
		goto unlock;
	}

	char *host_tmp = (char *)malloc_s(strlen(host)+1);
	if (!host_tmp) {
		err = -1;
		goto putaddrinfo;
	}
	memcpy(host_tmp, host, strlen(host));

	char *port_tmp = (char *)malloc_s(strlen(port)+1);
	if (!port_tmp) {
		err = -1;
		goto free;
	}
	memcpy(port_tmp, port, strlen(port));

	if (!which) {
		file->host = host_tmp;
		file->port = port_tmp;
	} else {
		file->bkp_host = host_tmp;
		file->bkp_port = port_tmp;
	}
	err = 0;
	goto unlock;

free:
	free(host_tmp);
putaddrinfo:
	s_putaddrinfo(file);
unlock:
	return err;
}

void s_putaddrinfo(sock *file)
{
	if (!file || !file->ailist) {
		err_dbg(0, err_fmt("arg check err"));
		return;
	}

	int which = get_ailist_nr(file);
	if (!which) {
		freeaddrinfo(file->ailist);
		file->ailist = NULL;
		free_s((void **)&file->host);
		free_s((void **)&file->port);
	} else {
		freeaddrinfo(file->bkp_ailist);
		file->bkp_ailist = NULL;
		free_s((void **)&file->bkp_host);
		free_s((void **)&file->bkp_port);
	}
}

int sock_bind(sock *file)
{
	if (!file || !file->ailist) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	int which = get_ailist_nr(file);
	if (!which)
		return bind(file->sockfd, file->ailist->ai_addr,
			    file->ailist->ai_addrlen);
	else
		return bind(file->sockfd, file->bkp_ailist->ai_addr,
			    file->bkp_ailist->ai_addrlen);
}

int sock_connect(sock *file)
{
	if (!file || !file->ailist) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}
	int err = connect(file->sockfd, file->ailist->ai_addr,
			  file->ailist->ai_addrlen);
	if (!err)
		file->offline = 0;
	return err;
}

int sock_listen(sock *file, int how_many)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}
	int err = listen(file->sockfd, how_many);
	if (!err)
		file->offline = 0;
	return err;
}

cli_info *alloc_cli_info(sock *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return NULL;
	}

	cli_info *ret = (cli_info *)malloc_s(sizeof(cli_info));
	if (!ret) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		return NULL;
	}

	if (file->family == AF_INET)
		ret->len = INET_ADDRSTRLEN;
	else if (file->family == AF_INET6)
		ret->len = INET6_ADDRSTRLEN;
	if (!ret->len) {
		err_dbg(0, err_fmt("sock family not support"));
		errno = EINVAL;
		free(ret);
		return NULL;
	}
	return ret;
}

void free_cli_info(cli_info *client)
{
	if (!client) {
		err_dbg(0, err_fmt("arg check err"));
		return;
	}
	free(client);
}

sock *sock_accept(sock *file, cli_info *client)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return NULL;
	}

	int fd;

	if (!client)
		fd = accept(file->sockfd, NULL, NULL);
	else
		fd = accept(file->sockfd, &client->addr, &client->len);
	if (fd == -1) {
		err_dbg(1, err_fmt("accept err"));
		return NULL;
	}

	sock *ret = (sock *)malloc_s(sizeof(sock));
	if (!ret) {
		err_dbg(0, err_fmt("malloc_s err"));
		goto close_ret;
	}

	ret->sockfd = fd;
	return ret;

close_ret:
	close(fd);
	return NULL;
}

void cli_info_print(cli_info *client)
{
	const char *err;
	if (client->addr.sa_family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)client;
		char data[INET_ADDRSTRLEN];
		err = inet_ntop(AF_INET, &in->sin_addr, data,
				INET_ADDRSTRLEN);
		if (!err) {
			err_dbg(1, err_fmt("inet_ntop err"));
			return;
		}
		printf("client addr: %s\n", data);
		printf("client port: %d\n", ntohs(in->sin_port));
	} else if (client->addr.sa_family == AF_INET6) {
		struct sockaddr_in6 *in = (struct sockaddr_in6 *)client;
		char data[INET6_ADDRSTRLEN];
		err = inet_ntop(AF_INET6, &in->sin6_addr, data,
				INET6_ADDRSTRLEN);
		if (!err) {
			err_dbg(1, err_fmt("inet_ntop err"));
			return;
		}
		printf("client addr: %s\n", data);
		printf("client port: %d\n", ntohs(in->sin6_port));
	} else
		printf("unknow family\n");
}

long fork_wget(char *url, char *file_w)
{
	if (!url || !file_w) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	/* TODO: need to rewrite */
	char *url_correct;
	int flag = 0;
	if (strstr(url, "&amp;")) {
		flag = 1;
		url_correct = del_str_all_fau(url, "amp;");
	} else
		url_correct = url;

	int child_pid;
	int err;
	if ((child_pid = fork()) < 0)
		err_sys(err_fmt("fork error"));
	else if (child_pid == 0) {
		close(0);
		close(1);
		close(2);
		err = execl("/usr/bin/wget", "/usr/bin/wget", url_correct,
			    "-O", file_w, "-t", "3", "-T", "9", NULL);
		if (err == -1)
			err_exit(1, err_fmt("execl error"));
		exit(0);
	} else {
		err = waitid(P_PID, child_pid, NULL, WEXITED);
		if (flag == 1)
			free(url_correct);
		if (err == -1) {
			err_sys(err_fmt("waitid error"));
			return -1;
		}
		return 0;
	}
	return 0;
}

static int set_sock_buf_len(sock *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	if (!file->sock_buf_len)
		file->sock_buf_len = SOCK_BUF_LEN_ORIG;
	int err = setsockopt(file->sockfd, SOL_SOCKET, SO_SNDBUF,
			     &file->sock_buf_len, sizeof(int));
	if (err == -1) {
		err_dbg(1, err_fmt("setsockopt SO_SNDBUF err"));
		return -1;
	}

	err = setsockopt(file->sockfd, SOL_SOCKET, SO_RCVBUF,
			 &file->sock_buf_len, sizeof(int));
	if (err == -1) {
		err_dbg(1, err_fmt("setsockopt SO_RCVBUF err"));
		return -1;
	}

	return 0;
}

static int get_sock_buf_len(sock *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	int buflen[2] = {0, 0};
	int len = sizeof(int);

	int err = getsockopt(file->sockfd, SOL_SOCKET, SO_SNDBUF,
			     (void *)&buflen[0], (void *)&len);
	if (err == -1) {
		err_dbg(1, err_fmt("getsockopt SO_SNDBUF err"));
		return -1;
	}

	err = getsockopt(file->sockfd, SOL_SOCKET, SO_RCVBUF,
			 (void *)&buflen[1], (void *)&len);
	if (err == -1) {
		err_dbg(1, err_fmt("getsockopt SO_RCVBUF err"));
		return -1;
	}

	file->sock_buf_len = min_32(buflen[0], buflen[1])/2;
	return 0;
}

int xchg_sock_buf_len0(sock *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	int err;
	if (!file->sock_buf_len) {
		err = set_sock_buf_len(file);
		if (err == -1)
			err_sys("set_sock_buf_len err");
		err = get_sock_buf_len(file);
		if (err == -1)
			err_sys("get_sock_buf_len err");
	}

	char buf[16];
	memset(buf, 0, 16);
	sprintf(buf, "%d", file->sock_buf_len);

	err = send(file->sockfd, buf, strlen(buf), 0);
	if (err == -1) {
		err_dbg(1, err_fmt("send err"));
		goto unlock;
	}

	memset(buf, 0, 16);
	err = recv(file->sockfd, buf, 16, 0);
	if (err == -1) {
		err_dbg(1, err_fmt("recv err"));
		goto unlock;
	} else if (err == 0) {
		err_dbg(0, err_fmt("offline"));
		err = -1;
		goto unlock;
	}

	int len = atoi(buf);
	if (len < file->sock_buf_len)
		file->sock_buf_len = len;
	err = 0;
unlock:
	file->offline = !!err;
	return err;
}

int xchg_sock_buf_len1(sock *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	int err;
	if (!file->sock_buf_len) {
		err = set_sock_buf_len(file);
		if (err == -1)
			err_sys("set_sock_buf_len err");
		err = get_sock_buf_len(file);
		if (err == -1)
			err_sys("get_sock_buf_len err");
	}

	char buf[16];
	memset(buf, 0, 16);

	err = recv(file->sockfd, buf, 16, 0);
	if (err == -1) {
		err_dbg(1, err_fmt("recv err"));
		goto unlock;
	} else if (err == 0) {
		err_dbg(0, err_fmt("offline"));
		err = -1;
		goto unlock;
	}

	int len = atoi(buf);
	if (len < file->sock_buf_len)
		file->sock_buf_len = len;
	memset(buf, 0, 16);
	sprintf(buf, "%d", file->sock_buf_len);

	err = send(file->sockfd, buf, strlen(buf), 0);
	if (err == -1) {
		err_dbg(1, err_fmt("send err"));
		goto unlock;
	}
	err = 0;
unlock:
	file->offline = !!err;
	return err;
}

static int check_sock_buflen(sock *file)
{
	return file->sock_buf_len > (int)sizeof(pkg_ctl);
}

/* FIXME: len should less than or equal 0xffffffff */
int sock_send(sock *file, void *msg, size_t len, int flag)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	int ret = 0;
	if (file->offline) {
		err_dbg(0, err_fmt("offline now"));
		goto unlock;
	}

	if (!check_sock_buflen(file)) {
		err_dbg(0, err_fmt("should check your sock_buf_len"));
		errno = EINVAL;
		goto unlock;
	}

	int msg_per_len = file->sock_buf_len-sizeof(pkg_ctl);
	int snd_cnt = len / msg_per_len + 1;
	sock_pkg *pack = (sock_pkg *)malloc_s(file->sock_buf_len);
	if (!pack) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		goto unlock;
	}
	char *tmp_pos = (char *)pack;

	struct timeval tv;
	int err = gettimeofday(&tv, NULL);
	if (err == -1) {
		err_dbg(1, err_fmt("gettimeofday err"));
		goto free_ret;
	}
	sprintf(tmp_pos+strlen(tmp_pos), "%016lx", tv.tv_sec+tv.tv_usec);
	sprintf(tmp_pos+strlen(tmp_pos), "%08x", (unsigned int)len);

	for (int i = 0; i < snd_cnt; i++) {
		char *src_pos = msg+i*msg_per_len;
		memset(tmp_pos+24, 0, file->sock_buf_len-24);
		sprintf(tmp_pos+24, "%08x", i);
		memcpy(tmp_pos+32,src_pos,min_32(strlen(src_pos),msg_per_len));
resend:
		err = send(file->sockfd, pack, file->sock_buf_len, 0);
		if (err == -1) {
			err_dbg(1, err_fmt("send err"));
			if ((errno == ECONNRESET))
				file->offline = 1;
			else if (errno == EINTR)
				goto resend;
			ret = 0;
			goto free_ret;
		}
		ret += err;
	}
free_ret:
	free(pack);
unlock:
	return ret ? ret : -1;
}

/*
 * XXX: here we use blocked `recv` to get msg, there could be a issue that
 * `recv` could be interrupt by any signal, maybe here, the way dealing with EINTR
 * is not right(TODO). so in some projects, I use sigprocmask to block the signal
 * that may interrupt `recv`
 */
int sock_recv(sock *file, void *msg, size_t len, int flag)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	int ret = 0;
	if (file->offline) {
		err_dbg(0, err_fmt("offline now"));
		goto unlock;
	}

	if (!check_sock_buflen(file)) {
		err_dbg(0, err_fmt("should check your sock_buf_len"));
		errno = EINVAL;
		goto unlock;
	}

	/*
	 * if we recv another tag msg, then we should just return,
	 * cause if the send side sock_send err, then the packets
	 * send already should be dropped
	 */
	int msg_per_len = file->sock_buf_len-sizeof(pkg_ctl);
	sock_pkg *pack = (sock_pkg *)malloc_s(file->sock_buf_len);
	if (!pack) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		goto unlock;
	}
	char *tmp_pos = (char *)pack;

	int err;
	char tag[16];
	memset(tag, 0, 16);
	int msg_size = 0;
	int recv_cnt = 0;
	while (1) {
		/* first, take a peek */
		err = recv(file->sockfd, tmp_pos, file->sock_buf_len,
			   MSG_PEEK);
		if ((err == -1) || (err == 0)) {
			err_dbg(1, err_fmt("recv MSG_PEEK err"));
			goto free_ret;
		}
		if (tag[0] == '\0')
			memcpy(tag, tmp_pos, 16);
		else {
			if (strncmp(tag, tmp_pos, 16))
				goto free_ret;
		}

		/* XXX: we must use MSG_WAITALL to recv `lenth` bytes */
rerecv:
		err = recv(file->sockfd,tmp_pos,file->sock_buf_len,MSG_WAITALL);
		if (err == -1) {
			err_dbg(1, err_fmt("recv err"));
			if (errno == EINTR)
				goto rerecv;
			goto free_ret;
		} else if (err == 0) {
			file->offline = 1;
			goto free_ret;
		}
		ret += err;
		if (!msg_size) {
			msg_size = hex2int(pack->control.size);
			recv_cnt = msg_size / msg_per_len + 1;
		}
		if (msg_size > len) {
			err_dbg(0, err_fmt("msg space not enough"));
			errno = EINVAL;
			goto free_ret;
		}
		memcpy((char *)msg+msg_per_len*hex2int(pack->control.index),
		       tmp_pos+sizeof(pkg_ctl),
		       min_32(msg_per_len, strlen(tmp_pos)));
		recv_cnt--;
		if (!recv_cnt)
			break;
	}
free_ret:
	free(pack);
unlock:
	return ret ? ret : -1;
}
