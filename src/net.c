#include "../include/net.h"
#include "../include/utils.h"

sock_file *sock_file_open(int family, int socktype, int protocol, int shut_how)
{
	sock_file *ret = (sock_file *)malloc(sizeof(sock_file));
	if (!ret) {
		err_dbg(0, err_fmt("malloc err"));
		return NULL;
	}
	memset(ret, 0, sizeof(sock_file));

	ret->family = family;
	ret->socktype = socktype;
	ret->protocol = protocol;
	ret->shut_how = shut_how;

	ret->sockfd = socket(family, socktype, protocol);
	if (ret->sockfd == -1) {
		err_dbg(1, err_fmt("socket err"));
		goto free_ret;
	}

	if (shut_how == -1)
		return ret;
	int err = shutdown(ret->sockfd, shut_how);
	if (err == -1) {
		err_dbg(1, err_fmt("shutdown err"));
		goto close_ret;
	}
	return ret;

close_ret:
	close(ret->sockfd);
free_ret:
	free(ret);
	return NULL;
}

int sock_file_close(sock_file *sockfile)
{
	if (!sockfile) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	int ret = close(sockfile->sockfd);
	free(sockfile);
	return ret;
}

int s_getaddrinfo(sock_file *sockfile, char *host, char *service, int flag,
		  sock_ai *res)
{
	if (!sockfile || !host|| !service) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	struct addrinfo hint;
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = sockfile->family;
	hint.ai_socktype = sockfile->socktype;
	hint.ai_protocol = sockfile->protocol;
	hint.ai_flags = flag;

	int err = getaddrinfo(host, service, &hint, &res->ailist);
	if (err != 0) {
		err_dbg(0,err_fmt("getaddrinfo err: %s"),gai_strerror(err));
		return -1;
	}

	return 0;
}

void s_putaddrinfo(sock_ai *res)
{
	if (!res) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return;
	}
	freeaddrinfo(res->ailist);
}

int sock_bind(sock_file *sockfile, sock_ai *sai)
{
	if (!sockfile || !sai) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}
	return bind(sockfile->sockfd, sai->ailist->ai_addr,
		    sai->ailist->ai_addrlen);
}

int sock_connect(sock_file *sockfile, sock_ai *sai)
{
	if (!sockfile || !sai) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}
	return connect(sockfile->sockfd, sai->ailist->ai_addr,
		       sai->ailist->ai_addrlen);
}

int sock_listen(sock_file *sockfile, int backlog)
{
	if (!sockfile) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}
	return listen(sockfile->sockfd, backlog);
}

cli_info *get_cli_info(sock_file *sockfile)
{
	if (!sockfile) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return NULL;
	}

	cli_info *ret = (cli_info *)malloc(sizeof(cli_info));
	if (!ret) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		return NULL;
	}
	memset(ret, 0, sizeof(cli_info));

	if (sockfile->family == AF_INET)
		ret->len = INET_ADDRSTRLEN;
	else if (sockfile->family == AF_INET6)
		ret->len = INET6_ADDRSTRLEN;
	if (!ret->len) {
		err_dbg(0, err_fmt("sock family not support"));
		errno = EINVAL;
		free(ret);
		return NULL;
	}
	return ret;
}

void put_cli_info(cli_info *client)
{
	if (!client) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return;
	}
	free(client);
}

int sock_accept(sock_file *sockfile, cli_info *client)
{
	if (!sockfile) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	if (!client)
		return accept(sockfile->sockfd, NULL, NULL);
	else
		return accept(sockfile->sockfd, &client->addr, &client->len);
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

/*
 * XXX: what we need here?
 * sometime we send a buf(>16K or larger), then when we recv the buf,
 * it is disordered, cause the system net send/recv buffer is limited,
 * getsockopt can show us how many bytes the buffer has
 * so we need some functions that ensure we recv what we send
 * usage:
 * call set_sock_buf_len and get_sock_buf_len
 * if no err, call xchg_sock_buf_len0&xchg_sock_buf_len1 to set the buf_len
 * if err, then check err and reconnect that again
 */

int set_sock_buf_len(sock_file *file)
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

int get_sock_buf_len(sock_file *file)
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

int xchg_sock_buf_len0(sock_file *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	char buf[16];
	memset(buf, 0, 16);
	sprintf(buf, "%d", file->sock_buf_len);

	int err = send(file->sockfd, buf, strlen(buf), 0);
	if ((err == -1) || (err == 0)) {
		err_dbg(1, err_fmt("send err"));
		return -1;
	}

	memset(buf, 0, 16);
	err = recv(file->sockfd, buf, 16, 0);
	if ((err == -1) || (err == 0)) {
		err_dbg(1, err_fmt("recv err"));
		return -1;
	}

	int len = atoi(buf);
	if (len < file->sock_buf_len)
		file->sock_buf_len = len;
	return 0;
}

int xchg_sock_buf_len1(sock_file *file)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	char buf[16];
	memset(buf, 0, 16);

	int err = recv(file->sockfd, buf, 16, 0);
	if ((err == -1) || (err == 0)) {
		err_dbg(1, err_fmt("recv err"));
		return -1;
	}

	int len = atoi(buf);
	if (len < file->sock_buf_len)
		file->sock_buf_len = len;
	memset(buf, 0, 16);
	sprintf(buf, "%d", file->sock_buf_len);

	err = send(file->sockfd, buf, strlen(buf), 0);
	if ((err == -1) || (err == 0)) {
		err_dbg(1, err_fmt("send err"));
		return -1;
	}
	return 0;
}

static int check_sock_buflen(sock_file *file)
{
	return file->sock_buf_len > (int)sizeof(pkg_ctl);
}

/* FIXME: len should less than or equal 0xffffffff */
int sock_send(sock_file *file, void *msg, size_t len, int flag)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	if (!check_sock_buflen(file)) {
		err_dbg(0, err_fmt("should check your sock_buf_len"));
		errno = EINVAL;
		return -1;
	}


	int msg_per_len = file->sock_buf_len-sizeof(pkg_ctl);
	int snd_cnt = len / msg_per_len + 1;
	sock_pkg *pack = (sock_pkg *)malloc(file->sock_buf_len);
	if (!pack) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		return -1;
	}
	memset(pack, 0, file->sock_buf_len);
	char *tmp_pos = (char *)pack;

	struct timeval tv;
	int err = gettimeofday(&tv, NULL);
	if (err == -1) {
		err_dbg(1, err_fmt("gettimeofday err"));
		goto out_free;
	}
	sprintf(tmp_pos+strlen(tmp_pos), "%016lx", tv.tv_sec+tv.tv_usec);
	sprintf(tmp_pos+strlen(tmp_pos), "%08x", (unsigned int)len);

	for (int i = 0; i < snd_cnt; i++) {
		char *src_pos = msg+i*msg_per_len;
		memset(tmp_pos+24, 0, file->sock_buf_len-24);
		sprintf(tmp_pos+24, "%08x", i);
		memcpy(tmp_pos+32,src_pos,min_32(strlen(src_pos),msg_per_len));
		err = send(file->sockfd, pack, file->sock_buf_len, flag);
		if ((err == -1) || (err == 0)) {
			err_dbg(1, err_fmt("send err"));
			goto out_free;
		}
	}
	free(pack);
	return 0;
out_free:
	free(pack);
	return -1;
}

int sock_recv(sock_file *file, void *msg, size_t len, int flag)
{
	if (!file) {
		err_dbg(0, err_fmt("arg check err"));
		errno = EINVAL;
		return -1;
	}

	if (!check_sock_buflen(file)) {
		err_dbg(0, err_fmt("should check your sock_buf_len"));
		errno = EINVAL;
		return -1;
	}

	/*
	 * if we recv another tag msg, then we should just return,
	 * cause if the send side sock_send err, then the packets
	 * send already should be dropped
	 */
	int msg_per_len = file->sock_buf_len-sizeof(pkg_ctl);
	sock_pkg *pack = (sock_pkg *)malloc(file->sock_buf_len);
	if (!pack) {
		err_dbg(0, err_fmt("malloc err"));
		errno = ENOMEM;
		return -1;
	}
	memset(pack, 0, file->sock_buf_len);
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
			goto out_free;
		}
		if (tag[0] == '\0')
			memcpy(tag, tmp_pos, 16);
		else {
			if (strncmp(tag, tmp_pos, 16))
				goto out_free;
		}

		/* XXX: we must use MSG_WAITALL to recv `lenth` bytes */
		err = recv(file->sockfd,tmp_pos,file->sock_buf_len,MSG_WAITALL);
		if ((err == -1) || (err == 0)) {
			err_dbg(1, err_fmt("recv err"));
			goto out_free;
		}
		if (!msg_size) {
			msg_size = hex2int(pack->control.size);
			recv_cnt = msg_size / msg_per_len + 1;
		}
		if (msg_size > len) {
			err_dbg(0, err_fmt("msg space not enough"));
			errno = EINVAL;
			goto out_free;
		}
		memcpy((char *)msg+msg_per_len*hex2int(pack->control.index),
		       tmp_pos+sizeof(pkg_ctl),
		       min_32(msg_per_len, strlen(tmp_pos)));
		recv_cnt--;
		if (!recv_cnt)
			break;
	}
	free(pack);
	return 0;
out_free:
	free(pack);
	return -1;
}
