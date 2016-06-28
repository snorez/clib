#ifndef __NET_H__
#define __NET_H__

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include "./error.h"
#include "./string.h"

typedef struct _sock {
	int family;
	int socktype;
	int protocol;
	int shut_how;
	int sockfd;
	int offline;
	int sock_buf_len;

	struct addrinfo *ailist;
	char *host;
	char *port;

	pthread_mutex_t mutex;
} sock;

typedef struct _cli_info {
	struct sockaddr addr;
	socklen_t len;
} cli_info;

extern sock *sock_open(int family, int type, int protocol);
extern int sock_close(sock *);
extern int s_getaddrinfo(sock *, char *host, char *service, int flag);
extern void s_putaddrinfo(sock *);
extern int sock_bind(sock *);
extern int sock_connect(sock *);
extern int sock_listen(sock *, int how_many);
extern cli_info *alloc_cli_info(sock *);
extern void free_cli_info(cli_info *client_info);
extern sock *sock_accept(sock *, cli_info *);
extern void cli_info_print(cli_info *client);
extern long fork_wget(char *url, char *file2write);

#define SOCK_BUF_LEN_ORIG (128*1024)

typedef struct _pkg_ctl {
	char tag[16];
	char size[8];
	char index[8];
} pkg_ctl;

typedef struct _sock_pkg {
	pkg_ctl control;
	char content[0];
} sock_pkg;

extern int xchg_sock_buf_len0(sock *file);
extern int xchg_sock_buf_len1(sock *file);
extern int sock_send(sock *file, void *msg, size_t len, int flag);
extern int sock_recv(sock *file, void *msg, size_t len, int flag);

#endif
