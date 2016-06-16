#ifndef __NET_H__
#define __NET_H__

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include "./error.h"
#include "./string.h"

typedef struct _sock_file {
	int family;
	int socktype;
	int protocol;
	int shut_how;
	int sockfd;
	int sock_buf_len;
} sock_file;

typedef struct _sock_ai {
	struct addrinfo *ailist;
} sock_ai;

typedef struct _cli_info {
	struct sockaddr addr;
	socklen_t len;
} cli_info;

extern sock_file *sock_file_open(int family, int type, int protocol, int shut);
extern int sock_file_close(sock_file *);
extern int s_getaddrinfo(sock_file *, char *host, char *service, int flag,
			 sock_ai *res);
extern void s_putaddrinfo(sock_ai *);
extern int sock_bind(sock_file *, sock_ai *);
extern int sock_connect(sock_file *, sock_ai *);
extern int sock_listen(sock_file *, int how_many);
extern cli_info *get_cli_info(sock_file *);
extern void put_cli_info(cli_info *client_info);
extern int sock_accept(sock_file *, cli_info *);
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

extern int set_sock_buf_len(sock_file *file);
extern int get_sock_buf_len(sock_file *file);
extern int xchg_sock_buf_len0(sock_file *file);
extern int xchg_sock_buf_len1(sock_file *file);
extern int sock_send(sock_file *file, void *msg, size_t len, int flag);
extern int sock_recv(sock_file *file, void *msg, size_t len, int flag);

#endif
