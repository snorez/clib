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
#ifndef NET_H_QGVOLRSZ
#define NET_H_QGVOLRSZ

#include "../include/clib_utils.h"
#include "../include/clib_eh.h"
#include "../include/clib_buf.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

DECL_BEGIN

typedef struct _sock {
	int family;
	int socktype;
	int protocol;
	int shut_how;
	int sockfd;
	int offline;
	int sock_buf_len;

	int which_ailist;		/* 0: target, 1: this */
	struct addrinfo *ailist;	/* primary tuple (ip, port) */
	char *host;
	char *port;
	struct addrinfo *bkp_ailist;	/* secondary tuple(ip, port) */
	char *bkp_host;
	char *bkp_port;
} sock;

typedef struct _cli_info {
	struct sockaddr addr;
	socklen_t len;
} cli_info;

typedef struct __attribute__((packed)) _eth_header {
	uint8_t		dstmac[6];
	uint8_t		srcmac[6];
	uint16_t	eth_type;
} eth_header;

typedef struct __attribute__((packed)) _arp_header {
	uint16_t	arp_hrd;
	uint16_t	arp_pro;
	uint8_t		arp_hln;
	uint8_t		arp_pln;
	uint16_t	arp_op;
} arp_header;

typedef struct __attribute__((packed)) _eth_arp {
	arp_header	ea_hdr;
	uint8_t		arp_sha[6];
	uint8_t		arp_spa[4];
	uint8_t		arp_tha[6];
	uint8_t		arp_tpa[4];
} eth_arp;

typedef struct __attribute__((packed)) _ipv4_header {
	uint8_t		ver_ihl;
	uint8_t		tos;			/* type of service */
	uint16_t	len;
	uint16_t	ident;
	uint16_t	frag_field;
	uint16_t	ttl;
	uint8_t		protocol;
	uint16_t	chksum;
	uint32_t	sourceip;
	uint32_t	destip;
} ipv4_header;

#define TCP_FIN		0x01
#define TCP_SYN		0x02
#define TCP_RST		0x04
#define TCP_PUSH	0x08
#define TCP_ACK		0x10
#define TCP_URG		0x20

typedef struct __attribute__((packed)) _tcp_header {
	uint16_t	srcport;
	uint16_t	destport;
	uint32_t	seqnum;
	uint32_t	acknum;
	uint8_t		tcp_hdr_len;		/* high 4 bits */
	uint8_t		flags;			/* low 6 bits */
	uint16_t	wnd_size;
	uint16_t	chksum;
	uint16_t	urgptr;
} tcp_header;

typedef struct __attribute__((packed)) _tcp_packet {
	ipv4_header	ip;
	tcp_header	tcp;
	uint8_t		data[10240];
} tcp_packet;

typedef struct __attribute__((packed)) _udp_header {
	uint16_t	srcport;
	uint16_t	destport;
	uint16_t	udp_hdr_len;
	uint16_t	chksum;
} udp_header;

typedef struct __attribute__((packed)) _udp_packet {
	ipv4_header	ip;
	udp_header	udp;
} udp_packet;

typedef struct __attribute__((packed)) _icmp_header {
	uint8_t		icmp_type;
	uint8_t		code;
	uint16_t	chksum;
} icmp_header;

typedef struct __attribute__((packed)) _icmp0 {
	uint8_t		type;
	uint8_t		code;
	uint16_t	chksum;
	uint16_t	id;
	uint16_t	seq;
	int8_t		data[1];
} icmp0;

typedef struct __attribute__((packed)) _icmp3 {
	uint8_t		type;
	uint8_t		code;
	uint16_t	chksum;
	uint16_t	pmvoid;
	uint16_t	nextmtu;
	int8_t		data[1];
} icmp3;

typedef struct __attribute__((packed)) _icmp5 {
	uint8_t		type;
	uint8_t		code;
	uint16_t	chksum;
	uint32_t	gwaddr;
	int8_t		data[1];
} icmp5;

typedef struct __attribute__((packed)) _icmp11 {
	uint8_t		type;
	uint8_t		code;
	uint16_t	chksum;
	uint32_t	_void;
	int8_t		data[1];
} icmp11;

typedef struct __attribute__((packed)) _pseudo_header {
	uint32_t srcip;
	uint32_t destip;
	uint8_t zero;
	uint8_t protocol;
	uint16_t tcp_len;
	tcp_header tcp;
} pseudo_header;

extern sock *sock_open(int family, int type, int protocol);
extern int sock_close(sock *);
extern int set_ailist_nr(sock *file);
extern int get_ailist_nr(sock *file);
extern int unset_ailist_nr(sock *file);
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

#ifndef CONFIG_SOCK_BUF_LEN_ORIG
#define SOCK_BUF_LEN_ORIG	(128*1024)
#else
#define	SOCK_BUF_LEN_ORIG	(CONFIG_SOCK_BUF_LEN_ORIG)
#endif

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
extern int clib_listen_sock(int domain, int type, int protocol, int backlog,
			    int *port);

DECL_END

#endif /* end of include guard: NET_H_QGVOLRSZ */
