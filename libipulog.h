#ifndef _LIBIPULOG_H
#define _LIBIPULOG_H

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <linux/netfilter_ipv4/ipt_ULOG.h>

/* FIXME: glibc sucks */
#ifndef MSG_TRUNC 
#define MSG_TRUNC	0x20
#endif

struct ipulog_handle;
extern int ipulog_errno;

u_int32_t ipulog_group2gmask(u_int32_t group);

struct ipulog_handle *ipulog_create_handle(u_int32_t gmask, u_int32_t rmem);

void ipulog_destroy_handle(struct ipulog_handle *h);

ssize_t ipulog_read(struct ipulog_handle *h,
		    unsigned char *buf, size_t len);

ulog_packet_msg_t *ipulog_get_packet(struct ipulog_handle *h,
				     const unsigned char *buf,
				     size_t len);

char *ipulog_strerror(int errcode);

int ipulog_get_fd(struct ipulog_handle *h);

void ipulog_perror(const char *s);

enum 
{
	IPULOG_ERR_NONE = 0,
	IPULOG_ERR_IMPL,
	IPULOG_ERR_HANDLE,
	IPULOG_ERR_SOCKET,
	IPULOG_ERR_BIND,
	IPULOG_ERR_RECVBUF,
	IPULOG_ERR_RECV,
	IPULOG_ERR_NLEOF,
	IPULOG_ERR_TRUNC,
	IPULOG_ERR_INVGR,
	IPULOG_ERR_INVNL,
};
#define IPULOG_MAXERR IPULOG_ERR_INVNL

#endif /* _LIBULOG_H */
