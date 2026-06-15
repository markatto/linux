// SPDX-License-Identifier: GPL-2.0
/*
 * Check that the per-family *_DIAG_SK_OPTS attribute reports the SOL_SOCKET
 * boolean options set on a socket.
 *
 * For each family the test opens a socket, sets a known set of SO_* options,
 * dumps it via SOCK_DIAG_BY_FAMILY (requesting the family's *_SHOW_SK_OPTS
 * gate where one exists), locates the socket by inode and checks the reported
 * bits. It also covers the SO_TIMESTAMP / SO_TIMESTAMPNS split, which both set
 * SOCK_RCVTSTAMP in the kernel and so must be told apart by the attribute.
 */
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/netlink_diag.h>
#include <linux/packet_diag.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>

#include "../kselftest.h"

static void set_bool(int fd, int opt)
{
	int one = 1;

	if (setsockopt(fd, SOL_SOCKET, opt, &one, sizeof(one)))
		ksft_exit_fail_perror("setsockopt");
}

static unsigned int sock_ino(int fd)
{
	struct stat st;

	if (fstat(fd, &st))
		ksft_exit_fail_perror("fstat");
	return st.st_ino;
}

/*
 * Dump using @req, find the message whose inode (at @ino_off in the fixed
 * header of size @hdrlen) matches @ino, and copy its SK_OPTS attribute @attr
 * into @out. Returns 0 if the attribute was found, -1 otherwise.
 */
static int query_sk_opts(const void *req, size_t reqlen, size_t hdrlen,
			 size_t ino_off, int attr, unsigned int ino,
			 struct sock_diag_sk_opts *out)
{
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	int fd, ret = -1;
	char buf[8192];
	ssize_t n;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
	if (fd < 0)
		ksft_exit_fail_perror("NETLINK_SOCK_DIAG socket");

	if (sendto(fd, req, reqlen, 0, (void *)&nladdr, sizeof(nladdr)) < 0)
		ksft_exit_fail_perror("sendto");

	while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) {
		struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
		int len = n;

		for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
			const char *hdr = NLMSG_DATA(nlh);
			struct rtattr *rta;
			int rtalen;

			if (nlh->nlmsg_type == NLMSG_DONE ||
			    nlh->nlmsg_type == NLMSG_ERROR)
				goto out;
			if (*(const __u32 *)(hdr + ino_off) != ino)
				continue;

			rta = (struct rtattr *)(hdr + NLMSG_ALIGN(hdrlen));
			rtalen = nlh->nlmsg_len - NLMSG_LENGTH(hdrlen);
			for (; RTA_OK(rta, rtalen); rta = RTA_NEXT(rta, rtalen)) {
				if (rta->rta_type != attr ||
				    RTA_PAYLOAD(rta) < sizeof(*out))
					continue;
				memcpy(out, RTA_DATA(rta), sizeof(*out));
				ret = 0;
				goto out;
			}
		}
	}
out:
	close(fd);
	return ret;
}

static int inet_sk_opts(int proto, unsigned int ino,
			struct sock_diag_sk_opts *o)
{
	struct {
		struct nlmsghdr nlh;
		struct inet_diag_req_v2 r;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		},
		.r = {
			.sdiag_family = AF_INET,
			.sdiag_protocol = proto,
			.idiag_states = ~0U,
		},
	};

	return query_sk_opts(&req, sizeof(req), sizeof(struct inet_diag_msg),
			     offsetof(struct inet_diag_msg, idiag_inode),
			     INET_DIAG_SK_OPTS, ino, o);
}

static int unix_sk_opts(unsigned int ino, struct sock_diag_sk_opts *o)
{
	struct {
		struct nlmsghdr nlh;
		struct unix_diag_req r;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		},
		.r = {
			.sdiag_family = AF_UNIX,
			.udiag_states = ~0U,
			.udiag_show = UDIAG_SHOW_SK_OPTS,
		},
	};

	return query_sk_opts(&req, sizeof(req), sizeof(struct unix_diag_msg),
			     offsetof(struct unix_diag_msg, udiag_ino),
			     UNIX_DIAG_SK_OPTS, ino, o);
}

static int packet_sk_opts(unsigned int ino, struct sock_diag_sk_opts *o)
{
	struct {
		struct nlmsghdr nlh;
		struct packet_diag_req r;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		},
		.r = {
			.sdiag_family = AF_PACKET,
			.pdiag_show = PACKET_SHOW_SK_OPTS,
		},
	};

	return query_sk_opts(&req, sizeof(req), sizeof(struct packet_diag_msg),
			     offsetof(struct packet_diag_msg, pdiag_ino),
			     PACKET_DIAG_SK_OPTS, ino, o);
}

static int netlink_sk_opts(unsigned int ino, struct sock_diag_sk_opts *o)
{
	struct {
		struct nlmsghdr nlh;
		struct netlink_diag_req r;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = SOCK_DIAG_BY_FAMILY,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		},
		.r = {
			.sdiag_family = AF_NETLINK,
			.sdiag_protocol = NDIAG_PROTO_ALL,
			.ndiag_show = NDIAG_SHOW_SK_OPTS,
		},
	};

	return query_sk_opts(&req, sizeof(req), sizeof(struct netlink_diag_msg),
			     offsetof(struct netlink_diag_msg, ndiag_ino),
			     NETLINK_DIAG_SK_OPTS, ino, o);
}

static void test_inet_tcp(void)
{
	struct sockaddr_in a = { .sin_family = AF_INET };
	struct sock_diag_sk_opts o;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		ksft_exit_fail_perror("inet tcp socket");
	set_bool(fd, SO_REUSEADDR);
	set_bool(fd, SO_REUSEPORT);
	set_bool(fd, SO_KEEPALIVE);
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(fd, (void *)&a, sizeof(a)) || listen(fd, 1))
		ksft_exit_fail_perror("inet tcp bind/listen");

	if (inet_sk_opts(IPPROTO_TCP, sock_ino(fd), &o))
		ksft_test_result_fail("inet TCP: no SK_OPTS attribute\n");
	else
		ksft_test_result(o.reuseaddr && o.reuseport && o.keepalive &&
				 !o.broadcast && !o.linger,
				 "inet TCP: reuseaddr reuseport keepalive\n");
	close(fd);
}

static int bind_udp(int opt)
{
	struct sockaddr_in a = { .sin_family = AF_INET };
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		ksft_exit_fail_perror("inet udp socket");
	set_bool(fd, opt);
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(fd, (void *)&a, sizeof(a)))
		ksft_exit_fail_perror("inet udp bind");
	return fd;
}

static void test_inet_udp_broadcast(void)
{
	struct sock_diag_sk_opts o;
	int fd;

	fd = bind_udp(SO_BROADCAST);
	if (inet_sk_opts(IPPROTO_UDP, sock_ino(fd), &o))
		ksft_test_result_fail("inet UDP: no SK_OPTS attribute\n");
	else
		ksft_test_result(o.broadcast && !o.reuseaddr && !o.timestamp,
				 "inet UDP: broadcast\n");
	close(fd);
}

static void test_inet_udp_timestamp(void)
{
	struct sock_diag_sk_opts o;
	int fd;

	fd = bind_udp(SO_TIMESTAMP);
	if (inet_sk_opts(IPPROTO_UDP, sock_ino(fd), &o))
		ksft_test_result_fail("inet UDP timestamp: no SK_OPTS\n");
	else
		ksft_test_result(o.timestamp && !o.timestampns,
				 "inet UDP: SO_TIMESTAMP -> timestamp, not timestampns\n");
	close(fd);
}

static void test_inet_udp_timestampns(void)
{
	struct sock_diag_sk_opts o;
	int fd;

	fd = bind_udp(SO_TIMESTAMPNS);
	if (inet_sk_opts(IPPROTO_UDP, sock_ino(fd), &o))
		ksft_test_result_fail("inet UDP timestampns: no SK_OPTS\n");
	else
		ksft_test_result(o.timestampns && !o.timestamp,
				 "inet UDP: SO_TIMESTAMPNS -> timestampns, not timestamp\n");
	close(fd);
}

static void test_unix(void)
{
	struct sockaddr_un un = { .sun_family = AF_UNIX };
	struct sock_diag_sk_opts o;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		ksft_exit_fail_perror("unix socket");
	set_bool(fd, SO_REUSEADDR);
	/* abstract name, unique per pid */
	un.sun_path[0] = '\0';
	snprintf(un.sun_path + 1, sizeof(un.sun_path) - 1, "sk_opts_%d", getpid());
	if (bind(fd, (void *)&un, sizeof(un.sun_family) + 1 +
		 strlen(un.sun_path + 1)) || listen(fd, 1))
		ksft_exit_fail_perror("unix bind/listen");

	if (unix_sk_opts(sock_ino(fd), &o))
		ksft_test_result_fail("AF_UNIX: no SK_OPTS attribute (gating?)\n");
	else
		ksft_test_result(o.reuseaddr, "AF_UNIX: reuseaddr (UDIAG_SHOW_SK_OPTS)\n");
	close(fd);
}

static void test_netlink(void)
{
	struct sockaddr_nl nl = { .nl_family = AF_NETLINK };
	struct sock_diag_sk_opts o;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0)
		ksft_exit_fail_perror("netlink socket");
	set_bool(fd, SO_REUSEADDR);
	/* bind to get a portid; unbound netlink sockets are not dumped */
	if (bind(fd, (void *)&nl, sizeof(nl)))
		ksft_exit_fail_perror("netlink bind");

	if (netlink_sk_opts(sock_ino(fd), &o))
		ksft_test_result_fail("AF_NETLINK: no SK_OPTS attribute (gating?)\n");
	else
		ksft_test_result(o.reuseaddr, "AF_NETLINK: reuseaddr (NDIAG_SHOW_SK_OPTS)\n");
	close(fd);
}

static void test_packet(void)
{
	struct sock_diag_sk_opts o;
	int fd;

	fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (fd < 0) {
		ksft_test_result_skip("AF_PACKET: %s\n", strerror(errno));
		return;
	}
	set_bool(fd, SO_BROADCAST);

	if (packet_sk_opts(sock_ino(fd), &o))
		ksft_test_result_fail("AF_PACKET: no SK_OPTS attribute (gating?)\n");
	else
		ksft_test_result(o.broadcast, "AF_PACKET: broadcast (PACKET_SHOW_SK_OPTS)\n");
	close(fd);
}

int main(void)
{
	ksft_print_header();
	ksft_set_plan(7);

	test_inet_tcp();
	test_inet_udp_broadcast();
	test_inet_udp_timestamp();
	test_inet_udp_timestampns();
	test_unix();
	test_netlink();
	test_packet();

	ksft_finished();
}
