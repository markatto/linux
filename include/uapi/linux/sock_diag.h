/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__SOCK_DIAG_H__
#define _UAPI__SOCK_DIAG_H__

#include <linux/types.h>

#define SOCK_DIAG_BY_FAMILY 20
#define SOCK_DESTROY 21

struct sock_diag_req {
	__u8	sdiag_family;
	__u8	sdiag_protocol;
};

enum {
	SK_MEMINFO_RMEM_ALLOC,
	SK_MEMINFO_RCVBUF,
	SK_MEMINFO_WMEM_ALLOC,
	SK_MEMINFO_SNDBUF,
	SK_MEMINFO_FWD_ALLOC,
	SK_MEMINFO_WMEM_QUEUED,
	SK_MEMINFO_OPTMEM,
	SK_MEMINFO_BACKLOG,
	SK_MEMINFO_DROPS,

	SK_MEMINFO_VARS,
};

/* SOL_SOCKET-level boolean options (see socket(7)), reported per socket via
 * each family's *_DIAG_SK_OPTS attribute. Filled by sock_diag_put_sk_opts()
 * from the generic struct sock, so every family reports them the same way.
 *
 * timestamp and timestampns report the SO_TIMESTAMP / SO_TIMESTAMPNS receive
 * mode regardless of the _OLD/_NEW timeval-width variant; that width split is
 * a userspace ABI detail and is not reported here.
 */
struct sock_diag_sk_opts {
	__u8	reuseaddr:1,
		reuseport:1,
		keepalive:1,
		broadcast:1,
		oobinline:1,
		dontroute:1,
		linger:1,
		timestamp:1;
	__u8	debug:1,
		zerocopy:1,
		txtime:1,
		rxq_ovfl:1,
		select_err_queue:1,
		nofcs:1,
		rcvmark:1,
		timestampns:1;
};

enum sknetlink_groups {
	SKNLGRP_NONE,
	SKNLGRP_INET_TCP_DESTROY,
	SKNLGRP_INET_UDP_DESTROY,
	SKNLGRP_INET6_TCP_DESTROY,
	SKNLGRP_INET6_UDP_DESTROY,
	__SKNLGRP_MAX,
};
#define SKNLGRP_MAX	(__SKNLGRP_MAX - 1)

enum {
	SK_DIAG_BPF_STORAGE_REQ_NONE,
	SK_DIAG_BPF_STORAGE_REQ_MAP_FD,
	__SK_DIAG_BPF_STORAGE_REQ_MAX,
};

#define SK_DIAG_BPF_STORAGE_REQ_MAX	(__SK_DIAG_BPF_STORAGE_REQ_MAX - 1)

enum {
	SK_DIAG_BPF_STORAGE_REP_NONE,
	SK_DIAG_BPF_STORAGE,
	__SK_DIAG_BPF_STORAGE_REP_MAX,
};

#define SK_DIAB_BPF_STORAGE_REP_MAX	(__SK_DIAG_BPF_STORAGE_REP_MAX - 1)

enum {
	SK_DIAG_BPF_STORAGE_NONE,
	SK_DIAG_BPF_STORAGE_PAD,
	SK_DIAG_BPF_STORAGE_MAP_ID,
	SK_DIAG_BPF_STORAGE_MAP_VALUE,
	__SK_DIAG_BPF_STORAGE_MAX,
};

#define SK_DIAG_BPF_STORAGE_MAX        (__SK_DIAG_BPF_STORAGE_MAX - 1)

#endif /* _UAPI__SOCK_DIAG_H__ */
