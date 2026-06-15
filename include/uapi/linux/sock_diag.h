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
 * each family's *_DIAG_SK_OPTS attribute. That attribute is a struct
 * nla_bitfield32 filled by sock_diag_put_sk_opts() from the generic struct
 * sock: its selector marks the options the running kernel knows how to report
 * and its value carries the ones that are set, so userspace can tell a cleared
 * option from one the kernel does not report and new options can be added
 * without growing a fixed struct. Every family reports them the same way.
 *
 * SK_DIAG_OPT_TIMESTAMP and SK_DIAG_OPT_TIMESTAMPNS report the SO_TIMESTAMP /
 * SO_TIMESTAMPNS receive mode regardless of the _OLD/_NEW timeval-width
 * variant; that width split is a userspace ABI detail and is not reported here.
 */
enum {
	SK_DIAG_OPT_REUSEADDR		= 1 << 0,
	SK_DIAG_OPT_REUSEPORT		= 1 << 1,
	SK_DIAG_OPT_KEEPALIVE		= 1 << 2,
	SK_DIAG_OPT_BROADCAST		= 1 << 3,
	SK_DIAG_OPT_OOBINLINE		= 1 << 4,
	SK_DIAG_OPT_DONTROUTE		= 1 << 5,
	SK_DIAG_OPT_LINGER		= 1 << 6,
	SK_DIAG_OPT_TIMESTAMP		= 1 << 7,
	SK_DIAG_OPT_DEBUG		= 1 << 8,
	SK_DIAG_OPT_ZEROCOPY		= 1 << 9,
	SK_DIAG_OPT_TXTIME		= 1 << 10,
	SK_DIAG_OPT_RXQ_OVFL		= 1 << 11,
	SK_DIAG_OPT_SELECT_ERR_QUEUE	= 1 << 12,
	SK_DIAG_OPT_NOFCS		= 1 << 13,
	SK_DIAG_OPT_RCVMARK		= 1 << 14,
	SK_DIAG_OPT_TIMESTAMPNS		= 1 << 15,
};

/* The options these headers know of; the selector on the wire is what the
 * running kernel reports.
 */
#define SK_DIAG_OPT_SUPPORTED						\
	(SK_DIAG_OPT_REUSEADDR | SK_DIAG_OPT_REUSEPORT |		\
	 SK_DIAG_OPT_KEEPALIVE | SK_DIAG_OPT_BROADCAST |		\
	 SK_DIAG_OPT_OOBINLINE | SK_DIAG_OPT_DONTROUTE |		\
	 SK_DIAG_OPT_LINGER | SK_DIAG_OPT_TIMESTAMP |			\
	 SK_DIAG_OPT_DEBUG | SK_DIAG_OPT_ZEROCOPY |			\
	 SK_DIAG_OPT_TXTIME | SK_DIAG_OPT_RXQ_OVFL |			\
	 SK_DIAG_OPT_SELECT_ERR_QUEUE | SK_DIAG_OPT_NOFCS |		\
	 SK_DIAG_OPT_RCVMARK | SK_DIAG_OPT_TIMESTAMPNS)

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
