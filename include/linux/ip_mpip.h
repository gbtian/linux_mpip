/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP module.
 *
 * Version:	@(#)ip_mpip.h	1.0.0	02/12/2013
 *
 * Authors:	Guibin Tian, <gbtian@gmail.com>
 *
 * Changes:
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _IP_MPIP_H
#define _IP_MPIP_H


#include <linux/types.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/skbuff.h>

#include <net/inet_sock.h>
#include <net/snmp.h>
#include <net/flow.h>

extern int sysctl_mpip_enabled;
int mpip_init(void);


#define MPIPCB(skb) ((struct mpip_skb_parm*)((skb)->cb))

struct mpip_options {
	unsigned char	optlen;
	unsigned char	node_id[ETH_ALEN];
	unsigned char	session_id;
	unsigned char	path_id;
	unsigned char	stat_path_id;
	unsigned char	packetcount;
	unsigned char	__data[0];
};

struct mpip_options_rcu {
	struct rcu_head rcu;
	struct mpip_options opt;
};


struct mpip_skb_parm {
	struct mpip_options	opt;		/* Compiled IP options		*/
};

extern int		mpip_rcv(struct sk_buff *skb);
extern int		mpip_xmit(struct sk_buff *skb);
extern void get_mpip_options(struct sk_buff *skb, char *options);
extern bool mpip_rcv_options(struct sk_buff *skb);
extern void print_mpip_options(struct mpip_options *opt);
extern int mpip_options_get(struct net *net, struct mpip_options_rcu **optp,
		   unsigned char *data, int optlen);
extern void mpip_options_build(struct sk_buff *skb, struct mpip_options *opt);
extern void mpip_log(char *file, int line, char *func);

static LIST_HEAD(wi_head);
static LIST_HEAD(pi_head);
static LIST_HEAD(ss_head);
static LIST_HEAD(rs_head);
static LIST_HEAD(ps_head);

#endif	/* _IP_MPIP_H */
