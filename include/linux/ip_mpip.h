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

extern int MPIP_OPT_LEN;
extern int sysctl_mpip_enabled;
int mpip_init(void);


#define MPIPCB(skb) ((struct mpip_skb_parm*)((skb)->cb))

struct mpip_options {
	unsigned char	optlen;
	unsigned char	node_id[ETH_ALEN];
	unsigned char	session_id;
	unsigned char	path_id;
	unsigned char	stat_path_id;
	u16	packet_count;
	//unsigned char   packet_count;
	unsigned char	__data[0];
};

struct mpip_options_rcu {
	struct rcu_head rcu;
	struct mpip_options opt;
};


struct mpip_skb_parm {
	struct mpip_options	opt;		/* Compiled IP options		*/

	unsigned char		flags;

	u16			frag_max_size;

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
extern bool mpip_rcv_options(struct sk_buff *skb);
extern int mpip_options_compile(struct net *net,
		    struct mpip_options *opt, struct sk_buff *skb);
extern int process_mpip_options(struct sk_buff *skb);


struct working_ip_table {
	unsigned char	node_id[ETH_ALEN]; /*receiver's node id. */
									   /*the node id is defined as the MAC*/
	__be32	addr; /* receiver' ip seen by sender */
	struct list_head list;
};


struct path_info_table {
	unsigned char	path_id; /* path id: 0,1,2,3,4....*/
	unsigned char node_id[ETH_ALEN]; /*node id*/
	__be32	saddr; /* source ip address*/
	__be32	daddr; /* destination ip address*/
	unsigned char	bw;  /* bandwidth */
	__u16   sent;  /* number of pkt sent on this path */
	__u16   rcv;  /* number of pkt received on this path */
	struct list_head list;
};


struct sender_session_table {
	unsigned char	session_id; /* session id*/

	/* socket information seen at the sender side*/
	__be32	saddr; /* source ip address*/
	__be32	daddr; /* destination ip address*/
	__be16	sport; /* source port*/
	__be16	dport; /* destination port*/
	struct list_head list;
};

struct receiver_socket_table {
	unsigned char	node_id[ETH_ALEN]; /* sender's node id*/
	unsigned char   session_id; /* sender's session id*/

	/* socket information seen at the receiver side*/
	__be32	saddr; /* source ip address*/
	__be32	daddr; /* destination ip address*/
	__be16	sport; /* source port*/
	__be16	dport; /* destination port*/
	struct list_head list;
};

struct path_stat_table {
	unsigned char	node_id[ETH_ALEN]; /* sender's node id*/
	unsigned char	path_id; /* path id: 0,1,2,3,4....*/
	u16   rcv;  /* number of pkt received on this path */
	unsigned long fbjiffies; /* last feedback time of this path's stat */
	struct list_head list;
};

struct local_addr_table {
	__be32	addr;
	struct list_head list;
};

int add_working_ip_table(unsigned char *node_id, __be32 addr);
int del_working_ip_table(unsigned char *node_id, __be32 addr);
struct working_ip_table * find_working_ip_table(unsigned char *node_id,
												__be32 addr);
int rcv_add_packet_rcv_2(unsigned char path_id, u16 packet_count);
int rcv_add_packet_rcv_5(unsigned char *node_id, unsigned char path_id);
int rcv_add_sock_info(unsigned char *node_id, __be32 saddr, __be16 sport,
		 	 __be32 daddr, __be16 dport, unsigned char session_id);
unsigned char find_fastest_path_id(unsigned char *node_id);
unsigned char find_earliest_stat_path_id(u16 *packet_count);
unsigned char find_sender_session_table(__be32 saddr, __be16 sport,
										__be32 daddr, __be16 dport);
int add_sender_session_table(__be32 saddr, __be16 sport,
							 __be32 daddr, __be16 dport,
							 unsigned char session_id);
__be32 find_local_addr_table(__be32 addr);
void get_available_local_addr();
unsigned char * find_node_id_in_working_ip_table(__be32 addr);
int add_path_info_table(unsigned char *node_id, __be32 daddr);

static LIST_HEAD(wi_head);
static LIST_HEAD(pi_head);
static LIST_HEAD(ss_head);
static LIST_HEAD(rs_head);
static LIST_HEAD(ps_head);
static LIST_HEAD(la_head);

#endif	/* _IP_MPIP_H */
