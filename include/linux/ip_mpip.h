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
extern int sysctl_mpip_log;

extern struct list_head wi_head;
extern struct list_head pi_head;
extern struct list_head ss_head;
extern struct list_head la_head;
extern struct list_head ps_head;

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


void mpip_log(const char *fmt, ...);

void print_node_id(unsigned char *node_id);

void print_addr(__be32 addr);

char *in_ntoa(unsigned long in);

bool is_equal_node_id(unsigned char *node_id_1, unsigned char *node_id_2);

int		mpip_rcv(struct sk_buff *skb);

int		mpip_xmit(struct sk_buff *skb);

void get_mpip_options(struct sk_buff *skb, char *options);

bool mpip_rcv_options(struct sk_buff *skb);

void print_mpip_options(struct mpip_options *opt);

void mpip_options_fragment(struct sk_buff *skb);

int insert_mpip_options(struct sk_buff *skb);

int mpip_options_get(struct net *net, struct mpip_options_rcu **optp,
					 unsigned char *data, int optlen);

void mpip_options_build(struct sk_buff *skb, struct mpip_options *opt);

//void mpip_log(char *file, int line, char *func);

bool mpip_rcv_options(struct sk_buff *skb);

int mpip_options_compile(struct net *net,
						 struct mpip_options *opt, struct sk_buff *skb);

int process_mpip_options(struct sk_buff *skb);


struct working_ip_table {
	unsigned char	node_id[ETH_ALEN]; /*receiver's node id. */
									   /*the node id is defined as the MAC*/
	__be32	addr; /* receiver' ip seen by sender */
	struct list_head list;
};


struct path_info_table {
	/*when sending pkts, check the bw to choose the fastest one*/
	/*update sent*/
	unsigned char node_id[ETH_ALEN]; /*destination node id*/
	unsigned char	path_id; /* path id: 0,1,2,3,4....*/
	__be32	saddr; /* source ip address*/
	__be32	daddr; /* destination ip address*/
	unsigned char	bw;  /* bandwidth */
	__u16   sent;  /* number of pkt sent on this path */
	__u16   rcv;  /* number of pkt received on this path */
	struct list_head list;
};


//
//struct sender_socket_table {
//	unsigned char	session_id; /* session id*/
//	/* socket information seen at the sender side*/
//	__be32	saddr; /* source ip address*/
//	__be32	daddr; /* destination ip address*/
//	__be16	sport; /* source port*/
//	__be16	dport; /* destination port*/
//	struct list_head list;
//};
//static LIST_HEAD(ss_head);

struct socket_session_table {
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

int add_working_ip(unsigned char *node_id, __be32 addr);

int del_working_ip(unsigned char *node_id, __be32 addr);

struct working_ip_table *find_working_ip(unsigned char *node_id, __be32 addr);

unsigned char * find_node_id_in_working_ip(__be32 addr);

int update_packet_rcv(unsigned char path_id, u16 packet_count);

unsigned char find_path_stat(unsigned char *node_id, unsigned char path_id);

int add_path_stat(unsigned char *node_id, unsigned char path_id);

int update_sender_packet_rcv(unsigned char *node_id, unsigned char path_id);

int update_path_info(void);

unsigned char find_receiver_socket_by_session(unsigned char *node_id,
								   	   	   	  unsigned char session_id);

unsigned char find_receiver_socket_by_socket(unsigned char *node_id,
											 __be32 saddr, __be16 sport,
											 __be32 daddr, __be16 dport);

int add_receiver_session(unsigned char *node_id,
						unsigned char session_id,
						__be32 saddr, __be16 sport,
		 	 	 	 	__be32 daddr, __be16 dport);

int get_receiver_session(unsigned char *node_id,	unsigned char session_id,
						__be32 *saddr, __be16 *sport,
						__be32 *daddr, __be16 *dport);

struct path_info_table *find_path_info(__be32 saddr, __be32 daddr);

bool is_dest_added(unsigned char *node_id, __be32 add);

int add_path_info(unsigned char *node_id, __be32 addr);

unsigned char find_fastest_path_id(unsigned char *node_id,
								   __be32 *saddr, __be32 *daddr,
								   __be32 origin_saddr, __be32 origin_daddr);

unsigned char find_earliest_stat_path_id(unsigned char *dest_node_id,
										 u16 *packet_count);

unsigned char get_sender_session(__be32 saddr, __be16 sport,
								 __be32 daddr, __be16 dport);

int add_sender_session(__be32 saddr, __be16 sport,
					  __be32 daddr, __be16 dport);

__be32 find_local_addr(__be32 addr);

void get_available_local_addr(void);

#endif	/* _IP_MPIP_H */
