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

#define MPIP_OPT_LEN 13
#define MPIP_OPT_NODE_ID_LEN 2

extern int sysctl_mpip_enabled;
extern int sysctl_mpip_send;
extern int sysctl_mpip_rcv;
extern int sysctl_mpip_log;
extern int sysctl_mpip_bw_factor;
extern int sysctl_mpip_bw_1;
extern int sysctl_mpip_bw_2;
extern int sysctl_mpip_bw_3;
extern int sysctl_mpip_bw_4;
extern int sysctl_mpip_hb;
extern int max_pkt_len;
extern int global_stat_1;
extern int global_stat_2;
extern int global_stat_3;

//
//extern struct list_head wi_head;
//extern struct list_head pi_head;
//extern struct list_head ss_head;
//extern struct list_head la_head;
//extern struct list_head ps_head;

int mpip_init(void);

void mpip_log(const char *fmt, ...);

void mpip_tcp_v4_send_check(struct sk_buff *skb, __be32 saddr, __be32 daddr);

void print_node_id(const char *prefix, unsigned char *node_id);

void print_addr(const char *prefix, __be32 addr);

__be32 convert_addr(char a1, char a2, char a3, char a4);

char *in_ntoa(unsigned long in);

bool is_equal_node_id(unsigned char *node_id_1, unsigned char *node_id_2);

int		mpip_rcv(struct sk_buff *skb);

int		mpip_xmit(struct sk_buff *skb);

struct net_device *find_dev_by_addr(__be32 addr);

int get_mpip_options(struct sk_buff *skb, __be32 old_saddr, __be32 old_daddr,
		__be32 *new_saddr, __be32 *new_daddr, unsigned char *options);

//int get_mpip_options_1(struct sk_buff *skb, __be32 old_saddr, __be32 old_daddr,
//			__be32 *new_saddr, __be32 *new_daddr, unsigned char *options);

bool check_bad_addr(__be32 saddr, __be32 daddr);

void print_mpip_options(const char *prefix, struct ip_options *opt);

int insert_mpip_options(struct sk_buff *skb, struct flowi *fl, bool pushed);

int mpip_compose_opt(struct sk_buff *skb, __be32 old_saddr, __be32 old_daddr,
					__be32 *new_saddr, __be32 *new_daddr);
//int mpip_compose_opt_1(struct sk_buff *skb, __be32 old_saddr, __be32 old_daddr,
//						__be32 *new_saddr, __be32 *new_daddr);

void mpip_options_build(struct sk_buff *skb, bool pushed);

int process_mpip_options(struct sk_buff *skb);

int get_mpip_options_udp(struct sk_buff *skb, __be32 *new_saddr, __be32 *new_daddr, unsigned char *options);

int insert_mpip_options_udp(struct sk_buff *skb, __be32 *new_saddr, __be32 *new_daddr);

int icmp_send_mpip_hb(struct sk_buff *skb);

int insert_mpip_options_hb(struct sk_buff *skb);


struct working_ip_table {
	unsigned char	node_id[MPIP_OPT_NODE_ID_LEN]; /*receiver's node id. */
									   /*the node id is defined as the MAC*/
	__be32	addr; /* receiver' ip seen by sender */
	struct list_head list;
};


struct path_info_table {
	/*when sending pkts, check the bw to choose the fastest one*/
	/*update sent*/
	unsigned char node_id[MPIP_OPT_NODE_ID_LEN]; /*destination node id*/
	unsigned char	path_id; /* path id: 0,1,2,3,4....*/
	__be32	saddr; /* source ip address*/
	__be32	daddr; /* destination ip address*/
	unsigned char rcvrate; /* rcv rate */
	__u32 losspkt; /*the amount of data that are lost*/
	int     delay;
	int 	posdelay;
	__u32	bw;  /* bandwidth */
	__u32   sentc;
	__u16   sent;  /* number of pkt sent on this path */
	__u16   rcv;  /* number of pkt received on this path */
	__u32   senth;
	__u32	rcvh;  /* number of mega received on this path */
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
	unsigned char	src_node_id[MPIP_OPT_NODE_ID_LEN]; /* local node id*/
	unsigned char	dst_node_id[MPIP_OPT_NODE_ID_LEN]; /* remote node id*/
	unsigned char   session_id; /* sender's session id*/

	/* socket information seen at the receiver side*/
	__be32	saddr; /* source ip address*/
	__be32	daddr; /* destination ip address*/
	__be16	sport; /* source port*/
	__be16	dport; /* destination port*/
	struct list_head list;
};



struct path_stat_table {
	unsigned char	node_id[MPIP_OPT_NODE_ID_LEN]; /* sender's node id*/
	unsigned char	path_id; /* path id: 0,1,2,3,4....*/
	__be32	saddr; /* source ip address*/
	__be32	daddr; /* destination ip address*/
//	atomic_t  rcv;  /* number of pkt received on this path */
	__u16  rcvc;    /* number of pkt received on this path */
	unsigned char	rcvh;  /* number of mega received on this path */
	__u16  rcv;
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

int update_packet_rcv(unsigned char path_id, unsigned char rcvh, u16 rcv);

struct path_stat_table *find_path_stat(unsigned char *node_id, unsigned char path_id);

struct path_stat_table *find_path_stat_by_addr(__be32 saddr, __be32 daddr);

int add_path_stat(unsigned char *node_id, unsigned char path_id, __be32 saddr, __be32 daddr);

int update_sender_packet_rcv(unsigned char *node_id, unsigned char path_id, u16 pkt_len);

int update_path_delay(__be32 saddr, __be32 daddr, __u32 delay);

int update_path_info(void);

unsigned char find_receiver_socket_by_session(unsigned char *node_id,
								   	   	   	  unsigned char session_id);

unsigned char find_receiver_socket_by_socket(unsigned char *node_id,
											 __be32 saddr, __be16 sport,
											 __be32 daddr, __be16 dport);

unsigned char add_receiver_session(unsigned char *src_node_id, unsigned char *dst_node_id,
						__be32 saddr, __be16 sport,
		 	 	 	 	__be32 daddr, __be16 dport,
		 	 	 	 	unsigned char session_id);

int get_receiver_session(unsigned char *node_id,	unsigned char session_id,
						__be32 *saddr, __be16 *sport,
						__be32 *daddr, __be16 *dport);

struct path_info_table *find_path_info(__be32 saddr, __be32 daddr);

unsigned char find_path_id(__be32 saddr, __be32 daddr);

bool is_dest_added(unsigned char *node_id, __be32 add);

int add_path_info(unsigned char *node_id, __be32 addr);

unsigned char add_rcv_for_path(struct sk_buff *skb, __be32 saddr, __be32 daddr, u16 pkt_len);

unsigned char add_sent_for_path(__be32 saddr, __be32 daddr, u16 pkt_len);

unsigned char find_fastest_path_id(unsigned char *node_id,
								   __be32 *saddr, __be32 *daddr,
								   __be32 origin_saddr, __be32 origin_daddr,
								   u16 pkt_len);

unsigned char find_earliest_stat_path_id(unsigned char *dest_node_id, unsigned char *rcvh,
										 u16 *rcv);

unsigned char get_sender_session(__be32 saddr, __be16 sport,
								 __be32 daddr, __be16 dport);

int add_sender_session(unsigned char *src_node_id, unsigned char *dst_node_id,
					   __be32 saddr, __be16 sport,
					   __be32 daddr, __be16 dport);

__be32 find_local_addr(__be32 addr);

void get_available_local_addr(void);

#endif	/* _IP_MPIP_H */
