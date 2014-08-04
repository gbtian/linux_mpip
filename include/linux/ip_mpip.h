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

#define MPIP_CM_LEN 25
#define MPIP_CM_NODE_ID_LEN 2
#define MPIP_TCP_BUF_LEN 5

//#define MPIP_FLAG_

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
extern int sysctl_mpip_use_tcp;
extern int sysctl_mpip_tcp_buf_count;

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

struct mpip_cm
{
	unsigned char	len;
	unsigned char	node_id[2];
	unsigned char	session_id;
	unsigned char	path_id;
	unsigned char	path_stat_id;
	__s32			timestamp;
	__s32			delay;
	__be32          addr1;
	__be32          addr2;
	unsigned char	flags;
	__s16			checksum;
};

struct mpip_query_table
{
	__be32				saddr; /* source ip address*/
	__be32				daddr; /* destination ip address*/
	__be16				sport; /* source port*/
	__be16				dport; /* destination port*/
	struct list_head 	list;
};

struct mpip_enabled_table
{
	__be32				addr; /* receiver' ip seen by sender */
	__be16				port;
	bool				mpip_enabled;
	int 				sent_count;
	struct list_head 	list;
};

struct addr_notified_table
{
	unsigned char		node_id[MPIP_CM_NODE_ID_LEN]; /*receiver's node id. */
	bool				notified;
	int					count;
	struct list_head 	list;
};


struct working_ip_table
{
	unsigned char		node_id[MPIP_CM_NODE_ID_LEN]; /*receiver's node id. */
	__be32				addr; /* receiver' ip seen by sender */
	__be16				port;
	unsigned int 		protocol;
	unsigned char		session_id;
	struct list_head 	list;
};


struct path_info_table
{
	/*when sending pkts, check the bw to choose the fastest one*/
	/*update sent*/
	unsigned char 		node_id[MPIP_CM_NODE_ID_LEN]; /*destination node id*/
	unsigned char		path_id; /* path id: 0,1,2,3,4....*/
	unsigned char		session_id;
	__be32				saddr; /* source ip address*/
	__be32				daddr; /* destination ip address*/
	__be16				sport; /* source port*/
	__be16				dport; /* destination port*/
//	unsigned int 		protocol;
	__s32 				min_delay;
	__s32     			delay;
	__s32     			queuing_delay;
	__s32     			max_queuing_delay;
	__u64				bw;  /* bandwidth */
	unsigned long 		fbjiffies; /* last feedback time of this path */
	unsigned char		count;
	__u64				pktcount;
	unsigned char		status;/* For tcp additional path:
	 	 	 	 	 	 	 	0: ready for use
	 	 	 	 	 	 	 	1: syn sent
	 	 	 	 	 	 	 	2: synack sent
	 	 	 	 	 	 	 	3: ack sent*/
	struct list_head 	list;
};


struct tcp_skb_buf
{
	__u32				seq;
	struct sk_buff *	skb;
	unsigned long 		fbjiffies;
	struct list_head 	list;
};

struct socket_session_table
{
	unsigned char		src_node_id[MPIP_CM_NODE_ID_LEN]; /* local node id*/
	unsigned char		dst_node_id[MPIP_CM_NODE_ID_LEN]; /* remote node id*/
	unsigned char   	session_id; /* sender's session id*/

	struct list_head 	tcp_buf;
	__u32				next_seq;
	int 				buf_count;
	unsigned int 		protocol;

	/* socket information seen at the receiver side*/
	__be32				saddr; /* source ip address*/
	__be32				daddr; /* destination ip address*/
	__be16				sport; /* source port*/
	__be16				dport; /* destination port*/
	struct list_head 	list;
};

struct path_stat_table
{
	unsigned char		node_id[MPIP_CM_NODE_ID_LEN]; /* sender's node id*/
	unsigned char		path_id; /* path id: 0,1,2,3,4....*/
	__s32     			delay;
	bool				feedbacked;
	__u64				pktcount;
	unsigned long 		fbjiffies; /* last feedback time of this path's stat */
	struct list_head 	list;
};

struct local_addr_table
{
	__be32				addr;
	struct list_head 	list;
};


int mpip_init(void);

void mpip_log(const char *fmt, ...);

void print_node_id(unsigned char *node_id);

void print_addr(__be32 addr);

__be32 convert_addr(char a1, char a2, char a3, char a4);

char *in_ntoa(unsigned long in);

bool is_equal_node_id(unsigned char *node_id_1, unsigned char *node_id_2);

int		mpip_rcv(struct sk_buff *skb);

int		mpip_xmit(struct sk_buff *skb);

struct net_device *find_dev_by_addr(__be32 addr);

void print_mpip_cm(struct mpip_cm *cm);

bool ip_route_out( struct sk_buff *skb, __be32 saddr, __be32 daddr);

bool send_mpip_msg(struct sk_buff *skb, bool sender, bool reverse,
		unsigned char flags, unsigned char session_id);

bool check_path_info_status(struct sk_buff *skb,
		unsigned char *node_id, unsigned char session_id);

bool send_mpip_syn(struct sk_buff *skb_in, __be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport,	bool syn, bool ack,
		unsigned char session_id);

bool send_mpip_skb(struct sk_buff *skb_in, unsigned char flags);

bool get_skb_port(struct sk_buff *skb, __be16 *sport, __be16 *dport);

bool insert_mpip_cm(struct sk_buff *skb, __be32 old_saddr, __be32 old_daddr,
					__be32 *new_saddr, __be32 *new_daddr,
					unsigned int protocol, unsigned char flags,
					unsigned char session_id);

int process_mpip_cm(struct sk_buff *skb);

bool check_bad_addr(__be32 addr);

void send_mpip_hb(struct sk_buff *skb, unsigned char session_id);

void send_mpip_enable(struct sk_buff *skb, bool sender, bool reverse);

void send_mpip_enabled(struct sk_buff *skb, bool sender, bool reverse);

int add_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport);

int delete_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport);

struct mpip_query_table *find_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport);

struct mpip_enabled_table *find_mpip_enabled(__be32 addr, __be16 port);

int add_mpip_enabled(__be32 addr, __be16 port, bool enabled);

bool is_mpip_enabled(__be32 addr, __be16 port);

bool is_local_addr(__be32 addr);

__be32 get_local_addr1(void);

__be32 get_local_addr2(void);

bool get_addr_notified(unsigned char *node_id);

struct addr_notified_table *find_addr_notified(unsigned char *node_id);

int add_addr_notified(unsigned char *node_id);

void process_addr_notified_event(unsigned char *node_id, unsigned char flags);

int add_working_ip(unsigned char *node_id, __be32 addr, __be16 port,
		unsigned char session_id, unsigned int protocol);

struct working_ip_table *find_working_ip(unsigned char *node_id, __be32 addr,
		__be16 port, unsigned int protocol);

unsigned char * find_node_id_in_working_ip(__be32 addr, __be16 port,
		unsigned int protocol);

struct path_stat_table *find_path_stat(unsigned char *node_id, unsigned char path_id);

int add_path_stat(unsigned char *node_id, unsigned char path_id);

int update_path_stat_delay(unsigned char *node_id, unsigned char path_id, u32 delay);

int update_path_delay(unsigned char path_id, __s32 delay);

bool ready_path_info(unsigned char *node_id, __be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport,	unsigned char session_id);

int update_path_info(unsigned char session_id, unsigned int len);


struct socket_session_table *get_receiver_session(unsigned char *src_node_id, unsigned char *dst_node_id,
						__be32 saddr, __be16 sport,
		 	 	 	 	__be32 daddr, __be16 dport,
		 	 	 	 	unsigned char session_id,
		 	 	 	 	unsigned char path_id,
		 	 	 	 	unsigned int protocol);

int get_receiver_session_info(unsigned char *node_id,	unsigned char session_id,
						__be32 *saddr, __be16 *sport,
						__be32 *daddr, __be16 *dport);

struct path_info_table *find_path_info(__be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport, unsigned char session_id);

bool is_dest_added(unsigned char *node_id, __be32 addr, __be16 port,
					unsigned char session_id, unsigned int protocol);

bool init_mpip_tcp_connection(__be32 daddr1, __be32 daddr2,
							__be32 saddr, __be32 daddr,
							__be16 sport, __be16 dport,
							unsigned char session_id);

int add_origin_path_info_tcp(unsigned char *node_id, __be32 saddr, __be32 daddr, __be16 sport,
		__be16 dport, unsigned char session_id, unsigned int protocol);


int add_path_info_tcp(unsigned char *node_id, __be32 saddr, __be32 daddr, __be16 sport,
		__be16 dport, unsigned char session_id, unsigned int protocol);

int add_path_info_udp(unsigned char *node_id, __be32 daddr, __be16 sport,
		__be16 dport, unsigned char session_id, unsigned int protocol);

bool is_original_path(unsigned char *node_id, __be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport,	unsigned char session_id);

unsigned char find_fastest_path_id(unsigned char *node_id,
			   __be32 *saddr, __be32 *daddr,  __be16 *sport, __be16 *dport,
			   __be32 origin_saddr, __be32 origin_daddr, __be16 origin_sport,
			   __be16 origin_dport, unsigned char session_id,
			   unsigned int protocol, unsigned int len);

unsigned char find_earliest_path_stat_id(unsigned char *dest_node_id, __s32 *delay);

struct socket_session_table *get_sender_session(__be32 saddr, __be16 sport,
							 __be32 daddr, __be16 dport, unsigned int protocol);

void add_sender_session(unsigned char *src_node_id, unsigned char *dst_node_id,
					   __be32 saddr, __be16 sport,
					   __be32 daddr, __be16 dport,
					   unsigned int protocol);

__be32 find_local_addr(__be32 addr);

void get_available_local_addr(void);

void update_addr_change(void);

int add_to_tcp_skb_buf(struct sk_buff *skb, unsigned char session_id);

//unsigned char get_session(struct sk_buff *skb);

void reset_mpip(void);

unsigned char get_tcp_session(struct sk_buff *skb);

#endif	/* _IP_MPIP_H */
