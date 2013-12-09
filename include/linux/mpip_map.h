/*
 * include/linux/mpip_map.h
 * 
 * 2002-10-18  written by Jim Houston jim.houston@ccur.com
 *	Copyright (C) 2002 by Concurrent Computer Corporation
 *	Distributed under the GNU GPL license version 2.
 *
 * Small id to pointer translation service avoiding fixed sized
 * tables.
 */

#ifndef __MPIP_MAP_H__
#define __MPIP_MAP_H__

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/if_ether.h>

struct working_ip_table {
	unsigned char	node_id[ETH_ALEN]; /*receiver's node id. */
									   /*the node id is defined as the MAC*/
	__be32	addr_1; /* receiver' ip seen by sender */
	__be32	addr_2;
	__be32	addr_3; /* maximumly support three interfaces*/
	struct list_head list;
};

int add_working_ip_table(struct working_ip_table *item, struct list_head *head);
int del_working_ip_table(unsigned char *node_id, struct list_head *head);
struct working_ip_table * find_working_ip_table(unsigned char *node_id,
												struct list_head *head);

struct path_info_table {
	__u8    path_id; /* path id: 0,1,2,3,4....*/
	__be32	saddr; /* source ip address*/
	__be32	daddr; /* destination ip address*/
	__u8    bw;  /* bandwidth */
	__u16   sent;  /* number of pkt sent on this path */
	__u16   rcv;  /* number of pkt received on this path */
	struct list_head list;
};

int add_path_info_table(struct path_info_table *item, struct list_head *head);
int del_path_info_table(__be32 saddr, __be32 daddr, struct list_head *head);
struct path_info_table * find_path_info_table(__be32 saddr, __be32 daddr,
										      struct list_head *head);

struct sender_session_table {
	__u8    session_id; /* session id*/

	/* socket information seen at the sender side*/
	__be32	saddr; /* source ip address*/
	__be32	daddr; /* destination ip address*/
	__be16	sport; /* source port*/
	__be16	dport; /* destination port*/
	struct list_head list;
};


struct receiver_socket_table {
	unsigned char	node_id[ETH_ALEN]; /* sender's node id*/
	__u8    session_id; /* sender's session id*/

	/* socket information seen at the receiver side*/
	__be32	saddr; /* source ip address*/
	__be32	daddr; /* destination ip address*/
	__be16	sport; /* source port*/
	__be16	dport; /* destination port*/
	struct list_head list;
};

struct path_stat_table {
	unsigned char	node_id[ETH_ALEN]; /* sender's node id*/
	__u8    path_id; /* path id: 0,1,2,3,4....*/
	__u16   rcv;  /* number of pkt received on this path */
	struct timeval fbtime; /* last feedback time of this path's stat */
	struct list_head list;
};


#endif /* __MPIP_MAP_H__ */
