#include <linux/ip_mpip.h>

int add_working_ip_table(unsigned char *node_id, __be32 addr)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct working_ip_table *item = NULL;

	if (find_working_ip_table(node_id, addr))
		return 0;

	item = kzalloc(sizeof(struct working_ip_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, ETH_ALEN);
	item->addr = addr;
	INIT_LIST_HEAD(&item->list);
	list_add(&(item->list), &wi_head);

	return 1;
}

int del_working_ip_table(unsigned char *node_id, __be32 addr)
{
	/* todo: need locks */
	struct working_ip_table *working_ip, *tmp;

	list_for_each_entry_safe(working_ip, tmp, &wi_head, list)
	{
		if ((strcmp(node_id, working_ip->node_id) == 0) &&
				(addr == working_ip->addr))
		{
			list_del(&(working_ip->list));
			kfree(working_ip);
			break;
		}
	}

	return 1;
}

struct working_ip_table * find_working_ip_table(unsigned char *node_id,
												__be32 addr)
{
	struct working_ip_table *working_ip;

	list_for_each_entry(working_ip, &wi_head, list)
	{
		if ((strcmp(node_id, working_ip->node_id)  == 0) &&
				(addr == working_ip->addr))
		{
			return working_ip;
		}
	}

	return NULL;
}


int rcv_add_packet_rcv_2(unsigned char path_id, u16 packet_count)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct path_info_table *path_info;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->path_id == path_id)
		{
			path_info->rcv = packet_count;
			break;
		}
	}

	return 1;
}

int rcv_add_packet_rcv_5(unsigned char *node_id, unsigned char path_id)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct path_stat_table *path_stat;

	list_for_each_entry(path_stat, &ps_head, list)
	{
		if ((strcmp(node_id, path_stat->node_id)  == 0) &&
				(path_stat->path_id == path_id))
		{
			path_stat->rcv += 1;
			break;
		}
	}

	return 1;
}

unsigned char find_receiver_socket_table(unsigned char *node_id, __be32 saddr,
										__be16 sport, __be32 daddr, __be16 dport)
{
	struct receiver_socket_table *receiver_socket;

	list_for_each_entry(receiver_socket, &rs_head, list)
	{
		if ((strcmp(receiver_socket->node_id, node_id) == 0) &&
			(receiver_socket->saddr == saddr) &&
			(receiver_socket->sport == sport) &&
			(receiver_socket->daddr == daddr) &&
			(receiver_socket->dport == dport))
		{
			return receiver_socket->session_id;
		}
	}

	return 0;
}

int rcv_add_sock_info(unsigned char *node_id, __be32 saddr, __be16 sport,
		 	 __be32 daddr, __be16 dport, unsigned char session_id)
{
	struct receiver_socket_table *item = NULL;

	if (find_receiver_socket_table(node_id, saddr, sport, daddr, dport) > 0)
		return 0;

	item = kzalloc(sizeof(struct receiver_socket_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, ETH_ALEN);
	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->session_id = session_id;
	INIT_LIST_HEAD(&item->list);
	list_add(&(item->list), &rs_head);

	return 1;
}


unsigned char find_fastest_path_id(void)
{
	struct path_info_table *path;
	struct path_info_table *f_path;
	unsigned char f_path_id = -1;
	unsigned char f_bw = -1;
	list_for_each_entry(path, &pi_head, list)
	{
		if (path->bw > f_bw)
		{
			f_path_id = path->path_id;
			f_bw = path->bw;
			f_path = path;
		}
	}

	if (f_path_id > 0)
	{
		f_path->sent += 1;
	}
	return f_path_id;
}


unsigned char find_earliest_stat_path_id(u16 *packet_count)
{
	struct path_stat_table *path_stat;
	struct path_stat_table *e_path_stat;
	unsigned char e_path_stat_id = -1;
	unsigned long e_fbtime = jiffies;
	list_for_each_entry(path_stat, &ps_head, list)
	{
		if (path_stat->fbjiffies < e_fbtime)
		{
			e_path_stat_id = path_stat->path_id;
			e_fbtime = path_stat->fbjiffies;
			e_path_stat = path_stat;
		}
	}

	if (e_path_stat_id > 0)
	{
		e_path_stat->fbjiffies = jiffies;
		*packet_count = e_path_stat->rcv;
	}

	return e_path_stat_id;
}

unsigned char find_sender_session_table(__be32 saddr, __be16 sport,
										__be32 daddr, __be16 dport)
{
	struct sender_session_table *sender_session;

	list_for_each_entry(sender_session, &ss_head, list)
	{
		if ((sender_session->saddr == saddr) &&
			(sender_session->sport == sport) &&
			(sender_session->daddr == daddr) &&
			(sender_session->dport == dport))
		{
			return sender_session->session_id;
		}
	}

	return 0;
}

int add_sender_session_table(__be32 saddr, __be16 sport,
							 __be32 daddr, __be16 dport, unsigned char session_id)
{
	struct sender_session_table *item = NULL;

	if (find_sender_session_table(saddr, sport, daddr, dport) > 0)
		return 0;

	item = kzalloc(sizeof(struct sender_session_table),	GFP_ATOMIC);

	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->session_id = session_id;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &ss_head);

	return 1;
}
