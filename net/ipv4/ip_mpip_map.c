#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/ip_mpip.h>

static unsigned char static_session_id = 1;
static unsigned char static_path_id = 1;


int add_working_ip(unsigned char *node_id, __be32 addr)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct working_ip_table *item = NULL;

	if (find_working_ip(node_id, addr))
		return 0;

	item = kzalloc(sizeof(struct working_ip_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, ETH_ALEN);
	item->addr = addr;
	INIT_LIST_HEAD(&item->list);
	list_add(&(item->list), &wi_head);

	return 1;
}

int del_working_ip(unsigned char *node_id, __be32 addr)
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

struct working_ip_table *find_working_ip(unsigned char *node_id, __be32 addr)
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

unsigned char * find_node_id_in_working_ip(__be32 addr)
{
	struct working_ip_table *working_ip;

	list_for_each_entry(working_ip, &wi_head, list)
	{
		if (addr == working_ip->addr)
		{
			return working_ip->node_id;
		}
	}

	return NULL;
}


int update_packet_rcv(unsigned char path_id, u16 packet_count)
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

unsigned char find_path_stat(unsigned char *node_id, unsigned char path_id)
{
	struct path_stat_table *path_stat;

	list_for_each_entry(path_stat, &la_head, list)
	{
		if ((strcmp(node_id, path_stat->node_id)  == 0) &&
			(path_stat->path_id == path_id))
		{
			return path_stat->path_id;
		}
	}

	return 0;
}

int add_path_stat(unsigned char *node_id, unsigned char path_id)
{
	struct path_stat_table *item = NULL;

	if (find_path_stat(node_id, path_id) > 0)
		return 0;

	item = kzalloc(sizeof(struct path_stat_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, ETH_ALEN);
	item->path_id = path_id;
	item->rcv = 0;
	item->fbjiffies = jiffies;
	INIT_LIST_HEAD(&item->list);
	list_add(&(item->list), &ps_head);

	return 1;
}

int inc_sender_packet_rcv(unsigned char *node_id, unsigned char path_id)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct path_stat_table *path_stat;

	if (find_path_stat(node_id, path_id) == 0)
	{
		add_path_stat(node_id, path_id);
	}

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

unsigned char find_receiver_socket(unsigned char *node_id, unsigned char session_id)
{
	struct receiver_socket_table *receiver_socket;

	list_for_each_entry(receiver_socket, &rs_head, list)
	{
		if ((strcmp(receiver_socket->node_id, node_id) == 0) &&
			(receiver_socket->session_id == session_id))
		{
			return receiver_socket->session_id;
		}
	}

	return 0;
}

int add_receiver_socket(unsigned char *node_id, unsigned char session_id,
						__be32 saddr, __be16 sport,
		 	 	 	 	__be32 daddr, __be16 dport)
{
	struct receiver_socket_table *item = NULL;

	if (find_receiver_socket(node_id, session_id) > 0)
		return 0;

	item = kzalloc(sizeof(struct receiver_socket_table), GFP_ATOMIC);

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

int get_receiver_socket(unsigned char *node_id,	unsigned char session_id,
						__be32 *saddr, __be16 *sport,
						__be32 *daddr, __be16 *dport)
{
	struct receiver_socket_table *receiver_socket;
	list_for_each_entry(receiver_socket, &rs_head, list)
	{
		if ((strcmp(receiver_socket->node_id, node_id) == 0) &&
				(receiver_socket->session_id == session_id))
		{
			*saddr = receiver_socket->saddr;
			*daddr = receiver_socket->daddr;
			*sport = receiver_socket->sport;
			*dport = receiver_socket->dport;

			return 1;
		}
	}

	return 0;
}


unsigned char find_path_info(unsigned char *node_id, __be32 addr)
{
	struct path_info_table *path_info;
	list_for_each_entry(path_info, &pi_head, list)
	{
		if ((strcmp(path_info->node_id, node_id) == 0) &&
			(path_info->daddr == addr))
		{
			return path_info->path_id;
		}
	}
	return 0;
}

int add_path_info(unsigned char *node_id, __be32 addr)
{
	struct local_addr_table *local_addr;

	if (find_path_info(node_id, addr))
		return 0;

	list_for_each_entry(local_addr, &la_head, list)
	{
		struct path_info_table *item = NULL;

		item = kzalloc(sizeof(struct local_addr_table),	GFP_ATOMIC);

		memcpy(item->node_id, node_id, ETH_ALEN);
		item->saddr = local_addr->addr;
		item->daddr = addr;
		item->sent = 0;
		item->rcv = 0;
		item->bw = 0;
		item->path_id = (static_path_id > 250) ? 1 : ++static_path_id;
		INIT_LIST_HEAD(&item->list);
		list_add(&(item->list), &pi_head);
	}

	return 1;
}

unsigned char find_fastest_path_id(unsigned char *node_id, __be32 *saddr, __be32 *daddr)
{
	struct path_info_table *path;
	struct path_info_table *f_path;
	unsigned char f_path_id = 0;
	unsigned char f_bw = -1;
	list_for_each_entry(path, &pi_head, list)
	{
		if (strcmp(path->node_id, node_id) != 0)
			continue;

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
		*saddr = f_path->saddr;
		*daddr = f_path->daddr;
	}
	return f_path_id;
}


unsigned char find_earliest_stat_path_id(unsigned char *dest_node_id, u16 *packet_count)
{
	struct path_stat_table *path_stat;
	struct path_stat_table *e_path_stat;
	unsigned char e_path_stat_id = 0;
	unsigned long e_fbtime = jiffies;
	list_for_each_entry(path_stat, &ps_head, list)
	{
		if (strcmp(path_stat->node_id, dest_node_id) != 0)
			continue;


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

unsigned char find_sender_socket(__be32 saddr, __be16 sport,
								 __be32 daddr, __be16 dport)
{
	struct sender_socket_table *sender_socket;

	list_for_each_entry(sender_socket, &ss_head, list)
	{
		if ((sender_socket->saddr == saddr) &&
			(sender_socket->sport == sport) &&
			(sender_socket->daddr == daddr) &&
			(sender_socket->dport == dport))
		{
			return sender_socket->session_id;
		}
	}

	return 0;
}

int add_sender_socket(__be32 saddr, __be16 sport,
					  __be32 daddr, __be16 dport)
{
	struct sender_socket_table *item = NULL;

	if (find_sender_socket(saddr, sport, daddr, dport) > 0)
		return 0;

	item = kzalloc(sizeof(struct sender_socket_table),	GFP_ATOMIC);

	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->session_id = (static_session_id > 250) ? 1 : ++static_session_id;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &ss_head);

	return 1;
}


__be32 find_local_addr(__be32 addr)
{
	struct local_addr_table *local_addr;

	list_for_each_entry(local_addr, &la_head, list)
	{
		if (local_addr->addr == addr)
		{
			return local_addr->addr;
		}
	}

	return 0;
}

//get the available ip addresses list locally that can be used to send out
//Internet packets
void get_available_local_addr(void)
{
	struct net_device *dev;
	struct local_addr_table *item = NULL;

	for_each_netdev(&init_net, dev)
	{
		//printk("dev = %s\n", dev->name);
		if (strstr(dev->name, "lo"))
			continue;

		if (dev->ip_ptr && dev->ip_ptr->ifa_list)
		{
			if (find_local_addr(dev->ip_ptr->ifa_list->ifa_address))
				continue;

			item = kzalloc(sizeof(struct local_addr_table),	GFP_ATOMIC);
			item->addr = dev->ip_ptr->ifa_list->ifa_address;
			INIT_LIST_HEAD(&item->list);
			list_add(&(item->list), &wi_head);
			//printk("my ip: %s\n", in_ntoa(dev->ip_ptr->ifa_list->ifa_address));
		}
	}
}
