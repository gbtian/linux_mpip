#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/ip_mpip.h>

static unsigned char static_session_id = 1;
static unsigned char static_path_id = 1;

bool is_equal_node_id(unsigned char *node_id_1, unsigned char *node_id_2)
{
	int i;

	if (!node_id_1 || !node_id_2)
		return false;

	for(i = 0; i < ETH_ALEN; i++)
	{
		if (node_id_1[i] != node_id_2[i])
			return false;
	}

	return true;
}

void print_node_id(unsigned char *node_id)
{
	if (!node_id)
		return;

	printk(KERN_EMERG "%02x-%02x-%02x-%02x-%02x-%02x\n",
			node_id[0], node_id[1], node_id[2],
			node_id[3], node_id[4], node_id[5]);
}

void print_addr(__be32 addr)
{
	char *p = (char *) &addr;
	printk(KERN_EMERG "%d.%d.%d.%d\n",
		(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));
}

static char *in_ntoa(unsigned long in)
{
	char *buff = kzalloc(18, GFP_ATOMIC);
	char *p;

	p = (char *) &in;
	sprintf(buff, "%d.%d.%d.%d",
		(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

	return(buff);
}


int add_working_ip(unsigned char *node_id, __be32 addr)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct working_ip_table *item = NULL;

	if (!node_id)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		return 0;
	}

	if (find_working_ip(node_id, addr))
		return 0;


	item = kzalloc(sizeof(struct working_ip_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, ETH_ALEN);
	item->addr = addr;
	INIT_LIST_HEAD(&item->list);
	list_add(&(item->list), &wi_head);



	//printk(KERN_EMERG "wi: %s, %s\n", print_node_id(node_id), in_ntoa(addr));
	//printk(KERN_EMERG "wi:", node_id, addr);
	printk(KERN_EMERG "wi:");
	print_node_id(node_id);
	print_addr(addr);


	return 1;
}

int del_working_ip(unsigned char *node_id, __be32 addr)
{
	/* todo: need locks */
	struct working_ip_table *working_ip, *tmp;


	list_for_each_entry_safe(working_ip, tmp, &wi_head, list)
	{
		if (is_equal_node_id(node_id, working_ip->node_id) &&
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

	if (!node_id)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		return NULL;
	}

	list_for_each_entry(working_ip, &wi_head, list)
	{
		if (is_equal_node_id(node_id, working_ip->node_id) &&
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

int inc_sender_packet_rcv(unsigned char *node_id, unsigned char path_id)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct path_stat_table *path_stat;

	if (!node_id)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		return 0;
	}

	if (find_path_stat(node_id, path_id) == 0)
	{
		add_path_stat(node_id, path_id);
	}

	list_for_each_entry(path_stat, &ps_head, list)
	{
		if (is_equal_node_id(node_id, path_stat->node_id) &&
			(path_stat->path_id == path_id))
		{
			if (path_stat->rcv >= 60000)
				path_stat->rcv = 0;

			path_stat->rcv += 1;

			break;
		}
	}

	return 1;
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

int update_path_info()
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct path_info_table *path_info;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if ((path_info->rcv == 1) && (path_info->sent >= 60000))
			path_info->sent = 1;

		if (path_info->sent > 0)
		{
			path_info->bw = (unsigned char)((path_info->rcv * 100) / path_info->sent);
		}
	}

	return 1;
}


unsigned char find_path_stat(unsigned char *node_id, unsigned char path_id)
{
	struct path_stat_table *path_stat;

	if (!node_id)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		return 0;
	}

	list_for_each_entry(path_stat, &la_head, list)
	{
		if (is_equal_node_id(node_id, path_stat->node_id) &&
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

	if (!node_id)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		return 0;
	}

	if (find_path_stat(node_id, path_id) > 0)
		return 0;


	item = kzalloc(sizeof(struct path_stat_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, ETH_ALEN);
	item->path_id = path_id;
	item->rcv = 0;
	item->fbjiffies = jiffies;
	INIT_LIST_HEAD(&item->list);
	list_add(&(item->list), &ps_head);


	printk(KERN_EMERG "ps: %d", path_id);
	print_node_id(node_id);

	return 1;
}


unsigned char find_receiver_socket_by_socket(unsigned char *node_id,
											 __be32 saddr, __be16 sport,
											 __be32 daddr, __be16 dport)
{
	struct receiver_socket_table *receiver_socket;

	if (!node_id)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		return 0;
	}

	list_for_each_entry(receiver_socket, &rs_head, list)
	{
		if (is_equal_node_id(receiver_socket->node_id, node_id) &&
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

unsigned char find_receiver_socket_by_session(unsigned char *node_id, unsigned char session_id)
{
	struct receiver_socket_table *receiver_socket;

	if (!node_id)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		return 0;
	}

	list_for_each_entry(receiver_socket, &rs_head, list)
	{
		if (is_equal_node_id(receiver_socket->node_id, node_id) &&
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

	if (!node_id)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		return 0;
	}

	if (find_receiver_socket_by_session(node_id, session_id) > 0)
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

	printk(KERN_EMERG "rs: %d,%d,%d\n", session_id,
					sport, dport);

	print_node_id(node_id);
	print_addr(saddr);
	print_addr(daddr);

	return 1;
}

int get_receiver_socket(unsigned char *node_id,	unsigned char session_id,
						__be32 *saddr, __be16 *sport,
						__be32 *daddr, __be16 *dport)
{
	struct receiver_socket_table *receiver_socket;

	if (!node_id)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		return 0;
	}

	list_for_each_entry(receiver_socket, &rs_head, list)
	{
		if (is_equal_node_id(receiver_socket->node_id, node_id) &&
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

	if (!node_id)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		return 0;
	}

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (is_equal_node_id(path_info->node_id, node_id) &&
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

	if (!node_id)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		return 0;
	}

	if (find_path_info(node_id, addr))
		return 0;


	list_for_each_entry(local_addr, &la_head, list)
	{
		struct path_info_table *item = NULL;

		item = kzalloc(sizeof(struct path_info_table),	GFP_ATOMIC);

		memcpy(item->node_id, node_id, ETH_ALEN);
		item->saddr = local_addr->addr;
		item->daddr = addr;
		item->sent = 0;
		item->rcv = 0;
		item->bw = 100;
		item->path_id = (static_path_id > 250) ? 1 : ++static_path_id;
		INIT_LIST_HEAD(&item->list);
		list_add(&(item->list), &pi_head);
		printk(KERN_EMERG "pi: %d\n", item->path_id);

		print_node_id(node_id);
		print_addr(addr);
	}

	return 1;
}

unsigned char find_fastest_path_id(unsigned char *node_id, __be32 *saddr, __be32 *daddr)
{
	struct path_info_table *path;
	struct path_info_table *f_path;
	unsigned char f_path_id = 0;
	unsigned char f_bw = 0;

	if (!node_id)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		return 0;
	}

	list_for_each_entry(path, &pi_head, list)
	{
		if (!is_equal_node_id(path->node_id, node_id))
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

	if (!dest_node_id)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		return 0;
	}

	list_for_each_entry(path_stat, &ps_head, list)
	{
		if (!is_equal_node_id(path_stat->node_id, dest_node_id))
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

	printk(KERN_EMERG "ss: %d,%d,%d\n", item->session_id,
			sport, dport);

	print_addr(saddr);
	print_addr(daddr);

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
	//printk(KERN_EMERG "local addr_1:");

	for_each_netdev(&init_net, dev)
	{
		//printk("dev = %s\n", dev->name);
		//if (strstr(dev->name, "lo"))
		//	continue;

		if (dev->ip_ptr && dev->ip_ptr->ifa_list)
		{
			if (find_local_addr(dev->ip_ptr->ifa_list->ifa_address))
				continue;

			item = kzalloc(sizeof(struct local_addr_table),	GFP_ATOMIC);
			item->addr = dev->ip_ptr->ifa_list->ifa_address;
			INIT_LIST_HEAD(&item->list);
			list_add(&(item->list), &la_head);

			printk(KERN_EMERG "local addr:");
			__be32 addr = dev->ip_ptr->ifa_list->ifa_address;
			print_addr(addr);

			//printk("my ip: %s\n", in_ntoa(dev->ip_ptr->ifa_list->ifa_address));
		}
	}
}
