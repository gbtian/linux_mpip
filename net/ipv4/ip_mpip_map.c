#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/ip_mpip.h>

static unsigned char static_session_id = 1;
static unsigned char static_path_id = 1;

static LIST_HEAD(wi_head);
static LIST_HEAD(pi_head);
static LIST_HEAD(ss_head);
static LIST_HEAD(la_head);
static LIST_HEAD(ps_head);

bool is_equal_node_id(unsigned char *node_id_1, unsigned char *node_id_2)
{
	int i;

	if (!node_id_1 || !node_id_2)
		return false;

	for(i = 0; i < MPIP_OPT_NODE_ID_LEN; i++)
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

	mpip_log( "%02x-%02x-%02x\n",
			node_id[0], node_id[1], node_id[2]);
}

bool is_lan_addr(__be32 addr)
{
	char *p = (char *) &addr;

	if ((p[0] & 255) == 192 &&
		(p[1] & 255) == 168)
	{
		return true;
	}
	return false;
}

void print_addr(__be32 addr)
{
	char *p = (char *) &addr;
	mpip_log( "%d.%d.%d.%d\n",
		(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));
}

char *in_ntoa(unsigned long in)
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
	int i;

	if (!node_id)
		return 0;

	if ((node_id[0] == node_id[1]) &&
		(node_id[1] == node_id[2]))
	{
		return 0;
	}

	if (find_working_ip(node_id, addr))
		return 0;


	item = kzalloc(sizeof(struct working_ip_table),	GFP_ATOMIC);

	for(i = 0; i < MPIP_OPT_NODE_ID_LEN; ++i)
		item->node_id[i] = node_id[i];

	//memcpy(item->node_id, node_id, MPIP_OPT_NODE_ID_LEN);
	item->addr = addr;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &wi_head);

	mpip_log( "wi:");

	print_node_id(node_id);
	print_addr(addr);


	return 1;
}

int del_working_ip(unsigned char *node_id, __be32 addr)
{
	/* todo: need locks */
	struct working_ip_table *working_ip;
	struct working_ip_table *tmp_ip;


	list_for_each_entry_safe(working_ip, tmp_ip, &wi_head, list)
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
		return NULL;

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

int update_sender_packet_rcv(unsigned char *node_id, unsigned char path_id)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct path_stat_table *path_stat;
	struct path_stat_table *tmp_stat;

	if (!node_id || (path_id == 0))
		return 0;

	list_for_each_entry_safe(path_stat, tmp_stat, &ps_head, list)
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
	struct path_info_table *tmp_info;

	list_for_each_entry_safe(path_info, tmp_info, &pi_head, list)
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
	struct path_info_table *tmp_info;

	list_for_each_entry_safe(path_info, tmp_info, &pi_head, list)
	{
		if ((path_info->rcv == 1) && (path_info->sent >= 60000))
			path_info->sent = 1;

		if (path_info->sent > 0)
		{
			path_info->bw = (unsigned char)((path_info->rcv * 100) / path_info->sent);
		}

		//mpip_log("update_path_info: %d, %d, %d, %d\n",path_info->path_id,
		//		path_info->sent, path_info->rcv, path_info->bw);

		//print_addr(path_info->saddr);
		//print_addr(path_info->daddr);
	}

	return 1;
}


unsigned char find_path_stat(unsigned char *node_id, unsigned char path_id)
{
	struct path_stat_table *path_stat;

	if (!node_id || (path_id == 0))
		return 0;

	list_for_each_entry(path_stat, &ps_head, list)
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
	int i;

	if (!node_id || (path_id == 0))
		return 0;

	if ((node_id[0] == node_id[1]) &&
		(node_id[1] == node_id[2]))
	{
		return 0;
	}

	if (find_path_stat(node_id, path_id) > 0)
		return 0;


	item = kzalloc(sizeof(struct path_stat_table),	GFP_ATOMIC);

	for(i = 0; i < MPIP_OPT_NODE_ID_LEN; ++i)
		item->node_id[i] = node_id[i];

	//memcpy(item->node_id, node_id, MPIP_OPT_NODE_ID_LEN);
	item->path_id = path_id;
	item->rcv = 0;
	item->fbjiffies = jiffies;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &ps_head);

	//mpip_log( "ps: %d", path_id);
	//print_node_id(node_id);

	return 1;
}


unsigned char get_sender_session(__be32 saddr, __be16 sport,
								 __be32 daddr, __be16 dport)
{
	struct socket_session_table *socket_session;

	list_for_each_entry(socket_session, &ss_head, list)
	{
		if ((socket_session->saddr == saddr) &&
			(socket_session->sport == sport) &&
			(socket_session->daddr == daddr) &&
			(socket_session->dport == dport))
		{
			return socket_session->session_id;
		}
	}

	return 0;
}

int add_sender_session(unsigned char *dest_node_id, __be32 saddr, __be16 sport,
					  __be32 daddr, __be16 dport)
{
	struct socket_session_table *item = NULL;
	int i;

	if (!is_lan_addr(daddr))
	{
		return 0;
	}

	if (!dest_node_id)
		return 0;

	if ((dest_node_id[0] == dest_node_id[1]) &&
		(dest_node_id[1] == dest_node_id[2]))
	{
		return 0;
	}

	if (get_sender_session(saddr, sport, daddr, dport) > 0)
		return 0;


	item = kzalloc(sizeof(struct socket_session_table),	GFP_ATOMIC);

	for(i = 0; i < MPIP_OPT_NODE_ID_LEN; ++i)
		item->node_id[i] = dest_node_id[i];

	//memcpy(item->node_id, dest_node_id, MPIP_OPT_NODE_ID_LEN);
	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->session_id = (static_session_id > 250) ? 1 : ++static_session_id;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &ss_head);

	//mpip_log( "ss: %d,%d,%d\n", item->session_id,
	//		sport, dport);

	//print_addr(saddr);
	//print_addr(daddr);

	return 1;
}



unsigned char find_receiver_session(unsigned char *node_id, unsigned char session_id)
{
	struct socket_session_table *socket_session;

	if (!node_id)
		return 0;

	list_for_each_entry(socket_session, &ss_head, list)
	{
		if (is_equal_node_id(socket_session->node_id, node_id) &&
			(socket_session->session_id == session_id))
		{
			return socket_session->session_id;
		}
	}

	return 0;
}

unsigned char add_receiver_session(unsigned char *node_id,
						__be32 saddr, __be16 sport,
		 	 	 	 	__be32 daddr, __be16 dport,
		 	 	 	 	unsigned char session_id)
{
	struct socket_session_table *item = NULL;
	int i, sid;


	if (!node_id)
		return 0;

	if ((node_id[0] == node_id[1]) &&
		(node_id[1] == node_id[2]))
	{
		return 0;
	}
	//sid = get_sender_session(saddr, sport, daddr, dport);
	sid = find_receiver_session(node_id, session_id)
	if (sid > 0)
		return sid;


	item = kzalloc(sizeof(struct socket_session_table), GFP_ATOMIC);

	for(i = 0; i < MPIP_OPT_NODE_ID_LEN; ++i)
		item->node_id[i] = node_id[i];

	//memcpy(item->node_id, node_id, MPIP_OPT_NODE_ID_LEN);
	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	if (session_id > 0)
	{
		item->session_id = session_id;
	}
	else
	{
		item->session_id = (static_session_id > 250) ? 1 : ++static_session_id;;
	}
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &ss_head);

//	mpip_log( "rs: %d,%d,%d\n", session_id,
//					sport, dport);
//
//	print_node_id(node_id);
//	print_addr(saddr);
//	print_addr(daddr);

	return item->session_id;
}

int get_receiver_session(unsigned char *node_id,	unsigned char session_id,
						__be32 *saddr, __be16 *sport,
						__be32 *daddr, __be16 *dport)
{
	struct socket_session_table *socket_session;

	if (!node_id || !session_id)
		return 0;

	if ((node_id[0] == node_id[1]) &&
		(node_id[1] == node_id[2]))
	{
		return 0;
	}

	list_for_each_entry(socket_session, &ss_head, list)
	{
		if (is_equal_node_id(socket_session->node_id, node_id) &&
				(socket_session->session_id == session_id))
		{
			*saddr = socket_session->saddr;
			*daddr = socket_session->daddr;
			*sport = socket_session->sport;
			*dport = socket_session->dport;

			return 1;
		}
	}

	return 0;
}


struct path_info_table *find_path_info(__be32 saddr, __be32 daddr)
{
	struct path_info_table *path_info;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if ((path_info->saddr == saddr) &&
			(path_info->daddr == daddr))
		{
			return path_info;
		}
	}
	return NULL;
}

bool is_dest_added(unsigned char *node_id, __be32 addr)
{
	struct path_info_table *path_info;

	if (!node_id)
		return 0;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (is_equal_node_id(path_info->node_id, node_id) &&
		   (path_info->daddr == addr))
		{
			return true;
		}
	}
	return false;
}

int add_path_info(unsigned char *node_id, __be32 addr)
{
	struct local_addr_table *local_addr;
	struct path_info_table *item = NULL;
	int i;

	if (!node_id)
		return 0;

	if ((node_id[0] == node_id[1]) &&
		(node_id[1] == node_id[2]))
	{
		return 0;
	}

	if (is_dest_added(node_id, addr))
		return 0;


	list_for_each_entry(local_addr, &la_head, list)
	{

		item = kzalloc(sizeof(struct path_info_table),	GFP_ATOMIC);

		for(i = 0; i < MPIP_OPT_NODE_ID_LEN; ++i)
			item->node_id[i] = node_id[i];

		//memcpy(item->node_id, node_id, MPIP_OPT_NODE_ID_LEN);
		item->saddr = local_addr->addr;
		item->daddr = addr;
		item->sent = 0;
		item->rcv = 0;
		item->bw = 100;
		item->path_id = (static_path_id > 250) ? 1 : ++static_path_id;
		INIT_LIST_HEAD(&(item->list));
		list_add(&(item->list), &pi_head);

		mpip_log( "pi: %d\n", item->path_id);

		print_node_id(node_id);
		print_addr(addr);
	}

	return 1;
}

unsigned char find_fastest_path_id(unsigned char *node_id,
								   __be32 *saddr, __be32 *daddr,
								   __be32 origin_saddr, __be32 origin_daddr,
								   int pkt_count)
{
	struct path_info_table *path;
	struct path_info_table *f_path;
	unsigned char f_path_id = 0;
	unsigned char f_bw = 0;

	if (!node_id)
		return 0;

	if ((node_id[0] == node_id[1]) &&
		(node_id[1] == node_id[2]))
	{
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
		f_path->sent += pkt_count;
		*saddr = f_path->saddr;
		*daddr = f_path->daddr;
	}
	else
	{
		f_path = find_path_info(origin_saddr, origin_daddr);
		if (f_path)
		{
			f_path->sent += pkt_count;
			*saddr = f_path->saddr;
			*daddr = f_path->daddr;
			f_path_id = f_path->path_id;
		}
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
		return 0;


	list_for_each_entry(path_stat, &ps_head, list)
	{
		if (!is_equal_node_id(path_stat->node_id, dest_node_id))
		{
			continue;
		}

		//mpip_log("id = %d, fb = %lu, eb = %lu\n", path_stat->path_id,
		//		path_stat->fbjiffies, e_fbtime);

		if (path_stat->fbjiffies <= e_fbtime)
		{
			e_path_stat_id = path_stat->path_id;
			//mpip_log("epathstatid = %d\n", e_path_stat_id);
			e_fbtime = path_stat->fbjiffies;
			e_path_stat = path_stat;
		}
	}

	if (e_path_stat_id > 0)
	{
		e_path_stat->fbjiffies = jiffies;
		*packet_count = e_path_stat->rcv;
	}

	//mpip_log("final epathstatid = %d\n", e_path_stat_id);
	return e_path_stat_id;
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
		if (strstr(dev->name, "lo"))
			continue;

		if (dev->ip_ptr && dev->ip_ptr->ifa_list)
		{
			if (find_local_addr(dev->ip_ptr->ifa_list->ifa_address))
				continue;

			item = kzalloc(sizeof(struct local_addr_table),	GFP_ATOMIC);
			item->addr = dev->ip_ptr->ifa_list->ifa_address;
			INIT_LIST_HEAD(&(item->list));
			list_add(&(item->list), &la_head);

			mpip_log( "local addr:");
			__be32 addr = dev->ip_ptr->ifa_list->ifa_address;
			print_addr(addr);
		}
	}
}



static void reset_mpip(void)
{
	struct working_ip_table *working_ip;
	struct working_ip_table *tmp_ip;

	struct path_info_table *path_info;
	struct path_info_table *tmp_info;

	struct socket_session_table *socket_session;
	struct socket_session_table *tmp_session;

	struct path_stat_table *path_stat;
	struct path_stat_table *tmp_stat;


	struct local_addr_table *local_addr;
	struct local_addr_table *tmp_addr;

	list_for_each_entry_safe(working_ip, tmp_ip, &wi_head, list)
	{
			list_del(&(working_ip->list));
			kfree(working_ip);
	}

	list_for_each_entry_safe(path_info, tmp_info, &pi_head, list)
	{
			list_del(&(path_info->list));
			kfree(path_info);
	}

	list_for_each_entry_safe(socket_session, tmp_session, &ss_head, list)
	{
			list_del(&(socket_session->list));
			kfree(socket_session);
	}

	list_for_each_entry_safe(path_stat, tmp_stat, &ps_head, list)
	{
			list_del(&(path_stat->list));
			kfree(path_stat);
	}

	list_for_each_entry_safe(local_addr, tmp_addr, &la_head, list)
	{
			list_del(&(local_addr->list));
			kfree(local_addr);
	}

	static_session_id = 1;
	static_path_id = 1;
}


asmlinkage long sys_mpip(void)
{
	struct working_ip_table *working_ip;
	struct path_info_table *path_info;
	struct socket_session_table *socket_session;
	struct path_stat_table *path_stat;
	struct local_addr_table *local_addr;
	char *p;

	mpip_log("******************wi*************\n");
	list_for_each_entry(working_ip, &wi_head, list)
	{
		mpip_log( "%02x-%02x-%02x  ",
				working_ip->node_id[0], working_ip->node_id[1], working_ip->node_id[2]);

		p = (char *) &(working_ip->addr);
		mpip_log( "%d.%d.%d.%d\n",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		mpip_log("+++++++++\n");
	}

	mpip_log("******************pi*************\n");
	list_for_each_entry(path_info, &pi_head, list)
	{
		mpip_log( "%02x-%02x-%02x  ",
				path_info->node_id[0], path_info->node_id[1], path_info->node_id[2]);

		mpip_log("%d  ", path_info->path_id);

		p = (char *) &(path_info->saddr);
		mpip_log( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		p = (char *) &(path_info->daddr);
		mpip_log( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		mpip_log("%d  ", path_info->bw);

		mpip_log("%d  ", path_info->sent);

		mpip_log("%d\n", path_info->rcv);

		mpip_log("+++++++++\n");
	}

	mpip_log("******************ss*************\n");
	list_for_each_entry(socket_session, &ss_head, list)
	{
		mpip_log( "%02x-%02x-%02x  ",
				socket_session->node_id[0], socket_session->node_id[1], socket_session->node_id[2]);

		mpip_log("%d  ", socket_session->session_id);

		p = (char *) &(socket_session->saddr);
		mpip_log( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		p = (char *) &(socket_session->daddr);
		mpip_log( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		mpip_log("%d\t", socket_session->sport);

		mpip_log("%d\n", socket_session->dport);

		mpip_log("+++++++++\n");
	}

	mpip_log("******************ps*************\n");
	list_for_each_entry(path_stat, &ps_head, list)
	{
		mpip_log( "%02x-%02x-%02x  ",
				path_stat->node_id[0], path_stat->node_id[1], path_stat->node_id[2]);

		mpip_log("%d  ", path_stat->path_id);
		mpip_log("%d  ", path_stat->rcv);
		mpip_log("%lu\n", path_stat->fbjiffies);

		mpip_log("+++++++++\n");
	}


	mpip_log("******************la*************\n");
	list_for_each_entry(local_addr, &la_head, list)
	{

		p = (char *) &(local_addr->addr);
		mpip_log( "%d.%d.%d.%d\n",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		mpip_log("+++++++++\n");
	}

	return 0;

}

asmlinkage long sys_reset_mpip(void)
{
	reset_mpip();
	mpip_log("reset ended\n");
	return 0;

}
