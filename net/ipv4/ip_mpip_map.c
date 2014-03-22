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

int global_stat_1 = 0;
int global_stat_2 = 0;
int global_stat_3 = 0;


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

void print_node_id(const char *prefix, unsigned char *node_id)
{
	if (!node_id)
		return;

	prefix = NULL;
	if (prefix)
	{
		mpip_log("%s: %02x-%02x\n", prefix,
					node_id[0], node_id[1]);
	}
	else
	{
		mpip_log( "%02x-%02x\n",
				node_id[0], node_id[1]);
	}
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

void print_addr(const char *prefix, __be32 addr)
{
	char *p = (char *) &addr;
	prefix = NULL;
	if (prefix)
	{
		mpip_log("%s: %d.%d.%d.%d\n", prefix,
					(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));
	}
	else
	{
		mpip_log( "%d.%d.%d.%d\n",
			(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));
	}
}


__be32 convert_addr(char a1, char a2, char a3, char a4)
{
	__be32 addr;
	char *p = (char *) &addr;
	p[0] = a1;
	p[1] = a2;
	p[2] = a3;
	p[3] = a4;

	return (__be32)addr;
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


	if (!node_id)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	if (find_working_ip(node_id, addr))
		return 0;


	item = kzalloc(sizeof(struct working_ip_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, MPIP_OPT_NODE_ID_LEN);
	item->addr = addr;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &wi_head);

	mpip_log( "wi:");

	print_node_id(__FUNCTION__, node_id);
	print_addr(__FUNCTION__, addr);


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

int update_sender_packet_rcv(unsigned char *node_id, unsigned char path_id, u16 pkt_len)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct path_stat_table *path_stat;
	struct path_stat_table *tmp_stat;

	if (!node_id || (path_id == 0))
		return 0;

	printk("%d, %s, %d\n", pkt_len, __FILE__, __LINE__);

	list_for_each_entry_safe(path_stat, tmp_stat, &ps_head, list)
	{
		if (is_equal_node_id(node_id, path_stat->node_id) &&
			(path_stat->path_id == path_id))
		{
			path_stat->rcvc += 1;
			path_stat->rcv += pkt_len>>3;

			if (path_stat->rcv >= 60000)
			{
				path_stat->rcvh += (path_stat->rcv / 60000);
				path_stat->rcv = (path_stat->rcv % 60000);
			}

			break;
		}
	}

	return 1;
}

int update_packet_rcv(unsigned char path_id, unsigned char rcvh, u16 rcv)
{
	struct path_info_table *path_info = NULL;
	struct path_info_table *tmp_info = NULL;
	int sec = 1;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->path_id == path_id)
		{
			mpip_log("%d, %d, %d, %d, %s, %d\n", path_info->rcvh, path_info->rcv, rcvh, rcv, __FILE__, __LINE__);
			path_info->rcvh += (rcvh + (path_info->rcv + rcv) / 60000);
			path_info->rcv = (path_info->rcv + rcv) % 60000;
			mpip_log("%d, %d, %d, %d, %s, %d\n", path_info->rcvh, path_info->rcv, rcvh, rcv, __FILE__, __LINE__);

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
	struct path_info_table *tmp_info = NULL;
	__u64 rcv = 0;
	__u64 sent = 0;
	int rcvrate = 0;

//	__be32 eaddr = convert_addr(192, 168, 2, 23);
//	__be32 eaddr1 = convert_addr(192, 168, 2, 21);
//
//	__be32 waddr = convert_addr(192, 168, 2, 22);
//	__be32 waddr1 = convert_addr(192, 168, 2, 20);
//
//
//	list_for_each_entry_safe(path_info, tmp_info, &pi_head, list)
//	{
//		if ((path_info->saddr == eaddr) && (path_info->daddr == eaddr1) ||
//			(path_info->saddr == eaddr1) && (path_info->daddr == eaddr))
//		{
//			path_info->bw = sysctl_mpip_bw_1;
//		}
//		else if ((path_info->saddr == waddr) && (path_info->daddr == waddr1) ||
//				 (path_info->saddr == waddr1) && (path_info->daddr == waddr))
//		{
//			path_info->bw = sysctl_mpip_bw_3;
//		}
//		else
//		{
//			path_info->bw = sysctl_mpip_bw_2;
//		}
//	}
//
//	return 1;

	list_for_each_entry(path_info, &pi_head, list)
	{
		rcv = path_info->rcvh * 60000 + path_info->rcv;
		sent = path_info->senth * 60000 + path_info->sent;
		if (sent <= 0)
			continue;
		rcvrate = (unsigned char)(rcv * 100 / sent);
		if (path_info->rcvrate > rcvrate)
		{
			path_info->bw -= 1;
		}
		path_info->rcvrate = rcvrate;
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

	if (!node_id || (path_id == 0))
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	if (find_path_stat(node_id, path_id) > 0)
		return 0;


	item = kzalloc(sizeof(struct path_stat_table),	GFP_ATOMIC);


	memcpy(item->node_id, node_id, MPIP_OPT_NODE_ID_LEN);
	item->path_id = path_id;
//	atomic_set(&(item->rcv), 0);
	item->rcvc = 0;
	item->rcvh = 0;
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

int add_sender_session(unsigned char *src_node_id, unsigned char *dst_node_id,
					   __be32 saddr, __be16 sport,
					   __be32 daddr, __be16 dport)
{
	struct socket_session_table *item = NULL;

	if (!is_lan_addr(saddr) || !is_lan_addr(daddr))
	{
		return 0;
	}

	if (!src_node_id || !dst_node_id)
		return 0;

	if ((src_node_id[0] == src_node_id[1]) || (dst_node_id[0] == dst_node_id[1]))
	{
		return 0;
	}

	if (get_sender_session(saddr, sport, daddr, dport) > 0)
		return 0;


	item = kzalloc(sizeof(struct socket_session_table),	GFP_ATOMIC);

	memcpy(item->src_node_id, src_node_id, MPIP_OPT_NODE_ID_LEN);
	memcpy(item->dst_node_id, dst_node_id, MPIP_OPT_NODE_ID_LEN);
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
		if (is_equal_node_id(socket_session->dst_node_id, node_id) &&
			(socket_session->session_id == session_id))
		{
			return socket_session->session_id;
		}
	}

	return 0;
}

unsigned char add_receiver_session(unsigned char *src_node_id, unsigned char *dst_node_id,
						__be32 saddr, __be16 sport,
		 	 	 	 	__be32 daddr, __be16 dport,
		 	 	 	 	unsigned char session_id)
{
	struct socket_session_table *item = NULL;
	int sid;


	if (!src_node_id || !dst_node_id || !session_id)
		return 0;

	if ((src_node_id[0] == src_node_id[1]) || (dst_node_id[0] == dst_node_id[1]))
	{
		return 0;
	}

	static_session_id = (static_session_id > session_id) ? static_session_id : session_id;

	sid = find_receiver_session(dst_node_id, session_id);
	if (sid > 0)
		return sid;

	sid = get_sender_session(saddr, sport, daddr, dport);
	if (sid > 0)
		return sid;


	item = kzalloc(sizeof(struct socket_session_table), GFP_ATOMIC);

	memcpy(item->src_node_id, src_node_id, MPIP_OPT_NODE_ID_LEN);
	memcpy(item->dst_node_id, dst_node_id, MPIP_OPT_NODE_ID_LEN);
	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->session_id = session_id;
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

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	list_for_each_entry(socket_session, &ss_head, list)
	{
		if (is_equal_node_id(socket_session->dst_node_id, node_id) &&
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
	__be32 waddr = convert_addr(192, 168, 2, 20);
	__be32 eaddr = convert_addr(192, 168, 2, 21);

	if (!node_id)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	if (is_dest_added(node_id, addr))
		return 0;


	list_for_each_entry(local_addr, &la_head, list)
	{

		item = kzalloc(sizeof(struct path_info_table),	GFP_ATOMIC);

		memcpy(item->node_id, node_id, MPIP_OPT_NODE_ID_LEN);
		item->saddr = local_addr->addr;
		item->daddr = addr;
		item->ts = jiffies;
		item->sentc = 0;
		item->senth = 0;
		item->sent = 0;
		item->rcvh = 0;
		item->rcv = 0;
		item->rcvrate = 100;

//		if (item->saddr == waddr)
//		{
//			item->bw = sysctl_mpip_bw_1;
//		}
//		else if (item->saddr == eaddr)
//		{
//			item->bw = sysctl_mpip_bw_2;
//		}
//		else
//		{
//			item->bw = 30;
//		}
		item->bw = 1000;
		item->path_id = (static_path_id > 250) ? 1 : ++static_path_id;
		INIT_LIST_HEAD(&(item->list));
		list_add(&(item->list), &pi_head);

		mpip_log( "pi: %d\n", item->path_id);

		print_node_id(__FUNCTION__, node_id);
		print_addr(__FUNCTION__, addr);
	}

	return 1;
}

unsigned char find_fastest_path_id(unsigned char *node_id,
								   __be32 *saddr, __be32 *daddr,
								   __be32 origin_saddr, __be32 origin_daddr,
								   u16 pkt_len)
{
	struct path_info_table *path;
	struct path_info_table *f_path;
	unsigned char f_path_id = 0;
	unsigned char f_bw = 0;
	int totalbw = 0, tmptotal = 0;
	int random = 0;

	if (!node_id)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

//	//step 1: probing paths with bw 0
//	list_for_each_entry(path, &pi_head, list)
//	{
//		if (!is_equal_node_id(path->node_id, node_id))
//			continue;
//
//		if (path->bw == 0)
//		{
//			f_path_id = path->path_id;
//			f_path = path;
//		}
//	}
//
//	if (f_path_id > 0)
//	{
//		if (f_path->sent == 0)
//		{
//			f_path->ts = jiffies;
//		}
//		f_path->sentc += 1;
//		f_path->sent += pkt_len>>3;
//		*saddr = f_path->saddr;
//		*daddr = f_path->daddr;
//
//		return f_path_id;
//	}
//
	printk("%d, %s, %d\n", pkt_len, __FILE__, __LINE__);

	//if comes here, it means all paths have been probed
	list_for_each_entry(path, &pi_head, list)
	{
		if (!is_equal_node_id(path->node_id, node_id))
			continue;

		totalbw += path->bw;

		if (path->bw > f_bw)
		{
			f_path_id = path->path_id;
			f_bw = path->bw;
			f_path = path;
		}
	}

	if (totalbw > 0)
	{
		random = get_random_int() % totalbw;
		random = (random > 0) ? random : -random;
		tmptotal = 0;

		list_for_each_entry(path, &pi_head, list)
		{
			if (!is_equal_node_id(path->node_id, node_id))
				continue;

			if (random < (path->bw + tmptotal))
			{
				f_path_id = path->path_id;
				f_path = path;

				break;
			}
			else
			{
				tmptotal += path->bw;
			}
		}
	}

	if (f_path_id > 0)
	{
		if (f_path->sent == 0)
		{
			f_path->ts = jiffies;
		}
		f_path->sentc += 1;
		f_path->sent += pkt_len>>3;
		*saddr = f_path->saddr;
		*daddr = f_path->daddr;

		if (f_path->sent >= 60000)
		{
			mpip_log("%d, %d, %s, %d\n", f_path->senth, f_path->sent, __FILE__, __LINE__);
			f_path->senth += (f_path->sent / 60000);
			f_path->sent = (f_path->sent % 60000);
			mpip_log("%d, %d, %s, %d\n", f_path->senth, f_path->sent, __FILE__, __LINE__);
		}
	}
	else
	{
		f_path = find_path_info(origin_saddr, origin_daddr);
		if (f_path)
		{
			if (f_path->sent == 0)
			{
				f_path->ts = jiffies;
			}

			f_path->sentc += 1;
			f_path->sent += pkt_len>>3;
			*saddr = f_path->saddr;
			*daddr = f_path->daddr;
			f_path_id = f_path->path_id;

			if (f_path->sent >= 60000)
			{
				mpip_log("%d, %d, %s, %d\n", f_path->senth, f_path->sent, __FILE__, __LINE__);
				f_path->senth += (f_path->sent / 60000);
				f_path->sent = (f_path->sent % 60000);
				mpip_log("%d, %d, %s, %d\n", f_path->senth, f_path->sent, __FILE__, __LINE__);
			}
		}
	}

//	printk("%d, %d, %d, %s, %d\n", pkt_len, f_path->senth, f_path->sent, __FILE__, __LINE__);
	return f_path_id;
}


unsigned char find_earliest_stat_path_id(unsigned char *dest_node_id, unsigned char *rcvh, u16 *rcv)
{
	struct path_stat_table *path_stat;
	struct path_stat_table *e_path_stat;
	unsigned char e_path_stat_id = 0;
	unsigned long e_fbtime = jiffies;
	int totalrcv = 0;
	int max_rcvc = 0;

	if (!dest_node_id)
		return 0;


	list_for_each_entry(path_stat, &ps_head, list)
	{
		if (!is_equal_node_id(path_stat->node_id, dest_node_id))
		{
			continue;
		}

		if (path_stat->fbjiffies <= e_fbtime)
		{
			e_path_stat_id = path_stat->path_id;
			e_path_stat = path_stat;
			e_fbtime = path_stat->fbjiffies;
		}
	}

	if (e_path_stat_id > 0)
	{
		e_path_stat->fbjiffies = jiffies;

		*rcvh = e_path_stat->rcvh;
		*rcv = e_path_stat->rcv;

		e_path_stat->rcvc = 0;
		e_path_stat->rcvh = 0;
		e_path_stat->rcv = 0;

	}

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
			print_addr(__FUNCTION__, dev->ip_ptr->ifa_list->ifa_address);
		}
	}

//	add_working_ip("1234", convert_addr(192,168,2,1));
//	add_path_info("1234", convert_addr(192,168,2,1));
//	add_path_stat("1234", 2);
}


struct net_device *find_dev_by_addr(__be32 addr)
{
	struct net_device *dev;

	for_each_netdev(&init_net, dev)
	{
		if (strstr(dev->name, "lo"))
			continue;

		if (dev->ip_ptr && dev->ip_ptr->ifa_list)
		{
			if (dev->ip_ptr->ifa_list->ifa_address == addr)
				return dev;
		}
	}
	return NULL;
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

	global_stat_1 = 0;
	global_stat_2 = 0;
	global_stat_3 = 0;

}


asmlinkage long sys_mpip(void)
{
	struct working_ip_table *working_ip;
	struct path_info_table *path_info;
	struct socket_session_table *socket_session;
	struct path_stat_table *path_stat;
	struct local_addr_table *local_addr;
	char *p;

	printk("******************wi*************\n");
	list_for_each_entry(working_ip, &wi_head, list)
	{
		printk( "%02x-%02x  ",
				working_ip->node_id[0], working_ip->node_id[1]);

		p = (char *) &(working_ip->addr);
		printk( "%d.%d.%d.%d\n",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		printk("+++++++++\n");
	}

	printk("******************ss*************\n");
	list_for_each_entry(socket_session, &ss_head, list)
	{
		printk( "%02x-%02x  ",
				socket_session->src_node_id[0], socket_session->src_node_id[1]);

		printk( "%02x-%02x  ",
						socket_session->dst_node_id[0], socket_session->dst_node_id[1]);

		printk("%d  ", socket_session->session_id);

		p = (char *) &(socket_session->saddr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		p = (char *) &(socket_session->daddr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		printk("%d\t", socket_session->sport);

		printk("%d\n", socket_session->dport);

		printk("+++++++++\n");
	}

	printk("******************ps*************\n");
	list_for_each_entry(path_stat, &ps_head, list)
	{
		printk( "%02x-%02x  ",
				path_stat->node_id[0], path_stat->node_id[1]);

		printk("%d  ", path_stat->path_id);
		printk("%d  ", path_stat->rcvh);
//		printk("%d  ", atomic_read(&(path_stat->rcv)));
		printk("%d  ", path_stat->rcv);
		printk("%lu\n", path_stat->fbjiffies);

		printk("+++++++++\n");
	}


	printk("******************la*************\n");
	list_for_each_entry(local_addr, &la_head, list)
	{

		p = (char *) &(local_addr->addr);
		printk( "%d.%d.%d.%d\n",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		printk("+++++++++\n");
	}


	printk("******************pi*************\n");
	list_for_each_entry(path_info, &pi_head, list)
	{
		printk( "%02x-%02x  ",
				path_info->node_id[0], path_info->node_id[1]);

		printk("%d  ", path_info->path_id);

		p = (char *) &(path_info->saddr);

		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		p = (char *) &(path_info->daddr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		printk("%d  ", path_info->rcvrate);

		printk("%d  ", path_info->bw);

		printk("%d  ", path_info->sentc);

		printk("%d  ", path_info->senth);

		printk("%d  ", path_info->sent);

		printk("%d  ", path_info->rcvh);

		printk("%d\n", path_info->rcv);

		printk("+++++++++\n");
	}


	printk("******************global stat*************\n");
	printk("%d  %d  %d\n", global_stat_1, global_stat_2, global_stat_3);


	return 0;

}

asmlinkage long sys_reset_mpip(void)
{
	reset_mpip();
	printk("reset ended\n");
	return 0;

}
