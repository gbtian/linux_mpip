#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/tcp.h>
#include <linux/ip_mpip.h>


static unsigned char static_session_id = 1;
static unsigned char static_path_id = 1;
static unsigned long earliest_fbjiffies = 0;

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

struct path_stat_table *find_path_stat_by_addr(__be32 saddr, __be32 daddr)
{
	struct path_stat_table *path_stat;

	list_for_each_entry(path_stat, &ps_head, list)
	{
		if ((path_stat->saddr == saddr) &&
			(path_stat->daddr == daddr))
		{
			return path_stat;
		}
	}
	return NULL;
}

void send_mpip_hb(struct sk_buff *skb)
{
	if (!skb)
		return;
	
	if ((jiffies - earliest_fbjiffies) / HZ >= sysctl_mpip_hb)
	{
		icmp_send_mpip_hb(skb);
	}
	
	earliest_fbjiffies = jiffies;
}

int update_path_stat_delay(__be32 saddr, __be32 daddr, u32 delay)
{
/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct path_stat_table *path_stat;
    struct timespec tv;
	u32  midtime;

	path_stat = find_path_stat_by_addr(saddr, daddr);
	if (path_stat)
	{
		getnstimeofday(&tv);
		midtime = (tv.tv_sec % 86400) * MSEC_PER_SEC * 100  + 100 * tv.tv_nsec / NSEC_PER_MSEC;

		path_stat->delay = midtime - delay;
	}


	return 1;
}


int update_path_delay(unsigned char path_id, __s32 delay)
{
    struct path_info_table *path_info;
	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->path_id == path_id)
		{
			path_info->delay = (99 * path_info->delay + delay) / 100;
			if (path_info->min_delay > path_info->delay || path_info->min_delay == 0)
			{
				path_info->min_delay = path_info->delay;
			}

			path_info->delay_diff = path_info->delay - path_info->min_delay;
			if (path_info->delay_diff > path_info->max_delay_diff)
			{
				path_info->max_delay_diff = path_info->delay_diff;
			}

			break;
		}
	}

	return 1;
}

__s32 calc_diff(__s32 delay_diff, __s32 min_delay_diff)
{
	__s32 diff = delay_diff - min_delay_diff;
	return diff / sysctl_mpip_bw_factor;
}

int update_path_info()
{
	struct path_info_table *path_info, *min_path = NULL, *max_path = NULL;
	__s32 min_delay_diff = -1;
	__s32 max_delay_diff = 0;

	__s32 min_max_delay_diff = -1;
	__s32 max_max_delay_diff = 0;

	__u64 max_bw = 0;


	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->delay_diff < min_delay_diff || min_delay_diff == -1)
		{
			min_delay_diff = path_info->delay_diff;
		}
	}

	if (min_delay_diff == -1)
		return 0;

	list_for_each_entry(path_info, &pi_head, list)
	{
		__s32 diff = calc_diff(path_info->delay_diff, min_delay_diff);

		path_info->bw += min_delay_diff / (diff + 1);

		if (path_info->bw > max_bw)
			max_bw = path_info->bw;

	}


	if (max_bw > 5000)
	{
		__u64 times = max_bw / 5000;
		list_for_each_entry(path_info, &pi_head, list)
		{
			path_info->bw /= times;
			if (path_info->bw <= 0)
				path_info->bw = 10;
		}
	}

	return 1;
}


struct path_stat_table *find_path_stat(unsigned char *node_id, unsigned char path_id)
{
	struct path_stat_table *path_stat;

	if (!node_id || (path_id == 0))
		return NULL;

	list_for_each_entry(path_stat, &ps_head, list)
	{
		if (is_equal_node_id(node_id, path_stat->node_id) &&
			(path_stat->path_id == path_id))
		{
			return path_stat;
		}
	}

	return NULL;
}

int add_path_stat(unsigned char *node_id, unsigned char path_id, __be32 saddr, __be32 daddr)
{
	struct path_stat_table *item = NULL;

	if (!node_id || (path_id == 0))
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	if (find_path_stat(node_id, path_id))
		return 0;


	item = kzalloc(sizeof(struct path_stat_table),	GFP_ATOMIC);


	memcpy(item->node_id, node_id, MPIP_OPT_NODE_ID_LEN);
	item->path_id = path_id;
	item->saddr = saddr;
	item->daddr = daddr;
	item->delay = 0;
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

	INIT_LIST_HEAD(&(item->tcp_buf));
	item->next_seq = 0;
	item->buf_count = 0;

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

unsigned char get_receiver_session_id(unsigned char *src_node_id, unsigned char *dst_node_id,
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

	INIT_LIST_HEAD(&(item->tcp_buf));
	item->next_seq = 0;
	item->buf_count = 0;

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

int get_receiver_session_info(unsigned char *node_id,	unsigned char session_id,
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

int add_to_tcp_skb_buf(struct sk_buff *skb, unsigned char session_id)
{
	struct tcphdr *tcph = NULL;
	struct socket_session_table *socket_session;
	struct tcp_skb_buf *item = NULL;
	struct tcp_skb_buf *tcp_buf = NULL;
	struct tcp_skb_buf *tmp_buf = NULL;

	list_for_each_entry(socket_session, &ss_head, list)
	{
		if (socket_session->session_id == session_id)
		{
			tcph = tcp_hdr(skb);
			if (!tcph)
			{
				mpip_log("%s, %d\n", __FILE__, __LINE__);
				goto fail;
			}

			if ((ntohl(tcph->seq) < socket_session->next_seq) &&
				(socket_session->next_seq) - ntohl(tcph->seq) < 0xFFFFFFF)
			{
				mpip_log("late: %u, %u, %s, %d\n", ntohl(tcph->seq), socket_session->next_seq, __FILE__, __LINE__);
				dst_input(skb);
				goto success;
			}

			if ((socket_session->next_seq == 0) ||
				(ntohl(tcph->seq) == socket_session->next_seq) ||
				(ntohl(tcph->seq) == socket_session->next_seq + 1)) //for three-way handshake
			{
				socket_session->next_seq = skb->len - ip_hdr(skb)->ihl * 4 - tcph->doff * 4 + ntohl(tcph->seq);
				mpip_log("send: %u, %u, %s, %d\n", ntohl(tcph->seq), socket_session->next_seq, __FILE__, __LINE__);
				dst_input(skb);

recursive:
				list_for_each_entry_safe(tcp_buf, tmp_buf, &(socket_session->tcp_buf), list)
				{
					if (tcp_buf->seq == socket_session->next_seq)
					{
						socket_session->next_seq = tcp_buf->skb->len - ip_hdr(tcp_buf->skb)->ihl * 4 -
																	   tcp_hdr(tcp_buf->skb)->doff * 4 + tcp_buf->seq;
						mpip_log("push: %u, %u, %s, %d\n", tcp_buf->seq, socket_session->next_seq, __FILE__, __LINE__);

						dst_input(tcp_buf->skb);

						list_del(&(tcp_buf->list));
						kfree(tcp_buf);

						socket_session->buf_count -= 1;

						goto recursive;
					}
				}
				goto success;
			}


			item = kzalloc(sizeof(struct tcp_skb_buf),	GFP_ATOMIC);
			if (!item)
				goto fail;

			item->seq = ntohl(tcph->seq);
			item->skb = skb;
			item->fbjiffies = jiffies;
			INIT_LIST_HEAD(&(item->list));
			list_add(&(item->list), &(socket_session->tcp_buf));
			socket_session->buf_count += 1;

			mpip_log("out of order: %u, %u, %s, %d\n", ntohl(tcph->seq), socket_session->next_seq, __FILE__, __LINE__);

			goto success;
		}
	}


success:
	return 1;
fail:
	mpip_log("Fail: %s, %d\n", __FILE__, __LINE__);
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

unsigned char find_path_id(__be32 saddr, __be32 daddr)
{
	struct path_info_table *path_info;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if ((path_info->saddr == saddr) &&
			(path_info->daddr == daddr))
		{
			return path_info->path_id;
		}
	}
	return 0;
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
//	__be32 waddr = convert_addr(192, 168, 2, 20);
//	__be32 eaddr = convert_addr(192, 168, 2, 21);

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
		item->fbjiffies = jiffies;
		item->saddr = local_addr->addr;
		item->daddr = addr;
		item->min_delay = 0;
		item->delay = 0;
		item->delay_diff = 0;
		item->max_delay_diff = 0;
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
								   __be32 origin_saddr, __be32 origin_daddr)
{
	struct path_info_table *path;
	struct path_info_table *f_path;
	unsigned char f_path_id = 0;

	__u64 totalbw = 0, tmptotal = 0, f_bw = 0;
	int random = 0;
	bool path_done = true;

	if (!node_id)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	//if comes here, it means all paths have been probed
	list_for_each_entry(path, &pi_head, list)
	{
		if (!is_equal_node_id(path->node_id, node_id))
			continue;

// for depreciated path
//		if ((jiffies - path->fbjiffies) / HZ >= sysctl_mpip_hb * 5)
//			continue;

		totalbw += path->bw;

		if (path->bw > f_bw)
		{
			f_bw = path->bw;
			f_path_id = path->path_id;
			f_path = path;
		}

		if (path->delay == 0)
			path_done = false;
	}

	if ((totalbw > 0) || !path_done)
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
		*saddr = f_path->saddr;
		*daddr = f_path->daddr;
	}
	else
	{
		f_path = find_path_info(origin_saddr, origin_daddr);
		if (f_path)
		{
			*saddr = f_path->saddr;
			*daddr = f_path->daddr;
			f_path_id = f_path->path_id;
		}
	}

	return f_path_id;
}


unsigned char find_earliest_stat_path_id(unsigned char *dest_node_id, __s32 *delay)
{
	struct path_stat_table *path_stat;
	struct path_stat_table *e_path_stat;
	unsigned char e_path_stat_id = 0;
	unsigned long e_fbtime = jiffies;
//	int totalrcv = 0;
//	int max_rcvc = 0;

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
		earliest_fbjiffies = jiffies;

		*delay = e_path_stat->delay;

		//e_path_stat->delay = 0;

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
	}

	printk("******************ps*************\n");
	list_for_each_entry(path_stat, &ps_head, list)
	{
		printk( "%02x-%02x  ",
				path_stat->node_id[0], path_stat->node_id[1]);

		printk("%d  ", path_stat->path_id);
		printk("%d  ", path_stat->delay);
		printk("%lu\n", path_stat->fbjiffies);
	}


	printk("******************la*************\n");
	list_for_each_entry(local_addr, &la_head, list)
	{

		p = (char *) &(local_addr->addr);
		printk( "%d.%d.%d.%d\n",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

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

		printk("%d  ", path_info->min_delay);

		printk("%d  ", path_info->delay);

		printk("%d  ", path_info->max_delay_diff);

		printk("%d  ", path_info->delay_diff);

		printk("%u  \n", path_info->bw);

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
