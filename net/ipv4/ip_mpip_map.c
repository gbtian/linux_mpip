#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/tcp.h>
#include <net/xfrm.h>
#include <net/icmp.h>
#include <linux/ip_mpip.h>


static unsigned char static_session_id = 1;
static unsigned char static_path_id = 1;
static unsigned long earliest_fbjiffies = 0;


static LIST_HEAD(mq_head);
static LIST_HEAD(me_head);
static LIST_HEAD(an_head);
static LIST_HEAD(wi_head);
static LIST_HEAD(pi_head);
static LIST_HEAD(ss_head);
static LIST_HEAD(la_head);
static LIST_HEAD(ps_head);

int global_stat_1;
int global_stat_2;
int global_stat_3;

bool is_equal_node_id(unsigned char *node_id_1, unsigned char *node_id_2)
{
	int i;

	if (!node_id_1 || !node_id_2)
		return false;

	for(i = 0; i < MPIP_CM_NODE_ID_LEN; i++)
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
	mpip_log( "%02x-%02x\n", node_id[0], node_id[1]);
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


void print_addr_1(__be32 addr)
{
	char *p = (char *) &addr;
	printk( "%d.%d.%d.%d\n",
			(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

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

struct mpip_query_table *find_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct mpip_query_table *mpip_query;

	list_for_each_entry(mpip_query, &mq_head, list)
	{
		if ((saddr == mpip_query->saddr) && (daddr == mpip_query->daddr) &&
			(sport == mpip_query->sport) && (dport == mpip_query->dport))
		{
			return mpip_query;
		}
	}

	return NULL;
}
int delete_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct mpip_query_table *mpip_query;
	struct mpip_query_table *tmp_query;
	list_for_each_entry_safe(mpip_query, tmp_query, &mq_head, list)
	{
		if ((saddr == mpip_query->saddr) && (daddr == mpip_query->daddr) &&
			(sport == mpip_query->sport) && (dport == mpip_query->dport))
		{
			mpip_log("%s, %d\n", __FILE__, __LINE__);
			list_del(&(mpip_query->list));
			kfree(mpip_query);

			return 1;
		}
	}

	return 0;
}

int add_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct mpip_query_table *item = find_mpip_query(saddr, daddr, sport, dport);

	if (item)
	{
		return 0;
	}

	item = kzalloc(sizeof(struct mpip_query_table),	GFP_ATOMIC);
	item->saddr = saddr;
	item->daddr = daddr;
	item->sport = sport;
	item->dport = dport;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &mq_head);

	mpip_log( "mq: %d, %d, %s, %s, %d\n", sport, dport, __FILE__, __FUNCTION__, __LINE__);
	print_addr(saddr);
	print_addr(saddr);

	return 1;
}

struct mpip_enabled_table *find_mpip_enabled(__be32 addr, __be16 port)
{
	struct mpip_enabled_table *mpip_enabled;

	list_for_each_entry(mpip_enabled, &me_head, list)
	{
		if ((addr == mpip_enabled->addr) && (port == mpip_enabled->port))
		{
			return mpip_enabled;
		}
	}

	return NULL;
}


int add_mpip_enabled(__be32 addr, __be16 port, bool enabled)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct mpip_enabled_table *item = find_mpip_enabled(addr, port);

	if (item)
	{
		item->mpip_enabled = enabled;
		return 0;
	}

	item = kzalloc(sizeof(struct mpip_enabled_table),	GFP_ATOMIC);
	item->addr = addr;
	item->port = port;
	item->mpip_enabled = enabled;
	item->sent_count = 0;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &me_head);

	mpip_log("%d, %d, %s, %s, %d\n", port, enabled, __FILE__, __FUNCTION__, __LINE__);
	print_addr(addr);

	return 1;
}

bool is_mpip_enabled(__be32 addr, __be16 port)
{
	bool enabled = false;
	struct mpip_enabled_table *item = NULL;

	if (!sysctl_mpip_enabled)
		enabled = false;

	item = find_mpip_enabled(addr, port);

	if (!item)
		enabled = false;
	else
		enabled = item->mpip_enabled;

	return enabled;
}

__be32 get_local_addr1(void)
{
	struct local_addr_table *local_addr;

	int index = 0;

	list_for_each_entry(local_addr, &la_head, list)
	{
		if (index == 0)
			return local_addr->addr;
	}

	return 0;
}

__be32 get_local_addr2(void)
{
	struct local_addr_table *local_addr;

	int index = 0;

	list_for_each_entry(local_addr, &la_head, list)
	{
		if (index == 1)
			return local_addr->addr;

		++index;
	}

	return 0;
}

bool is_local_addr(__be32 addr)
{
	if (find_local_addr(addr) > 0)
		return true;

	return false;
}

int add_working_ip(unsigned char *node_id, __be32 addr, __be16 port,
					unsigned char session_id, unsigned int protocol)
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

	item = find_working_ip(node_id, addr, port, protocol);
	if (item)
	{
		item->session_id = session_id;
		return 0;
	}

	item = kzalloc(sizeof(struct working_ip_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
	item->addr = addr;
	item->port = port;
	item->session_id = session_id;
	item->protocol = protocol;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &wi_head);

//	mpip_log( "wi:");
//
//	print_node_id(__FUNCTION__, node_id);
//	print_addr(__FUNCTION__, addr);

	return 1;
}

struct working_ip_table *find_working_ip(unsigned char *node_id, __be32 addr,
		__be16 port, unsigned int protocol)
{
	struct working_ip_table *working_ip;

	if (!node_id)
		return NULL;

	list_for_each_entry(working_ip, &wi_head, list)
	{
		if (is_equal_node_id(node_id, working_ip->node_id) &&
				(addr == working_ip->addr) &&
				(port == working_ip->port) &&
				(protocol == working_ip->protocol))
		{
			return working_ip;
		}
	}

	return NULL;
}

unsigned char * find_node_id_in_working_ip(__be32 addr, __be16 port,
											unsigned int protocol)
{
	struct working_ip_table *working_ip;

	list_for_each_entry(working_ip, &wi_head, list)
	{
		if ((addr == working_ip->addr) && (port == working_ip->port) &&
			(protocol == working_ip->protocol))
		{
			return working_ip->node_id;
		}
	}

	return NULL;
}

struct addr_notified_table *find_addr_notified(unsigned char *node_id)
{
	struct addr_notified_table *addr_notified;

	if (!node_id)
		return NULL;

	list_for_each_entry(addr_notified, &an_head, list)
	{
		if (is_equal_node_id(node_id, addr_notified->node_id))
		{
			return addr_notified;
		}
	}

	return NULL;
}

bool get_addr_notified(unsigned char *node_id)
{
	bool notified = true;
	struct addr_notified_table *addr_notified = find_addr_notified(node_id);
	if (addr_notified)
	{
		notified = addr_notified->notified;
		if (!notified)
		{
			addr_notified->count += 1;
			if (addr_notified->count > 5)
			{
				addr_notified->notified = true;
				addr_notified->count = 0;
			}
		}
		else
			addr_notified->count = 0;

		mpip_log("%d, %s, %d\n", notified, __FILE__, __LINE__);
		return notified;
	}

	return true;
}

int add_addr_notified(unsigned char *node_id)
{
	struct addr_notified_table *item = NULL;


	if (!node_id)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	if (find_addr_notified(node_id))
		return 0;


	item = kzalloc(sizeof(struct addr_notified_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
	item->notified = true;
	item->count = 0;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &an_head);

//	mpip_log( "an:");
//
//	print_node_id(__FUNCTION__, node_id);

	return 1;
}

void process_addr_notified_event(unsigned char *node_id, unsigned char flags)
{

//	reset_mpip();
//	return;

//	struct working_ip_table *working_ip;
//	struct working_ip_table *tmp_ip;

	struct path_info_table *path_info;
	struct path_info_table *tmp_info;

	struct path_stat_table *path_stat;
	struct path_stat_table *tmp_stat;

	if (!node_id || flags != 1)
		return;

	if (node_id[0] == node_id[1])
	{
		return;
	}

	mpip_log("%s, %d\n", __FILE__, __LINE__);



//	list_for_each_entry_safe(working_ip, tmp_ip, &wi_head, list)
//	{
//		if (is_equal_node_id(node_id, working_ip->node_id))
//		{
//			mpip_log("%s, %d\n", __FILE__, __LINE__);
//			list_del(&(working_ip->list));
//			kfree(working_ip);
//		}
//	}

	list_for_each_entry_safe(path_info, tmp_info, &pi_head, list)
	{
		if (is_equal_node_id(node_id, path_info->node_id))
		{
//			mpip_log("%s, %d\n", __FILE__, __LINE__);
			list_del(&(path_info->list));
			kfree(path_info);
		}
	}

	list_for_each_entry_safe(path_stat, tmp_stat, &ps_head, list)
	{
		if (is_equal_node_id(node_id, path_stat->node_id))
		{
//			mpip_log("%s, %d\n", __FILE__, __LINE__);
			list_del(&(path_stat->list));
			kfree(path_stat);
		}
	}
}

int update_path_stat_delay(unsigned char *node_id, unsigned char path_id, u32 delay)
{
/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct path_stat_table *path_stat;
    struct timespec tv;
	u32  midtime;

	if (!node_id || (path_id == 0))
		return 0;

	if (node_id[0] == node_id[1])
		return 0;

	path_stat = find_path_stat(node_id, path_id);
	if (path_stat)
	{
		getnstimeofday(&tv);
		midtime = (tv.tv_sec % 86400) * MSEC_PER_SEC * 100  + 100 * tv.tv_nsec / NSEC_PER_MSEC;

		path_stat->delay = midtime - delay;
		path_stat->feedbacked = false;
		path_stat->pktcount += 1;
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
			if (path_info->delay == 0)
			{
				path_info->bw = 1000;
			}

			if (path_info->count == 0)
			{
				path_info->delay = delay;
			}
			else
			{
				path_info->delay = (99 * path_info->delay + delay) / 100;
				//path_info->delay = delay;
			}

			if (path_info->count < 500)
			{
				path_info->min_delay = (99 * path_info->min_delay + delay) / 100;
				//path_info->min_delay = delay;
				path_info->count += 1;
			}
			else
			{
				if (path_info->min_delay > path_info->delay)
				{
					path_info->min_delay = (99 * path_info->min_delay + delay) / 100;
					//path_info->min_delay = delay;
				}
			}

			path_info->queuing_delay = path_info->delay - path_info->min_delay;
			if (path_info->queuing_delay > path_info->max_queuing_delay)
			{
				path_info->max_queuing_delay = path_info->queuing_delay;
			}

			break;
		}
	}

	return 1;
}



__s32 calc_si_diff(bool is_delay)
{
	__s32 si = 0;
	__s32 K = 0;
	__s32 sigma = 0;
	__s32 diff = 0;
	__s32 max = 0;
	struct path_info_table *path_info, *prev_info;

	if (is_delay)
	{
		list_for_each_entry(path_info, &pi_head, list)
		{
			prev_info = list_entry(path_info->list.prev, typeof(*path_info), list);
			if (!prev_info)
				continue;


			diff = (path_info->delay - prev_info->delay > 0) ?
				   (path_info->delay - prev_info->delay) :
				   (prev_info->delay - path_info->delay);

			max = (path_info->delay > prev_info->delay) ?
				   path_info->delay : prev_info->delay;

			if (max > diff)
			{
				if (max == -500)
				{
					max = -499;
				}
				sigma += (100 * diff) / (max + 500);
				++K;
			}
		}
	}
	else
	{
		list_for_each_entry(path_info, &pi_head, list)
		{
			prev_info = list_entry(path_info->list.prev, typeof(*path_info), list);
			if (!prev_info)
				continue;


			diff = (path_info->queuing_delay - prev_info->queuing_delay > 0) ?
				   (path_info->queuing_delay - prev_info->queuing_delay) :
				   (prev_info->queuing_delay - path_info->queuing_delay);

			max = (path_info->queuing_delay > prev_info->queuing_delay) ?
				   path_info->queuing_delay : prev_info->queuing_delay;

			if (max > diff)
			{
				if (max == -500)
				{
					max = -499;
				}
				sigma += (100 * diff) / (max + 500);
				++K;
			}
		}
	}

	if (K == 0)
		si = 0;
	else
		si = sigma / K;
	
	return 100 - si;
}

__s32 calc_diff(__s32 value, __s32 min_value, bool is_delay)
{
	__s32 diff = value - min_value;
//	__s32 si = calc_si_diff(is_delay);
	//printk("%d, %s, %d\n", si, __FILE__, __LINE__);
//	return diff / si;
	return diff;
}

bool is_in_sorted_list(struct list_head *sorted_list, struct path_info_table *path_info)
{
	if (!sorted_list)
		return false;

	struct sort_path *sp = NULL;

	list_for_each_entry(sp, sorted_list, list)
	{
		if (sp->path_info->path_id == path_info->path_id)
			return true;
	}
	return false;

}
int update_path_info(unsigned char session_id, unsigned int len)
{
	struct path_info_table *path_info;
	__s32 min_queuing_delay = -1;
	__s32 min_delay = -1;
	__s32 max_queuing_delay = 0;
	__s32 max_delay = 0;
	__u64 max_bw = 0;

	if (session_id <= 0)
		return 0;

	struct list_head sorted_list;
	INIT_LIST_HEAD(&(sorted_list));
	int count = 0;


	while(true)
	{
//		printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		struct path_info_table *min_path = NULL;
		__s32 min_value = -1;
		list_for_each_entry(path_info, &pi_head, list)
		{
			if (path_info->session_id != session_id)
				continue;

//			printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			if (!is_in_sorted_list(&sorted_list, path_info))
			{
				if (path_info->max_queuing_delay < min_value || min_value == -1)
				{
					min_value = path_info->max_queuing_delay;
					min_path = path_info;
//					printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
				}
			}
		}

//		printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		if (min_path != NULL)
		{
//			printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			struct sort_path *item = kzalloc(sizeof(struct sort_path),	GFP_ATOMIC);
			if (!item)
				break;

//			printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			item->path_info = min_path;
			INIT_LIST_HEAD(&(item->list));
			list_add(&(item->list), &(sorted_list));
			++count;
		}
		else
			break;
	}

	struct sort_path *sp = NULL;
	struct sort_path *next_sp = NULL;
//	printk("%d: %s, %s, %d\n", count, __FILE__, __FUNCTION__, __LINE__);
	if (count == 4)
	{
		list_for_each_entry(sp, &sorted_list, list)
		{
//			printk("%d: %s, %s, %d\n", sp->path_info->path_id, __FILE__, __FUNCTION__, __LINE__);
			next_sp = list_entry(sp->list.next, typeof(*sp), list);
			if(next_sp)
			{
				sp->path_info->ave_delay = next_sp->path_info->ave_delay =
						(sp->path_info->delay + next_sp->path_info->delay) / 2;

				sp->path_info->ave_max_queuing_delay = next_sp->path_info->ave_max_queuing_delay =
										(sp->path_info->max_queuing_delay + next_sp->path_info->max_queuing_delay) / 2;

//				printk("%d: %s, %s, %d\n", next_sp->path_info->path_id, __FILE__, __FUNCTION__, __LINE__);

				sp = list_entry(sp->list.next, typeof(*sp), list);

//				printk("%d: %s, %s, %d\n", sp->path_info->path_id, __FILE__, __FUNCTION__, __LINE__);
			}
		}
	}
	else
	{
		list_for_each_entry(sp, &sorted_list, list)
		{
			sp->path_info->ave_delay = sp->path_info->delay;
			sp->path_info->ave_max_queuing_delay = sp->path_info->max_queuing_delay;
//			printk("%d: %s, %s, %d\n", sp->path_info->path_id, __FILE__, __FUNCTION__, __LINE__);

		}
	}

	list_for_each_entry_safe(sp, next_sp, &sorted_list, list)
	{
		list_del(&(sp->list));
		kfree(sp);
	}


	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->session_id != session_id)
			continue;

		if (path_info->max_queuing_delay < min_queuing_delay || min_queuing_delay == -1)
		{
			min_queuing_delay = path_info->max_queuing_delay;
		}

		if (abs(path_info->max_queuing_delay) > max_queuing_delay)
		{
			max_queuing_delay = abs(path_info->max_queuing_delay);
		}

		if (path_info->delay < min_delay || min_delay == -1)
		{
			min_delay = path_info->delay;
		}

		if (abs(path_info->delay) > max_delay)
		{
			max_delay = abs(path_info->delay);
		}
	}

	if (min_queuing_delay == -1)
	{
		return 0;
	}

	if (max_queuing_delay <= 20)
	{
		max_queuing_delay = 100;
	}

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->session_id != session_id)
			continue;

		__s32 diff1 = calc_diff(path_info->ave_max_queuing_delay, min_queuing_delay, false);

		if (diff1 <= 0)
			diff1 = 1;

		__s32 diff2 = calc_diff(path_info->ave_delay, min_delay, true);

		if (diff2 <= 0)
			diff2 = 1;

		len = 1550;

		if ((path_info->delay == 0) && (path_info->pktcount > 5))
			path_info->bw = path_info->bw / 5;
		else
		{
			int tmp = len * max_queuing_delay / (diff1+sysctl_mpip_bw_4);

			if (max_delay < 0)
				max_delay = -max_delay;

			tmp += (1550 - len) * max_delay / (diff2+sysctl_mpip_bw_4);
			path_info->bw = (999 * path_info->bw + tmp) / 1000;
		}

		if (path_info->bw > max_bw)
			max_bw = path_info->bw;

	}

	if (max_bw > 50000)
	{
		__u64 times = max_bw / 50000;
		if (times > 0)
		{
			list_for_each_entry(path_info, &pi_head, list)
			{
				if (path_info->session_id != session_id)
					continue;

				path_info->bw /= times;
				if (path_info->bw <= 0)
					path_info->bw = 0;
			}
		}
	}

	return 1;
}

bool check_path_info_status(struct sk_buff *skb,
		unsigned char *node_id, unsigned char session_id)
{
	struct path_info_table *path_info;

	if (!node_id || (session_id <= 0))
		return false;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (is_equal_node_id(node_id, path_info->node_id) &&
		    (session_id == path_info->session_id) &&
		    (path_info->status != 0))
		{
			mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			send_mpip_syn(skb, path_info->saddr, convert_addr(192, 168, 1, 15),
					path_info->sport, path_info->dport,	true, false,
					session_id);

		}
	}

	return true;
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

int add_path_stat(unsigned char *node_id, unsigned char path_id)
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


	memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
	item->path_id = path_id;
	item->delay = 0;
	item->feedbacked = false;
	item->fbjiffies = jiffies;
	item->pktcount = 0;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &ps_head);

	//mpip_log( "ps: %d", path_id);
	//print_node_id(node_id);

	return 1;
}


struct socket_session_table *get_sender_session(__be32 saddr, __be16 sport,
								 __be32 daddr, __be16 dport, unsigned int protocol)
{
	struct socket_session_table *socket_session;

//	printk("%s, %d\n", __FILE__, __LINE__);
//	print_addr(__FUNCTION__, saddr);
//	print_addr(__FUNCTION__, daddr);
//	printk("%d, %d, %s, %d\n", sport, dport, __FILE__, __LINE__);


	list_for_each_entry(socket_session, &ss_head, list)
	{
		if ((socket_session->saddr == saddr) &&
			(socket_session->sport == sport) &&
			(socket_session->daddr == daddr) &&
			(socket_session->dport == dport) &&
			(socket_session->protocol == protocol))
		{
//			printk("%s, %d\n", __FILE__, __LINE__);
//			print_addr(__FUNCTION__, saddr);
//			print_addr(__FUNCTION__, daddr);
//			printk("%d, %d, %s, %d\n", sport, dport, __FILE__, __LINE__);

			return socket_session;
		}
	}

	return NULL;
}

void add_sender_session(unsigned char *src_node_id, unsigned char *dst_node_id,
					   __be32 saddr, __be16 sport,
					   __be32 daddr, __be16 dport,
					   unsigned int protocol)
{
	struct socket_session_table *item = NULL;

//	if (!is_lan_addr(saddr) || !is_lan_addr(daddr))
//	{
//		return 0;
//	}

	if (!src_node_id || !dst_node_id)
		return;

	if ((src_node_id[0] == src_node_id[1]) || (dst_node_id[0] == dst_node_id[1]))
	{
		return;
	}

	if (get_sender_session(saddr, sport, daddr, dport, protocol))
		return;


	item = kzalloc(sizeof(struct socket_session_table),	GFP_ATOMIC);

	memcpy(item->src_node_id, src_node_id, MPIP_CM_NODE_ID_LEN);
	memcpy(item->dst_node_id, dst_node_id, MPIP_CM_NODE_ID_LEN);

	INIT_LIST_HEAD(&(item->tcp_buf));
	item->next_seq = 0;
	item->buf_count = 0;
	item->protocol = protocol;
	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->session_id = (static_session_id > 250) ? 1 : ++static_session_id;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &ss_head);

	mpip_log("%s, %d\n", __FILE__, __LINE__);
	print_addr(saddr);
	print_addr(daddr);
	mpip_log( "ss: %d,%d,%d\n", item->session_id,
			sport, dport);
	mpip_log("%s, %d\n", __FILE__, __LINE__);
}



struct socket_session_table *find_receiver_session(unsigned char *node_id, unsigned char session_id)
{
	struct socket_session_table *socket_session;

	if (!node_id)
		return 0;

	list_for_each_entry(socket_session, &ss_head, list)
	{
		if (is_equal_node_id(socket_session->dst_node_id, node_id) &&
			(socket_session->session_id == session_id))
		{
			return socket_session;
		}
	}

	return NULL;
}

struct socket_session_table *get_receiver_session(unsigned char *src_node_id, unsigned char *dst_node_id,
						__be32 saddr, __be16 sport,
		 	 	 	 	__be32 daddr, __be16 dport,
		 	 	 	 	unsigned char session_id,
		 	 	 	 	unsigned char path_id,
		 	 	 	 	unsigned int protocol)
{
	struct socket_session_table *item = NULL;
	int sid;


	if (!src_node_id || !dst_node_id || (session_id <= 0))
		return 0;

	if ((src_node_id[0] == src_node_id[1]) || (dst_node_id[0] == dst_node_id[1]))
	{
		return 0;
	}

	static_session_id = (static_session_id > session_id) ? static_session_id : session_id;

	item = find_receiver_session(dst_node_id, session_id);
	if (item)
		return item;

	mpip_log("%s, %d\n", __FILE__, __LINE__);
	print_addr(saddr);
	print_addr(daddr);
	mpip_log("%d, %d, %s, %d\n", sport, dport, __FILE__, __LINE__);

	item = get_sender_session(saddr, sport, daddr, dport, protocol);
	if (item)
		return item;

	if (path_id > 0)
		return NULL;

	item = kzalloc(sizeof(struct socket_session_table), GFP_ATOMIC);

	memcpy(item->src_node_id, src_node_id, MPIP_CM_NODE_ID_LEN);
	memcpy(item->dst_node_id, dst_node_id, MPIP_CM_NODE_ID_LEN);

	INIT_LIST_HEAD(&(item->tcp_buf));
	item->next_seq = 0;
	item->buf_count = 0;
	item->protocol = protocol;
	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->session_id = session_id;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &ss_head);

	return item;
}

int get_receiver_session_info(unsigned char *node_id,	unsigned char session_id,
						__be32 *saddr, __be16 *sport,
						__be32 *daddr, __be16 *dport)
{
	struct socket_session_table *socket_session;

	if (!node_id || (session_id <= 0))
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

	//rcu_read_lock();

	//printk("%d, %s, %s, %d\n", session_id, __FILE__, __FUNCTION__, __LINE__);

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

		//	printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);

			if ((ntohl(tcph->seq) < socket_session->next_seq) &&
				(socket_session->next_seq) - ntohl(tcph->seq) < 0xFFFFFFF)
			{
				printk("late: %d %u, %u, %s, %d\n", socket_session->buf_count,
						ntohl(tcph->seq), socket_session->next_seq, __FILE__, __LINE__);
				dst_input(skb);
				goto success;
			}

			if ((socket_session->next_seq == 0) ||
				(ntohl(tcph->seq) == socket_session->next_seq) ||
				(ntohl(tcph->seq) == socket_session->next_seq + 1)) //for three-way handshake
			{
				printk("send: %d, %u, %u, %s, %d\n", socket_session->buf_count,
						ntohl(tcph->seq), socket_session->next_seq, __FILE__, __LINE__);
				socket_session->next_seq = skb->len - ip_hdr(skb)->ihl * 4 - tcph->doff * 4 + ntohl(tcph->seq);
				dst_input(skb);

recursive:
				if (socket_session->buf_count > 0)
				{
					list_for_each_entry_safe(tcp_buf, tmp_buf, &(socket_session->tcp_buf), list)
					{
						if (tcp_buf->seq == socket_session->next_seq)
						{
							socket_session->next_seq = tcp_buf->skb->len - ip_hdr(tcp_buf->skb)->ihl * 4 -
																		   tcp_hdr(tcp_buf->skb)->doff * 4 + tcp_buf->seq;
							printk("push: %d, %u, %u, %s, %d\n", socket_session->buf_count,
									tcp_buf->seq, socket_session->next_seq, __FILE__, __LINE__);

							dst_input(tcp_buf->skb);

							list_del(&(tcp_buf->list));
							kfree(tcp_buf);

							socket_session->buf_count -= 1;

							goto recursive;
						}
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

			printk("out of order: %d, %u, %u, %s, %d\n", socket_session->buf_count,
					ntohl(tcph->seq), socket_session->next_seq,
					__FILE__, __LINE__);

			goto success;
		}
	}


success:
//	rcu_read_unlock();
	return 1;
fail:
//	rcu_read_unlock();
	mpip_log("Fail: %s, %d\n", __FILE__, __LINE__);
	return 0;
}

struct path_info_table *find_path_info(__be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport, unsigned char session_id)
{
	struct path_info_table *path_info;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if ((path_info->saddr == saddr) &&
			(path_info->daddr == daddr) &&
			(path_info->sport == sport) &&
			(path_info->dport == dport) &&
			(path_info->session_id == session_id))
		{
			return path_info;
		}
	}
	return NULL;
}

bool init_mpip_tcp_connection(__be32 daddr1, __be32 daddr2,
							__be32 saddr, __be32 daddr,
							__be16 sport, __be16 dport,
							unsigned char session_id)
{

	struct local_addr_table *local_addr;
	struct path_info_table *item = NULL;
	list_for_each_entry(local_addr, &la_head, list)
	{
		if (local_addr->addr == saddr)
		{
			if (daddr1 == daddr)
			{
				if ((daddr2 != 0) && !find_path_info(local_addr->addr, daddr2, sport + 1, dport, session_id))
				{
					printk("%d, %d, %d: %s, %s, %d\n", session_id, sport + 1, dport, __FILE__, __FUNCTION__, __LINE__);
					print_addr_1(local_addr->addr);
					print_addr_1(daddr2);

					send_mpip_syn(NULL, local_addr->addr, daddr2,
							sport + 1, dport, true, false, session_id);
				}
			}
			else
			{
				if ((daddr1 != 0) && !find_path_info(local_addr->addr, daddr1, sport + 1, dport, session_id))
				{
					printk("%d, %d, %d: %s, %s, %d\n", session_id, sport + 1, dport, __FILE__, __FUNCTION__, __LINE__);
					print_addr_1(local_addr->addr);
					print_addr_1(daddr1);

					send_mpip_syn(NULL, local_addr->addr, daddr1,
							sport + 1, dport, true, false, session_id);
				}
			}
		}
		else
		{
			if ((daddr1 != 0) && !find_path_info(local_addr->addr, daddr1, sport + 2, dport, session_id))
			{
				printk("%d, %d, %d: %s, %s, %d\n", session_id, sport + 2, dport, __FILE__, __FUNCTION__, __LINE__);
				print_addr_1(local_addr->addr);
				print_addr_1(daddr1);

				send_mpip_syn(NULL, local_addr->addr, daddr1,
						sport + 2, dport, true, false, session_id);
			}

			if ((daddr2 != 0) && !find_path_info(local_addr->addr, daddr2, sport + 3, dport, session_id))
			{
				printk("%d, %d, %d: %s, %s, %d\n", session_id, sport + 3, dport, __FILE__, __FUNCTION__, __LINE__);
				print_addr_1(local_addr->addr);
				print_addr_1(daddr2);

				send_mpip_syn(NULL, local_addr->addr, daddr2,
						sport + 3, dport, true, false, session_id);
			}
		}
	}

	return true;
}


bool is_origin_path_info_added(unsigned char *node_id, unsigned char session_id, unsigned int protocol)
{
	struct path_info_table *path_info;

	if (!node_id || (session_id <= 0))
		return false;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (is_equal_node_id(path_info->node_id, node_id) &&
		   (path_info->session_id == session_id))
		{
			return true;
		}
	}

	return false;
}


int add_origin_path_info_tcp(unsigned char *node_id, __be32 saddr, __be32 daddr, __be16 sport,
		__be16 dport, unsigned char session_id, unsigned int protocol)
{
	struct path_info_table *item = NULL;

	if (!node_id || session_id <= 0)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	if (is_origin_path_info_added(node_id, session_id, protocol))
		return 0;

	mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);

	item = kzalloc(sizeof(struct path_info_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
	item->fbjiffies = jiffies;
	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->session_id = session_id;
	item->min_delay = 0;
	item->delay = 0;
	item->queuing_delay = 0;
	item->max_queuing_delay = 0;
	item->count = 0;
	item->bw = 1000;
	item->pktcount = 0;
	item->path_id = (static_path_id > 250) ? 1 : ++static_path_id;

	if (is_original_path(node_id, item->saddr, item->daddr,
			item->sport, item->dport, session_id) || (protocol != IPPROTO_TCP))
	{
		item->status = 0;
	}
	else
	{
		item->status = 0;
	}

	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &pi_head);

	return 1;
}


int add_path_info_tcp(int id, unsigned char *node_id, __be32 saddr, __be32 daddr, __be16 sport,
		__be16 dport, unsigned char session_id, unsigned int protocol)
{
	struct path_info_table *item = NULL;

	if (!node_id || session_id <= 0)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	item = find_path_info(saddr, daddr,
				sport, dport, session_id);

	if (item)
	{
		item->status = 0;
		return true;
	}

	item = kzalloc(sizeof(struct path_info_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
	item->fbjiffies = jiffies;
	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->session_id = session_id;
	item->min_delay = 0;
	item->delay = 0;
	item->queuing_delay = 0;
	item->max_queuing_delay = 0;
	item->count = 0;
	item->bw = 1000;
	item->pktcount = 0;
	item->path_id = (static_path_id > 250) ? 1 : ++static_path_id;
	item->status = 0;

	printk("%d, %d, %d, %d: %s, %s, %d\n", id, session_id, sport, dport, __FILE__, __FUNCTION__, __LINE__);
//	print_addr_1(saddr);
//	print_addr_1(daddr);


//	if (is_original_path(node_id, item->saddr, item->daddr,
//			item->sport, item->dport, session_id) || (protocol != IPPROTO_TCP))
//	{
//		item->status = 0;
//	}
//	else
//	{
//		item->status = 0;
//	}

	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &pi_head);

	return 1;
}


bool ready_path_info(int id, unsigned char *node_id, __be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport,	unsigned char session_id)
{
	struct path_info_table *path_info = find_path_info(saddr, daddr,
			sport, dport, session_id);

	mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
	if (path_info)
	{
		path_info->status = 0;
		return true;
	}
	else
	{
		if (add_path_info_tcp(id, node_id, saddr, daddr, sport, dport, session_id, IPPROTO_TCP))
			return true;
	}

	return false;
}

bool is_dest_added(unsigned char *node_id, __be32 addr, __be16 port,
					unsigned char session_id, unsigned int protocol)
{
	struct path_info_table *path_info;

	if (!node_id)
		return 0;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (is_equal_node_id(path_info->node_id, node_id) &&
		   (path_info->daddr == addr) &&
		   (path_info->dport == port) &&
		   (path_info->session_id == session_id))
		{
			return true;
		}
	}
	return false;
}


bool is_original_path(unsigned char *node_id, __be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport,	unsigned char session_id)
{
	__be32 osaddr = 0, odaddr = 0;
	__be16 osport = 0, odport = 0;

	if (get_receiver_session_info(node_id, session_id,
			  &osaddr, &osport, &odaddr, &odport))
	{
		if ((saddr == osaddr) && (daddr == odaddr) &&
			(sport == osport) && (dport == odport))
		{
			return true;
		}
	}

	return false;
}

int add_path_info_udp(unsigned char *node_id, __be32 daddr, __be16 sport,
		__be16 dport, unsigned char session_id, unsigned int protocol)
{
	struct local_addr_table *local_addr;
	struct path_info_table *item = NULL;
//	__be32 waddr = convert_addr(192, 168, 2, 20);
//	__be32 eaddr = convert_addr(192, 168, 2, 21);

	if (!node_id || session_id <= 0)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}
//
//	if (is_dest_added(node_id, daddr, dport, session_id, protocol))
//		return 0;


	list_for_each_entry(local_addr, &la_head, list)
	{

		item = find_path_info(local_addr->addr, daddr,
						sport, dport, session_id);
		if (item)
		{
			item->status = 0;
			continue;
		}

		item = kzalloc(sizeof(struct path_info_table),	GFP_ATOMIC);

		memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
		item->fbjiffies = jiffies;
		item->saddr = local_addr->addr;
		item->sport = sport;
		item->daddr = daddr;
		item->dport = dport;
		item->session_id = session_id;
		item->min_delay = 0;
		item->delay = 0;
		item->queuing_delay = 0;
		item->max_queuing_delay = 0;
		item->count = 0;
		item->bw = 1000;
		item->pktcount = 0;
		item->path_id = (static_path_id > 250) ? 1 : ++static_path_id;

		if (is_original_path(node_id, item->saddr, item->daddr,
				item->sport, item->dport, session_id) || (protocol != IPPROTO_TCP))
		{
			item->status = 0;
		}
		else
		{
			item->status = 1;
		}

		INIT_LIST_HEAD(&(item->list));
		list_add(&(item->list), &pi_head);

//		mpip_log( "pi: %d\n", item->path_id);
//
//		print_node_id(__FUNCTION__, node_id);
//		print_addr(__FUNCTION__, addr);
	}

	return 1;
}

struct path_info_table *find_lowest_delay_path(unsigned char *node_id,
		unsigned char session_id)
{
	struct path_info_table *path_info;
	struct path_info_table *f_path = NULL;
	__s32 min_delay = -1;


	if (session_id <= 0)
		return 0;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (!is_equal_node_id(path_info->node_id, node_id) ||
				path_info->session_id != session_id ||
				path_info->status != 0)
		{
			continue;
		}

		if (path_info->delay < min_delay || min_delay == -1)
		{
			min_delay = path_info->delay;
			f_path = path_info;
		}
	}

	return f_path;
}

unsigned char find_fastest_path_id(unsigned char *node_id,
			   __be32 *saddr, __be32 *daddr,  __be16 *sport, __be16 *dport,
			   __be32 origin_saddr, __be32 origin_daddr, __be16 origin_sport,
			   __be16 origin_dport, unsigned char session_id,
			   unsigned int protocol, unsigned int len, bool is_ack)
{
	struct path_info_table *path;
	struct path_info_table *f_path;
	unsigned char f_path_id = 0;

	__u64 totalbw = 0, tmptotal = 0, f_bw = 0;
	int random = 0;
	bool path_done = true;

	if (!node_id || session_id <= 0)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}
	//for ack packet, use the path with lowest delay
	if (is_ack)
	{
		f_path = find_lowest_delay_path(node_id, session_id);

		if (f_path)
		{
			*saddr = f_path->saddr;
			*daddr = f_path->daddr;
			*sport = f_path->sport;
			*dport = f_path->dport;
			f_path->pktcount += 1;
			f_path_id = f_path->path_id;

			return f_path_id;
		}
	}
	update_path_info(session_id, len);
	//if comes here, it means all paths have been probed
	list_for_each_entry(path, &pi_head, list)
	{
		if (!is_equal_node_id(path->node_id, node_id) ||
			path->session_id != session_id ||
			path->status != 0)
		{
			continue;
		}

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

	//if ((totalbw > 0) || !path_done)
	if (totalbw > 0)
	{
		random = get_random_int() % totalbw;
		random = (random > 0) ? random : -random;
		tmptotal = 0;

		list_for_each_entry(path, &pi_head, list)
		{
			if (!is_equal_node_id(path->node_id, node_id) ||
				path->session_id != session_id ||
				path->status != 0)
			{
				continue;
			}

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
		*sport = f_path->sport;
		*dport = f_path->dport;
		f_path->pktcount += 1;
	}
	else
	{
		f_path = find_path_info(origin_saddr, origin_daddr, origin_sport, origin_dport, session_id);
		if (f_path)
		{
			*saddr = f_path->saddr;
			*daddr = f_path->daddr;
			*sport = f_path->sport;
			*dport = f_path->dport;
			f_path->pktcount += 1;
			f_path_id = f_path->path_id;
		}
	}

	return f_path_id;
}


void send_mpip_hb(struct sk_buff *skb, unsigned char session_id)
{
	if (!skb)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return;
	}

	if (((jiffies - earliest_fbjiffies) * 1000 / HZ) >= sysctl_mpip_hb)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		if (send_mpip_msg(skb, false, true, 2, session_id))
			earliest_fbjiffies = jiffies;
	}
}

unsigned char find_earliest_path_stat_id(unsigned char *dest_node_id, __s32 *delay)
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

		//if (!path_stat->feedbacked && path_stat->fbjiffies <= e_fbtime)
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
		e_path_stat->feedbacked = true;
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

		if (!netif_running(dev))
		{
//			if (dev->ip_ptr && dev->ip_ptr->ifa_list)
//			{
//				mpip_log( "un-active: %lu  ", dev->state);
//				print_addr(__FUNCTION__, dev->ip_ptr->ifa_list->ifa_address);
//			}

			continue;
		}
		if (dev->ip_ptr && dev->ip_ptr->ifa_list)
		{
			if (find_local_addr(dev->ip_ptr->ifa_list->ifa_address))
				continue;

			item = kzalloc(sizeof(struct local_addr_table),	GFP_ATOMIC);
			item->addr = dev->ip_ptr->ifa_list->ifa_address;
			INIT_LIST_HEAD(&(item->list));
			list_add(&(item->list), &la_head);
//			mpip_log( "local addr: %lu  ", dev->state);
//			print_addr(__FUNCTION__, dev->ip_ptr->ifa_list->ifa_address);
		}
	}
}

void update_addr_change(void)
{
//	reset_mpip();
//	return;

	struct local_addr_table *local_addr;
	struct local_addr_table *tmp_addr;
	struct working_ip_table *working_ip;
	struct path_info_table *path_info;
	struct path_info_table *tmp_info;
	struct path_stat_table *path_stat;
	struct path_stat_table *tmp_stat;

	mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);

	struct addr_notified_table *addr_notified;
	list_for_each_entry(addr_notified, &an_head, list)
	{
		addr_notified->notified = false;
	}
	list_for_each_entry_safe(local_addr, tmp_addr, &la_head, list)
	{
		list_del(&(local_addr->list));
		kfree(local_addr);
	}

	get_available_local_addr();

	list_for_each_entry_safe(path_info, tmp_info, &pi_head, list)
	{
		list_del(&(path_info->list));
		kfree(path_info);
	}

//	list_for_each_entry(working_ip, &wi_head, list)
//	{
//		add_path_info(working_ip->node_id, working_ip->addr, working_ip->port,
//				working_ip->session_id, working_ip->protocol);
//	}

	list_for_each_entry_safe(path_stat, tmp_stat, &ps_head, list)
	{
			list_del(&(path_stat->list));
			kfree(path_stat);
	}
	mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
}

struct net_device *find_dev_by_addr(__be32 addr)
{
	struct net_device *dev;

	for_each_netdev(&init_net, dev)
	{
		if (strstr(dev->name, "lo"))
			continue;

		if (!netif_running(dev))
			continue;

		if (dev->ip_ptr && dev->ip_ptr->ifa_list)
		{
			if (dev->ip_ptr->ifa_list->ifa_address == addr)
				return dev;
		}
	}
	return NULL;
}


void reset_mpip(void)
{
	struct mpip_enabled_table *mpip_enabled;
	struct mpip_enabled_table *tmp_enabled;

	struct addr_notified_table *addr_notified;
	struct addr_notified_table *tmp_notified;

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

	list_for_each_entry_safe(mpip_enabled, tmp_enabled, &me_head, list)
	{
			list_del(&(mpip_enabled->list));
			kfree(mpip_enabled);
	}

	list_for_each_entry_safe(addr_notified, tmp_notified, &an_head, list)
	{
			list_del(&(addr_notified->list));
			kfree(addr_notified);
	}

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
	struct mpip_enabled_table *mpip_enbaled;
	struct mpip_query_table *mpip_query;
	struct addr_notified_table *addr_notified;
	struct working_ip_table *working_ip;
	struct path_info_table *path_info;
	struct socket_session_table *socket_session;
	struct path_stat_table *path_stat;
	struct local_addr_table *local_addr;
	char *p;

	printk("******************me*************\n");
	list_for_each_entry(mpip_enbaled, &me_head, list)
	{
		p = (char *) &(mpip_enbaled->addr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		printk("%d  ", mpip_enbaled->port);

		printk("%d  ", mpip_enbaled->sent_count);

		printk("%d\n", mpip_enbaled->mpip_enabled);
	}


	printk("******************mq*************\n");
	list_for_each_entry(mpip_query, &mq_head, list)
	{
		p = (char *) &(mpip_query->saddr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		p = (char *) &(mpip_query->saddr);
				printk( "%d.%d.%d.%d  ",
						(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		printk("%d  ", mpip_query->sport);

		printk("%d\n", mpip_query->dport);
	}

	printk("******************an*************\n");
	list_for_each_entry(addr_notified, &an_head, list)
	{
		printk( "%02x-%02x  ",
				addr_notified->node_id[0], addr_notified->node_id[1]);

		printk("%d\n", addr_notified->notified);
	}

	printk("******************wi*************\n");
	list_for_each_entry(working_ip, &wi_head, list)
	{
		printk( "%02x-%02x  ",
				working_ip->node_id[0], working_ip->node_id[1]);

		p = (char *) &(working_ip->addr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		printk("%d  ", working_ip->port);

		printk("%d  ", working_ip->session_id);

		printk("%d\n", working_ip->protocol);
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

		printk("%d  ", socket_session->sport);

		printk("%d  ", socket_session->dport);

		printk("%d\n", socket_session->protocol);
	}

	printk("******************ps*************\n");
	list_for_each_entry(path_stat, &ps_head, list)
	{
		printk( "%02x-%02x  ",
				path_stat->node_id[0], path_stat->node_id[1]);

		printk("%d  ", path_stat->path_id);

		printk("%d  ", path_stat->delay);

		printk("%lu  ", path_stat->fbjiffies);

		printk("%llu\n", path_stat->pktcount);
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

		printk("%d  ", path_info->sport);

		printk("%d  ", path_info->dport);

		printk("%d  ", path_info->session_id);

//		printk("%d  ", path_info->min_delay);

		printk("%d  ", path_info->delay);

		printk("%d  ", path_info->ave_delay);

		printk("%d  ", path_info->max_queuing_delay);

		printk("%d  ", path_info->ave_max_queuing_delay);

//		printk("%d  ", path_info->queuing_delay);

		printk("%llu  ", path_info->bw);

		printk("%llu\n", path_info->pktcount);

//		printk("%d\n", path_info->status);

	}

	return 0;

}

asmlinkage long sys_reset_mpip(void)
{
	reset_mpip();
	printk("reset ended\n");
	return 0;
}
