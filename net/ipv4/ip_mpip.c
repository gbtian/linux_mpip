#undef __KERNEL__
#define __KERNEL__

#undef MODULE
#define MODULE

#include <linux/module.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/sysctl.h>
#include <linux/syscalls.h>
#include <net/route.h>
#include <net/tcp.h>

#include <linux/inetdevice.h>
#include <linux/ip_mpip.h>
#include <net/ip.h>


//int MPIP_CM_LEN = sizeof(struct mpip_options);
//int MPIP_CM_LEN = 9;
//int MPIP_CM_NODE_ID_LEN = 3;
static unsigned char *static_node_id = NULL;
static char log_buf[256];

static struct mpip_cm send_mpip_cm;
static struct mpip_cm rcv_mpip_cm;

int sysctl_mpip_enabled __read_mostly = 0;
int sysctl_mpip_send __read_mostly = 0;
int sysctl_mpip_rcv __read_mostly = 0;
int sysctl_mpip_log __read_mostly = 1;
int sysctl_mpip_bw_factor __read_mostly = 1;
int sysctl_mpip_bw_1 __read_mostly = 240;
int sysctl_mpip_bw_2 __read_mostly = 60;
int sysctl_mpip_bw_3 __read_mostly = 30;
int sysctl_mpip_bw_4 __read_mostly = 30;
int sysctl_mpip_hb __read_mostly = 1000;
int sysctl_mpip_use_tcp __read_mostly = 1;
int sysctl_mpip_tcp_buf_count __read_mostly = 10;
int max_pkt_len = 65500;


static struct ctl_table mpip_table[] =
{
 	{
 		.procname = "mpip_enabled",
 		.data = &sysctl_mpip_enabled,
 		.maxlen = sizeof(int),
 		.mode = 0644,
 		.proc_handler = &proc_dointvec
 	},
 	{
 		.procname = "mpip_send",
 		.data = &sysctl_mpip_send,
 		.maxlen = sizeof(int),
 		.mode = 0644,
 		.proc_handler = &proc_dointvec
 	},
 	{
 	 		.procname = "mpip_rcv",
 	 		.data = &sysctl_mpip_rcv,
 	 		.maxlen = sizeof(int),
 	 		.mode = 0644,
 	 		.proc_handler = &proc_dointvec
 	},
 	{
 	 		.procname = "mpip_log",
 	 		.data = &sysctl_mpip_log,
 	 		.maxlen = sizeof(int),
 	 		.mode = 0644,
 	 		.proc_handler = &proc_dointvec
 	},
 	{
 	 		.procname = "mpip_bw_factor",
 	 		.data = &sysctl_mpip_bw_factor,
 	 		.maxlen = sizeof(int),
 	 		.mode = 0644,
 	 		.proc_handler = &proc_dointvec
 	},
 	{
 	 		.procname = "mpip_bw_1",
 	 		.data = &sysctl_mpip_bw_1,
 	 		.maxlen = sizeof(int),
 	 		.mode = 0644,
 	 		.proc_handler = &proc_dointvec
 	},
 	{
 	 		.procname = "mpip_bw_2",
 	 		.data = &sysctl_mpip_bw_2,
 	 		.maxlen = sizeof(int),
 	 		.mode = 0644,
 	 		.proc_handler = &proc_dointvec
 	},
 	{
 	 		.procname = "mpip_bw_3",
 	 		.data = &sysctl_mpip_bw_3,
 	 		.maxlen = sizeof(int),
 	 		.mode = 0644,
 	 		.proc_handler = &proc_dointvec
 	},
 	{
 	 		.procname = "mpip_bw_4",
 	 		.data = &sysctl_mpip_bw_4,
 	 		.maxlen = sizeof(int),
 	 		.mode = 0644,
 	 		.proc_handler = &proc_dointvec
 	},
 	{
			.procname = "mpip_hb",
			.data = &sysctl_mpip_hb,
			.maxlen = sizeof(int),
			.mode = 0644,
			.proc_handler = &proc_dointvec
	},
 	{
			.procname = "mpip_use_tcp",
			.data = &sysctl_mpip_use_tcp,
			.maxlen = sizeof(int),
			.mode = 0644,
			.proc_handler = &proc_dointvec
	},
 	{
			.procname = "mpip_tcp_buf_count",
			.data = &sysctl_mpip_tcp_buf_count,
			.maxlen = sizeof(int),
			.mode = 0644,
			.proc_handler = &proc_dointvec
	},
 	{ }
};


/* React on IPv4-addr add/rem-events */
static int mpip_inetaddr_event(struct notifier_block *this,
				   unsigned long event, void *ptr)
{
	struct net_device *dev = NULL;
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	if (ifa && ifa->ifa_dev)
		dev = ifa->ifa_dev->dev;
	else
	{
		dump_stack();
		mpip_log("%s, %d\n", __FILE__, __LINE__);
	}

	if (dev && dev->ip_ptr && dev->ip_ptr->ifa_list)
	{
		if (sysctl_mpip_enabled)
		{
			mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			update_addr_change();
		}
	}

	return NOTIFY_DONE;
}

/* React on ifup/down-events */
static int netdev_event(struct notifier_block *this, unsigned long event,
			void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct in_device *in_dev;

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	rcu_read_lock();
	in_dev = __in_dev_get_rtnl(dev);

	if (in_dev) {
		for_ifa(in_dev) {
			mpip_inetaddr_event(NULL, event, ifa);
		} endfor_ifa(in_dev);
	}

	rcu_read_unlock();
	return NOTIFY_DONE;
}

static struct notifier_block mpip_netdev_notifier = {
		.notifier_call = netdev_event,
};

static struct notifier_block mpip_inetaddr_notifier = {
		.notifier_call = mpip_inetaddr_event,
};

int mpip_init(void)
{
	struct ctl_table_header *mptcp_sysctl;
	int ret;
    //In kernel, __MPIP__ will be checked to decide which functions to call.
	mptcp_sysctl = register_net_sysctl(&init_net, "net/mpip", mpip_table);
	ret = register_inetaddr_notifier(&mpip_inetaddr_notifier);
	ret = register_netdevice_notifier(&mpip_netdev_notifier);

	//get_available_local_addr();

    return 0;
}



void mpip_log(const char *fmt, ...)
{
	va_list args;
	int r;
//	struct file *fp;
//    struct inode *inode = NULL;
//	mm_segment_t fs;
//	loff_t pos;

	if (!sysctl_mpip_log)
		return;

	memset(log_buf, 0, 256);
	va_start(args, fmt);
	r = vsnprintf(log_buf, 256, fmt, args);
	va_end(args);

    printk(log_buf);

    return;


//	fp = filp_open("/home/bill/log", O_RDWR | O_CREAT | O_SYNC, 0644);
//	if (IS_ERR(fp))
//	{
//		printk("create file error\n");
//		return;
//	}
//
//	fs = get_fs();
//	set_fs(KERNEL_DS);
//	pos = fp->f_dentry->d_inode->i_size;
//	//pos = 0;
//	vfs_write(fp, log_buf, strlen(log_buf), &pos);
//	vfs_fsync(fp, 0);
//	filp_close(fp, NULL);
//	set_fs(fs);

}
EXPORT_SYMBOL(mpip_log);

void print_mpip_cm(struct mpip_cm *cm)
{

	mpip_log("len = %d\n", cm->len);
	mpip_log("node_id= ");
	print_node_id(cm->node_id);
	mpip_log("session_id = %d\n", cm->session_id);
	mpip_log("path_id = %d\n",   cm->path_id);
	mpip_log("path_stat_id = %d\n",  cm->path_stat_id);
	mpip_log("delay = %d\n",   cm->delay);
	mpip_log("timestamp = %d\n",   cm->timestamp);
	mpip_log("flags = %d\n",   cm->flags);
	print_addr(cm->addr1);
	print_addr(cm->addr2);
	mpip_log("checksum = %d\n",   cm->checksum);
}
EXPORT_SYMBOL(print_mpip_cm);

unsigned char *get_node_id(void)
{
	struct net_device *dev;

	if (static_node_id)
		return static_node_id;


	for_each_netdev(&init_net, dev)
	{
		if (strstr(dev->name, "lo"))
			continue;

		static_node_id = kzalloc(MPIP_CM_NODE_ID_LEN, GFP_ATOMIC);
		memcpy(static_node_id, dev->perm_addr + ETH_ALEN - MPIP_CM_NODE_ID_LEN, MPIP_CM_NODE_ID_LEN);
		return static_node_id;
	}

	return NULL;
}

unsigned char get_session_id(unsigned char *src_node_id, unsigned char *dst_node_id,
					__be32 saddr, __be16 sport,
					__be32 daddr, __be16 dport,
					unsigned int protocol,
					bool *is_new)
{

	struct socket_session_table *socket_session = NULL;
	mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
	if (!src_node_id || !dst_node_id)
	{
		printk("%s, %d\n", __FILE__, __LINE__);
		return 0;
	}
	mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
	socket_session = get_sender_session(saddr, sport, daddr, dport, protocol);

	if (!socket_session)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		print_addr(saddr);
		print_addr(daddr);
		mpip_log("%d, %d, %s, %d\n", sport, dport, __FILE__, __LINE__);

		*is_new = true;
		if (src_node_id && dst_node_id)
		{
			add_sender_session(src_node_id, dst_node_id, saddr, sport, daddr, dport, protocol);
			socket_session = get_sender_session(saddr, sport, daddr, dport, protocol);
			add_path_info_tcp(dst_node_id, saddr, daddr, sport, dport, socket_session->session_id, protocol);
		}
	}
	else
	{
//		mpip_log("%s, %d\n", __FILE__, __LINE__);
		*is_new = false;
	}

	return socket_session->session_id;
}

unsigned char get_path_id(unsigned char *node_id,
		__be32 *saddr, __be32 *daddr, __be16 *sport, __be16 *dport,
		__be32 origin_saddr, __be32 origin_daddr, __be16 origin_sport,
		__be16 origin_dport, unsigned char session_id,
		unsigned int protocol, unsigned int len)
{
	if (!node_id || session_id <= 0)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	return find_fastest_path_id(node_id, saddr, daddr, sport, dport,
								origin_saddr, origin_daddr, origin_sport,
								origin_dport, session_id,
								protocol, len);
}


unsigned char get_path_stat_id(unsigned char *dest_node_id,  __s32 *delay)
{
	if (!dest_node_id)
		return 0;

	if (dest_node_id[0] == dest_node_id[1])
	{
		return 0;
	}

	return find_earliest_path_stat_id(dest_node_id,  delay);
}

bool check_bad_addr(__be32 addr)
{
	__be32 myaddr = convert_addr(127, 0, 0, 1);
	if (myaddr == addr)
		return false;

	myaddr = convert_addr(127, 0, 1, 1);
	if (myaddr == addr)
		return false;

	myaddr = convert_addr(192, 168, 1, 1);
	if (myaddr == addr)
		return false;

	myaddr = convert_addr(192, 168, 2, 1);
	if (myaddr == addr)
		return false;

	myaddr = convert_addr(224, 0, 0, 251);
	if (myaddr == addr)
		return false;

	if (((addr & 0xff) == 255) || ((addr>>8 & 0xff) == 255) || ((addr>>16 & 0xff) == 255) || ((addr>>24 & 0xff) == 255))
		return false;

	return true;
}

__s16 calc_checksum(unsigned char *cm)
{
	__s16 checksum = 0;
	int i;
	if (!cm)
		return 0;

	for (i = 0; i < MPIP_CM_LEN - 2; ++i)
		checksum += cm[i];

	return checksum;
}

bool get_skb_port(struct sk_buff *skb, __be16 *sport, __be16 *dport)
{
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;

	if (!skb)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	iph = ip_hdr(skb);

	if((iph->protocol != IPPROTO_TCP) && (iph->protocol != IPPROTO_UDP))
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	//if TCP PACKET
	if (iph->protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(skb); //this fixed the problem
		if (!tcph)
		{
			mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return false;
		}

		*sport = tcph->source; //sport now has the source port
		*dport = tcph->dest;   //dport now has the dest port

	}
	else if(iph->protocol == IPPROTO_UDP)
	{
		udph = udp_hdr(skb); //this fixed the problem
		if (!udph)
		{
			mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return false;
		}

		*sport = udph->source; //sport now has the source port
		*dport = udph->dest;   //dport now has the dest port
	}
	else
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	return true;
}

bool is_syn_pkt(struct sk_buff *skb)
{
	struct tcphdr *tcph = NULL;

	if (!skb)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	tcph = tcp_hdr(skb);

	if (tcph->syn && !tcph->ack)
	{
		return true;
	}

	return false;
}

bool is_synack_pkt(struct sk_buff *skb)
{
	struct tcphdr *tcph = NULL;

	if (!skb)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	tcph = tcp_hdr(skb);

	if (tcph->syn && tcph->ack)
	{
		return true;
	}

	return false;
}

bool is_ack_pkt(struct sk_buff *skb)
{
	struct tcphdr *tcph = NULL;

	if (!skb)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	tcph = tcp_hdr(skb);

	if (!tcph->syn && tcph->ack)
	{
		return true;
	}

	return false;
}




void send_mpip_enable(struct sk_buff *skb, bool sender, bool reverse)
{
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	__be32 addr = 0;
	__be16 port = 0;
	struct mpip_enabled_table *item = NULL;

	if (!skb)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return;
	}

	iph = ip_hdr(skb);
	addr = sender ? iph->daddr : iph->saddr;

	if(iph->protocol == IPPROTO_TCP)
	{
		tcph= tcp_hdr(skb);
		if (!tcph)
		{
			mpip_log("%s, %d\n", __FILE__, __LINE__);
			return;
		}
		port = sender ? tcph->dest : tcph->source;
	}
	else if(iph->protocol == IPPROTO_UDP)
	{
		udph= udp_hdr(skb);
		if (!udph)
		{
			mpip_log("%s, %d\n", __FILE__, __LINE__);
			return;
		}
		port = sender ? udph->dest : udph->source;
	}
	else
		return;

	if (is_local_addr(addr) || !check_bad_addr(addr))
		return;

	item = find_mpip_enabled(addr, port);

	//if (item && ((item->sent_count > 3) || (item->mpip_enabled)))
	if (item && item->mpip_enabled)
	{
		return;
	}
	else if (item)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		if (send_mpip_msg(skb, sender, reverse, 3, 0))
			item->sent_count += 1;
	}
	else
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		add_mpip_enabled(addr, port, false);
		send_mpip_msg(skb, sender, reverse, 3, 0);
	}
}

void send_mpip_enabled(struct sk_buff *skb, bool sender, bool reverse)
{
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	if (!skb)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return;
	}

	iph = ip_hdr(skb);
	if(iph->protocol == IPPROTO_TCP)
	{
		tcph= tcp_hdr(skb);
		if (!tcph)
		{
			mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return;
		}

		if (find_mpip_query(iph->saddr, iph->daddr, tcph->source, tcph->dest))
		{
			mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			send_mpip_msg(skb, sender, reverse, 4, 0);
			delete_mpip_query(iph->saddr, iph->daddr, tcph->source, tcph->dest);
		}
	}
	else if (iph->protocol == IPPROTO_UDP)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		send_mpip_msg(skb, sender, reverse, 4, 0);
	}
}

static void reverse_addr_and_port(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	__be32 tmp_addr = 0;
	__be16 tmp_port = 0;

	if (!skb)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return;
	}


	iph = ip_hdr(skb);
	if (iph == NULL)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return;
	}

	tmp_addr = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = tmp_addr;

	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(skb); //this fixed the problem
		if (!tcph)
		{
			mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return;
		}

		tmp_port = tcph->source;
		tcph->source = tcph->dest;
		tcph->dest = tmp_port;

	}
	else if(iph->protocol == IPPROTO_UDP)
	{
		udph = udp_hdr(skb); //this fixed the problem
		if (!udph)
		{
			mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return;
		}
		tmp_port = udph->source;
		udph->source = udph->dest;
		udph->dest = tmp_port;
	}
	else
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return;
	}
}

static bool copy_and_send(struct sk_buff *skb, bool reverse,
		unsigned char flags, unsigned char session_id)
{
	struct iphdr *iph;
	__be32 new_saddr=0, new_daddr=0;
	struct net_device *new_dst_dev = NULL;
	int err = 0;
	struct sk_buff *nskb = NULL;
	struct rtable *rt;

	if(!skb)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return false;
	}
	nskb = skb_copy(skb, GFP_ATOMIC);

	if (nskb == NULL)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return false;
	}

	iph = ip_hdr(nskb);
	if (iph == NULL)
	{
		kfree_skb(nskb);
		printk("%s, %d\n", __FILE__, __LINE__);
		return false;
	}

	rt = skb_rtable(nskb);

	if ((u8 *)iph < nskb->head ||
	    (skb_network_header(nskb) + sizeof(*iph)) >
	    skb_tail_pointer(nskb))
	{
		kfree_skb(nskb);
		printk("%s, %d\n", __FILE__, __LINE__);
		return false;
	}
	/*
	 *	No replies to physical multicast/broadcast
	 */
	if (nskb->pkt_type != PACKET_HOST)
	{
		kfree_skb(nskb);
		printk("%s, %d\n", __FILE__, __LINE__);
		return false;
	}
	/*
	 *	Now check at the protocol level
	 */
	if (rt->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
	{
		kfree_skb(nskb);
		printk("%s, %d\n", __FILE__, __LINE__);
		return false;
	}
	/*
	 *	Only reply to fragment 0. We byte re-order the constant
	 *	mask for efficiency.
	 */
//	if (iph->frag_off & htons(IP_OFFSET))
//	{
//		kfree_skb(nskb);
//		printk("%s, %d\n", __FILE__, __LINE__);
//		return false;
//	}

	if (reverse)
	{
		reverse_addr_and_port(nskb);
	}

	iph = ip_hdr(nskb);

	mpip_log("%d, %d, %s, %s, %d\n", iph->id, ip_hdr(skb)->protocol, __FILE__, __FUNCTION__, __LINE__);
	if (!insert_mpip_cm(nskb, iph->saddr, iph->daddr, &new_saddr, &new_daddr,
			iph->protocol, flags, session_id))
	{
		kfree_skb(nskb);
		printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	if (new_saddr != 0)
	{
		new_dst_dev = find_dev_by_addr(new_saddr);
		if (new_dst_dev)
		{
			iph->saddr = new_saddr;
			iph->daddr = new_daddr;
		}
	}

	if (ip_route_out(nskb, iph->saddr, iph->daddr))
	{
		skb_dst(skb)->dev = find_dev_by_addr(iph->saddr);
		skb->dev = find_dev_by_addr(iph->saddr);

		err = __ip_local_out(nskb);
		if (likely(err == 1))
			err = dst_output(nskb);
	}
	else
	{
		kfree_skb(nskb);
		printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	mpip_log("%d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);

	return true;
}
//
//static bool new_and_send(struct sk_buff *skb_in, bool reverse, unsigned char flags)
//{
//	struct iphdr *iph, *iph_in;
//	struct tcphdr *tcph = NULL;
//	struct udphdr *udph = NULL;
//	__be32 new_saddr=0, new_daddr=0;
//	struct net_device *new_dst_dev = NULL;
//	int err = 0;
//	struct sk_buff *skb = NULL;
//	__be16 srcport, dstport;
//
//    int total_len, eth_len, ip_len, udp_len, header_len;
//
//
//	// 设置各个协议数据长度
//    udp_len = sizeof(*udph);
//    ip_len = eth_len = udp_len + sizeof(*iph);
//    total_len = eth_len + ETH_HLEN + NET_IP_ALIGN;
//    header_len = total_len;
//
//	if(!skb_in)
//	{
//		mpip_log("%s, %d\n", __FILE__, __LINE__);
//		return false;
//	}
//
//	iph_in = ip_hdr(skb_in);
//	if (iph_in == NULL)
//	{
//		printk("%s, %d\n", __FILE__, __LINE__);
//		return false;
//	}
//
//	if(iph_in->protocol == IPPROTO_TCP)
//	{
//		tcph = tcp_hdr(skb_in); //this fixed the problem
//		if (!tcph)
//		{
//			printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
//			return false;
//		}
//		if (reverse)
//		{
//			srcport = tcph->dest;
//			dstport = tcph->source;
//		}
//		else
//		{
//			srcport = tcph->source;
//			dstport = tcph->dest;
//		}
//	}
//	else if(iph_in->protocol == IPPROTO_UDP)
//	{
//		udph = udp_hdr(skb_in); //this fixed the problem
//		if (!udph)
//		{
//			printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
//			return false;
//		}
//
//		if (reverse)
//		{
//			srcport = udph->dest;
//			dstport = udph->source;
//		}
//		else
//		{
//			srcport = udph->source;
//			dstport = udph->dest;
//		}
//	}
//	else
//	{
//		return false;
//	}
//
//
//	skb = alloc_skb(234, GFP_ATOMIC );
//	if ( !skb ) {
//		printk( "alloc_skb fail.\n" );
//		return false;
//	}
//
//	// 预先保留skb的协议首部长度大小
//	skb_reserve(skb, 234);
//
//	skb_orphan(skb);
//
//	if(iph_in->protocol == IPPROTO_TCP)
//	{
//		skb_push(skb, sizeof(struct tcphdr));
//		skb_reset_transport_header(skb);
//		tcph = tcp_hdr(skb);
//
//		tcph->seq = 0;
//		tcph->ack_seq	= 0;
//		tcph->source = srcport;
//		tcph->dest = dstport;
//		tcph->check = 0;
//		tcph->urg_ptr = 0;
//	}
//	else if(iph_in->protocol == IPPROTO_UDP)
//	{
//		skb_push(skb, sizeof(struct udphdr));
//		skb_reset_transport_header(skb);
//		udph = udp_hdr(skb);
//		udph->source = srcport;
//		udph->dest = dstport;
//		udph->len = htons(sizeof(struct udphdr));
//		udph->check = 0;
//	}
//
//	// skb->data 移动到ip首部
//	skb_push(skb, sizeof(struct iphdr));
//	skb_reset_network_header(skb);
//	iph = ip_hdr(skb);
//	iph->version = 4;
//	iph->ihl = 5;
//	iph->tot_len = htons(skb->len);
//	iph->tos      = 0;
//	iph->id       = 0;
//	iph->frag_off = 0;
//	iph->ttl      = 64;
//	iph->protocol = iph_in->protocol;
//	iph->check    = 0;
//
//	if (reverse)
//	{
//		iph->saddr = iph_in->daddr;
//		iph->daddr = iph_in->saddr;
//	}
//	else
//	{
//		iph->saddr = iph_in->saddr;
//		iph->daddr = iph_in->daddr;
//	}
//
//	mpip_log("sending: %d, %s, %s, %d\n", ip_hdr(skb)->id, __FILE__, __FUNCTION__, __LINE__);
//	print_addr(ip_hdr(skb)->saddr);
//	print_addr(ip_hdr(skb)->daddr);
//
//	if (!insert_mpip_cm(skb, iph->saddr, iph->daddr, &new_saddr, &new_daddr,
//			iph->protocol, flags, 0))
//	{
//		kfree_skb(skb);
//		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
//		return false;
//	}
//	iph = ip_hdr(skb);
//
//	mpip_log("sending: %d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
//	print_addr(iph->saddr);
//	print_addr(iph->daddr);
//	if (new_saddr != 0)
//	{
//		new_dst_dev = find_dev_by_addr(new_saddr);
//		if (new_dst_dev)
//		{
//			iph->saddr = new_saddr;
//			iph->daddr = new_daddr;
//
//			mpip_log("sending: %d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
//			print_addr(iph->saddr);
//			print_addr(iph->daddr);
//		}
//	}
//
//	mpip_log("sending: %d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
//	print_addr(iph->saddr);
//	print_addr(iph->daddr);
//
//	if (ip_route_out(skb, iph->saddr, iph->daddr))
//	{
//		skb_dst(skb)->dev = find_dev_by_addr(iph->saddr);
//		skb->dev = find_dev_by_addr(iph->saddr);
//		err = __ip_local_out(skb);
//		if (likely(err == 1))
//			err = dst_output(skb);
//	}
//	else
//	{
//		kfree_skb(skb);
//		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
//		return false;
//	}
//
//	mpip_log("%d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
//
//	return true;
//}
//
//static bool new_udp_and_send(struct sk_buff *skb_in, bool reverse, unsigned char flags)
//{
//	struct iphdr *iph, *iph_in;
//	struct tcphdr *tcph = NULL;
//	struct udphdr *udph = NULL;
//	__be32 new_saddr=0, new_daddr=0;
//	struct net_device *new_dst_dev = NULL;
//	int err = 0;
//	struct sk_buff *skb = NULL;
//	__be16 srcport, dstport;
//
//    int total_len, eth_len, ip_len, udp_len, header_len;
//
//
//	// 设置各个协议数据长度
//    udp_len = sizeof(*udph);
//    ip_len = eth_len = udp_len + sizeof(*iph);
//    total_len = eth_len + ETH_HLEN + NET_IP_ALIGN;
//    header_len = total_len;
//
//	if(!skb_in)
//	{
//		mpip_log("%s, %d\n", __FILE__, __LINE__);
//		return false;
//	}
//
//	iph_in = ip_hdr(skb_in);
//	if (iph_in == NULL)
//	{
//		printk("%s, %d\n", __FILE__, __LINE__);
//		return false;
//	}
//
//	if(iph_in->protocol == IPPROTO_TCP)
//	{
//		tcph = tcp_hdr(skb_in); //this fixed the problem
//		if (!tcph)
//		{
//			printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
//			return false;
//		}
//		if (reverse)
//		{
//			srcport = tcph->dest;
//			dstport = tcph->source;
//		}
//		else
//		{
//			srcport = tcph->source;
//			dstport = tcph->dest;
//		}
//	}
//	else if(iph_in->protocol == IPPROTO_UDP)
//	{
//		udph = udp_hdr(skb_in); //this fixed the problem
//		if (!udph)
//		{
//			printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
//			return false;
//		}
//
//		if (reverse)
//		{
//			srcport = udph->dest;
//			dstport = udph->source;
//		}
//		else
//		{
//			srcport = udph->source;
//			dstport = udph->dest;
//		}
//	}
//
//
//	skb = alloc_skb(234, GFP_ATOMIC );
//	if ( !skb ) {
//		printk( "alloc_skb fail.\n" );
//		return false;
//	}
//
//	// 预先保留skb的协议首部长度大小
//	skb_reserve(skb, 234);
//
//	// skb->data 移动到udp首部
//	skb_push(skb, sizeof(struct udphdr));
//	skb_reset_transport_header(skb);
//	udph = udp_hdr(skb);
//	udph->source = srcport;
//	udph->dest = dstport;
//	udph->len = htons(sizeof(struct udphdr));
//	udph->check = 0;
//
//
//	// skb->data 移动到ip首部
//	skb_push(skb, sizeof(struct iphdr));
//	skb_reset_network_header(skb);
//	iph = ip_hdr(skb);
//	iph->version = 4;
//	iph->ihl = 5;
//	iph->tot_len = htons(skb->len);
//	iph->tos      = 0;
//	iph->id       = 0;
//	iph->frag_off = 0;
//	iph->ttl      = 64;
//	iph->protocol = IPPROTO_UDP;
//	iph->check    = 0;
//
//	if (reverse)
//	{
//		iph->saddr = iph_in->daddr;
//		iph->daddr = iph_in->saddr;
//	}
//	else
//	{
//		iph->saddr = iph_in->saddr;
//		iph->daddr = iph_in->daddr;
//	}
//
//	mpip_log("%d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
//	if (!insert_mpip_cm(skb, iph->saddr, iph->daddr, &new_saddr, &new_daddr,
//			iph->protocol, flags, 0))
//	{
//		kfree_skb(skb);
//		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
//		return false;
//	}
//
//	if (new_saddr != 0)
//	{
//		new_dst_dev = find_dev_by_addr(new_saddr);
//		if (new_dst_dev)
//		{
//			mpip_log("sending: %d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
//			print_addr(iph->saddr);
//			print_addr(iph->daddr);
//			if (ip_route_out(skb, new_saddr, new_daddr))
//			{
//				iph->saddr = new_saddr;
//				iph->daddr = new_daddr;
//				skb_dst(skb)->dev = find_dev_by_addr(iph->saddr);
//				skb->dev = find_dev_by_addr(iph->saddr);
//			}
//			else
//			{
//				kfree_skb(skb);
//				mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
//				return false;
//			}
//
//			mpip_log("sending: %d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
//			print_addr(iph->saddr);
//			print_addr(iph->daddr);
//		}
//	}
//
//	err = __ip_local_out(skb);
//	if (likely(err == 1))
//		err = dst_output(skb);
//
//	mpip_log("%d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
//
//	return true;
//}
//
bool ip_route_out( struct sk_buff *skb, __be32 saddr, __be32 daddr)
{
    struct flowi4 fl = {};
    struct rtable *rt = NULL;

    fl.saddr = saddr;
    fl.daddr = daddr;
    rt = ip_route_output_key(&init_net, &fl);
    if (rt)
    {
		mpip_log( "route output dev=%s\n", rt->dst.dev->name  );
		skb_dst_set_noref(skb, &(rt->dst));
		rt->dst.dev = find_dev_by_addr(saddr);
		mpip_log( "route output dev 1=%s\n", rt->dst.dev->name  );

		return true;
    }
    return false;

}

bool send_mpip_msg(struct sk_buff *skb_in, bool sender, bool reverse,
		unsigned char flags, unsigned char session_id)
{
	//return new_and_send(skb_in, reverse, flags);
	return copy_and_send(skb_in, reverse, flags, session_id);
}


bool send_mpip_syn(struct sk_buff *skb_in, __be32 saddr, __be32 daddr,
		__be16 sport, __be16 dport,	bool syn, bool ack,
		unsigned char session_id)
{
	struct iphdr *iph;
	struct tcphdr *tcph = NULL;
//	__be32 new_saddr=0, new_daddr=0;
//	struct net_device *new_dst_dev = NULL;
	int err = 0;
	struct sk_buff *skb = NULL;
//	struct rtable *rt;

	if (session_id <= 0)
		return false;

	/*
	if(!skb_in)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return false;
	}


	skb = skb_copy(skb_in, GFP_ATOMIC);

	if (skb == NULL)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return false;
	}

	iph = ip_hdr(skb);
	if (iph == NULL)
	{
		kfree_skb(skb);
		printk("%s, %d\n", __FILE__, __LINE__);
		return false;
	}

	rt = skb_rtable(skb);

	if ((u8 *)iph < skb->head ||
	    (skb_network_header(skb) + sizeof(*iph)) >
	    skb_tail_pointer(skb))
	{
		kfree_skb(skb);
		printk("%s, %d\n", __FILE__, __LINE__);
		return false;
	}

	if (skb->pkt_type != PACKET_HOST)
	{
		kfree_skb(skb);
		printk("%s, %d\n", __FILE__, __LINE__);
		return false;
	}

	if (rt->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
	{
		kfree_skb(skb);
		printk("%s, %d\n", __FILE__, __LINE__);
		return false;
	}

	printk("sending syn: %d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);

	iph->saddr = saddr;
	iph->daddr = daddr;
	iph->protocol = IPPROTO_TCP;

	tcph = tcp_hdr(skb);

	tcph->source = sport;
	tcph->dest = dport;

	if (syn)
	{
		tcph->syn = 1;
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_SYN;
	}
	if (ack)
	{
		tcph->ack = 1;
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_ACK;
	}

	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum = 0;

	TCP_SKB_CB(skb)->sacked = 0;

	skb_shinfo(skb)->gso_segs = 1;
	skb_shinfo(skb)->gso_size = 0;
	skb_shinfo(skb)->gso_type = 0;

	TCP_SKB_CB(skb)->seq = 0;
	TCP_SKB_CB(skb)->end_seq = 0;
	if (TCP_SKB_CB(skb)->tcp_flags & (TCPHDR_SYN | TCPHDR_FIN))
	{
		TCP_SKB_CB(skb)->end_seq = 1;
	}

	tcph->seq = 0;
	tcph->ack_seq	= 0;
	tcph->source = sport;
	tcph->dest = dport;
	tcph->check = 0;
	tcph->urg_ptr = 0;
*/

	skb = alloc_skb(255, GFP_ATOMIC );
	if ( !skb ) {
		printk( "alloc_skb fail.\n" );
		return false;
	}

	skb_reserve(skb, MAX_TCP_HEADER);
//
//	skb_orphan(skb);

	skb_push(skb, sizeof(struct tcphdr));
	skb_reset_transport_header(skb);
	tcph = tcp_hdr(skb);

	if (syn && !ack)
	{
		tcph->res1 = 0;
		tcph->syn = 1;
		tcph->ack = 0;
		tcph->psh = 0;
		tcph->fin = 0;
		tcph->rst = 0;
		tcph->urg = 0;
		tcph->cwr = 0;
		tcph->ece = 0;
		TCP_SKB_CB(skb)->tcp_flags = TCPHDR_SYN;

		mpip_log("sending syn: %d, %d, %s, %s, %d\n", sport, dport, __FILE__, __FUNCTION__, __LINE__);
		print_addr(saddr);
		print_addr(daddr);
	}
	if (syn && ack)
	{
		tcph->res1 = 0;
		tcph->syn = 1;
		tcph->ack = 1;
		tcph->psh = 0;
		tcph->fin = 0;
		tcph->rst = 0;
		tcph->urg = 0;
		tcph->cwr = 0;
		tcph->ece = 0;
		TCP_SKB_CB(skb)->tcp_flags = TCPHDR_SYN | TCPHDR_ACK;

		printk("sending synack: %d, %d, %s, %s, %d\n", sport, dport, __FILE__, __FUNCTION__, __LINE__);
		print_addr(saddr);
		print_addr(daddr);
	}
	if (!syn && ack)
	{
		tcph->res1 = 0;
		tcph->syn = 0;
		tcph->ack = 1;
		tcph->psh = 0;
		tcph->fin = 0;
		tcph->rst = 0;
		tcph->urg = 0;
		tcph->cwr = 0;
		tcph->ece = 0;
		TCP_SKB_CB(skb)->tcp_flags = TCPHDR_ACK;

		mpip_log("sending ack: %d, %d, %s, %s, %d\n", sport, dport, __FILE__, __FUNCTION__, __LINE__);
		print_addr(saddr);
		print_addr(daddr);
	}

	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum = 0;

	TCP_SKB_CB(skb)->sacked = 0;

	skb_shinfo(skb)->gso_segs = 1;
	skb_shinfo(skb)->gso_size = 0;
	skb_shinfo(skb)->gso_type = 0;

	TCP_SKB_CB(skb)->seq = 0;
	TCP_SKB_CB(skb)->end_seq = 0;
	if (TCP_SKB_CB(skb)->tcp_flags & (TCPHDR_SYN | TCPHDR_FIN))
	{
		TCP_SKB_CB(skb)->end_seq = 1;
	}

	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->seq = 0;
	tcph->ack_seq	= 0;
//	if (convert_addr(192,168,1,15) == saddr)
//	{
//		tcph->source = 9999;
//	}
//	else
//	{
//		tcph->source = sport;
//	}

	tcph->source = sport;
	tcph->dest = dport;


	tcph->check = 0;
	tcph->urg_ptr = 0;

	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	iph->version = 4;
	iph->ihl = 5;
	iph->tot_len = htons(skb->len);
	iph->tos      = 0;
	iph->id       = 0;
	iph->frag_off = 0;
	iph->ttl      = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check    = 0;

	iph->saddr = saddr;
	iph->daddr = daddr;

	if (!insert_mpip_cm(skb, iph->saddr, iph->daddr, NULL, NULL,
			iph->protocol, 5, session_id))
	{
		kfree_skb(skb);
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	iph = ip_hdr(skb);
	tcph = tcp_hdr(skb);

	if (ip_route_out(skb, iph->saddr, iph->daddr))
	{
		skb_dst(skb)->dev = find_dev_by_addr(iph->saddr);
		skb->dev = find_dev_by_addr(iph->saddr);
		err = __ip_local_out(skb);
		if (likely(err == 1))
			err = dst_output(skb);
	}
	else
	{
		kfree_skb(skb);
		printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}


	return true;
}



bool insert_mpip_cm(struct sk_buff *skb, __be32 old_saddr, __be32 old_daddr,
		__be32 *new_saddr, __be32 *new_daddr, unsigned int protocol,
		unsigned char flags, unsigned char session_id)
{
	int  i;
    struct timespec tv;
	u32  midtime;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	unsigned char *dst_node_id = NULL;
	__be16 sport = 0, dport = 0, new_sport = 0, new_dport = 0;
	unsigned char path_id = 0;
	unsigned char path_stat_id = 0;
	unsigned char *send_cm = NULL;
	__s32 delay = 0;
	__be32 addr1 = 0, addr2 = 0;
	__s16 checksum = 0;

	bool is_new = true;
	if (!skb)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	if((protocol != IPPROTO_TCP) && (protocol != IPPROTO_UDP))
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	if (skb_tailroom(skb) < MPIP_CM_LEN * 2)
	{
		mpip_log("%d, %d, %s, %s, %d\n", skb_tailroom(skb),
				skb->len, __FILE__, __FUNCTION__, __LINE__);
		return false;
	}


	if (flags > 1)
	{
		if (skb->len > 150)
		{
			mpip_log("%d, %d, %s, %s, %d\n", skb_tailroom(skb),
								skb->len, __FILE__, __FUNCTION__, __LINE__);
			skb->tail -= MPIP_CM_LEN + 1;
			skb->len  -= MPIP_CM_LEN + 1;

//			if (pskb_expand_head(skb, 0, MPIP_CM_LEN + 1, GFP_ATOMIC))
//			{
//				mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
//				return false;
//			}
		}
	}
	else
	{
		if ((skb_tailroom(skb) < MPIP_CM_LEN + 1) && (protocol == IPPROTO_TCP))
		{
			unsigned int mss = tcp_original_mss(skb->sk);
			unsigned int mss1 = tcp_current_mss(skb->sk);

			mpip_log("%d, %d, %d, %d, %s, %s, %d\n", skb_tailroom(skb),
					skb->len, mss, mss1, __FILE__, __FUNCTION__, __LINE__);

			if ((mss - (skb->len - 32)) < (MPIP_CM_LEN + 1))
			{
				mpip_log("%d, %d, %s, %d\n", skb->len, mss, __FILE__, __LINE__);
				return false;
			}
		}
	}

	if (!check_bad_addr(old_saddr) || !check_bad_addr(old_daddr))
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	if (!get_skb_port(skb, &sport, &dport))
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	send_cm = skb_tail_pointer(skb) + 1;

	dst_node_id = find_node_id_in_working_ip(old_daddr, dport, protocol);

	get_node_id();
	get_available_local_addr();

	addr1 = get_local_addr1();
	addr2 = get_local_addr2();

	send_mpip_cm.len = send_cm[0] = MPIP_CM_LEN;

	for(i = 0; i < MPIP_CM_NODE_ID_LEN; i++)
    	send_mpip_cm.node_id[i] = send_cm[1 + i] =  static_node_id[i];

	if (session_id > 0)
	{
		send_mpip_cm.session_id = send_cm[3] = session_id;
	}
	else if (flags < 2)
    {
		send_mpip_cm.session_id = send_cm[3] = get_session_id(static_node_id, dst_node_id,
												old_saddr, sport,
												old_daddr, dport, protocol, &is_new);
    }
    else
    {
    	send_mpip_cm.session_id = send_cm[3] = 0;
    }

    if ((!is_new || flags == 2) && new_saddr)
    {
    	path_id = get_path_id(dst_node_id, new_saddr, new_daddr, &new_sport, &new_dport,
    							old_saddr, old_daddr, sport, dport,
    							send_mpip_cm.session_id, protocol, skb->len);
    }

    path_stat_id = get_path_stat_id(dst_node_id, &delay);

    send_mpip_cm.path_id = send_cm[4] = path_id;
    send_mpip_cm.path_stat_id = send_cm[5] = path_stat_id;

    getnstimeofday(&tv);
    send_mpip_cm.timestamp = midtime = (tv.tv_sec % 86400) * MSEC_PER_SEC * 100  + 100 * tv.tv_nsec / NSEC_PER_MSEC;

	send_cm[6] = midtime & 0xff;
	send_cm[7] = (midtime>>8) & 0xff;
	send_cm[8] = (midtime>>16) & 0xff;
	send_cm[9] = (midtime>>24) & 0xff;

	send_mpip_cm.delay = delay;

	send_cm[10] = delay & 0xff;
	send_cm[11] = (delay>>8) & 0xff;
	send_cm[12] = (delay>>16) & 0xff;
	send_cm[13] = (delay>>24) & 0xff;

	send_mpip_cm.addr1 = addr1;

	send_cm[14] = addr1 & 0xff;
	send_cm[15] = (addr1>>8) & 0xff;
	send_cm[16] = (addr1>>16) & 0xff;
	send_cm[17] = (addr1>>24) & 0xff;

	send_mpip_cm.addr2 = addr2;

	send_cm[18] = addr2 & 0xff;
	send_cm[19] = (addr2>>8) & 0xff;
	send_cm[20] = (addr2>>16) & 0xff;
	send_cm[21] = (addr2>>24) & 0xff;

	if (get_addr_notified(dst_node_id))
		send_mpip_cm.flags = send_cm[22] = 0;
	else
		send_mpip_cm.flags = send_cm[22] = 1;

	if (flags > 1)
		send_mpip_cm.flags = send_cm[22] = flags;

	checksum = calc_checksum(send_cm);

	send_mpip_cm.checksum = checksum;
	send_cm[23] = checksum & 0xff;
	send_cm[24] = (checksum>>8) & 0xff;


	if (new_saddr && ((*new_saddr) > 0))
	{
		mpip_log("sending: %d, %d, %d, %d, %s, %s, %d\n", ip_hdr(skb)->id,
				ip_hdr(skb)->protocol, sport, dport, __FILE__, __FUNCTION__,
				__LINE__);
		print_addr(*new_saddr);
		print_addr(*new_daddr);
	}
	else
	{
		mpip_log("sending: %d, %d, %d, %d, %s, %s, %d\n", ip_hdr(skb)->id,
				ip_hdr(skb)->protocol, sport, dport, __FILE__, __FUNCTION__,
				__LINE__);
		print_addr(ip_hdr(skb)->saddr);
		print_addr(ip_hdr(skb)->daddr);
	}
	print_mpip_cm(&send_mpip_cm);
	skb_put(skb, MPIP_CM_LEN + 1);


	if(protocol == IPPROTO_TCP)
	{
		bool inited = (new_dport != 0);
		bool origin = false;
		if (inited)
		{
			origin = is_original_path(dst_node_id, *new_saddr, *new_daddr,
										new_sport, new_dport, send_mpip_cm.session_id);
		}

		if (sysctl_mpip_use_tcp || !inited || origin)
		{
			tcph = tcp_hdr(skb); //this fixed the problem
			if (!tcph)
			{
				mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
				return false;
			}

			if (new_dport != 0)
			{
				mpip_log("Sending change port: %d, %d, %d, %s, %s, %d\n", ip_hdr(skb)->id,
								 new_sport, new_dport, __FILE__, __FUNCTION__, __LINE__);
				tcph->source = new_sport;
				tcph->dest = new_dport;
			}

			tcph->check = 0;
			tcph->check = csum_tcpudp_magic(old_saddr, old_daddr,
											skb->len, protocol,
											csum_partial((char *)tcph, skb->len, 0));

			skb->ip_summed = CHECKSUM_UNNECESSARY;
		}
		else
		{
			unsigned char *tmp = kzalloc(sizeof(struct iphdr), GFP_ATOMIC);

			if (!tmp)
			{
				mpip_log("tmp == NULL\n");
				return 0;
			}

			unsigned char *myiph = skb_network_header(skb);
			memcpy(tmp, myiph, sizeof(struct iphdr));
			memcpy(myiph - 8, tmp, sizeof(struct iphdr));
			kfree(tmp);

			skb_push(skb, 8);
			skb_reset_network_header(skb);
			skb_set_transport_header(skb, sizeof(struct iphdr));

			struct iphdr *iph = ip_hdr(skb);
			iph->protocol = IPPROTO_UDP;
			udph = udp_hdr(skb); //this fixed the problem
			if (!udph)
			{
				mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
				return false;
			}
			if (new_dport != 0)
			{
				udph->source = new_sport;
				udph->dest = new_dport;
			}

			//udph->len = skb->len - iph->ihl * 4;

			udph->len = htons(skb->len - iph->ihl * 4);
			udph->check = 0;
			udph->check = csum_tcpudp_magic(old_saddr, old_daddr,
										   skb->len, protocol,
										   csum_partial((char *)udph, skb->len, 0));
			skb->ip_summed = CHECKSUM_UNNECESSARY;

			mpip_log("sending: %d, %d, %d, %d, %d, %s, %s, %d\n", ip_hdr(skb)->id, ntohs(udph->len),
							ip_hdr(skb)->protocol, sport, dport, __FILE__, __FUNCTION__,
							__LINE__);
		}
	}
	else if(protocol == IPPROTO_UDP)
	{
		udph = udp_hdr(skb); //this fixed the problem
		if (!udph)
		{
			mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return false;
		}
		if (new_dport != 0)
		{
			udph->source = new_sport;
			udph->dest = new_dport;
		}

		mpip_log("UDP: %d, %d, %s, %s, %d\n", ntohs(udph->len), ip_hdr(skb)->protocol,
					__FILE__, __FUNCTION__,	__LINE__);

		udph->len = htons(ntohs(udph->len) + MPIP_CM_LEN + 1);
		udph->check = 0;
		udph->check = csum_tcpudp_magic(old_saddr, old_daddr,
									   skb->len, protocol,
									   csum_partial((char *)udph, skb->len, 0));
		skb->ip_summed = CHECKSUM_UNNECESSARY;

		mpip_log("UDP: %d, %d, %s, %s, %d\n", ntohs(udph->len), ip_hdr(skb)->protocol,
					__FILE__, __FUNCTION__,	__LINE__);
	}

	return true;
}
EXPORT_SYMBOL(insert_mpip_cm);


int process_mpip_cm(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
//	int  res;

//	struct net_device *new_dst_dev = NULL;
	__be32 saddr = 0, daddr = 0;
	__be16 sport = 0, dport = 0;
	__be16 osport = 0, odport = 0;
	struct socket_session_table *socket_session = NULL;
	unsigned char *rcv_cm = NULL;
	__s16 checksum = 0;

	if (!skb)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		goto fail;
	}

	iph = ip_hdr(skb);

	if((iph->protocol != IPPROTO_TCP) && (iph->protocol != IPPROTO_UDP))
	{
		printk("%d, %s, %s, %d\n", iph->protocol, __FILE__, __FUNCTION__, __LINE__);
		goto fail;
	}

	if(iph->protocol == IPPROTO_TCP)
	{
		tcph= tcp_hdr(skb);
		if (!tcph)
		{
			mpip_log("%s, %d\n", __FILE__, __LINE__);
			goto fail;
		}
		osport = htons((unsigned short int) tcph->source);
		odport = htons((unsigned short int) tcph->dest);
		sport = tcph->source;
		dport = tcph->dest;
	}
	else if(iph->protocol == IPPROTO_UDP)
	{
		udph= udp_hdr(skb);
		if (!udph)
		{
			mpip_log("%s, %d\n", __FILE__, __LINE__);
			goto fail;
		}
		osport = htons((unsigned short int) udph->source);
		odport = htons((unsigned short int) udph->dest);
		sport = udph->source;
		dport = udph->dest;
	}

	rcv_cm = skb_tail_pointer(skb) - MPIP_CM_LEN;

	if ((rcv_cm[0] != MPIP_CM_LEN) || (rcv_cm[22] > 5))
	{
		mpip_log("%d, %d, %s, %s, %d\n", rcv_cm[0], rcv_cm[14], __FILE__, __FUNCTION__, __LINE__);
		goto fail;
	}

	rcv_mpip_cm.len 			= rcv_cm[0];
	rcv_mpip_cm.node_id[0] 		= rcv_cm[1];
	rcv_mpip_cm.node_id[1]		= rcv_cm[2];
	rcv_mpip_cm.session_id		= rcv_cm[3];
	rcv_mpip_cm.path_id  		= rcv_cm[4];
	rcv_mpip_cm.path_stat_id  	= rcv_cm[5];
	rcv_mpip_cm.timestamp  		= (rcv_cm[9]<<24 | rcv_cm[8]<<16 |
				   	   	    	rcv_cm[7]<<8 | rcv_cm[6]);
	rcv_mpip_cm.delay 	 		= (rcv_cm[13]<<24 | rcv_cm[12]<<16 |
				   	   	    	rcv_cm[11]<<8 | rcv_cm[10]);
	rcv_mpip_cm.addr1 	 		= (rcv_cm[17]<<24 | rcv_cm[16]<<16 |
					   	   	    	rcv_cm[15]<<8 | rcv_cm[14]);
	rcv_mpip_cm.addr2 	 		= (rcv_cm[21]<<24 | rcv_cm[20]<<16 |
						   	   	    	rcv_cm[19]<<8 | rcv_cm[18]);
	rcv_mpip_cm.flags 			= rcv_cm[22];
	rcv_mpip_cm.checksum 		= (rcv_cm[24]<<8 | rcv_cm[23]);

	print_mpip_cm(&rcv_mpip_cm);

	checksum = calc_checksum(rcv_cm);
	if (checksum != (rcv_cm[24]<<8 | rcv_cm[23]))
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		mpip_log("%d, %d, %d, %d\n", rcv_cm[23], rcv_cm[24], checksum, (rcv_cm[24]<<8 | rcv_cm[23]));
		goto fail;
	}

	skb->tail -= MPIP_CM_LEN + 1;
	skb->len  -= MPIP_CM_LEN + 1;

	if ((iph->protocol == IPPROTO_TCP) && (rcv_mpip_cm.session_id > 0))
	{

		if ((odport > 6000) && is_original_path(rcv_mpip_cm.node_id,
				iph->daddr, iph->saddr, dport, sport, rcv_mpip_cm.session_id))
		{
			if (sysctl_mpip_use_tcp)
			{
				init_mpip_tcp_connection(rcv_mpip_cm.addr1, rcv_mpip_cm.addr2,
						iph->daddr, iph->saddr, dport, sport,
						rcv_mpip_cm.session_id);
			}
			else
			{
				add_path_info_udp(rcv_mpip_cm.node_id, rcv_mpip_cm.addr1, dport,
						sport, rcv_mpip_cm.session_id, iph->protocol);
				add_path_info_udp(rcv_mpip_cm.node_id, rcv_mpip_cm.addr2, dport,
						sport, rcv_mpip_cm.session_id, iph->protocol);
			}
		}
//		check_path_info_status(skb, rcv_mpip_cm.node_id, rcv_mpip_cm.session_id);
	}

	if (rcv_mpip_cm.flags == 5)
	{
		mpip_log("receiving syn: %d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
		if (is_syn_pkt(skb))
		{
			mpip_log("receiving syn: %d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
			send_mpip_syn(skb, iph->daddr, iph->saddr, tcph->dest, tcph->source,
					true, true, rcv_mpip_cm.session_id);

			goto msg_pkt;
		}
		else if (is_synack_pkt(skb))
		{
			mpip_log("receiving synack: %d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
			send_mpip_syn(skb, iph->daddr, iph->saddr, tcph->dest, tcph->source,
					false, true, rcv_mpip_cm.session_id);

			ready_path_info(rcv_mpip_cm.node_id, iph->daddr, iph->saddr,
					tcph->dest, tcph->source, rcv_mpip_cm.session_id);

			goto msg_pkt;
		}
		else if (is_ack_pkt(skb))
		{
			mpip_log("receiving ack: %d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
			ready_path_info(rcv_mpip_cm.node_id, iph->daddr, iph->saddr, tcph->dest, tcph->source, rcv_mpip_cm.session_id);

			goto msg_pkt;
		}
	}


	get_available_local_addr();

	add_mpip_enabled(iph->saddr, sport, true);
	add_addr_notified(rcv_mpip_cm.node_id);
	process_addr_notified_event(rcv_mpip_cm.node_id, rcv_mpip_cm.flags);

	add_working_ip(rcv_mpip_cm.node_id, iph->saddr, sport, rcv_mpip_cm.session_id, iph->protocol);
	add_path_stat(rcv_mpip_cm.node_id, rcv_mpip_cm.path_id);

	update_path_stat_delay(rcv_mpip_cm.node_id, rcv_mpip_cm.path_id, rcv_mpip_cm.timestamp);
	update_path_delay(rcv_mpip_cm.path_stat_id, rcv_mpip_cm.delay);

	socket_session = get_receiver_session(static_node_id,
										rcv_mpip_cm.node_id,
										iph->daddr, dport,
										iph->saddr, sport,
										rcv_mpip_cm.session_id,
										rcv_mpip_cm.path_id,
										iph->protocol);


	if (iph->protocol == IPPROTO_TCP)
	{
		add_origin_path_info_tcp(rcv_mpip_cm.node_id, iph->daddr, iph->saddr,
				dport, sport, rcv_mpip_cm.session_id, iph->protocol);
	}
	else
	{
		add_path_info_udp(rcv_mpip_cm.node_id, iph->saddr, dport,
				sport, rcv_mpip_cm.session_id, iph->protocol);
	}

//	update_path_info(rcv_mpip_cm.session_id);

	if (rcv_mpip_cm.flags == 3)
	{
		if (iph->protocol == IPPROTO_TCP)
			add_mpip_query(iph->daddr, iph->saddr, dport, sport);
		else
		{
			mpip_log("receiving: %d, %d, %d, %s, %s, %d\n", iph->id, sport, dport, __FILE__, __FUNCTION__, __LINE__);
			print_addr(iph->saddr);
			print_addr(iph->daddr);
			send_mpip_enabled(skb, false, true);
		}
	}

	if (socket_session)
	{
		mpip_log("receiving: %d, %d, %d, %s, %s, %d\n", iph->id, sport, dport, __FILE__, __FUNCTION__, __LINE__);
		print_addr(iph->saddr);
		print_addr(iph->daddr);

		iph->saddr = socket_session->daddr;
		iph->daddr = socket_session->saddr;

		if (iph->protocol == IPPROTO_UDP && socket_session->protocol == IPPROTO_TCP)
		{
			mpip_log("receiving: %d, %d, %d, %s, %s, %d\n", iph->id, sport, dport, __FILE__, __FUNCTION__, __LINE__);
			print_addr(iph->saddr);
			print_addr(iph->daddr);

			unsigned char *tmp = kzalloc(sizeof(struct iphdr), GFP_ATOMIC);

			if (!tmp)
			{
				mpip_log("tmp == NULL\n");
				return 0;
			}

			iph->protocol = IPPROTO_TCP;
			unsigned char *myiph = skb_network_header(skb);
			memcpy(tmp, myiph, sizeof(struct iphdr));
			memcpy(myiph + 8, tmp, sizeof(struct iphdr));
			kfree(tmp);

			skb_pull(skb, 8);
			skb_reset_network_header(skb);
			skb_set_transport_header(skb, sizeof(struct iphdr));

			tcph = tcp_hdr(skb); //this fixed the problem
			if (!tcph)
			{
				mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
				return false;
			}

			mpip_log("Receiving change port: %d, %d, %d, %s, %s, %d\n", ip_hdr(skb)->id,
					socket_session->dport, socket_session->sport, __FILE__, __FUNCTION__, __LINE__);

			tcph->source = socket_session->dport;
			tcph->dest = socket_session->sport;

			iph = ip_hdr(skb);
			mpip_log("receiving: %d, %d, %d, %s, %s, %d\n", iph->id,
					socket_session->dport, socket_session->sport,
					__FILE__, __FUNCTION__, __LINE__);
			print_addr(iph->saddr);
			print_addr(iph->daddr);


		}
		else if(iph->protocol==IPPROTO_TCP && socket_session->protocol == IPPROTO_TCP)
		{
			mpip_log("Receiving change port: %d, %d, %d, %s, %s, %d\n", ip_hdr(skb)->id,
								socket_session->dport, socket_session->sport, __FILE__, __FUNCTION__, __LINE__);

			tcph->source = socket_session->dport;
			tcph->dest = socket_session->sport;
		}
		else if(iph->protocol==IPPROTO_UDP && socket_session->protocol == IPPROTO_UDP)
		{
			mpip_log("Receiving change port: %d, %d, %d, %s, %s, %d\n", ip_hdr(skb)->id,
								socket_session->dport, socket_session->sport, __FILE__, __FUNCTION__, __LINE__);
			udph->source = socket_session->dport;
			udph->dest = socket_session->sport;

		}
	}

	iph = ip_hdr(skb);

	if(iph->protocol==IPPROTO_TCP)
	{
		tcph->check = 0;
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
										skb->len, iph->protocol,
										csum_partial((char *)tcph, skb->len, 0));
		skb->ip_summed = CHECKSUM_UNNECESSARY;

		ip_send_check(iph);
	}
	else if(iph->protocol==IPPROTO_UDP)
	{
		mpip_log("receiving: %d, %d, %d, %s, %s, %d\n", ip_hdr(skb)->id, ntohs(udph->len),
												ip_hdr(skb)->protocol,  __FILE__, __FUNCTION__,
												__LINE__);

		udph->len = htons(ntohs(udph->len) - MPIP_CM_LEN - 1);

		mpip_log("receiving: %d, %d, %d, %s, %s, %d\n", ip_hdr(skb)->id, ntohs(udph->len),
												ip_hdr(skb)->protocol,  __FILE__, __FUNCTION__,
												__LINE__);

		udph->check = 0;
		udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
									   skb->len, iph->protocol,
									   csum_partial((char *)udph, skb->len, 0));
		skb->ip_summed = CHECKSUM_UNNECESSARY;

		ip_send_check(iph);
	}


	if (iph->protocol == IPPROTO_UDP)
	{
		send_mpip_hb(skb, rcv_mpip_cm.session_id);
	}

msg_pkt:
	if (rcv_mpip_cm.flags > 1)
		return 2;

nor_pkt:
	return 1;

fail:
	return 0;
}
EXPORT_SYMBOL(process_mpip_cm);

unsigned char get_tcp_session(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph = NULL;
	__be16 sport = 0, dport = 0;
	struct socket_session_table *socket_session = NULL;

	if (!skb)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return 0;
	}

	iph = ip_hdr(skb);

	if (iph->protocol != IPPROTO_TCP)
		return 0;

	tcph= tcp_hdr(skb); //this fixed the problem
	if (!tcph)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return 0;
	}
	sport = tcph->source;
	dport = tcph->dest;

	socket_session = get_sender_session(iph->daddr, dport, iph->saddr, sport, IPPROTO_TCP);

	if (!socket_session)
		return 0;

	return socket_session->session_id;

}
