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


//int MPIP_OPT_LEN = sizeof(struct mpip_options);
//int MPIP_OPT_LEN = 9;
//int MPIP_OPT_NODE_ID_LEN = 3;
static unsigned char *static_node_id = NULL;
static char log_buf[256];
static char options[MPIP_OPT_LEN];
static struct ip_options_rcu *mp_opt = NULL;

int sysctl_mpip_enabled __read_mostly = 0;
int sysctl_mpip_send __read_mostly = 0;
int sysctl_mpip_rcv __read_mostly = 0;
int sysctl_mpip_log __read_mostly = 0;
int sysctl_mpip_bw_factor __read_mostly = 1;
int sysctl_mpip_bw_1 __read_mostly = 240;
int sysctl_mpip_bw_2 __read_mostly = 60;
int sysctl_mpip_bw_3 __read_mostly = 30;
int sysctl_mpip_bw_4 __read_mostly = 30;
int sysctl_mpip_hb __read_mostly = 10;
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

	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net_device *dev = ifa->ifa_dev->dev;
	struct net *net = dev_net(ifa->ifa_dev->dev);

	if (dev && dev->ip_ptr && dev->ip_ptr->ifa_list)
	{
		printk("%s, %d\n", __FILE__, __LINE__);
		print_addr(__FUNCTION__, dev->ip_ptr->ifa_list->ifa_address);
	}

//	addr4_event_handler(ifa, event, net);

	return NOTIFY_DONE;
}

/* React on ifup/down-events */
static int netdev_event(struct notifier_block *this, unsigned long event,
			void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct in_device *in_dev;
#if IS_ENABLED(CONFIG_IPV6)
	struct inet6_dev *in6_dev;
#endif

	if (!(event == NETDEV_UP || event == NETDEV_DOWN ||
	      event == NETDEV_CHANGE))
		return NOTIFY_DONE;

	rcu_read_lock();
	in_dev = __in_dev_get_rtnl(dev);


	printk("%s, %d\n", __FILE__, __LINE__);

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


static void addr4_event_handler(struct in_ifaddr *ifa, unsigned long event,
				struct net *net)
{
//	struct mptcp_loc_addr *mptcp_local, *old;
//	struct net_device *netdev = ifa->ifa_dev->dev;
//	struct mptcp_fm_ns *fm_ns = fm_get_ns(net);
//	int i;
//
//	if (ifa->ifa_scope > RT_SCOPE_LINK ||
//	    ipv4_is_loopback(ifa->ifa_local))
//		return;
//
//	rcu_read_lock_bh();
//	spin_lock(&fm_ns->local_lock);
//
//	mptcp_local = rcu_dereference(fm_ns->local);
//
//	if (event == NETDEV_DOWN ||!netif_running(netdev) ||
//	    (netdev->flags & IFF_NOMULTIPATH)) {
//		/* It's an event that removes the address */
//		struct mptcp_addr_event event;
//		bool found = false;
//
//		/* Look for the address among the local addresses */
//		mptcp_for_each_bit_set(mptcp_local->loc4_bits, i) {
//			if (mptcp_local->locaddr4[i].addr.s_addr == ifa->ifa_local) {
//				found = true;
//				break;
//			}
//		}
//
//		/* Not in the list - so we don't care */
//		if (!found)
//			goto exit;
//
//		old = mptcp_local;
//		mptcp_local = kmemdup(mptcp_local, sizeof(*mptcp_local),
//				      GFP_ATOMIC);
//		if (!mptcp_local)
//			goto exit;
//		kfree(old);
//
//		mptcp_local->loc4_bits &= ~(1 << i);
//
//		rcu_assign_pointer(fm_ns->local, mptcp_local);
//
//		/* Now, we have to create an event for the MPTCP-sockets */
//		event.code = MPTCP_EVENT_DEL;
//		event.family = AF_INET;
//		event.id = i;
//		event.u.addr4.s_addr = ifa->ifa_local;
//		add_pm_event(net, &event);
//
//	} else {
//		/* The event modifies / adds an address */
//		bool found = false;
//
//		/* Look for the address among the local addresses */
//		mptcp_for_each_bit_set(mptcp_local->loc4_bits, i) {
//			if (mptcp_local->locaddr4[i].addr.s_addr == ifa->ifa_local) {
//				found = true;
//				break;
//			}
//		}
//
//		if (!found) {
//			/* Not in the list, so we have to find an empty slot */
//			i = __mptcp_find_free_index(mptcp_local->loc4_bits, 0,
//						    mptcp_local->next_v4_index);
//			if (i < 0)
//				goto exit;
//		} else {
//			struct mptcp_addr_event event;
//
//			/* Let's check if anything changes */
//			if ((netdev->flags & IFF_MPBACKUP) ? 1 : 0 == mptcp_local->locaddr4[i].low_prio)
//				goto exit;
//
//
//			/* Now, we have to create an event for the MPTCP-sockets */
//			event.code = MPTCP_EVENT_MOD;
//			event.family = AF_INET;
//			event.id = i;
//			event.low_prio = mptcp_local->locaddr4[i].low_prio;
//			event.u.addr4.s_addr = ifa->ifa_local;
//			add_pm_event(net, &event);
//		}
//
//		old = mptcp_local;
//		mptcp_local = kmemdup(mptcp_local, sizeof(*mptcp_local),
//				      GFP_ATOMIC);
//		if (!mptcp_local)
//			goto exit;
//		kfree(old);
//
//		mptcp_local->locaddr4[i].addr.s_addr = ifa->ifa_local;
//		mptcp_local->locaddr4[i].id = i;
//		mptcp_local->locaddr4[i].low_prio = (netdev->flags & IFF_MPBACKUP) ? 1 : 0;
//
//		if (!found) {
//			mptcp_local->loc4_bits |= (1 << i);
//			mptcp_local->next_v4_index = i + 1;
//		}
//
//		rcu_assign_pointer(fm_ns->local, mptcp_local);
//
//		if (!found) {
//			struct mptcp_addr_event event;
//
//			/* Now, we have to create an event for the MPTCP-sockets */
//			event.code = MPTCP_EVENT_ADD;
//			event.family = AF_INET;
//			event.id = i;
//			event.low_prio = mptcp_local->locaddr4[i].low_prio;
//			event.u.addr4.s_addr = ifa->ifa_local;
//			add_pm_event(net, &event);
//		}
//	}
//
//exit:
//	spin_unlock(&fm_ns->local_lock);
//	rcu_read_unlock_bh();
//	return;
}

static struct notifier_block mpip_inetaddr_notifier = {
		.notifier_call = mpip_inetaddr_event,
};

int mpip_init(void)
{
	struct ctl_table_header *mptcp_sysctl;
	int ret;
    //In kernel, __MPIP__ will be checked to decide which functions to call.
	mptcp_sysctl = register_net_sysctl(&init_net, "net/mpip", mpip_table);
//	ret = register_inetaddr_notifier(&mpip_inetaddr_notifier);
//	ret = register_netdevice_notifier(&mpip_netdev_notifier);

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

void print_mpip_options(const char *prefix, struct ip_options *opt)
{
	prefix = NULL;
	if (prefix)
	{
		mpip_log("%s: optlen = %d\n", prefix, opt->optlen);
		mpip_log("%s: node_id= ");
		print_node_id(NULL, opt->node_id);
		mpip_log("%s: session_id = %d\n", prefix, opt->session_id);
		mpip_log("%s: path_id = %d\n",  prefix, opt->path_id);
		mpip_log("%s: stat_path_id = %d\n",  prefix, opt->stat_path_id);
		mpip_log("%s: delay = %d\n",  prefix, opt->delay);
		mpip_log("%s: nexthop = %d\n",  prefix, opt->nexthop);
	}
	else
	{
		mpip_log("optlen = %d\n", opt->optlen);
		mpip_log("node_id = ");
		print_node_id(NULL, opt->node_id);
		mpip_log("session_id = %d\n", opt->session_id);
		mpip_log("path_id = %d\n", opt->path_id);
		mpip_log("stat_path_id = %d\n", opt->stat_path_id);
		mpip_log("delay = %d\n", opt->delay);
		mpip_log("nexthop = %d\n", opt->nexthop);
	}
}
EXPORT_SYMBOL(print_mpip_options);

unsigned char *get_node_id(void)
{
	struct net_device *dev;

	if (static_node_id)
		return static_node_id;


	for_each_netdev(&init_net, dev)
	{
		if (strstr(dev->name, "lo"))
			continue;

		static_node_id = kzalloc(MPIP_OPT_NODE_ID_LEN, GFP_ATOMIC);
		memcpy(static_node_id, dev->perm_addr, MPIP_OPT_NODE_ID_LEN);
		return static_node_id;
	}

	return NULL;
}

unsigned char get_session_id(unsigned char *src_node_id, unsigned char *dst_node_id,
					__be32 saddr, __be16 sport,
					__be32 daddr, __be16 dport, bool *is_new)
{

	unsigned char session_id;

	if (!src_node_id || !dst_node_id)
		return 0;

	session_id = get_sender_session(saddr, sport, daddr, dport);

	if (session_id == 0)
	{
		//printk("%s, %d\n", __FILE__, __LINE__);
//		print_addr(__FUNCTION__, saddr);
//		print_addr(__FUNCTION__, daddr);
		//printk("%d, %d, %s, %d\n", sport, dport, __FILE__, __LINE__);

		*is_new = true;
		if (src_node_id && dst_node_id)
		{
			add_sender_session(src_node_id, dst_node_id, saddr, sport, daddr, dport);
			session_id = get_sender_session(saddr, sport, daddr, dport);
		}
	}
	else
	{
//		mpip_log("%s, %d\n", __FILE__, __LINE__);
		*is_new = false;
	}

	return session_id;
}

unsigned char get_path_id(unsigned char *node_id, __be32 *saddr, __be32 *daddr,
						  __be32 origin_saddr, __be32 origin_daddr)
{
	if (node_id == NULL)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	return find_fastest_path_id(node_id, saddr, daddr,
								origin_saddr, origin_daddr);
}


unsigned char get_path_stat_id(unsigned char *dest_node_id,  __s32 *delay)
{
	if (!dest_node_id)
		return 0;

	if (dest_node_id[0] == dest_node_id[1])
	{
		return 0;
	}

	return find_earliest_stat_path_id(dest_node_id,  delay);
}

bool check_bad_addr(__be32 saddr, __be32 daddr)
{
	__be32 addr = convert_addr(127, 0, 0, 1);
	if ((addr == saddr) || (addr == daddr))
		return false;

	addr = convert_addr(127, 0, 1, 1);
	if ((addr == saddr) || (addr == daddr))
		return false;

	addr = convert_addr(192, 168, 1, 1);
	if ((addr == saddr) || (addr == daddr))
		return false;

//	addr = convert_addr(192, 168, 2, 1);
//	if ((addr == saddr) || (addr == daddr))
//		return false;

	addr = convert_addr(224, 0, 0, 251);
	if ((addr == saddr) || (addr == daddr))
		return false;

	return true;
}

int get_mpip_options(struct sk_buff *skb, __be32 old_saddr, __be32 old_daddr,
		__be32 *new_saddr, __be32 *new_daddr, unsigned char *options)
{
	struct sock *sk = skb->sk;
//	struct inet_sock *inet = inet_sk(sk);
	int  i;
    struct timespec tv;
	u32  midtime;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	unsigned char *dst_node_id = NULL;
//	__be32 saddr = 0, daddr = 0;
	__be16 sport = 0, dport = 0;
	__be16 osport = 0, odport = 0;
	unsigned char path_id = 0;
	unsigned char path_stat_id = 0;

	__s32 delay = 0;
	bool is_new = true;

	if (!skb)
	{
//		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return 0;
	}

	if(sk->sk_protocol != IPPROTO_TCP && sk->sk_protocol != IPPROTO_UDP && sk->sk_protocol != IPPROTO_ICMP)
		return 0;

	if (!check_bad_addr(old_saddr, old_daddr))
	{
//		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return 0;
	}

	dst_node_id = find_node_id_in_working_ip(old_daddr);

	//if TCP PACKET
	if(sk->sk_protocol==IPPROTO_TCP)
	{
	    //tcp_header = (struct tcphdr *)skb_transport_header(sock_buff); //doing the cast this way gave me the same problem

//		tcph= (struct tcphdr *)((__u32 *)iph + iph->ihl); //this fixed the problem
		tcph = tcp_hdr(skb); //this fixed the problem
		if (!tcph)
		{
//			mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return 0;
		}
		osport = htons((unsigned short int) tcph->source); //sport now has the source port
		odport = htons((unsigned short int) tcph->dest);   //dport now has the dest port
		sport = tcph->source; //sport now has the source port
		dport = tcph->dest;   //dport now has the dest port

	}
	else if(sk->sk_protocol==IPPROTO_UDP)
	{
		udph = udp_hdr(skb); //this fixed the problem
		if (!udph)
		{
//			mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return 0;
		}
		osport = htons((unsigned short int) udph->source); //sport now has the source port
		odport = htons((unsigned short int) udph->dest);   //dport now has the dest port
		sport = udph->source; //sport now has the source port
		dport = udph->dest;   //dport now has the dest port
	}
	else if (sk->sk_protocol!=IPPROTO_ICMP)
	{
//		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return 0;
	}

	get_node_id();
	get_available_local_addr();


	options[0] = IPOPT_MPIP;
	options[1] = MPIP_OPT_LEN;

    for(i = 0; i < MPIP_OPT_NODE_ID_LEN; i++)
    	options[2 + i] =  static_node_id[i];


    if (sk->sk_protocol!=IPPROTO_ICMP)
    {
		options[4] = get_session_id(static_node_id, dst_node_id,
									old_saddr, sport,
									old_daddr, dport, &is_new);
    }
    else
    {
    	options[4] = 0;
    }

    if (sk->sk_protocol == IPPROTO_ICMP || !is_new)
    {
//    	mpip_log("%s, %d\n", __FILE__, __LINE__);
    	path_id = get_path_id(dst_node_id, new_saddr, new_daddr,
    							old_saddr, old_daddr);
    }

    path_stat_id = get_path_stat_id(dst_node_id, &delay);

    options[5] = (((path_id << 4) & 0xf0) | (path_stat_id & 0x0f));

    getnstimeofday(&tv);
	midtime = (tv.tv_sec % 86400) * MSEC_PER_SEC * 100  + 100 * tv.tv_nsec / NSEC_PER_MSEC;

	options[6] = midtime & 0xff;
	options[7] = (midtime>>8) & 0xff;
	options[8] = (midtime>>16) & 0xff;
	options[9] = (midtime>>24) & 0xff;

	options[10] = delay & 0xff;
	options[11] = (delay>>8) & 0xff;
	options[12] = (delay>>16) & 0xff;
	options[13] = (delay>>24) & 0xff;


//mpip_log("\ns: iph->id=%d\n", iph->id);
//    mpip_log("s: old_saddr=");
//	print_addr(NULL, old_saddr);
//
//	mpip_log("s: new_saddr=");
//	print_addr(NULL, *new_saddr);
//
//	mpip_log("s: old_daddr=");
//	print_addr(NULL, old_daddr);
//
//	mpip_log("s: new_daddr=");
//	print_addr(NULL, *new_daddr);
//
//	if(sk->sk_protocol==IPPROTO_TCP)
//	{
//		mpip_log("s: tcph->source= %d, osport=%d, sport=%d\n", tcph->source, osport, sport);
//		mpip_log("s: tcph->dest= %d, odport=%d, dport=%d\n", tcph->dest, odport, dport);
//	}
//	else if(sk->sk_protocol==IPPROTO_UDP)
//	{
//		mpip_log("s: udph->source= %d, osport=%d, sport=%d\n", udph->source, osport, sport);
//		mpip_log("s: udph->dest= %d, odport=%d, dport=%d\n", udph->dest, odport, dport);
//	}

    return 1;

}
EXPORT_SYMBOL(get_mpip_options);


int process_mpip_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	struct iphdr *iph;
	struct net_device *dev;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	int  res;
//	unsigned char *tmp = NULL;
//	unsigned char *iph_addr;

	struct net_device *new_dst_dev = NULL;
	__be32 saddr = 0, daddr = 0;
	__be16 sport = 0, dport = 0;
	__be16 osport = 0, odport = 0;
	unsigned char session_id = 0;

	if (!skb)
	{
//		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return 0;
	}

	iph = ip_hdr(skb);

	if (iph->ihl == 5)
		return 0;

	dev = skb->dev;
	opt = &(IPCB(skb)->opt);
	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);
	if (ip_options_compile(dev_net(dev), opt, skb))
	{
//		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		return 0;
	}


	//mpip_log("Receive: %d, %s, %d\n", iph->protocol, __FILE__, __LINE__);

	//if TCP PACKET
	if(iph->protocol == IPPROTO_TCP)
	{
		//tcp_header = (struct tcphdr *)skb_transport_header(sock_buff); //doing the cast this way gave me the same problem
		//tcph= (struct tcphdr *)((__u32 *)iph + iph->ihl); //this fixed the problem
		tcph= tcp_hdr(skb); //this fixed the problem
		if (!tcph)
		{
			mpip_log("%s, %d\n", __FILE__, __LINE__);
			return 0;
		}
		osport = htons((unsigned short int) tcph->source); //sport now has the source port
		odport = htons((unsigned short int) tcph->dest);   //dport now has the dest port
		sport = tcph->source; //sport now has the source port
		dport = tcph->dest;   //dport now has the dest port
	}
	else if(iph->protocol == IPPROTO_UDP)
	{
		udph= udp_hdr(skb); //this fixed the problem
		if (!udph)
		{
			mpip_log("%s, %d\n", __FILE__, __LINE__);
			return 0;
		}
		osport = htons((unsigned short int) udph->source); //sport now has the source port
		odport = htons((unsigned short int) udph->dest);   //dport now has the dest port
		sport = udph->source; //sport now has the source port
		dport = udph->dest;   //dport now has the dest port
	}

	get_available_local_addr();

	if (opt->session_id > 0)
	{
		add_working_ip(opt->node_id, iph->saddr);
		add_path_info(opt->node_id, iph->saddr);
		add_path_stat(opt->node_id, opt->path_id, iph->saddr, iph->daddr);

		update_path_stat_delay(iph->saddr, iph->daddr, opt->nexthop);
		update_path_delay(opt->stat_path_id, opt->delay);

		update_path_info();
	}

	if (iph->protocol != IPPROTO_ICMP)
	{
		session_id = get_receiver_session_id(static_node_id, opt->node_id, iph->daddr, dport,
											iph->saddr, sport, opt->session_id);

		res = get_receiver_session_info(opt->node_id, session_id,
								  &saddr, &sport, &daddr, &dport);
	}

//	mpip_log("r: iph->id=%d\n", iph->id);
//	mpip_log("r: iph->saddr=");
//	print_addr(__FUNCTION__, iph->saddr);
//
//	mpip_log("r: daddr=");
//	print_addr(__FUNCTION__, daddr);
//
//	mpip_log("r: iph->daddr=");
//	print_addr(__FUNCTION__, iph->daddr);
//
//
//	mpip_log("r: saddr=");
//	print_addr(__FUNCTION__, saddr);
//
//	if(iph->protocol==IPPROTO_TCP)
//	{
//		mpip_log("r: tcph->source= %d, osport=%d, dport=%d\n", tcph->source, osport, dport);
//		mpip_log("r: tcph->dest= %d, odport=%d, sport=%d\n", tcph->dest, odport, sport);
//	}
//	else if(iph->protocol==IPPROTO_UDP)
//	{
//		mpip_log("r: udph->source= %d, osport=%d, dport=%d\n", udph->source, osport, dport);
//		mpip_log("r: udph->dest= %d, odport=%d, sport=%d\n", udph->dest, odport, sport);
//	}

//	print_mpip_options(__FUNCTION__, opt);


	if (res && iph->protocol != IPPROTO_ICMP)
	{
//		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
//		mpip_log("r: modifying header\n");
		iph->saddr = daddr;
		iph->daddr = saddr;

//		mpip_log("old_dst_dev: %s, %s, %s, %d\n", skb->dev->name, __FILE__, __FUNCTION__, __LINE__);
		new_dst_dev = find_dev_by_addr(iph->daddr);
		if (new_dst_dev)
		{
			skb->dev = new_dst_dev;
		}

//		mpip_log("new_dst_dev: %s, %s, %s, %d\n", skb->dev->name, __FILE__, __FUNCTION__, __LINE__);
	}

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
			udph->check = 0;
			udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
										   skb->len, iph->protocol,
										   csum_partial((char *)udph, skb->len, 0));
			skb->ip_summed = CHECKSUM_UNNECESSARY;

			ip_send_check(iph);
	}
	else if (iph->protocol == IPPROTO_ICMP)
	{
		mpip_log("Receive ICMP options: %d, %s, %d\n", iph->ihl, __FILE__,  __LINE__);
		print_mpip_options(__FUNCTION__, opt);
	}
	return 1;
}


void mpip_options_build(struct sk_buff *skb, bool pushed)
{
	unsigned char *tmp = NULL;
	unsigned char *iph = skb_network_header(skb);

	if (!pushed)
	{
		tmp = kzalloc(sizeof(struct iphdr), GFP_ATOMIC);
		memcpy(tmp, iph, sizeof(struct iphdr));
		memcpy(iph - mp_opt->opt.optlen, tmp, sizeof(struct iphdr));
		kfree(tmp);

		skb_push(skb, mp_opt->opt.optlen);
		skb_reset_network_header(skb);

		iph = skb_network_header(skb);
	}

	memcpy(&(IPCB(skb)->opt), &(mp_opt->opt), sizeof(struct ip_options));
	memcpy(iph+sizeof(struct iphdr), mp_opt->opt.__data, mp_opt->opt.optlen);
}


static int mpip_options_get(struct net *net, struct ip_options_rcu *opt,
		   unsigned char *data, int optlen)
{
	if (optlen)
		memcpy(opt->opt.__data, data, optlen);

	while (optlen & 3)
		opt->opt.__data[optlen++] = IPOPT_END;
	opt->opt.optlen = optlen;

	if (optlen && ip_options_compile(net, &opt->opt, NULL))
	{
		return -EINVAL;
	}

	return 0;
}

bool mpip_compose_opt(struct sk_buff *skb, __be32 old_saddr, __be32 old_daddr,
		__be32 *new_saddr, __be32 *new_daddr)
{
	int res;

	if (!is_mpip_enabled(old_daddr))
		return false;

	if (!get_mpip_options(skb, old_saddr, old_daddr, new_saddr, new_daddr, options))
		return false;

	if (!mp_opt)
	{
		mp_opt = kzalloc(sizeof(struct ip_options_rcu) + ((MPIP_OPT_LEN + 3) & ~3),
				   GFP_ATOMIC);
	}

	res = mpip_options_get(sock_net(skb->sk), mp_opt, options, MPIP_OPT_LEN);
//	print_mpip_options(__FUNCTION__, &(mp_opt->opt));

	return true;
}

bool insert_mpip_options(struct sk_buff *skb, __be32 *new_saddr, __be32 *new_daddr)
{
	struct iphdr *iph = ip_hdr(skb);
	int res;

	if (!is_mpip_enabled(iph->daddr))
		return false;

	if (!get_mpip_options(skb, iph->saddr, iph->daddr, new_saddr, new_daddr, options))
		return false;

	if (!mp_opt)
		mp_opt = kzalloc(sizeof(struct ip_options_rcu) + ((MPIP_OPT_LEN + 3) & ~3),
			       GFP_ATOMIC);

	res = mpip_options_get(sock_net(skb->sk), mp_opt, options, MPIP_OPT_LEN);

	iph->ihl += (mp_opt->opt.optlen)>>2;

	mpip_options_build(skb, false);

	return true;
}


unsigned char get_session(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph = NULL;
	__be16 sport = 0, dport = 0;
	unsigned char session_id = 0;

	if (!skb)
	{
//		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return 0;
	}

	iph = ip_hdr(skb);

	if (iph->ihl == 5 || iph->protocol != IPPROTO_TCP)
		return 0;

	tcph= tcp_hdr(skb); //this fixed the problem
	if (!tcph)
	{
//		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return 0;
	}
	sport = tcph->source;
	dport = tcph->dest;

	return get_sender_session(iph->daddr, dport, iph->saddr, sport);

}
