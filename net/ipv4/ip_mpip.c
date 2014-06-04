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
int sysctl_mpip_log __read_mostly = 0;
int sysctl_mpip_bw_factor __read_mostly = 50;
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
	struct net_device *dev = NULL;
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	if (ifa && ifa->ifa_dev)
		dev = ifa->ifa_dev->dev;
	else
	{
		dump_stack();
		printk("%s, %d\n", __FILE__, __LINE__);
	}

	if (dev && dev->ip_ptr && dev->ip_ptr->ifa_list)
	{
		if (sysctl_mpip_enabled)
			update_addr_change();
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
	mpip_log("changed = %d\n",   cm->changed);
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
					__be32 daddr, __be16 dport, bool *is_new)
{

	unsigned char session_id;

	if (!src_node_id || !dst_node_id)
		return 0;

	session_id = get_sender_session(saddr, sport, daddr, dport);

	if (session_id == 0)
	{
//		printk("%s, %d\n", __FILE__, __LINE__);
//		print_addr(__FUNCTION__, saddr);
//		print_addr(__FUNCTION__, daddr);
//		printk("%d, %d, %s, %d\n", sport, dport, __FILE__, __LINE__);

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

	return find_earliest_path_stat_id(dest_node_id,  delay);
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

	addr = convert_addr(192, 168, 2, 1);
	if ((addr == saddr) || (addr == daddr))
		return false;

	addr = convert_addr(224, 0, 0, 251);
	if ((addr == saddr) || (addr == daddr))
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

bool insert_mpip_cm(struct sk_buff *skb, __be32 old_saddr, __be32 old_daddr,
		__be32 *new_saddr, __be32 *new_daddr, unsigned int protocol, bool heartbeat)
{
	int  i;
    struct timespec tv;
	u32  midtime;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	unsigned char *dst_node_id = NULL;
	__be16 sport = 0, dport = 0;
	__be16 osport = 0, odport = 0;
	unsigned char path_id = 0;
	unsigned char path_stat_id = 0;
	unsigned char *send_cm = NULL;
	__s32 delay = 0;
	__s16 checksum = 0;
	unsigned int mss = 0;

	bool is_new = true;

	if (!skb)
	{
		printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}


	if((protocol != IPPROTO_TCP) && (protocol != IPPROTO_UDP))
	{
		printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	if (!heartbeat && (skb_tailroom(skb) < MPIP_CM_LEN + 1))
	{
		printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	if (!check_bad_addr(old_saddr, old_daddr))
	{
//		printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

//	if ((protocol == IPPROTO_TCP) && skb->sk)
//	{
//		mss = tcp_current_mss(skb->sk);
//	}

	if (heartbeat && (skb->len > 150))
	{
		skb->tail -= MPIP_CM_LEN + 10;
		skb->len  -= MPIP_CM_LEN + 10;
	}

	send_cm = skb_tail_pointer(skb) + 1;

	dst_node_id = find_node_id_in_working_ip(old_daddr);

	//if TCP PACKET
	if(protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(skb); //this fixed the problem
		if (!tcph)
		{
			printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return false;
		}
		osport = htons((unsigned short int) tcph->source); //sport now has the source port
		odport = htons((unsigned short int) tcph->dest);   //dport now has the dest port
		sport = tcph->source; //sport now has the source port
		dport = tcph->dest;   //dport now has the dest port

	}
	else if(protocol == IPPROTO_UDP)
	{
		udph = udp_hdr(skb); //this fixed the problem
		if (!udph)
		{
			printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return false;
		}
		osport = htons((unsigned short int) udph->source); //sport now has the source port
		odport = htons((unsigned short int) udph->dest);   //dport now has the dest port
		sport = udph->source; //sport now has the source port
		dport = udph->dest;   //dport now has the dest port
	}
	else
	{
		printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
	}

	get_node_id();
	get_available_local_addr();

	send_mpip_cm.len = send_cm[0] = MPIP_CM_LEN;


    for(i = 0; i < MPIP_CM_NODE_ID_LEN; i++)
    	send_mpip_cm.node_id[i] = send_cm[1 + i] =  static_node_id[i];


    send_mpip_cm.session_id = send_cm[3] = get_session_id(static_node_id, dst_node_id,
														old_saddr, sport,
														old_daddr, dport, &is_new);

    if (!is_new || heartbeat)
    {
    	path_id = get_path_id(dst_node_id, new_saddr, new_daddr,
    							old_saddr, old_daddr);
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

	if (get_addr_notified(dst_node_id))
		send_mpip_cm.changed = send_cm[14] = 0;
	else
		send_mpip_cm.changed = send_cm[14] = 1;

	if (heartbeat)
		send_mpip_cm.changed = send_cm[14] = 2;

	checksum = calc_checksum(send_cm);

	send_mpip_cm.checksum = checksum;
	send_cm[15] = checksum & 0xff;
	send_cm[16] = (checksum>>8) & 0xff;

	//mpip_log("sending: %s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
	//mpip_log("%d, %d, %d\n", send_cm[15], send_cm[16], checksum);
	//print_mpip_cm(&send_mpip_cm);

	skb_put(skb, MPIP_CM_LEN + 1);

	if (sysctl_mpip_send)
	{
		if(protocol==IPPROTO_TCP)
		{
			tcph->check = 0;
			tcph->check = csum_tcpudp_magic(old_saddr, old_daddr,
											skb->len, protocol,
											csum_partial((char *)tcph, skb->len, 0));
			skb->ip_summed = CHECKSUM_UNNECESSARY;

		}
		else if(protocol==IPPROTO_UDP)
		{
			udph->check = 0;
			udph->check = csum_tcpudp_magic(old_saddr, old_daddr,
										   skb->len, protocol,
										   csum_partial((char *)udph, skb->len, 0));
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		}
	}

	return true;

}
EXPORT_SYMBOL(insert_mpip_cm);


int process_mpip_cm(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	int  res;

	struct net_device *new_dst_dev = NULL;
	__be32 saddr = 0, daddr = 0;
	__be16 sport = 0, dport = 0;
	__be16 osport = 0, odport = 0;
	unsigned char session_id = 0;
	unsigned char *rcv_cm = NULL;
	__s16 checksum = 0;

	if (!skb)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return 0;
	}

	iph = ip_hdr(skb);

	if((iph->protocol != IPPROTO_TCP) && (iph->protocol != IPPROTO_UDP))
		return 0;

//	mpip_log("receiving: %d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
//	print_addr(iph->saddr);
//	print_addr(iph->daddr);
	rcv_cm = skb_tail_pointer(skb) - MPIP_CM_LEN;

	if ((rcv_cm[0] != MPIP_CM_LEN) || (rcv_cm[14] > 2))
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
//		add_mpip_enabled(iph->saddr, false);
		return 0;
	}

	checksum = calc_checksum(rcv_cm);
	if (checksum != (rcv_cm[16]<<8 | rcv_cm[15]))
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		mpip_log("%d, %d, %d, %d\n", rcv_cm[15], rcv_cm[16], checksum, (rcv_cm[16]<<8 | rcv_cm[15]));

//		add_mpip_enabled(iph->saddr, false);
		return 0;
	}

	skb->tail -= MPIP_CM_LEN + 1;
	skb->len  -= MPIP_CM_LEN + 1;

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
	rcv_mpip_cm.changed 		= rcv_cm[14];
	rcv_mpip_cm.checksum 		= (rcv_cm[16]<<8 | rcv_cm[15]);


//	print_mpip_cm(&rcv_mpip_cm);

	if(iph->protocol == IPPROTO_TCP)
	{
		tcph= tcp_hdr(skb);
		if (!tcph)
		{
			mpip_log("%s, %d\n", __FILE__, __LINE__);
			return 0;
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
			return 0;
		}
		osport = htons((unsigned short int) udph->source);
		odport = htons((unsigned short int) udph->dest);
		sport = udph->source;
		dport = udph->dest;
	}

	get_available_local_addr();


	add_mpip_enabled(iph->saddr, true);
	add_addr_notified(rcv_mpip_cm.node_id);
	process_addr_notified_event(rcv_mpip_cm.node_id, rcv_mpip_cm.changed);

	add_working_ip(rcv_mpip_cm.node_id, iph->saddr);
	add_path_info(rcv_mpip_cm.node_id, iph->saddr);
	add_path_stat(rcv_mpip_cm.node_id, rcv_mpip_cm.path_id, iph->saddr, iph->daddr);

	update_path_stat_delay(iph->saddr, iph->daddr, rcv_mpip_cm.timestamp);
	update_path_delay(rcv_mpip_cm.path_stat_id, rcv_mpip_cm.delay);
	update_path_info();

	if ((rcv_mpip_cm.session_id > 0) && (iph->protocol != IPPROTO_ICMP))
	{
		session_id = get_receiver_session_id(static_node_id,
											rcv_mpip_cm.node_id,
											iph->daddr, dport,
											iph->saddr, sport,
											rcv_mpip_cm.session_id,
											rcv_mpip_cm.path_id);
	}

	res = get_receiver_session_info(rcv_mpip_cm.node_id, session_id,
							  &saddr, &sport, &daddr, &dport);

	if (res && (iph->protocol != IPPROTO_ICMP))
	{
		iph->saddr = daddr;
		iph->daddr = saddr;

		new_dst_dev = find_dev_by_addr(saddr);
		if (new_dst_dev)
		{
			skb->dev = new_dst_dev;
		}
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

	if (rcv_mpip_cm.changed == 2)
		return 2;

	return 1;
}
EXPORT_SYMBOL(process_mpip_cm);

unsigned char get_session(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph = NULL;
	__be16 sport = 0, dport = 0;

	if (!skb)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return 0;
	}

	iph = ip_hdr(skb);

	if (iph->ihl == 5 || iph->protocol != IPPROTO_TCP)
		return 0;

	tcph= tcp_hdr(skb); //this fixed the problem
	if (!tcph)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return 0;
	}
	sport = tcph->source;
	dport = tcph->dest;

	return get_sender_session(iph->daddr, dport, iph->saddr, sport);

}
