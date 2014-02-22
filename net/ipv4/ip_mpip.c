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
 	{ }
};




int mpip_init(void)
{
	struct ctl_table_header *mptcp_sysctl;

    //In kernel, __MPIP__ will be checked to decide which functions to call.
	mptcp_sysctl = register_net_sysctl(&init_net, "net/mpip", mpip_table);
	//register_netdevice_notifier(&mpip_netdev_notifier);
	//if (!mptcp_sysctl)
	//	goto register_sysctl_failed;

	//register_sysctl_failed:
	//	mpip_undo();

	//get_available_local_addr();

    return 0;
}



void mpip_log(const char *fmt, ...)
{
	va_list args;
	int r;

	struct file *fp;
    struct inode *inode = NULL;
	mm_segment_t fs;
	loff_t pos;

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

void print_mpip_options(struct ip_options *opt)
{
	mpip_log("optlen: %d\n", opt->optlen);
	mpip_log("node_id: ");
	print_node_id(opt->node_id);
	mpip_log("session_id: %d\n", opt->session_id);
	mpip_log("path_id: %d\n", opt->path_id);
	mpip_log("stat_path_id: %d\n", opt->stat_path_id);
	mpip_log("packet_count: %d\n", opt->packet_count);
}
EXPORT_SYMBOL(print_mpip_options);

static __sum16 mpip_tcp_v4_checksum_init(struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
//	printk("i: %s, %d\n", __FILE__, __LINE__);
	if (skb->ip_summed == CHECKSUM_COMPLETE)
	{
//		printk("i: %s, %d\n", __FILE__, __LINE__);
		if (!tcp_v4_check(skb->len, iph->saddr,
				  iph->daddr, skb->csum))
		{
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			return 0;
		}
	}

//	printk("i: %s, %d\n", __FILE__, __LINE__);
	skb->csum = csum_tcpudp_nofold(iph->saddr, iph->daddr,
				       skb->len, IPPROTO_TCP, 0);

//	printk("i: %s, %d\n", __FILE__, __LINE__);

	if (skb->len <= 76)
	{
//		printk("i: %s, %d\n", __FILE__, __LINE__);
		return __skb_checksum_complete(skb);
	}
	return 0;
}

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

char get_session_id(unsigned char *dest_node_id, __be32 saddr, __be16 sport,
					__be32 daddr, __be16 dport, bool *is_new)
{
	unsigned char session_id = get_sender_session(saddr, sport,
										  		  daddr, dport);


	if (session_id == 0)
	{
		printk("%s, %d\n", __FILE__, __LINE__);
		*is_new = true;
		if (dest_node_id)
		{
			add_sender_session(dest_node_id, saddr, sport, daddr, dport);
			session_id = get_sender_session(saddr, sport, daddr, dport);
		}
	}
	else
	{
		printk("%s, %d\n", __FILE__, __LINE__);
		*is_new = false;
	}

	return session_id;
}

unsigned char get_path_id(unsigned char *node_id, __be32 *saddr, __be32 *daddr,
						  __be32 origin_saddr, __be32 origin_daddr, int pkt_count)
{
	if (node_id == NULL)
		return 0;

	if ((node_id[0] == node_id[1]) &&
		(node_id[1] == node_id[2]))
	{
		return 0;
	}

	return find_fastest_path_id(node_id, saddr, daddr,
								origin_saddr, origin_daddr, pkt_count);
}

unsigned char get_path_stat_id(unsigned char *dest_node_id, u16 *packet_count)
{
	if (!dest_node_id)
		return 0;

	if ((dest_node_id[0] == dest_node_id[1]) &&
		(dest_node_id[1] == dest_node_id[2]))
	{
		return 0;
	}

	return find_earliest_stat_path_id(dest_node_id, packet_count);
}


int get_mpip_options(struct sk_buff *skb, unsigned char *options)
{
	if (!skb)
		return 0;

	struct iphdr *iph = ip_hdr(skb);
	if (!iph)
		return 0;

	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;

	int i;
	unsigned char *dest_node_id = find_node_id_in_working_ip(iph->daddr);
	__be32 saddr = 0, daddr = 0;
	__be16 sport = 0, dport = 0;
	__be16 osport = 0, odport = 0;
	u16	packet_count = 0;
	unsigned char path_id = 0;
	unsigned char path_stat_id = 0;
	int pkt_len = skb->len + 12;
	int mtu = ip_skb_dst_mtu(skb);
	int pkt_count = pkt_len / mtu + ((pkt_len % mtu) ? 1 : 0);
	bool is_new = true;


	//if TCP PACKET
	if(iph->protocol==IPPROTO_TCP)
	{
	    //tcp_header = (struct tcphdr *)skb_transport_header(sock_buff); //doing the cast this way gave me the same problem

//		tcph= (struct tcphdr *)((__u32 *)iph + iph->ihl); //this fixed the problem
		tcph= tcp_hdr(skb); //this fixed the problem
		osport = htons((unsigned short int) tcph->source); //sport now has the source port
		odport = htons((unsigned short int) tcph->dest);   //dport now has the dest port
		sport = tcph->source; //sport now has the source port
		dport = tcph->dest;   //dport now has the dest port

	}
	else if(iph->protocol==IPPROTO_UDP)
	{
		return 0;
//		udph= udp_hdr(skb); //this fixed the problem
//		osport = htons((unsigned short int) udph->source); //sport now has the source port
//		odport = htons((unsigned short int) udph->dest);   //dport now has the dest port
//		sport = udph->source; //sport now has the source port
//		dport = udph->dest;   //dport now has the dest port
	}

	get_node_id();
	get_available_local_addr();


	options[0] = IPOPT_MPIP;
	options[1] = MPIP_OPT_LEN;

    for(i = 0; i < MPIP_OPT_NODE_ID_LEN; i++)
    	options[2 + i] =  static_node_id[i];

    options[5] = get_session_id(dest_node_id,
    							iph->saddr, sport,
								iph->daddr, dport, &is_new);

    if (!is_new)
    {
    	printk("%s, %d\n", __FILE__, __LINE__);
    	path_id = get_path_id(dest_node_id, &saddr, &daddr,
			 	 	 	  iph->saddr, iph->daddr, pkt_count);
    }

    path_stat_id = get_path_stat_id(dest_node_id, &packet_count);

    options[6] = (((path_id << 4) & 0xf0) | (path_stat_id & 0x0f));

    options[7] = packet_count & 0xff; //packet_count
    options[8] = (packet_count>>8) & 0xff; //packet_count


    mpip_log("\ns: iph->id=%d\n", iph->id);
    mpip_log("s: iph->saddr=");
	print_addr(iph->saddr);

	mpip_log("s: saddr=");
	print_addr(saddr);

	mpip_log("s: iph->daddr=");
	print_addr(iph->daddr);

	mpip_log("s: daddr=");
	print_addr(daddr);

	mpip_log("s: tcph->source= %d, osport=%d, sport=%d\n", tcph->source, osport, sport);
	mpip_log("s: tcph->dest= %d, odport=%d, dport=%d\n", tcph->dest, odport, dport);

    if (path_id > 0)
    {
		mpip_log("s: modifying header\n");

		__be32 waddr = convert_addr(192, 168, 1, 20);
		__be32 eaddr = convert_addr(192, 168, 1, 21);


    	iph->saddr = saddr;
    	iph->daddr = daddr;

		if (iph->saddr == waddr)
		{
			iph->saddr = eaddr;
		}

		if (iph->daddr == waddr)
		{
			iph->daddr = eaddr;
		}

//    	mpip_log("s: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",iph->id, skb->ip_summed, tcph->check, iph->check, __LINE__);
    }

    return 1;

}
EXPORT_SYMBOL(get_mpip_options);


int process_mpip_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	struct iphdr *iph;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct net_device *dev = skb->dev;
	unsigned char *optptr;
	int i, res;
	unsigned char *tmp = NULL;
	unsigned char *iph_addr;

	__be32 saddr = 0, daddr = 0;
	__be16 sport = 0, dport = 0;
	__be16 osport = 0, odport = 0;
	unsigned char session_id = 0;

	if (!skb)
		return 0;

	iph = ip_hdr(skb);


	if (iph->ihl <= 5)
		return 0;

	//if TCP PACKET
	if(iph->protocol==IPPROTO_TCP)
	{
		//tcp_header = (struct tcphdr *)skb_transport_header(sock_buff); //doing the cast this way gave me the same problem
		//tcph= (struct tcphdr *)((__u32 *)iph + iph->ihl); //this fixed the problem
		tcph= tcp_hdr(skb); //this fixed the problem
		osport = htons((unsigned short int) tcph->source); //sport now has the source port
		odport = htons((unsigned short int) tcph->dest);   //dport now has the dest port
		sport = tcph->source; //sport now has the source port
		dport = tcph->dest;   //dport now has the dest port
	}
//	printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",iph->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
//	printk("r: tcpheader=%p, %d\n",tcp_hdr(skb), __LINE__);
	opt = &(IPCB(skb)->opt);
	if (!opt)
		return 0;

	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);
	if (ip_options_compile(dev_net(dev), opt, skb))
	{
		mpip_log("what happened\n");
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		return 1;
	}

//	printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",iph->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
//	printk("r: tcpheader=%p, %d\n",tcp_hdr(skb), __LINE__);
	get_available_local_addr();


	add_working_ip(opt->node_id, iph->saddr);
	add_path_info(opt->node_id, iph->saddr);
	add_path_stat(opt->node_id, opt->path_id);

	update_packet_rcv(opt->stat_path_id, opt->packet_count);
	update_sender_packet_rcv(opt->node_id, opt->path_id);
	update_path_info();

	session_id = add_receiver_session(opt->node_id, iph->daddr, dport,
										iph->saddr, sport, opt->session_id);

	res = get_receiver_session(opt->node_id, session_id,
							  &saddr, &sport, &daddr, &dport);

	mpip_log("\nreceiving:\n");
	mpip_log("r: iph->id=%d\n", iph->id);
	mpip_log("r: iph->saddr=");
	print_addr(iph->saddr);

	mpip_log("r: daddr=");
	print_addr(daddr);

	mpip_log("r: iph->daddr=");
	print_addr(iph->daddr);


	mpip_log("r: saddr=");
	print_addr(saddr);

	mpip_log("r: tcph->source= %d, osport=%d, dport=%d\n", tcph->source, osport, dport);
	mpip_log("r: tcph->dest= %d, odport=%d, sport=%d\n", tcph->dest, odport, sport);


	print_mpip_options(opt);

	if (res)
	{
		mpip_log("r: modifying header\n");
//		printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",iph->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
//		printk("r: tcpheader=%p, %d\n",tcp_hdr(skb), __LINE__);
		iph->saddr = daddr;
		iph->daddr = saddr;
//		printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",iph->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
//		printk("r: tcpheader=%p, %d\n",tcp_hdr(skb), __LINE__);
	}

	iph->tot_len = htons(skb->len);
	if((iph->protocol==IPPROTO_TCP) && sysctl_mpip_send)
	{
		printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",iph->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
		__tcp_v4_send_check(skb, iph->saddr, iph->daddr);
		printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",iph->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
	}

	if (sysctl_mpip_rcv)
	{
		//iph->tot_len = htons(skb->len);
		ip_send_check(iph);
	}

	//if (opt->optlen > 0)
	if (false)
	{
		mpip_log("r: unwrapping options\n");
		tmp = kzalloc(sizeof(struct iphdr), GFP_ATOMIC);

		if (!tmp)
		{
			mpip_log("tmp == NULL\n");
			return 0;
		}

		iph_addr = skb_network_header(skb);
		memcpy(tmp, iph_addr, sizeof(struct iphdr));
		printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",(ip_hdr(skb))->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
		printk("r: tcpheader=%p, ipheader=%p, ihl=%d, %d\n",tcp_hdr(skb), ip_hdr(skb), ip_hdr(skb)->ihl, __LINE__);
		memcpy(iph_addr + opt->optlen, tmp, sizeof(struct iphdr));
		printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",(ip_hdr(skb))->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
		printk("r: tcpheader=%p, ipheader=%p, ihl=%d, %d\n",tcp_hdr(skb), ip_hdr(skb), ip_hdr(skb)->ihl, __LINE__);
		kfree(tmp);
		printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",(ip_hdr(skb))->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
		printk("r: tcpheader=%p, ipheader=%p, ihl=%d, %d\n",tcp_hdr(skb), ip_hdr(skb), ip_hdr(skb)->ihl, __LINE__);
		//skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb_pull(skb, opt->optlen);
		printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",(ip_hdr(skb))->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
		printk("r: tcpheader=%p, ipheader=%p, ihl=%d, %d\n",tcp_hdr(skb), ip_hdr(skb), ip_hdr(skb)->ihl, __LINE__);
		skb_reset_network_header(skb);
		skb_reset_transport_header(skb);
		printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",(ip_hdr(skb))->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
		printk("r: tcpheader=%p, ipheader=%p, ihl=%d, %d\n",tcp_hdr(skb), ip_hdr(skb), ip_hdr(skb)->ihl, __LINE__);

		iph = ip_hdr(skb);
		printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",(ip_hdr(skb))->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
		printk("r: tcpheader=%p, ipheader=%p, ihl=%d, %d\n",tcp_hdr(skb), ip_hdr(skb), ip_hdr(skb)->ihl, __LINE__);
		iph->ihl -= opt->optlen>>2;
		printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",(ip_hdr(skb))->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
		printk("r: tcpheader=%p, ipheader=%p, ihl=%d, %d\n",tcp_hdr(skb), ip_hdr(skb), ip_hdr(skb)->ihl, __LINE__);
		iph->tot_len = htons(skb->len);
		if((iph->protocol==IPPROTO_TCP) && sysctl_mpip_send)
		{
			tcph= tcp_hdr(skb);
			printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",iph->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
			skb->csum = csum_partial((char *)tcph,
							 sizeof(struct tcphdr), skb->csum);
			tcph->check = tcp_v4_check(skb->len, iph->saddr, iph->daddr, skb->csum);
			printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",iph->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
		}

		if (sysctl_mpip_rcv)
		{
			//iph->tot_len = htons(skb->len);
			ip_send_check(iph);
		}

//		mpip_log("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",iph->id, skb->ip_summed, tcph->check, iph->check, __LINE__);
	}

	return 1;
}
EXPORT_SYMBOL(process_mpip_options);

int process_mpip_options_1(struct sk_buff *skb, struct ip_options *opt)
{
	struct iphdr *iph;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct net_device *dev = skb->dev;
	unsigned char *optptr;
	int i, res;
	unsigned char *tmp = NULL;
	unsigned char *iph_addr;

	__be32 saddr = 0, daddr = 0;
	__be16 sport = 0, dport = 0;
	__be16 osport = 0, odport = 0;
	unsigned char session_id = 0;


	if (!opt || !skb)
		return 0;

	iph = ip_hdr(skb);


	if (iph->ihl <= 5)
		return 0;

	//if TCP PACKET
	if(iph->protocol==IPPROTO_TCP)
	{
		//tcp_header = (struct tcphdr *)skb_transport_header(sock_buff); //doing the cast this way gave me the same problem
		//tcph= (struct tcphdr *)((__u32 *)iph + iph->ihl); //this fixed the problem
		tcph= tcp_hdr(skb); //this fixed the problem
		osport = htons((unsigned short int) tcph->source); //sport now has the source port
		odport = htons((unsigned short int) tcph->dest);   //dport now has the dest port
		sport = tcph->source; //sport now has the source port
		dport = tcph->dest;   //dport now has the dest port
	}
	else
	{
		return 0;
	}

//	printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",iph->id, skb->ip_summed, (tcp_hdr(skb))->check, iph->check, __LINE__);
//	printk("r: tcpheader=%p, %d\n",tcp_hdr(skb), __LINE__);
	get_available_local_addr();


	add_working_ip(opt->node_id, iph->saddr);
	add_path_info(opt->node_id, iph->saddr);
	add_path_stat(opt->node_id, opt->path_id);

	update_packet_rcv(opt->stat_path_id, opt->packet_count);
	update_sender_packet_rcv(opt->node_id, opt->path_id);
	update_path_info();

	session_id = add_receiver_session(opt->node_id, iph->daddr, dport,
										iph->saddr, sport, opt->session_id);

	res = get_receiver_session(opt->node_id, session_id,
							  &saddr, &sport, &daddr, &dport);

	mpip_log("\nreceiving:\n");
	mpip_log("r: iph->id=%d\n", iph->id);
	mpip_log("r: iph->saddr=");
	print_addr(iph->saddr);

	mpip_log("r: daddr=");
	print_addr(daddr);

	mpip_log("r: iph->daddr=");
	print_addr(iph->daddr);


	mpip_log("r: saddr=");
	print_addr(saddr);

	mpip_log("r: tcph->source= %d, osport=%d, dport=%d\n", tcph->source, osport, dport);
	mpip_log("r: tcph->dest= %d, odport=%d, sport=%d\n", tcph->dest, odport, sport);


	print_mpip_options(opt);

	if (res)
	{
		mpip_log("r: modifying header\n");

		//if ((iph->saddr != daddr) || (iph->daddr != saddr))
		{
			iph->saddr = daddr;
			iph->daddr = saddr;

			if((iph->protocol==IPPROTO_TCP) && sysctl_mpip_send)
			{
//				printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",(ip_hdr(skb))->id, skb->ip_summed, (tcp_hdr(skb))->check, (ip_hdr(skb))->check, __LINE__);
				//__tcp_v4_send_check(skb, iph->saddr, iph->daddr);
				//mpip_tcp_v4_checksum_init(skb);
				//tcp_checksum_complete(skb);

				tcph->check = 0;
				tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
				                                  skb->len, iph->protocol,
				                                  csum_partial((char *)tcph, skb->len, 0));
				skb->ip_summed = CHECKSUM_UNNECESSARY;

//				printk("r: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",(ip_hdr(skb))->id, skb->ip_summed, (tcp_hdr(skb))->check, (ip_hdr(skb))->check, __LINE__);
			}

			if (sysctl_mpip_rcv)
			{
				ip_send_check(iph);
			}
		}
	}

	return 1;
}

void mpip_options_build(struct sk_buff *skb, struct ip_options *opt)
{
//	unsigned char *tmp = NULL;
	unsigned char *iph = skb_network_header(skb);

//	tmp = kzalloc(sizeof(struct iphdr), GFP_ATOMIC);
//	memcpy(tmp, iph, sizeof(struct iphdr));
//	memcpy(iph - opt->optlen, tmp, sizeof(struct iphdr));
//	kfree(tmp);
//
//	skb_push(skb, opt->optlen);
//	skb_reset_network_header(skb);
//
//	iph = skb_network_header(skb);

	memcpy(&(IPCB(skb)->opt), opt, sizeof(struct ip_options));
	memcpy(iph+sizeof(struct iphdr), opt->__data, opt->optlen);
}


static int mpip_options_get(struct net *net, struct ip_options_rcu *opt,
		   unsigned char *data, int optlen)
{
//	struct ip_options_rcu *opt = ip_options_get_alloc(optlen);
//
//	if (!opt)
//		return -ENOMEM;


	if (optlen)
		memcpy(opt->opt.__data, data, optlen);

	while (optlen & 3)
		opt->opt.__data[optlen++] = IPOPT_END;
	opt->opt.optlen = optlen;

	if (optlen && ip_options_compile(net, &opt->opt, NULL)) {
		//kfree(opt);
		return -EINVAL;
	}

	return 0;
}

int insert_mpip_options(struct sk_buff *skb)
{
	//unsigned char *options = NULL;
	//static struct ip_options_rcu *mp_opt = NULL;
	int res, i;
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph;


	if (iph->ihl > 5)
	{
		mpip_log("here we get: %d\n", iph->ihl);
		return 0;
	}


	//options = kzalloc(MPIP_OPT_LEN, GFP_ATOMIC);

	if (!get_mpip_options(skb, options))
		return 0;

	if (!mp_opt)
		mp_opt = kzalloc(sizeof(struct ip_options_rcu) + ((MPIP_OPT_LEN + 3) & ~3),
			       GFP_ATOMIC);

	res = mpip_options_get(sock_net(skb->sk), mp_opt, options, MPIP_OPT_LEN);
	iph->ihl += (mp_opt->opt.optlen)>>2;
	mpip_options_build(skb, &(mp_opt->opt));

//	printk("s: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",(ip_hdr(skb))->id, skb->ip_summed, (tcp_hdr(skb))->check, (ip_hdr(skb))->check, __LINE__);
	//mpip_tcp_v4_checksum_init(skb);
	//tcp_checksum_complete(skb);
	//printk("s: id=%d, skb->ip_summed=%d, tcph->check=%d, iph->check=%d, %d\n",(ip_hdr(skb))->id, skb->ip_summed, (tcp_hdr(skb))->check, (ip_hdr(skb))->check, __LINE__);

	mpip_log("\nsending:\n");
	print_mpip_options(&(mp_opt->opt));

	//kfree(options);
	//kfree(mp_opt);
	return 1;
}

