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


int sysctl_mpip_enabled __read_mostly = 0;
int sysctl_mpip_send __read_mostly = 0;
int sysctl_mpip_rcv __read_mostly = 0;
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
	printk("optlen: %d\n", opt->optlen);
	printk("node_id: ");
	print_node_id(opt->node_id);
	printk("session_id: %d\n", opt->session_id);
	printk("path_id: %d\n", opt->path_id);
	printk("stat_path_id: %d\n", opt->stat_path_id);
	printk("packet_count: %d\n", opt->packet_count);
}
EXPORT_SYMBOL(print_mpip_options);


unsigned char *get_node_id(void)
{
	struct net_device *dev;

	if (static_node_id)
		return static_node_id;


	for_each_netdev(&init_net, dev)
	{
		//printk("dev = %s\n", dev->name);
		if (strstr(dev->name, "lo"))
			continue;

		static_node_id = kzalloc(MPIP_OPT_NODE_ID_LEN, GFP_ATOMIC);
		memcpy(static_node_id, dev->perm_addr, MPIP_OPT_NODE_ID_LEN);
		return static_node_id;
	}

	return NULL;
}

char get_session_id(__be32 saddr, __be16 sport,
					__be32 daddr, __be16 dport, bool *is_new)
{
	unsigned char session_id = get_sender_session(saddr, sport,
										  		  daddr, dport);


	if (session_id == 0)
	{
		*is_new = true;
		//add_sender_session(saddr, sport, daddr, dport);
		//session_id = get_sender_session(saddr, sport, daddr, dport);
	}
	else
	{
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


void get_mpip_options(struct sk_buff *skb, unsigned char *options)
{
	struct iphdr *iph = ip_hdr(skb);
	const struct tcphdr *tcph = tcp_hdr(skb);
	int i;
	unsigned char *dest_node_id = find_node_id_in_working_ip(iph->daddr);
	__be32 saddr = 0, daddr = 0;
	__be16 sport = 0, dport = 0;
	u16	packet_count = 0;
	unsigned char path_id = 0;
	unsigned char path_stat_id = 0;
	int pkt_len = skb->len + 12;
	int mtu = ip_skb_dst_mtu(skb);
	int pkt_count = pkt_len / mtu + ((pkt_len % mtu) ? 1 : 0);
	bool is_new = true;

	get_node_id();
	get_available_local_addr();


	options[0] = IPOPT_MPIP;
	options[1] = MPIP_OPT_LEN;

    for(i = 0; i < MPIP_OPT_NODE_ID_LEN; i++)
    	options[2 + i] =  static_node_id[i];

    options[5] = get_session_id(iph->saddr, tcph->source,
								iph->daddr, tcph->dest, &is_new);

    if (!is_new)
    {
    	path_id = get_path_id(dest_node_id, &saddr, &daddr,
			 	 	 	  iph->saddr, iph->daddr, pkt_count);
    }

    path_stat_id = get_path_stat_id(dest_node_id, &packet_count);

    options[6] = (((path_id << 4) & 0xf0) | (path_stat_id & 0x0f));

    options[7] = packet_count & 0xff; //packet_count
    options[8] = (packet_count>>8) & 0xff; //packet_count

    mpip_log("\ns: iph->saddr=");
	print_addr(iph->saddr);

	mpip_log("s: saddr=");
	print_addr(saddr);

	mpip_log("s: iph->daddr=");
	print_addr(iph->daddr);

	mpip_log("s: daddr=");
	print_addr(daddr);

	mpip_log("r: tcph->source= %d\n", tcph->source);
	mpip_log("r: tcph->dest= %d\n", tcph->dest);

    if (path_id > 0)
    {


    	iph->saddr = saddr;
    	iph->daddr = daddr;

    	iph->tot_len = htons(skb->len);
    	iph->check = 0;
    	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
    }

}
EXPORT_SYMBOL(get_mpip_options);


int process_mpip_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	struct iphdr *iph;
	struct net_device *dev = skb->dev;
	unsigned char *optptr;
	int i, res;
	unsigned char *tmp = NULL;
	unsigned char *iph_addr = skb_network_header(skb);

	struct tcphdr *tcph = tcp_hdr(skb);
	__be32 saddr = 0, daddr = 0;
	__be16 sport = 0, dport = 0;
	unsigned char session_id = 0;

	iph = ip_hdr(skb);


	if (iph->ihl <= 5)
		return 0;

	opt = &(IPCB(skb)->opt);
	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);
	if (ip_options_compile(dev_net(dev), opt, skb))
	{
		printk("what happened\n");
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		return 1;
	}

	get_available_local_addr();


	add_working_ip(opt->node_id, iph->saddr);
	add_path_info(opt->node_id, iph->saddr);
	add_path_stat(opt->node_id, opt->path_id);

	update_packet_rcv(opt->stat_path_id, opt->packet_count);
	update_sender_packet_rcv(opt->node_id, opt->path_id);
	update_path_info();

	session_id = add_receiver_session(opt->node_id, iph->daddr, tcph->dest,
										iph->saddr, tcph->source);

	res = get_receiver_session(opt->node_id, session_id,
							  &saddr, &sport, &daddr, &dport);

	if (res)
	{
		mpip_log("\nr: iph->saddr=");
		print_addr(iph->saddr);

		mpip_log("r: daddr=");
		print_addr(daddr);

		mpip_log("r: iph->daddr=");
		print_addr(iph->daddr);

		mpip_log("r: saddr=");
		print_addr(saddr);

		mpip_log("r: tcph->source= %d, dport=%d\n", tcph->source, dport);
		mpip_log("r: tcph->dest= %d, sport=%d\n", tcph->dest, sport);

		iph->saddr = daddr;
		iph->daddr = saddr;

		iph->tot_len = htons(skb->len);
		iph->check = 0;
		iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

		//tcph->source = dport;
		//tcph->dest = sport;

		//__tcp_v4_send_check(skb, daddr,saddr);

		//if (skb->sk)
		//	tcp_v4_send_check(skb->sk, skb);
		//tcph->check = 0;

		//tcph->check = tcp_fast_csum()

		printk("receiving:\n");
		print_mpip_options(opt);
	}


	if (opt->optlen > 0)
	{
		tmp = kzalloc(sizeof(struct iphdr), GFP_ATOMIC);
		memcpy(tmp, iph_addr, sizeof(struct iphdr));
		memcpy(iph_addr + opt->optlen, tmp, sizeof(struct iphdr));
		kfree(tmp);

		skb_pull(skb, opt->optlen);
		skb_reset_network_header(skb);
		iph = ip_hdr(skb);
		iph->ihl -= opt->optlen>>2;
		iph->tot_len = htons(skb->len);
		iph->check = 0;
		iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
	}

	return 1;
}
EXPORT_SYMBOL(process_mpip_options);

void mpip_options_build(struct sk_buff *skb, struct ip_options *opt)
{
	unsigned char *tmp = NULL;
	unsigned char *iph = skb_network_header(skb);

	tmp = kzalloc(sizeof(struct iphdr), GFP_ATOMIC);
	memcpy(tmp, iph, sizeof(struct iphdr));
	memcpy(iph - opt->optlen, tmp, sizeof(struct iphdr));
	kfree(tmp);

	skb_push(skb, opt->optlen);
	skb_reset_network_header(skb);

	iph = skb_network_header(skb);

	memcpy(&(IPCB(skb)->opt), opt, sizeof(struct ip_options));
	memcpy(iph+sizeof(struct iphdr), opt->__data, opt->optlen);
}

int insert_mpip_options(struct sk_buff *skb)
{
	unsigned char *options = NULL;
	struct ip_options_rcu *mp_opt = NULL;
	struct iphdr *iph;
	int res, i;

	iph = ip_hdr(skb);
	//if (iph->id == 0)
	//	return 0;

	//printk("\nsend before: %d\n", iph->ihl);
	//printk("send before id: %d\n", iph->id);
	if (iph->ihl > 5)
	{
		printk("here we get: %d\n", iph->ihl);
		return 0;
	}

	options = kzalloc(MPIP_OPT_LEN, GFP_ATOMIC);

	get_mpip_options(skb, options);
	res = ip_options_get(sock_net(skb->sk), &mp_opt, options, MPIP_OPT_LEN);
	iph->ihl += (mp_opt->opt.optlen)>>2;
	mpip_options_build(skb, &(mp_opt->opt));

	printk("\nsending:\n");
	print_mpip_options(&(mp_opt->opt));

//	iph = ip_hdr(skb);

//	if (iph->saddr != iph->daddr)
//	{
//		print_mpip_options(&(mp_opt->opt));
//		printk("send id: %d\n", iph->id);
//		printk("send len: %d\n", skb->len);
//		print_addr(iph->saddr);
//		print_addr(iph->daddr);
//	}
//	printk("send after: %d\n", iph->ihl);

	kfree(options);
	kfree(mp_opt);
	return 1;
}

