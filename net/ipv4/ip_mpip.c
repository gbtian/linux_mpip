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
}

/* Called only under RTNL semaphore */

static int inetdev_mpip_event(struct notifier_block *this, unsigned long event,
			 void *ptr)
{

	reset_mpip();

	return NOTIFY_DONE;
}

static struct notifier_block mpip_netdev_notifier = {
	.notifier_call = inetdev_mpip_event,
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
					__be32 daddr, __be16 dport)
{
	unsigned char session_id = get_sender_session(saddr, sport,
										  		  daddr, dport);

//	if (session_id == 0)
//	{
//		session_id = find_receiver_socket_by_socket(dest_node_id,
//										  	  	  	daddr, dport,
//										  	  	  	saddr, sport);
//	}

	if (session_id == 0)
	{
		add_sender_session(saddr, sport, daddr, dport);
		session_id = get_sender_session(saddr, sport, daddr, dport);
	}

	return session_id;
}

unsigned char get_path_id(unsigned char *node_id, __be32 *saddr, __be32 *daddr,
						  __be32 origin_saddr, __be32 origin_daddr)
{
	if (node_id == NULL)
		return 0;

	return find_fastest_path_id(node_id, saddr, daddr,
								origin_saddr, origin_daddr);
}

unsigned char get_path_stat_id(unsigned char *dest_node_id, u16 *packet_count)
{
	if (!dest_node_id)
		return 0;

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

	get_node_id();
	get_available_local_addr();


	options[0] = IPOPT_MPIP;
	options[1] = MPIP_OPT_LEN;
//
	//node_id
    for(i = 0; i < MPIP_OPT_NODE_ID_LEN; i++)
    	options[2 + i] =  static_node_id[i];

    options[5] = get_session_id(iph->saddr, tcph->source,
								iph->daddr, tcph->dest);

    path_id = get_path_id(dest_node_id, &saddr, &daddr,
			 	 	 	  iph->saddr, iph->daddr);

    path_stat_id = get_path_stat_id(dest_node_id, &packet_count);

    options[6] = (((path_id << 4) & 0xf0) | (path_stat_id & 0x0f));

    options[7] = packet_count & 0xff; //packet_count
    options[8] = (packet_count>>8) & 0xff; //packet_count


    if (path_id > 0)
    //if (false)
    {
    	mpip_log("\niph->saddr=");
    	print_addr(iph->saddr);

    	mpip_log("saddr=");
    	print_addr(saddr);

    	mpip_log("iph->daddr=");
    	print_addr(iph->daddr);

    	mpip_log("daddr=");
    	print_addr(daddr);

    	iph->saddr = saddr;
    	iph->daddr = daddr;

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

	iph = ip_hdr(skb);

	printk("iph->ihl = %d\n", iph->ihl);

	if (iph->ihl != 8)
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

	add_receiver_session(opt->node_id,  opt->session_id,
						iph->daddr, tcph->dest, iph->saddr, tcph->source);

	res = get_receiver_session(opt->node_id, opt->session_id,
							  &saddr, &sport, &daddr, &dport);

	if (res)
	//if (false)
	{
		mpip_log("\n11iph->saddr=");
		print_addr(iph->saddr);

		mpip_log("11daddr=");
		print_addr(daddr);

		mpip_log("11iph->daddr=");
		print_addr(iph->daddr);

		mpip_log("11saddr=");
		print_addr(saddr);

		mpip_log("tcph->source= %d, dport=%d\n", tcph->source, dport);
		mpip_log("tcph->dest= %d, sport=%d\n", tcph->dest, sport);

		iph->saddr = daddr;
		iph->daddr = saddr;
		//tcph->source = dport;
		//tcph->dest = sport;
		iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
		//tcph->check = tcp_fast_csum()
	}


	print_mpip_options(opt);


	if (opt->optlen > 0)
	{
//		mpip_log("222 ihl=%d\n", iph->ihl);
//		mpip_log("222 optlen=%d\n", opt->optlen);
//		mpip_log("222 data=%d\n", skb->data);
//		mpip_log("222 len=%d\n", skb->len);
		tmp = kzalloc(sizeof(struct iphdr), GFP_ATOMIC);
		memcpy(tmp, iph_addr, sizeof(struct iphdr));
		memcpy(iph_addr + opt->optlen, tmp, sizeof(struct iphdr));
		//memcpy(iph_addr + opt->optlen, iph_addr, sizeof(struct iphdr));
		kfree(tmp);

		skb_pull(skb, opt->optlen);
		skb_reset_network_header(skb);
		iph = ip_hdr(skb);

//		mpip_log("222 new ihl=%d\n", iph->ihl);
//		mpip_log("222 new data=%d\n", skb->data);
//		mpip_log("222 new len=%d\n", skb->len);
		iph->ihl -= opt->optlen>>2;
//		mpip_log("222 newest ihl=%d\n", iph->ihl);
//		mpip_log("222 newest data=%d\n", skb->data);
//		mpip_log("222 newest len=%d\n", skb->len);
//
//		print_addr(iph->saddr);
//		print_addr(iph->daddr);
	}

	return 1;
}
EXPORT_SYMBOL(process_mpip_options);


int insert_mpip_options(struct sk_buff *skb)
{
	unsigned char *options = NULL;
	struct ip_options_rcu *mp_opt = NULL;
	struct iphdr *iph;
	int res, i;

	iph = ip_hdr(skb);
	if (iph->ihl > 5)
		return 0;

	options = kzalloc(MPIP_OPT_LEN, GFP_ATOMIC);

	get_mpip_options(skb, options);
	res = ip_options_get(sock_net(skb->sk), &mp_opt, options, MPIP_OPT_LEN);
	iph->ihl += (mp_opt->opt.optlen)>>2;
	ip_options_build(skb, &(mp_opt->opt), 0, NULL, 0);

	kfree(options);
	return 1;
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
