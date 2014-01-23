#undef __KERNEL__
#define __KERNEL__

#undef MODULE
#define MODULE

#include <linux/module.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/sysctl.h>

#include <linux/ip_mpip.h>
#include <net/ip.h>


int MPIP_OPT_LEN = sizeof(struct mpip_options);
//int MPIP_OPT_LEN = 12;
static unsigned char *static_node_id = NULL;
static struct mpip_options *static_rcv_opt = NULL;
static char log_buf[256];


int sysctl_mpip_enabled __read_mostly = 0;
int sysctl_mpip_log __read_mostly = 0;


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
 		.procname = "mpip_log",
 		.data = &sysctl_mpip_log,
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

	list_for_each_entry_safe(working_ip, tmp_ip, &wi_head, list)
	{
			list_del(&(working_ip->list));
			kfree(working_ip);
	}

	struct path_info_table *path_info;
	struct path_info_table *tmp_info;

	list_for_each_entry_safe(path_info, tmp_info, &pi_head, list)
	{
			list_del(&(path_info->list));
			kfree(path_info);
	}

	struct sender_socket_table *sender_socket;
	struct sender_socket_table *tmp_socket;

	list_for_each_entry_safe(sender_socket, tmp_socket, &ss_head, list)
	{
			list_del(&(sender_socket->list));
			kfree(sender_socket);
	}

	struct receiver_socket_table *receiver_socket;
	struct receiver_socket_table *tmp_receiver;

	list_for_each_entry_safe(receiver_socket, tmp_receiver, &rs_head, list)
	{
			list_del(&(receiver_socket->list));
			kfree(receiver_socket);
	}

	struct path_stat_table *path_stat;
	struct path_stat_table *tmp_stat;

	list_for_each_entry_safe(path_stat, tmp_stat, &ps_head, list)
	{
			list_del(&(path_stat->list));
			kfree(path_stat);
	}

	struct local_addr_table *local_addr;
	struct local_addr_table *tmp_addr;

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

	if (!sysctl_mpip_log)
		return;

	memset(log_buf, 0, 256);
	va_start(args, fmt);
	r = vsnprintf(log_buf, 256, fmt, args);
	va_end(args);

    printk(log_buf);

	fp = filp_open("/home/bill/log", O_RDWR | O_CREAT | O_SYNC, 0644);
	if (IS_ERR(fp))
	{
		printk("create file error\n");
		return;
	}

	fs = get_fs();
	set_fs(KERNEL_DS);
	pos = fp->f_dentry->d_inode->i_size;
	//pos = 0;
	vfs_write(fp, log_buf, strlen(log_buf), &pos);
	vfs_fsync(fp, 0);
	filp_close(fp, NULL);
	set_fs(fs);

}
EXPORT_SYMBOL(mpip_log);

void print_mpip_options(struct mpip_options *opt)
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

		static_node_id = kzalloc(ETH_ALEN, GFP_ATOMIC);
		memcpy(static_node_id, dev->perm_addr, ETH_ALEN);
		return static_node_id;
	}

	return NULL;
}

char get_session_id(unsigned char *dest_node_id,
					__be32 saddr, __be16 sport,
					__be32 daddr, __be16 dport)
{
	unsigned char session_id = find_sender_socket(saddr, sport,
										  		  daddr, dport);

	if (session_id == 0)
	{
		session_id = find_receiver_socket_by_socket(dest_node_id,
										  	  	  	saddr, sport,
										  	  	  	daddr, dport);
	}
	if (session_id == 0)
	{
		add_sender_socket(saddr, sport, daddr, dport);
		session_id = find_sender_socket(saddr, sport, daddr, dport);
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

int mpip_options_echo(struct mpip_options *dopt, struct sk_buff *skb)
{
	const struct mpip_options *sopt;
	unsigned char *sptr, *dptr;

	memset(dopt, 0, sizeof(struct mpip_options));

	sopt = &(MPIPCB(skb)->opt);

	if (sopt->optlen == 0)
		return 0;

	sptr = skb_network_header(skb);
	dptr = dopt->__data;

	memcpy(dptr, sptr, MPIP_OPT_LEN);

	while (dopt->optlen & 3) {
		*dptr++ = IPOPT_END;
		dopt->optlen++;
	}
	return 0;
}


void mpip_options_fragment(struct sk_buff *skb)
{
	unsigned char *optptr = skb_network_header(skb) + sizeof(struct iphdr);
	memset(optptr, IPOPT_NOOP, MPIP_OPT_LEN);
}


void get_mpip_options(struct sk_buff *skb, char *options)
{
	struct iphdr *iph = ip_hdr(skb);
	const struct tcphdr *tcph = tcp_hdr(skb);
	int i;
	unsigned char *dest_node_id = find_node_id_in_working_ip(iph->daddr);
	__be32 saddr = 0, daddr = 0;
	__be16 sport = 0, dport = 0;
	u16	packet_count = 0;

	get_node_id();
	get_available_local_addr();
	//printk(KERN_EMERG "saddr:");
	//print_addr(iph->saddr);
	//printk(KERN_EMERG "daddr:");
	//print_addr(iph->daddr);

	options[0] = MPIP_OPT_LEN;

	//node_id
    for(i = 0; i < ETH_ALEN; i++)
   	 options[1 + i] =  static_node_id[i];
    
    options[7] = get_session_id(dest_node_id,
    							iph->saddr, tcph->source,
            					iph->daddr, tcph->dest);//
    options[8] = get_path_id(dest_node_id, &saddr, &daddr,
    						 iph->saddr, iph->daddr); //path id
    options[9] = get_path_stat_id(dest_node_id, &packet_count); //stat path id
    options[10] = packet_count & 0xff; //packet_count
    options[11] = (packet_count>>8) & 0xff; //packet_count

//	for(i = 0; i < ETH_ALEN; i++)
//		options[1 + i] =  0;
//
//    options[7] = 10;
//	options[8] = 10;
//	options[9] = 10;
//	options[10] = 1000 & 0xff; //packet_count
//	options[11] = (1000>>8) & 0xff; //packet_count


    if (options[8] > 0)
    {
    	printk("iph->saddr=");
    	print_addr(iph->saddr);

    	printk("saddr=");
    	print_addr(saddr);

    	printk("iph->daddr=");
    	print_addr(iph->daddr);

    	printk("daddr=");
    	print_addr(daddr);

    	iph->saddr = saddr;
    	iph->daddr = daddr;

    	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
    }

}
EXPORT_SYMBOL(get_mpip_options);


int process_mpip_options(struct sk_buff *skb)
{
	unsigned char *optptr;
	int i, res;
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(skb);
	__be32 saddr = 0, daddr = 0;
	__be16 sport = 0, dport = 0;
	struct mpip_options *rcv_opt = kzalloc(MPIP_OPT_LEN, GFP_ATOMIC);;


	if (skb == NULL)
		return 1;

	//if (!static_rcv_opt)
	//	static_rcv_opt = kzalloc(MPIP_OPT_LEN, GFP_ATOMIC);

	//memset(static_rcv_opt, NULL, MPIP_OPT_LEN);


	optptr = (unsigned char *)&(ip_hdr(skb)[1]);

	//for (i = 0; i < 12; ++i)
    //   	printk("optptr[%d] = %d\n", i, optptr[i]);

	rcv_opt->optlen = optptr[0];
	for(i = 0; i < ETH_ALEN; i++)
		rcv_opt->node_id[i] = optptr[1 + i];

	rcv_opt->session_id = optptr[7];
	rcv_opt->path_id = optptr[8];
	rcv_opt->stat_path_id = optptr[9];
	rcv_opt->packet_count = (optptr[11]<<8)|optptr[10];

	//print_mpip_options(rcv_opt);

	add_working_ip(rcv_opt->node_id, iph->saddr);
	add_path_info(rcv_opt->node_id, iph->saddr);
	add_path_stat(rcv_opt->node_id, rcv_opt->path_id);

	update_packet_rcv(rcv_opt->stat_path_id, rcv_opt->packet_count);
	update_sender_packet_rcv(rcv_opt->node_id, rcv_opt->path_id);
	update_path_info();

	add_receiver_socket(rcv_opt->node_id,  rcv_opt->session_id,
						iph->saddr, tcph->source, iph->daddr, tcph->dest);

	res = get_receiver_socket(rcv_opt->node_id, rcv_opt->session_id,
							  &saddr, &sport, &daddr, &dport);

	if (res)
	{
    	printk("11iph->saddr=");
    	print_addr(iph->saddr);

    	printk("11saddr=");
    	print_addr(saddr);

    	printk("11iph->daddr=");
    	print_addr(iph->daddr);

    	printk("11daddr=");
    	print_addr(daddr);

    	printk("tcph->source= %d, sport=%d\n", tcph->source, sport);
    	printk("tcph->dest= %d, dport=%d\n", tcph->dest, dport);

    	iph->saddr = saddr;
    	iph->daddr = daddr;
    	tcph->source = sport;
    	tcph->dest = dport;
    	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
    	//tcph->check = tcp_fast_csum()
	}
//
//
	//print_mpip_options(rcv_opt);
	kfree(rcv_opt);


	return 1;
}
EXPORT_SYMBOL(process_mpip_options);


static struct mpip_options_rcu *mpip_options_get_alloc(const int optlen)
{
	int size = sizeof(struct mpip_options_rcu) + ((optlen + 3) & ~3);
	//printk("size = %d\n", size);
	return kzalloc(size, GFP_ATOMIC);
}


int mpip_options_compile(struct net *net,
                       struct mpip_options *opt, struct sk_buff *skb)
{
	unsigned char *optptr;
	int i;
	if (skb != NULL)
	{
		optptr = (unsigned char *)&(ip_hdr(skb)[1]);
	}
	else
	{
		optptr = opt->__data;
	}
	for(i = 0; i < ETH_ALEN; i++)
		opt->node_id[i] = optptr[1 + i];

	opt->session_id = optptr[7];
	opt->path_id = optptr[8];
	opt->stat_path_id = optptr[9];
	opt->packet_count = (optptr[11]<<8)|optptr[10];

	return 1;
}
EXPORT_SYMBOL(mpip_options_compile);



static int mpip_options_get_finish(struct net *net, struct mpip_options_rcu **optp,
				 struct mpip_options_rcu *opt, int optlen)
{
	while (optlen & 3)
	{
		opt->opt.__data[optlen++] = IPOPT_END;
	}
	opt->opt.optlen = optlen;
	mpip_options_compile(net, &(opt->opt), NULL);

	//if (optlen && mpip_options_compile(net, &opt->opt, NULL))
	//{
	//	kfree(opt);
	//	return -EINVAL;
	//}
	//if (*optp)
	//{
		//kfree(*optp);
	//}

	*optp = opt;
	return 0;
}

int insert_mpip_options(struct sk_buff *skb)
{
	char options[MPIP_OPT_LEN];
	unsigned int optlen = 0;
	struct mpip_options_rcu *mp_opt = NULL;
	struct iphdr *iph;
	int res;

	iph = ip_hdr(skb);
	if (iph->ihl > 5)
		return 0;

	get_mpip_options(skb, options);
	res = mpip_options_get(sock_net(skb->sk), &mp_opt, options, MPIP_OPT_LEN);
	iph->ihl += (mp_opt->opt.optlen)>>2;
	mpip_options_build(skb, &(mp_opt->opt));

	return 1;
}

int mpip_options_get(struct net *net, struct mpip_options_rcu **optp,
		   unsigned char *data, int optlen)
{
	struct mpip_options_rcu *opt = mpip_options_get_alloc(optlen);

	//return 1;

	if (!opt)
		return -ENOMEM;

	if (optlen)
	{
		memcpy(opt->opt.__data, data, optlen);
	}

	return mpip_options_get_finish(net, optp, opt, optlen);
}


void mpip_options_build(struct sk_buff *skb, struct mpip_options *opt)
{
	unsigned char *iph = skb_network_header(skb);

	memcpy(&(MPIPCB(skb)->opt), opt, MPIP_OPT_LEN);
	memcpy(iph+sizeof(struct iphdr), opt->__data, opt->optlen);
}
EXPORT_SYMBOL(mpip_options_build);

bool mpip_rcv_options(struct sk_buff *skb)
{
	process_mpip_options(skb);

	return true;
}

EXPORT_SYMBOL(mpip_rcv_options);
