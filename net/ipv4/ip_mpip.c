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
static unsigned char *node_id = NULL;
static struct mpip_options *rcv_opt = NULL;


int sysctl_mpip_enabled __read_mostly = 0;


static struct ctl_table mpip_table[] =
{
 	{
 		.procname = "mpip_enabled",
 		.data = &sysctl_mpip_enabled,
 		.maxlen = sizeof(int),
 		.mode = 0644,
 		.proc_handler = &proc_dointvec
 	},
 	{ }
};

void mpip_undo(void)
{
}

int mpip_init(void)
{
	struct ctl_table_header *mptcp_sysctl;

    //In kernel, __MPIP__ will be checked to decide which functions to call.
	mptcp_sysctl = register_net_sysctl(&init_net, "net/mpip", mpip_table);
	//if (!mptcp_sysctl)
	//	goto register_sysctl_failed;

	//register_sysctl_failed:
	//	mpip_undo();

	get_available_local_addr();

    return 0;
}



/*
 * 	Process ingress packets with mpip mechanism
 */
int mpip_rcv(struct sk_buff *skb)
{
	int i;
	struct ethhdr *eth;

	eth = eth_hdr(skb);

	printk("src mac:");
	for(i = 0; i < ETH_ALEN; i++)
		printk(KERN_ALERT "%02x", eth->h_source[i]);
	printk("\n");

	printk("dest mac:");
	for(i = 0; i < ETH_ALEN; i++)
		printk(KERN_ALERT "%02x", eth->h_dest[i]);

	return 0;
}

void mpip_log(char *file, int line, char *func)
{
    //printk("%s, %d, %s \n", file, line, func);
    return;

	struct file *fp;
    struct inode *inode = NULL;
	mm_segment_t fs;
	loff_t pos;
	char *buf = kmalloc(1024, GFP_ATOMIC);
	sprintf(buf, "%s:%d - %s\n", file, line, func);

	fp = filp_open("/home/bill/log", O_RDWR | O_CREAT | O_SYNC, 0644);
	if (IS_ERR(fp))
	{
		printk("create file error\n");
		kfree(buf);
		return;
	}

	fs = get_fs();
	set_fs(KERNEL_DS);
	pos = fp->f_dentry->d_inode->i_size;
	//pos = 0;
	vfs_write(fp, buf, strlen(buf), &pos);
	vfs_fsync(fp, 0);
	filp_close(fp, NULL);
	set_fs(fs);
	kfree(buf);
	return;
}
EXPORT_SYMBOL(mpip_log);

void print_mpip_options(struct mpip_options *opt)
{
	printk("optlen: %d\n", opt->optlen);
	//printk("node_id: %d\n", opt->node_id);
	printk("\nsession_id: %d\n", opt->session_id);
	printk("path_id: %d\n", opt->path_id);
	printk("stat_path_id: %d\n", opt->stat_path_id);
	printk("packet_count: %d\n", opt->packet_count);
}
EXPORT_SYMBOL(print_mpip_options);


unsigned char *get_node_id(struct sk_buff *skb)
{
	struct net_device *dev;
	if (node_id)
		return node_id;

	node_id = kzalloc(ETH_ALEN, GFP_ATOMIC);
	dev = skb->dev;

	memcpy(node_id, dev->dev_addr, ETH_ALEN);

	return node_id;
}

char get_session_id(__be32 saddr, __be16 sport, __be32 daddr, __be16 dport)
{
	unsigned char session_id = find_sender_session_table(saddr, sport,
														daddr, dport);

	if (session_id == 0)
	{
		add_sender_session_table(saddr, sport, daddr, dport, session_id);
		session_id = find_sender_session_table(saddr, sport, daddr, dport);
	}

	return session_id;
}

unsigned char get_path_id(unsigned char *node_id)
{
	if (node_id == NULL)
		return 0;

	return find_fastest_path_id(node_id);
}

unsigned char get_path_stat_id(u16 *packet_count)
{
	return find_earliest_stat_path_id(packet_count);
}


void get_mpip_options(struct sk_buff *skb, char *options)
{
	const struct iphdr *iph = ip_hdr(skb);
	const struct tcphdr *tcph = tcp_hdr(skb);
	int i;

	u16	packet_count = 0;

	options[0] = MPIP_OPT_LEN;

	//node_id
    for(i = 0; i < ETH_ALEN; i++)
    	options[1 + i] =  node_id[i];
    
    options[7] = get_session_id(iph->saddr, tcph->source,
    							iph->daddr, tcph->dest); //session id
    options[8] = get_path_id(find_node_id_in_working_ip_table(iph->daddr)); //path id
    options[9] = get_path_stat_id(&packet_count); //stat path id
    options[10] = packet_count & 0xff; //packet_count
    options[11] = (packet_count>>8) & 0xff; //packet_count
}
EXPORT_SYMBOL(get_mpip_options);

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


int process_mpip_options(struct sk_buff *skb)
{
	unsigned char *optptr;
	int i;
	const struct iphdr *iph = ip_hdr(skb);
	const struct tcphdr *tcph = tcp_hdr(skb);

	if (skb == NULL)
		return 1;

	if (!rcv_opt)
		rcv_opt = kzalloc(MPIP_OPT_LEN, GFP_ATOMIC);

	memset(rcv_opt, NULL, MPIP_OPT_LEN);


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

	add_working_ip_table(rcv_opt->node_id, iph->saddr);
	rcv_add_packet_rcv_2(rcv_opt->stat_path_id, rcv_opt->packet_count);
	rcv_add_sock_info(rcv_opt->node_id, iph->saddr, tcph->source, iph->daddr,
				tcph->dest, rcv_opt->session_id);
	rcv_add_packet_rcv_5(rcv_opt->node_id, rcv_opt->path_id);

	print_mpip_options(rcv_opt);

	return 1;
}
EXPORT_SYMBOL(process_mpip_options);


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

