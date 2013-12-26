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
	if (!mptcp_sysctl)
		goto register_sysctl_failed;

	register_sysctl_failed:
		mpip_undo();

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
	return;

	struct file *fp;
    struct inode *inode = NULL;
	mm_segment_t fs;
	loff_t pos;
	char *buf = kmalloc(1024, GFP_KERNEL);
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
	printk("node_id: %d\n", opt->node_id);
	printk("\nsession_id: %d\n", opt->session_id);
	printk("path_id: %d\n", opt->path_id);
	printk("stat_path_id: %d\n", opt->stat_path_id);
	printk("packetcount: %d\n", opt->packetcount);
}
EXPORT_SYMBOL(print_mpip_options);

void get_mpip_options(struct sk_buff *skb, char *options)
{
	//struct ethhdr *eth;
	int i;

	//eth = eth_hdr(skb);

	//memset(options, 0, sizeof(options));

	mpip_log(__FILE__, __LINE__, __FUNCTION__);
    options[0] = IPOPT_NOP;
    options[1] = IPOPT_NOP;
    options[2] = IPOPT_NOP;
    options[3] = IPOPT_NOP;
    mpip_log(__FILE__, __LINE__, __FUNCTION__);
    options[4+IPOPT_OPTVAL] = IPOPT_MPIP;
    mpip_log(__FILE__, __LINE__, __FUNCTION__);
    options[4+IPOPT_OLEN] = 11;
    mpip_log(__FILE__, __LINE__, __FUNCTION__);

	//node_id
	for(i = 0; i < ETH_ALEN; i++)
		options[6 + i] =  1;
	mpip_log(__FILE__, __LINE__, __FUNCTION__);
	options[12] = 8; //session id
	mpip_log(__FILE__, __LINE__, __FUNCTION__);
    options[13] = 3; //path id
    mpip_log(__FILE__, __LINE__, __FUNCTION__);
    options[14] = 4; //stat path id
    mpip_log(__FILE__, __LINE__, __FUNCTION__);
    options[15] = 50; //packet_count
    mpip_log(__FILE__, __LINE__, __FUNCTION__);
}
EXPORT_SYMBOL(mpip_options_build);

static struct mpip_options_rcu *mpip_options_get_alloc(const int optlen)
{
	mpip_log(__FILE__, __LINE__, __FUNCTION__);
	return kzalloc(sizeof(struct mpip_options_rcu) + ((optlen + 3) & ~3),
			GFP_KERNEL);
}


int mpip_options_compile(struct net *net,
                       struct mpip_options *opt, struct sk_buff *skb)
{
    __be32 spec_dst = htonl(INADDR_ANY);
    unsigned char *pp_ptr = NULL;
	unsigned char *optptr;
	unsigned char *iph;
	int optlen, l, i;
	mpip_log(__FILE__, __LINE__, __FUNCTION__);
	if (skb != NULL)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		optptr = (unsigned char *)&(ip_hdr(skb)[1]);
	}
	else
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		optptr = opt->__data;
	}
	iph = optptr - sizeof(struct iphdr);
	mpip_log(__FILE__, __LINE__, __FUNCTION__);
	for (l = opt->optlen; l > 1; )
	{
		mpip_log(__FILE__, opt->optlen, __FUNCTION__);
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		switch (*optptr)
		{
			case IPOPT_END:
				mpip_log(__FILE__, __LINE__, __FUNCTION__);
				for (optptr++, l--; l>0; optptr++, l--)
				{
					if (*optptr != IPOPT_END)
					{
						*optptr = IPOPT_END;
					}
				}
				goto eol;
			case IPOPT_NOOP:
				mpip_log(__FILE__, __LINE__, __FUNCTION__);
				l--;
				optptr++;
				continue;
		}
		optlen = optptr[1];
		mpip_log(__FILE__, optlen, __FUNCTION__);
		mpip_log(__FILE__, l, __FUNCTION__);
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		if (optlen<2 || optlen>l)
		{
			mpip_log(__FILE__, __LINE__, __FUNCTION__);
			pp_ptr = optptr;
			goto error;
		}
		switch (*optptr)
		{
			case IPOPT_MPIP:
				mpip_log(__FILE__, __LINE__, __FUNCTION__);
				if (optlen < 3)
				{
					mpip_log(__FILE__, __LINE__, __FUNCTION__);
					pp_ptr = optptr + 1;
					goto error;
				}
				mpip_log(__FILE__, __LINE__, __FUNCTION__);
				for(i = 0; i < ETH_ALEN; i++)
					opt->node_id[i] = optptr[2 + i];

				mpip_log(__FILE__, optptr[8], __FUNCTION__);
				mpip_log(__FILE__, __LINE__, __FUNCTION__);
				opt->session_id = optptr[8];
				mpip_log(__FILE__, optptr[9], __FUNCTION__);
				mpip_log(__FILE__, __LINE__, __FUNCTION__);
				opt->path_id = optptr[9];
				mpip_log(__FILE__, optptr[10], __FUNCTION__);
				mpip_log(__FILE__, __LINE__, __FUNCTION__);
				opt->stat_path_id = optptr[10];
				mpip_log(__FILE__, optptr[11], __FUNCTION__);
				mpip_log(__FILE__, __LINE__, __FUNCTION__);
				opt->packetcount = optptr[11];
				mpip_log(__FILE__, __LINE__, __FUNCTION__);

				break;

			default:
				mpip_log(__FILE__, __LINE__, __FUNCTION__);
				if (!skb && !ns_capable(net->user_ns, CAP_NET_RAW))
				{
					pp_ptr = optptr;
					goto error;
				}
				break;
		}
		l -= optlen;
		optptr += optlen;
	}

eol:
	if (!pp_ptr)
		return 0;

error:
	mpip_log(__FILE__, __LINE__, __FUNCTION__);
	return -EINVAL;
}
EXPORT_SYMBOL(mpip_options_compile);


static int mpip_options_get_finish(struct net *net, struct mpip_options_rcu **optp,
				 struct mpip_options_rcu *opt, int optlen)
{
	while (optlen & 3)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		opt->opt.__data[optlen++] = IPOPT_END;
	}
	mpip_log(__FILE__, __LINE__, __FUNCTION__);
	opt->opt.optlen = optlen;
	mpip_log(__FILE__, __LINE__, __FUNCTION__);
	if (optlen && mpip_options_compile(net, &opt->opt, NULL))
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		kfree(opt);
		return -EINVAL;
	}
	mpip_log(__FILE__, __LINE__, __FUNCTION__);
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

	mpip_log(__FILE__, __LINE__, __FUNCTION__);

	if (!opt)
		return -ENOMEM;
	mpip_log(__FILE__, __LINE__, __FUNCTION__);

	if (optlen)
	{
		mpip_log(__FILE__, __LINE__, __FUNCTION__);
		memcpy(opt->opt.__data, data, optlen);
	}

	mpip_log(__FILE__, __LINE__, __FUNCTION__);
	return mpip_options_get_finish(net, optp, opt, optlen);
}


void mpip_options_build(struct sk_buff *skb, struct mpip_options *opt)
{
	unsigned char *iph = skb_network_header(skb);

	memcpy(&(MPIPCB(skb)->opt), opt, sizeof(struct mpip_options));
	memcpy(iph+sizeof(struct iphdr), opt->__data, opt->optlen);
}

bool mpip_rcv_options(struct sk_buff *skb)
{
	struct mpip_options *opt;
	const struct iphdr *iph;

	//struct net_device *dev = skb->dev;

	//iph = ip_hdr(skb);
	//opt = (struct mpip_options *)(&(skb->cb));
	//if (opt->optlen != sizeof(struct mpip_options))
	//{
	//	printk("opt->optlen != sizeof(struct mpip_options)\n");
	//	return true;
	//}
	//print_mpip_options(opt);
	//todo: process the options

	return true;
}
EXPORT_SYMBOL(mpip_rcv_options);



static int __init mpipinit(void)
{
    printk(KERN_ALERT "*************************\n");
    printk(KERN_ALERT "enter mpip module!\n");
    printk(KERN_ALERT "*************************\n");

//	int newval;
//	int newlen = sizeof(int);
//	newval = 1;
//
//    sysctlbyname("net.mpip.mpip_enabled", NULL, 0, newval, newlen);

//    witable = kmalloc(sizeof(struct working_ip_table), GFP_KERNEL);
//    INIT_LIST_HEAD(&witable->list);
//
//    pitable = kmalloc(sizeof(struct path_info_table), GFP_KERNEL);
//    INIT_LIST_HEAD(&pitable->list);
//
//    sstable = kmalloc(sizeof(struct sender_session_table), GFP_KERNEL);
//    INIT_LIST_HEAD(&sstable->list);
//
//    rstable = kmalloc(sizeof(struct receiver_socket_table), GFP_KERNEL);
//    INIT_LIST_HEAD(&rstable->list);
//
//    pstable = kmalloc(sizeof(struct path_stat_table), GFP_KERNEL);
//    INIT_LIST_HEAD(&pstable->list);

    return 0;
}

static void __exit mpipexit(void)
{

    printk(KERN_ALERT "*************************\n");
    printk(KERN_ALERT "exit mpip module!\n");
    printk(KERN_ALERT "*************************\n");
}

module_init(mpipinit);
module_exit(mpipexit);
