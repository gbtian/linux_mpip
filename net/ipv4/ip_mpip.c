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

void print_mpip_options(struct mpip_options opt)
{
	int i;
	printk("node_id:\n");
	for(i = 0; i < ETH_ALEN; i++)
		printk("%02x", opt.node_id[i]);
	printk("\nsession_id: %d\n", opt.session_id);
	printk("path_id: %d\n", opt.path_id);
	printk("stat_path_id: %d\n", opt.stat_path_id);
	printk("packetcount: %d\n", opt.packetcount);

}

void mpip_options_build(struct sk_buff *skb, struct ip_options *opt)
{
	int err;
	//char options[3 + 4 + 1];
	unsigned char *iph;
//	memset(options, 0, sizeof(options));
//	options[0] = IPOPT_NOP;
//	options[1+IPOPT_OPTVAL] = IPOPT_MPIP;
//	options[1+IPOPT_OLEN] = sizeof(options)-1;
//	options[1+IPOPT_OFFSET] = IPOPT_MINOFF;
//    options[4] = 8; //session id
//    options[5] = 3; //path id
//    options[6] = 4; //stat path id
//    options[7] = 50; //packet count
//

    //printk("%s:%d - %s\n", __FILE__, __LINE__, __FUNCTION__ );
    //struct ip_options_rcu *opt = NULL;
    //err = ip_options_get(sock_net(skb->sk), &opt, options, 8);
    //printk("%s:%d - %s\n", __FILE__, __LINE__, __FUNCTION__ );

    //printk("opt->opt.optlen= %d\n", opt->opt.optlen);
    //printk("%s:%d - %s\n", __FILE__, __LINE__, __FUNCTION__ );
    //printk("options= %s\n", options);
    //printk("%s:%d - %s\n", __FILE__, __LINE__, __FUNCTION__ );


    iph = skb_network_header(skb);

	memcpy(&(IPCB(skb)->opt), opt, sizeof(struct ip_options));
	memcpy(iph+sizeof(struct iphdr), opt->__data, opt->optlen);


	//opt = kmalloc(sizeof(struct mpip_options), GFP_KERNEL);
	//if (!opt)
	//{
	//	printk("opt==NULL\n");
	//}
	//else
	//{
//		opt->optlen = sizeof(struct mpip_options);
//		//	memcpy(opt->node_id, eth->h_dest, ETH_ALEN);
//		opt->session_id = 8;
//		opt->path_id = 3;
//		opt->stat_path_id = 4;
//		opt->packetcount = 500;
//
//		print_mpip_options(opt);
//		kfree(opt);
//
//	}

//	//todo: the value of option will be extracted from all the tables.
//
//	//iph = skb_network_header(skb);
//
//	//memcpy(&(skb->cb), opt, sizeof(struct mpip_options));
//	//memcpy(iph+sizeof(struct iphdr), opt->__data, opt->optlen);
//

}
EXPORT_SYMBOL(mpip_options_build);

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
