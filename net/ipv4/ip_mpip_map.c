#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/tcp.h>
#include <net/xfrm.h>
#include <net/icmp.h>
#include <linux/ip_mpip.h>


static unsigned char static_session_id = 1;
static unsigned char static_path_id = 1;
static unsigned long earliest_fbjiffies = 0;

static LIST_HEAD(mq_head);
static LIST_HEAD(me_head);
static LIST_HEAD(an_head);
static LIST_HEAD(wi_head);
static LIST_HEAD(pi_head);
static LIST_HEAD(ss_head);
static LIST_HEAD(la_head);
static LIST_HEAD(ps_head);

int global_stat_1;
int global_stat_2;
int global_stat_3;

bool is_equal_node_id(unsigned char *node_id_1, unsigned char *node_id_2)
{
	int i;

	if (!node_id_1 || !node_id_2)
		return false;

	for(i = 0; i < MPIP_CM_NODE_ID_LEN; i++)
	{
		if (node_id_1[i] != node_id_2[i])
			return false;
	}

	return true;
}

void print_node_id(unsigned char *node_id)
{
	if (!node_id)
		return;
	mpip_log( "%02x-%02x\n", node_id[0], node_id[1]);
}

bool is_lan_addr(__be32 addr)
{
	char *p = (char *) &addr;

	if ((p[0] & 255) == 192 &&
		(p[1] & 255) == 168)
	{
		return true;
	}
	return false;
}

void print_addr(__be32 addr)
{
	char *p = (char *) &addr;
	mpip_log( "%d.%d.%d.%d\n",
			(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

}


__be32 convert_addr(char a1, char a2, char a3, char a4)
{
	__be32 addr;
	char *p = (char *) &addr;
	p[0] = a1;
	p[1] = a2;
	p[2] = a3;
	p[3] = a4;

	return (__be32)addr;
}


char *in_ntoa(unsigned long in)
{
	char *buff = kzalloc(18, GFP_ATOMIC);
	char *p;

	p = (char *) &in;
	sprintf(buff, "%d.%d.%d.%d",
		(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

	return(buff);
}

struct mpip_query_table *find_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct mpip_query_table *mpip_query;

	list_for_each_entry(mpip_query, &mq_head, list)
	{
		if ((saddr == mpip_query->saddr) && (daddr == mpip_query->daddr) &&
			(sport == mpip_query->sport) && (dport == mpip_query->dport))
		{
			return mpip_query;
		}
	}

	return NULL;
}
int delete_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct mpip_query_table *mpip_query;
	struct mpip_query_table *tmp_query;
	list_for_each_entry_safe(mpip_query, tmp_query, &mq_head, list)
	{
		if ((saddr == mpip_query->saddr) && (daddr == mpip_query->daddr) &&
			(sport == mpip_query->sport) && (dport == mpip_query->dport))
		{
			mpip_log("%s, %d\n", __FILE__, __LINE__);
			list_del(&(mpip_query->list));
			kfree(mpip_query);

			return 1;
		}
	}

	return 0;
}

int add_mpip_query(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct mpip_query_table *item = find_mpip_query(saddr, daddr, sport, dport);

	if (item)
	{
		return 0;
	}

	item = kzalloc(sizeof(struct mpip_query_table),	GFP_ATOMIC);
	item->saddr = saddr;
	item->daddr = daddr;
	item->sport = sport;
	item->dport = dport;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &mq_head);

	mpip_log( "mq: %d, %d, %s, %s, %d\n", sport, dport, __FILE__, __FUNCTION__, __LINE__);
	print_addr(saddr);
	print_addr(saddr);

	return 1;
}

struct mpip_enabled_table *find_mpip_enabled(__be32 addr, __be16 port)
{
	struct mpip_enabled_table *mpip_enabled;

	list_for_each_entry(mpip_enabled, &me_head, list)
	{
		if ((addr == mpip_enabled->addr) && (port == mpip_enabled->port))
		{
			return mpip_enabled;
		}
	}

	return NULL;
}


int add_mpip_enabled(__be32 addr, __be16 port, bool enabled)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct mpip_enabled_table *item = find_mpip_enabled(addr, port);

	if (item)
	{
		item->mpip_enabled = enabled;
		return 0;
	}

	item = kzalloc(sizeof(struct mpip_enabled_table),	GFP_ATOMIC);
	item->addr = addr;
	item->port = port;
	item->mpip_enabled = enabled;
	item->sent_count = 0;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &me_head);

	mpip_log( "me: %d, %d\n", port, enabled);
	print_addr(addr);

	return 1;
}

bool is_mpip_enabled(__be32 addr, __be16 port)
{
	bool enabled = false;
	struct mpip_enabled_table *item = NULL;

	if (!sysctl_mpip_enabled)
		enabled = false;

	item = find_mpip_enabled(addr, port);

	if (!item)
		enabled = false;
	else
		enabled = item->mpip_enabled;

	return enabled;
}

bool is_local_addr(__be32 addr)
{
	if (find_local_addr(addr) > 0)
		return true;

	return false;
}

int add_working_ip(unsigned char *node_id, __be32 addr, __be16 port, unsigned char session_id)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct working_ip_table *item = NULL;


	if (!node_id)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	item = find_working_ip(node_id, addr, port);
	if (item)
	{
		item->session_id = session_id;
		return 0;
	}

	item = kzalloc(sizeof(struct working_ip_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
	item->addr = addr;
	item->port = port;
	item->session_id = session_id;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &wi_head);

//	mpip_log( "wi:");
//
//	print_node_id(__FUNCTION__, node_id);
//	print_addr(__FUNCTION__, addr);

	return 1;
}

struct working_ip_table *find_working_ip(unsigned char *node_id, __be32 addr, __be16 port)
{
	struct working_ip_table *working_ip;

	if (!node_id)
		return NULL;

	list_for_each_entry(working_ip, &wi_head, list)
	{
		if (is_equal_node_id(node_id, working_ip->node_id) &&
				(addr == working_ip->addr) &&
				(port == working_ip->port))
		{
			return working_ip;
		}
	}

	return NULL;
}

unsigned char * find_node_id_in_working_ip(__be32 addr, __be16 port)
{
	struct working_ip_table *working_ip;

	list_for_each_entry(working_ip, &wi_head, list)
	{
		if ((addr == working_ip->addr) && (port == working_ip->port))
		{
			return working_ip->node_id;
		}
	}

	return NULL;
}

struct addr_notified_table *find_addr_notified(unsigned char *node_id)
{
	struct addr_notified_table *addr_notified;

	if (!node_id)
		return NULL;

	list_for_each_entry(addr_notified, &an_head, list)
	{
		if (is_equal_node_id(node_id, addr_notified->node_id))
		{
			return addr_notified;
		}
	}

	return NULL;
}

bool get_addr_notified(unsigned char *node_id)
{
	bool notified = true;
	struct addr_notified_table *addr_notified = find_addr_notified(node_id);
	if (addr_notified)
	{
		notified = addr_notified->notified;
		if (!notified)
		{
			addr_notified->count += 1;
			if (addr_notified->count > 5)
			{
				addr_notified->notified = true;
				addr_notified->count = 0;
			}
		}
		else
			addr_notified->count = 0;

//		mpip_log("%d, %s, %d\n", notified, __FILE__, __LINE__);
		return notified;
	}

	return true;
}

int add_addr_notified(unsigned char *node_id)
{
	struct addr_notified_table *item = NULL;


	if (!node_id)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	if (find_addr_notified(node_id))
		return 0;


	item = kzalloc(sizeof(struct addr_notified_table),	GFP_ATOMIC);

	memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
	item->notified = true;
	item->count = 0;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &an_head);

//	mpip_log( "an:");
//
//	print_node_id(__FUNCTION__, node_id);

	return 1;
}

void send_mpip_hb(struct sk_buff *skb)
{
	if (!skb)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return;
	}

//	printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
	if (((jiffies - earliest_fbjiffies) / (HZ / 100)) >= sysctl_mpip_hb)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		if (send_mpip_msg(skb, false, true, 2))
			earliest_fbjiffies = jiffies;
	}
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
		if (send_mpip_msg(skb, sender, reverse, 3))
			item->sent_count += 1;
	}
	else
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		add_mpip_enabled(addr, port, false);
		send_mpip_msg(skb, sender, reverse, 3);
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

		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		if (find_mpip_query(iph->saddr, iph->daddr, tcph->source, tcph->dest))
		{
			mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			send_mpip_msg(skb, sender, reverse, 4);
			delete_mpip_query(iph->saddr, iph->daddr, tcph->source, tcph->dest);
		}
	}
	else if (iph->protocol == IPPROTO_UDP)
	{
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		send_mpip_msg(skb, sender, reverse, 4);
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
static bool copy_and_send(struct sk_buff *skb, bool reverse, unsigned char flags)
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
	if (iph->frag_off & htons(IP_OFFSET))
	{
		kfree_skb(nskb);
		printk("%s, %d\n", __FILE__, __LINE__);
		return false;
	}

	if (reverse)
	{
		reverse_addr_and_port(nskb);
	}

	iph = ip_hdr(nskb);

	mpip_log("%d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
	if (!insert_mpip_cm(nskb, iph->saddr, iph->daddr, &new_saddr, &new_daddr, iph->protocol, flags))
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

	if (ip_route_out(nskb, iph->daddr))
	{
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


static bool new_and_send(struct sk_buff *skb_in, bool reverse, unsigned char flags)
{
	struct iphdr *iph, *iph_in;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	__be32 new_saddr=0, new_daddr=0;
	struct net_device *new_dst_dev = NULL;
	int err = 0;
	struct sk_buff *skb = NULL;
	__be16 srcport, dstport;

    int total_len, eth_len, ip_len, udp_len, header_len;


	// 设置各个协议数据长度
    udp_len = sizeof(*udph);
    ip_len = eth_len = udp_len + sizeof(*iph);
    total_len = eth_len + ETH_HLEN + NET_IP_ALIGN;
    header_len = total_len;

	if(!skb_in)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return false;
	}

	iph_in = ip_hdr(skb_in);
	if (iph_in == NULL)
	{
		printk("%s, %d\n", __FILE__, __LINE__);
		return false;
	}

	if(iph_in->protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(skb_in); //this fixed the problem
		if (!tcph)
		{
			printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return false;
		}
		if (reverse)
		{
			srcport = tcph->dest;
			dstport = tcph->source;
		}
		else
		{
			srcport = tcph->source;
			dstport = tcph->dest;
		}
	}
	else if(iph_in->protocol == IPPROTO_UDP)
	{
		udph = udp_hdr(skb_in); //this fixed the problem
		if (!udph)
		{
			printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return false;
		}

		if (reverse)
		{
			srcport = udph->dest;
			dstport = udph->source;
		}
		else
		{
			srcport = udph->source;
			dstport = udph->dest;
		}
	}
	else
	{
		return false;
	}


	skb = alloc_skb(234, GFP_ATOMIC );
	if ( !skb ) {
		printk( "alloc_skb fail.\n" );
		return false;
	}

	// 预先保留skb的协议首部长度大小
	skb_reserve(skb, 234);

	skb_orphan(skb);

	if(iph_in->protocol == IPPROTO_TCP)
	{
		skb_push(skb, sizeof(struct tcphdr));
		skb_reset_transport_header(skb);
		tcph = tcp_hdr(skb);

		tcph->seq = 0;
		tcph->ack_seq	= 0;
		tcph->source = srcport;
		tcph->dest = dstport;
		tcph->check = 0;
		tcph->urg_ptr = 0;
	}
	else if(iph_in->protocol == IPPROTO_UDP)
	{
		skb_push(skb, sizeof(struct udphdr));
		skb_reset_transport_header(skb);
		udph = udp_hdr(skb);
		udph->source = srcport;
		udph->dest = dstport;
		udph->len = htons(sizeof(struct udphdr));
		udph->check = 0;
	}

	// skb->data 移动到ip首部
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
	iph->protocol = iph_in->protocol;
	iph->check    = 0;

	if (reverse)
	{
		iph->saddr = iph_in->daddr;
		iph->daddr = iph_in->saddr;
	}
	else
	{
		iph->saddr = iph_in->saddr;
		iph->daddr = iph_in->daddr;
	}

	mpip_log("sending: %d, %s, %s, %d\n", ip_hdr(skb)->id, __FILE__, __FUNCTION__, __LINE__);
	print_addr(ip_hdr(skb)->saddr);
	print_addr(ip_hdr(skb)->daddr);

	if (!insert_mpip_cm(skb, iph->saddr, iph->daddr, &new_saddr, &new_daddr, iph->protocol, flags))
	{
		kfree_skb(skb);
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	mpip_log("sending: %d, %s, %s, %d\n", ip_hdr(skb)->id, __FILE__, __FUNCTION__, __LINE__);
	print_addr(ip_hdr(skb)->saddr);
	print_addr(ip_hdr(skb)->daddr);
	if (new_saddr != 0)
	{
		new_dst_dev = find_dev_by_addr(new_saddr);
		if (new_dst_dev)
		{
			iph->saddr = new_saddr;
			iph->daddr = new_daddr;

			mpip_log("sending: %d, %s, %s, %d\n", ip_hdr(skb)->id, __FILE__, __FUNCTION__, __LINE__);
			print_addr(ip_hdr(skb)->saddr);
			print_addr(ip_hdr(skb)->daddr);
		}
	}

	mpip_log("sending: %d, %s, %s, %d\n", ip_hdr(skb)->id, __FILE__, __FUNCTION__, __LINE__);
	print_addr(ip_hdr(skb)->saddr);
	print_addr(ip_hdr(skb)->daddr);

	if (ip_route_out(skb, ip_hdr(skb)->daddr))
	{
		skb->dev = find_dev_by_addr(iph->saddr);
		err = __ip_local_out(skb);
		if (likely(err == 1))
			err = dst_output(skb);
	}
	else
	{
		kfree_skb(skb);
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	mpip_log("%d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);

	return true;
}



static bool new_udp_and_send(struct sk_buff *skb_in, bool reverse, unsigned char flags)
{
	struct iphdr *iph, *iph_in;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	__be32 new_saddr=0, new_daddr=0;
	struct net_device *new_dst_dev = NULL;
	int err = 0;
	struct sk_buff *skb = NULL;
	__be16 srcport, dstport;

    int total_len, eth_len, ip_len, udp_len, header_len;


	// 设置各个协议数据长度
    udp_len = sizeof(*udph);
    ip_len = eth_len = udp_len + sizeof(*iph);
    total_len = eth_len + ETH_HLEN + NET_IP_ALIGN;
    header_len = total_len;

	if(!skb_in)
	{
		mpip_log("%s, %d\n", __FILE__, __LINE__);
		return false;
	}

	iph_in = ip_hdr(skb_in);
	if (iph_in == NULL)
	{
		printk("%s, %d\n", __FILE__, __LINE__);
		return false;
	}

	if(iph_in->protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(skb_in); //this fixed the problem
		if (!tcph)
		{
			printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return false;
		}
		if (reverse)
		{
			srcport = tcph->dest;
			dstport = tcph->source;
		}
		else
		{
			srcport = tcph->source;
			dstport = tcph->dest;
		}
	}
	else if(iph_in->protocol == IPPROTO_UDP)
	{
		udph = udp_hdr(skb_in); //this fixed the problem
		if (!udph)
		{
			printk("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
			return false;
		}

		if (reverse)
		{
			srcport = udph->dest;
			dstport = udph->source;
		}
		else
		{
			srcport = udph->source;
			dstport = udph->dest;
		}
	}


	skb = alloc_skb(234, GFP_ATOMIC );
	if ( !skb ) {
		printk( "alloc_skb fail.\n" );
		return false;
	}

	// 预先保留skb的协议首部长度大小
	skb_reserve(skb, 234);

	// skb->data 移动到udp首部
	skb_push(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);
	udph = udp_hdr(skb);
	udph->source = srcport;
	udph->dest = dstport;
	udph->len = htons(sizeof(struct udphdr));
	udph->check = 0;


	// skb->data 移动到ip首部
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
	iph->protocol = IPPROTO_UDP;
	iph->check    = 0;

	if (reverse)
	{
		iph->saddr = iph_in->daddr;
		iph->daddr = iph_in->saddr;
	}
	else
	{
		iph->saddr = iph_in->saddr;
		iph->daddr = iph_in->daddr;
	}

	mpip_log("%d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
	if (!insert_mpip_cm(skb, iph->saddr, iph->daddr, &new_saddr, &new_daddr, iph->protocol, flags))
	{
		kfree_skb(skb);
		mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
		return false;
	}

	if (new_saddr != 0)
	{
		new_dst_dev = find_dev_by_addr(new_saddr);
		if (new_dst_dev)
		{
			mpip_log("sending: %d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
			print_addr(iph->saddr);
			print_addr(iph->daddr);
			if (ip_route_out(skb, new_daddr))
			{
				iph->saddr = new_saddr;
				iph->daddr = new_daddr;
				skb->dev = find_dev_by_addr(iph->saddr);
			}
			else
			{
				kfree_skb(skb);
				mpip_log("%s, %s, %d\n", __FILE__, __FUNCTION__, __LINE__);
				return false;
			}

			mpip_log("sending: %d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);
			print_addr(iph->saddr);
			print_addr(iph->daddr);
		}
	}

	err = __ip_local_out(skb);
	if (likely(err == 1))
		err = dst_output(skb);

	mpip_log("%d, %s, %s, %d\n", iph->id, __FILE__, __FUNCTION__, __LINE__);

	return true;
}

bool ip_route_out( struct sk_buff *skb, __be32 daddr)
{
    struct flowi4 fl = {};
    struct rtable *rt = NULL;

    fl.daddr = daddr;
    rt = ip_route_output_key(&init_net, &fl);
    if (rt)
    {
		printk( "route output dev=%s\n", rt->dst.dev->name  );
		skb_dst_set_noref(skb, &(rt->dst));

		return true;
    }
    return false;

}

bool send_mpip_msg(struct sk_buff *skb_in, bool sender, bool reverse, unsigned char flags)
{
	//return new_and_send(skb_in, reverse, flags);
	return copy_and_send(skb_in, reverse, flags);
}

void process_addr_notified_event(unsigned char *node_id, unsigned char flags)
{
//	struct working_ip_table *working_ip;
//	struct working_ip_table *tmp_ip;

	struct path_info_table *path_info;
	struct path_info_table *tmp_info;

	struct path_stat_table *path_stat;
	struct path_stat_table *tmp_stat;

	if (!node_id || flags != 1)
		return;

	if (node_id[0] == node_id[1])
	{
		return;
	}

	mpip_log("%s, %d\n", __FILE__, __LINE__);



//	list_for_each_entry_safe(working_ip, tmp_ip, &wi_head, list)
//	{
//		if (is_equal_node_id(node_id, working_ip->node_id))
//		{
//			mpip_log("%s, %d\n", __FILE__, __LINE__);
//			list_del(&(working_ip->list));
//			kfree(working_ip);
//		}
//	}

	list_for_each_entry_safe(path_info, tmp_info, &pi_head, list)
	{
		if (is_equal_node_id(node_id, path_info->node_id))
		{
//			mpip_log("%s, %d\n", __FILE__, __LINE__);
			list_del(&(path_info->list));
			kfree(path_info);
		}
	}

	list_for_each_entry_safe(path_stat, tmp_stat, &ps_head, list)
	{
		if (is_equal_node_id(node_id, path_stat->node_id))
		{
//			mpip_log("%s, %d\n", __FILE__, __LINE__);
			list_del(&(path_stat->list));
			kfree(path_stat);
		}
	}
}

int update_path_stat_delay(unsigned char *node_id, unsigned char path_id, u32 delay)
{
/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	struct path_stat_table *path_stat;
    struct timespec tv;
	u32  midtime;

	if (!node_id || (path_id == 0))
		return 0;

	if (node_id[0] == node_id[1])
		return 0;

	path_stat = find_path_stat(node_id, path_id);
	if (path_stat)
	{
		getnstimeofday(&tv);
		midtime = (tv.tv_sec % 86400) * MSEC_PER_SEC * 100  + 100 * tv.tv_nsec / NSEC_PER_MSEC;

		path_stat->delay = midtime - delay;
	}


	return 1;
}


int update_path_delay(unsigned char path_id, __s32 delay)
{
    struct path_info_table *path_info;
	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->path_id == path_id)
		{
			if (path_info->count == 0)
			{
				path_info->delay = delay;
			}

			path_info->delay = (99 * path_info->delay + delay) / 100;
			if (path_info->count < 10)
			{
				path_info->min_delay = path_info->delay;
				path_info->count += 1;
			}
			else
			{
				if (path_info->min_delay > path_info->delay)
				{
					path_info->min_delay = path_info->delay;
				}
			}

			path_info->queuing_delay = path_info->delay - path_info->min_delay;
			if (path_info->queuing_delay > path_info->max_queuing_delay)
			{
				path_info->max_queuing_delay = path_info->queuing_delay;
			}

			break;
		}
	}

	return 1;
}



__s32 calc_si_diff(void)
{
	__s32 si = 0;
	__s32 K = 0;
	__s32 sigma = 0;
	__s32 diff = 0;
	__s32 max = 0;
	struct path_info_table *path_info, *prev_info;
	list_for_each_entry(path_info, &pi_head, list)
	{
		prev_info = list_entry(path_info->list.prev, typeof(*path_info), list);
		if (!prev_info)
			continue;
		

		diff = (path_info->queuing_delay - prev_info->queuing_delay > 0) ? 
		       (path_info->queuing_delay - prev_info->queuing_delay) :
		       (prev_info->queuing_delay - path_info->queuing_delay);
		
		max = (path_info->queuing_delay > prev_info->queuing_delay) ? 
		       path_info->queuing_delay : prev_info->queuing_delay;
		
		if (max > diff)
		{
			sigma += (100 * diff) / (max + 500);
			++K;
		}

		//printk("%d, %d, %d, %d, %d\n", diff, max, (100 * diff) / (max + 500), sigma, __LINE__);
	}

	if (K == 0)
		si = 0;
	else
		si = sigma / K;
	
	return 100 - si;
}

__s32 calc_diff(__s32 queuing_delay, __s32 min_queuing_delay)
{
	__s32 diff = queuing_delay - min_queuing_delay;
	__s32 si = calc_si_diff();
	//printk("%d, %s, %d\n", si, __FILE__, __LINE__);
	return diff / (sysctl_mpip_bw_factor * si);
}

int update_path_info(void)
{
	struct path_info_table *path_info;
	__s32 min_queuing_delay = -1;
	__s32 max_queuing_delay = 0;


	__u64 max_bw = 0;


	list_for_each_entry(path_info, &pi_head, list)
	{
		if (path_info->queuing_delay < min_queuing_delay || min_queuing_delay == -1)
		{
			min_queuing_delay = path_info->queuing_delay;
		}

		if (path_info->queuing_delay > max_queuing_delay)
		{
			max_queuing_delay = path_info->queuing_delay;
		}
	}

	if (min_queuing_delay == -1)
		return 0;

	list_for_each_entry(path_info, &pi_head, list)
	{
		__s32 diff = calc_diff(path_info->queuing_delay, min_queuing_delay);

		path_info->bw += max_queuing_delay / (diff + 1);

		if (path_info->bw > max_bw)
			max_bw = path_info->bw;

	}


	if (max_bw > 5000)
	{
		__u64 times = max_bw / 5000;
		list_for_each_entry(path_info, &pi_head, list)
		{
			path_info->bw /= times;
			if (path_info->bw <= 0)
				path_info->bw = 10;
		}
	}

	return 1;
}


struct path_stat_table *find_path_stat(unsigned char *node_id, unsigned char path_id)
{
	struct path_stat_table *path_stat;

	if (!node_id || (path_id == 0))
		return NULL;

	list_for_each_entry(path_stat, &ps_head, list)
	{
		if (is_equal_node_id(node_id, path_stat->node_id) &&
			(path_stat->path_id == path_id))
		{
			return path_stat;
		}
	}

	return NULL;
}

int add_path_stat(unsigned char *node_id, unsigned char path_id)
{
	struct path_stat_table *item = NULL;

	if (!node_id || (path_id == 0))
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	if (find_path_stat(node_id, path_id))
		return 0;


	item = kzalloc(sizeof(struct path_stat_table),	GFP_ATOMIC);


	memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
	item->path_id = path_id;
	item->delay = 0;
	item->fbjiffies = jiffies;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &ps_head);

	//mpip_log( "ps: %d", path_id);
	//print_node_id(node_id);

	return 1;
}


unsigned char get_sender_session(__be32 saddr, __be16 sport,
								 __be32 daddr, __be16 dport)
{
	struct socket_session_table *socket_session;

//	printk("%s, %d\n", __FILE__, __LINE__);
//	print_addr(__FUNCTION__, saddr);
//	print_addr(__FUNCTION__, daddr);
//	printk("%d, %d, %s, %d\n", sport, dport, __FILE__, __LINE__);


	list_for_each_entry(socket_session, &ss_head, list)
	{
		if ((socket_session->saddr == saddr) &&
			(socket_session->sport == sport) &&
			(socket_session->daddr == daddr) &&
			(socket_session->dport == dport))
		{
//			printk("%s, %d\n", __FILE__, __LINE__);
//			print_addr(__FUNCTION__, saddr);
//			print_addr(__FUNCTION__, daddr);
//			printk("%d, %d, %s, %d\n", sport, dport, __FILE__, __LINE__);

			return socket_session->session_id;
		}
	}

	return 0;
}

int add_sender_session(unsigned char *src_node_id, unsigned char *dst_node_id,
					   __be32 saddr, __be16 sport,
					   __be32 daddr, __be16 dport)
{
	struct socket_session_table *item = NULL;

//	if (!is_lan_addr(saddr) || !is_lan_addr(daddr))
//	{
//		return 0;
//	}

	if (!src_node_id || !dst_node_id)
		return 0;

	if ((src_node_id[0] == src_node_id[1]) || (dst_node_id[0] == dst_node_id[1]))
	{
		return 0;
	}

	if (get_sender_session(saddr, sport, daddr, dport) > 0)
		return 0;


	item = kzalloc(sizeof(struct socket_session_table),	GFP_ATOMIC);

	memcpy(item->src_node_id, src_node_id, MPIP_CM_NODE_ID_LEN);
	memcpy(item->dst_node_id, dst_node_id, MPIP_CM_NODE_ID_LEN);

	INIT_LIST_HEAD(&(item->tcp_buf));
	item->next_seq = 0;
	item->buf_count = 0;

	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->session_id = (static_session_id > 250) ? 1 : ++static_session_id;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &ss_head);

//	mpip_log("%s, %d\n", __FILE__, __LINE__);
//	print_addr(__FUNCTION__, saddr);
//	print_addr(__FUNCTION__, daddr);
//	mpip_log( "ss: %d,%d,%d\n", item->session_id,
//			sport, dport);
//	mpip_log("%s, %d\n", __FILE__, __LINE__);

	return 1;
}



unsigned char find_receiver_session(unsigned char *node_id, unsigned char session_id)
{
	struct socket_session_table *socket_session;

	if (!node_id)
		return 0;

	list_for_each_entry(socket_session, &ss_head, list)
	{
		if (is_equal_node_id(socket_session->dst_node_id, node_id) &&
			(socket_session->session_id == session_id))
		{
			return socket_session->session_id;
		}
	}

	return 0;
}

unsigned char get_receiver_session_id(unsigned char *src_node_id, unsigned char *dst_node_id,
						__be32 saddr, __be16 sport,
		 	 	 	 	__be32 daddr, __be16 dport,
		 	 	 	 	unsigned char session_id,
		 	 	 	 	unsigned char path_id)
{
	struct socket_session_table *item = NULL;
	int sid;


	if (!src_node_id || !dst_node_id || !session_id)
		return 0;

	if ((src_node_id[0] == src_node_id[1]) || (dst_node_id[0] == dst_node_id[1]))
	{
		return 0;
	}

	static_session_id = (static_session_id > session_id) ? static_session_id : session_id;

	sid = find_receiver_session(dst_node_id, session_id);
	if (sid > 0)
		return sid;

	printk("%s, %d\n", __FILE__, __LINE__);
	print_addr(saddr);
	print_addr(daddr);
	printk("%d, %d, %s, %d\n", sport, dport, __FILE__, __LINE__);

//	sid = get_sender_session(saddr, sport, daddr, dport);
//	if (sid > 0)
//		return sid;

	if (path_id > 0)
		return 0;

	item = kzalloc(sizeof(struct socket_session_table), GFP_ATOMIC);

	memcpy(item->src_node_id, src_node_id, MPIP_CM_NODE_ID_LEN);
	memcpy(item->dst_node_id, dst_node_id, MPIP_CM_NODE_ID_LEN);

	INIT_LIST_HEAD(&(item->tcp_buf));
	item->next_seq = 0;
	item->buf_count = 0;

	item->saddr = saddr;
	item->sport = sport;
	item->daddr = daddr;
	item->dport = dport;
	item->session_id = session_id;
	INIT_LIST_HEAD(&(item->list));
	list_add(&(item->list), &ss_head);

//	mpip_log("%s, %d\n", __FILE__, __LINE__);
//	print_addr(__FUNCTION__, saddr);
//	print_addr(__FUNCTION__, daddr);
//	mpip_log( "ss: %d,%d,%d\n", item->session_id,
//			sport, dport);
//	mpip_log("%s, %d\n", __FILE__, __LINE__);

	return item->session_id;
}

int get_receiver_session_info(unsigned char *node_id,	unsigned char session_id,
						__be32 *saddr, __be16 *sport,
						__be32 *daddr, __be16 *dport)
{
	struct socket_session_table *socket_session;

	if (!node_id || (session_id <= 0))
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	list_for_each_entry(socket_session, &ss_head, list)
	{
		if (is_equal_node_id(socket_session->dst_node_id, node_id) &&
				(socket_session->session_id == session_id))
		{
			*saddr = socket_session->saddr;
			*daddr = socket_session->daddr;
			*sport = socket_session->sport;
			*dport = socket_session->dport;

			return 1;
		}
	}

	return 0;
}

int add_to_tcp_skb_buf(struct sk_buff *skb, unsigned char session_id)
{
	struct tcphdr *tcph = NULL;
	struct socket_session_table *socket_session;
	struct tcp_skb_buf *item = NULL;
	struct tcp_skb_buf *tcp_buf = NULL;
	struct tcp_skb_buf *tmp_buf = NULL;

	rcu_read_lock();

	list_for_each_entry(socket_session, &ss_head, list)
	{
		if (socket_session->session_id == session_id)
		{
			tcph = tcp_hdr(skb);
			if (!tcph)
			{
				mpip_log("%s, %d\n", __FILE__, __LINE__);
				goto fail;
			}

			if ((ntohl(tcph->seq) < socket_session->next_seq) &&
				(socket_session->next_seq) - ntohl(tcph->seq) < 0xFFFFFFF)
			{
				mpip_log("late: %u, %u, %s, %d\n", ntohl(tcph->seq), socket_session->next_seq, __FILE__, __LINE__);
				dst_input(skb);
				goto success;
			}

			if ((socket_session->next_seq == 0) ||
				(ntohl(tcph->seq) == socket_session->next_seq) ||
				(ntohl(tcph->seq) == socket_session->next_seq + 1)) //for three-way handshake
			{
				socket_session->next_seq = skb->len - ip_hdr(skb)->ihl * 4 - tcph->doff * 4 + ntohl(tcph->seq);
				mpip_log("send: %u, %u, %s, %d\n", ntohl(tcph->seq), socket_session->next_seq, __FILE__, __LINE__);
				dst_input(skb);

recursive:
				list_for_each_entry_safe(tcp_buf, tmp_buf, &(socket_session->tcp_buf), list)
				{
					if (tcp_buf->seq == socket_session->next_seq)
					{
						socket_session->next_seq = tcp_buf->skb->len - ip_hdr(tcp_buf->skb)->ihl * 4 -
																	   tcp_hdr(tcp_buf->skb)->doff * 4 + tcp_buf->seq;
						mpip_log("push: %u, %u, %s, %d\n", tcp_buf->seq, socket_session->next_seq, __FILE__, __LINE__);

						dst_input(tcp_buf->skb);

						list_del(&(tcp_buf->list));
						kfree(tcp_buf);

						socket_session->buf_count -= 1;

						goto recursive;
					}
				}
				goto success;
			}


			item = kzalloc(sizeof(struct tcp_skb_buf),	GFP_ATOMIC);
			if (!item)
				goto fail;

			item->seq = ntohl(tcph->seq);
			item->skb = skb;
			item->fbjiffies = jiffies;
			INIT_LIST_HEAD(&(item->list));
			list_add(&(item->list), &(socket_session->tcp_buf));
			socket_session->buf_count += 1;

			mpip_log("out of order: %u, %u, %d, %s, %d\n", ntohl(tcph->seq),
					socket_session->next_seq, socket_session->buf_count,
					__FILE__, __LINE__);

			goto success;
		}
	}


success:
	rcu_read_unlock();
	return 1;
fail:
	rcu_read_unlock();
	mpip_log("Fail: %s, %d\n", __FILE__, __LINE__);
	return 0;
}

struct path_info_table *find_path_info(__be32 saddr, __be32 daddr, __be16 dport)
{
	struct path_info_table *path_info;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if ((path_info->saddr == saddr) &&
			(path_info->daddr == daddr) &&
			(path_info->dport == dport))
		{
			return path_info;
		}
	}
	return NULL;
}


bool is_dest_added(unsigned char *node_id, __be32 addr, __be16 port, unsigned char session_id)
{
	struct path_info_table *path_info;

	if (!node_id)
		return 0;

	list_for_each_entry(path_info, &pi_head, list)
	{
		if (is_equal_node_id(path_info->node_id, node_id) &&
		   (path_info->daddr == addr) &&
		   (path_info->dport == port) &&
		   (path_info->session_id == session_id))
		{
			return true;
		}
	}
	return false;
}


int add_path_info(unsigned char *node_id, __be32 addr, __be16 port, unsigned char session_id)
{
	struct local_addr_table *local_addr;
	struct path_info_table *item = NULL;
//	__be32 waddr = convert_addr(192, 168, 2, 20);
//	__be32 eaddr = convert_addr(192, 168, 2, 21);

	if (!node_id || session_id <= 0)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	if (is_dest_added(node_id, addr, port, session_id))
		return 0;


	list_for_each_entry(local_addr, &la_head, list)
	{

		item = kzalloc(sizeof(struct path_info_table),	GFP_ATOMIC);

		memcpy(item->node_id, node_id, MPIP_CM_NODE_ID_LEN);
		item->fbjiffies = jiffies;
		item->saddr = local_addr->addr;
		item->daddr = addr;
		item->dport = port;
		item->session_id = session_id;
		item->min_delay = 0;
		item->delay = 0;
		item->queuing_delay = 0;
		item->max_queuing_delay = 0;
		item->count = 0;
		item->bw = 1000;
		item->pktcount = 0;
		item->path_id = (static_path_id > 250) ? 1 : ++static_path_id;
		INIT_LIST_HEAD(&(item->list));
		list_add(&(item->list), &pi_head);

//		mpip_log( "pi: %d\n", item->path_id);
//
//		print_node_id(__FUNCTION__, node_id);
//		print_addr(__FUNCTION__, addr);
	}

	return 1;
}


unsigned char find_fastest_path_id(unsigned char *node_id,
			   __be32 *saddr, __be32 *daddr, __be16 *dport,
			   __be32 origin_saddr, __be32 origin_daddr,
			   __be16 origin_dport, unsigned char session_id)
{
	struct path_info_table *path;
	struct path_info_table *f_path;
	unsigned char f_path_id = 0;

	__u64 totalbw = 0, tmptotal = 0, f_bw = 0;
	int random = 0;
	bool path_done = true;

	if (!node_id || session_id <= 0)
		return 0;

	if (node_id[0] == node_id[1])
	{
		return 0;
	}

	//if comes here, it means all paths have been probed
	list_for_each_entry(path, &pi_head, list)
	{
		if (!is_equal_node_id(path->node_id, node_id) ||
			path->session_id != session_id)
		{
			continue;
		}

// for depreciated path
//		if ((jiffies - path->fbjiffies) / HZ >= sysctl_mpip_hb * 5)
//			continue;

		totalbw += path->bw;

		if (path->bw > f_bw)
		{
			f_bw = path->bw;
			f_path_id = path->path_id;
			f_path = path;
		}

		if (path->delay == 0)
			path_done = false;
	}

	if ((totalbw > 0) || !path_done)
	{
		random = get_random_int() % totalbw;
		random = (random > 0) ? random : -random;
		tmptotal = 0;

		list_for_each_entry(path, &pi_head, list)
		{
			if (!is_equal_node_id(path->node_id, node_id))
				continue;

			if (random < (path->bw + tmptotal))
			{
				f_path_id = path->path_id;
				f_path = path;

				break;
			}
			else
			{
				tmptotal += path->bw;
			}
		}
	}

	if (f_path_id > 0)
	{
		*saddr = f_path->saddr;
		*daddr = f_path->daddr;
		*dport = f_path->dport;
		f_path->pktcount += 1;
	}
	else
	{
		f_path = find_path_info(origin_saddr, origin_daddr, origin_dport);
		if (f_path)
		{
			*saddr = f_path->saddr;
			*daddr = f_path->daddr;
			*dport = f_path->dport;
			f_path->pktcount += 1;
			f_path_id = f_path->path_id;
		}
	}

	return f_path_id;
}


unsigned char find_earliest_path_stat_id(unsigned char *dest_node_id, __s32 *delay)
{
	struct path_stat_table *path_stat;
	struct path_stat_table *e_path_stat;
	unsigned char e_path_stat_id = 0;
	unsigned long e_fbtime = jiffies;
//	int totalrcv = 0;
//	int max_rcvc = 0;

	if (!dest_node_id)
		return 0;


	list_for_each_entry(path_stat, &ps_head, list)
	{
		if (!is_equal_node_id(path_stat->node_id, dest_node_id))
		{
			continue;
		}

		if (path_stat->fbjiffies <= e_fbtime)
		{
			e_path_stat_id = path_stat->path_id;
			e_path_stat = path_stat;
			e_fbtime = path_stat->fbjiffies;
		}
	}

	if (e_path_stat_id > 0)
	{
		e_path_stat->fbjiffies = jiffies;
		earliest_fbjiffies = jiffies;

		*delay = e_path_stat->delay;

		//e_path_stat->delay = 0;

	}

	return e_path_stat_id;
}


__be32 find_local_addr(__be32 addr)
{
	struct local_addr_table *local_addr;

	list_for_each_entry(local_addr, &la_head, list)
	{
		if (local_addr->addr == addr)
		{
			return local_addr->addr;
		}
	}

	return 0;
}

//get the available ip addresses list locally that can be used to send out
//Internet packets
void get_available_local_addr(void)
{
	struct net_device *dev;
	struct local_addr_table *item = NULL;

	for_each_netdev(&init_net, dev)
	{
		if (strstr(dev->name, "lo"))
			continue;

		if (!netif_running(dev))
		{
//			if (dev->ip_ptr && dev->ip_ptr->ifa_list)
//			{
//				mpip_log( "un-active: %lu  ", dev->state);
//				print_addr(__FUNCTION__, dev->ip_ptr->ifa_list->ifa_address);
//			}

			continue;
		}
		if (dev->ip_ptr && dev->ip_ptr->ifa_list)
		{
			if (find_local_addr(dev->ip_ptr->ifa_list->ifa_address))
				continue;

			item = kzalloc(sizeof(struct local_addr_table),	GFP_ATOMIC);
			item->addr = dev->ip_ptr->ifa_list->ifa_address;
			INIT_LIST_HEAD(&(item->list));
			list_add(&(item->list), &la_head);
//			mpip_log( "local addr: %lu  ", dev->state);
//			print_addr(__FUNCTION__, dev->ip_ptr->ifa_list->ifa_address);
		}
	}
}

void update_addr_change(void)
{
	struct local_addr_table *local_addr;
	struct local_addr_table *tmp_addr;
	struct working_ip_table *working_ip;
	struct path_info_table *path_info;
	struct path_info_table *tmp_info;
	struct path_stat_table *path_stat;
	struct path_stat_table *tmp_stat;

//	mpip_log("%s, %d\n", __FILE__, __LINE__);

	struct addr_notified_table *addr_notified;
	list_for_each_entry(addr_notified, &an_head, list)
	{
//		mpip_log("%s, %d\n", __FILE__, __LINE__);
		addr_notified->notified = false;
	}
//	mpip_log("%s, %d\n", __FILE__, __LINE__);
	list_for_each_entry_safe(local_addr, tmp_addr, &la_head, list)
	{
//		mpip_log("%s, %d\n", __FILE__, __LINE__);
		list_del(&(local_addr->list));
		kfree(local_addr);
	}
//	mpip_log("%s, %d\n", __FILE__, __LINE__);
	get_available_local_addr();

	list_for_each_entry_safe(path_info, tmp_info, &pi_head, list)
	{
//		mpip_log("%s, %d\n", __FILE__, __LINE__);
		list_del(&(path_info->list));
		kfree(path_info);
	}

	list_for_each_entry(working_ip, &wi_head, list)
	{
//		mpip_log("%s, %d\n", __FILE__, __LINE__);
		add_path_info(working_ip->node_id, working_ip->addr, working_ip->port, working_ip->session_id);
	}

	list_for_each_entry_safe(path_stat, tmp_stat, &ps_head, list)
	{
			list_del(&(path_stat->list));
			kfree(path_stat);
	}
}

struct net_device *find_dev_by_addr(__be32 addr)
{
	struct net_device *dev;

	for_each_netdev(&init_net, dev)
	{
		if (strstr(dev->name, "lo"))
			continue;

		if (!netif_running(dev))
			continue;

		if (dev->ip_ptr && dev->ip_ptr->ifa_list)
		{
			if (dev->ip_ptr->ifa_list->ifa_address == addr)
				return dev;
		}
	}
	return NULL;
}


static void reset_mpip(void)
{
	struct mpip_enabled_table *mpip_enabled;
	struct mpip_enabled_table *tmp_enabled;

	struct addr_notified_table *addr_notified;
	struct addr_notified_table *tmp_notified;

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

	list_for_each_entry_safe(mpip_enabled, tmp_enabled, &me_head, list)
	{
			list_del(&(mpip_enabled->list));
			kfree(mpip_enabled);
	}

	list_for_each_entry_safe(addr_notified, tmp_notified, &an_head, list)
	{
			list_del(&(addr_notified->list));
			kfree(addr_notified);
	}

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

	static_session_id = 1;
	static_path_id = 1;

	global_stat_1 = 0;
	global_stat_2 = 0;
	global_stat_3 = 0;

}


asmlinkage long sys_mpip(void)
{
	struct mpip_enabled_table *mpip_enbaled;
	struct addr_notified_table *addr_notified;
	struct working_ip_table *working_ip;
	struct path_info_table *path_info;
	struct socket_session_table *socket_session;
	struct path_stat_table *path_stat;
	struct local_addr_table *local_addr;
	char *p;

	printk("******************me*************\n");
	list_for_each_entry(mpip_enbaled, &me_head, list)
	{
		p = (char *) &(mpip_enbaled->addr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		printk("%d  ", mpip_enbaled->port);

		printk("%d  ", mpip_enbaled->sent_count);

		printk("%d\n", mpip_enbaled->mpip_enabled);
	}

	printk("******************an*************\n");
	list_for_each_entry(addr_notified, &an_head, list)
	{
		printk( "%02x-%02x  ",
				addr_notified->node_id[0], addr_notified->node_id[1]);

		printk("%d\n", addr_notified->notified);
	}

	printk("******************wi*************\n");
	list_for_each_entry(working_ip, &wi_head, list)
	{
		printk( "%02x-%02x  ",
				working_ip->node_id[0], working_ip->node_id[1]);

		p = (char *) &(working_ip->addr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		printk("%d  ", working_ip->port);

		printk("%d\n", working_ip->session_id);
	}

	printk("******************ss*************\n");
	list_for_each_entry(socket_session, &ss_head, list)
	{
		printk( "%02x-%02x  ",
				socket_session->src_node_id[0], socket_session->src_node_id[1]);

		printk( "%02x-%02x  ",
						socket_session->dst_node_id[0], socket_session->dst_node_id[1]);

		printk("%d  ", socket_session->session_id);

		p = (char *) &(socket_session->saddr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		p = (char *) &(socket_session->daddr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		printk("%d\t", socket_session->sport);

		printk("%d\n", socket_session->dport);
	}

	printk("******************ps*************\n");
	list_for_each_entry(path_stat, &ps_head, list)
	{
		printk( "%02x-%02x  ",
				path_stat->node_id[0], path_stat->node_id[1]);

		printk("%d  ", path_stat->path_id);
		printk("%d  ", path_stat->delay);
		printk("%lu\n", path_stat->fbjiffies);
	}


	printk("******************la*************\n");
	list_for_each_entry(local_addr, &la_head, list)
	{
		p = (char *) &(local_addr->addr);
		printk( "%d.%d.%d.%d\n",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

	}


	printk("******************pi*************\n");
	list_for_each_entry(path_info, &pi_head, list)
	{
		printk( "%02x-%02x  ",
				path_info->node_id[0], path_info->node_id[1]);

		printk("%d  ", path_info->path_id);

		p = (char *) &(path_info->saddr);

		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		p = (char *) &(path_info->daddr);
		printk( "%d.%d.%d.%d  ",
				(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));

		printk("%d  ", path_info->dport);

		printk("%d  ", path_info->session_id);

		printk("%d  ", path_info->min_delay);

		printk("%d  ", path_info->delay);

		printk("%d  ", path_info->max_queuing_delay);

		printk("%d  ", path_info->queuing_delay);

		printk("%llu  ", path_info->bw);

		printk("%llu  \n", path_info->pktcount);

	}
//
//	printk("******************global stat*************\n");
//	printk("%d  %d  %d\n", global_stat_1, global_stat_2, global_stat_3);

	return 0;

}

asmlinkage long sys_reset_mpip(void)
{
	reset_mpip();
	printk("reset ended\n");
	return 0;
}

//
//void send_udp(struct net_device *odev, u16 local_port,
//		u32 remote_ip, u16 remote_port, u8 *msg, int len)
//{
//    struct sk_buff *skb;
//    int total_len, eth_len, ip_len, udp_len, header_len;
//    struct udphdr *udph;
//    struct iphdr *iph;
//    struct ethhdr *eth;
//    u32 local_ip;
//
//    //local_ip = inet_select_addr(odev, remote_ip, RT_SCOPE_LINK);
//    // 选择网络设备地址
//    local_ip = inet_select_addr(odev, 0, RT_SCOPE_UNIVERSE);
//	printk( "local ip is "NIPQUAD_FMT"/n", NIPQUAD( local_ip ) );
//	local_ip = ntohl( local_ip );
//	if ( !local_ip ) {
//		return;
//	}
//
//	// 设置各个协议数据长度
//    udp_len = len + sizeof(*udph);
//    ip_len = eth_len = udp_len + sizeof(*iph);
//    total_len = eth_len + ETH_HLEN + NET_IP_ALIGN;
//    header_len = total_len - len;
//
//	// 分配skb
//    skb = alloc_skb(234, GFP_ATOMIC );
//    if ( !skb ) {
//    	printk( "alloc_skb fail./n" );
//        return;
//    }
//
//	// 预先保留skb的协议首部长度大小
//     skb_reserve( skb, 234);
//
//	// skb->data 移动到udp首部
//    skb_push(skb, sizeof(*udph));
//    skb_reset_transport_header(skb);
//    udph = udp_hdr(skb);
//    udph->source = htons(local_port);
//    udph->dest = htons(remote_port);
//    udph->len = htons(sizeof(*udph));
//    udph->check = 0;
//    udph->check = csum_tcpudp_magic(htonl(local_ip),
//            htonl(remote_ip),
//            udp_len, IPPROTO_UDP,
//            csum_partial(udph, udp_len, 0));
//    if (udph->check == 0)
//        udph->check = CSUM_MANGLED_0;
//
//	// skb->data 移动到ip首部
//    skb_push(skb, sizeof(*iph));
//    skb_reset_network_header(skb);
//    iph = ip_hdr(skb);
//
//    /* iph->version = 4; iph->ihl = 5; */
//    put_unaligned(0x45, (unsigned char *)iph);
//    iph->tos      = 0;
//    put_unaligned(htons(ip_len), &(iph->tot_len));
//    iph->id       = 0;
//    iph->frag_off = 0;
//    iph->ttl      = 64;
//    iph->protocol = IPPROTO_UDP;
//    iph->check    = 0;
//    put_unaligned(htonl(local_ip), &(iph->saddr));
//    put_unaligned(htonl(remote_ip), &(iph->daddr));
//    iph->check    = ip_fast_csum((unsigned char *)iph, iph->ihl);
//
//	/*
//	// skb->data 移动到eth首部
//     eth = (struct ethhdr *) skb_push(skb, ETH_HLEN);
//    skb_reset_mac_header(skb);
//    skb->protocol = eth->h_proto = htons(ETH_P_IP);
//    memcpy(eth->h_source, dev_addr, ETH_ALEN);
//    memcpy(eth->h_dest, remote_mac, ETH_ALEN);
//
//	*/
//
//    skb->dev = odev;
//
//    // 直接发送
//    //dev_queue_xmit( skb );
//
//    // 获取output rtable
//    if ( ip_route_out( skb, iph ) != 0 ) {
//        goto free_skb;
//    }
//
//	// 通过系统决定发送
//    ip_local_out(skb);
//    return;
//
//free_skb:
//    trace( "free skb./n" );
//    kfree_skb(skb);
//    return ;
//}
