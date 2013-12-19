#include <linux/mpip_map.h>

int add_working_ip_table(struct working_ip_table *item, struct list_head *head)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	INIT_LIST_HEAD(&item->list);
	list_add(&item->list, head);

	return 1;
}

int del_working_ip_table(unsigned char *node_id,	struct list_head *head)
{
	/* todo: need locks */
	struct working_ip_table *node_ip, *tmp;

	list_for_each_entry_safe(node_ip, tmp, head, list)
	{
		if (strcmp(node_id, node_ip->node_id)  == 0)
		{
			list_del(&node_ip->list);
			kfree(node_ip);
			break;
		}
	}

	return 1;
}

struct working_ip_table * find_working_ip_table(unsigned char *node_id,
													   struct list_head *head)
{
	struct working_ip_table *node_ip;

	list_for_each_entry(node_ip, head, list)
	{
		if (strcmp(node_id, node_ip->node_id)  == 0)
		{
			return node_ip;
		}
	}

	return NULL;
}



int add_path_info_table(struct path_info_table *item, struct list_head *head)
{
	/* todo: need sanity checks, leave it for now */
	/* todo: need locks */
	INIT_LIST_HEAD(&item->list);
	list_add(&item->list, head);

	return 1;
}

int del_path_info_table(__be32 saddr, __be32 daddr,
							   struct list_head *head)
{
	/* todo: need locks */
	struct path_info_table *path, *tmp;

	list_for_each_entry_safe(path, tmp, head, list)
	{
		if ((path->saddr == saddr) && (path->daddr == daddr))
		{
			list_del(&path->list);
			kfree(path);
			break;
		}
	}

	return 1;
}

struct path_info_table * find_path_info_table(__be32 saddr,
										      __be32 daddr,
											  struct list_head *head)
{
	struct path_info_table *path;

	list_for_each_entry(path, head, list)
	{
		if ((path->saddr == saddr) && (path->daddr == daddr))
		{
			return path;
		}
	}

	return NULL;
}

