# Iptables源码阅读
``` c
// 函数入口，根据输入的命令校验打开的iptables，非主要功能部分不做具体需求
int main(int argc, char **argv)
{
	return subcmd_main(argc, argv, multi_subcommands);
}

// 以iptables为例，详细讲解源码，入口为xtables_ip4_main
static const struct subcommand multi_subcommands[] = {
    ... ...
	{"iptables",			xtables_ip4_main}
    ... ...
};
```

``` c
// 进入xtables主体函数，生命当前的协议族为Ipv4
int xtables_ip4_main(int argc, char *argv[])
{
	return xtables_main(NFPROTO_IPV4, "iptables", argc, argv);
}
``` 


``` c
struct xtables_globals
{
	unsigned int option_offset;
	const char *program_name, *program_version;
	struct option *orig_opts;       // 原先的可传参数字段
	struct option *opts;　　　　　　　// 可扩展
	void (*exit_err)(enum xtables_exittype status, const char *msg, ...) __attribute__((noreturn, format(printf,2,3)));
	int (*compat_rev)(const char *name, uint8_t rev, int opt);
};
```

``` c
// 全局
static const char *xtables_libdir;
// 初始化动态库地址
void xtables_init(void)
{
	xtables_libdir = getenv("XTABLES_LIBDIR");
	if (xtables_libdir != NULL)
		return;
	xtables_libdir = getenv("IPTABLES_LIB_DIR");
	if (xtables_libdir != NULL) {
		fprintf(stderr, "IPTABLES_LIB_DIR is deprecated, "
		        "use XTABLES_LIBDIR.\n");
		return;
	}
	/*
	 * Well yes, IP6TABLES_LIB_DIR is of lower priority over
	 * IPTABLES_LIB_DIR since this moved to libxtables; I think that is ok
	 * for these env vars are deprecated anyhow, and in light of the
	 * (shared) libxt_*.so files, makes less sense to have
	 * IPTABLES_LIB_DIR != IP6TABLES_LIB_DIR.
	 */
	xtables_libdir = getenv("IP6TABLES_LIB_DIR");
	if (xtables_libdir != NULL) {
		fprintf(stderr, "IP6TABLES_LIB_DIR is deprecated, "
		        "use XTABLES_LIBDIR.\n");
		return;
	}
	xtables_libdir = XTABLES_LIBDIR;
}
```


``` c
//　全局
const struct xtables_afinfo *afinfo;

//　赋值 为ipv4
static const struct xtables_afinfo afinfo_ipv4 = {
	.kmod          = "ip_tables",
	.proc_exists   = "/proc/net/ip_tables_names",   //　运行路径
	.libprefix     = "libipt_",        
	.family	       = NFPROTO_IPV4,       //　协议族
	.ipproto       = IPPROTO_IP,
	.so_rev_match  = IPT_SO_GET_REVISION_MATCH,
	.so_rev_target = IPT_SO_GET_REVISION_TARGET,
};

```


``` c
//　全局
struct xtables_globals *xt_params = NULL;

// 将传入的global 保存为全局，　并赋值　basic_exit_err,输出错误到命令行并退出
int xtables_set_params(struct xtables_globals *xtp)
{
	if (!xtp) {
		fprintf(stderr, "%s: Illegal global params\n",__func__);
		return -1;
	}

	xt_params = xtp;

	if (!xt_params->exit_err)
		xt_params->exit_err = basic_exit_err;

	return 0;
}

```


``` c
// 初始化nft
	/*
	参数　h 　　nft_handle　　　IPV4 family
	*/

	// h目前紧包含协议族，xtables_ipv4为表数组
	if (nft_init(&h, xtables_ipv4) < 0) {}

int nft_init(struct nft_handle *h, struct builtin_table *t)
{
	
	h->nl = mnl_socket_open(NETLINK_NETFILTER);
	if (h->nl == NULL)
		return -1;

	// 指定auto pid 为内核帮助分配pid
	if (mnl_socket_bind(h->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		mnl_socket_close(h->nl);
		return -1;
	}

	// pid 已为内核分配，记录pid
	h->portid = mnl_socket_get_portid(h->nl);
	h->tables = t;


	INIT_LIST_HEAD(&h->obj_list);
	INIT_LIST_HEAD(&h->err_list);

	return 0;
}	

// socket协议族，netlink
static struct mnl_socket *__mnl_socket_open(int bus, int flags)
{
	struct mnl_socket *nl;

	nl = calloc(1, sizeof(struct mnl_socket));
	if (nl == NULL)
		return NULL;

	nl->fd = socket(AF_NETLINK, SOCK_RAW | flags, bus);
	if (nl->fd == -1) {
		free(nl);
		return NULL;
	}

	return nl;
}


int mnl_socket_bind(struct mnl_socket *nl, unsigned int groups, pid_t pid)
{
	int ret;
	socklen_t addr_len;

	nl->addr.nl_family = AF_NETLINK;
	nl->addr.nl_groups = groups;
	nl->addr.nl_pid = pid;

	ret = bind(nl->fd, (struct sockaddr *) &nl->addr, sizeof (nl->addr));
	if (ret < 0)
		return ret;

	addr_len = sizeof(nl->addr);
	ret = getsockname(nl->fd, (struct sockaddr *) &nl->addr, &addr_len);
	if (ret < 0)	
		return ret;

	if (addr_len != sizeof(nl->addr)) {
		errno = EINVAL;
		return -1;
	}
	if (nl->addr.nl_family != AF_NETLINK) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

unsigned int mnl_socket_get_portid(const struct mnl_socket *nl)
{
	return nl->addr.nl_pid;
}
```


``` c
	/* 解析命令行参数
	tables 默认表　filter
	*/
	ret = do_commandx(&h, argc, argv, &table, false);

// 解析表
struct nft_xt_cmd_parse {
	unsigned int			command;
	unsigned int			rulenum;
	char				*table;         // 表名
	const char			*chain;         // 链名
	const char			*newname;　　　　// 挂载表名  
	const char			*policy;
	bool				restore;　　　　　// 是否需要保存
	int				verbose;
	bool				xlate;
};


struct xtables_args {
	int		family;
	uint16_t	proto;
	uint8_t		flags;
	uint8_t		invflags;
	char		iniface[IFNAMSIZ], outiface[IFNAMSIZ];
	unsigned char	iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];
	bool		goto_set;
	const char	*shostnetworkmask, *dhostnetworkmask;
	const char	*pcnt, *bcnt;
	struct addr_mask s, d;
	unsigned long long pcnt_cnt, bcnt_cnt;
};


struct iptables_command_state {
	union {
		struct ebt_entry eb;
		struct ipt_entry fw;
		struct ip6t_entry fw6;
		struct arpt_entry arp;
	};
	int invert;
	int c;
	unsigned int options;
	struct xtables_rule_match *matches;       // 规则表
	struct ebt_match *match_list;
	struct xtables_target *target;
	struct xt_counters counters;
	char *protocol;
	int proto_used;
	const char *jumpto;
	char **argv;
	bool restore;
};

```


``` c
/* Keep track of fully registered external matches/targets: linked lists. */
struct xtables_match *xtables_matches;
struct xtables_target *xtables_targets;

// 解压
void do_parse(struct nft_handle *h, int argc, char *argv[],
	      struct nft_xt_cmd_parse *p, struct iptables_command_state *cs,
	      struct xtables_args *args)
{
	... ...
	// 清空所有记录
	for (m = xtables_matches; m; m = m->next)
		m->mflags = 0;

	for (t = xtables_targets; t; t = t->next) {
		t->tflags = 0;
		t->used = 0;
	}
	... ...

	// 根据ipv4保存opts方法
	h->ops = nft_family_ops_lookup(h->family);	



}


struct nft_family_ops nft_family_ops_ipv4 = {
	.add			= nft_ipv4_add,
	.is_same		= nft_ipv4_is_same,
	.parse_meta		= nft_ipv4_parse_meta,
	.parse_payload		= nft_ipv4_parse_payload,
	.parse_immediate	= nft_ipv4_parse_immediate,
	.print_header		= print_header,
	.print_rule		= nft_ipv4_print_rule,
	.save_rule		= nft_ipv4_save_rule,
	.save_counters		= save_counters,
	.save_chain		= nft_ipv46_save_chain,
	.proto_parse		= nft_ipv4_proto_parse,
	.post_parse		= nft_ipv4_post_parse,
	.parse_target		= nft_ipv46_parse_target,
	.rule_to_cs		= nft_rule_to_iptables_command_state,
	.clear_cs		= nft_clear_iptables_command_state,
	.rule_find		= nft_ipv46_rule_find,
	.xlate			= nft_ipv4_xlate,
};
```