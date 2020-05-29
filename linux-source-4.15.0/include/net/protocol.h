/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the protocol dispatcher.
 *
 * Version:	@(#)protocol.h	1.0.2	05/07/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Changes:
 *		Alan Cox	:	Added a name field and a frag handler
 *					field for later.
 *		Alan Cox	:	Cleaned up, and sorted types.
 *		Pedro Roque	:	inet6 protocols
 */
 
#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <linux/in6.h>
#include <linux/skbuff.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <linux/ipv6.h>
#endif
#include <linux/netdevice.h>

/* This is one larger than the largest protocol value that can be
 * found in an ipv4 or ipv6 header.  Since in both cases the protocol
 * value is presented in a __u8, this is defined to be 256.
 */
#define MAX_INET_PROTOS		256

/* This is used to register protocols. */
/*
*内核协议栈使用net_protocol结构体表示其所支持的传输层协议，
*系统初始化或者相应协议模块加载时，具体的协议将根据协议号
*将其实现的net_protocol结构体注册到协议栈中，即以协议号为
*索引添加到全局结构体指针数组inet_protos[]中。对于TCP的实例
*就是tcp_protocol
*/
struct net_protocol {
	int			(*early_demux)(struct sk_buff *skb); //协议处理函数，当对于tcp来说就是tcp协议处理tcp段的函数
	int			(*early_demux_handler)(struct sk_buff *skb);
	int			(*handler)(struct sk_buff *skb);
	void			(*err_handler)(struct sk_buff *skb, u32 info);
	unsigned int		no_policy:1,
				netns_ok:1,
				/* does the protocol do more stringent
				 * icmp tag validation than simple
				 * socket lookup?
				 */
				icmp_strict_tag_validation:1;
};

#if IS_ENABLED(CONFIG_IPV6)
struct inet6_protocol {
	void	(*early_demux)(struct sk_buff *skb);
	void    (*early_demux_handler)(struct sk_buff *skb);
	int	(*handler)(struct sk_buff *skb);

	void	(*err_handler)(struct sk_buff *skb,
			       struct inet6_skb_parm *opt,
			       u8 type, u8 code, int offset,
			       __be32 info);
	unsigned int	flags;	/* INET6_PROTO_xxx */
};

#define INET6_PROTO_NOPOLICY	0x1
#define INET6_PROTO_FINAL	0x2
#endif

struct net_offload {
	struct offload_callbacks callbacks;
	unsigned int		 flags;	/* Flags used by IPv6 for now */
};
/* This should be set for any extension header which is compatible with GSO. */
#define INET6_PROTO_GSO_EXTHDR	0x1

/* This is used to register socket interfaces for IP protocols.  */
//在IPv4协议族中，一个传输层协议对应一个inet_protosw结构，协议族中所有的inet_protosw结构实例
//都定义在静态数组inetsw_array[]中。网络子系统初始化时，根据每个结构的type，就是sock类型，
//注册到一个全局的list_head结构数组inetsw[]中，即socket类型相同的inet_protosw结构在inetsw[]
//中已其对应的元素为链表头则称一个双向链表
struct inet_protosw {
	struct list_head list;			//list是一个双链表结构

        /* These two fields form the lookup key.  */
	unsigned short	 type;	   /* This is the 2nd argument to socket(2). */
	unsigned short	 protocol; /* This is the L4 protocol number.  */

	struct proto	 *prot;
	const struct proto_ops *ops;
  
	unsigned char	 flags;      /* See INET_PROTOSW_* below.  */
};
#define INET_PROTOSW_REUSE 0x01	     /* Are ports automatically reusable? */
#define INET_PROTOSW_PERMANENT 0x02  /* Permanent protocols are unremovable. */
#define INET_PROTOSW_ICSK      0x04  /* Is this an inet_connection_sock? */

extern struct net_protocol __rcu *inet_protos[MAX_INET_PROTOS];
extern const struct net_offload __rcu *inet_offloads[MAX_INET_PROTOS];
extern const struct net_offload __rcu *inet6_offloads[MAX_INET_PROTOS];

#if IS_ENABLED(CONFIG_IPV6)
extern struct inet6_protocol __rcu *inet6_protos[MAX_INET_PROTOS];
#endif

int inet_add_protocol(const struct net_protocol *prot, unsigned char num);
int inet_del_protocol(const struct net_protocol *prot, unsigned char num);
int inet_add_offload(const struct net_offload *prot, unsigned char num);
int inet_del_offload(const struct net_offload *prot, unsigned char num);
void inet_register_protosw(struct inet_protosw *p);
void inet_unregister_protosw(struct inet_protosw *p);

#if IS_ENABLED(CONFIG_IPV6)
int inet6_add_protocol(const struct inet6_protocol *prot, unsigned char num);
int inet6_del_protocol(const struct inet6_protocol *prot, unsigned char num);
int inet6_register_protosw(struct inet_protosw *p);
void inet6_unregister_protosw(struct inet_protosw *p);
#endif
int inet6_add_offload(const struct net_offload *prot, unsigned char num);
int inet6_del_offload(const struct net_offload *prot, unsigned char num);

#endif	/* _PROTOCOL_H */
