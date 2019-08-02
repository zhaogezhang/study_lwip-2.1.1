/**
 * @file
 * This is the IPv4 layer implementation for incoming and outgoing IP traffic.
 *
 * @see ip_frag.c
 *
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
/* IP 数据包协议格式，详细内容见链接：https://tools.ietf.org/html/rfc791
 *
 *    0 				  1 				  2 				  3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |Version|	IHL  |Type of Service|			Total Length		 |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |		   Identification		 |Flags|	  Fragment Offset	 |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |	Time to Live |	  Protocol	 |		   Header Checksum		 |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |						 Source Address 						 |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |					  Destination Address						 |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |					  Options					 |	  Padding	 |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |					         Payload                             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   版本（Version）：IP 报文版本号，IPV4 = 4，IPV6 = 6
 *   首部长度（IHL）：IP 协议头长度，单位是 4 字节，在没有 IP 头选项的情况下，一般为 5（5 x 32bit = 20B）
 *   服务类型（Type of Service）：默认不使用，应用于 QOS 服务
 *   当前数据包总长度（Total Length）：IP 协议头长度 + 负载数据长度 
 *   数据包 ID 标志（Identification）：IP 报文的唯一 ID，属于同一个数据包的分片报文 ID 相同，用于 IP 数据包重组
 *   数据包分片结束标志（Flags）：标明是否分片以及是否是最后一个分片数据包
 *   分片数据包偏移量（Fragment Offset）：表示当前分片数据包负载数据在完整数据包负载数据中的偏移量
 *   TTL（Time to Live）：生存时间，即路由器的跳数，每经过一个路由器，该 TTL 减一，因此路由器需要重新计算IP报文的校验和
 *   负载数据协议类型（Protocol）：常用的有 ICMP = 1，IGMP = 2，TCP = 6，UDP = 17
 *   头部校验和（Header Checksum）：IP 协议头校验和，接收端在收到报文时进行计算，如果校验和错误，直接丢弃
 *   源 IP 地址（Source Address）：发送这个数据包机器的 IP 地址
 *   目的 IP 地址（Destination Address）：接收这个数据包机器的 IP 地址
 *   可选字段（Options）：默认不使用
 *   负载数据（Payload）：上层协议的数据报文，如 TCP 报文、UDP 报文等
 *
 */

#include "lwip/opt.h"

#if LWIP_IPV4

#include "lwip/ip.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/ip4_frag.h"
#include "lwip/inet_chksum.h"
#include "lwip/netif.h"
#include "lwip/icmp.h"
#include "lwip/igmp.h"
#include "lwip/priv/raw_priv.h"
#include "lwip/udp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/autoip.h"
#include "lwip/stats.h"
#include "lwip/prot/iana.h"

#include <string.h>

#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif

/** Set this to 0 in the rare case of wanting to call an extra function to
 * generate the IP checksum (in contrast to calculating it on-the-fly). */
/* 表示当前协议栈是否使用默认的计算 IP 层协议头校验和函数，如果不使用，则需要
 * 网络接口通过添加自定义钩子函数来计算相应的校验和并添加到协议头对应位置处 */
#ifndef LWIP_INLINE_IP_CHKSUM
#if LWIP_CHECKSUM_CTRL_PER_NETIF
#define LWIP_INLINE_IP_CHKSUM   0
#else /* LWIP_CHECKSUM_CTRL_PER_NETIF */
#define LWIP_INLINE_IP_CHKSUM   1
#endif /* LWIP_CHECKSUM_CTRL_PER_NETIF */
#endif

#if LWIP_INLINE_IP_CHKSUM && CHECKSUM_GEN_IP
#define CHECKSUM_GEN_IP_INLINE  1
#else
#define CHECKSUM_GEN_IP_INLINE  0
#endif

#if LWIP_DHCP || defined(LWIP_IP_ACCEPT_UDP_PORT)

/* 表示当前协议栈在 IP 层支持基于链路地址（例如 MAC 地址）寻址的功能，即跳过                     IPv4 地址校验，直接校验传输层端口信息 */
#define IP_ACCEPT_LINK_LAYER_ADDRESSING 1

/** Some defines for DHCP to let link-layer-addressed packets through while the
 * netif is down.
 * To use this in your own application/protocol, define LWIP_IP_ACCEPT_UDP_PORT(port)
 * to return 1 if the port is accepted and 0 if the port is not accepted.
 */
/* 因为类似于 DHCP 这样的服务是通过链路层地址进行寻址的（例如以太网 MAC 地址），所以我们
 * 在 IP 层不能对这样的网络数据包协议头中的 IP 地址进行校验过滤，而是通过应用层端口号来判
 * 断是否可以处理接收到的网络数据包。基于这个原理，我们也可以通过实现 LWIP_IP_ACCEPT_UDP_PORT
 * 钩子函数来添加自定义的、基于链路层地址寻址的端口号 */
#if LWIP_DHCP && defined(LWIP_IP_ACCEPT_UDP_PORT)
/* accept DHCP client port and custom port */
#define IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(port) (((port) == PP_NTOHS(LWIP_IANA_PORT_DHCP_CLIENT)) \
         || (LWIP_IP_ACCEPT_UDP_PORT(port)))
#elif defined(LWIP_IP_ACCEPT_UDP_PORT) /* LWIP_DHCP && defined(LWIP_IP_ACCEPT_UDP_PORT) */
/* accept custom port only */
#define IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(port) (LWIP_IP_ACCEPT_UDP_PORT(port))
#else /* LWIP_DHCP && defined(LWIP_IP_ACCEPT_UDP_PORT) */
/* accept DHCP client port only */
#define IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(port) ((port) == PP_NTOHS(LWIP_IANA_PORT_DHCP_CLIENT))
#endif /* LWIP_DHCP && defined(LWIP_IP_ACCEPT_UDP_PORT) */

#else /* LWIP_DHCP */
#define IP_ACCEPT_LINK_LAYER_ADDRESSING 0
#endif /* LWIP_DHCP */

/** The IP header ID of the next outgoing IP packet */
/* 一个全局静态变量，用来表示下一个待发送的数据包在 IP 协议的协议头中的使用的数据包 ID 标志值
 * 这个变量在 IP 数据包分片时用来表示每一个分片数据包所属的数据包号 */
static u16_t ip_id;

#if LWIP_MULTICAST_TX_OPTIONS
/** The default netif used for multicast */
/* 在 IPv4 协议模块中，默认使用的多播网络接口指针 */
static struct netif *ip4_default_multicast_netif;

/**
 * @ingroup ip4
 * Set a default netif for IPv4 multicast. */
/*********************************************************************************************************
** 函数名称: ip4_set_default_multicast_netif
** 功能描述: 设置 IPv4 模块默认使用的多播网络接口指针值
** 输	 入: default_multicast_netif - IPv4 模块要设置的默认多播网络接口指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
ip4_set_default_multicast_netif(struct netif *default_multicast_netif)
{
  ip4_default_multicast_netif = default_multicast_netif;
}
#endif /* LWIP_MULTICAST_TX_OPTIONS */

/* 这个指针指向一个钩子函数，这个钩子函数实现了根据指定的源 IP 地址计算我们需要使用当前系统内
 * 哪个有效网络接口来发送指定的数据包，通过实现这种路由策略，我们可以把指定的 IP 设备发出的所
 * 有数据包发送到指定的路由设备处 */
#ifdef LWIP_HOOK_IP4_ROUTE_SRC
/**
 * Source based IPv4 routing must be fully implemented in
 * LWIP_HOOK_IP4_ROUTE_SRC(). This function only provides the parameters.
 */
/*********************************************************************************************************
** 函数名称: ip4_route_src
** 功能描述: 尝试使用我们自己实现的基于“源” IP 地址的路由策略找到一个发送指定数据包的网络接口，如果
**         : 基于“源” IP 地址的路由策略没找到有效的网络接口，则使用默认基于“目的” IP 地址的路由策略
** 输	 入: src - 需要发送的数据包的“源” IPv4 地址
**         : dest - 需要发送的数据包的“目的” IPv4 地址
** 输	 出: netif * - 用来发送指定数据包的网络接口指针
**         : NULL - 没找到合适的网络接口
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct netif *
ip4_route_src(const ip4_addr_t *src, const ip4_addr_t *dest)
{
  if (src != NULL) {
    /* when src==NULL, the hook is called from ip4_route(dest) */
    /* 根据我们自己实现的钩子函数得出用来发送指定“源” IP 地址的数据包的网络接口 */
    struct netif *netif = LWIP_HOOK_IP4_ROUTE_SRC(src, dest);
    if (netif != NULL) {
      return netif;
    }
  }

  /* 如果我们自己实现的基于“源”地址的路由策略没有得到有效的网络接口，则使用默认路由 */
  return ip4_route(dest);
}
#endif /* LWIP_HOOK_IP4_ROUTE_SRC */

/**
 * Finds the appropriate network interface for a given IP address. It
 * searches the list of network interfaces linearly. A match is found
 * if the masked IP address of the network interface equals the masked
 * IP address given to the function.
 *
 * @param dest the destination IP address for which to find the route
 * @return the netif on which to send to reach dest
 */
/*********************************************************************************************************
** 函数名称: ip4_route
** 功能描述: lwip 协议栈 IPv4 模块默认使用的路由策略实现函数，基本功能逻辑如下:
**         : 1. 如果是往多播地址发送的数据包，则直接放回默认多播网络接口指针
**         : 2. 如果指定的目的 IPv4 地址和当前网络接口的网络地址匹配、即在一个子网中，则返回这个
**         :    网络接口指针
**         : 3. 如果网络接口不支持广播功能且当前数据包的目的 IPv4 地址是这个网络接口的网关地址则
**         :    返回这个网络接口指针
**         : 4. 如果目标地址为回环网络域内的 IPv4 地址的情况，即回环发送数据包，则从当前系统内随便
**         :    找一个处于 UP 状态的网络接口
**         : 5. 根据基于“源” IP 地址的路由策略和基于“目的” IP 地址的路由策略得出一个有效的网络接口
**         : 6. 如果可使用的所有路由策略都没有找到用于发送指定数据包的网络接口，且默认网络接口处于
**         :    正常工作状态则返回系统默认网络接口
** 输	 入: dest - 需要发送的数据包的“目的” IPv4 地址
** 输	 出: netif * - 用来发送指定数据包的网络接口指针
**         : NULL - 没找到合适的网络接口
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct netif *
ip4_route(const ip4_addr_t *dest)
{
#if !LWIP_SINGLE_NETIF
  struct netif *netif;

  LWIP_ASSERT_CORE_LOCKED();

#if LWIP_MULTICAST_TX_OPTIONS
  /* Use administratively selected interface for multicast by default */
  /* 如果是往多播地址发送的数据包，则直接返回默认多播网络接口指针 */
  if (ip4_addr_ismulticast(dest) && ip4_default_multicast_netif) {
    return ip4_default_multicast_netif;
  }
#endif /* LWIP_MULTICAST_TX_OPTIONS */

  /* bug #54569: in case LWIP_SINGLE_NETIF=1 and LWIP_DEBUGF() disabled, the following loop is optimized away */
  LWIP_UNUSED_ARG(dest);

  /* iterate through netifs */
  NETIF_FOREACH(netif) {
    /* is the netif up, does it have a link and a valid address? */
    if (netif_is_up(netif) && netif_is_link_up(netif) && !ip4_addr_isany_val(*netif_ip4_addr(netif))) {
      /* network mask matches? */
	  /* 如果指定的目的 IPv4 地址和当前网络接口的网络地址匹配、即在一个子网中，则返回这个网络接口指针 */
      if (ip4_addr_netcmp(dest, netif_ip4_addr(netif), netif_ip4_netmask(netif))) {
        /* return netif on which to forward IP packet */
        return netif;
      }
	  
      /* gateway matches on a non broadcast interface? (i.e. peer in a point to point interface) */
	  /* 如果网络接口不支持广播功能且当前数据包的目的 IPv4 地址是这个网络接口的网关地址，则返回这个网络接口指针 */
      if (((netif->flags & NETIF_FLAG_BROADCAST) == 0) && ip4_addr_cmp(dest, netif_ip4_gw(netif))) {
        /* return netif on which to forward IP packet */
        return netif;
      }
    }
  }

/* 如果目标地址为回环网络域内的 IPv4 地址的情况，即回环发送数据包，则从当前系统内随便找一个处于
 * UP 状态的网络接口 */
#if LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF
  /* loopif is disabled, looopback traffic is passed through any netif */
  if (ip4_addr_isloopback(dest)) {
    /* don't check for link on loopback traffic */
    if (netif_default != NULL && netif_is_up(netif_default)) {
      return netif_default;
    }
    /* default netif is not up, just use any netif for loopback traffic */
    NETIF_FOREACH(netif) {
      if (netif_is_up(netif)) {
        return netif;
      }
    }
    return NULL;
  }
#endif /* LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF */

/* 处理基于“源” IP 地址的路由策略和基于“目的” IP 地址的路由策略情况 */
#ifdef LWIP_HOOK_IP4_ROUTE_SRC
  /* 这个指针指向一个钩子函数，这个钩子函数实现了根据指定的“源” IP 地址计算我们需要使用当前系统内
   * 哪个有效网络接口来发送指定的数据包，通过实现这种路由策略，我们可以把指定的 IP 设备发出的所
   * 有数据包发送到指定的路由设备处 */
  netif = LWIP_HOOK_IP4_ROUTE_SRC(NULL, dest);
  if (netif != NULL) {
    return netif;
  }
#elif defined(LWIP_HOOK_IP4_ROUTE)
  /* 这个指针指向一个钩子函数，这个钩子函数实现了根据指定的“目的” IP 地址计算我们需要使用当前系统内
   * 哪个有效网络接口来发送指定的数据包 */
  netif = LWIP_HOOK_IP4_ROUTE(dest);
  if (netif != NULL) {
    return netif;
  }
#endif
#endif /* !LWIP_SINGLE_NETIF */

  if ((netif_default == NULL) || !netif_is_up(netif_default) || !netif_is_link_up(netif_default) ||
      ip4_addr_isany_val(*netif_ip4_addr(netif_default)) || ip4_addr_isloopback(dest)) {
    /* No matching netif found and default netif is not usable.
       If this is not good enough for you, use LWIP_HOOK_IP4_ROUTE() */
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_route: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
    IP_STATS_INC(ip.rterr);
    MIB2_STATS_INC(mib2.ipoutnoroutes);
    return NULL;
  }

  /* 如果可使用的所有路由策略都没有找到用于发送指定数据包的网络接口，且默认网络接口处于
   * 正常工作状态则返回系统默认网络接口 */
  return netif_default;
}

#if IP_FORWARD
/**
 * Determine whether an IP address is in a reserved set of addresses
 * that may not be forwarded, or whether datagrams to that destination
 * may be forwarded.
 * @param p the packet to forward
 * @return 1: can forward 0: discard
 */
/*********************************************************************************************************
** 函数名称: ip4_canforward
** 功能描述: 根据当前接收到的数据包类型信息以及目的 IPv4 地址判断当前网络系统是否可以转发这个数据包
** 输	 入: p - 接收到的网络数据包指针
** 输	 出: 1 - 可以被路由
**         : 0 - 不可以被路由
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int
ip4_canforward(struct pbuf *p)
{
  /* 获取当前将要发送的网络数据包的目的 IPv4 地址（网络字节序）*/
  u32_t addr = lwip_htonl(ip4_addr_get_u32(ip4_current_dest_addr()));

/* 如果我们自己实现了自定义的钩子函数判断指定 IPv4 地址是否可以路由函数
 * 则优先使用我们自定义的函数 */
#ifdef LWIP_HOOK_IP4_CANFORWARD
  int ret = LWIP_HOOK_IP4_CANFORWARD(p, addr);
  if (ret >= 0) {
    return ret;
  }
#endif /* LWIP_HOOK_IP4_CANFORWARD */

  /* 默认情况下“广播”包只能在局域网内收发，所以不能对广播包执行路由操作 */
  if (p->flags & PBUF_FLAG_LLBCAST) {
    /* don't route link-layer broadcasts */
    return 0;
  }
  
  /* 默认情况下“多播”包只能在局域网内收发，所以不能对多播包执行路由操作 */
  if ((p->flags & PBUF_FLAG_LLMCAST) || IP_MULTICAST(addr)) {
    /* don't route link-layer multicasts (use LWIP_HOOK_IP4_CANFORWARD instead) */
    return 0;
  }

  /* EXPERIMENTAL 类型的目的地址不可以路由 */
  if (IP_EXPERIMENTAL(addr)) {
    return 0;
  }

  /* 回环网络不可以路由 */
  if (IP_CLASSA(addr)) {
    u32_t net = addr & IP_CLASSA_NET;
    if ((net == 0) || (net == ((u32_t)IP_LOOPBACKNET << IP_CLASSA_NSHIFT))) {
      /* don't route loopback packets */
      return 0;
    }
  }
  
  return 1;
}

/**
 * Forwards an IP packet. It finds an appropriate route for the
 * packet, decrements the TTL value of the packet, adjusts the
 * checksum and outputs the packet on the appropriate interface.
 *
 * @param p the packet to forward (p->payload points to IP header)
 * @param iphdr the IP header of the input packet
 * @param inp the netif on which this packet was received
 */
/*********************************************************************************************************
** 函数名称: ip4_forward
** 功能描述: 为当前接收到的网络数据包找到一个合适的路由网络接口，然后通过这个路由网络接口把这个数据包
**         : 转发出去，在转发数据包之前，会更新数据包中的相关数据（TTL、checksum）
** 注     释: 1. 如果接收到的网络数据包的 TTL 值减 1 后为 0，则调用 icmp_time_exceeded 发送个 icmp 消息
**         : 2. 如果接收的网路数据包长度超过指定的路由网络接口 MTU，并且这个数据包不能执行分片，则调用
**         :    icmp_dest_unreach 发送个 ICMP_DUR_FRAG 类型 icmp 消息
** 输	 入: p - 接收到的网络数据包指针
**         : iphdr - 接收到网络数据的 IP 协议头
**         : inp - 接收到网络数据的网络接口
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
ip4_forward(struct pbuf *p, struct ip_hdr *iphdr, struct netif *inp)
{
  struct netif *netif;

  PERF_START;
  LWIP_UNUSED_ARG(inp);

  /* 根据当前接收到的数据包类型信息以及目的 IPv4 地址判断这个数据包是否可以路由 */
  if (!ip4_canforward(p)) {
    goto return_noroute;
  }

  /* RFC3927 2.7: do not forward link-local addresses */
  if (ip4_addr_islinklocal(ip4_current_dest_addr())) {
    LWIP_DEBUGF(IP_DEBUG, ("ip4_forward: not forwarding LLA %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                           ip4_addr1_16(ip4_current_dest_addr()), ip4_addr2_16(ip4_current_dest_addr()),
                           ip4_addr3_16(ip4_current_dest_addr()), ip4_addr4_16(ip4_current_dest_addr())));
    goto return_noroute;
  }

  /* Find network interface where to forward this IP packet to. */
  /* 尝试使用我们自己实现的基于“源” IP 地址的路由策略找到一个发送指定数据包的网络接口，如果
     基于“源” IP 地址的路由策略没找到有效的网络接口，则使用默认基于“目的” IP 地址的路由策略 */
  netif = ip4_route_src(ip4_current_src_addr(), ip4_current_dest_addr());
  if (netif == NULL) {
    LWIP_DEBUGF(IP_DEBUG, ("ip4_forward: no forwarding route for %"U16_F".%"U16_F".%"U16_F".%"U16_F" found\n",
                           ip4_addr1_16(ip4_current_dest_addr()), ip4_addr2_16(ip4_current_dest_addr()),
                           ip4_addr3_16(ip4_current_dest_addr()), ip4_addr4_16(ip4_current_dest_addr())));
    /* @todo: send ICMP_DUR_NET? */
    goto return_noroute;
  }

/* 如果 IP_FORWARD_ALLOW_TX_ON_RX_NETIF==1 表示我们在网络数据包路由的时候允许从
 * 接收到网络数据包的网络接口上把接收到的网络数据包再发送出去，这个只有在无线网络
 * 中需要启用，默认情况下不启动 */
#if !IP_FORWARD_ALLOW_TX_ON_RX_NETIF
  /* Do not forward packets onto the same network interface on which
   * they arrived. */
  if (netif == inp) {
    LWIP_DEBUGF(IP_DEBUG, ("ip4_forward: not bouncing packets back on incoming interface.\n"));
    goto return_noroute;
  }
#endif /* IP_FORWARD_ALLOW_TX_ON_RX_NETIF */

  /* decrement TTL */
  IPH_TTL_SET(iphdr, IPH_TTL(iphdr) - 1);

  /* send ICMP if TTL == 0 */
  if (IPH_TTL(iphdr) == 0) {
    MIB2_STATS_INC(mib2.ipinhdrerrors);
#if LWIP_ICMP
    /* Don't send ICMP messages in response to ICMP messages */
    if (IPH_PROTO(iphdr) != IP_PROTO_ICMP) {
      icmp_time_exceeded(p, ICMP_TE_TTL);
    }
#endif /* LWIP_ICMP */
    return;
  }

  /* Incrementally update the IP checksum. */
  if (IPH_CHKSUM(iphdr) >= PP_HTONS(0xffffU - 0x100)) {
    IPH_CHKSUM_SET(iphdr, (u16_t)(IPH_CHKSUM(iphdr) + PP_HTONS(0x100) + 1));
  } else {
    IPH_CHKSUM_SET(iphdr, (u16_t)(IPH_CHKSUM(iphdr) + PP_HTONS(0x100)));
  }

  LWIP_DEBUGF(IP_DEBUG, ("ip4_forward: forwarding packet to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                         ip4_addr1_16(ip4_current_dest_addr()), ip4_addr2_16(ip4_current_dest_addr()),
                         ip4_addr3_16(ip4_current_dest_addr()), ip4_addr4_16(ip4_current_dest_addr())));

  IP_STATS_INC(ip.fw);
  MIB2_STATS_INC(mib2.ipforwdatagrams);
  IP_STATS_INC(ip.xmit);

  PERF_STOP("ip4_forward");
  
  /* don't fragment if interface has mtu set to 0 [loopif] */
  /* 如果接收到的数据包长度超过了指定网络接口的 MTU，则需要对当前接收到的网络数据包先分片
   * 然后再通过指定的网络接口发送出去 */
  if (netif->mtu && (p->tot_len > netif->mtu)) {
    if ((IPH_OFFSET(iphdr) & PP_NTOHS(IP_DF)) == 0) {
#if IP_FRAG
      ip4_frag(p, netif, ip4_current_dest_addr());
#else /* IP_FRAG */
      /* @todo: send ICMP Destination Unreachable code 13 "Communication administratively prohibited"? */
#endif /* IP_FRAG */
    } else {
#if LWIP_ICMP
      /* send ICMP Destination Unreachable code 4: "Fragmentation Needed and DF Set" */
      icmp_dest_unreach(p, ICMP_DUR_FRAG);
#endif /* LWIP_ICMP */
    }
    return;
  }
  
  /* transmit pbuf on chosen interface */
  /* 把接收到的数据包通过指定的路由网络接口发送出去 */
  netif->output(netif, p, ip4_current_dest_addr());
  return;
return_noroute:
  MIB2_STATS_INC(mib2.ipoutnoroutes);
}
#endif /* IP_FORWARD */

/** Return true if the current input packet should be accepted on this netif */
/*********************************************************************************************************
** 函数名称: ip4_input_accept
** 功能描述: 判断指定的网络接口是否可以处理当前接收到的网络数据包
** 输	 入: netif - 需要判断的网络接口指针
** 输	 出: 1 - 指定的网络接口可以接收
**         : 0 - 指定的网络接口不可以接收
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int
ip4_input_accept(struct netif *netif)
{
  LWIP_DEBUGF(IP_DEBUG, ("ip_input: iphdr->dest 0x%"X32_F" netif->ip_addr 0x%"X32_F" (0x%"X32_F", 0x%"X32_F", 0x%"X32_F")\n",
                         ip4_addr_get_u32(ip4_current_dest_addr()), ip4_addr_get_u32(netif_ip4_addr(netif)),
                         ip4_addr_get_u32(ip4_current_dest_addr()) & ip4_addr_get_u32(netif_ip4_netmask(netif)),
                         ip4_addr_get_u32(netif_ip4_addr(netif)) & ip4_addr_get_u32(netif_ip4_netmask(netif)),
                         ip4_addr_get_u32(ip4_current_dest_addr()) & ~ip4_addr_get_u32(netif_ip4_netmask(netif))));

  /* interface is up and configured? */
  /* 指定的网络接口已经处于 UP 状态并且已经配置完成 */
  if ((netif_is_up(netif)) && (!ip4_addr_isany_val(*netif_ip4_addr(netif)))) {
    /* unicast to this interface address? */
    /* 如果当前接收到的数据包是：
     * 1. 通过单播方式发送到指定的接口处                       或
     * 2. 当前接收到的数据包是个广播数据包                      或
     * 3. 当前接收到的数据包是发往回环地址的数据包
     * 则表示可以处理 */
    if (ip4_addr_cmp(ip4_current_dest_addr(), netif_ip4_addr(netif)) ||
        /* or broadcast on this interface network address? */
        ip4_addr_isbroadcast(ip4_current_dest_addr(), netif)
#if LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF
        || (ip4_addr_get_u32(ip4_current_dest_addr()) == PP_HTONL(IPADDR_LOOPBACK))
#endif /* LWIP_NETIF_LOOPBACK && !LWIP_HAVE_LOOPIF */
       ) {
      LWIP_DEBUGF(IP_DEBUG, ("ip4_input: packet accepted on interface %c%c\n",
                             netif->name[0], netif->name[1]));
      /* accept on this netif */
      return 1;
    }
#if LWIP_AUTOIP
    /* connections to link-local addresses must persist after changing
        the netif's address (RFC3927 ch. 1.9) */
    if (autoip_accept_packet(netif, ip4_current_dest_addr())) {
      LWIP_DEBUGF(IP_DEBUG, ("ip4_input: LLA packet accepted on interface %c%c\n",
                             netif->name[0], netif->name[1]));
      /* accept on this netif */
      return 1;
    }
#endif /* LWIP_AUTOIP */
  }
  return 0;
}

/**
 * This function is called by the network interface device driver when
 * an IP packet is received. The function does the basic checks of the
 * IP header such as packet size being at least larger than the header
 * size etc. If the packet was not destined for us, the packet is
 * forwarded (using ip_forward). The IP checksum is always checked.
 *
 * Finally, the packet is sent to the upper layer protocol input function.
 *
 * @param p the received IP packet (p->payload points to IP header)
 * @param inp the netif on which this packet was received
 * @return ERR_OK if the packet was processed (could return ERR_* if it wasn't
 *         processed, but currently always returns ERR_OK)
 */
/*********************************************************************************************************
** 函数名称: ip4_input
** 功能描述: 当底层网卡驱动程序接收到一个 IPv4 数据包的时候会通过调用这个接口把接收到的 IPv4 数据包
**         : 上传到协议栈的 IPv4 模块进行处理，这个接口做的工作如下：
**         : 1. 校验 IPv4 协议头中的版本号是否正确
**         : 2. 通过自定义的钩子函数指针，对接收到的 IPV4 数据包进行一些自定义的处理
**         : 3. 校验接收到的 IPv4 网络数据包协议头中的长度信息合法性
**         : 4. 校验接收到的 IPv4 数据包的协议头的“校验和”字段信息合法性
**         : 5. 处理接收到的数据包的“目的” IPv4 地址信息
**         :    a. 如果接收到的 IPv4 数据包是“多播/组播”数据包，则判断接收到这个数据包的网络接口是否
**         :       在这个数据包要发送的目的组中
**         :    b. 如果接收到的 IPv4 数据包是“单播/广播”数据包，则判断当前系统内是否存在接收这个数据
**         :       包的网络接口
**         : 6. 处理基于链路地址寻址的服务数据包，即跳过                     IPv4 地址校验，直接校验传输层端口信息
**         : 7. 校验接收到的数据包的“源” IPv4 地址是否是广播地址或者是多播地址，如果是，则表示接收
**         :    到的是一个非法数据包，则直接释放其占用的资源并返回
**         : 8. 如果接收到的数据包不是发送给当前机器的，并且这个数据包不是广播数据包则尝试从当前设备的
**         :    路由信息中为这个数据包找一个合适的路由设备，然后把这个数据包转发到找到的路由设备处
**         : 9. 如果接收到的网络数据包是个分片数据包，则对其进行重组，拼接成一个完成的数据包
**         : 10.处理 igmp 协议中，在协议头“选项”扩展字段中添加的 router alert 数据的场景对于这样的数据包
**         :    目前只对其统计，不做任何其他处理
**         : 11.根据接收到的数据包“负载数据协议类型”把“负载数据”分发到相应上层协议模块中进行下一步处理
** 输	 入: p - 网卡驱动程序接收到的 IPv4 数据包
**         : inp - 接收到 IPv4 数据包的网络接口指针
** 输	 出: 1 - 
**         : 0 - 指定的网络接口不可以接收
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
ip4_input(struct pbuf *p, struct netif *inp)
{
  const struct ip_hdr *iphdr;
  struct netif *netif;

  /* 表示接收到的 IPv4 协议的协议头长度 */
  u16_t iphdr_hlen;
  
  /* 表示接收到的 IPv4 协议数据包的长度（包括协议头和负载数据）*/
  u16_t iphdr_len;
  
#if IP_ACCEPT_LINK_LAYER_ADDRESSING || LWIP_IGMP
  /* 表示我们是否需要校验接收到的 IPv4 数据包中的“源” IPv4 地址信息 */
  int check_ip_src = 1;
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING || LWIP_IGMP */

#if LWIP_RAW
  raw_input_state_t raw_status;
#endif /* LWIP_RAW */

  LWIP_ASSERT_CORE_LOCKED();

  IP_STATS_INC(ip.recv);
  MIB2_STATS_INC(mib2.ipinreceives);

  /* identify the IP header */
  iphdr = (struct ip_hdr *)p->payload;

  /* 校验 IPv4 协议头中的版本号是否正确 */
  if (IPH_V(iphdr) != 4) {
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_WARNING, ("IP packet dropped due to bad version number %"U16_F"\n", (u16_t)IPH_V(iphdr)));
    ip4_debug_print(p);
    pbuf_free(p);
    IP_STATS_INC(ip.err);
    IP_STATS_INC(ip.drop);
    MIB2_STATS_INC(mib2.ipinhdrerrors);
    return ERR_OK;
  }

/* 我们可以通过实现这个函数指针的钩子函数，在接收到一个 IPv4 数据包的时候，对 IPV4 
 * 数据包进行一些自定义的处理 */
#ifdef LWIP_HOOK_IP4_INPUT
  if (LWIP_HOOK_IP4_INPUT(p, inp)) {
    /* the packet has been eaten */
    return ERR_OK;
  }
#endif

  /* obtain IP header length in bytes */
  iphdr_hlen = IPH_HL_BYTES(iphdr);
  /* obtain ip length in bytes */
  iphdr_len = lwip_ntohs(IPH_LEN(iphdr));

  /* Trim pbuf. This is especially required for packets < 60 bytes. */
  if (iphdr_len < p->tot_len) {
    pbuf_realloc(p, iphdr_len);
  }

  /* header length exceeds first pbuf length, or ip length exceeds total pbuf length? */
  /* 校验接收到的 IPv4 网络数据包协议头中的长度信息合法性 */
  if ((iphdr_hlen > p->len) || (iphdr_len > p->tot_len) || (iphdr_hlen < IP_HLEN)) {
    if (iphdr_hlen < IP_HLEN) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                  ("ip4_input: short IP header (%"U16_F" bytes) received, IP packet dropped\n", iphdr_hlen));
    }
    if (iphdr_hlen > p->len) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                  ("IP header (len %"U16_F") does not fit in first pbuf (len %"U16_F"), IP packet dropped.\n",
                   iphdr_hlen, p->len));
    }
    if (iphdr_len > p->tot_len) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                  ("IP (len %"U16_F") is longer than pbuf (len %"U16_F"), IP packet dropped.\n",
                   iphdr_len, p->tot_len));
    }
    /* free (drop) packet pbufs */
    pbuf_free(p);
    IP_STATS_INC(ip.lenerr);
    IP_STATS_INC(ip.drop);
    MIB2_STATS_INC(mib2.ipindiscards);
    return ERR_OK;
  }

  /* verify checksum */
  /* 校验接收到的 IPv4 数据包的协议头的“校验和”字段信息合法性 */
#if CHECKSUM_CHECK_IP
  IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_IP) {
    if (inet_chksum(iphdr, iphdr_hlen) != 0) {

      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                  ("Checksum (0x%"X16_F") failed, IP packet dropped.\n", inet_chksum(iphdr, iphdr_hlen)));
      ip4_debug_print(p);
      pbuf_free(p);
      IP_STATS_INC(ip.chkerr);
      IP_STATS_INC(ip.drop);
      MIB2_STATS_INC(mib2.ipinhdrerrors);
      return ERR_OK;
    }
  }
#endif

  /* copy IP addresses to aligned ip_addr_t */
  ip_addr_copy_from_ip4(ip_data.current_iphdr_dest, iphdr->dest);
  ip_addr_copy_from_ip4(ip_data.current_iphdr_src, iphdr->src);

  /* match packet against an interface, i.e. is this packet for us? */
  /* 处理接收到的数据包的“目的” IPv4 地址信息 */
  if (ip4_addr_ismulticast(ip4_current_dest_addr())) {
  
  	/* 如果接收到的 IPv4 数据包是“多播/组播”数据包，则判断接收到这个数据包的网络
   	 * 接口是否在这个数据包要发送的目的组中 */
   
#if LWIP_IGMP
    if ((inp->flags & NETIF_FLAG_IGMP) && (igmp_lookfor_group(inp, ip4_current_dest_addr()))) {
      /* IGMP snooping switches need 0.0.0.0 to be allowed as source address (RFC 4541) */
      ip4_addr_t allsystems;

	  /* 224.0.0.1 表示所有组播主机 */
      IP4_ADDR(&allsystems, 224, 0, 0, 1);
	
      if (ip4_addr_cmp(ip4_current_dest_addr(), &allsystems) &&
          ip4_addr_isany(ip4_current_src_addr())) {
        check_ip_src = 0;
      }
      netif = inp;
    } else {
      netif = NULL;
    }
#else /* LWIP_IGMP */
    if ((netif_is_up(inp)) && (!ip4_addr_isany_val(*netif_ip4_addr(inp)))) {
      netif = inp;
    } else {
      netif = NULL;
    }
#endif /* LWIP_IGMP */

  } else {
    
    /* 如果接收到的 IPv4 数据包是“单播/广播”数据包，则判断当前系统内是否存在接收这个
     * 数据包的网络接口 */

    /* start trying with inp. if that's not acceptable, start walking the
       list of configured netifs. */
    if (ip4_input_accept(inp)) {
      netif = inp;
    } else {
      netif = NULL;
#if !LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF
      /* Packets sent to the loopback address must not be accepted on an
       * interface that does not have the loopback address assigned to it,
       * unless a non-loopback interface is used for loopback traffic. */
      /* 如果当前协议栈不支持非回环网络接口的回环功能，则只有在当前接收到的数据包的
       * 目的 IPv4 地址为非回环域的地址才可以处理这个数据包，如果当前接收到的数据包
       * 的目的 IPv4 地址处于回环域中，则不处理 */
      if (!ip4_addr_isloopback(ip4_current_dest_addr()))
#endif /* !LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF */
      {
#if !LWIP_SINGLE_NETIF
        /* 遍历当前系统内的每一个网络接口，分别判断是否可以处理当前接收到的 IPv4 数据包 */
        NETIF_FOREACH(netif) {
          if (netif == inp) {
            /* we checked that before already */
            continue;
          }
          if (ip4_input_accept(netif)) {
		  	/* 找到了可以处理当前接收到的数据包的网络接口 */
            break;
          }
        }
#endif /* !LWIP_SINGLE_NETIF */
      }
    }
  }

/* 处理基于链路地址寻址的服务数据包，即跳过                     IPv4 地址校验，直接校验传输层端口信息 */
#if IP_ACCEPT_LINK_LAYER_ADDRESSING
  /* Pass DHCP messages regardless of destination address. DHCP traffic is addressed
   * using link layer addressing (such as Ethernet MAC) so we must not filter on IP.
   * According to RFC 1542 section 3.1.1, referred by RFC 2131).
   *
   * If you want to accept private broadcast communication while a netif is down,
   * define LWIP_IP_ACCEPT_UDP_PORT(dst_port), e.g.:
   *
   * #define LWIP_IP_ACCEPT_UDP_PORT(dst_port) ((dst_port) == PP_NTOHS(12345))
   */
  /* 因为 DHCP 服务是通过链路层地址进行寻址的（例如以太网 MAC 地址），所以我们在 IP 层
   * 不能对这样的网络数据包协议头中的 IP 地址进行校验过滤 */
  if (netif == NULL) {
    /* remote port is DHCP server? */
    /* 这个位置不仅仅局限于接收 udp 协议数据包，如果想要接收 tcp 数据包，则可以通过扩展一个功能分支实现 */
    if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
      const struct udp_hdr *udphdr = (const struct udp_hdr *)((const u8_t *)iphdr + iphdr_hlen);
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE, ("ip4_input: UDP packet to DHCP client port %"U16_F"\n",
                                              lwip_ntohs(udphdr->dest)));
      if (IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(udphdr->dest)) {
        LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE, ("ip4_input: DHCP packet accepted.\n"));
        netif = inp;
        check_ip_src = 0;
      }
    }
  }
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING */

  /* broadcast or multicast packet source address? Compliant with RFC 1122: 3.2.1.3 */
  /* 校验接收到的数据包的“源” IPv4 地址是否是广播地址或者是多播地址，如果是，则表示接收
   * 到的是一个非法数据包，则直接释放其占用的资源并返回 */
#if LWIP_IGMP || IP_ACCEPT_LINK_LAYER_ADDRESSING
  if (check_ip_src
#if IP_ACCEPT_LINK_LAYER_ADDRESSING
      /* DHCP servers need 0.0.0.0 to be allowed as source address (RFC 1.1.2.2: 3.2.1.3/a) */
      && !ip4_addr_isany_val(*ip4_current_src_addr())
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING */
     )
#endif /* LWIP_IGMP || IP_ACCEPT_LINK_LAYER_ADDRESSING */
  {
    if ((ip4_addr_isbroadcast(ip4_current_src_addr(), inp)) ||
        (ip4_addr_ismulticast(ip4_current_src_addr()))) {
      /* packet source is not valid */
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING, ("ip4_input: packet source is not valid.\n"));
      /* free (drop) packet pbufs */
      pbuf_free(p);
      IP_STATS_INC(ip.drop);
      MIB2_STATS_INC(mib2.ipinaddrerrors);
      MIB2_STATS_INC(mib2.ipindiscards);
      return ERR_OK;
    }
  }

  /* packet not for us? */
  /* 如果接收到的数据包不是发送给当前机器的，并且这个数据包不是广播数据包则尝试从当前设备的
   * 路由信息中为这个数据包找一个合适的路由设备，然后把这个数据包转发到找到的路由设备处 */
  if (netif == NULL) {
    /* packet not for us, route or discard */
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_TRACE, ("ip4_input: packet not for us.\n"));
	
#if IP_FORWARD
    /* non-broadcast packet? */
    if (!ip4_addr_isbroadcast(ip4_current_dest_addr(), inp)) {
      /* try to forward IP packet on (other) interfaces */
      ip4_forward(p, (struct ip_hdr *)p->payload, inp);
    } else
#endif /* IP_FORWARD */
    {
      IP_STATS_INC(ip.drop);
      MIB2_STATS_INC(mib2.ipinaddrerrors);
      MIB2_STATS_INC(mib2.ipindiscards);
    }

    pbuf_free(p);
    return ERR_OK;
  }
  
  /* packet consists of multiple fragments? */
  /* 如果接收到的网络数据包是个分片数据包，则对其进行重组，拼接成一个完成的数据包 */
  if ((IPH_OFFSET(iphdr) & PP_HTONS(IP_OFFMASK | IP_MF)) != 0) {
#if IP_REASSEMBLY /* packet fragment reassembly code present? */
    LWIP_DEBUGF(IP_DEBUG, ("IP packet is a fragment (id=0x%04"X16_F" tot_len=%"U16_F" len=%"U16_F" MF=%"U16_F" offset=%"U16_F"), calling ip4_reass()\n",
                           lwip_ntohs(IPH_ID(iphdr)), p->tot_len, lwip_ntohs(IPH_LEN(iphdr)), (u16_t)!!(IPH_OFFSET(iphdr) & PP_HTONS(IP_MF)), (u16_t)((lwip_ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK) * 8)));
    /* reassemble the packet*/
    p = ip4_reass(p);
    /* packet not fully reassembled yet? */
    if (p == NULL) {
      /* 表示当前接收到的分片数据包还不是完整数据包的最后一个分片，所以直接返回 */
      return ERR_OK;
    }
    iphdr = (const struct ip_hdr *)p->payload;
#else /* IP_REASSEMBLY == 0, no packet fragment reassembly code present */
    pbuf_free(p);
    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("IP packet dropped since it was fragmented (0x%"X16_F") (while IP_REASSEMBLY == 0).\n",
                lwip_ntohs(IPH_OFFSET(iphdr))));
    IP_STATS_INC(ip.opterr);
    IP_STATS_INC(ip.drop);
    /* unsupported protocol feature */
    MIB2_STATS_INC(mib2.ipinunknownprotos);
    return ERR_OK;
#endif /* IP_REASSEMBLY */
  }

/* 处理 igmp 协议中，在协议头“选项”扩展字段中添加的 router alert 数据的场景
 * 对于这样的数据包，目前只对其统计，不做任何其他处理 */
#if IP_OPTIONS_ALLOWED == 0 /* no support for IP options in the IP header? */

#if LWIP_IGMP
  /* there is an extra "router alert" option in IGMP messages which we allow for but do not police */
  if ((iphdr_hlen > IP_HLEN) &&  (IPH_PROTO(iphdr) != IP_PROTO_IGMP)) {
#else
  if (iphdr_hlen > IP_HLEN) {
#endif /* LWIP_IGMP */

    LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("IP packet dropped since there were IP options (while IP_OPTIONS_ALLOWED == 0).\n"));
    pbuf_free(p);
    IP_STATS_INC(ip.opterr);
    IP_STATS_INC(ip.drop);
    /* unsupported protocol feature */
    MIB2_STATS_INC(mib2.ipinunknownprotos);
    return ERR_OK;
  }
#endif /* IP_OPTIONS_ALLOWED == 0 */

  /* send to upper layers */
  LWIP_DEBUGF(IP_DEBUG, ("ip4_input: \n"));
  ip4_debug_print(p);
  LWIP_DEBUGF(IP_DEBUG, ("ip4_input: p->len %"U16_F" p->tot_len %"U16_F"\n", p->len, p->tot_len));

  /* 记录和当前接收的网络数据包相关的信息到全局变量中 */
  ip_data.current_netif = netif;
  ip_data.current_input_netif = inp;
  ip_data.current_ip4_header = iphdr;
  ip_data.current_ip_header_tot_len = IPH_HL_BYTES(iphdr);

#if LWIP_RAW
  /* raw input did not eat the packet? */
  raw_status = raw_input(p, inp);
  if (raw_status != RAW_INPUT_EATEN)
#endif /* LWIP_RAW */
  {
    pbuf_remove_header(p, iphdr_hlen); /* Move to payload, no check necessary. */

    /* 根据接收到的数据包“负载数据协议类型”把“负载数据”分发到相应上层协议模块中进行下一步处理 */
    switch (IPH_PROTO(iphdr)) {
		
#if LWIP_UDP
      case IP_PROTO_UDP:
#if LWIP_UDPLITE
      case IP_PROTO_UDPLITE:
#endif /* LWIP_UDPLITE */
        MIB2_STATS_INC(mib2.ipindelivers);
        udp_input(p, inp);
        break;
#endif /* LWIP_UDP */

#if LWIP_TCP
      case IP_PROTO_TCP:
        MIB2_STATS_INC(mib2.ipindelivers);
        tcp_input(p, inp);
        break;
#endif /* LWIP_TCP */

#if LWIP_ICMP
      case IP_PROTO_ICMP:
        MIB2_STATS_INC(mib2.ipindelivers);
        icmp_input(p, inp);
        break;
#endif /* LWIP_ICMP */

#if LWIP_IGMP
      case IP_PROTO_IGMP:
        igmp_input(p, inp, ip4_current_dest_addr());
        break;
#endif /* LWIP_IGMP */

      default:
#if LWIP_RAW
        if (raw_status == RAW_INPUT_DELIVERED) {
          MIB2_STATS_INC(mib2.ipindelivers);
        } else
#endif /* LWIP_RAW */

        {
#if LWIP_ICMP
          /* send ICMP destination protocol unreachable unless is was a broadcast */
          if (!ip4_addr_isbroadcast(ip4_current_dest_addr(), netif) &&
              !ip4_addr_ismulticast(ip4_current_dest_addr())) {
            pbuf_header_force(p, (s16_t)iphdr_hlen); /* Move to ip header, no check necessary. */
            icmp_dest_unreach(p, ICMP_DUR_PROTO);
          }
#endif /* LWIP_ICMP */

          LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("Unsupported transport protocol %"U16_F"\n", (u16_t)IPH_PROTO(iphdr)));

          IP_STATS_INC(ip.proterr);
          IP_STATS_INC(ip.drop);
          MIB2_STATS_INC(mib2.ipinunknownprotos);
        }
        pbuf_free(p);
        break;
    }
  }

  /* @todo: this is not really necessary... */
  /* 数据包处理完毕，清空记录在全局变量中和接收到的数据包相关的信息 */
  ip_data.current_netif = NULL;
  ip_data.current_input_netif = NULL;
  ip_data.current_ip4_header = NULL;
  ip_data.current_ip_header_tot_len = 0;
  ip4_addr_set_any(ip4_current_src_addr());
  ip4_addr_set_any(ip4_current_dest_addr());

  return ERR_OK;
}

/**
 * Sends an IP packet on a network interface. This function constructs
 * the IP header and calculates the IP header checksum. If the source
 * IP address is NULL, the IP address of the outgoing network
 * interface is filled in as source address.
 * If the destination IP address is LWIP_IP_HDRINCL, p is assumed to already
 * include an IP header and p->payload points to it instead of the data.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
            IP header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP4_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 * @param netif the netif on which to send this packet
 * @return ERR_OK if the packet was sent OK
 *         ERR_BUF if p doesn't have enough space for IP/LINK headers
 *         returns errors returned by netif->output
 *
 * @note ip_id: RFC791 "some host may be able to simply use
 *  unique identifiers independent of destination"
 */
/*********************************************************************************************************
** 函数名称: ip4_output_if
** 功能描述: 通过指定的网络接口发送指定的网络数据包，在发送之前会根据传入的参数在负载数据前构建并添加
**         : 一个 IP 协议头
** 注     释: 1. 如果目的 IPv4 地址参数为 LWIP_IP_HDRINCL，表示要发送的网络数据包中已经添加了 IP 协议头
**         :    数据并且 pbuf->payload 指向了 IP 协议头位置处，我们无需重新构建协议头了，这个常常用在 
**         :    TCP 重传数据包场景下
**         : 2. 如果如果不是 TCP 重传数据包且在函数参数中没指定 IPv4 “源”地址，则默认设置为发送网络数据
**         :    包的网络接口的 IPv4 地址
** 输	 入: p - 需要发送的网络数据包
**         : src - 网络数据包协议头的 IPv4 源地址字段值
**         : dest - 网络数据包协议头的 IPv4 目的地址字段值
**         : ttl - 网络数据包协议头的 time to live 字段值
**         : tos - 网络数据包协议头的 type of          service 字段值
**         : proto - 网络数据包协议头的 protocol 字段值
**         : netif - 发送网络数据包的网络接口指针
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
ip4_output_if(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
              u8_t ttl, u8_t tos,
              u8_t proto, struct netif *netif)
{
#if IP_OPTIONS_SEND
  return ip4_output_if_opt(p, src, dest, ttl, tos, proto, netif, NULL, 0);
}

/**
 * Same as ip_output_if() but with the possibility to include IP options:
 *
 * @ param ip_options pointer to the IP options, copied into the IP header
 * @ param optlen length of ip_options
 */
/*********************************************************************************************************
** 函数名称: ip4_output_if_opt
** 功能描述: 通过指定的网络接口发送指定的网络数据包，在发送之前会根据传入的参数在负载数据前构建并添加
**         : 一个 IP 协议头，需要注意的是，这个函数除了支持常规 IPv4 协议头，还支持 IPv4 协议头中的“选项”
**         : 扩展字段
** 注     释: 1. 如果目的 IPv4 地址参数为 LWIP_IP_HDRINCL，表示要发送的网络数据包中已经添加了 IP 协议头
**         :    数据并且 pbuf->payload 指向了 IP 协议头位置处，我们无需重新构建协议头了，这个常常用在 
**         :    TCP 重传数据包场景下
**         : 2. 如果如果不是 TCP 重传数据包且在函数参数中没指定 IPv4 “源”地址，则默认设置为发送网络数据
**         :    包的网络接口的 IPv4 地址
** 输	 入: p - 需要发送的网络数据包
**         : src - 网络数据包协议头的 IPv4 源地址字段值
**         : dest - 网络数据包协议头的 IPv4 目的地址字段值
**         : ttl - 网络数据包协议头的 time to live 字段值
**         : tos - 网络数据包协议头的 type of          service 字段值
**         : proto - 网络数据包协议头的 protocol 字段值
**         : netif - 发送网络数据包的网络接口指针
**         : ip_options - 网络数据包协议头的“选项”扩展部分数据地址
**         : optlen - 网络数据包协议头的“选项”扩展部分数据长度
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
ip4_output_if_opt(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
                  u8_t ttl, u8_t tos, u8_t proto, struct netif *netif, void *ip_options,
                  u16_t optlen)
{
#endif /* IP_OPTIONS_SEND */

  const ip4_addr_t *src_used = src;

  /* 如果不是 TCP 重传数据包且在函数参数中没指定 IPv4 “源”地址，则默认设置为
   * 发送网络数据包的网络接口的 IPv4 地址 */
  if (dest != LWIP_IP_HDRINCL) {
    if (ip4_addr_isany(src)) {
      src_used = netif_ip4_addr(netif);
    }
  }

#if IP_OPTIONS_SEND
  return ip4_output_if_opt_src(p, src_used, dest, ttl, tos, proto, netif,
                               ip_options, optlen);
#else /* IP_OPTIONS_SEND */
  return ip4_output_if_src(p, src_used, dest, ttl, tos, proto, netif);
#endif /* IP_OPTIONS_SEND */
}

/**
 * Same as ip_output_if() but 'src' address is not replaced by netif address
 * when it is 'any'.
 */
/*********************************************************************************************************
** 函数名称: ip4_output_if_src
** 功能描述: 通过指定的网络接口发送指定的网络数据包，在发送之前会根据传入的参数在负载数据前构建并添加
**         : 一个 IP 协议头
** 注     释: 1. 如果目的 IPv4 地址参数为 LWIP_IP_HDRINCL，表示要发送的网络数据包中已经添加了 IP 协议头
**         :    数据并且 pbuf->payload 指向了 IP 协议头位置处，我们无需重新构建协议头了，这个常常用在 
**         :    TCP 重传数据包场景下
** 输	 入: p - 需要发送的网络数据包
**         : src - 网络数据包协议头的 IPv4 源地址字段值
**         : dest - 网络数据包协议头的 IPv4 目的地址字段值
**         : ttl - 网络数据包协议头的 time to live 字段值
**         : tos - 网络数据包协议头的 type of          service 字段值
**         : proto - 网络数据包协议头的 protocol 字段值
**         : netif - 发送网络数据包的网络接口指针
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
ip4_output_if_src(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
                  u8_t ttl, u8_t tos,
                  u8_t proto, struct netif *netif)
{
#if IP_OPTIONS_SEND
  return ip4_output_if_opt_src(p, src, dest, ttl, tos, proto, netif, NULL, 0);
}

/**
 * Same as ip_output_if_opt() but 'src' address is not replaced by netif address
 * when it is 'any'.
 */
/*********************************************************************************************************
** 函数名称: ip4_output_if_opt_src
** 功能描述: 通过指定的网络接口发送指定的网络数据包，在发送之前会根据传入的参数在负载数据前构建并添加
**         : 一个 IP 协议头，需要注意的是，这个函数除了支持常规 IPv4 协议头，还支持 IPv4 协议头中的“选项”
**         : 扩展字段，具体执行逻辑如下：
**         : 1. 校验待发送的数据包的引用计数值是否合法
**         : 2. 通过目的 IPv4 地址判断当前待发送的网络数据包中是否已经有了 IP 协议头部分数据，如果没有 IP 
**         :    协议头，则通过函数参数构建并填充当前数据包的 IP 协议头，如果有 IP 协议头，则直接执行后续逻辑
**         : 3. 判断当前要发送的网络数据包目的 IPv4 地址是否是发现自己的回环数据包或者是否是发向回环网
**         :    络接口的回环数据包，如果是回环数据包，则直接把数据包发送到回环链表上
**         : 4. 如果待发送的网络数据包长度超过当前网络接口 MTU 值，则把数据包分片后再依次发送到下层协议处
**         : 5. 如果待发送的网络数据包不需要执行分片操作，则把数据包直接发送到下层协议处
** 注     释: 1. 如果目的 IPv4 地址参数为 LWIP_IP_HDRINCL，表示要发送的网络数据包中已经添加了 IP 协议头
**         :    数据并且 pbuf->payload 指向了 IP 协议头位置处，我们无需重新构建协议头了，这个常常用在 
**         :    TCP 重传数据包场景下
** 输	 入: p - 需要发送的网络数据包
**         : src - 网络数据包协议头的 IPv4 源地址字段值
**         : dest - 网络数据包协议头的 IPv4 目的地址字段值
**         : ttl - 网络数据包协议头的 time to live 字段值
**         : tos - 网络数据包协议头的 type of          service 字段值
**         : proto - 网络数据包协议头的 protocol 字段值
**         : netif - 发送网络数据包的网络接口指针
**         : ip_options - 网络数据包协议头的“选项”扩展部分数据地址
**         : optlen - 网络数据包协议头的“选项”扩展部分数据长度
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
ip4_output_if_opt_src(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
                      u8_t ttl, u8_t tos, u8_t proto, struct netif *netif, void *ip_options,
                      u16_t optlen)
{
#endif /* IP_OPTIONS_SEND */

  struct ip_hdr *iphdr;
  ip4_addr_t dest_addr;

#if CHECKSUM_GEN_IP_INLINE
  u32_t chk_sum = 0;
#endif /* CHECKSUM_GEN_IP_INLINE */

  LWIP_ASSERT_CORE_LOCKED();

  /* 校验待发送的数据包的引用计数值是否合法 */
  LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

  MIB2_STATS_INC(mib2.ipoutrequests);

  /* Should the IP header be generated or is it already included in p? */
  /* 通过目的 IPv4 地址判断当前待发送的网络数据包中是否已经有了 IP 协议头部分数据，如果没有 IP 协议头
   * 则通过函数参数构建并填充当前数据包的 IP 协议头，如果有 IP 协议头，则直接执行后续逻辑 */
  if (dest != LWIP_IP_HDRINCL) {
    u16_t ip_hlen = IP_HLEN;
	

#if IP_OPTIONS_SEND
    u16_t optlen_aligned = 0;
    if (optlen != 0) {

#if CHECKSUM_GEN_IP_INLINE
      int i;
#endif /* CHECKSUM_GEN_IP_INLINE */

      /* 校验我们要在 IP 协议头中添加的“选项”扩展字段数据长度是否合法 */
	  if (optlen > (IP_HLEN_MAX - IP_HLEN)) {
        /* optlen too long */
        LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_output_if_opt: optlen too long\n"));
        IP_STATS_INC(ip.err);
        MIB2_STATS_INC(mib2.ipoutdiscards);
        return ERR_VAL;
      }
	  
      /* round up to a multiple of 4 */
	  /* 把 IP 协议头中添加的“选项”扩展字段的数据长度向上按照 4 字节对齐 */
      optlen_aligned = (u16_t)((optlen + 3) & ~3);
      ip_hlen = (u16_t)(ip_hlen + optlen_aligned);
	  
      /* First write in the IP options */
	  /* 添加 IP 协议头中添加的“选项”扩展字段空间 */
      if (pbuf_add_header(p, optlen_aligned)) {
        LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_output_if_opt: not enough room for IP options in pbuf\n"));
        IP_STATS_INC(ip.err);
        MIB2_STATS_INC(mib2.ipoutdiscards);
        return ERR_BUF;
      }
	  
      MEMCPY(p->payload, ip_options, optlen);

	  /* 把 IP 协议头中添加的“选项”扩展字段的 pad 数据空间内容填充为 0 */
      if (optlen < optlen_aligned) {
        /* zero the remaining bytes */
        memset(((char *)p->payload) + optlen, 0, (size_t)(optlen_aligned - optlen));
      }

/* 计算 IP 协议头中添加的“选项”扩展字段数据的校验和 */
#if CHECKSUM_GEN_IP_INLINE
      for (i = 0; i < optlen_aligned / 2; i++) {
        chk_sum += ((u16_t *)p->payload)[i];
      }
#endif /* CHECKSUM_GEN_IP_INLINE */

    }
#endif /* IP_OPTIONS_SEND */


    /* generate IP header */
	/* 添加常规 IP 协议头空间并根据函数参数构建常规 IP 协议头并计算对应数据的校验和 */
    if (pbuf_add_header(p, IP_HLEN)) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_output: not enough room for IP header in pbuf\n"));

      IP_STATS_INC(ip.err);
      MIB2_STATS_INC(mib2.ipoutdiscards);
      return ERR_BUF;
    }

    iphdr = (struct ip_hdr *)p->payload;
    LWIP_ASSERT("check that first pbuf can hold struct ip_hdr",
                (p->len >= sizeof(struct ip_hdr)));

    IPH_TTL_SET(iphdr, ttl);
    IPH_PROTO_SET(iphdr, proto);
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += PP_NTOHS(proto | (ttl << 8));
#endif /* CHECKSUM_GEN_IP_INLINE */

    /* dest cannot be NULL here */
    ip4_addr_copy(iphdr->dest, *dest);
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += ip4_addr_get_u32(&iphdr->dest) & 0xFFFF;
    chk_sum += ip4_addr_get_u32(&iphdr->dest) >> 16;
#endif /* CHECKSUM_GEN_IP_INLINE */

    IPH_VHL_SET(iphdr, 4, ip_hlen / 4);
    IPH_TOS_SET(iphdr, tos);
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += PP_NTOHS(tos | (iphdr->_v_hl << 8));
#endif /* CHECKSUM_GEN_IP_INLINE */
    IPH_LEN_SET(iphdr, lwip_htons(p->tot_len));
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += iphdr->_len;
#endif /* CHECKSUM_GEN_IP_INLINE */
    IPH_OFFSET_SET(iphdr, 0);
    IPH_ID_SET(iphdr, lwip_htons(ip_id));
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += iphdr->_id;
#endif /* CHECKSUM_GEN_IP_INLINE */

    /* 一个全局静态变量，用来表示下一个待发送的数据包在 IP 协议的协议头中的使用的数据包
     * ID 标志值，这个变量在 IP 数据包分片时用来表示每一个分片数据包所属的数据包号 */
    ++ip_id;

    /* 如果函数参数指定的“源” IPv4 地址为 NULL，则设置IP 协议的协议头中的“源” IPv4 地址为 
     * IP4_ADDR_ANY4（0.0.0.0），否者设置为参数指定的地址 */
    if (src == NULL) {
      ip4_addr_copy(iphdr->src, *IP4_ADDR_ANY4);
    } else {
      /* src cannot be NULL here */
      ip4_addr_copy(iphdr->src, *src);
    }

#if CHECKSUM_GEN_IP_INLINE
    chk_sum += ip4_addr_get_u32(&iphdr->src) & 0xFFFF;
    chk_sum += ip4_addr_get_u32(&iphdr->src) >> 16;
    chk_sum = (chk_sum >> 16) + (chk_sum & 0xFFFF);
    chk_sum = (chk_sum >> 16) + chk_sum;
    chk_sum = ~chk_sum;

	/* 判断当前系统是否需要添加 IP 层协议校验和 */
    IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_IP) {
      iphdr->_chksum = (u16_t)chk_sum; /* network order */
    }
	
#if LWIP_CHECKSUM_CTRL_PER_NETIF
    else {
      IPH_CHKSUM_SET(iphdr, 0);
    }
#endif /* LWIP_CHECKSUM_CTRL_PER_NETIF*/

#else /* CHECKSUM_GEN_IP_INLINE */
    IPH_CHKSUM_SET(iphdr, 0);

#if CHECKSUM_GEN_IP
    IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_IP) {
      IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, ip_hlen));
    }
#endif /* CHECKSUM_GEN_IP */

#endif /* CHECKSUM_GEN_IP_INLINE */

  } else {
    /* IP header already included in p */
    if (p->len < IP_HLEN) {
      LWIP_DEBUGF(IP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("ip4_output: LWIP_IP_HDRINCL but pbuf is too short\n"));
      IP_STATS_INC(ip.err);
      MIB2_STATS_INC(mib2.ipoutdiscards);
      return ERR_BUF;
    }
	
    iphdr = (struct ip_hdr *)p->payload;
    ip4_addr_copy(dest_addr, iphdr->dest);
    dest = &dest_addr;
  }

  IP_STATS_INC(ip.xmit);

  LWIP_DEBUGF(IP_DEBUG, ("ip4_output_if: %c%c%"U16_F"\n", netif->name[0], netif->name[1], (u16_t)netif->num));
  ip4_debug_print(p);


/* 判断当前要发送的网络数据包目的 IPv4 地址是否是发现自己的回环数据包或者是否是发向
 * 回环网络接口的回环数据包，如果是回环数据包，则直接把数据包发送到回环链表上 */
#if ENABLE_LOOPBACK
  if (ip4_addr_cmp(dest, netif_ip4_addr(netif))
  	
#if !LWIP_HAVE_LOOPIF
      || ip4_addr_isloopback(dest)
#endif /* !LWIP_HAVE_LOOPIF */

    ) {
    /* Packet to self, enqueue it for loopback */
    LWIP_DEBUGF(IP_DEBUG, ("netif_loop_output()"));
    return netif_loop_output(netif, p);
  }

/* 表示当前通过 udp 多播协议发送的数据包需要回环发送到当前网络接口上 */	 
#if LWIP_MULTICAST_TX_OPTIONS
  if ((p->flags & PBUF_FLAG_MCASTLOOP) != 0) {
    netif_loop_output(netif, p);
  }
#endif /* LWIP_MULTICAST_TX_OPTIONS */

#endif /* ENABLE_LOOPBACK */


/* 如果待发送的网络数据包长度超过当前网络接口 MTU 值，则把数据包分片后再依次发送到下层协议处 */
#if IP_FRAG
  /* don't fragment if interface has mtu set to 0 [loopif] */
  if (netif->mtu && (p->tot_len > netif->mtu)) {
    return ip4_frag(p, netif, dest);
  }
#endif /* IP_FRAG */

  LWIP_DEBUGF(IP_DEBUG, ("ip4_output_if: call netif->output()\n"));
  /* 如果待发送的网络数据包不需要执行分片操作，则把数据包直接发送到下层协议处 */
  return netif->output(netif, p, dest);
}

/**
 * Simple interface to ip_output_if. It finds the outgoing network
 * interface and calls upon ip_output_if to do the actual work.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
            IP header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP4_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */
/*********************************************************************************************************
** 函数名称: ip4_output
** 功能描述: 根据当前系统的路由策略找到一个发送指定数据包的网络接口，并通过找到的网络接口发送指定的
**         : 网络数据包，在发送之前会根据传入的参数在负载数据前构建并添加一个 IP 协议头
** 注     释: 1. 如果目的 IPv4 地址参数为 LWIP_IP_HDRINCL，表示要发送的网络数据包中已经添加了 IP 协议头
**         :    数据并且 pbuf->payload 指向了 IP 协议头位置处，我们无需重新构建协议头了，这个常常用在 
**         :    TCP 重传数据包场景下
**         : 2. 如果如果不是 TCP 重传数据包且在函数参数中没指定 IPv4 “源”地址，则默认设置为发送网络数据
**         :    包的网络接口的 IPv4 地址
** 输	 入: p - 需要发送的网络数据包
**         : src - 网络数据包协议头的 IPv4 源地址字段值
**         : dest - 网络数据包协议头的 IPv4 目的地址字段值
**         : ttl - 网络数据包协议头的 time to live 字段值
**         : tos - 网络数据包协议头的 type of          service 字段值
**         : proto - 网络数据包协议头的 protocol 字段值
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
ip4_output(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
           u8_t ttl, u8_t tos, u8_t proto)
{
  struct netif *netif;

  LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

  /* 根据当前系统的路由策略找到一个发送指定数据包的网络接口 */
  if ((netif = ip4_route_src(src, dest)) == NULL) {
    LWIP_DEBUGF(IP_DEBUG, ("ip4_output: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                           ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
    IP_STATS_INC(ip.rterr);
    return ERR_RTE;
  }

  return ip4_output_if(p, src, dest, ttl, tos, proto, netif);
}

#if LWIP_NETIF_USE_HINTS
/** Like ip_output, but takes and addr_hint pointer that is passed on to netif->addr_hint
 *  before calling ip_output_if.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
            IP header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP4_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 * @param netif_hint netif output hint pointer set to netif->hint before
 *        calling ip_output_if()
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */
/*********************************************************************************************************
** 函数名称: ip4_output_hinted
** 功能描述: 根据当前系统的路由策略找到一个发送指定数据包的网络接口，并通过找到的网络接口根据指定的 arp 
**         : 映射项信息发送指定的网络数据包，在发送之前会根据传入的参数在负载数据前构建并添加一个 IP 协议头
** 注     释: 1. 如果目的 IPv4 地址参数为 LWIP_IP_HDRINCL，表示要发送的网络数据包中已经添加了 IP 协议头
**         :    数据并且 pbuf->payload 指向了 IP 协议头位置处，我们无需重新构建协议头了，这个常常用在 
**         :    TCP 重传数据包场景下
**         : 2. 如果如果不是 TCP 重传数据包且在函数参数中没指定 IPv4 “源”地址，则默认设置为发送网络数据
**         :    包的网络接口的 IPv4 地址
** 输	 入: p - 需要发送的网络数据包
**         : src - 网络数据包协议头的 IPv4 源地址字段值
**         : dest - 网络数据包协议头的 IPv4 目的地址字段值
**         : ttl - 网络数据包协议头的 time to live 字段值
**         : tos - 网络数据包协议头的 type of          service 字段值
**         : proto - 网络数据包协议头的 protocol 字段值
**         : netif_hint - 本次发送使用的 arp 映射项索引值指针
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
ip4_output_hinted(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
                  u8_t ttl, u8_t tos, u8_t proto, struct netif_hint *netif_hint)
{
  struct netif *netif;
  err_t err;

  /* 在上层模块向 IP 层传输待发送的网络数据包时，网络数据包的引用计数必须为 1 */
  LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

  /* 根据当前系统的路由策略找到一个发送指定数据包的网络接口 */
  if ((netif = ip4_route_src(src, dest)) == NULL) {
    LWIP_DEBUGF(IP_DEBUG, ("ip4_output: No route to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                           ip4_addr1_16(dest), ip4_addr2_16(dest), ip4_addr3_16(dest), ip4_addr4_16(dest)));
    IP_STATS_INC(ip.rterr);
    return ERR_RTE;
  }

  /* 根据指定的 arp 映射项索引值设置当前要发送网络数据包的网络接口的 hints 字段值
   * 这个字段值在执行 arp 地址转换的时候会用到，用来提高地址转换效率 */
  NETIF_SET_HINTS(netif, netif_hint);
  err = ip4_output_if(p, src, dest, ttl, tos, proto, netif);
  NETIF_RESET_HINTS(netif);

  return err;
}
#endif /* LWIP_NETIF_USE_HINTS*/

#if IP_DEBUG
/* Print an IP header by using LWIP_DEBUGF
 * @param p an IP packet, p->payload pointing to the IP header
 */
/*********************************************************************************************************
** 函数名称: ip4_debug_print
** 功能描述: 打印指定网络数据包的常规 IP 协议头部分数据内容，不包含“选项”扩展部分
** 输	 入: p - 需要打印头部信息的网络数据包指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
ip4_debug_print(struct pbuf *p)
{
  struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;

  LWIP_DEBUGF(IP_DEBUG, ("IP header:\n"));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|%2"S16_F" |%2"S16_F" |  0x%02"X16_F" |     %5"U16_F"     | (v, hl, tos, len)\n",
                         (u16_t)IPH_V(iphdr),
                         (u16_t)IPH_HL(iphdr),
                         (u16_t)IPH_TOS(iphdr),
                         lwip_ntohs(IPH_LEN(iphdr))));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|    %5"U16_F"      |%"U16_F"%"U16_F"%"U16_F"|    %4"U16_F"   | (id, flags, offset)\n",
                         lwip_ntohs(IPH_ID(iphdr)),
                         (u16_t)(lwip_ntohs(IPH_OFFSET(iphdr)) >> 15 & 1),
                         (u16_t)(lwip_ntohs(IPH_OFFSET(iphdr)) >> 14 & 1),
                         (u16_t)(lwip_ntohs(IPH_OFFSET(iphdr)) >> 13 & 1),
                         (u16_t)(lwip_ntohs(IPH_OFFSET(iphdr)) & IP_OFFMASK)));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|  %3"U16_F"  |  %3"U16_F"  |    0x%04"X16_F"     | (ttl, proto, chksum)\n",
                         (u16_t)IPH_TTL(iphdr),
                         (u16_t)IPH_PROTO(iphdr),
                         lwip_ntohs(IPH_CHKSUM(iphdr))));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  | (src)\n",
                         ip4_addr1_16_val(iphdr->src),
                         ip4_addr2_16_val(iphdr->src),
                         ip4_addr3_16_val(iphdr->src),
                         ip4_addr4_16_val(iphdr->src)));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(IP_DEBUG, ("|  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  |  %3"U16_F"  | (dest)\n",
                         ip4_addr1_16_val(iphdr->dest),
                         ip4_addr2_16_val(iphdr->dest),
                         ip4_addr3_16_val(iphdr->dest),
                         ip4_addr4_16_val(iphdr->dest)));
  LWIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
}
#endif /* IP_DEBUG */

#endif /* LWIP_IPV4 */
