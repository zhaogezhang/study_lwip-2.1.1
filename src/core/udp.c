/**
 * @file
 * User Datagram Protocol module\n
 * The code for the User Datagram Protocol UDP & UDPLite (RFC 3828).\n
 * See also @ref udp_raw
 *
 * @defgroup udp_raw UDP
 * @ingroup callbackstyle_api
 * User Datagram Protocol module\n
 * @see @ref api
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

/* @todo Check the use of '(struct udp_pcb).chksum_len_rx'!
 */

/* UDP-Lite 数据包协议格式，详细内容见链接：https://tools.ietf.org/html/rfc3828
 *
 *    0 			 15 16			   31
 *   +--------+--------+--------+--------+
 *   |	   Source	   |   Destination	 |
 *   |		Port	   |	  Port		 |
 *   +--------+--------+--------+--------+
 *   |	  Checksum	   |				 |
 *   |	  Coverage	   |	Checksum	 |
 *   +--------+--------+--------+--------+
 *   |									 |
 *   :				Payload 			 :
 *   |									 |
 *   +-----------------------------------+
 *
 *   源端口（Source Port）：发送这个数据包进程的端口号
 *   目的端口（Destination Port）：接收这个数据包进程的端口号
 *   校验和覆盖范围（Checksum Coverage）：表示从 udp 协议头开始，参与校验和计算的 8 位字节数
 *   校验和（Checksum）：udp 数据包的校验和，0 表示没有校验和
 *   负载数据（Payload）：当前 udp 数据包的负载数据
 *
 */
#include "lwip/opt.h"

#if LWIP_UDP /* don't build if not configured for use in lwipopts.h */

#include "lwip/udp.h"
#include "lwip/def.h"
#include "lwip/memp.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip_addr.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/netif.h"
#include "lwip/icmp.h"
#include "lwip/icmp6.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/dhcp.h"

#include <string.h>

/* 定义当前协议栈的 udp 模块的合法端口号分配范围 */
#ifndef UDP_LOCAL_PORT_RANGE_START
/* From http://www.iana.org/assignments/port-numbers:
   "The Dynamic and/or Private Ports are those from 49152 through 65535" */
#define UDP_LOCAL_PORT_RANGE_START  0xc000
#define UDP_LOCAL_PORT_RANGE_END    0xffff
#define UDP_ENSURE_LOCAL_PORT_RANGE(port) ((u16_t)(((port) & (u16_t)~UDP_LOCAL_PORT_RANGE_START) + UDP_LOCAL_PORT_RANGE_START))
#endif

/* last local UDP port */
static u16_t udp_port = UDP_LOCAL_PORT_RANGE_START;

/* The list of UDP PCBs */
/* exported in udp.h (was static) */
/* 多文件全局变量，通过单链表的方式把系统内所有 udp 连接的控制块信息链接起来
 * 需要注意的是，这个链表只包含那些已经绑定了 IP 地址和端口号的 udp 协议控制块 */
struct udp_pcb *udp_pcbs;

/**
 * Initialize this module.
 */
/*********************************************************************************************************
** 函数名称: udp_init
** 功能描述: 初始化当前协议栈的 udp 功能模块（初始化起始端口号的值）
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
udp_init(void)
{
#ifdef LWIP_RAND
  udp_port = UDP_ENSURE_LOCAL_PORT_RANGE(LWIP_RAND());
#endif /* LWIP_RAND */
}

/**
 * Allocate a new local UDP port.
 *
 * @return a new (free) local UDP port number
 */
/*********************************************************************************************************
** 函数名称: udp_new_port
** 功能描述: 尝试从当前系统内申请一个空闲的 udp 端口号
** 输	 入: 
** 输	 出: udp_port - 成功申请到的空闲 udp 端口号
**         : 0 - 申请失败，当前当前系统没有空闲的 udp 端口号
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static u16_t
udp_new_port(void)
{
  u16_t n = 0;
  struct udp_pcb *pcb;

again:
  if (udp_port++ == UDP_LOCAL_PORT_RANGE_END) {
    udp_port = UDP_LOCAL_PORT_RANGE_START;
  }
  
  /* Check all PCBs. */
  for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
    if (pcb->local_port == udp_port) {
      if (++n > (UDP_LOCAL_PORT_RANGE_END - UDP_LOCAL_PORT_RANGE_START)) {
        return 0;
      }
      goto again;
    }
  }
  return udp_port;
}

/** Common code to see if the current input packet matches the pcb
 * (current input packet is accessed via ip(4/6)_current_* macros)
 *
 * @param pcb pcb to check
 * @param inp network interface on which the datagram was received (only used for IPv4)
 * @param broadcast 1 if his is an IPv4 broadcast (global or subnet-only), 0 otherwise (only used for IPv4)
 * @return 1 on match, 0 otherwise
 */
/*********************************************************************************************************
** 函数名称: udp_input_local_match
** 功能描述: 校验在指定的网路接口上接收到的 udp 数据包和指定的 udp 控制块的“本地” IP 地址信息是否匹配
**         : 具体执行的操作逻辑如下：
**         : 1. 如果指定的 udp 连接已经和指定的网络接口建立绑定关系，且当前接收到 udp 数据包的网络接口
**         :    不是这个 udp 连接绑定的网络接口，则直接返回 0（表示不匹配）
**         : 2. 如果启动了“双栈”协议功能（同时支持 IPv4 协议和 IPv6 协议）
**         :    a. 如果当前接收到的 udp 数据包“是”广播数据包，但是指定的 udp 协议控制块“不支持”接收广播
**         :       数据，则直接返回 0（表示不匹配）
**         :    b. 如果当前接收到的 udp 数据包“是”广播数据包但是指定的 udp 协议控制块“支持”接收广播
**         :       数据包，则直接返回 1（表示匹配）
**         :    c. 如果当前接收到的 udp 数据包“不是”广播数据包则直接返回 1（表示匹配）
**         : 3. 校验指定的 udp 控制块的“本地” IP 地址信息和当前接收到的 udp 数据包的“目的” IP 地址信息
**         :    是否匹配
**         :    a. 如果当前 udp 协议控制块的本地 IP（IPv4 and IPv6）地址为 ANY（0.0.0.0）地址，则直接
**         :       返回 1（表示匹配）
**         :    b. 如果当前接收到的 udp 数据包的目的 IPv4 地址是全局局域网 IPv4 地址（255.255.255.255）
**         :       则直接返回 1（表示匹配）
**         :    c. 如果当前接收到的 udp 数据包的目的 IPv4 地址是子网广播地址并且和当前的网路接口的 IPv4 
**         :       地址在一个子网广播域内，则直接返回 1（表示匹配）
**         :    d. 如果当前接收到的 udp 数据包的目的 IP（IPv4 and IPv6）地址等于当前 udp 协议控制块的
**         :       本地 IP（IPv4 and IPv6）地址，则直接返回 1（表示匹配）
** 输	 入: pcb - 需要校验的 udp 协议控制块指针
**         : inp - 表示接收到当前数据包的网路接口指针
**         : broadcast - 表示当前接收到的数据包是否是广播数据包
** 输	 出: 1 - 匹配
**         : 0 - 不匹配
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static u8_t
udp_input_local_match(struct udp_pcb *pcb, struct netif *inp, u8_t broadcast)
{
  LWIP_UNUSED_ARG(inp);       /* in IPv6 only case */
  LWIP_UNUSED_ARG(broadcast); /* in IPv6 only case */

  LWIP_ASSERT("udp_input_local_match: invalid pcb", pcb != NULL);
  LWIP_ASSERT("udp_input_local_match: invalid netif", inp != NULL);

  /* check if PCB is bound to specific netif */
  /* 如果指定的 udp 连接已经和指定的网络接口建立绑定关系，且当前接收到 udp 数据包的网络接口不是这个
   * udp 连接绑定的网络接口，则直接返回 0，表示不匹配 */
  if ((pcb->netif_idx != NETIF_NO_INDEX) &&
      (pcb->netif_idx != netif_get_index(ip_data.current_input_netif))) {
    return 0;
  }

  /* Dual-stack: PCBs listening to any IP type also listen to any IP address */
  /* 如果启动了“双栈”协议功能（同时支持 IPv4 协议和 IPv6 协议），则接收所有 udp 数据包 */
  if (IP_IS_ANY_TYPE_VAL(pcb->local_ip)) {
  	
#if LWIP_IPV4 && IP_SOF_BROADCAST_RECV
    /* 如果当前接收到的 udp 数据包是广播数据包，但是指定的 udp 协议控制块不支持接收广播数据，则直接返回 0，表示不匹配 */
    if ((broadcast != 0) && !ip_get_option(pcb, SOF_BROADCAST)) {
      return 0;
    }
#endif /* LWIP_IPV4 && IP_SOF_BROADCAST_RECV */

    return 1;
  }

  /* Only need to check PCB if incoming IP version matches PCB IP version */
  /* 校验指定的 udp 控制块的“本地” IP 地址类型和当前接收到的 udp 数据包的“目的” IP 地址“类型”是否匹配 */
  if (IP_ADDR_PCB_VERSION_MATCH_EXACT(pcb, ip_current_dest_addr())) {
  	

#if LWIP_IPV4
    /* Special case: IPv4 broadcast: all or broadcasts in my subnet
     * Note: broadcast variable can only be 1 if it is an IPv4 broadcast */
    /* 如果接收到的 udp 数据包是个 IPv4 广播数据包，则判断接收到的 udp 数据包是否是发送到当前 udp 协议控制块的数据包 */
    if (broadcast != 0) {
		
#if IP_SOF_BROADCAST_RECV
      if (ip_get_option(pcb, SOF_BROADCAST))
#endif /* IP_SOF_BROADCAST_RECV */

      {
        /* 如果满足下面的任何一个条件，表示当前 udp 协议控制块可以处理当前接收到的 udp 数据包，分别如下：
         * 1. 当前 udp 协议控制块的本地 IPv4 地址为 ANY（0.0.0.0）地址
         * 2. 当前接收到的 udp 数据包的目的 IPv4 地址是全局局域网 IPv4 地址（255.255.255.255）
         * 3. 当前接收到的 udp 数据包的目的 IPv4 地址是子网广播地址并且和当前的网路接口的 IPv4 地址在一个子网广播域内 */
        if (ip4_addr_isany(ip_2_ip4(&pcb->local_ip)) ||
            ((ip4_current_dest_addr()->addr == IPADDR_BROADCAST)) ||
            ip4_addr_netcmp(ip_2_ip4(&pcb->local_ip), ip4_current_dest_addr(), netif_ip4_netmask(inp))) {
          return 1;
        }
      }
    } else

#endif /* LWIP_IPV4 */


      /* Handle IPv4 and IPv6: all or exact match */
      /* 如果收到的 udp 数据包是“单播”或者“多播”数据包，那么如果满足下面的任何一个条件，表示当前 udp 协议控制块
       * 可以处理当前接收到的 udp 数据包，分别如下：
       * 1. 当前 udp 协议控制块的本地 IP（IPv4 and IPv6）地址为 ANY（0.0.0.0）地址
       * 2. 当前接收到的 udp 数据包的目的 IP（IPv4 and IPv6）地址等于当前 udp 协议控制块的本地 IP（IPv4 and IPv6）地址 */
      if (ip_addr_isany(&pcb->local_ip) || ip_addr_cmp(&pcb->local_ip, ip_current_dest_addr())) {
        return 1;
      }
  }

  return 0;
}

/**
 * Process an incoming UDP datagram.
 *
 * Given an incoming UDP datagram (as a chain of pbufs) this function
 * finds a corresponding UDP PCB and hands over the pbuf to the pcbs
 * recv function. If no pcb is found or the datagram is incorrect, the
 * pbuf is freed.
 *
 * @param p pbuf to be demultiplexed to a UDP PCB (p->payload pointing to the UDP header)
 * @param inp network interface on which the datagram was received.
 *
 */
/*********************************************************************************************************
** 函数名称: udp_input
** 功能描述: 处理一个从 IP 协议层接收到的 udp 数据包，基本的操作逻辑如下：
**         : 1. 校验接收到的 udp 数据包长度是否合法
**         : 2. 分别遍历系统内每个 udp 协议控制块结构，尝试找到一个和当前接收的 udp 数据包的 IP 地址信息和
**         :    udp 端口信息匹配的 udp 协议控制块结构，优先使用匹配并建立连接的的 udp 协议控制块结构，如果
**         :    没找到匹配并建立连接的 udp 协议控制块，则使用匹配度最高但是“未”建立连接的 udp 协议控制块
**         : 3. 判断当前接收到的 udp 数据包是否是发送给接收到这个数据包的网路接口的，如果是发送给接收到这
**         :    个数据包的网路接口的，则执行下面的操作，否则直接返回
**         :    a. 校验接收到的 udp 数据包的校验和字段值是否合法
**         :    b. 如果在当前系统中找到了和接收到的 udp 数据包匹配的 udp 协议控制块结构，则执行下面的操作
**         :       处理接收到的 udp 数据包
**         :       I.  如果第一个匹配的 udp 协议控制块中“设置”了 SOF_REUSEADDR socket 选项并且当前接收到
**         :           的数据包“是”多播数据包或者广播数据包，则把接收到的多播数据包或者广播数据包“克隆”
**         :           并“传输”到每一个地址匹配的协议控制块中
**         :       II. 如果第一个匹配的 udp 协议控制块中“没设置” SOF_REUSEADDR socket 选项或者当前接收到
**         :           的数据包“不是”多播数据包或者广播数据包，则只通过匹配的 udp 协议控制块中的接收数据
**         :           回调函数处理当前接收到的 udp 数据包
**         :    c. 如果当前系统中没有找到匹配的 udp 协议控制块结构，则发送一个目的端口不可达的 icmp 数据包
**         :       到发送当前接收到的 udp 数据包的以太网设备处
** 输	 入: p - 接收到的 udp 数据包指针
**         : inp - 表示接收到      udp 数据包的网路接口指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
udp_input(struct pbuf *p, struct netif *inp)
{
  struct udp_hdr *udphdr;
  struct udp_pcb *pcb, *prev;
  struct udp_pcb *uncon_pcb;
  u16_t src, dest;

  /* 表示当前接收的数据包是否是广播数据包（子网广播包或者全局局域网广播包）*/
  u8_t broadcast;

  /* 表示当前接收到的 udp 数据包是否是发送给接收到这个数据包的网路接口的 */
  u8_t for_us = 0;

  LWIP_UNUSED_ARG(inp);

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ASSERT("udp_input: invalid pbuf", p != NULL);
  LWIP_ASSERT("udp_input: invalid netif", inp != NULL);

  PERF_START;

  UDP_STATS_INC(udp.recv);

  /* Check minimum length (UDP header) */
  /* 校验接收到的 udp 数据包长度是否合法 */
  if (p->len < UDP_HLEN) {
    /* drop short packets */
    LWIP_DEBUGF(UDP_DEBUG,
                ("udp_input: short UDP datagram (%"U16_F" bytes) discarded\n", p->tot_len));
    UDP_STATS_INC(udp.lenerr);
    UDP_STATS_INC(udp.drop);
    MIB2_STATS_INC(mib2.udpinerrors);
    pbuf_free(p);
    goto end;
  }

  udphdr = (struct udp_hdr *)p->payload;

  /* is broadcast packet ? */
  /* 表示当前接收的数据包是否是广播数据包（子网广播包或者全局局域网广播包）*/
  broadcast = ip_addr_isbroadcast(ip_current_dest_addr(), ip_current_netif());

  LWIP_DEBUGF(UDP_DEBUG, ("udp_input: received datagram of length %"U16_F"\n", p->tot_len));

  /* convert src and dest ports to host byte order */
  /* 获取当前 udp 数据包的源端口号和目的端口号，并转换成主机字节序 */
  src = lwip_ntohs(udphdr->src);
  dest = lwip_ntohs(udphdr->dest);

  udp_debug_print(udphdr);

  /* print the UDP source and destination */
  LWIP_DEBUGF(UDP_DEBUG, ("udp ("));
  ip_addr_debug_print_val(UDP_DEBUG, *ip_current_dest_addr());
  LWIP_DEBUGF(UDP_DEBUG, (", %"U16_F") <-- (", lwip_ntohs(udphdr->dest)));
  ip_addr_debug_print_val(UDP_DEBUG, *ip_current_src_addr());
  LWIP_DEBUGF(UDP_DEBUG, (", %"U16_F")\n", lwip_ntohs(udphdr->src)));

  pcb = NULL;
  prev = NULL;
  uncon_pcb = NULL;
  
  /* Iterate through the UDP pcb list for a matching pcb.
   * 'Perfect match' pcbs (connected to the remote port & ip address) are
   * preferred. If no perfect match is found, the first unconnected pcb that
   * matches the local port and ip address gets the datagram. */
  /* 分别遍历系统内每个 udp 协议控制块结构，尝试找到一个和当前接收的 udp 数据包的
   * IP 地址信息和 udp 端口信息匹配的 udp 协议控制块结构，优先使用匹配并建立连接的
   * 的 udp 协议控制块结构，如果没找到匹配并建立连接的 udp 协议控制块，则使用匹配
   * 度最高但是“未”建立连接的 udp 协议控制块 */
  for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
  	
    /* print the PCB local and remote address */
    LWIP_DEBUGF(UDP_DEBUG, ("pcb ("));
    ip_addr_debug_print_val(UDP_DEBUG, pcb->local_ip);
    LWIP_DEBUGF(UDP_DEBUG, (", %"U16_F") <-- (", pcb->local_port));
    ip_addr_debug_print_val(UDP_DEBUG, pcb->remote_ip);
    LWIP_DEBUGF(UDP_DEBUG, (", %"U16_F")\n", pcb->remote_port));

    /* compare PCB local addr+port to UDP destination addr+port */
	/* 比较当前接收到的 udp 数据包的“目的”端口信息和“目的”地址信息和当前遍历的 udp 协议控制块
	 * 对应的“本地”端口信息和“本地”地址信息是否匹配，如果匹配，则进行下一步处理 */
    if ((pcb->local_port == dest) &&
        (udp_input_local_match(pcb, inp, broadcast) != 0)) {

	  /* 记录当前系统内处于“未连接”状态的 udp 协议控制块中“匹配度”最高的 udp 协议控制块 */
      if ((pcb->flags & UDP_FLAGS_CONNECTED) == 0) {
        if (uncon_pcb == NULL) {
          /* the first unconnected matching PCB */
          uncon_pcb = pcb;
		  
#if LWIP_IPV4
        } else if (broadcast && ip4_current_dest_addr()->addr == IPADDR_BROADCAST) {
          /* global broadcast address (only valid for IPv4; match was checked before) */
          if (!IP_IS_V4_VAL(uncon_pcb->local_ip) || !ip4_addr_cmp(ip_2_ip4(&uncon_pcb->local_ip), netif_ip4_addr(inp))) {
            /* uncon_pcb does not match the input netif, check this pcb */
            if (IP_IS_V4_VAL(pcb->local_ip) && ip4_addr_cmp(ip_2_ip4(&pcb->local_ip), netif_ip4_addr(inp))) {
              /* better match */
              uncon_pcb = pcb;
            }
          }
#endif /* LWIP_IPV4 */

        }
		
#if SO_REUSE
        else if (!ip_addr_isany(&pcb->local_ip)) {
          /* prefer specific IPs over catch-all */
          uncon_pcb = pcb;
        }
#endif /* SO_REUSE */

      }

      /* compare PCB remote addr+port to UDP source addr+port */
	  /* 比较当前接收到的 udp 数据包的“源”端口信息和“源”地址信息和当前遍历的 udp 协议控制块
	   * 对应的“对端”端口信息和“对端”地址信息是否匹配，如果仍然匹配，则表示当前接收到的 udp
	   * 数据包是发送给当前遍历的 udp 协议控制块的 */
      if ((pcb->remote_port == src) &&
          (ip_addr_isany_val(pcb->remote_ip) ||
           ip_addr_cmp(&pcb->remote_ip, ip_current_src_addr()))) {
        /* the first fully matching PCB */
        if (prev != NULL) {
          /* move the pcb to the front of udp_pcbs so that is
             found faster next time */
          /* 如果当前接收到的 udp         数据包的目的       udp 协议控制块不在全局 udp 协议控制块链表头部位置
		   * 为了提高下次查找这个 udp 协议控制块的效率，把这个 udp 协议控制块移动到全局 udp 协议
		   * 控制块的链表头部位置 */
          prev->next = pcb->next;
          pcb->next = udp_pcbs;
          udp_pcbs = pcb;
        } else {
          UDP_STATS_INC(udp.cachehit);
        }

		/* 找到目的 udp 协议控制块后，直接退出当前 for 循环，停止继续查找 */
        break;
      }
    }

    prev = pcb;
  }
  
  /* no fully matching pcb found? then look for an unconnected pcb */
  /* 如果没找到完全匹配的 udp 协议控制块，则尝试使用“匹配度”最高的处于“未连接”状态的 udp 协议控制块 */
  if (pcb == NULL) {
    pcb = uncon_pcb;
  }

  /* Check checksum if this is a match or if it was directed at us. */
  /* 判断当前接收到的 udp 数据包是否是发送给接收到这个数据包的网路接口的 */
  if (pcb != NULL) {
    for_us = 1;
  } else {
  
#if LWIP_IPV6
    if (ip_current_is_v6()) {
      for_us = netif_get_ip6_addr_match(inp, ip6_current_dest_addr()) >= 0;
    }
#endif /* LWIP_IPV6 */

#if LWIP_IPV4
    if (!ip_current_is_v6()) {
      for_us = ip4_addr_cmp(netif_ip4_addr(inp), ip4_current_dest_addr());
    }
#endif /* LWIP_IPV4 */
  }

  /* 表示当前接收到的 udp 数据包是发送给接收到这个数据包的网路接口的 */
  if (for_us) {
  	
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_input: calculating checksum\n"));


/* 校验接收到的 udp 数据包的校验和字段值是否合法 */
#if CHECKSUM_CHECK_UDP
    IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_UDP) {
    
#if LWIP_UDPLITE
      /* 处理接收到的 udp-lite 协议数据包的校验和 */
      if (ip_current_header_proto() == IP_PROTO_UDPLITE) {
        /* Do the UDP Lite checksum */
        u16_t chklen = lwip_ntohs(udphdr->len);
        if (chklen < sizeof(struct udp_hdr)) {
          if (chklen == 0) {
            /* For UDP-Lite, checksum length of 0 means checksum
               over the complete packet (See RFC 3828 chap. 3.1) */
            chklen = p->tot_len;
          } else {
            /* At least the UDP-Lite header must be covered by the
               checksum! (Again, see RFC 3828 chap. 3.1) */
            goto chkerr;
          }
        }
		
        if (ip_chksum_pseudo_partial(p, IP_PROTO_UDPLITE,
                                     p->tot_len, chklen,
                                     ip_current_src_addr(), ip_current_dest_addr()) != 0) {
          goto chkerr;
        }
      } else
#endif /* LWIP_UDPLITE */

      {
        if (udphdr->chksum != 0) {
          if (ip_chksum_pseudo(p, IP_PROTO_UDP, p->tot_len,
                               ip_current_src_addr(),
                               ip_current_dest_addr()) != 0) {
            goto chkerr;
          }
        }
      }
    }
#endif /* CHECKSUM_CHECK_UDP */


    if (pbuf_remove_header(p, UDP_HLEN)) {
      /* Can we cope with this failing? Just assert for now */
      LWIP_ASSERT("pbuf_remove_header failed\n", 0);
      UDP_STATS_INC(udp.drop);
      MIB2_STATS_INC(mib2.udpinerrors);
      pbuf_free(p);
      goto end;
    }

    /* 如果在当前系统中找到了和接收到的 udp 数据包匹配的 udp 协议控制块结构
	 * 则通过匹配的 udp 协议控制块处理接收到的 udp 数据包 */
    if (pcb != NULL) {
      MIB2_STATS_INC(mib2.udpindatagrams);

/* 处理 SO_REUSEADDR socket 选项相关功能逻辑 */
#if SO_REUSE && SO_REUSE_RXTOALL
      /* 如果第一个匹配的 udp 协议控制块中设置了 SOF_REUSEADDR socket 选项并且当前接收到的
       * 数据包是否是多播数据包或者广播数据包，则把接收到的多播数据包或者广播数据包“克隆”并
       * “传输”到每一个地址匹配的协议控制块中 */
      if (ip_get_option(pcb, SOF_REUSEADDR) &&
          (broadcast || ip_addr_ismulticast(ip_current_dest_addr()))) {
        /* pass broadcast- or multicast packets to all multicast pcbs
           if SOF_REUSEADDR is set on the first match */
        struct udp_pcb *mpcb;
        for (mpcb = udp_pcbs; mpcb != NULL; mpcb = mpcb->next) {
          if (mpcb != pcb) {
            /* compare PCB local addr+port to UDP destination addr+port */
		    
            if ((mpcb->local_port == dest) &&
                (udp_input_local_match(mpcb, inp, broadcast) != 0)) {
              /* pass a copy of the packet to all local matches */
		      /* 把接收到的多播数据包或者广播数据包“克隆”并“传输”到每一个地址匹配的协议控制块中 */
              if (mpcb->recv != NULL) {
                struct pbuf *q;
                q = pbuf_clone(PBUF_RAW, PBUF_POOL, p);
                if (q != NULL) {
                  mpcb->recv(mpcb->recv_arg, mpcb, q, ip_current_src_addr(), src);
                }
              }
            }
          }
        }
      }
#endif /* SO_REUSE && SO_REUSE_RXTOALL */

      /* callback */
      /* 通过匹配的 udp 协议控制块中的接收数据回调函数处理当前接收到的 udp 数据包
       * 需要注意的是，我们需要在这个接收回调函数中释放接收的数据包 pbuf 结构 */
      if (pcb->recv != NULL) {
        /* now the recv function is responsible for freeing p */
        pcb->recv(pcb->recv_arg, pcb, p, ip_current_src_addr(), src);
      } else {
        /* no recv function registered? then we have to free the pbuf! */
        pbuf_free(p);
        goto end;
      }
    } else {
    
      LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_input: not for us.\n"));

#if LWIP_ICMP || LWIP_ICMP6
      /* No match was found, send ICMP destination port unreachable unless
         destination address was broadcast/multicast. */
      /* 如果当前系统中没有找到匹配的 udp 协议控制块结构，则发送一个目的端口不可达的 icmp 数据包
       * 到发送当前接收到的 udp 数据包的以太网设备处 */
      if (!broadcast && !ip_addr_ismulticast(ip_current_dest_addr())) {
        /* move payload pointer back to ip header */
        pbuf_header_force(p, (s16_t)(ip_current_header_tot_len() + UDP_HLEN));
        icmp_port_unreach(ip_current_is_v6(), p);
      }
#endif /* LWIP_ICMP || LWIP_ICMP6 */

      UDP_STATS_INC(udp.proterr);
      UDP_STATS_INC(udp.drop);
      MIB2_STATS_INC(mib2.udpnoports);
      pbuf_free(p);
    }
  } else {
    pbuf_free(p);
  }
  
end:
  PERF_STOP("udp_input");
  return;
  
#if CHECKSUM_CHECK_UDP
chkerr:
  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
              ("udp_input: UDP (or UDP Lite) datagram discarded due to failing checksum\n"));
  UDP_STATS_INC(udp.chkerr);
  UDP_STATS_INC(udp.drop);
  MIB2_STATS_INC(mib2.udpinerrors);
  pbuf_free(p);
  PERF_STOP("udp_input");
#endif /* CHECKSUM_CHECK_UDP */
}

/**
 * @ingroup udp_raw
 * Sends the pbuf p using UDP. The pbuf is not deallocated.
 *
 *
 * @param pcb UDP PCB used to send the data.
 * @param p chain of pbuf's to be sent.
 *
 * The datagram will be sent to the current remote_ip & remote_port
 * stored in pcb. If the pcb is not bound to a port, it will
 * automatically be bound to a random port.
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occurred.
 * - ERR_MEM. Out of memory.
 * - ERR_RTE. Could not find route to destination address.
 * - ERR_VAL. No PCB or PCB is dual-stack
 * - More errors could be returned by lower protocol layers.
 *
 * @see udp_disconnect() udp_sendto()
 */
/*********************************************************************************************************
** 函数名称: udp_send
** 功能描述: 通过指定的 udp 协议控制块发送指定的 udp 数据包
** 输	 入: pcb - 用来发送 udp 数据包的 udp 协议控制块
**         : p - 要发送的 udp 数据包
** 输	 出: err_t - 发送状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
udp_send(struct udp_pcb *pcb, struct pbuf *p)
{
  LWIP_ERROR("udp_send: invalid pcb", pcb != NULL, return ERR_ARG);
  LWIP_ERROR("udp_send: invalid pbuf", p != NULL, return ERR_ARG);

  if (IP_IS_ANY_TYPE_VAL(pcb->remote_ip)) {
    return ERR_VAL;
  }

  /* send to the packet using remote ip and port stored in the pcb */
  return udp_sendto(pcb, p, &pcb->remote_ip, pcb->remote_port);
}

#if LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP
/** @ingroup udp_raw
 * Same as udp_send() but with checksum
 */ 
/*********************************************************************************************************
** 函数名称: udp_send_chksum
** 功能描述: 通过指定的 udp 协议控制块发送指定的、携带有应用层数据校验和的 udp 数据包
** 输	 入: pcb - 用来发送 udp 数据包的 udp 协议控制块
**		   : p - 要发送的 udp 数据包
**		   : have_chksum - 表示是否已经计算了应用层数据的校验和
**		   : chksum - 表示应用层数据的校验和（have_chksum = true）
** 输	 出: err_t - 发送状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
udp_send_chksum(struct udp_pcb *pcb, struct pbuf *p,
                u8_t have_chksum, u16_t chksum)
{
  LWIP_ERROR("udp_send_chksum: invalid pcb", pcb != NULL, return ERR_ARG);
  LWIP_ERROR("udp_send_chksum: invalid pbuf", p != NULL, return ERR_ARG);

  if (IP_IS_ANY_TYPE_VAL(pcb->remote_ip)) {
    return ERR_VAL;
  }

  /* send to the packet using remote ip and port stored in the pcb */
  return udp_sendto_chksum(pcb, p, &pcb->remote_ip, pcb->remote_port,
                           have_chksum, chksum);
}
#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */

/**
 * @ingroup udp_raw
 * Send data to a specified address using UDP.
 *
 * @param pcb UDP PCB used to send the data.
 * @param p chain of pbuf's to be sent.
 * @param dst_ip Destination IP address.
 * @param dst_port Destination UDP port.
 *
 * dst_ip & dst_port are expected to be in the same byte order as in the pcb.
 *
 * If the PCB already has a remote address association, it will
 * be restored after the data is sent.
 *
 * @return lwIP error code (@see udp_send for possible error codes)
 *
 * @see udp_disconnect() udp_send()
 */ 
/*********************************************************************************************************
** 函数名称: udp_sendto
** 功能描述: 根据指定的 udp 协议控制块和目的 IP（IPv4 or IPv6）地址从当前系统内找到一个合适的网络接口
**         : 然后通过找到的网络接口把指定的 udp 数据包发送出去
** 输	 入: pcb - 用来发送 udp 数据包的 udp 协议控制块
**		   : p - 要发送的 udp 数据包
**		   : dst_ip - 要发送的 udp 数据包的目的 IP（IPv4 or IPv6） 地址
**		   : dst_port - 要发送的 udp 数据包目的端口号
** 输	 出: err_t - 发送状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
udp_sendto(struct udp_pcb *pcb, struct pbuf *p,
           const ip_addr_t *dst_ip, u16_t dst_port)
{
#if LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP
  return udp_sendto_chksum(pcb, p, dst_ip, dst_port, 0, 0);
}

/** @ingroup udp_raw
 * Same as udp_sendto(), but with checksum */
/*********************************************************************************************************
** 函数名称: udp_sendto_chksum
** 功能描述: 根据指定的 udp 协议控制块和目的 IP（IPv4 or IPv6）地址从当前系统内找到一个合适的网络接口
**         : 然后通过找到的网络接口把指定的、携带有应用层数据校验和的 udp 数据包发送出去
** 输	 入: pcb - 用来发送 udp 数据包的 udp 协议控制块
**		   : p - 要发送的 udp 数据包
**		   : dst_ip - 要发送的 udp 数据包的目的 IP（IPv4 or IPv6） 地址
**		   : dst_port - 要发送的 udp 数据包目的端口号
**		   : have_chksum - 表示是否已经计算了应用层数据的校验和
**		   : chksum - 表示应用层数据的校验和（have_chksum = true）
** 输	 出: err_t - 发送状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
udp_sendto_chksum(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip,
                  u16_t dst_port, u8_t have_chksum, u16_t chksum)
{
#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */
  struct netif *netif;

  LWIP_ERROR("udp_sendto: invalid pcb", pcb != NULL, return ERR_ARG);
  LWIP_ERROR("udp_sendto: invalid pbuf", p != NULL, return ERR_ARG);
  LWIP_ERROR("udp_sendto: invalid dst_ip", dst_ip != NULL, return ERR_ARG);

  /* 判断指定的 IP（IPv4 or IPv6）地址类型和指定的协议控制块的 local_ip 地址类型是否匹配 */
  if (!IP_ADDR_PCB_VERSION_MATCH(pcb, dst_ip)) {
    return ERR_VAL;
  }

  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_send\n"));

  /* 根据当前待发送的 udp 数据包的目的 IP（IPv4 or IPv6）地址从当前系统
   * 内找到一个合适的网络接口中用来发送待发送的 udp 数据包 */
  if (pcb->netif_idx != NETIF_NO_INDEX) {
    netif = netif_get_by_index(pcb->netif_idx);
  } else {


  
#if LWIP_MULTICAST_TX_OPTIONS
    netif = NULL;
    if (ip_addr_ismulticast(dst_ip)) {
      /* For IPv6, the interface to use for packets with a multicast destination
       * is specified using an interface index. The same approach may be used for
       * IPv4 as well, in which case it overrides the IPv4 multicast override
       * address below. Here we have to look up the netif by going through the
       * list, but by doing so we skip a route lookup. If the interface index has
       * gone stale, we fall through and do the regular route lookup after all. */
      if (pcb->mcast_ifindex != NETIF_NO_INDEX) {
        netif = netif_get_by_index(pcb->mcast_ifindex);
      }

	  
#if LWIP_IPV4
      else
	  	
#if LWIP_IPV6
        if (IP_IS_V4(dst_ip))
#endif /* LWIP_IPV6 */

        {
          /* IPv4 does not use source-based routing by default, so we use an
             administratively selected interface for multicast by default.
             However, this can be overridden by setting an interface address
             in pcb->mcast_ip4 that is used for routing. If this routing lookup
             fails, we try regular routing as though no override was set. */
          if (!ip4_addr_isany_val(pcb->mcast_ip4) &&
              !ip4_addr_cmp(&pcb->mcast_ip4, IP4_ADDR_BROADCAST)) {
            netif = ip4_route_src(ip_2_ip4(&pcb->local_ip), &pcb->mcast_ip4);
          }
        }
#endif /* LWIP_IPV4 */


    }

    if (netif == NULL)
#endif /* LWIP_MULTICAST_TX_OPTIONS */



    {
      /* find the outgoing network interface for this packet */
      netif = ip_route(&pcb->local_ip, dst_ip);
    }
  }

  /* no outgoing network interface could be found? */
  if (netif == NULL) {
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("udp_send: No route to "));
    ip_addr_debug_print(UDP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, dst_ip);
    LWIP_DEBUGF(UDP_DEBUG, ("\n"));
    UDP_STATS_INC(udp.rterr);
    return ERR_RTE;
  }

/* 通过找到的网络接口把待发送的 udp 数据包发送出去 */
#if LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP
  return udp_sendto_if_chksum(pcb, p, dst_ip, dst_port, netif, have_chksum, chksum);
#else /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */
  return udp_sendto_if(pcb, p, dst_ip, dst_port, netif);
#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */
}

/**
 * @ingroup udp_raw
 * Send data to a specified address using UDP.
 * The netif used for sending can be specified.
 *
 * This function exists mainly for DHCP, to be able to send UDP packets
 * on a netif that is still down.
 *
 * @param pcb UDP PCB used to send the data.
 * @param p chain of pbuf's to be sent.
 * @param dst_ip Destination IP address.
 * @param dst_port Destination UDP port.
 * @param netif the netif used for sending.
 *
 * dst_ip & dst_port are expected to be in the same byte order as in the pcb.
 *
 * @return lwIP error code (@see udp_send for possible error codes)
 *
 * @see udp_disconnect() udp_send()
 */
/*********************************************************************************************************
** 函数名称: udp_sendto_if
** 功能描述: 根据当前 udp 协议控制块的 local_ip 地址校验当前 udp 数据包的目的 IP（IPv4 or IPv6）
**         : 地址是否合法，如果合法，则通过 udp_sendto_if_src 函数把指定的 udp 数据包发送出去
** 输	 入: pcb - 用来发送 udp 数据包的 udp 协议控制块
**		   : p - 要发送的 udp 数据包
**		   : dst_ip - 要发送的 udp 数据包的目的 IP（IPv4 or IPv6） 地址
**		   : dst_port - 要发送的 udp 数据包目的端口号
**         : netif - 用来发送 udp 数据包的网络接口指针
** 输	 出: err_t - 发送状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
udp_sendto_if(struct udp_pcb *pcb, struct pbuf *p,
              const ip_addr_t *dst_ip, u16_t dst_port, struct netif *netif)
{
#if LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP
  return udp_sendto_if_chksum(pcb, p, dst_ip, dst_port, netif, 0, 0);
}

/** Same as udp_sendto_if(), but with checksum */
/*********************************************************************************************************
** 函数名称: udp_sendto_if_chksum
** 功能描述: 根据当前 udp 协议控制块的 local_ip 地址校验当前 udp 数据包的目的 IP（IPv4 or IPv6）
**         : 地址是否合法，如果合法，则通过 udp_sendto_if_src 函数把指定的、携带有应用层数据校验和
**         : 的 udp 数据包发送出去
** 输	 入: pcb - 用来发送 udp 数据包的 udp 协议控制块
**		   : p - 要发送的 udp 数据包
**		   : dst_ip - 要发送的 udp 数据包的目的 IP（IPv4 or IPv6） 地址
**		   : dst_port - 要发送的 udp 数据包目的端口号
**         : netif - 用来发送 udp 数据包的网络接口指针
**		   : have_chksum - 表示是否已经计算了应用层数据的校验和
**		   : chksum - 表示应用层数据的校验和（have_chksum = true）
** 输	 出: err_t - 发送状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
udp_sendto_if_chksum(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip,
                     u16_t dst_port, struct netif *netif, u8_t have_chksum,
                     u16_t chksum)
{
#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */
  const ip_addr_t *src_ip;

  LWIP_ERROR("udp_sendto_if: invalid pcb", pcb != NULL, return ERR_ARG);
  LWIP_ERROR("udp_sendto_if: invalid pbuf", p != NULL, return ERR_ARG);
  LWIP_ERROR("udp_sendto_if: invalid dst_ip", dst_ip != NULL, return ERR_ARG);
  LWIP_ERROR("udp_sendto_if: invalid netif", netif != NULL, return ERR_ARG);

  /* 判断指定的 IP（IPv4 or IPv6）地址类型和指定的协议控制块的 local_ip 地址类型是否匹配 */
  if (!IP_ADDR_PCB_VERSION_MATCH(pcb, dst_ip)) {
    return ERR_VAL;
  }

  /* PCB local address is IP_ANY_ADDR or multicast? */
  /* 根据当前 udp 数据包的目的 IP（IPv4 or IPv6）地址校验当前 udp 协议控制块的 local_ip 地址是否合法 */
#if LWIP_IPV6
  /* 判断指定的 IP 地址是否是 IPv6 类型 */
  if (IP_IS_V6(dst_ip)) {
    if (ip6_addr_isany(ip_2_ip6(&pcb->local_ip)) ||
        ip6_addr_ismulticast(ip_2_ip6(&pcb->local_ip))) {
      src_ip = ip6_select_source_address(netif, ip_2_ip6(dst_ip));
      if (src_ip == NULL) {
        /* No suitable source address was found. */
        return ERR_RTE;
      }
    } else {
      /* use UDP PCB local IPv6 address as source address, if still valid. */
      if (netif_get_ip6_addr_match(netif, ip_2_ip6(&pcb->local_ip)) < 0) {
        /* Address isn't valid anymore. */
        return ERR_RTE;
      }
      src_ip = &pcb->local_ip;
    }
  }
#endif /* LWIP_IPV6 */

#if LWIP_IPV4 && LWIP_IPV6
  else
#endif /* LWIP_IPV4 && LWIP_IPV6 */

#if LWIP_IPV4
    if (ip4_addr_isany(ip_2_ip4(&pcb->local_ip)) ||
        ip4_addr_ismulticast(ip_2_ip4(&pcb->local_ip))) {
      /* if the local_ip is any or multicast
       * use the outgoing network interface IP address as source address */
      src_ip = netif_ip_addr4(netif);
    } else {
      /* check if UDP PCB local IP address is correct
       * this could be an old address if netif->ip_addr has changed */
      if (!ip4_addr_cmp(ip_2_ip4(&(pcb->local_ip)), netif_ip4_addr(netif))) {
        /* local_ip doesn't match, drop the packet */
        return ERR_RTE;
      }
      /* use UDP PCB local IP address as source address */
      src_ip = &pcb->local_ip;
    }
#endif /* LWIP_IPV4 */

#if LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP
  return udp_sendto_if_src_chksum(pcb, p, dst_ip, dst_port, netif, have_chksum, chksum, src_ip);
#else /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */
  return udp_sendto_if_src(pcb, p, dst_ip, dst_port, netif, src_ip);
#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */
}

/** @ingroup udp_raw
 * Same as @ref udp_sendto_if, but with source address */
/*********************************************************************************************************
** 函数名称: udp_sendto_if_src_chksum
** 功能描述: 根据函数参数指定的协议数据，为待发送的 udp 数据包构建一个 udp 协议头，然后通过调用 IP 协议层
**         : 接口 ip_output_if_src 把把指定的 udp 数据包发送出去
** 输	 入: pcb - 用来发送 udp 数据包的 udp 协议控制块
**		   : p - 要发送的 udp 数据包
**		   : dst_ip - 要发送的 udp 数据包的目的 IP（IPv4 or IPv6） 地址
**		   : dst_port - 要发送的 udp 数据包目的端口号
**         : netif - 用来发送 udp 数据包的网络接口指针
**         : src_ip - 要发送的 udp 数据包的“源” IP（IPv4 or IPv6） 地址
** 输	 出: err_t - 发送状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
udp_sendto_if_src(struct udp_pcb *pcb, struct pbuf *p,
                  const ip_addr_t *dst_ip, u16_t dst_port, struct netif *netif, const ip_addr_t *src_ip)
{
#if LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP
  return udp_sendto_if_src_chksum(pcb, p, dst_ip, dst_port, netif, 0, 0, src_ip);
}

/** Same as udp_sendto_if_src(), but with checksum */
/*********************************************************************************************************
** 函数名称: udp_sendto_if_src_chksum
** 功能描述: 根据函数参数指定的协议数据，为待发送的 udp 数据包构建一个 udp 协议头，然后通过调用 IP 协议层
**         : 接口 ip_output_if_src 把把指定的、携带有应用层数据校验和的 udp 数据包发送出去，具体操作如下：
**         : 1. 分别校验待发送的 udp 数据包的“目的” IP 和待发送的 udp 数据包的“源” IP（IPv4 or IPv6）
**         :    地址类型和指定的协议控制块的 local_ip 地址类型是否匹配
**         : 2. 如果待发送的是 udp 广播数据包，则校验当前 udp 协议控制块的 SOF_BROADCAST socket 选项
**         : 3. 如果指定的 udp 协议控制块还没有绑定“本地”端口号，则执行端口绑定操作
**         : 4. 校验待发送的 udp 数据包长度是否合法
**         : 5. 为待发送的 udp 数据包添加协议头空间，如果当前 udp 数据包 pbuf 没预先给 udp 协议头预留空间
**         :    则需要申请一个新的 udp 协议头的 pbuf 结构，然后链接到待发送的 udp 数据包的 pbuf 链表头部
**         :    位置，用来存储 udp 协议头数据
**         : 6. 根据函数参数设置待发送的 udp 数据包的协议头数据内容
**         : 7. 计算待发送的 udp 数据包的校验和，兼容了 udp-lite 工作模式
**         : 8. 根据当前协议栈是否启用 IP_MULTICAST_TTL 选项初始化待发送的 udp 数据包的 ttl 值
**         : 9. 把待发送的 udp 数据包通过下层 IP 协议模块中的 ip_output_if_src 接口发送出去
** 输	 入: pcb - 用来发送 udp 数据包的 udp 协议控制块
**		   : p - 要发送的 udp 数据包
**		   : dst_ip - 要发送的 udp 数据包的目的 IP（IPv4 or IPv6） 地址
**		   : dst_port - 要发送的 udp 数据包目的端口号
**         : netif - 用来发送 udp 数据包的网络接口指针
**		   : have_chksum - 表示是否已经计算了应用层数据的校验和
**		   : chksum - 表示应用层数据的校验和（have_chksum = true）
**         : src_ip - 要发送的 udp 数据包的“源” IP（IPv4 or IPv6） 地址
** 输	 出: err_t - 发送状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
udp_sendto_if_src_chksum(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip,
                         u16_t dst_port, struct netif *netif, u8_t have_chksum,
                         u16_t chksum, const ip_addr_t *src_ip)
{
#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */
  struct udp_hdr *udphdr;
  err_t err;
  struct pbuf *q; /* q will be sent down the stack */
  u8_t ip_proto;
  u8_t ttl;

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("udp_sendto_if_src: invalid pcb", pcb != NULL, return ERR_ARG);
  LWIP_ERROR("udp_sendto_if_src: invalid pbuf", p != NULL, return ERR_ARG);
  LWIP_ERROR("udp_sendto_if_src: invalid dst_ip", dst_ip != NULL, return ERR_ARG);
  LWIP_ERROR("udp_sendto_if_src: invalid src_ip", src_ip != NULL, return ERR_ARG);
  LWIP_ERROR("udp_sendto_if_src: invalid netif", netif != NULL, return ERR_ARG);

  /* 分别校验待发送的 udp 数据包的“目的” IP 和待发送的 udp 数据包的“源” IP（IPv4 or IPv6）
   * 地址类型和指定的协议控制块的 local_ip 地址类型是否匹配 */
  if (!IP_ADDR_PCB_VERSION_MATCH(pcb, src_ip) ||
      !IP_ADDR_PCB_VERSION_MATCH(pcb, dst_ip)) {
    return ERR_VAL;
  }


/* 如果待发送的是 udp 广播数据包，则校验当前 udp 协议控制块的 SOF_BROADCAST socket 选项 */
#if LWIP_IPV4 && IP_SOF_BROADCAST
  /* broadcast filter? */
  if (!ip_get_option(pcb, SOF_BROADCAST) &&
  	
#if LWIP_IPV6
      IP_IS_V4(dst_ip) &&
#endif /* LWIP_IPV6 */

      ip_addr_isbroadcast(dst_ip, netif)) {
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                ("udp_sendto_if: SOF_BROADCAST not enabled on pcb %p\n", (void *)pcb));
    return ERR_VAL;
  }
#endif /* LWIP_IPV4 && IP_SOF_BROADCAST */


  /* if the PCB is not yet bound to a port, bind it here */
  /* 如果指定的 udp 协议控制块还没有绑定“本地”端口号，则执行端口绑定操作 */
  if (pcb->local_port == 0) {
    LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_send: not yet bound to a port, binding now\n"));
    err = udp_bind(pcb, &pcb->local_ip, pcb->local_port);
    if (err != ERR_OK) {
      LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("udp_send: forced port bind failed\n"));
      return err;
    }
  }

  /* packet too large to add a UDP header without causing an overflow? */
  /* 校验待发送的 udp 数据包长度是否合法 */
  if ((u16_t)(p->tot_len + UDP_HLEN) < p->tot_len) {
    return ERR_MEM;
  }
  
  /* not enough space to add an UDP header to first pbuf in given p chain? */
  /* 为待发送的 udp 数据包添加协议头空间，如果当前 udp 数据包 pbuf 没预先给 udp 协议头预留空间
   * 则需要申请一个新的 udp 协议头的 pbuf 结构，然后链接到待发送的 udp 数据包的 pbuf 链表头部
   * 位置，用来存储 udp 协议头数据 */
  if (pbuf_add_header(p, UDP_HLEN)) {
    /* allocate header in a separate new pbuf */
    q = pbuf_alloc(PBUF_IP, UDP_HLEN, PBUF_RAM);
    /* new header pbuf could not be allocated? */
    if (q == NULL) {
      LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("udp_send: could not allocate header\n"));
      return ERR_MEM;
    }
	
    if (p->tot_len != 0) {
      /* chain header q in front of given pbuf p (only if p contains data) */
      pbuf_chain(q, p);
    }
	
    /* first pbuf q points to header pbuf */
    LWIP_DEBUGF(UDP_DEBUG,
                ("udp_send: added header pbuf %p before given pbuf %p\n", (void *)q, (void *)p));
  } else {
    /* adding space for header within p succeeded */
    /* first pbuf q equals given pbuf */
    q = p;
    LWIP_DEBUGF(UDP_DEBUG, ("udp_send: added header in given pbuf %p\n", (void *)p));
  }
  
  LWIP_ASSERT("check that first pbuf can hold struct udp_hdr",
              (q->len >= sizeof(struct udp_hdr)));
  
  /* q now represents the packet to be sent */
  /* 根据函数参数设置待发送的 udp 数据包的协议头数据内容 */
  udphdr = (struct udp_hdr *)q->payload;
  udphdr->src = lwip_htons(pcb->local_port);
  udphdr->dest = lwip_htons(dst_port);
  /* in UDP, 0 checksum means 'no checksum' */
  udphdr->chksum = 0x0000;

  /* Multicast Loop? */
#if LWIP_MULTICAST_TX_OPTIONS
  if (((pcb->flags & UDP_FLAGS_MULTICAST_LOOP) != 0) && ip_addr_ismulticast(dst_ip)) {
    q->flags |= PBUF_FLAG_MCASTLOOP;
  }
#endif /* LWIP_MULTICAST_TX_OPTIONS */

  LWIP_DEBUGF(UDP_DEBUG, ("udp_send: sending datagram of length %"U16_F"\n", q->tot_len));

/* 计算待发送的 udp 数据包的校验和，兼容了 udp-lite 工作模式 */
#if LWIP_UDPLITE
  /* UDP Lite protocol? */
  if (pcb->flags & UDP_FLAGS_UDPLITE) {
    u16_t chklen, chklen_hdr;
	
    LWIP_DEBUGF(UDP_DEBUG, ("udp_send: UDP LITE packet length %"U16_F"\n", q->tot_len));
  
    /* set UDP message length in UDP header */
    chklen_hdr = chklen = pcb->chksum_len_tx;
    if ((chklen < sizeof(struct udp_hdr)) || (chklen > q->tot_len)) {
      if (chklen != 0) {
        LWIP_DEBUGF(UDP_DEBUG, ("udp_send: UDP LITE pcb->chksum_len is illegal: %"U16_F"\n", chklen));
      }
      /* For UDP-Lite, checksum length of 0 means checksum
         over the complete packet. (See RFC 3828 chap. 3.1)
         At least the UDP-Lite header must be covered by the
         checksum, therefore, if chksum_len has an illegal
         value, we generate the checksum over the complete
         packet to be safe. */
      chklen_hdr = 0;
      chklen = q->tot_len;
    }
	
    udphdr->len = lwip_htons(chklen_hdr);

	
    /* calculate checksum */
#if CHECKSUM_GEN_UDP
    IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_UDP) {

/* 如果应用层数据的校验和已经计算完了，那么我们在 udp 协议层只需要计算
 * udp 协议头的校验和，然后和应用层数据校验和累加在一起就是整个 udp 数
 * 据包的校验和了 */
#if LWIP_CHECKSUM_ON_COPY
      if (have_chksum) {
        chklen = UDP_HLEN;
      }
#endif /* LWIP_CHECKSUM_ON_COPY */

      udphdr->chksum = ip_chksum_pseudo_partial(q, IP_PROTO_UDPLITE,
                       q->tot_len, chklen, src_ip, dst_ip);

/* 如果应用层数据的校验和已经计算完了，那么我们在 udp 协议层只需要计算
 * udp 协议头的校验和，然后和应用层数据校验和累加在一起就是整个 udp 数
 * 据包的校验和了 */
#if LWIP_CHECKSUM_ON_COPY
      if (have_chksum) {
        u32_t acc;
        acc = udphdr->chksum + (u16_t)~(chksum);
        udphdr->chksum = FOLD_U32T(acc);
      }
#endif /* LWIP_CHECKSUM_ON_COPY */

      /* chksum zero must become 0xffff, as zero means 'no checksum' */
      if (udphdr->chksum == 0x0000) {
        udphdr->chksum = 0xffff;
      }
    }
#endif /* CHECKSUM_GEN_UDP */


    ip_proto = IP_PROTO_UDPLITE;
  } else
#endif /* LWIP_UDPLITE */
  {      /* UDP */
  
    LWIP_DEBUGF(UDP_DEBUG, ("udp_send: UDP packet length %"U16_F"\n", q->tot_len));
	
    udphdr->len = lwip_htons(q->tot_len);

	
    /* calculate checksum */
#if CHECKSUM_GEN_UDP
    IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_UDP) {
      /* Checksum is mandatory over IPv6. */
      if (IP_IS_V6(dst_ip) || (pcb->flags & UDP_FLAGS_NOCHKSUM) == 0) {
        u16_t udpchksum;
		
#if LWIP_CHECKSUM_ON_COPY
        if (have_chksum) {
          u32_t acc;
          udpchksum = ip_chksum_pseudo_partial(q, IP_PROTO_UDP,
                                               q->tot_len, UDP_HLEN, src_ip, dst_ip);
          acc = udpchksum + (u16_t)~(chksum);
          udpchksum = FOLD_U32T(acc);
        } else
#endif /* LWIP_CHECKSUM_ON_COPY */

        {
          udpchksum = ip_chksum_pseudo(q, IP_PROTO_UDP, q->tot_len,
                                       src_ip, dst_ip);
        }

        /* chksum zero must become 0xffff, as zero means 'no checksum' */
        if (udpchksum == 0x0000) {
          udpchksum = 0xffff;
        }
        udphdr->chksum = udpchksum;
      }
    }
#endif /* CHECKSUM_GEN_UDP */


    ip_proto = IP_PROTO_UDP;
  }

  /* Determine TTL to use */
/* 根据当前协议栈是否启用 IP_MULTICAST_TTL 选项初始化待发送的 udp 数据包的 ttl 值 */
#if LWIP_MULTICAST_TX_OPTIONS
  ttl = (ip_addr_ismulticast(dst_ip) ? udp_get_multicast_ttl(pcb) : pcb->ttl);
#else /* LWIP_MULTICAST_TX_OPTIONS */
  ttl = pcb->ttl;
#endif /* LWIP_MULTICAST_TX_OPTIONS */

  LWIP_DEBUGF(UDP_DEBUG, ("udp_send: UDP checksum 0x%04"X16_F"\n", udphdr->chksum));
  LWIP_DEBUGF(UDP_DEBUG, ("udp_send: ip_output_if (,,,,0x%02"X16_F",)\n", (u16_t)ip_proto));
  
  /* output to IP */
  /* 把待发送的 udp 数据包通过下层 IP 协议模块中的 ip_output_if_src 接口发送出去 */
  NETIF_SET_HINTS(netif, &(pcb->netif_hints));
  err = ip_output_if_src(q, src_ip, dst_ip, ttl, pcb->tos, ip_proto, netif);
  NETIF_RESET_HINTS(netif);

  /* @todo: must this be increased even if error occurred? */
  MIB2_STATS_INC(mib2.udpoutdatagrams);

  /* did we chain a separate header pbuf earlier? */
  if (q != p) {
    /* free the header pbuf */
    pbuf_free(q);
    q = NULL;
    /* p is still referenced by the caller, and will live on */
  }

  UDP_STATS_INC(udp.xmit);
  return err;
}

/**
 * @ingroup udp_raw
 * Bind an UDP PCB.
 * 
 * @param pcb UDP PCB to be bound with a local address ipaddr and port.
 * @param ipaddr local IP address to bind with. Use IP_ANY_TYPE to
 * bind to all local interfaces.
 * @param port local UDP port to bind with. Use 0 to automatically bind
 * to a random port between UDP_LOCAL_PORT_RANGE_START and
 * UDP_LOCAL_PORT_RANGE_END.
 *
 * ipaddr & port are expected to be in the same byte order as in the pcb.
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occurred.
 * - ERR_USE. The specified ipaddr and port are already bound to by
 * another UDP PCB.
 *
 * @see udp_disconnect()
 */
/*********************************************************************************************************
** 函数名称: udp_bind
** 功能描述: 把指定的 udp 协议控制块绑定到指定的“本地”网络接口和“本地”端口号上
** 输	 入: pcb - 需要绑定的 udp 协议控制块
**		   : ipaddr - 要绑定的“本地”网络接口 IP（IPv4 or IPv6）地址，IP_ANY_TYPE 表示本地所有网络接口
**		   : port - 要绑定的“本地”端口号，0 表示自动绑定到一个合法的随机端口号上
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
udp_bind(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{
  struct udp_pcb *ipcb;
  u8_t rebind;
  
#if LWIP_IPV6 && LWIP_IPV6_SCOPES
  ip_addr_t zoned_ipaddr;
#endif /* LWIP_IPV6 && LWIP_IPV6_SCOPES */

  LWIP_ASSERT_CORE_LOCKED();

/* 如果没有指定要邦定的网络接口 IP（IPv4 or IPv6）地址且当前协议栈支持 IPv4 协议
 * 则设置成 IP4_ADDR_ANY */
#if LWIP_IPV4
  /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
  if (ipaddr == NULL) {
    ipaddr = IP4_ADDR_ANY;
  }
#else /* LWIP_IPV4 */
  LWIP_ERROR("udp_bind: invalid ipaddr", ipaddr != NULL, return ERR_ARG);
#endif /* LWIP_IPV4 */

  LWIP_ERROR("udp_bind: invalid pcb", pcb != NULL, return ERR_ARG);

  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, ("udp_bind(ipaddr = "));
  ip_addr_debug_print(UDP_DEBUG | LWIP_DBG_TRACE, ipaddr);
  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE, (", port = %"U16_F")\n", port));

  rebind = 0;
  /* Check for double bind and rebind of the same pcb */
  /* 校验指定的 udp 协议控制块当前是否是重复绑定 */
  for (ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next) {
    /* is this UDP PCB already on active list? */
    if (pcb == ipcb) {
      rebind = 1;
      break;
    }
  }

#if LWIP_IPV6 && LWIP_IPV6_SCOPES
  /* If the given IP address should have a zone but doesn't, assign one now.
   * This is legacy support: scope-aware callers should always provide properly
   * zoned source addresses. Do the zone selection before the address-in-use
   * check below; as such we have to make a temporary copy of the address. */
  if (IP_IS_V6(ipaddr) && ip6_addr_lacks_zone(ip_2_ip6(ipaddr), IP6_UNKNOWN)) {
    ip_addr_copy(zoned_ipaddr, *ipaddr);
    ip6_addr_select_zone(ip_2_ip6(&zoned_ipaddr), ip_2_ip6(&zoned_ipaddr));
    ipaddr = &zoned_ipaddr;
  }
#endif /* LWIP_IPV6 && LWIP_IPV6_SCOPES */

  /* no port specified? */
  if (port == 0) {
    /* 如果没有指定要邦定的“本地”端口号，则从当前系统内申请一个随机的空闲端口号 */
    port = udp_new_port();
    if (port == 0) {
      /* no more ports available in local range */
      LWIP_DEBUGF(UDP_DEBUG, ("udp_bind: out of free UDP ports\n"));
      return ERR_USE;
    }
  } else {
    for (ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next) {
      if (pcb != ipcb) {
        /* By default, we don't allow to bind to a port that any other udp
           PCB is already bound to, unless *all* PCBs with that port have tha
           REUSEADDR flag set. */

/* 处理多个 udp 协议控制块地址复用的情况（只有 IP 地址和端口号都重叠的情况下才是
 * 地址复用，如果只是二者其中的一个有重叠，则不是复用）*/           
#if SO_REUSE
        if (!ip_get_option(pcb, SOF_REUSEADDR) ||
            !ip_get_option(ipcb, SOF_REUSEADDR))
#endif /* SO_REUSE */

        {
          /* port matches that of PCB in list and REUSEADDR not set -> reject */
          if ((ipcb->local_port == port) &&
              /* IP address matches or any IP used? */
              (ip_addr_cmp(&ipcb->local_ip, ipaddr) || ip_addr_isany(ipaddr) ||
              ip_addr_isany(&ipcb->local_ip))) {
            /* other PCB already binds to this local IP and port */
            LWIP_DEBUGF(UDP_DEBUG,
                        ("udp_bind: local port %"U16_F" already bound by another pcb\n", port));
            return ERR_USE;
          }
        }
      }
    }
  }

  /* 把指定的 udp 协议控制块绑定到指定的 IP（IPv4 or IPv6）地址和“本地”端口号上 */
  ip_addr_set_ipaddr(&pcb->local_ip, ipaddr);
  pcb->local_port = port;
  mib2_udp_bind(pcb);
  
  /* pcb not active yet? */
  /* 把当前绑定成功的 udp 协议控制块插入到全局链表中 */
  if (rebind == 0) {
    /* place the PCB on the active list if not already there */
    pcb->next = udp_pcbs;
    udp_pcbs = pcb;
  }
  
  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("udp_bind: bound to "));
  ip_addr_debug_print_val(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, pcb->local_ip);
  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, (", port %"U16_F")\n", pcb->local_port));
  return ERR_OK;
}

/**
 * @ingroup udp_raw
 * Bind an UDP PCB to a specific netif.
 * After calling this function, all packets received via this PCB
 * are guaranteed to have come in via the specified netif, and all
 * outgoing packets will go out via the specified netif.
 *
 * @param pcb UDP PCB to be bound.
 * @param netif netif to bind udp pcb to. Can be NULL.
 *
 * @see udp_disconnect()
 */
/*********************************************************************************************************
** 函数名称: udp_bind_netif
** 功能描述: 把指定的 udp 协议控制块绑定到指定的网络接口上
** 注     释: 在把 udp 协议控制块绑定到指定的网络接口上之后，这个 udp 协议控制块只会接收绑定网络接口上
**         : 发给它的数据，同样，在发送数据的时候，只会从绑定的网络接口往外发送
** 输	 入: pcb - 需要绑定的 udp 协议控制块
**		   : netif - 要绑定的网络接口指针
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
udp_bind_netif(struct udp_pcb *pcb, const struct netif *netif)
{
  LWIP_ASSERT_CORE_LOCKED();

  if (netif != NULL) {
    pcb->netif_idx = netif_get_index(netif);
  } else {
    pcb->netif_idx = NETIF_NO_INDEX;
  }
}

/**
 * @ingroup udp_raw
 * Sets the remote end of the pcb. This function does not generate any
 * network traffic, but only sets the remote address of the pcb.
 *
 * @param pcb UDP PCB to be connected with remote address ipaddr and port.
 * @param ipaddr remote IP address to connect with.
 * @param port remote UDP port to connect with.
 *
 * @return lwIP error code
 *
 * ipaddr & port are expected to be in the same byte order as in the pcb.
 *
 * The udp pcb is bound to a random local port if not already bound.
 *
 * @see udp_disconnect()
 */ 
/*********************************************************************************************************
** 函数名称: udp_connect
** 功能描述: 把指定的 udp 协议控制块连接到指定的 IP（IPv4 or IPv6）地址和端口号上
** 注     释: 如果指定的 udp 协议控制块的“本地”端口还没绑定，则绑定到一个随机端口上
** 输	 入: pcb - 需要连接的 udp 协议控制块
**		   : ipaddr - 要连接的对端设备 IP（IPv4 or IPv6）地址
**		   : port - 要连接的对端设备端口号
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
udp_connect(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{
  struct udp_pcb *ipcb;

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("udp_connect: invalid pcb", pcb != NULL, return ERR_ARG);
  LWIP_ERROR("udp_connect: invalid ipaddr", ipaddr != NULL, return ERR_ARG);

  /* 如果指定的 udp 协议控制块的“本地”端口还没绑定，则绑定到一个随机端口上 */
  if (pcb->local_port == 0) {
    err_t err = udp_bind(pcb, &pcb->local_ip, pcb->local_port);
    if (err != ERR_OK) {
      return err;
    }
  }

  ip_addr_set_ipaddr(&pcb->remote_ip, ipaddr);
  
#if LWIP_IPV6 && LWIP_IPV6_SCOPES
  /* If the given IP address should have a zone but doesn't, assign one now,
   * using the bound address to make a more informed decision when possible. */
  if (IP_IS_V6(&pcb->remote_ip) &&
      ip6_addr_lacks_zone(ip_2_ip6(&pcb->remote_ip), IP6_UNKNOWN)) {
    ip6_addr_select_zone(ip_2_ip6(&pcb->remote_ip), ip_2_ip6(&pcb->local_ip));
  }
#endif /* LWIP_IPV6 && LWIP_IPV6_SCOPES */

  pcb->remote_port = port;
  pcb->flags |= UDP_FLAGS_CONNECTED;

  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("udp_connect: connected to "));
  ip_addr_debug_print_val(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
                          pcb->remote_ip);
  LWIP_DEBUGF(UDP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, (", port %"U16_F")\n", pcb->remote_port));

  /* Insert UDP PCB into the list of active UDP PCBs. */
  /* 如果指定的 udp 协议控制块还没插入到全局 udp 协议控制块链表中，则插入到链表头位置 */
  for (ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next) {
    if (pcb == ipcb) {
      /* already on the list, just return */
      return ERR_OK;
    }
  }
  /* PCB not yet on the list, add PCB now */
  pcb->next = udp_pcbs;
  udp_pcbs = pcb;
  return ERR_OK;
}

/**
 * @ingroup udp_raw
 * Remove the remote end of the pcb. This function does not generate
 * any network traffic, but only removes the remote address of the pcb.
 *
 * @param pcb the udp pcb to disconnect.
 */
/*********************************************************************************************************
** 函数名称: udp_disconnect
** 功能描述: 把指定的 udp 协议控制块和指定的 IP（IPv4 or IPv6）地址和端口号上断开连接关系
** 注     释: 断开连接的 udp 协议控制块仍然处于全局 udp 协议控制块链表中
** 输	 入: pcb - 需要断开连接的 udp 协议控制块
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
udp_disconnect(struct udp_pcb *pcb)
{
  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("udp_disconnect: invalid pcb", pcb != NULL, return);

  /* reset remote address association */
#if LWIP_IPV4 && LWIP_IPV6
  if (IP_IS_ANY_TYPE_VAL(pcb->local_ip)) {
    ip_addr_copy(pcb->remote_ip, *IP_ANY_TYPE);
  } else {
#endif

    ip_addr_set_any(IP_IS_V6_VAL(pcb->remote_ip), &pcb->remote_ip);

#if LWIP_IPV4 && LWIP_IPV6
  }
#endif

  pcb->remote_port = 0;
  pcb->netif_idx = NETIF_NO_INDEX;
  /* mark PCB as unconnected */
  udp_clear_flags(pcb, UDP_FLAGS_CONNECTED);
}

/**
 * @ingroup udp_raw
 * Set a receive callback for a UDP PCB.
 * This callback will be called when receiving a datagram for the pcb.
 *
 * @param pcb the pcb for which to set the recv callback
 * @param recv function pointer of the callback function
 * @param recv_arg additional argument to pass to the callback function
 */
/*********************************************************************************************************
** 函数名称: udp_recv
** 功能描述: 设置指定 udp 协议控制块的处理数据回调函数指针以及回用户自定义的回调函数参数
** 输	 入: pcb - 需要接收数据的 udp 协议控制块
**         : recv - 接收到当前指定 udp 协议控制块数据后调用的回调函数指针
**         : recv_arg - 用户自定义的回调函数参数
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
udp_recv(struct udp_pcb *pcb, udp_recv_fn recv, void *recv_arg)
{
  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("udp_recv: invalid pcb", pcb != NULL, return);

  /* remember recv() callback and user data */
  pcb->recv = recv;
  pcb->recv_arg = recv_arg;
}

/**
 * @ingroup udp_raw
 * Removes and deallocates the pcb.  
 * 
 * @param pcb UDP PCB to be removed. The PCB is removed from the list of
 * UDP PCB's and the data structure is freed from memory.
 *
 * @see udp_new()
 */ 
/*********************************************************************************************************
** 函数名称: udp_remove
** 功能描述: 把指定的 udp 协议控制块从全局 udp 协议控制块链表中移除并释放其占用的内存资源
** 输	 入: pcb - 需要从系统移除的 udp 协议控制块
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
udp_remove(struct udp_pcb *pcb)
{
  struct udp_pcb *pcb2;

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("udp_remove: invalid pcb", pcb != NULL, return);

  mib2_udp_unbind(pcb);

  /* pcb to be removed is first in list? */
  /* 把指定的 udp 协议控制块从全局 udp 协议控制块链表中移除 */
  if (udp_pcbs == pcb) {
    /* make list start at 2nd pcb */
    udp_pcbs = udp_pcbs->next;
    /* pcb not 1st in list */
  } else {
    for (pcb2 = udp_pcbs; pcb2 != NULL; pcb2 = pcb2->next) {
      /* find pcb in udp_pcbs list */
      if (pcb2->next != NULL && pcb2->next == pcb) {
        /* remove pcb from list */
        pcb2->next = pcb->next;
        break;
      }
    }
  }

  /* 释放指定的 udp 协议控制块占用的内存资源 */
  memp_free(MEMP_UDP_PCB, pcb);
}

/**
 * @ingroup udp_raw
 * Creates a new UDP pcb which can be used for UDP communication. The
 * pcb is not active until it has either been bound to a local address
 * or connected to a remote address.
 *
 * @return The UDP PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @see udp_remove()
 */
/*********************************************************************************************************
** 函数名称: udp_new
** 功能描述: 创建一个新的 udp 协议控制块结构，用来和其他设备建立通信
** 注     释: 这个函数创建的 udp 协议控制块是个未初始化的
** 输	 入: 
** 输	 出: pcb - 成功创建的 udp 协议控制块指针
**         : NULL - 创建失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct udp_pcb *
udp_new(void)
{
  struct udp_pcb *pcb;

  LWIP_ASSERT_CORE_LOCKED();

  pcb = (struct udp_pcb *)memp_malloc(MEMP_UDP_PCB);
  /* could allocate UDP PCB? */
  if (pcb != NULL) {
    /* UDP Lite: by initializing to all zeroes, chksum_len is set to 0
     * which means checksum is generated over the whole datagram per default
     * (recommended as default by RFC 3828). */
    /* initialize PCB to all zeroes */
    memset(pcb, 0, sizeof(struct udp_pcb));
    pcb->ttl = UDP_TTL;
  
#if LWIP_MULTICAST_TX_OPTIONS
    udp_set_multicast_ttl(pcb, UDP_TTL);
#endif /* LWIP_MULTICAST_TX_OPTIONS */

  }
  return pcb;
}

/**
 * @ingroup udp_raw
 * Create a UDP PCB for specific IP type.
 * The pcb is not active until it has either been bound to a local address
 * or connected to a remote address.
 * 
 * @param type IP address type, see @ref lwip_ip_addr_type definitions.
 * If you want to listen to IPv4 and IPv6 (dual-stack) packets,
 * supply @ref IPADDR_TYPE_ANY as argument and bind to @ref IP_ANY_TYPE.
 * @return The UDP PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @see udp_remove()
 */ 
/*********************************************************************************************************
** 函数名称: udp_new_ip_type
** 功能描述: 创建一个指定 IP 类型的 udp 协议控制块结构，用来和其他设备建立通信
** 输	 入: type - 需要创建的 IP 类型，详情见：lwip_ip_addr_type
** 输	 出: pcb - 成功创建的 udp 协议控制块指针
**         : NULL - 创建失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct udp_pcb *
udp_new_ip_type(u8_t type)
{
  struct udp_pcb *pcb;

  LWIP_ASSERT_CORE_LOCKED();

  pcb = udp_new();
  
#if LWIP_IPV4 && LWIP_IPV6
  if (pcb != NULL) {
    IP_SET_TYPE_VAL(pcb->local_ip,  type);
    IP_SET_TYPE_VAL(pcb->remote_ip, type);
  }
#else
  LWIP_UNUSED_ARG(type);
#endif /* LWIP_IPV4 && LWIP_IPV6 */

  return pcb;
}

/** This function is called from netif.c when address is changed
 *
 * @param old_addr IP address of the netif before change
 * @param new_addr IP address of the netif after change
 */ 
/*********************************************************************************************************
** 函数名称: udp_netif_ip_addr_changed
** 功能描述: 把当前系统内所有 local_ip（IPv4 or IPv6）地址等于指定的“旧的” IP（IPv4 or IPv6）地址的
**         : udp 协议控制块的 local_ip（IPv4 or IPv6）地址更新成指定的“新的” IP（IPv4 or IPv6）地址
** 输	 入: old_addr - 旧的 local_ip（IPv4 or IPv6）地址
**         : new_addr - 新的 local_ip（IPv4 or IPv6）地址
** 输	 出: pcb - 成功创建的 udp 协议控制块指针
**         : NULL - 创建失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void udp_netif_ip_addr_changed(const ip_addr_t *old_addr, const ip_addr_t *new_addr)
{
  struct udp_pcb *upcb;

  if (!ip_addr_isany(old_addr) && !ip_addr_isany(new_addr)) {
    for (upcb = udp_pcbs; upcb != NULL; upcb = upcb->next) {
      /* PCB bound to current local interface address? */
      if (ip_addr_cmp(&upcb->local_ip, old_addr)) {
        /* The PCB is bound to the old ipaddr and
         * is set to bound to the new one instead */
        ip_addr_copy(upcb->local_ip, *new_addr);
      }
    }
  }
}

#if UDP_DEBUG
/**
 * Print UDP header information for debug purposes.
 *
 * @param udphdr pointer to the udp header in memory.
 */
void
udp_debug_print(struct udp_hdr *udphdr)
{
  LWIP_DEBUGF(UDP_DEBUG, ("UDP header:\n"));
  LWIP_DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(UDP_DEBUG, ("|     %5"U16_F"     |     %5"U16_F"     | (src port, dest port)\n",
                          lwip_ntohs(udphdr->src), lwip_ntohs(udphdr->dest)));
  LWIP_DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(UDP_DEBUG, ("|     %5"U16_F"     |     0x%04"X16_F"    | (len, chksum)\n",
                          lwip_ntohs(udphdr->len), lwip_ntohs(udphdr->chksum)));
  LWIP_DEBUGF(UDP_DEBUG, ("+-------------------------------+\n"));
}
#endif /* UDP_DEBUG */

#endif /* LWIP_UDP */
