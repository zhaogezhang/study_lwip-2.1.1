/**
 * @file
 * UDP API (to be used from TCPIP thread)\n
 * See also @ref udp_raw
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
#ifndef LWIP_HDR_UDP_H
#define LWIP_HDR_UDP_H

#include "lwip/opt.h"

#if LWIP_UDP /* don't build if not configured for use in lwipopts.h */

#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/ip.h"
#include "lwip/ip6_addr.h"
#include "lwip/prot/udp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 表示当前 udp 数据包不计算校验和 */
#define UDP_FLAGS_NOCHKSUM       0x01U

/* 表示当前 udp 协议是 udp-lite 协议 */
#define UDP_FLAGS_UDPLITE        0x02U

/* 表示当前 udp 协议控制块已经和指定的对端设备建立了连接 */
#define UDP_FLAGS_CONNECTED      0x04U

/* 表示当前通过 udp 多播协议发送的数据包需要回环发送到当前网络接口上 */
#define UDP_FLAGS_MULTICAST_LOOP 0x08U

struct udp_pcb;

/** Function prototype for udp pcb receive callback functions
 * addr and port are in same byte order as in the pcb
 * The callback is responsible for freeing the pbuf
 * if it's not used any more.
 *
 * ATTENTION: Be aware that 'addr' might point into the pbuf 'p' so freeing this pbuf
 *            can make 'addr' invalid, too.
 *
 * @param arg user supplied argument (udp_pcb.recv_arg)
 * @param pcb the udp_pcb which received data
 * @param p the packet buffer that was received
 * @param addr the remote IP address from which the packet was received
 * @param port the remote port from which the packet was received
 */
/* 定义用来处理接收到的合法的 udp 数据包的函数指针类型 */
typedef void (*udp_recv_fn)(void *arg, struct udp_pcb *pcb, struct pbuf *p,
    const ip_addr_t *addr, u16_t port);

/** the UDP protocol control block */
/* 定义了当前协议栈使用的 udp 协议控制块结构，包含了一个 udp 连接的所有信息 */
struct udp_pcb {
  /** Common members of all PCB types */
  /* 表示当前 udp 连接和 IP 协议层相关的控制参数 */
  IP_PCB;

  /* Protocol specific PCB members */

  /* 协议栈通过单向链表把当前系统内的所有 udp 连接控制块组织起来 */
  struct udp_pcb *next;

  /* 表示当前 udp 协议控制块的标志变量，例如 UDP_FLAGS_CONNECTED */
  u8_t flags;
  
  /** ports are in host byte order */
  /* 表示当前 udp 协议控制块的本地端口号和对端端口号信息：
   * 在接收 udp 数据时 local_port 用来匹配接收到的 udp 数据包的“目的”端口号
   * remote_port 用来匹配接收到的 udp 数据包的“源”端口号，只有在这两个端口
   * 号匹配的情况下才会处理接收到的 udp 数据包
   * 在发送 udp 数据时，local_port 表示当前要发送的udp 数据包的“源”端口号
   * remote_port 表示当前要发送的 udp 数据包的“目的”端口号 */
  u16_t local_port, remote_port;

#if LWIP_MULTICAST_TX_OPTIONS

#if LWIP_IPV4
  /** outgoing network interface for multicast packets, by IPv4 address (if not 'any') */
  /* 表示当前 udp 连接在发送多播数据时使用的网络接口的 IPv4 地址，这个地址在 mcast_ifindex 
   * 无效（mcast_ifindex = NETIF_NO_INDEX）时使用 */
  ip4_addr_t mcast_ip4;
#endif /* LWIP_IPV4 */

  /** outgoing network interface for multicast packets, by interface index (if nonzero) */
  /* 表示当前 udp 连接在发送多播数据时使用的绑定网络接口发送，NETIF_NO_INDEX 表示没有
   * 绑定接口，其他值表示绑定的网络接口的索引值 */
  u8_t mcast_ifindex;

  /** TTL for outgoing multicast packets */
  /* 表示当前 udp 连接在发送多播数据时使用的 ttl（Time To Live）值 */
  u8_t mcast_ttl;
  
#endif /* LWIP_MULTICAST_TX_OPTIONS */

#if LWIP_UDPLITE
  /** used for UDP_LITE only */
  /* 表示当前 udp 连接在计算校验和时需要覆盖的数据的字节数，0 表示计算整个数据包的校验和 */
  u16_t chksum_len_rx, chksum_len_tx;
#endif /* LWIP_UDPLITE */

  /** receive callback function */
  /* 表示在当前 udp 连接接收到的合法 udp 数据包时，通过这个函数指针来处理接收到的 udp 数据包 */
  udp_recv_fn recv;

  /** user-supplied argument for the recv callback */
  /* 表示在调用处理合法 udp 数据包的函数指针时，用户可自定义的函数参数内容 */
  void *recv_arg;
};

/* udp_pcbs export for external reference (e.g. SNMP agent) */
extern struct udp_pcb *udp_pcbs;

/* The following functions is the application layer interface to the
   UDP code. */
struct udp_pcb * udp_new        (void);
struct udp_pcb * udp_new_ip_type(u8_t type);
void             udp_remove     (struct udp_pcb *pcb);
err_t            udp_bind       (struct udp_pcb *pcb, const ip_addr_t *ipaddr,
                                 u16_t port);
void             udp_bind_netif (struct udp_pcb *pcb, const struct netif* netif);
err_t            udp_connect    (struct udp_pcb *pcb, const ip_addr_t *ipaddr,
                                 u16_t port);
void             udp_disconnect (struct udp_pcb *pcb);
void             udp_recv       (struct udp_pcb *pcb, udp_recv_fn recv,
                                 void *recv_arg);
err_t            udp_sendto_if  (struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *dst_ip, u16_t dst_port,
                                 struct netif *netif);
err_t            udp_sendto_if_src(struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *dst_ip, u16_t dst_port,
                                 struct netif *netif, const ip_addr_t *src_ip);
err_t            udp_sendto     (struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *dst_ip, u16_t dst_port);
err_t            udp_send       (struct udp_pcb *pcb, struct pbuf *p);

#if LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP
err_t            udp_sendto_if_chksum(struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *dst_ip, u16_t dst_port,
                                 struct netif *netif, u8_t have_chksum,
                                 u16_t chksum);
err_t            udp_sendto_chksum(struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *dst_ip, u16_t dst_port,
                                 u8_t have_chksum, u16_t chksum);
err_t            udp_send_chksum(struct udp_pcb *pcb, struct pbuf *p,
                                 u8_t have_chksum, u16_t chksum);
err_t            udp_sendto_if_src_chksum(struct udp_pcb *pcb, struct pbuf *p,
                                 const ip_addr_t *dst_ip, u16_t dst_port, struct netif *netif,
                                 u8_t have_chksum, u16_t chksum, const ip_addr_t *src_ip);
#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */

#define          udp_flags(pcb) ((pcb)->flags)
#define          udp_setflags(pcb, f)  ((pcb)->flags = (f))

#define          udp_set_flags(pcb, set_flags)     do { (pcb)->flags = (u8_t)((pcb)->flags |  (set_flags)); } while(0)
#define          udp_clear_flags(pcb, clr_flags)   do { (pcb)->flags = (u8_t)((pcb)->flags & (u8_t)(~(clr_flags) & 0xff)); } while(0)
#define          udp_is_flag_set(pcb, flag)        (((pcb)->flags & (flag)) != 0)

/* The following functions are the lower layer interface to UDP. */
void             udp_input      (struct pbuf *p, struct netif *inp);

void             udp_init       (void);

/* for compatibility with older implementation */
#define udp_new_ip6() udp_new_ip_type(IPADDR_TYPE_V6)

#if LWIP_MULTICAST_TX_OPTIONS
#if LWIP_IPV4
#define udp_set_multicast_netif_addr(pcb, ip4addr) ip4_addr_copy((pcb)->mcast_ip4, *(ip4addr))
#define udp_get_multicast_netif_addr(pcb)          (&(pcb)->mcast_ip4)
#endif /* LWIP_IPV4 */
#define udp_set_multicast_netif_index(pcb, idx)    ((pcb)->mcast_ifindex = (idx))
#define udp_get_multicast_netif_index(pcb)         ((pcb)->mcast_ifindex)
#define udp_set_multicast_ttl(pcb, value)          ((pcb)->mcast_ttl = (value))
#define udp_get_multicast_ttl(pcb)                 ((pcb)->mcast_ttl)
#endif /* LWIP_MULTICAST_TX_OPTIONS */

#if UDP_DEBUG
void udp_debug_print(struct udp_hdr *udphdr);
#else
#define udp_debug_print(udphdr)
#endif

void udp_netif_ip_addr_changed(const ip_addr_t* old_addr, const ip_addr_t* new_addr);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_UDP */

#endif /* LWIP_HDR_UDP_H */
