/**
 * @file
 * IGMP API
 */

/*
 * Copyright (c) 2002 CITEL Technologies Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of CITEL Technologies Ltd nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CITEL TECHNOLOGIES AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL CITEL TECHNOLOGIES OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is a contribution to the lwIP TCP/IP stack.
 * The Swedish Institute of Computer Science and Adam Dunkels
 * are specifically granted permission to redistribute this
 * source code.
*/

#ifndef LWIP_HDR_IGMP_H
#define LWIP_HDR_IGMP_H

#include "lwip/opt.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

#if LWIP_IPV4 && LWIP_IGMP /* don't build if not configured for use in lwipopts.h */

#ifdef __cplusplus
extern "C" {
#endif

/* IGMP timer */
/* 当前协议栈的 igmp 模块的基准定时器超时周期，单位是毫秒 */
#define IGMP_TMR_INTERVAL              100 /* Milliseconds */

/* 表示在 igmp v1 多播组成员查询消息使用的 Max Resp Time */
#define IGMP_V1_DELAYING_MEMBER_TMR   (1000/IGMP_TMR_INTERVAL)

/* 在一个网络接口加入到一个新的多播组中时，在发送完一个多播组成员报告信息之后，为了
 * 尽量保证当前需要发送的多播组成员报告信息能够成功发送到想要发送的设备上，为当前多
 * 播组启动一个软件定时器，尝试二次发送，这时使用的软件定时器超时时间就是这个值 */
#define IGMP_JOIN_DELAYING_MEMBER_TMR (500 /IGMP_TMR_INTERVAL)

/* Compatibility defines (don't use for new code) */
#define IGMP_DEL_MAC_FILTER            NETIF_DEL_MAC_FILTER
#define IGMP_ADD_MAC_FILTER            NETIF_ADD_MAC_FILTER

/**
 * igmp group structure - there is
 * a list of groups for each interface
 * these should really be linked from the interface, but
 * if we keep them separate we will not affect the lwip original code
 * too much
 *
 * There will be a group for the all systems group address but this
 * will not run the state machine as it is used to kick off reports
 * from all the other groups
 */
/* 每个网路接口都有一个多播组链表结构，这个链表的首地址存储在这个网络  接                   
 * 口的 client_data 的 LWIP_NETIF_CLIENT_DATA_INDEX_IGMP 位置处，其中每
 * 一个这样的结构体表示一个多播组。因为一个网络接口可以同时在多个多播组
 * 中，所以这个结构体通过单向链表把这些多播组信息链接起来，并且，单向链
 * 表的第一个成员结构记录的一定是 allsystem 多播组信息 */
struct igmp_group {
  /** next link */
  /* 通过这个单向链表结构把同一个网路接口的所有多播组信息链接起来 */
  struct igmp_group *next;
  
  /** multicast address */
  /* 记录当前多播组信息代表的多播组地址 */
  ip4_addr_t         group_address;
  
  /** signifies we were the last person to report */
  /* 表示当前多播组的最后一个成员报告信息是否已经发送完成 */
  u8_t               last_reporter_flag;
  
  /** current state of the group */
  /* 表示当前多播组信息的状态，例如 IGMP_GROUP_DELAYING_MEMBER */
  u8_t               group_state;
  
  /** timer for reporting, negative is OFF */
  /* 记录当前多播组的定时器超时剩余时间，单位是 IGMP_TMR_INTERVAL */
  u16_t              timer;
  
  /** counter of simultaneous uses */
  /* 表示当前多播组信息的引用计数值 */
  u8_t               use;
};

/*  Prototypes */
void   igmp_init(void);
err_t  igmp_start(struct netif *netif);
err_t  igmp_stop(struct netif *netif);
void   igmp_report_groups(struct netif *netif);
struct igmp_group *igmp_lookfor_group(struct netif *ifp, const ip4_addr_t *addr);
void   igmp_input(struct pbuf *p, struct netif *inp, const ip4_addr_t *dest);
err_t  igmp_joingroup(const ip4_addr_t *ifaddr, const ip4_addr_t *groupaddr);
err_t  igmp_joingroup_netif(struct netif *netif, const ip4_addr_t *groupaddr);
err_t  igmp_leavegroup(const ip4_addr_t *ifaddr, const ip4_addr_t *groupaddr);
err_t  igmp_leavegroup_netif(struct netif *netif, const ip4_addr_t *groupaddr);
void   igmp_tmr(void);

/** @ingroup igmp 
 * Get list head of IGMP groups for netif.
 * Note: The allsystems group IP is contained in the list as first entry.
 * @see @ref netif_set_igmp_mac_filter()
 */
/* 获取指定网络接口的多播组信息链表头指针，单向链表的第一个成员结构记录的一定是 allsystem 多播组地址信息 */
#define netif_igmp_data(netif) ((struct igmp_group *)netif_get_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_IGMP))

#ifdef __cplusplus
}
#endif

#endif /* LWIP_IPV4 && LWIP_IGMP */

#endif /* LWIP_HDR_IGMP_H */
