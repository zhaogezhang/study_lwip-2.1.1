/**
 * @file
 * IGMP - Internet Group Management Protocol
 *
 * @defgroup igmp IGMP
 * @ingroup ip4
 * To be called from TCPIP thread
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

/* 
 * Note 1)
 * Although the rfc requires V1 AND V2 capability
 * we will only support v2 since now V1 is very old (August 1989)
 * V1 can be added if required
 *
 * a debug print and statistic have been implemented to
 * show this up.
 *
 * Note 2)
 * A query for a specific group address (as opposed to ALLHOSTS)
 * has now been implemented as I am unsure if it is required
 *
 * a debug print and statistic have been implemented to
 * show this up.
 *
 * Note 3)
 * The router alert rfc 2113 is implemented in outgoing packets
 * but not checked rigorously incoming
 * 
 * Steve Reynolds
 */
 
/*
 * RFC 988  - Host extensions for IP multicasting                   - V0
 * RFC 1054 - Host extensions for IP multicasting                   -
 * RFC 1112 - Host extensions for IP multicasting                   - V1
 * RFC 2236 - Internet Group Management Protocol, Version 2         - V2  <- this code is based on this RFC (it's the "de facto" standard)
 * RFC 3376 - Internet Group Management Protocol, Version 3         - V3
 * RFC 4604 - Using Internet Group Management Protocol Version 3... - V3+
 * RFC 2113 - IP Router Alert Option                                -
 */
 
/*
 * IGMP V2 数据包协议格式，详细内容见链接：https://tools.ietf.org/html/rfc2236
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |      Type     | Max Resp Time |           Checksum            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Group Address                         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   消息类型（Type）：常用的有三种消息类型，分别如下：
 *
 *   +------------------------------------------------------------------------------------------------+
 *   | Type |                        说明                                                               |
 *   +------+-----------------------------------------------------------------------------------------+
 *   |      | Group Address |                                                                         |
 *   |      +-----------------------------------------------------------------------------------------+ 
 *   | 0x11 |  0.0.0.0      | 常规组查询 | 查询当前网络所有多播组的成员信息                                                |
 *   |      +-----------------------------------------------------------------------------------------+ 
 *   |      |  指定组地址        | 指定组查询 | 查询当前网络指定多播组的成员信息                                                |
 *   +------+-----------------------------------------------------------------------------------------+ 
 *   | 0x16 |  多播组成员报告消息，表示有主机设备在指定的多播组中，路由器需要转发这个多播组的数据                                              |
 *   +------+-----------------------------------------------------------------------------------------+ 
 *   | 0x17 |  多播组离开报告消息，表示没有主机设备在指定的多播组中，路由器不需要转发这个多播组的数据                                            |
 *   +------+-----------------------------------------------------------------------------------------+ 
 *
 *   最大响应时间（Max Resp Time）：只有在多播组          成员查询消息中有效，表示接收设备需要在指定的时间
 *       内发送响应数据包，时间单位是 0.1 秒。在其他类型或者 IGMP V1 多播组成员查询消息中，这个
 *       字段值设置为 0
 *
 *   校验和（Checksum）：整个 IGMP 消息的校验和
 *
 *   组地址（Group Address）：当前 IGMP 消息使用的多播组地址，不同 igmp 消息类型意义不同
 *
 * 
 * IGMP 功能模块中的软件定时器的使用：
 *   因为在路由器发送常规组查询的时候，每个接收到常规组查询数据包的主机都会为当前网络接口
 *   的每个组发送一个组成员报告消息，为了避免多个主机重复的发送同一个组成员报告消息（因为
 *   会有多个主机在同一个组中）给路由器，所以在路由器接收到一个新的组报告消息的时候，会转
 *   发这个组报告消息给网络中的所有主机，在这些主机收到这条组报告消息的时候，就会把想要发
 *   送、但是还没发送的这个相同的组成员报告消息丢弃掉，这样就解决了多个主机重复的发送同一
 *   个组成员报告消息的问题，也正是为了实现这个功能，所以在每次发送组成员报告消息的时候都
 *   是通过启动一个定时器（定时器超时时间是随机生成的），然后在定时器超时函数中再发送对应
 *   的组成员报告消息
 *
 */
#include "lwip/opt.h"

#if LWIP_IPV4 && LWIP_IGMP /* don't build if not configured for use in lwipopts.h */

#include "lwip/igmp.h"
#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/ip.h"
#include "lwip/inet_chksum.h"
#include "lwip/netif.h"
#include "lwip/stats.h"
#include "lwip/prot/igmp.h"

#include <string.h>

static struct igmp_group *igmp_lookup_group(struct netif *ifp, const ip4_addr_t *addr);
static err_t  igmp_remove_group(struct netif *netif, struct igmp_group *group);
static void   igmp_timeout(struct netif *netif, struct igmp_group *group);
static void   igmp_start_timer(struct igmp_group *group, u8_t max_time);
static void   igmp_delaying_member(struct igmp_group *group, u8_t maxresp);
static err_t  igmp_ip_output_if(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest, struct netif *netif);
static void   igmp_send(struct netif *netif, struct igmp_group *group, u8_t type);

/* 全局变量，记录所有主机设备的多播组地址 */
static ip4_addr_t     allsystems;

/* 全局变量，记录所有路由设备的多播组地址 */
static ip4_addr_t     allrouters;

/**
 * Initialize the IGMP module
 */
/*********************************************************************************************************
** 函数名称: igmp_init
** 功能描述: 初始化网络协议栈的 igmp 功能
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
igmp_init(void)
{
  LWIP_DEBUGF(IGMP_DEBUG, ("igmp_init: initializing\n"));

  /* 初始化两个常用的多播组地址 */
  IP4_ADDR(&allsystems, 224, 0, 0, 1);
  IP4_ADDR(&allrouters, 224, 0, 0, 2);
}

/**
 * Start IGMP processing on interface
 *
 * @param netif network interface on which start IGMP processing
 */
/*********************************************************************************************************
** 函数名称: igmp_start
** 功能描述: 启动指定网络接口的 igmp 功能，并根据情况执行下面操作：
**         : 1. 如果这个网络接口还没有 allsystems 组信息，则创建一个 allsystems 组信息并添加到这个
**         :    网络接口的组信息链表头部位置
**         : 2. 如果这个网络接口支持 MAC 地址过滤功能，则向 MAC 过滤表中添加 allsystems 组地址信息
** 输	 入: netif - 需要启动 igmp 功能的网络接口指针
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
igmp_start(struct netif *netif)
{
  struct igmp_group *group;

  LWIP_DEBUGF(IGMP_DEBUG, ("igmp_start: starting IGMP processing on if %p\n", (void *)netif));

  /* 判断当前网络接口是否有 allsystems 组信息，如果没有则创建一个 allsystems 组信息
   * 并插入到这个网路接口的组信息链表头部 */
  group = igmp_lookup_group(netif, &allsystems);

  if (group != NULL) {
    group->group_state = IGMP_GROUP_IDLE_MEMBER;
    group->use++;

    /* Allow the igmp messages at the MAC level */
	/* 如果当前网络接口支持 MAC 地址过滤功能，则向 MAC 过滤表中添加 allsystems 组地址信息 */
    if (netif->igmp_mac_filter != NULL) {
      LWIP_DEBUGF(IGMP_DEBUG, ("igmp_start: igmp_mac_filter(ADD "));
      ip4_addr_debug_print_val(IGMP_DEBUG, allsystems);
      LWIP_DEBUGF(IGMP_DEBUG, (") on if %p\n", (void *)netif));
      netif->igmp_mac_filter(netif, &allsystems, NETIF_ADD_MAC_FILTER);
    }

    return ERR_OK;
  }

  return ERR_MEM;
}

/**
 * Stop IGMP processing on interface
 *
 * @param netif network interface on which stop IGMP processing
 */
/*********************************************************************************************************
** 函数名称: igmp_stop
** 功能描述: 停止指定网络接口的 igmp 功能，并释放这个网络接口的所有组地址信息资源
** 输	 入: netif - 需要停止 igmp 功能的网络接口指针
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
igmp_stop(struct netif *netif)
{
  /* 获取指定网络接口的组播信息链表头指针，单向链表的第一个成员结构记录的一定是 allsystem 组地址信息 */
  struct igmp_group *group = netif_igmp_data(netif);

  /* 清空当前网络接口的组地址信息 */
  netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_IGMP, NULL);

  /* 分别遍历当前网络接口的每一个组地址信息，并释放他们的资源 */
  while (group != NULL) {
    struct igmp_group *next = group->next; /* avoid use-after-free below */

    /* disable the group at the MAC level */
    if (netif->igmp_mac_filter != NULL) {
      LWIP_DEBUGF(IGMP_DEBUG, ("igmp_stop: igmp_mac_filter(DEL "));
      ip4_addr_debug_print_val(IGMP_DEBUG, group->group_address);
      LWIP_DEBUGF(IGMP_DEBUG, (") on if %p\n", (void *)netif));
      netif->igmp_mac_filter(netif, &(group->group_address), NETIF_DEL_MAC_FILTER);
    }

    /* free group */
    memp_free(MEMP_IGMP_GROUP, group);

    /* move to "next" */
    group = next;
  }
  
  return ERR_OK;
}

/**
 * Report IGMP memberships for this interface
 *
 * @param netif network interface on which report IGMP memberships
 */
/*********************************************************************************************************
** 函数名称: igmp_report_groups
** 功能描述: 为指定的网络接口中的所有组发送一个组成员报告信息，具体执行的操作如下：
**         : 1. 把指定的网络接口的所有组设置为延迟发送组成员报告信息模式
**         : 2. 为其启动一个延迟定时器
** 注     释: 这个函数不会处理 allsystems 组
** 输	 入: netif - 需要发送组成员报告信息的网络接口指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
igmp_report_groups(struct netif *netif)
{
  /* 获取指定网络接口的组播信息链表头指针，单向链表的第一个成员结构记录的一定是 allsystem 组地址信息 */
  struct igmp_group *group = netif_igmp_data(netif);

  LWIP_DEBUGF(IGMP_DEBUG, ("igmp_report_groups: sending IGMP reports on if %p\n", (void *)netif));

  /* Skip the first group in the list, it is always the allsystems group added in igmp_start() */
  /* 跳过当前网络接口的 allsystems 组 */
  if (group != NULL) {
    group = group->next;
  }

  /* 遍历指定网络接口的每一个组结构，并设置这个组为延迟发送组成员报告信息模式
   * 并为其启动一个延迟定时器 */
  while (group != NULL) {
    igmp_delaying_member(group, IGMP_JOIN_DELAYING_MEMBER_TMR);
    group = group->next;
  }
}

/**
 * Search for a group in the netif's igmp group list
 *
 * @param ifp the network interface for which to look
 * @param addr the group ip address to search for
 * @return a struct igmp_group* if the group has been found,
 *         NULL if the group wasn't found.
 */
/*********************************************************************************************************
** 函数名称: igmp_lookfor_group
** 功能描述: 查询指定网络接口的组信息链表上是否有和指定的组地址匹配的组
** 输	 入: ifp - 需要查找的网络接口指针
**         : addr- 需要查找的组播地址
** 输	 出: group - 找到的组结构指针
**         : NULL - 没找到和指定的组播地址匹配的组
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct igmp_group *
igmp_lookfor_group(struct netif *ifp, const ip4_addr_t *addr)
{
  /* 获取指定网络接口的组播信息链表头指针，单向链表的第一个成员结构记录的一定是 allsystem 组地址信息 */
  struct igmp_group *group = netif_igmp_data(ifp);

  /* 分别遍历指定网络接口的组播信息链表结构中的每一个成员，判断是否是我们
   * 要找到组信息 */
  while (group != NULL) {
    if (ip4_addr_cmp(&(group->group_address), addr)) {
      return group;
    }
    group = group->next;
  }

  /* to be clearer, we return NULL here instead of
   * 'group' (which is also NULL at this point).
   */
  return NULL;
}

/**
 * Search for a specific igmp group and create a new one if not found-
 *
 * @param ifp the network interface for which to look
 * @param addr the group ip address to search
 * @return a struct igmp_group*,
 *         NULL on memory error.
 */
/*********************************************************************************************************
** 函数名称: igmp_lookup_group
** 功能描述: 查询指定的网络接口的组信息链表上是否有指定的组地址信息，如果没有，则创建一个指定的组信息
**         : 并插入到这个网络接口的组信息链表中，然后返回这个组信息结构的地址
** 输	 入: ifp - 需要查找的网络接口指针
**         : addr- 需要查找的组播地址
** 输	 出: group - 找到的组信息结构指针
**         : NULL - 没找到和指定的组播地址匹配的组
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static struct igmp_group *
igmp_lookup_group(struct netif *ifp, const ip4_addr_t *addr)
{
  struct igmp_group *group;

  /* 获取指定网络接口的组播信息链表头指针，单向链表的第一个成员结构记录的一定是 allsystem 组地址信息 */
  struct igmp_group *list_head = netif_igmp_data(ifp);

  /* Search if the group already exists */
  /* 判断指定的网路接口是否已经在指定的组中 */
  group = igmp_lookfor_group(ifp, addr);
  if (group != NULL) {
    /* Group already exists. */
    return group;
  }

  /* Group doesn't exist yet, create a new one */
  /* 申请一个组信息结构并根据函数参数初始化相关成员值，然后把新创建的组结构插到
   * 当前网络接口的组信息链表中 */
  group = (struct igmp_group *)memp_malloc(MEMP_IGMP_GROUP);
  if (group != NULL) {
    ip4_addr_set(&(group->group_address), addr);
    group->timer              = 0; /* Not running */
    group->group_state        = IGMP_GROUP_NON_MEMBER;
    group->last_reporter_flag = 0;
    group->use                = 0;

    /* Ensure allsystems group is always first in list */
    if (list_head == NULL) {
      /* this is the first entry in linked list */
      LWIP_ASSERT("igmp_lookup_group: first group must be allsystems",
                  (ip4_addr_cmp(addr, &allsystems) != 0));
      group->next = NULL;
      netif_set_client_data(ifp, LWIP_NETIF_CLIENT_DATA_INDEX_IGMP, group);
    } else {
      /* append _after_ first entry */
      LWIP_ASSERT("igmp_lookup_group: all except first group must not be allsystems",
                  (ip4_addr_cmp(addr, &allsystems) == 0));
      group->next = list_head->next;
      list_head->next = group;
    }
  }

  LWIP_DEBUGF(IGMP_DEBUG, ("igmp_lookup_group: %sallocated a new group with address ", (group ? "" : "impossible to ")));
  ip4_addr_debug_print(IGMP_DEBUG, addr);
  LWIP_DEBUGF(IGMP_DEBUG, (" on if %p\n", (void *)ifp));

  return group;
}

/**
 * Remove a group from netif's igmp group list, but don't free it yet
 *
 * @param group the group to remove from the netif's igmp group list
 * @return ERR_OK if group was removed from the list, an err_t otherwise
 */
/*********************************************************************************************************
** 函数名称: igmp_remove_group
** 功能描述: 从指定的网络接口的组信息链表中移除指定的组信息
** 输	 入: netif - 需要移除组信息的网络接口
**         : group- 需要移除的组信息
** 输	 出: ERR_OK - 操作成功
**         : ERR_ARG - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
igmp_remove_group(struct netif *netif, struct igmp_group *group)
{
  err_t err = ERR_OK;
  struct igmp_group *tmp_group;

  /* Skip the first group in the list, it is always the allsystems group added in igmp_start() */
  /* 从指定的网络接口的组信息链表的第二个成员开始遍历，查找需要移除的组信息，如果找到，则从链表中移除 */
  for (tmp_group = netif_igmp_data(netif); tmp_group != NULL; tmp_group = tmp_group->next) {
    if (tmp_group->next == group) {
      tmp_group->next = group->next;
      break;
    }
  }
  /* Group not found in netif's igmp group list */
  if (tmp_group == NULL) {
    err = ERR_ARG;
  }

  return err;
}

/**
 * Called from ip_input() if a new IGMP packet is received.
 *
 * @param p received igmp packet, p->payload pointing to the igmp header
 * @param inp network interface on which the packet was received
 * @param dest destination ip address of the igmp packet
 */
/*********************************************************************************************************
** 函数名称: igmp_input
** 功能描述: 处理接收到的 igmp 数据包，一般会在 ip_input 函数中调用
** 输	 入: p - 接收到的 igmp 数据包指针
**         : inp- 接收到 igmp 数据包的网络接口指针
**         : dest - 当前 igmp 数据包的目的 IPv4 地址
** 输	 出: ERR_OK - 操作成功
**         : ERR_ARG - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
igmp_input(struct pbuf *p, struct netif *inp, const ip4_addr_t *dest)
{
  struct igmp_msg   *igmp;
  struct igmp_group *group;
  struct igmp_group *groupref;

  IGMP_STATS_INC(igmp.recv);

  /* Note that the length CAN be greater than 8 but only 8 are used - All are included in the checksum */
  /* 校验当前接收到的 igmp 数据包长度是否合法 */
  if (p->len < IGMP_MINLEN) {
    pbuf_free(p);
    IGMP_STATS_INC(igmp.lenerr);
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: length error\n"));
    return;
  }

  LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: message from "));
  ip4_addr_debug_print_val(IGMP_DEBUG, ip4_current_header()->src);
  LWIP_DEBUGF(IGMP_DEBUG, (" to address "));
  ip4_addr_debug_print_val(IGMP_DEBUG, ip4_current_header()->dest);
  LWIP_DEBUGF(IGMP_DEBUG, (" on if %p\n", (void *)inp));

  /* Now calculate and check the checksum */
  /* 校验当前接收到的 igmp 数据包校验和是否合法 */
  igmp = (struct igmp_msg *)p->payload;
  if (inet_chksum(igmp, p->len)) {
    pbuf_free(p);
    IGMP_STATS_INC(igmp.chkerr);
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: checksum error\n"));
    return;
  }

  /* Packet is ok so find an existing group */
  /* 查询指定网络接口的组信息链表上是否有和指定的组地址匹配的组 */
  group = igmp_lookfor_group(inp, dest); /* use the destination IP address of incoming packet */

  /* If group can be found or create... */
  if (!group) {
    pbuf_free(p);
    IGMP_STATS_INC(igmp.drop);
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: IGMP frame not for us\n"));
    return;
  }

  /* NOW ACT ON THE INCOMING MESSAGE TYPE... */
  /* 根据当前接收到的 igmp 数据包类型执行相关操作 */
  switch (igmp->igmp_msgtype) {
    case IGMP_MEMB_QUERY:
      /* IGMP_MEMB_QUERY to the "all systems" address ? */
      /* 目标 IPv4 地址为   所有主机（224.0.0.1）且 igmp 组地址是 0.0.0.0 表示当前是常规组查询 */
      if ((ip4_addr_cmp(dest, &allsystems)) && ip4_addr_isany(&igmp->igmp_group_address)) {
        /* THIS IS THE GENERAL QUERY */
        LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: General IGMP_MEMB_QUERY on \"ALL SYSTEMS\" address (224.0.0.1) [igmp_maxresp=%i]\n", (int)(igmp->igmp_maxresp)));

		/* 如果是多播组成员查询消息且 igmp_maxresp 字段值为 0，当前接收到的 igmp 数据包是 
		 * igmp v1 多播组成员查询消息，否则是 igmp v2 多播组成员查询消息 */
        if (igmp->igmp_maxresp == 0) {
          IGMP_STATS_INC(igmp.rx_v1);
          LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: got an all hosts query with time== 0 - this is V1 and not implemented - treat as v2\n"));
          igmp->igmp_maxresp = IGMP_V1_DELAYING_MEMBER_TMR;
        } else {
          IGMP_STATS_INC(igmp.rx_general);
        }
		
		/* 获取指定网络接口的组播信息链表头指针，单向链表的第一个成员结构记录的一定是 allsystem 组地址信息 */
        groupref = netif_igmp_data(inp);

        /* Do not send messages on the all systems group address! */
        /* Skip the first group in the list, it is always the allsystems group added in igmp_start() */
		/* 跳过网络接口的组播信息链表头的 allsystems 组信息结构 */
        if (groupref != NULL) {
          groupref = groupref->next;
        }

		/* 分别遍历当前网路接口的组播信息链表，并为每个组发送一个组成员报告消息 */
        while (groupref) {
          igmp_delaying_member(groupref, igmp->igmp_maxresp);
          groupref = groupref->next;
        }
      } else {
        /* IGMP_MEMB_QUERY to a specific group ? */
	    /* 如果 igmp 组地址不是 0.0.0.0 表示当前是指定组查询 */
        if (!ip4_addr_isany(&igmp->igmp_group_address)) {
			
          LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: IGMP_MEMB_QUERY to a specific group "));
          ip4_addr_debug_print_val(IGMP_DEBUG, igmp->igmp_group_address);
		
          if (ip4_addr_cmp(dest, &allsystems)) {
            ip4_addr_t groupaddr;
            LWIP_DEBUGF(IGMP_DEBUG, (" using \"ALL SYSTEMS\" address (224.0.0.1) [igmp_maxresp=%i]\n", (int)(igmp->igmp_maxresp)));
		  
            /* we first need to re-look for the group since we used dest last time */
            ip4_addr_copy(groupaddr, igmp->igmp_group_address);

			/* 查询指定网络接口的组信息链表上是否有和指定的组地址匹配的组 */
            group = igmp_lookfor_group(inp, &groupaddr);
          } else {
            LWIP_DEBUGF(IGMP_DEBUG, (" with the group address as destination [igmp_maxresp=%i]\n", (int)(igmp->igmp_maxresp)));
          }

          /* 如果当前网络接口有和指定的组地址匹配的组，则为这个组发送一个组成员报告消息 */
          if (group != NULL) {
            IGMP_STATS_INC(igmp.rx_group);
            igmp_delaying_member(group, igmp->igmp_maxresp);
          } else {
            IGMP_STATS_INC(igmp.drop);
          }
		  
        } else {
          IGMP_STATS_INC(igmp.proterr);
        }
      }
      break;
	  
    case IGMP_V2_MEMB_REPORT:
	  /* 因为在路由器发送常规组查询的时候，每个接收到常规组查询数据包的主机都会为当前网络接口
	   * 的每个组发送一个组成员报告消息，为了避免多个主机重复的发送同一个组成员报告消息（因为
	   * 会有多个主机在同一个组中）给路由器，所以在路由器接收到一个新的组报告消息的时候，会转
	   * 发这个组报告消息给网络中的所有主机，在这些主机收到这条组报告消息的时候，就会把想要发
	   * 送、但是还没发送的这个相同的组成员报告消息丢弃掉，这样就解决了多个主机重复的发送同一
	   * 个组成员报告消息的问题，也正是为了实现这个功能，所以在每次发送组成员报告消息的时候都
	   * 是通过启动一个定时器（定时器超时时间是随机生成的），然后在定时器超时函数中再发送对应
	   * 的组成员报告消息 */
      LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: IGMP_V2_MEMB_REPORT\n"));
      IGMP_STATS_INC(igmp.rx_report);
	
      if (group->group_state == IGMP_GROUP_DELAYING_MEMBER) {
        /* This is on a specific group we have already looked up */
        group->timer = 0; /* stopped */
        group->group_state = IGMP_GROUP_IDLE_MEMBER;
        group->last_reporter_flag = 0;
      }
      break;
	  
    default:
      LWIP_DEBUGF(IGMP_DEBUG, ("igmp_input: unexpected msg %d in state %d on group %p on if %p\n",
                               igmp->igmp_msgtype, group->group_state, (void *)&group, (void *)inp));
      IGMP_STATS_INC(igmp.proterr);
      break;
  }

  pbuf_free(p);
  return;
}

/**
 * @ingroup igmp
 * Join a group on one network interface.
 *
 * @param ifaddr ip address of the network interface which should join a new group
 * @param groupaddr the ip address of the group which to join
 * @return ERR_OK if group was joined on the netif(s), an err_t otherwise
 */
/*********************************************************************************************************
** 函数名称: igmp_joingroup
** 功能描述: 把当前系统内所有支持 igmp 协议并且和指定 IPv4 地址匹配的网络接口加入到指定的多播组中
** 输	 入: ifaddr - 需要匹配的 IPv4 地址
**         : groupaddr- 匹配后加入的多播组地址
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
igmp_joingroup(const ip4_addr_t *ifaddr, const ip4_addr_t *groupaddr)
{
  err_t err = ERR_VAL; /* no matching interface */
  struct netif *netif;

  LWIP_ASSERT_CORE_LOCKED();

  /* make sure it is multicast address */
  LWIP_ERROR("igmp_joingroup: attempt to join non-multicast address", ip4_addr_ismulticast(groupaddr), return ERR_VAL;);
  LWIP_ERROR("igmp_joingroup: attempt to join allsystems address", (!ip4_addr_cmp(groupaddr, &allsystems)), return ERR_VAL;);

  /* loop through netif's */
  /* 遍历当前系统内每一个网络接口，如果指定的网路接口支持 igmp 协议并且这个网络接口的
   * IPv4 地址和我们指定的 IPv4 地址匹配，则把这个网路接口加入到指定的多播组中 */
  NETIF_FOREACH(netif) {
    /* Should we join this interface ? */
    if ((netif->flags & NETIF_FLAG_IGMP) && ((ip4_addr_isany(ifaddr) || ip4_addr_cmp(netif_ip4_addr(netif), ifaddr)))) {
	  /* 把指定的网络接口加入指定的多播组中 */
      err = igmp_joingroup_netif(netif, groupaddr);
      if (err != ERR_OK) {
        /* Return an error even if some network interfaces are joined */
        /** @todo undo any other netif already joined */
        return err;
      }
    }
  }

  return err;
}

/**
 * @ingroup igmp
 * Join a group on one network interface.
 *
 * @param netif the network interface which should join a new group
 * @param groupaddr the ip address of the group which to join
 * @return ERR_OK if group was joined on the netif, an err_t otherwise
 */
/*********************************************************************************************************
** 函数名称: igmp_joingroup_netif
** 功能描述: 把指定的网络接口加入到指定的多播组中
** 输	 入: netif - 需要加入多播组的网络接口
**         : groupaddr - 需要加入的多播组地址
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
igmp_joingroup_netif(struct netif *netif, const ip4_addr_t *groupaddr)
{
  struct igmp_group *group;

  LWIP_ASSERT_CORE_LOCKED();

  /* make sure it is multicast address */
  LWIP_ERROR("igmp_joingroup_netif: attempt to join non-multicast address", ip4_addr_ismulticast(groupaddr), return ERR_VAL;);
  LWIP_ERROR("igmp_joingroup_netif: attempt to join allsystems address", (!ip4_addr_cmp(groupaddr, &allsystems)), return ERR_VAL;);

  /* make sure it is an igmp-enabled netif */
  LWIP_ERROR("igmp_joingroup_netif: attempt to join on non-IGMP netif", netif->flags & NETIF_FLAG_IGMP, return ERR_VAL;);

  /* find group or create a new one if not found */
  /* 查询指定的网络接口的组信息链表上是否有指定的组地址信息，如果没有，则创建一个指定的组信息
     并插入到这个网络接口的组信息链表中，然后返回这个组信息结构的地址 */
  group = igmp_lookup_group(netif, groupaddr);

  if (group != NULL) {
    /* This should create a new group, check the state to make sure */
    if (group->group_state != IGMP_GROUP_NON_MEMBER) {
      LWIP_DEBUGF(IGMP_DEBUG, ("igmp_joingroup_netif: join to group not in state IGMP_GROUP_NON_MEMBER\n"));
    } else {
      /* OK - it was new group */
      LWIP_DEBUGF(IGMP_DEBUG, ("igmp_joingroup_netif: join to new group: "));
      ip4_addr_debug_print(IGMP_DEBUG, groupaddr);
      LWIP_DEBUGF(IGMP_DEBUG, ("\n"));

      /* If first use of the group, allow the group at the MAC level */
	  /* 如果当前组是第一次启用，并且支持 MAC 组地址过滤功能，则把这个组地址添加到 MAC 过滤表中 */
      if ((group->use == 0) && (netif->igmp_mac_filter != NULL)) {
        LWIP_DEBUGF(IGMP_DEBUG, ("igmp_joingroup_netif: igmp_mac_filter(ADD "));
        ip4_addr_debug_print(IGMP_DEBUG, groupaddr);
        LWIP_DEBUGF(IGMP_DEBUG, (") on if %p\n", (void *)netif));
        netif->igmp_mac_filter(netif, groupaddr, NETIF_ADD_MAC_FILTER);
      }

      IGMP_STATS_INC(igmp.tx_join);
	  
	  /* 当前网络接口加入到指定的多播组中后，发送一个组成员报告消息 */
      igmp_send(netif, group, IGMP_V2_MEMB_REPORT);

	  /* 为了尽量保证当前需要发送的组成员报告信息能够成功发送到想要发送的设备上
	   * 为当前组启动一个软件定时器，尝试二次发送 */
      igmp_start_timer(group, IGMP_JOIN_DELAYING_MEMBER_TMR);

      /* Need to work out where this timer comes from */
	  /* 更新当前组状态 */
      group->group_state = IGMP_GROUP_DELAYING_MEMBER;
    }
	
    /* Increment group use */
	/* 增加当前组引用计数 */
    group->use++;
	
    /* Join on this interface */
    return ERR_OK;
  } else {
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_joingroup_netif: Not enough memory to join to group\n"));
    return ERR_MEM;
  }
}

/**
 * @ingroup igmp
 * Leave a group on one network interface.
 *
 * @param ifaddr ip address of the network interface which should leave a group
 * @param groupaddr the ip address of the group which to leave
 * @return ERR_OK if group was left on the netif(s), an err_t otherwise
 */
/*********************************************************************************************************
** 函数名称: igmp_leavegroup
** 功能描述: 把当前系统内所有支持 igmp 协议并且和指定 IPv4 地址匹配的网络接口从指定的多播组中退出
** 输	 入: netif - 需要匹配的 IPv4 地址
**         : groupaddr - 匹配后退出的多播组地址
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
igmp_leavegroup(const ip4_addr_t *ifaddr, const ip4_addr_t *groupaddr)
{
  err_t err = ERR_VAL; /* no matching interface */
  struct netif *netif;

  LWIP_ASSERT_CORE_LOCKED();

  /* make sure it is multicast address */
  LWIP_ERROR("igmp_leavegroup: attempt to leave non-multicast address", ip4_addr_ismulticast(groupaddr), return ERR_VAL;);
  LWIP_ERROR("igmp_leavegroup: attempt to leave allsystems address", (!ip4_addr_cmp(groupaddr, &allsystems)), return ERR_VAL;);

  /* loop through netif's */
  /* 遍历当前系统内每一个网络接口，如果指定的网路接口支持 igmp 协议并且这个网络接口的
   * IPv4 地址和我们指定的 IPv4 地址匹配，则把这个网路接口从指定的多播组中移除 */
  NETIF_FOREACH(netif) {
    /* Should we leave this interface ? */
    if ((netif->flags & NETIF_FLAG_IGMP) && ((ip4_addr_isany(ifaddr) || ip4_addr_cmp(netif_ip4_addr(netif), ifaddr)))) {
      /* 把指定的网络接口从指定的多播组中退出 */
      err_t res = igmp_leavegroup_netif(netif, groupaddr);
      if (err != ERR_OK) {
        /* Store this result if we have not yet gotten a success */
        err = res;
      }
    }
  }

  return err;
}

/**
 * @ingroup igmp
 * Leave a group on one network interface.
 *
 * @param netif the network interface which should leave a group
 * @param groupaddr the ip address of the group which to leave
 * @return ERR_OK if group was left on the netif, an err_t otherwise
 */
/*********************************************************************************************************
** 函数名称: igmp_leavegroup_netif
** 功能描述: 把指定的网络接口从指定的多播组中退出
** 输	 入: netif - 需要退出多播组的网络接口
**         : groupaddr - 需要退出的多播组地址
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
igmp_leavegroup_netif(struct netif *netif, const ip4_addr_t *groupaddr)
{
  struct igmp_group *group;

  LWIP_ASSERT_CORE_LOCKED();

  /* make sure it is multicast address */
  LWIP_ERROR("igmp_leavegroup_netif: attempt to leave non-multicast address", ip4_addr_ismulticast(groupaddr), return ERR_VAL;);
  LWIP_ERROR("igmp_leavegroup_netif: attempt to leave allsystems address", (!ip4_addr_cmp(groupaddr, &allsystems)), return ERR_VAL;);

  /* make sure it is an igmp-enabled netif */
  LWIP_ERROR("igmp_leavegroup_netif: attempt to leave on non-IGMP netif", netif->flags & NETIF_FLAG_IGMP, return ERR_VAL;);

  /* find group */
  /* 查询指定网络接口的组信息链表上是否有和指定的组地址匹配的组 */
  group = igmp_lookfor_group(netif, groupaddr);

  if (group != NULL) {
  	
    /* Only send a leave if the flag is set according to the state diagram */
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_leavegroup_netif: Leaving group: "));
    ip4_addr_debug_print(IGMP_DEBUG, groupaddr);
    LWIP_DEBUGF(IGMP_DEBUG, ("\n"));

    /* If there is no other use of the group */
    if (group->use <= 1) {
      /* Remove the group from the list */
	  /* 从指定的网络接口的组信息链表中移除指定的组信息 */
      igmp_remove_group(netif, group);

      /* If we are the last reporter for this group */
      if (group->last_reporter_flag) {
        LWIP_DEBUGF(IGMP_DEBUG, ("igmp_leavegroup_netif: sending leaving group\n"));
        IGMP_STATS_INC(igmp.tx_leave);
        igmp_send(netif, group, IGMP_LEAVE_GROUP);
      }

      /* Disable the group at the MAC level */
	  /* 把指定的多播组地址从 MAC 地址过滤表中移除 */
      if (netif->igmp_mac_filter != NULL) {
        LWIP_DEBUGF(IGMP_DEBUG, ("igmp_leavegroup_netif: igmp_mac_filter(DEL "));
        ip4_addr_debug_print(IGMP_DEBUG, groupaddr);
        LWIP_DEBUGF(IGMP_DEBUG, (") on if %p\n", (void *)netif));
        netif->igmp_mac_filter(netif, groupaddr, NETIF_DEL_MAC_FILTER);
      }

      /* Free group struct */
	  /* 释放当前多播组信息内存空间资源 */
      memp_free(MEMP_IGMP_GROUP, group);
    } else {
      /* Decrement group use */
	  /* 递减当前多播组的引用计数值 */
      group->use--;
    }
	
    return ERR_OK;
  } else {
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_leavegroup_netif: not member of group\n"));
    return ERR_VAL;
  }
}

/**
 * The igmp timer function (both for NO_SYS=1 and =0)
 * Should be called every IGMP_TMR_INTERVAL milliseconds (100 ms is default).
 */
/*********************************************************************************************************
** 函数名称: igmp_tmr
** 功能描述: 当前协议栈 igmp 模块的基准定时器超时处理函数，主要用来更新系统内所有网络接口中的所有
**         : 组信息的超时计数值，如果超时计数值达到 0，则调用对应组的 igmp_timeout 函数
** 注     释: 这个函数的调用周期为 IGMP_TMR_INTERVAL 毫秒
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
igmp_tmr(void)
{
  struct netif *netif;

  /* 分别遍历当前系统内的每一个网络接口，并更新这个网路接口上的组信息链表
   * 的每一个组信息的软件定时器超时计数值，如果有组信息的超时计数值达到 0
   * 则调用对应组的 igmp_timeout 函数 */
  NETIF_FOREACH(netif) {
    struct igmp_group *group = netif_igmp_data(netif);

    while (group != NULL) {
	  /* 这个位置需要注意的是，只有在 group->timer 的值大于 0 的时候才会执行
	   * 计数值递减操作，所以，如果我们需要停止某个组的软件定时器的时候，只需
	   * 要把这个组的时间计数值设置为 0 即可 */
      if (group->timer > 0) {
        group->timer--;
        if (group->timer == 0) {
          igmp_timeout(netif, group);
        }
      }
      group = group->next;
    }
  }
}

/**
 * Called if a timeout for one group is reached.
 * Sends a report for this group.
 *
 * @param group an igmp_group for which a timeout is reached
 */
/*********************************************************************************************************
** 函数名称: igmp_timeout
** 功能描述: 如果指定组的超时计数值到达 0，则会为这个组调用这个函数，进而为这个组发送一个组成员报告信息
**         : 并更新这个组的状态为 IGMP_GROUP_IDLE_MEMBER，表示发送了一个组成员报告信息
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
igmp_timeout(struct netif *netif, struct igmp_group *group)
{
  /* If the state is IGMP_GROUP_DELAYING_MEMBER then we send a report for this group
     (unless it is the allsystems group) */
  /* 判断当前组是否处于 IGMP_GROUP_DELAYING_MEMBER 状态并且是否是 allsystems 组 */
  if ((group->group_state == IGMP_GROUP_DELAYING_MEMBER) &&
      (!(ip4_addr_cmp(&(group->group_address), &allsystems)))) {
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_timeout: report membership for group with address "));
    ip4_addr_debug_print_val(IGMP_DEBUG, group->group_address);
    LWIP_DEBUGF(IGMP_DEBUG, (" on if %p\n", (void *)netif));

    /* 更新当前组状态，表示发送了一个组成员报告信息 */
    group->group_state = IGMP_GROUP_IDLE_MEMBER;

    IGMP_STATS_INC(igmp.tx_report);
	/* 通过指定的网络接口为指定的组发送了一个组成员报告信息 */
    igmp_send(netif, group, IGMP_V2_MEMB_REPORT);
  }
}

/**
 * Start a timer for an igmp group
 *
 * @param group the igmp_group for which to start a timer
 * @param max_time the time in multiples of IGMP_TMR_INTERVAL (decrease with
 *        every call to igmp_tmr())
 */
/*********************************************************************************************************
** 函数名称: igmp_start_timer
** 功能描述: 为指定的 igmp 组启动一个软件定时器
** 输	 入: group - 需要定时器的组
**         : maxresp - 最大的超时时间，单位是毫秒
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
igmp_start_timer(struct igmp_group *group, u8_t max_time)
{
#ifdef LWIP_RAND
  group->timer = (u16_t)(max_time > 2 ? (LWIP_RAND() % max_time) : 1);
#else /* LWIP_RAND */
  /* ATTENTION: use this only if absolutely necessary! */
  group->timer = max_time / 2;
#endif /* LWIP_RAND */

  if (group->timer == 0) {
    group->timer = 1;
  }
}

/**
 * Delaying membership report for a group if necessary
 *
 * @param group the igmp_group for which "delaying" membership report
 * @param maxresp query delay
 */
/*********************************************************************************************************
** 函数名称: igmp_delaying_member
** 功能描述: 为指定的组发送一个组成员报告消息，具体的操作如下
**         : 1. 设置指定的组处于延迟发送组成员报告信息模式
**         : 2. 为其启动一个延迟定时器
** 输	 入: group - 需要延迟发送组成员报告信息的组
**         : maxresp - 最大的延时时间，单位是毫秒
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
igmp_delaying_member(struct igmp_group *group, u8_t maxresp)
{
  if ((group->group_state == IGMP_GROUP_IDLE_MEMBER) ||
      ((group->group_state == IGMP_GROUP_DELAYING_MEMBER) &&
       ((group->timer == 0) || (maxresp < group->timer)))) {
    /* 为指定的组启动软件延迟定时器，并更新组状态到 IGMP_GROUP_DELAYING_MEMBER */
    igmp_start_timer(group, maxresp);
    group->group_state = IGMP_GROUP_DELAYING_MEMBER;
  }
}


/**
 * Sends an IP packet on a network interface. This function constructs the IP header
 * and calculates the IP header checksum. If the source IP address is NULL,
 * the IP address of the outgoing network interface is filled in as source address.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == LWIP_IP_HDRINCL, p already includes an
            IP header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP4_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param netif the netif on which to send this packet
 * @return ERR_OK if the packet was sent OK
 *         ERR_BUF if p doesn't have enough space for IP/LINK headers
 *         returns errors returned by netif->output
 */
/*********************************************************************************************************
** 函数名称: igmp_ip_output_if
** 功能描述: 通过指定的网络接口发送一个带有路由告警选项的 igmp 协议数据包，在发送之前会根据传入的参数
**         : 设置 IP 协议头中的 IPv4 源地址和 IPv4 目的地址字段值
** 输	 入: p - 需要发送的网络数据包
**         : src - 网络数据包协议头的 IPv4 源地址字段值
**         : dest - 网络数据包协议头的 IPv4 目的地址字段值
**         : netif - 发送网络数据包的网络接口指针
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
igmp_ip_output_if(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest, struct netif *netif)
{
  /* This is the "router alert" option */
  u16_t ra[2];

  /* 初始化 igmp 数据包的 IP 协议头中的路由告警选项内容*/
  ra[0] = PP_HTONS(ROUTER_ALERT);
  ra[1] = 0x0000; /* Router shall examine packet */
  
  IGMP_STATS_INC(igmp.xmit);

  /* 通过指定的网络接口发送带有路由告警选项的网络数据包                          */
  return ip4_output_if_opt(p, src, dest, IGMP_TTL, 0, IP_PROTO_IGMP, netif, ra, ROUTER_ALERTLEN);
}

/**
 * Send an igmp packet to a specific group.
 *
 * @param group the group to which to send the packet
 * @param type the type of igmp packet to send
 */
/*********************************************************************************************************
** 函数名称: igmp_send
** 功能描述: 通过指定的网路接口向指定的多播组发送一个指定类型的 igmp 数据包
** 输	 入: netif - 发送 igmp 数据包的网络接口指针
**         : group - 目的地多播组指针
**         : type - igmp 数据包类型，目前仅支持 IGMP_V2_MEMB_REPOR 和 IGMP_LEAVE_GROUP
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
igmp_send(struct netif *netif, struct igmp_group *group, u8_t type)
{
  struct pbuf     *p    = NULL;
  struct igmp_msg *igmp = NULL;
  ip4_addr_t   src  = *IP4_ADDR_ANY4;
  ip4_addr_t  *dest = NULL;

  /* IP header + "router alert" option + IGMP header */
  p = pbuf_alloc(PBUF_TRANSPORT, IGMP_MINLEN, PBUF_RAM);

  if (p) {
    igmp = (struct igmp_msg *)p->payload;
	
    LWIP_ASSERT("igmp_send: check that first pbuf can hold struct igmp_msg",
                (p->len >= sizeof(struct igmp_msg)));

	/* 设置当前 igmp 数据包所属网络数据包协议头的 IPv4 源地址字段值 */
    ip4_addr_copy(src, *netif_ip4_addr(netif));

    /* 设置当前 igmp 数据包所属网络数据包协议头的 IPv4 目的地址字段值以及
	 * 当前 igmp 数据包协议头中的组地址字段值 */
    if (type == IGMP_V2_MEMB_REPORT) {
      dest = &(group->group_address);
      ip4_addr_copy(igmp->igmp_group_address, group->group_address);
      group->last_reporter_flag = 1; /* Remember we were the last to report */
    } else {
      if (type == IGMP_LEAVE_GROUP) {
        dest = &allrouters;
        ip4_addr_copy(igmp->igmp_group_address, group->group_address);
      }
    }

    /* 初始化 igmp 协议头，并根据指定的参数通过指定的网络接口把这个 igmp 数据包发送出去 */
    if ((type == IGMP_V2_MEMB_REPORT) || (type == IGMP_LEAVE_GROUP)) {
      igmp->igmp_msgtype  = type;
      igmp->igmp_maxresp  = 0;
      igmp->igmp_checksum = 0;
      igmp->igmp_checksum = inet_chksum(igmp, IGMP_MINLEN);

      /* 过指定的网络接口发送一个带有路由告警选项的 igmp 协议数据包，在发送之前会
         根据传入的参数设置 IP 协议头中的 IPv4 源地址和 IPv4 目的地址字段值 */
      igmp_ip_output_if(p, &src, dest, netif);
    }

    pbuf_free(p);
  } else {
    LWIP_DEBUGF(IGMP_DEBUG, ("igmp_send: not enough memory for igmp_send\n"));
    IGMP_STATS_INC(igmp.memerr);
  }
}

#endif /* LWIP_IPV4 && LWIP_IGMP */
