/**
 * @file
 * Address Resolution Protocol module for IP over Ethernet
 *
 * Functionally, ARP is divided into two parts. The first maps an IP address
 * to a physical address when sending a packet, and the second part answers
 * requests from other machines for our physical address.
 *
 * This implementation complies with RFC 826 (Ethernet ARP). It supports
 * Gratuitious ARP from RFC3220 (IP Mobility Support for IPv4) section 4.6
 * if an interface calls etharp_gratuitous(our_netif) upon address change.
 */

/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * Copyright (c) 2003-2004 Leon Woestenberg <leon.woestenberg@axon.tv>
 * Copyright (c) 2003-2004 Axon Digital Design B.V., The Netherlands.
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
 */
/* arp 协议数据包格式定义如下：
 *
 *      dhost     shost     type   ar_hrd ar_pro  ar_hln   ar_pln   ar_op    arp_sha    arp_spa    arp_dha    arp_dpa
 *   +----------+--------+--------+------+------+--------+--------+--------+----------+----------+----------+----------+
 *   | 以太网      | 以太网 	 | 帧类型	  | 硬件   | 协议 | 硬件地 | 协议地 | 操作码            | 发送者      | 发送者      | 目标设备		| 目标设备     |
 *   | 目的地址 | 源地址 |  	          |	类型 | 类型	    | 址长度 | 址长度 |		       | 硬件地址 | IPv4地址 | 硬件地址 | IPv4地址 |
 *   +----------+--------+--------+------+------+--------+--------+--------+----------+----------+----------+----------+
 *      6 byte    6 byte   2 byte  2 byte 2 byte  6 byte   4 byte   2 byte    6 byte     4 byte     6 byte     4 byte
 *
 *   |<------ ether_header ------>|<------------ arp_header -------------->|
 *
 *                                |<---------------------------------- ether_arp ------------------------------------->|
 *
 *   以太网目的地址（6 Bytes）：
 *   当发送 ARP 请求时此处全为 1（FF:FF:FF:FF:FF:FF），即为广播地址。当发送 ARP 响应时，此处即为目的端 MAC 地址
 *
 *   以太网源地址（6 Bytes）：
 *   发送 ARP 请求的 MAC 地址，为本机 MAC 地址
 *
 *   帧类型（2 Bytes）：
 *   表示的是后面的数据类型，ARP 请求和 ARP 应答这个值为 0x0806
 *
 *   硬件类型（2 Bytes）：
 *   硬件地址不只以太网一种，是以太网类型时此值为 1
 *
 *   协议类型（2 Bytes）：
 *   要映射的协议地址的类型，要对 IPv4 地址进行映射，此值为 0x0800
 *
 *   硬件地址长度（1 Byte）：
 *   即为 MAC 地址长度 6 Byte
 *
 *   协议地址长度（1 Byte）：
 *   即为 IP 地址长度 4 Byte
 *
 *   操作类型（2 Bytes）：
 *   值为 1，表示进行 ARP 请求；值为2，表示进行 ARP 应答；值为 3，表示进行 RARP 请求；值为 4，表示进行 RARP 应答
 *
 *   发送者硬件地址（6 Bytes）：
 *   这是本机的 MAC 地址，与第二个字段相同
 *
 *   发送者 IP 地址（4 Bytes）：
 *   这是本机的 IP 地址
 *
 *   目标硬件地址（6 Bytes）：
 *   在发送 ARP 请求时，还不知道目的端的 MAC 地址，所以此处全为 0 ( 00:00:00:00:00:00 )。当发送 ARP 响应报文时，此处即为目的端 MAC 地址
 *
 *   目标 IP 地址（4 Bytes）：
 *   目标端 IP 地址。
 *
 */
#include "lwip/opt.h"

#if LWIP_IPV4 && LWIP_ARP /* don't build if not configured for use in lwipopts.h */

#include "lwip/etharp.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"
#include "lwip/prot/iana.h"
#include "netif/ethernet.h"

#include <string.h>

#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif

/** Re-request a used ARP entry 1 minute before it would expire to prevent
 *  breaking a steadily used connection because the ARP entry timed out. */
/* 分别定义了单播和广播模式下，请求指定地址的 arp 信息周期 */
#define ARP_AGE_REREQUEST_USED_UNICAST   (ARP_MAXAGE - 30)
#define ARP_AGE_REREQUEST_USED_BROADCAST (ARP_MAXAGE - 15)

/** the time an ARP entry stays pending after first request,
 *  for ARP_TMR_INTERVAL = 1000, this is
 *  10 seconds.
 *
 *  @internal Keep this number at least 2, otherwise it might
 *  run out instantly if the timeout occurs directly after a request.
 */
/* 表示当一个 arp 映射项处于 pending 状态下时，如果累计时间超过 ARP_MAXPENDING 时（单位是 arp 定时器超时周期），
 * 就视为这个 arp 映射项为无效映射，会从 arp 地址映射表中移除 */
#define ARP_MAXPENDING 5

/** ARP states */
enum etharp_state {
  ETHARP_STATE_EMPTY = 0,

  /* 在 arp 定时器超时处理函数中，会对处于 pending 状态的 arp 映射项的 IPv4 地址发送一个
   * arp 查询请求，并且处于         pending 状态的   arp 映射项是不完整的（没有 MAC 地址信息）*/
  ETHARP_STATE_PENDING,
  
  ETHARP_STATE_STABLE,
  ETHARP_STATE_STABLE_REREQUESTING_1,
  ETHARP_STATE_STABLE_REREQUESTING_2
#if ETHARP_SUPPORT_STATIC_ENTRIES  
  /* 如果某个指定的 arp 映射项被设置为 ETHARP_STATE_STATIC 状态，则表示这个
   * arp 映射项不会被自动移除、状态也不会被修改而长驻在                        arp 地址映射表中 */
  , ETHARP_STATE_STATIC
#endif /* ETHARP_SUPPORT_STATIC_ENTRIES */
};

/* 定义 lwip 协议栈中一个 ARP 地址映射项数据结构 */
struct etharp_entry {
/* 表示在进行 arp 地址解析期间，是否需要通过队列方式缓存多个发往这个 ip 上的数据包 */
#if ARP_QUEUEING
  /** Pointer to queue of pending outgoing packets on this ARP entry. */
  struct etharp_q_entry *q;
#else /* ARP_QUEUEING */
  /** Pointer to a single pending outgoing packet on this ARP entry. */
  struct pbuf *q;
#endif /* ARP_QUEUEING */

  /* 表示当前 arp 地址映射项对应的 IPv4 地址 */
  ip4_addr_t ipaddr;

  /* 表示当前 arp 地址映射项所属的网络接口 */
  struct netif *netif;

  /* 表示当前 arp 地址映射项对应的物理地址（网卡 MAC 地址）*/
  struct eth_addr ethaddr;

  /* 表示当前 arp 映射项从上次更新到目前为止，经历的 arp 定时器超时周期数 */
  u16_t ctime;

  /* 表示当前 arp 映射项状态 */
  u8_t state;
};

/* 当前系统内所有网络接口共用的 arp 缓存数组 */
static struct etharp_entry arp_table[ARP_TABLE_SIZE];

/* 全局变量，在没有启动 struct netif 结构体中的 hints 字段时，通过这个“本地”全局变量在
 * arp 功能模块，记录在当前系统的所有网络接口中，上一次通信使用的 arp 地址项在 arp 地址
 * 表中的索引值 */
#if !LWIP_NETIF_HWADDRHINT
static netif_addr_idx_t etharp_cached_entry;
#endif /* !LWIP_NETIF_HWADDRHINT */

/** Try hard to create a new entry - we want the IP address to appear in
    the cache (even if this means removing an active entry or so). */
/* 表示在查询 arp 地址映射表的时候，如果没找到我们指定的 IPv4 地址匹配的 arp 映射项，且当前
 * arp 地址映射表已经满了，则会从中回收一个 arp 映射项，然后为我们指定的 IPv4 地址创建一个
 * 新的 arp 映射项，在回收 arp 映射项的时候，选择被回收的 arp 映射项顺序如下：
 * oldest stable entry -> oldest pending entry without queued packets -> oldest pending entry with queued packets */   
#define ETHARP_FLAG_TRY_HARD     1

/* 表示在查询 arp 地址映射表的时候，如果没找到我们指定的 IPv4 地址匹配的 arp 映射项，则返回
 * 而不会为我们指定的 IPv4 地址创建一个新的 arp 映射项 */
#define ETHARP_FLAG_FIND_ONLY    2

/* 如果我们既没有设置 ETHARP_FLAG_TRY_HARD 标志，也没有设置 ETHARP_FLAG_FIND_ONLY 标志，那么
 * 在没找到我们指定的 IPv4 地址匹配的 arp 映射项时，如果 arp 地址映射表没满，则会为我们指定的
 * IPv4 地址创建一个新的 arp 映射项 */


#if ETHARP_SUPPORT_STATIC_ENTRIES
#define ETHARP_FLAG_STATIC_ENTRY 4
#endif /* ETHARP_SUPPORT_STATIC_ENTRIES */

/* 在命中一个 arp 地址项的时候，通过这个宏定义来同步相关数据（(netif)->hints->addr_hint 或者 etharp_cached_entry）*/
#if LWIP_NETIF_HWADDRHINT
#define ETHARP_SET_ADDRHINT(netif, addrhint)  do { if (((netif) != NULL) && ((netif)->hints != NULL)) { \
                                              (netif)->hints->addr_hint = (addrhint); }} while(0)
#else /* LWIP_NETIF_HWADDRHINT */
#define ETHARP_SET_ADDRHINT(netif, addrhint)  (etharp_cached_entry = (addrhint))
#endif /* LWIP_NETIF_HWADDRHINT */


/* Check for maximum ARP_TABLE_SIZE */
#if (ARP_TABLE_SIZE > NETIF_ADDR_IDX_MAX)
#error "ARP_TABLE_SIZE must fit in an s16_t, you have to reduce it in your lwipopts.h"
#endif


static err_t etharp_request_dst(struct netif *netif, const ip4_addr_t *ipaddr, const struct eth_addr *hw_dst_addr);
static err_t etharp_raw(struct netif *netif,
                        const struct eth_addr *ethsrc_addr, const struct eth_addr *ethdst_addr,
                        const struct eth_addr *hwsrc_addr, const ip4_addr_t *ipsrc_addr,
                        const struct eth_addr *hwdst_addr, const ip4_addr_t *ipdst_addr,
                        const u16_t opcode);

#if ARP_QUEUEING
/**
 * Free a complete queue of etharp entries
 *
 * @param q a qeueue of etharp_q_entry's to free
 */
/*********************************************************************************************************
** 函数名称: free_etharp_q
** 功能描述: 释放指定的 arp 缓存队列中所有的还没有发出的 pbuf 数据结构
** 输	 入: q - arp 缓存队列指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
free_etharp_q(struct etharp_q_entry *q)
{
  struct etharp_q_entry *r;
  LWIP_ASSERT("q != NULL", q != NULL);
  while (q) {
    r = q;
    q = q->next;
    LWIP_ASSERT("r->p != NULL", (r->p != NULL));
    pbuf_free(r->p);
    memp_free(MEMP_ARP_QUEUE, r);
  }
}
#else /* ARP_QUEUEING */

/** Compatibility define: free the queued pbuf */
#define free_etharp_q(q) pbuf_free(q)

#endif /* ARP_QUEUEING */

/** Clean up ARP table entries */
/*********************************************************************************************************
** 函数名称: etharp_free_entry
** 功能描述: 回收指定索引的 arp 映射项以及这个映射项数据队里中未发送的数据包
** 输	 入: i - 需要回收的 arp 映射项索引值
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
etharp_free_entry(int i)
{
  /* remove from SNMP ARP index tree */
  mib2_remove_arp_entry(arp_table[i].netif, &arp_table[i].ipaddr);
  
  /* and empty packet queue */
  if (arp_table[i].q != NULL) {
    /* remove all queued packets */
    LWIP_DEBUGF(ETHARP_DEBUG, ("etharp_free_entry: freeing entry %"U16_F", packet queue %p.\n", (u16_t)i, (void *)(arp_table[i].q)));
    free_etharp_q(arp_table[i].q);
    arp_table[i].q = NULL;
  }
  
  /* recycle entry for re-use */
  arp_table[i].state = ETHARP_STATE_EMPTY;
#ifdef LWIP_DEBUG
  /* for debugging, clean out the complete entry */
  arp_table[i].ctime = 0;
  arp_table[i].netif = NULL;
  ip4_addr_set_zero(&arp_table[i].ipaddr);
  arp_table[i].ethaddr = ethzero;
#endif /* LWIP_DEBUG */
}

/**
 * Clears expired entries in the ARP table.
 *
 * This function should be called every ARP_TMR_INTERVAL milliseconds (1 second),
 * in order to expire entries in the ARP table.
 */
/*********************************************************************************************************
** 函数名称: etharp_tmr
** 功能描述: arp 模块定时器超时处理函数，会被周期性调度，默认超时周期是 1 秒，在这个函数中会对 arp 映射项
**         : 执行的操作分别有：1. 把 arp 映射项从 arp 地址映射表中移除
**         :                   2. 更新 arp 映射项的状态
**         :                   3. 对 arp 映射项映射的 IPv4 地址发送一个 arp 查询请求
**         : 
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
etharp_tmr(void)
{
  int i;

  LWIP_DEBUGF(ETHARP_DEBUG, ("etharp_timer\n"));
  
  /* remove expired entries from the ARP table */
  for (i = 0; i < ARP_TABLE_SIZE; ++i) {
    u8_t state = arp_table[i].state;
    if (state != ETHARP_STATE_EMPTY
#if ETHARP_SUPPORT_STATIC_ENTRIES
        /* 如果某个指定的 arp 映射项被设置为 ETHARP_STATE_STATIC 状态，则表示这个
         * arp 映射项不会被自动移除而长驻在 arp               地址映射表中 */
        && (state != ETHARP_STATE_STATIC)
#endif /* ETHARP_SUPPORT_STATIC_ENTRIES */
       ) {
      /* arp 定时器每超时一次，会把当前系统内“所有”有效的 arp 映射项的 ctime 字段值加 1 */
      arp_table[i].ctime++;
	  
      if ((arp_table[i].ctime >= ARP_MAXAGE) ||
          ((arp_table[i].state == ETHARP_STATE_PENDING)  &&
           (arp_table[i].ctime >= ARP_MAXPENDING))) {
        /* pending or stable entry has become old! */
        LWIP_DEBUGF(ETHARP_DEBUG, ("etharp_timer: expired %s entry %d.\n",
                                   arp_table[i].state >= ETHARP_STATE_STABLE ? "stable" : "pending", i));
        /* clean up entries that have just been expired */
	    /* 如果指定的 arp 映射项驻留在 arp 地址表中的时间超过预设定的阈值，则把它从 arp 地址表中移除 */
        etharp_free_entry(i);
      } else if (arp_table[i].state == ETHARP_STATE_STABLE_REREQUESTING_1) {
        /* Don't send more than one request every 2 seconds. */
        arp_table[i].state = ETHARP_STATE_STABLE_REREQUESTING_2;
      } else if (arp_table[i].state == ETHARP_STATE_STABLE_REREQUESTING_2) {
        /* Reset state to stable, so that the next transmitted packet will
           re-send an ARP request. */
        arp_table[i].state = ETHARP_STATE_STABLE;
      } else if (arp_table[i].state == ETHARP_STATE_PENDING) {
        /* still pending, resend an ARP query */
        etharp_request(arp_table[i].netif, &arp_table[i].ipaddr);
      }
    }
  }
}

/**
 * Search the ARP table for a matching or new entry.
 *
 * If an IP address is given, return a pending or stable ARP entry that matches
 * the address. If no match is found, create a new entry with this address set,
 * but in state ETHARP_EMPTY. The caller must check and possibly change the
 * state of the returned entry.
 *
 * If ipaddr is NULL, return a initialized new entry in state ETHARP_EMPTY.
 *
 * In all cases, attempt to create new entries from an empty entry. If no
 * empty entries are available and ETHARP_FLAG_TRY_HARD flag is set, recycle
 * old entries. Heuristic choose the least important entry for recycling.
 *
 * @param ipaddr IP address to find in ARP cache, or to add if not found.
 * @param flags See @ref etharp_state
 * @param netif netif related to this address (used for NETIF_HWADDRHINT)
 *
 * @return The ARP entry index that matched or is created, ERR_MEM if no
 * entry is found or could be recycled.
 */
/*********************************************************************************************************
** 函数名称: etharp_find_entry
** 功能描述: 从当前协议栈的 arp 地址映射表中查找一个和指定 IPv4 地址匹配的 arp 映射项，如果当前 arp
**		   : 映射表中没有和我们指定信息匹配的 arp 映射项，则根据当前 arp 映射表状态及 flags 参数标志
**         : 执行如下不同操作：
**		   : 1. 如果 arp 映射表没满
**         :    a. 如果在参数 flags 中“设置了” ETHARP_FLAG_FIND_ONLY 标志，则直接返回 ERR_MEM
**		   :    b. 如果在参数 flags 中“没设置” ETHARP_FLAG_FIND_ONLY 标志，则为我们指定的 IPv4 地址创建
**         :       一个新的 arp 映射项并返回这个映射项的索引值
**		   : 2. 如果 arp 映射表满了
**		   :    a. 如果在参数 flags 中“设置了” ETHARP_FLAG_FIND_ONLY 标志，则直接返回 ERR_MEM
**		   :    b. 如果在参数 flags 中“没设置” ETHARP_FLAG_FIND_ONLY 标志也“没设置” ETHARP_FLAG_TRY_HARD
**		   :       标志，则直接返回 ERR_MEM
**		   :    c. 如果在参数 flags 中“没设置” ETHARP_FLAG_FIND_ONLY 标志但是“设置了” ETHARP_FLAG_TRY_HARD
**		   :       标志，则根据 oldest stable entry -> oldest pending entry without queued packets -> 
**         :       oldest pending entry with queued packets 的顺序选择一个已经存在的 arp 映射项回收，然后
**         :       在回收的这个位置为我们指定的 IPv4 地址创建一个新的 arp 映射项，并返回这个映射项的索引值
**         :      （因为这个 arp 映射项目前只有 IPv4 地址，所以是不完整的）
** 输	 入: ipaddr - 要查找的 arp 映射项的 IPv4 地址
**         : flags - 查找时使用的标志
**         : netif - 要查找的 arp 映射项所属网络接口指针
** 输	 出: i > 0 - 找到的 arp 映射项在 arp 映射表中的索引值（可能是刚刚创建的，所以还没有 MAC 地址信息）
**         : i < 0 - 没找到指定的 arp 映射项
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static s16_t
etharp_find_entry(const ip4_addr_t *ipaddr, u8_t flags, struct netif *netif)
{
  s16_t old_pending = ARP_TABLE_SIZE, old_stable = ARP_TABLE_SIZE;

  /* 记录当前协议栈内，在 arp 地址映射表中第一个处于 ETHARP_STATE_EMPTY 状态的 arp 映射项的索引值 */
  s16_t empty = ARP_TABLE_SIZE;
  
  s16_t i = 0;
  /* oldest entry with packets on queue */
  s16_t old_queue = ARP_TABLE_SIZE;
  
  /* its age */
  u16_t age_queue = 0, age_pending = 0, age_stable = 0;

  LWIP_UNUSED_ARG(netif);

  /**
   * a) do a search through the cache, remember candidates
   * b) select candidate entry
   * c) create new entry
   */

  /* a) in a single search sweep, do all of this
   * 1) remember the first empty entry (if any)
   * 2) remember the oldest stable entry (if any)
   * 3) remember the oldest pending entry without queued packets (if any)
   * 4) remember the oldest pending entry with queued packets (if any)
   * 5) search for a matching IP entry, either pending or stable
   *    until 5 matches, or all entries are searched for.
   */

  for (i = 0; i < ARP_TABLE_SIZE; ++i) {
    u8_t state = arp_table[i].state;
	
    /* no empty entry found yet and now we do find one? */
    if ((empty == ARP_TABLE_SIZE) && (state == ETHARP_STATE_EMPTY)) {
      LWIP_DEBUGF(ETHARP_DEBUG, ("etharp_find_entry: found empty entry %d\n", (int)i));
	  
      /* remember first empty entry */
	  /* 记录 arp 映射表中第一个处于 ETHARP_STATE_EMPTY 状态的 arp 映射项索引 */
      empty = i;
    } else if (state != ETHARP_STATE_EMPTY) {
      LWIP_ASSERT("state == ETHARP_STATE_PENDING || state >= ETHARP_STATE_STABLE",
                  state == ETHARP_STATE_PENDING || state >= ETHARP_STATE_STABLE);
	  
      /* if given, does IP address match IP address in ARP entry? */
      if (ipaddr && ip4_addr_cmp(ipaddr, &arp_table[i].ipaddr)
#if ETHARP_TABLE_MATCH_NETIF
          && ((netif == NULL) || (netif == arp_table[i].netif))
#endif /* ETHARP_TABLE_MATCH_NETIF */
         ) {
        LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: found matching entry %d\n", (int)i));
        /* found exact IP address match, simply bail out */
		/* 如果找到了 IPv4 地址匹配且 netif 接口匹配的 arp 映射项，则返回这个映射项在 arp 映射表中的索引值 */
        return i;
      }
		 
      /* pending entry? */
      if (state == ETHARP_STATE_PENDING) {
        /* pending with queued packets? */
        if (arp_table[i].q != NULL) {
          if (arp_table[i].ctime >= age_queue) {
		  	/* 记录当前 arp 地址映射表中，处于 ETHARP_STATE_PENDING 状态且“有”还未发送的数据包中，驻留
		  	 * 时间最长的 arp 映射项在 arp 映射表中的索引值以及驻留时间 */
            old_queue = i;
            age_queue = arp_table[i].ctime;
          }
        } else
          /* pending without queued packets? */
        {
          if (arp_table[i].ctime >= age_pending) {		  	
		    /* 记录当前 arp 地址映射表中，处于 ETHARP_STATE_PENDING 状态且“没有”未发送的数据包中，驻留
		     * 时间最长的 arp 映射项在 arp 映射表中的索引值以及驻留时间 */
            old_pending = i;
            age_pending = arp_table[i].ctime;
          }
        }
        /* stable entry? */
      } else if (state >= ETHARP_STATE_STABLE) {
#if ETHARP_SUPPORT_STATIC_ENTRIES
        /* don't record old_stable for static entries since they never expire */
        if (state < ETHARP_STATE_STATIC)
#endif /* ETHARP_SUPPORT_STATIC_ENTRIES */
        {
          /* remember entry with oldest stable entry in oldest, its age in maxtime */
          if (arp_table[i].ctime >= age_stable) {		  	
		   /* 记录当前 arp 地址映射表中，处于 ETHARP_STATE_STABLE 状态且驻留时间最长的 arp 映射项在 arp
			* 映射表中的索引值以及驻留时间 */
            old_stable = i;
            age_stable = arp_table[i].ctime;
          }
        }
      }
    }
  }
  /* { we have no match } => try to create a new entry */

  /* don't create new entry, only search? */
  /* 如果我们既没有设置 ETHARP_FLAG_TRY_HARD 标志，也没有设置 ETHARP_FLAG_FIND_ONLY 标志，那么
   * 在没找到我们指定的 IPv4 地址匹配的 arp 映射项时，如果 arp 地址映射表没满，则会为我们指定的
   * IPv4 地址创建一个新的 arp 映射项 */
  if (((flags & ETHARP_FLAG_FIND_ONLY) != 0) ||
      /* or no empty entry found and not allowed to recycle? */
      ((empty == ARP_TABLE_SIZE) && ((flags & ETHARP_FLAG_TRY_HARD) == 0))) {
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: no empty entry found and not allowed to recycle\n"));
    return (s16_t)ERR_MEM;
  }

  /* b) choose the least destructive entry to recycle:
   * 1) empty entry
   * 2) oldest stable entry
   * 3) oldest pending entry without queued packets
   * 4) oldest pending entry with queued packets
   *
   * { ETHARP_FLAG_TRY_HARD is set at this point }
   */

  /* 1) empty entry available? */
  if (empty < ARP_TABLE_SIZE) {
    i = empty;
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: selecting empty entry %d\n", (int)i));
  } else {
    /* 2) found recyclable stable entry? */
    if (old_stable < ARP_TABLE_SIZE) {
      /* recycle oldest stable*/
      i = old_stable;
      LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: selecting oldest stable entry %d\n", (int)i));
      /* no queued packets should exist on stable entries */
      LWIP_ASSERT("arp_table[i].q == NULL", arp_table[i].q == NULL);
      /* 3) found recyclable pending entry without queued packets? */
    } else if (old_pending < ARP_TABLE_SIZE) {
      /* recycle oldest pending */
      i = old_pending;
      LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: selecting oldest pending entry %d (without queue)\n", (int)i));
      /* 4) found recyclable pending entry with queued packets? */
    } else if (old_queue < ARP_TABLE_SIZE) {
      /* recycle oldest pending (queued packets are free in etharp_free_entry) */
      i = old_queue;
      LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: selecting oldest pending entry %d, freeing packet queue %p\n", (int)i, (void *)(arp_table[i].q)));
      /* no empty or recyclable entries found */
    } else {
      LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_find_entry: no empty or recyclable entries found\n"));
      return (s16_t)ERR_MEM;
    }

    /* { empty or recyclable entry found } */
    LWIP_ASSERT("i < ARP_TABLE_SIZE", i < ARP_TABLE_SIZE);
    etharp_free_entry(i);
  }

  LWIP_ASSERT("i < ARP_TABLE_SIZE", i < ARP_TABLE_SIZE);
  LWIP_ASSERT("arp_table[i].state == ETHARP_STATE_EMPTY",
              arp_table[i].state == ETHARP_STATE_EMPTY);

  /* IP address given? */
  /* 新创建了一个 arp 映射项，设置这个映射项的 IPv4 地址值 */
  if (ipaddr != NULL) {
    /* set IP address */
    ip4_addr_copy(arp_table[i].ipaddr, *ipaddr);
  }
  arp_table[i].ctime = 0;
#if ETHARP_TABLE_MATCH_NETIF
  arp_table[i].netif = netif;
#endif /* ETHARP_TABLE_MATCH_NETIF */
  return (s16_t)i;
}

/**
 * Update (or insert) a IP/MAC address pair in the ARP cache.
 *
 * If a pending entry is resolved, any queued packets will be sent
 * at this point.
 *
 * @param netif netif related to this entry (used for NETIF_ADDRHINT)
 * @param ipaddr IP address of the inserted ARP entry.
 * @param ethaddr Ethernet address of the inserted ARP entry.
 * @param flags See @ref etharp_state
 *
 * @return
 * - ERR_OK Successfully updated ARP cache.
 * - ERR_MEM If we could not add a new ARP entry when ETHARP_FLAG_TRY_HARD was set.
 * - ERR_ARG Non-unicast address given, those will not appear in ARP cache.
 *
 * @see pbuf_free()
 */
/*********************************************************************************************************
** 函数名称: etharp_update_arp_entry
** 功能描述: 更新指定的 IPv4 地址对应的 arp 映射项内容，在更新成功后，把在这个 arp 映射项的数据队列
**         : 中的数据包通过以太网 (ethernet_output) 发送出去
** 输	 入: netif - 和 arp 映射项相关的网络接口
**         : ipaddr - 要更新的 arp 映射项的 IPv4 地址
**         : ethaddr - 要更新的 arp 映射项的 MAC 地址
**         : flags - 查找 arp 映射项时使用的标志
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
etharp_update_arp_entry(struct netif *netif, const ip4_addr_t *ipaddr, struct eth_addr *ethaddr, u8_t flags)
{
  s16_t i;
  LWIP_ASSERT("netif->hwaddr_len == ETH_HWADDR_LEN", netif->hwaddr_len == ETH_HWADDR_LEN);
  LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_update_arp_entry: %"U16_F".%"U16_F".%"U16_F".%"U16_F" - %02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F"\n",
              ip4_addr1_16(ipaddr), ip4_addr2_16(ipaddr), ip4_addr3_16(ipaddr), ip4_addr4_16(ipaddr),
              (u16_t)ethaddr->addr[0], (u16_t)ethaddr->addr[1], (u16_t)ethaddr->addr[2],
              (u16_t)ethaddr->addr[3], (u16_t)ethaddr->addr[4], (u16_t)ethaddr->addr[5]));
  
  /* non-unicast address? */
  if (ip4_addr_isany(ipaddr) ||
      ip4_addr_isbroadcast(ipaddr, netif) ||
      ip4_addr_ismulticast(ipaddr)) {
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_update_arp_entry: will not add non-unicast IP address to ARP cache\n"));
    return ERR_ARG;
  }
	  
  /* find or create ARP entry */
  i = etharp_find_entry(ipaddr, flags, netif);
  /* bail out if no entry could be found */
  if (i < 0) {
    return (err_t)i;
  }

/* 处理刚刚找到或创建的 arp 映射项状态值 */
#if ETHARP_SUPPORT_STATIC_ENTRIES
  if (flags & ETHARP_FLAG_STATIC_ENTRY) {
    /* record static type */
    arp_table[i].state = ETHARP_STATE_STATIC;
  } else if (arp_table[i].state == ETHARP_STATE_STATIC) {
    /* found entry is a static type, don't overwrite it */
    return ERR_VAL;
  } else
#endif /* ETHARP_SUPPORT_STATIC_ENTRIES */
  {
    /* mark it stable */
    arp_table[i].state = ETHARP_STATE_STABLE;
  }

  /* record network interface */
  arp_table[i].netif = netif;
  /* insert in SNMP ARP index tree */
  mib2_add_arp_entry(netif, &arp_table[i].ipaddr);

  LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_update_arp_entry: updating stable entry %"S16_F"\n", i));
  
  /* update address */
  /* 设置刚刚找到或创建的 arp 映射项中的物理地址信息 */
  SMEMCPY(&arp_table[i].ethaddr, ethaddr, ETH_HWADDR_LEN);

  /* reset time stamp */
  /* 在每次更新 arp 映射项的物理地址信息时，都清空这个 arp 映射项的 ctime 值，避免这个
   * arp 映射项在 arp 定时器超时处理函数中被回收移除 */
  arp_table[i].ctime = 0;
  
  /* this is where we will send out queued packets! */
  /* 因为上面已经设置了当前指定的 arp 映射项的 IPv4 地址以及与其对应的物理地址
   * 所以我们现在有了完成的 arp 映射项，所以可以把之前放在这个 arp 映射项的数据
   * 队列上的数据包向外发送了 */
#if ARP_QUEUEING
  while (arp_table[i].q != NULL) {
    struct pbuf *p;
    /* remember remainder of queue */
    struct etharp_q_entry *q = arp_table[i].q;
    /* pop first item off the queue */
    arp_table[i].q = q->next;
    /* get the packet pointer */
    p = q->p;
    /* now queue entry can be freed */
    memp_free(MEMP_ARP_QUEUE, q);
#else /* ARP_QUEUEING */
  if (arp_table[i].q != NULL) {
    struct pbuf *p = arp_table[i].q;
    arp_table[i].q = NULL;
#endif /* ARP_QUEUEING */

    /* send the queued IP packet */
	/* 把从当前 arp 映射项上取出的一个完整数据包（pbuf）通过以太网向外发送 */
    ethernet_output(netif, p, (struct eth_addr *)(netif->hwaddr), ethaddr, ETHTYPE_IP);
    /* free the queued IP packet */
    pbuf_free(p);
  }
  return ERR_OK;
}

#if ETHARP_SUPPORT_STATIC_ENTRIES
/** Add a new static entry to the ARP table. If an entry exists for the
 * specified IP address, this entry is overwritten.
 * If packets are queued for the specified IP address, they are sent out.
 *
 * @param ipaddr IP address for the new static entry
 * @param ethaddr ethernet address for the new static entry
 * @return See return values of etharp_add_static_entry
 */
/*********************************************************************************************************
** 函数名称: etharp_add_static_entry
** 功能描述: 向 arp 地址映射表中添加一个指定映射关系的 ETHARP_STATE_STATIC 类型的 arp 映射项，如果在
**         : arp 地址映射表中已经有了和指定的 IPv4 地址对应的 arp 映射项，则更新这个映射项的内容，如果
**         : 在指定的映射项的数据队列中有未发送的数据包，则通过以太网发送这些数据
** 输	 入: ipaddr - 要添加的 arp 映射项的 IPv4 地址
**		   : ethaddr - 要添加的 arp 映射项的 MAC 地址
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
etharp_add_static_entry(const ip4_addr_t *ipaddr, struct eth_addr *ethaddr)
{
  struct netif *netif;
  LWIP_ASSERT_CORE_LOCKED();
  LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_add_static_entry: %"U16_F".%"U16_F".%"U16_F".%"U16_F" - %02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F":%02"X16_F"\n",
              ip4_addr1_16(ipaddr), ip4_addr2_16(ipaddr), ip4_addr3_16(ipaddr), ip4_addr4_16(ipaddr),
              (u16_t)ethaddr->addr[0], (u16_t)ethaddr->addr[1], (u16_t)ethaddr->addr[2],
              (u16_t)ethaddr->addr[3], (u16_t)ethaddr->addr[4], (u16_t)ethaddr->addr[5]));

  /* 判断指定的 IPv4 地址在当前的系统环境中是否有可使用的路由网络接口 */
  netif = ip4_route(ipaddr);
  if (netif == NULL) {
    return ERR_RTE;
  }

  return etharp_update_arp_entry(netif, ipaddr, ethaddr, ETHARP_FLAG_TRY_HARD | ETHARP_FLAG_STATIC_ENTRY);
}

/** Remove a static entry from the ARP table previously added with a call to
 * etharp_add_static_entry.
 *
 * @param ipaddr IP address of the static entry to remove
 * @return ERR_OK: entry removed
 *         ERR_MEM: entry wasn't found
 *         ERR_ARG: entry wasn't a static entry but a dynamic one
 */
/*********************************************************************************************************
** 函数名称: etharp_remove_static_entry
** 功能描述: 从当前 arp 映射表中移除指定的 IPv4 地址对应的 arp 映射项以及这个映射项数据队列中未发送的数据
** 输	 入: ipaddr - 要移除的 arp 映射项的 IPv4 地址
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
etharp_remove_static_entry(const ip4_addr_t *ipaddr)
{
  s16_t i;
  LWIP_ASSERT_CORE_LOCKED();
  LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_remove_static_entry: %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
              ip4_addr1_16(ipaddr), ip4_addr2_16(ipaddr), ip4_addr3_16(ipaddr), ip4_addr4_16(ipaddr)));

  /* find or create ARP entry */
  i = etharp_find_entry(ipaddr, ETHARP_FLAG_FIND_ONLY, NULL);
  /* bail out if no entry could be found */
  if (i < 0) {
    return (err_t)i;
  }

  if (arp_table[i].state != ETHARP_STATE_STATIC) {
    /* entry wasn't a static entry, cannot remove it */
    return ERR_ARG;
  }
  /* entry found, free it */
  etharp_free_entry(i);
  return ERR_OK;
}
#endif /* ETHARP_SUPPORT_STATIC_ENTRIES */

/**
 * Remove all ARP table entries of the specified netif.
 *
 * @param netif points to a network interface
 */
/*********************************************************************************************************
** 函数名称: etharp_cleanup_netif
** 功能描述: 清空系统内和指定网络接口相关的所有 arp 缓存项
** 输	 入: netif - 需要清空 arp 数据的网络结构指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
etharp_cleanup_netif(struct netif *netif)
{
  int i;

  for (i = 0; i < ARP_TABLE_SIZE; ++i) {
    u8_t state = arp_table[i].state;
    if ((state != ETHARP_STATE_EMPTY) && (arp_table[i].netif == netif)) {
      etharp_free_entry(i);
    }
  }
}

/**
 * Finds (stable) ethernet/IP address pair from ARP table
 * using interface and IP address index.
 * @note the addresses in the ARP table are in network order!
 *
 * @param netif points to interface index
 * @param ipaddr points to the (network order) IP address index
 * @param eth_ret points to return pointer
 * @param ip_ret points to return pointer
 * @return table index if found, -1 otherwise
 */
/*********************************************************************************************************
** 函数名称: etharp_find_addr
** 功能描述: 从当前系统的 arp 映射表中查找和指定的 IPv4 地址对应的 arp 映射项，并返回他们的地址信息
** 输	 入: netif - 和 IPv4 地址相关的网络接口指针
**         : ipaddr - 要查找的 IPv4 地址的映射项
**         : eth_ret - 返回找到的 arp 映射项中的物理地址信息
**         : ip_ret - 返回找到的 arp 映射项中的 IPv4 地址信息
** 输	 出: i >= 0 - 找到的 arp 映射项中索引值
**         : -1 - 没找到和指定的 IPv4 地址对应的 arp 映射项
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
ssize_t
etharp_find_addr(struct netif *netif, const ip4_addr_t *ipaddr,
                 struct eth_addr **eth_ret, const ip4_addr_t **ip_ret)
{
  s16_t i;

  LWIP_ASSERT("eth_ret != NULL && ip_ret != NULL",
              eth_ret != NULL && ip_ret != NULL);

  LWIP_UNUSED_ARG(netif);

  i = etharp_find_entry(ipaddr, ETHARP_FLAG_FIND_ONLY, netif);
  if ((i >= 0) && (arp_table[i].state >= ETHARP_STATE_STABLE)) {
    *eth_ret = &arp_table[i].ethaddr;
    *ip_ret = &arp_table[i].ipaddr;
    return i;
  }
  return -1;
}

/**
 * Possibility to iterate over stable ARP table entries
 *
 * @param i entry number, 0 to ARP_TABLE_SIZE
 * @param ipaddr return value: IP address
 * @param netif return value: points to interface
 * @param eth_ret return value: ETH address
 * @return 1 on valid index, 0 otherwise
 */
/*********************************************************************************************************
** 函数名称: etharp_get_entry
** 功能描述: 从当前系统的 arp 映射表中读取指定索引的 arp 映射项内容，并返回相关信息
** 输     入: i - 要读取的 arp 映射项的索引值
** 		   : ipaddr - arp 映射项的 IPv4 地址
**         : netif - arp 映射项的网络接口指针
** 		   : eth_ret - arp 映射项的物理地址
** 输     出: 1 - 读取成功
** 		   : 0 - 读取失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int
etharp_get_entry(size_t i, ip4_addr_t **ipaddr, struct netif **netif, struct eth_addr **eth_ret)
{
  LWIP_ASSERT("ipaddr != NULL", ipaddr != NULL);
  LWIP_ASSERT("netif != NULL", netif != NULL);
  LWIP_ASSERT("eth_ret != NULL", eth_ret != NULL);

  if ((i < ARP_TABLE_SIZE) && (arp_table[i].state >= ETHARP_STATE_STABLE)) {
    *ipaddr  = &arp_table[i].ipaddr;
    *netif   = arp_table[i].netif;
    *eth_ret = &arp_table[i].ethaddr;
    return 1;
  } else {
    return 0;
  }
}

/**
 * Responds to ARP requests to us. Upon ARP replies to us, add entry to cache
 * send out queued IP packets. Updates cache with snooped address pairs.
 *
 * Should be called for incoming ARP packets. The pbuf in the argument
 * is freed by this function.
 *
 * @param p The ARP packet that arrived on netif. Is freed by this function.
 * @param netif The lwIP network interface on which the ARP packet pbuf arrived.
 *
 * @see pbuf_free()
 */
/*********************************************************************************************************
** 函数名称: etharp_input
** 功能描述: 处理以太网接收到的 arp 数据包，首先校验 arp 数据“包头”信息，并根据数据包信息处理本地的 
**         : arp 映射表内容，然后再根据 arp 操作码（ARP_REQUEST or ARP_REPLY）执行相应逻辑
** 注     释: arp 数据包格式：https://www.cnblogs.com/laojie4321/archive/2012/04/12/2444187.html
** 输	 入: p - 接收到的 arp 数据包
**		   : netif - 接收到 arp 数据包的网络接口
** 输     出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
etharp_input(struct pbuf *p, struct netif *netif)
{
  struct etharp_hdr *hdr;
  /* these are aligned properly, whereas the ARP header fields might not be */
  ip4_addr_t sipaddr, dipaddr;
  u8_t for_us;

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("netif != NULL", (netif != NULL), return;);

  hdr = (struct etharp_hdr *)p->payload;

  /* RFC 826 "Packet Reception": */
  /* 校验 arp 数据包中的“协议头”部分数据内容 */
  if ((hdr->hwtype != PP_HTONS(LWIP_IANA_HWTYPE_ETHERNET)) ||
      (hdr->hwlen != ETH_HWADDR_LEN) ||
      (hdr->protolen != sizeof(ip4_addr_t)) ||
      (hdr->proto != PP_HTONS(ETHTYPE_IP)))  {
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
                ("etharp_input: packet dropped, wrong hw type, hwlen, proto, protolen or ethernet type (%"U16_F"/%"U16_F"/%"U16_F"/%"U16_F")\n",
                 hdr->hwtype, (u16_t)hdr->hwlen, hdr->proto, (u16_t)hdr->protolen));
    ETHARP_STATS_INC(etharp.proterr);
    ETHARP_STATS_INC(etharp.drop);
    pbuf_free(p);
    return;
  }
  ETHARP_STATS_INC(etharp.recv);

#if LWIP_AUTOIP
  /* We have to check if a host already has configured our random
   * created link local address and continuously check if there is
   * a host with this IP-address so we can detect collisions */
  autoip_arp_reply(netif, hdr);
#endif /* LWIP_AUTOIP */

  /* Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers without
   * structure packing (not using structure copy which breaks strict-aliasing rules). */
  IPADDR_WORDALIGNED_COPY_TO_IP4_ADDR_T(&sipaddr, &hdr->sipaddr);
  IPADDR_WORDALIGNED_COPY_TO_IP4_ADDR_T(&dipaddr, &hdr->dipaddr);

  /* this interface is not configured? */
  /* 判断接收到的 arp 数据包是否是发送给我们的 */
  if (ip4_addr_isany_val(*netif_ip4_addr(netif))) {
    for_us = 0;
  } else {
    /* ARP packet directed to us? */
    for_us = (u8_t)ip4_addr_cmp(&dipaddr, netif_ip4_addr(netif));
  }

  /* ARP message directed to us?
      -> add IP address in ARP cache; assume requester wants to talk to us,
         can result in directly sending the queued packets for this host.
     ARP message not directed to us?
      ->  update the source IP address in the cache, if present */
  /* 根据接收到的 arp 数据包处理本地的 arp 映射表内容 */
  etharp_update_arp_entry(netif, &sipaddr, &(hdr->shwaddr),
                          for_us ? ETHARP_FLAG_TRY_HARD : ETHARP_FLAG_FIND_ONLY);

  /* now act on the message itself */
  switch (hdr->opcode) {
    /* ARP request? */
    /* 处理其他设备发送的 arp 请求操作 */
    case PP_HTONS(ARP_REQUEST):
      /* ARP request. If it asked for our address, we send out a
       * reply. In any case, we time-stamp any existing ARP entry,
       * and possibly send out an IP packet that was queued on it. */

      LWIP_DEBUGF (ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: incoming ARP request\n"));
      /* ARP request for our address? */
      if (for_us) {
        /* send ARP response */
	    /* 如果是别的设备向当前设备发送了一个 arp 请求信息，则给这个设备恢复一个 arp 响应数据包 */
        etharp_raw(netif,
                   (struct eth_addr *)netif->hwaddr, &hdr->shwaddr,
                   (struct eth_addr *)netif->hwaddr, netif_ip4_addr(netif),
                   &hdr->shwaddr, &sipaddr,
                   ARP_REPLY);
        /* we are not configured? */
      } else if (ip4_addr_isany_val(*netif_ip4_addr(netif))) {
        /* { for_us == 0 and netif->ip_addr.addr == 0 } */
        LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: we are unconfigured, ARP request ignored.\n"));
        /* request was not directed to us */
      } else {
        /* { for_us == 0 and netif->ip_addr.addr != 0 } */
        LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: ARP request was not for us.\n"));
      }
      break;

	/* 处理其他设备发送的 arp 回复操作 */
    case PP_HTONS(ARP_REPLY):
      /* ARP reply. We already updated the ARP cache earlier. */
      LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: incoming ARP reply\n"));
#if (LWIP_DHCP && DHCP_DOES_ARP_CHECK)
      /* DHCP wants to know about ARP replies from any host with an
       * IP address also offered to us by the DHCP server. We do not
       * want to take a duplicate IP address on a single network.
       * @todo How should we handle redundant (fail-over) interfaces? */
      dhcp_arp_reply(netif, &sipaddr);
#endif /* (LWIP_DHCP && DHCP_DOES_ARP_CHECK) */
      break;

    default:
      LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: ARP unknown opcode type %"S16_F"\n", lwip_htons(hdr->opcode)));
      ETHARP_STATS_INC(etharp.err);
      break;
  }
  /* free ARP packet */
  pbuf_free(p);
}

/** Just a small helper function that sends a pbuf to an ethernet address
 * in the arp_table specified by the index 'arp_idx'.
 */
/*********************************************************************************************************
** 函数名称: etharp_output_to_arp_index
** 功能描述: 把指定的网络数据包通过指定的以太网接口发送到指定的 arp 映射项代表的目的地址处
** 注     释: 在每次发送数据之前会对指定的、处于                   ETHARP_STATE_STABLE 状态的 arp 映射项驻留时间做判断
**         : 如果驻留时间超过了设定的阈值，则发送一个相应的 arp 请求
** 输	 入: netif - 发送指定网络数据包的网络接口指针
**		   : q - 要发送的网络数据包
**         : arp_idx - 发送的网络数据包的目的地址在 arp 映射表中的索引值
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
etharp_output_to_arp_index(struct netif *netif, struct pbuf *q, netif_addr_idx_t arp_idx)
{
  LWIP_ASSERT("arp_table[arp_idx].state >= ETHARP_STATE_STABLE",
              arp_table[arp_idx].state >= ETHARP_STATE_STABLE);
  
  /* if arp table entry is about to expire: re-request it,
     but only if its state is ETHARP_STATE_STABLE to prevent flooding the
     network with ARP requests if this address is used frequently. */
  /* 如果指定的 arp 映射项即将超时，则对这个 arp 的 IPv4 地址重新发送一个 arp 请求信息
   * 来更新 arp 映射项内容。另外，为了防止因发送大量 arp 请求占用网络资源，所以只对处于
   * ETHARP_STATE_STABLE 状态的 arp 映射项做相关处理 */
  if (arp_table[arp_idx].state == ETHARP_STATE_STABLE) {
    if (arp_table[arp_idx].ctime >= ARP_AGE_REREQUEST_USED_BROADCAST) {
      /* issue a standard request using broadcast */
      if (etharp_request(netif, &arp_table[arp_idx].ipaddr) == ERR_OK) {
        arp_table[arp_idx].state = ETHARP_STATE_STABLE_REREQUESTING_1;
      }
    } else if (arp_table[arp_idx].ctime >= ARP_AGE_REREQUEST_USED_UNICAST) {
      /* issue a unicast request (for 15 seconds) to prevent unnecessary broadcast */
      if (etharp_request_dst(netif, &arp_table[arp_idx].ipaddr, &arp_table[arp_idx].ethaddr) == ERR_OK) {
        arp_table[arp_idx].state = ETHARP_STATE_STABLE_REREQUESTING_1;
      }
    }
  }

  /* 把指定的网络数据包通过指定的以太网接口发送到指定的 arp 映射项代表的目的地址处 */
  return ethernet_output(netif, q, (struct eth_addr *)(netif->hwaddr), &arp_table[arp_idx].ethaddr, ETHTYPE_IP);
}

/**
 * Resolve and fill-in Ethernet address header for outgoing IP packet.
 *
 * For IP multicast and broadcast, corresponding Ethernet addresses
 * are selected and the packet is transmitted on the link.
 *
 * For unicast addresses, the packet is submitted to etharp_query(). In
 * case the IP address is outside the local network, the IP address of
 * the gateway is used.
 *
 * @param netif The lwIP network interface which the IP packet will be sent on.
 * @param q The pbuf(s) containing the IP packet to be sent.
 * @param ipaddr The IP address of the packet destination.
 *
 * @return
 * - ERR_RTE No route to destination (no gateway to external networks),
 * or the return type of either etharp_query() or ethernet_output().
 */
/*********************************************************************************************************
** 函数名称: etharp_output
** 功能描述: 把指定的网络数据包通过指定的以太网接口发送给指定的 IPv4 设备，如果发送的目的 IPv4 地址是
**         : 广播地址或者是多播地址，则通过以太网发送函数直接发送网络数据包，如果发送的目的 IPv4 地址
**         : 是单播地址，则需要执行的步骤如下：
**         : 1. 如果目的 IPv4 地址和指定的网络接口不在同一个网段内并且目的 IPv4 地址不是 linklocal 地址
**         :    则通过路由信息为目的地址找出一个合适的网关，然后把这个数据包发送到网关设备处
**         : 2. 如果缓存的 arp 地址信息和当前目的地址“匹配”，则通过缓冲的 arp 映射项直接发送网络数据包
**         : 3. 如果缓存的 arp 地址信息和当前目的地址“不匹配”，则通过查询 arp 映射表找到和当前目的地址
**         :    匹配的 arp 映射项然后把指定的网络数据包发送到这个 arp 映射项代表的目的 MAC 地址处
**         : 4. 如果当前系统内没有和我们指定的目的地址相关的 arp 映射项内容，则创建一个新的 arp 映射项
**         :    并发送一个 arp 请求，然后把需要发送的网络数据包添加到新创建的 arp 映射项的数据队列上
** 输	 入: netif - 发送指定网络数据包的网络接口指针
**		   : q - 要发送的网络数据包
**		   : ipaddr - 目的设备 IPv4 地址
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
etharp_output(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr)
{
  const struct eth_addr *dest;
  struct eth_addr mcastaddr;
  const ip4_addr_t *dst_addr = ipaddr;

  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ASSERT("netif != NULL", netif != NULL);
  LWIP_ASSERT("q != NULL", q != NULL);
  LWIP_ASSERT("ipaddr != NULL", ipaddr != NULL);

  /* Determine on destination hardware address. Broadcasts and multicasts
   * are special, other IP addresses are looked up in the ARP table. */

  /* broadcast destination IP address? */
  if (ip4_addr_isbroadcast(ipaddr, netif)) {
    /* broadcast on Ethernet also */
    dest = (const struct eth_addr *)&ethbroadcast;
    /* multicast destination IP address? */
  } else if (ip4_addr_ismulticast(ipaddr)) {
    /* Hash IP multicast address to MAC address.*/
    mcastaddr.addr[0] = LL_IP4_MULTICAST_ADDR_0;
    mcastaddr.addr[1] = LL_IP4_MULTICAST_ADDR_1;
    mcastaddr.addr[2] = LL_IP4_MULTICAST_ADDR_2;
    mcastaddr.addr[3] = ip4_addr2(ipaddr) & 0x7f;
    mcastaddr.addr[4] = ip4_addr3(ipaddr);
    mcastaddr.addr[5] = ip4_addr4(ipaddr);
    /* destination Ethernet address is multicast */
    dest = &mcastaddr;
    /* unicast destination IP address? */
  } else {
    netif_addr_idx_t i;
    /* outside local network? if so, this can neither be a global broadcast nor
       a subnet broadcast. */
    /* 如果目的 IPv4 地址和指定的网络接口不在同一个网段内并且目的 IPv4 地址不是 linklocal 地址
     * 则通过路由信息为目的地址找出一个合适的网关，然后把这个数据包发送到网关设备处 */
    if (!ip4_addr_netcmp(ipaddr, netif_ip4_addr(netif), netif_ip4_netmask(netif)) &&
        !ip4_addr_islinklocal(ipaddr)) {
        
#if LWIP_AUTOIP
      struct ip_hdr *iphdr = LWIP_ALIGNMENT_CAST(struct ip_hdr *, q->payload);
      /* According to RFC 3297, chapter 2.6.2 (Forwarding Rules), a packet with
         a link-local source address must always be "directly to its destination
         on the same physical link. The host MUST NOT send the packet to any
         router for forwarding". */
      if (!ip4_addr_islinklocal(&iphdr->src))
#endif /* LWIP_AUTOIP */

      {
#ifdef LWIP_HOOK_ETHARP_GET_GW
        /* For advanced routing, a single default gateway might not be enough, so get
           the IP address of the gateway to handle the current destination address. */
        /* 通过实现路由钩子函数，实现高级路由功能，如果这个钩子函数没实现，则使用当前网络接口默认网关 */
        dst_addr = LWIP_HOOK_ETHARP_GET_GW(netif, ipaddr);
        if (dst_addr == NULL)
#endif /* LWIP_HOOK_ETHARP_GET_GW */
        {
          /* interface has default gateway? */
          if (!ip4_addr_isany_val(*netif_ip4_gw(netif))) {
            /* send to hardware address of default gateway IP address */
            dst_addr = netif_ip4_gw(netif);
            /* no default gateway available */
          } else {
            /* no route to destination error (default gateway missing) */
            return ERR_RTE;
          }
        }
      }
    }

/* 如果缓存的 arp 地址信息和当前目的地址匹配，则通过缓冲的 arp 映射项直接发送网络数据包，这样在 arp 映射表比较大
 * 且我们持续向同一个设备发送数据的时候，会提高 arp 命中效率 */
#if LWIP_NETIF_HWADDRHINT
    if (netif->hints != NULL) {
      /* per-pcb cached entry was given */
      netif_addr_idx_t etharp_cached_entry = netif->hints->addr_hint;
      if (etharp_cached_entry < ARP_TABLE_SIZE) {
#endif /* LWIP_NETIF_HWADDRHINT */
        if ((arp_table[etharp_cached_entry].state >= ETHARP_STATE_STABLE) &&
#if ETHARP_TABLE_MATCH_NETIF
            (arp_table[etharp_cached_entry].netif == netif) &&
#endif
            (ip4_addr_cmp(dst_addr, &arp_table[etharp_cached_entry].ipaddr))) {
          /* the per-pcb-cached entry is stable and the right one! */
          ETHARP_STATS_INC(etharp.cachehit);
          return etharp_output_to_arp_index(netif, q, etharp_cached_entry);
        }
#if LWIP_NETIF_HWADDRHINT
      }
    }
#endif /* LWIP_NETIF_HWADDRHINT */

    /* find stable entry: do this here since this is a critical path for
       throughput and etharp_find_entry() is kind of slow */
    /* 如果 arp 缓存没命中，则通过查询 arp 映射表找到和当前目的地址匹配的 arp 映射项
     * 然后把指定的网络数据包发送到这个 arp 映射项代表的目的 MAC 地址处 */
    for (i = 0; i < ARP_TABLE_SIZE; i++) {
      if ((arp_table[i].state >= ETHARP_STATE_STABLE) &&
#if ETHARP_TABLE_MATCH_NETIF
          (arp_table[i].netif == netif) &&
#endif
          (ip4_addr_cmp(dst_addr, &arp_table[i].ipaddr))) {
        /* found an existing, stable entry */
        ETHARP_SET_ADDRHINT(netif, i);
        return etharp_output_to_arp_index(netif, q, i);
      }
    }
    /* no stable entry found, use the (slower) query function:
       queue on destination Ethernet address belonging to ipaddr */
    /* 如果当前系统内没有和我们指定的目的地址相关的 arp 映射项内容，则创建一个新的 
     * arp 映射项并发送一个 arp 请求，然后把需要发送的网络数据包添加到新创建的 arp
     * 映射项的数据队列上 */
    return etharp_query(netif, dst_addr, q);
  }

  /* continuation for multicast/broadcast destinations */
  /* obtain source Ethernet address of the given interface */
  /* send packet directly on the link */
  /* 如果发送的目的 IPv4 地址是广播地址或者是多播地址，则通过以太网发送函数直接发送网络数据包 */
  return ethernet_output(netif, q, (struct eth_addr *)(netif->hwaddr), dest, ETHTYPE_IP);
}

/**
 * Send an ARP request for the given IP address and/or queue a packet.
 *
 * If the IP address was not yet in the cache, a pending ARP cache entry
 * is added and an ARP request is sent for the given address. The packet
 * is queued on this entry.
 *
 * If the IP address was already pending in the cache, a new ARP request
 * is sent for the given address. The packet is queued on this entry.
 *
 * If the IP address was already stable in the cache, and a packet is
 * given, it is directly sent and no ARP request is sent out.
 *
 * If the IP address was already stable in the cache, and no packet is
 * given, an ARP request is sent out.
 *
 * @param netif The lwIP network interface on which ipaddr
 * must be queried for.
 * @param ipaddr The IP address to be resolved.
 * @param q If non-NULL, a pbuf that must be delivered to the IP address.
 * q is not freed by this function.
 *
 * @note q must only be ONE packet, not a packet queue!
 *
 * @return
 * - ERR_BUF Could not make room for Ethernet header.
 * - ERR_MEM Hardware address unknown, and no more ARP entries available
 *   to query for address or queue the packet.
 * - ERR_MEM Could not queue packet due to memory shortage.
 * - ERR_RTE No route to destination (no gateway to external networks).
 * - ERR_ARG Non-unicast address given, those will not appear in ARP cache.
 *
 */
/*********************************************************************************************************
** 函数名称: etharp_query
** 功能描述: 如果指定的 IPv4 地址在当前系统的 arp 映射表中有与其对饮的 arp 映射项，则把指定的网络数据包
**         : 发送到这个 arp 映射项表示的目的 MAC 地址处，如果指定的 IPv4 地址在当前系统的 arp 映射表中
**         : 没有对应的 arp 映射项，则创建一个与其对应的新的 arp 映射项，然后发送一个 arp 请求数据，并把
**         : 需要发送的网络数据包添加到新创建的 arp 映射项的数据队列中
** 输	 入: netif - 发送 arp 请求的网络接口指针
**		   : ipaddr - 需要查询 arp 请求 IPv4 地址
**		   : q - 需要放到 arp 映射项数据队列中的网络数据包
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
etharp_query(struct netif *netif, const ip4_addr_t *ipaddr, struct pbuf *q)
{
  struct eth_addr *srcaddr = (struct eth_addr *)netif->hwaddr;
  err_t result = ERR_MEM;
  int is_new_entry = 0;
  s16_t i_err;
  netif_addr_idx_t i;

  /* non-unicast address? */
  if (ip4_addr_isbroadcast(ipaddr, netif) ||
      ip4_addr_ismulticast(ipaddr) ||
      ip4_addr_isany(ipaddr)) {
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_query: will not add non-unicast IP address to ARP cache\n"));
    return ERR_ARG;
  }

  /* find entry in ARP cache, ask to create entry if queueing packet */
  /* 从当前系统的 arp 地址映射表中查询指定的目的 IPv4 地址对应的 arp 映射项，如果没有与其对应的
   * arp 映射项，则尝试创建一个与其对应的新的                   arp 映射项 */
  i_err = etharp_find_entry(ipaddr, ETHARP_FLAG_TRY_HARD, netif);

  /* could not find or create entry? */
  if (i_err < 0) {
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_query: could not create ARP entry\n"));
    if (q) {
      LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_query: packet dropped\n"));
      ETHARP_STATS_INC(etharp.memerr);
    }
    return (err_t)i_err;
  }
  LWIP_ASSERT("type overflow", (size_t)i_err < NETIF_ADDR_IDX_MAX);
  i = (netif_addr_idx_t)i_err;

  /* mark a fresh entry as pending (we just sent a request) */
  if (arp_table[i].state == ETHARP_STATE_EMPTY) {
    is_new_entry = 1;
    arp_table[i].state = ETHARP_STATE_PENDING;
    /* record network interface for re-sending arp request in etharp_tmr */
    arp_table[i].netif = netif;
  }

  /* { i is either a STABLE or (new or existing) PENDING entry } */
  LWIP_ASSERT("arp_table[i].state == PENDING or STABLE",
              ((arp_table[i].state == ETHARP_STATE_PENDING) ||
               (arp_table[i].state >= ETHARP_STATE_STABLE)));

  /* do we have a new entry? or an implicit query request? */
  if (is_new_entry || (q == NULL)) {
    /* try to resolve it; send out ARP request */
    /* 对指定的 IPv4 地址发送一个 arp 请求信息 */
    result = etharp_request(netif, ipaddr);
    if (result != ERR_OK) {
      /* ARP request couldn't be sent */
      /* We don't re-send arp request in etharp_tmr, but we still queue packets,
         since this failure could be temporary, and the next packet calling
         etharp_query again could lead to sending the queued packets. */
    }
    if (q == NULL) {
      return result;
    }
  }

  /* packet given? */
  LWIP_ASSERT("q != NULL", q != NULL);
  /* stable entry? */
  if (arp_table[i].state >= ETHARP_STATE_STABLE) {
    /* we have a valid IP->Ethernet address mapping */
    /* 如果命中了 arp 映射项，则更新 arp 缓存内容为命中的那个 */
    ETHARP_SET_ADDRHINT(netif, i);
    /* send the packet */
    result = ethernet_output(netif, q, srcaddr, &(arp_table[i].ethaddr), ETHTYPE_IP);
    /* pending entry? (either just created or already pending */
  } else if (arp_table[i].state == ETHARP_STATE_PENDING) {
    /* entry is still pending, queue the given packet 'q' */
    struct pbuf *p;
    int copy_needed = 0;
    /* IF q includes a pbuf that must be copied, copy the whole chain into a
     * new PBUF_RAM. See the definition of PBUF_NEEDS_COPY for details. */
    p = q;
    while (p) {
      LWIP_ASSERT("no packet queues allowed!", (p->len != p->tot_len) || (p->next == 0));
      if (PBUF_NEEDS_COPY(p)) {
        copy_needed = 1;
        break;
      }
      p = p->next;
    }
    if (copy_needed) {
      /* copy the whole packet into new pbufs */
      p = pbuf_clone(PBUF_LINK, PBUF_RAM, q);
    } else {
      /* referencing the old pbuf is enough */
      p = q;
      pbuf_ref(p);
    }
	
    /* packet could be taken over? */
    /* 把需要发送的网络数据包添加到当前 arp 映射项的数据队列中 */
	if (p != NULL) {
      /* queue packet ... */
#if ARP_QUEUEING
      struct etharp_q_entry *new_entry;

      /* allocate a new arp queue entry */
      /* 从 lwip 内存池中申请一个 arp 数据队列项结构 */
      new_entry = (struct etharp_q_entry *)memp_malloc(MEMP_ARP_QUEUE);
      if (new_entry != NULL) {
        unsigned int qlen = 0;
        new_entry->next = 0;
        new_entry->p = p;
        if (arp_table[i].q != NULL) {
          /* queue was already existent, append the new entry to the end */
          struct etharp_q_entry *r;
          r = arp_table[i].q;
          qlen++;
          while (r->next != NULL) {
            r = r->next;
            qlen++;
          }
		  /* 把新的网络数据包插入到链表尾部 */
          r->next = new_entry;
        } else {
          /* queue did not exist, first item in queue */
          arp_table[i].q = new_entry;
        }

#if ARP_QUEUE_LEN
        /* 如果当前 arp 映射项的数据队列上的网络数据包“包数”超过了预先设定的阈值
         * 则把“最旧”的数据包从中移除并释放，因为我们会把新的数据包插入到链表尾部
         * 所以最旧的数据包就是链表头部位置的那个数据包 */
        if (qlen >= ARP_QUEUE_LEN) {
          struct etharp_q_entry *old;
          old = arp_table[i].q;
          arp_table[i].q = arp_table[i].q->next;
          pbuf_free(old->p);
          memp_free(MEMP_ARP_QUEUE, old);
        }
#endif

        LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_query: queued packet %p on ARP entry %"U16_F"\n", (void *)q, i));
        result = ERR_OK;
      } else {
        /* the pool MEMP_ARP_QUEUE is empty */
        pbuf_free(p);
        LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_query: could not queue a copy of PBUF_REF packet %p (out of memory)\n", (void *)q));
        result = ERR_MEM;
      }
	  
#else /* ARP_QUEUEING */
      /* always queue one packet per ARP request only, freeing a previously queued packet */
      if (arp_table[i].q != NULL) {
        LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_query: dropped previously queued packet %p for ARP entry %"U16_F"\n", (void *)q, (u16_t)i));
        pbuf_free(arp_table[i].q);
      }
      arp_table[i].q = p;
      result = ERR_OK;
      LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_query: queued packet %p on ARP entry %"U16_F"\n", (void *)q, (u16_t)i));
#endif /* ARP_QUEUEING */
    } else {
      ETHARP_STATS_INC(etharp.memerr);
      LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_query: could not queue a copy of PBUF_REF packet %p (out of memory)\n", (void *)q));
      result = ERR_MEM;
    }
  }
  return result;
}

/**
 * Send a raw ARP packet (opcode and all addresses can be modified)
 *
 * @param netif the lwip network interface on which to send the ARP packet
 * @param ethsrc_addr the source MAC address for the ethernet header
 * @param ethdst_addr the destination MAC address for the ethernet header
 * @param hwsrc_addr the source MAC address for the ARP protocol header
 * @param ipsrc_addr the source IP address for the ARP protocol header
 * @param hwdst_addr the destination MAC address for the ARP protocol header
 * @param ipdst_addr the destination IP address for the ARP protocol header
 * @param opcode the type of the ARP packet
 * @return ERR_OK if the ARP packet has been sent
 *         ERR_MEM if the ARP packet couldn't be allocated
 *         any other err_t on failure
 */
/*********************************************************************************************************
** 函数名称: etharp_raw
** 功能描述: 根据指定的信息，组成一个 arp 协议数据包并通过以太网设备发送出去
** 注     释: arp 协议数据格式介绍：https://www.cnblogs.com/laojie4321/archive/2012/04/12/2444187.html
** 输	 入: netif - 发送 arp 数据包的网络接口指针
**		   : ethsrc_addr - 以太网协议数据包“包头”中的源设备 MAC 地址
**		   : ethdst_addr - 以太网协议数据包“包头”中的目的设备 MAC 地址
**		   : hwsrc_addr - arp 协议数据包“包头”中的源设备 MAC 地址
**		   : ipsrc_addr - arp 协议数据包“包头”中的源设备 IPv4 地址
**		   : hwdst_addr - arp 协议数据包“包头”中的目的设备 MAC 地址
**		   : ipdst_addr - arp 协议数据包“包头”中的目的设备 IPv4 地址
**		   : opcode - arp 协议数据包“包头”中的操作码内容
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
etharp_raw(struct netif *netif, const struct eth_addr *ethsrc_addr,
           const struct eth_addr *ethdst_addr,
           const struct eth_addr *hwsrc_addr, const ip4_addr_t *ipsrc_addr,
           const struct eth_addr *hwdst_addr, const ip4_addr_t *ipdst_addr,
           const u16_t opcode)
{
  struct pbuf *p;
  err_t result = ERR_OK;
  struct etharp_hdr *hdr;

  LWIP_ASSERT("netif != NULL", netif != NULL);

  /* allocate a pbuf for the outgoing ARP request packet */
  /* 为需要发送的 arp 协议数据包申请一个 pbuf 结构 */
  p = pbuf_alloc(PBUF_LINK, SIZEOF_ETHARP_HDR, PBUF_RAM);
  /* could allocate a pbuf for an ARP request? */
  if (p == NULL) {
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("etharp_raw: could not allocate pbuf for ARP request.\n"));
    ETHARP_STATS_INC(etharp.memerr);
    return ERR_MEM;
  }
  LWIP_ASSERT("check that first pbuf can hold struct etharp_hdr",
              (p->len >= SIZEOF_ETHARP_HDR));

  /* 初始化 arp 协议数据包内容 */
  hdr = (struct etharp_hdr *)p->payload;
  LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_raw: sending raw ARP packet.\n"));
  hdr->opcode = lwip_htons(opcode);

  LWIP_ASSERT("netif->hwaddr_len must be the same as ETH_HWADDR_LEN for etharp!",
              (netif->hwaddr_len == ETH_HWADDR_LEN));

  /* Write the ARP MAC-Addresses */
  SMEMCPY(&hdr->shwaddr, hwsrc_addr, ETH_HWADDR_LEN);
  SMEMCPY(&hdr->dhwaddr, hwdst_addr, ETH_HWADDR_LEN);
  /* Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers without
   * structure packing. */
  IPADDR_WORDALIGNED_COPY_FROM_IP4_ADDR_T(&hdr->sipaddr, ipsrc_addr);
  IPADDR_WORDALIGNED_COPY_FROM_IP4_ADDR_T(&hdr->dipaddr, ipdst_addr);

  hdr->hwtype = PP_HTONS(LWIP_IANA_HWTYPE_ETHERNET);
  hdr->proto = PP_HTONS(ETHTYPE_IP);
  /* set hwlen and protolen */
  hdr->hwlen = ETH_HWADDR_LEN;
  hdr->protolen = sizeof(ip4_addr_t);

  /* send ARP query */
  /* 通过以太网设备发送一个 arp 协议数据包 */
#if LWIP_AUTOIP
  /* If we are using Link-Local, all ARP packets that contain a Link-Local
   * 'sender IP address' MUST be sent using link-layer broadcast instead of
   * link-layer unicast. (See RFC3927 Section 2.5, last paragraph) */
  if (ip4_addr_islinklocal(ipsrc_addr)) {
    ethernet_output(netif, p, ethsrc_addr, &ethbroadcast, ETHTYPE_ARP);
  } else
#endif /* LWIP_AUTOIP */
  {
    ethernet_output(netif, p, ethsrc_addr, ethdst_addr, ETHTYPE_ARP);
  }

  ETHARP_STATS_INC(etharp.xmit);
  /* free ARP query packet */
  /* 发送完 arp 协议数据包后，释放这个数据包的 pbuf 结构 */
  pbuf_free(p);
  p = NULL;
  /* could not allocate pbuf for ARP request */

  return result;
}

/**
 * Send an ARP request packet asking for ipaddr to a specific eth address.
 * Used to send unicast request to refresh the ARP table just before an entry
 * times out
 *
 * @param netif the lwip network interface on which to send the request
 * @param ipaddr the IP address for which to ask
 * @param hw_dst_addr the ethernet address to send this packet to
 * @return ERR_OK if the request has been sent
 *         ERR_MEM if the ARP packet couldn't be allocated
 *         any other err_t on failure
 */
/*********************************************************************************************************
** 函数名称: etharp_request_dst
** 功能描述: 向指定的物理设备地址上为指定的 IPv4 地址发送一个 arp 请求
** 注     释: 常常通过单播方式为当前 arp 映射表中将要“过期”的 arp 映射项请求新的 arp 映射信息
** 输	 入: netif - 发送 arp 数据包的网络接口指针
**		   : ipaddr - arp 协议数据包“包头”中的目的设备 IPv4 地址
**		   : hw_dst_addr - 以太网协议数据包“包头”中的目的设备 MAC 地址
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
etharp_request_dst(struct netif *netif, const ip4_addr_t *ipaddr, const struct eth_addr *hw_dst_addr)
{
  return etharp_raw(netif, (struct eth_addr *)netif->hwaddr, hw_dst_addr,
                    (struct eth_addr *)netif->hwaddr, netif_ip4_addr(netif), &ethzero,
                    ipaddr, ARP_REQUEST);
}

/**
 * Send an ARP request packet asking for ipaddr.
 *
 * @param netif the lwip network interface on which to send the request
 * @param ipaddr the IP address for which to ask
 * @return ERR_OK if the request has been sent
 *         ERR_MEM if the ARP packet couldn't be allocated
 *         any other err_t on failure
 */
/*********************************************************************************************************
** 函数名称: etharp_request_dst
** 功能描述: 通过广播的方式为指定的 IPv4 地址发送一个 arp 请求
** 输	 入: netif - 发送 arp 数据包的网络接口指针
**		   : ipaddr - arp 协议数据包“包头”中的目的设备 IPv4 地址
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
etharp_request(struct netif *netif, const ip4_addr_t *ipaddr)
{
  LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_request: sending ARP request.\n"));
  return etharp_request_dst(netif, ipaddr, &ethbroadcast);
}

#endif /* LWIP_IPV4 && LWIP_ARP */
