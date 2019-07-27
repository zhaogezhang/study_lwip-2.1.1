/**
 * @file
 * This is the IPv4 packet segmentation and reassembly implementation.
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
 * Author: Jani Monoses <jani@iv.ro>
 *         Simon Goldschmidt
 * original reassembly code by Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/opt.h"

#if LWIP_IPV4

#include "lwip/ip4_frag.h"
#include "lwip/def.h"
#include "lwip/inet_chksum.h"
#include "lwip/netif.h"
#include "lwip/stats.h"
#include "lwip/icmp.h"

#include <string.h>

#if IP_REASSEMBLY
/**
 * The IP reassembly code currently has the following limitations:
 * - IP header options are not supported
 * - fragments must not overlap (e.g. due to different routes),
 *   currently, overlapping or duplicate fragments are thrown away
 *   if IP_REASS_CHECK_OVERLAP=1 (the default)!
 *
 * @todo: work with IP header options
 */
/* lwip 的 IPv4 分片数据包重组功能目前有如下两个限制：
 * 1. IP 数据包协议头中不支持 IP “选项”扩展字段
 * 2. 分片后的数据包之间不能有重叠区域，如果 IP_REASS_CHECK_OVERLAP=1
 *    则在出现分片数据包有重叠区域的时候，将会丢弃这个数据包
 */

/** Setting this to 0, you can turn off checking the fragments for overlapping
 * regions. The code gets a little smaller. Only use this if you know that
 * overlapping won't occur on your network! */
/* 如果 IP_REASS_CHECK_OVERLAP=1，表示在执行分片数据包重组的时候，会检测数据包之间
 * 是否有重叠区域，如果有重叠区域，则会丢弃这个数据包。如果 IP_REASS_CHECK_OVERLAP=0
 * 表示在执行分片数据包重组的时候，不检测数据包之间是否有重叠区域，如果有重叠区域
 * 也会当成正常数据包接收，这样重组之后数据包就会出错，默认情况是开启这个功能的 */
#ifndef IP_REASS_CHECK_OVERLAP
#define IP_REASS_CHECK_OVERLAP 1
#endif /* IP_REASS_CHECK_OVERLAP */

/** Set to 0 to prevent freeing the oldest datagram when the reassembly buffer is
 * full (IP_REASS_MAX_PBUFS pbufs are enqueued). The code gets a little smaller.
 * Datagrams will be freed by timeout only. Especially useful when MEMP_NUM_REASSDATA
 * is set to 1, so one datagram can be reassembled at a time, only. */
/* 如果 IP_REASS_FREE_OLDEST=1 表示在重组接收到的分片数据包的过程中，如果当前协议栈
 * 在分片数据包缓存队列中的“完整”数据包缓存队列项个数超过预先设置的阈值或者当前系统缓存的
 * “分片”数据包的 pbuf 链表长度超过预先设置的阈值时，则把最“旧”的那个正在缓存重组的“完整”
 * 缓存队列项以及相关“分片数据包”释放掉。把释放出的空间用来存储新接收到的“完整”数据包，如果 
 * IP_REASS_FREE_OLDEST=0，则表示即使当前系统内“完整”数据包缓存队列项个数超过预先设定的阈值
 * 或者当前系统缓存的“分片”数据包的 pbuf 链表长度超过预先设置的阈值时不会释放最“旧”的那个正
 * 在缓存重组的“完整”数据包，而是直接丢弃当前接收到的新的“完整”数据包，这种情况下，只有在
 * 数据包接收重组超时的时候才会释放相应的“完整”数据包*/
#ifndef IP_REASS_FREE_OLDEST
#define IP_REASS_FREE_OLDEST 1
#endif /* IP_REASS_FREE_OLDEST */

/* 表示当前的“完整”数据包在重组过程中，已经收到了最后一个“分片”数据包 */
#define IP_REASS_FLAG_LASTFRAG 0x01

/* 表示当前的“完整”数据包在重组过程中，已经接收到全部的“分片”数据包 */
#define IP_REASS_VALIDATE_TELEGRAM_FINISHED  1

/* 表示当前的“完整”数据包在重组过程中，还没接收到全部的“分片”数据包 */
#define IP_REASS_VALIDATE_PBUF_QUEUED        0

/* 表示接收到了一个无效的“分片”数据包 */
#define IP_REASS_VALIDATE_PBUF_DROPPED       -1

/** This is a helper struct which holds the starting
 * offset and the ending offset of this fragment to
 * easily chain the fragments.
 * It has the same packing requirements as the IP header, since it replaces
 * the IP header in memory in incoming fragments (after copying it) to keep
 * track of the various fragments. (-> If the IP header doesn't need packing,
 * this struct doesn't need packing, too.)
 */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif

/* 这个结构体被放在每一个“分片”数据包 pubf->payload 的起始位置处（占用了 IP 数据包的 
 * IP 协议头空间），用来指向下一个有效的“分片”数据包 pbuf，通过这种方式，把属于同一个
 * “完整”数据包的每一个“分片”数据包链接起来，形成一个单向链表 */
PACK_STRUCT_BEGIN
struct ip_reass_helper {
  // 把属于同一个“完整”数据包的每一个“分片”数据包链接起来，形成一个单向链表
  PACK_STRUCT_FIELD(struct pbuf *next_pbuf);

  /* 表示当前“分片”数据包的负载数据空间映射到“完整”数据包负载空间中的起始位置 */
  PACK_STRUCT_FIELD(u16_t start);

  /* 表示当前“分片”数据包的负载数据空间映射到“完整”数据包负载空间中的结束位置 */
  PACK_STRUCT_FIELD(u16_t end);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
	
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

/* 判断指定的两个 IPv4 协议头中的 IPv4 地址（源地址和目的地址）信息和报文 ID 信息是否相等 */
#define IP_ADDRESSES_AND_ID_MATCH(iphdrA, iphdrB)  \
  (ip4_addr_cmp(&(iphdrA)->src, &(iphdrB)->src) && \
   ip4_addr_cmp(&(iphdrA)->dest, &(iphdrB)->dest) && \
   IPH_ID(iphdrA) == IPH_ID(iphdrB)) ? 1 : 0

/* global variables */
/* 全局变量，用来表示当前系统内正在重组的“完整”数据包缓存队列头地址 */
static struct ip_reassdata *reassdatagrams;

/* 全局变量，用来表示当前系统内在重组数据包缓存队列中的所有“分片”数据包的 pbuf 链表长度 */
static u16_t ip_reass_pbufcount;

/* function prototypes */
static void ip_reass_dequeue_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev);
static int ip_reass_free_complete_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev);

/**
 * Reassembly timer base function
 * for both NO_SYS == 0 and 1 (!).
 *
 * Should be called every 1000 msec (defined by IP_TMR_INTERVAL).
 */
/*********************************************************************************************************
** 函数名称: ip_reass_tmr
** 功能描述: 分片数据包重组定时器超时函数，每一秒钟调用一次，在这个函数中会更新每一个正在重组的
**         : “完整”数据包剩余时间计数值，如果这个计数值达到 0，表示在预设定的时间内没有成功接收
**         : 到“完整”的数据包，则把当前已经缓存的和这个“完整”的数据包相关的分片数据包释放掉，并
**         : 发送一个时间超时的 icmp 数据包
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
ip_reass_tmr(void)
{
  struct ip_reassdata *r, *prev = NULL;

  r = reassdatagrams;

  /* 分别遍历当前系统内正在重组的每一个“完整”数据包缓存结构 */
  while (r != NULL) {
    /* Decrement the timer. Once it reaches 0,
     * clean up the incomplete fragment assembly */
    if (r->timer > 0) {
      r->timer--;
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip_reass_tmr: timer dec %"U16_F"\n", (u16_t)r->timer));
      prev = r;
      r = r->next;
    } else {
      /* reassembly timed out */
      struct ip_reassdata *tmp;
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip_reass_tmr: timer timed out\n"));
      tmp = r;
      /* get the next pointer before freeing */
      r = r->next;
      /* free the helper struct and all enqueued pbufs */
      ip_reass_free_complete_datagram(tmp, prev);
    }
  }
}

/**
 * Free a datagram (struct ip_reassdata) and all its pbufs.
 * Updates the total count of enqueued pbufs (ip_reass_pbufcount),
 * SNMP counters and sends an ICMP time exceeded packet.
 *
 * @param ipr datagram to free
 * @param prev the previous datagram in the linked list
 * @return the number of pbufs freed
 */
/*********************************************************************************************************
** 函数名称: ip_reass_free_complete_datagram
** 功能描述: 释放指定的“完整”数据包的队列项以及队列项中包含的每一个“分片”数据包结构
** 输	 入: ipr - 要释放的“完整”数据包的队列项指针
**         : prev - 要释放的“完整”数据包的队列项前驱指针，可能为 NULL
** 输	 出: pbufs_freed - 一共释放的 pbuf 个数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int
ip_reass_free_complete_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev)
{
  u16_t pbufs_freed = 0;
  u16_t clen;
  struct pbuf *p;
  struct ip_reass_helper *iprh;

  LWIP_ASSERT("prev != ipr", prev != ipr);
  if (prev != NULL) {
    LWIP_ASSERT("prev->next == ipr", prev->next == ipr);
  }

  MIB2_STATS_INC(mib2.ipreasmfails);
  
#if LWIP_ICMP
  iprh = (struct ip_reass_helper *)ipr->p->payload;
  if (iprh->start == 0) {
    /* The first fragment was received, send ICMP time exceeded. */
    /* First, de-queue the first pbuf from r->p. */
    p = ipr->p;
    ipr->p = iprh->next_pbuf;
    /* Then, copy the original header into it. */
    SMEMCPY(p->payload, &ipr->iphdr, IP_HLEN);
    icmp_time_exceeded(p, ICMP_TE_FRAG);
    clen = pbuf_clen(p);
    LWIP_ASSERT("pbufs_freed + clen <= 0xffff", pbufs_freed + clen <= 0xffff);
    pbufs_freed = (u16_t)(pbufs_freed + clen);
    pbuf_free(p);
  }
#endif /* LWIP_ICMP */

  /* First, free all received pbufs.  The individual pbufs need to be released
     separately as they have not yet been chained */
  /* 分别遍历当前“完整”数据包的队列项中的每一个“分片”数据包，并释放分片数据包的内存空间 */
  p = ipr->p;
  while (p != NULL) {
    struct pbuf *pcur;
    iprh = (struct ip_reass_helper *)p->payload;
    pcur = p;
    /* get the next pointer before freeing */
    p = iprh->next_pbuf;
    clen = pbuf_clen(pcur);
    LWIP_ASSERT("pbufs_freed + clen <= 0xffff", pbufs_freed + clen <= 0xffff);
    pbufs_freed = (u16_t)(pbufs_freed + clen);
    pbuf_free(pcur);
  }
  
  /* Then, unchain the struct ip_reassdata from the list and free it. */
  /* 把指定的“完整”数据包的队列项从“全局”缓存队列链表中移除，并释放队列项的内存空间到对应内存池中 */
  ip_reass_dequeue_datagram(ipr, prev);
  
  LWIP_ASSERT("ip_reass_pbufcount >= pbufs_freed", ip_reass_pbufcount >= pbufs_freed);

  /* 更新当前系统的重组数据包缓存队列中包含的“分片”数据包计数变量值 */
  ip_reass_pbufcount = (u16_t)(ip_reass_pbufcount - pbufs_freed);

  return pbufs_freed;
}

#if IP_REASS_FREE_OLDEST
/**
 * Free the oldest datagram to make room for enqueueing new fragments.
 * The datagram 'fraghdr' belongs to is not freed!
 *
 * @param fraghdr IP header of the current fragment
 * @param pbufs_needed number of pbufs needed to enqueue
 *        (used for freeing other datagrams if not enough space)
 * @return the number of pbufs freed
 */
/*********************************************************************************************************
** 函数名称: ip_reass_remove_oldest_datagram
** 功能描述: 尝试从当前系统内正在重组的所有“完整”数据包缓存队列链表中回收指定数量的 pbuf 个数
** 输	 入: fraghdr - 当前接收到的“分片”数据包的 IP 协议头结构
**         : pbufs_needed - 需要释放的 pbuf 个数
** 输	 出: pbufs_freed - 成功释放的 pbuf 个数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int
ip_reass_remove_oldest_datagram(struct ip_hdr *fraghdr, int pbufs_needed)
{
  /* @todo Can't we simply remove the last datagram in the
   *       linked list behind reassdatagrams?
   */
  struct ip_reassdata *r, *oldest, *prev, *oldest_prev;
  int pbufs_freed = 0, pbufs_freed_current;
  int other_datagrams;

  /* Free datagrams until being allowed to enqueue 'pbufs_needed' pbufs,
   * but don't free the datagram that 'fraghdr' belongs to! */
  do {
    oldest = NULL;
    prev = NULL;
    oldest_prev = NULL;
    other_datagrams = 0;
    r = reassdatagrams;

	/* 遍历当前系统内正在重组的所有“完整”数据包缓存队列链表，找到最“旧”的“完整”数据包
	 * 的队列项结构，在查找的过程中，会跳过当前正在接收的数据包的队列项 */
    while (r != NULL) {
		
      /* 跳过当前正在接收的数据包的队列项 */
      if (!IP_ADDRESSES_AND_ID_MATCH(&r->iphdr, fraghdr)) {
        /* Not the same datagram as fraghdr */
        other_datagrams++;
        if (oldest == NULL) {
          oldest = r;
          oldest_prev = prev;
        } else if (r->timer <= oldest->timer) {
          /* older than the previous oldest */
          oldest = r;
          oldest_prev = prev;
        }
      }
	  
      if (r->next != NULL) {
        prev = r;
      }
	  
      r = r->next;
    }

	/* 把找到的最“旧”的“完整”数据包的队列项所占用的空间全部释放，并统计成功释放的 
	 * pbuf（分片数据包）个数          */
    if (oldest != NULL) {
      pbufs_freed_current = ip_reass_free_complete_datagram(oldest, oldest_prev);
      pbufs_freed += pbufs_freed_current;
    }
	
  } while ((pbufs_freed < pbufs_needed) && (other_datagrams > 1));
  return pbufs_freed;
}
#endif /* IP_REASS_FREE_OLDEST */

/**
 * Enqueues a new fragment into the fragment queue
 * @param fraghdr points to the new fragments IP hdr
 * @param clen number of pbufs needed to enqueue (used for freeing other datagrams if not enough space)
 * @return A pointer to the queue location into which the fragment was enqueued
 */
/*********************************************************************************************************
** 函数名称: ip_reass_enqueue_new_datagram
** 功能描述: 在接收到一个新的“完整”数据包的“分片”数据包时，尝试从系统申请一个空闲的“完整”数据包
**         : 缓存队列项并插入全局缓存队列项链表头部位置，然后返回缓存队列项结构指针
** 输	 入: fraghdr - 当前接收到的“分片”数据包的 IP 协议头结构
**         : clen - 当前接收到的“分片”数据包的 pbuf 链表长度
** 输	 出: ipr - 新申请到的“完整”数据包缓存队列项指针
**         : NULL - 申请失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static struct ip_reassdata *
ip_reass_enqueue_new_datagram(struct ip_hdr *fraghdr, int clen)
{
  struct ip_reassdata *ipr;
  
#if ! IP_REASS_FREE_OLDEST
  LWIP_UNUSED_ARG(clen);
#endif

  /* No matching previous fragment found, allocate a new reassdata struct */
  /* 尝试从内存池申请一个空闲的“完整”数据包缓存队列项结构，用来组织新接收到的“完整”数据包 */
  ipr = (struct ip_reassdata *)memp_malloc(MEMP_REASSDATA);
  if (ipr == NULL) {

#if IP_REASS_FREE_OLDEST
    /* 如果从内存池中申请“完整”数据包缓存队列项结构失败，则尝试回收当前系统内最“旧”的那个
     * “完整”数据包缓存队列项以及相关“分片”数据包 */
    if (ip_reass_remove_oldest_datagram(fraghdr, clen) >= clen) {
      ipr = (struct ip_reassdata *)memp_malloc(MEMP_REASSDATA);
    }
    if (ipr == NULL)
#endif /* IP_REASS_FREE_OLDEST */

    {
      /* 如果没有找到可用的“完整”数据包缓存队列项，则直接返回 NULL */
      IPFRAG_STATS_INC(ip_frag.memerr);
      LWIP_DEBUGF(IP_REASS_DEBUG, ("Failed to alloc reassdata struct\n"));
      return NULL;
    }
  }
  
  memset(ipr, 0, sizeof(struct ip_reassdata));
  ipr->timer = IP_REASS_MAXAGE;

  /* enqueue the new structure to the front of the list */
  ipr->next = reassdatagrams;
  reassdatagrams = ipr;
  
  /* copy the ip header for later tests and input */
  /* @todo: no ip options supported? */
  /* 因为不支持 IP 协议头的“选项”扩展字段，所以这个位置只复制常规 IP 协议头 */
  SMEMCPY(&(ipr->iphdr), fraghdr, IP_HLEN);
  
  return ipr;
}

/**
 * Dequeues a datagram from the datagram queue. Doesn't deallocate the pbufs.
 * @param ipr points to the queue entry to dequeue
 */
/*********************************************************************************************************
** 函数名称: ip_reass_dequeue_datagram
** 功能描述: 把指定的“完整”数据包的队列项从“全局”缓存队列链表中移除，并释放队列项的内存空间到对应内存池中
** 输	 入: ipr - 要释放的“完整”数据包的队列项指针
**         : prev - 要释放的“完整”数据包的队列项的前驱指针，可能为 NULL
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
ip_reass_dequeue_datagram(struct ip_reassdata *ipr, struct ip_reassdata *prev)
{
  /* dequeue the reass struct  */
  /* 把指定的“完整”数据包的队列项从“全局”缓存队列链表中移除 */
  if (reassdatagrams == ipr) {
    /* it was the first in the list */
    reassdatagrams = ipr->next;
  } else {
    /* it wasn't the first, so it must have a valid 'prev' */
    LWIP_ASSERT("sanity check linked list", prev != NULL);
    prev->next = ipr->next;
  }

  /* now we can free the ip_reassdata struct */
  /* 把“完整”数据包的队列项内存空间释放到相应的内存池中 */
  memp_free(MEMP_REASSDATA, ipr);
}

/**
 * Chain a new pbuf into the pbuf list that composes the datagram.  The pbuf list
 * will grow over time as  new pbufs are rx.
 * Also checks that the datagram passes basic continuity checks (if the last
 * fragment was received at least once).
 * @param ipr points to the reassembly state
 * @param new_p points to the pbuf for the current fragment
 * @param is_last is 1 if this pbuf has MF==0 (ipr->flags not updated yet)
 * @return see IP_REASS_VALIDATE_* defines
 */
/*********************************************************************************************************
** 函数名称: ip_reass_chain_frag_into_datagram_and_validate
** 功能描述: 把接收到的“分片”数据包按照升序地址排序后插入到指定的“完整”数据包缓存队列项的“分片”数据包
**         : 链表中，并在插入之后判断当前正在重组的“完整”数据包是否已经接收到了所有“分片”数据包
** 输	 入: ipr - 表示当前接收到的“分片”数据包所属“完整”数据包缓存队列项指针
**         : new_p - 当前接收到的“分片”数据包指针
**         : is_last - 当前接收到的“分片”数据包指针是否是所属“完整”数据包的最后一个“分片”数据包
** 输	 出: IP_REASS_VALIDATE_TELEGRAM_FINISHED - 表示已经接收到全部的“分片”数据包
**         : IP_REASS_VALIDATE_PBUF_QUEUED - 表示还没接收到全部的“分片”数据包
**         : IP_REASS_VALIDATE_PBUF_DROPPED - 表示接收到了一个无效的“分片”数据包
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int
ip_reass_chain_frag_into_datagram_and_validate(struct ip_reassdata *ipr, struct pbuf *new_p, int is_last)
{
  struct ip_reass_helper *iprh, *iprh_tmp, *iprh_prev = NULL;
  struct pbuf *q;
  u16_t offset, len;
  u8_t hlen;
  struct ip_hdr *fraghdr;

  /* 表示在当前接收到的“分片”数据包地址空间之前是否有空洞存在，用来协助表示当前是否
   * 已经接收到了指定的“完整”数据包的所有“分片”数据包，1 表示在接收到的“分片”数据包
   * 之前“没有”空洞，0 表示在接收到的“分片”数据包之前“有”空洞 */
  int valid = 1;

  /* Extract length and fragment offset from current fragment */
  fraghdr = (struct ip_hdr *)new_p->payload;

  /* IP 协议头长度 + 负载数据长度 */
  len = lwip_ntohs(IPH_LEN(fraghdr));

  /* IP 协议头长度 */
  hlen = IPH_HL_BYTES(fraghdr);
  
  if (hlen > len) {
    /* invalid datagram */
    return IP_REASS_VALIDATE_PBUF_DROPPED;
  }

  /* 负载数据长度 */
  len = (u16_t)(len - hlen);

  /* 表示当前分片数据包负载数据在完整数据包负载数据中的偏移量 */
  offset = IPH_OFFSET_BYTES(fraghdr);

  /* overwrite the fragment's ip header from the pbuf with our helper struct,
   * and setup the embedded helper structure. */
  /* make sure the struct ip_reass_helper fits into the IP header */
  LWIP_ASSERT("sizeof(struct ip_reass_helper) <= IP_HLEN",
              sizeof(struct ip_reass_helper) <= IP_HLEN);

  /* 把 IP 数据包的 IP 协议头映射成与其对应的 ip_reass_helper 头结构并初始化 */
  iprh = (struct ip_reass_helper *)new_p->payload;
  iprh->next_pbuf = NULL;
  iprh->start = offset;
  iprh->end = (u16_t)(offset + len);
  if (iprh->end < offset) {
    /* u16_t overflow, cannot handle this */
    return IP_REASS_VALIDATE_PBUF_DROPPED;
  }

  /* Iterate through until we either get to the end of the list (append),
   * or we find one with a larger offset (insert). */
  /* 遍历指定的“完整”数据包的缓存队列项中的“分片”数据包链表结构，为新接收到的
   * “分片”数据包按照地址升序的方式在“完整”数据包链表中找到合适的插入位置，需
   * 要注意的是，在这个循环中，只有在当前接收的“分片”数据包按照地址排序后在
   * “完整”数据包链表的头部或者中间位置使才会执行插入操作 */
  for (q = ipr->p; q != NULL;) {
    iprh_tmp = (struct ip_reass_helper *)q->payload;

    /* 根据地址范围把新接收到的“分片”数据包的插入到“完整”数据包链表的合适位置
     * 并校验插入之后是否会有地址重叠 */
    if (iprh->start < iprh_tmp->start) {
      /* the new pbuf should be inserted before this */
      iprh->next_pbuf = q;
	  
      if (iprh_prev != NULL) {
	  	
        /* not the fragment with the lowest offset */
#if IP_REASS_CHECK_OVERLAP
        if ((iprh->start < iprh_prev->end) || (iprh->end > iprh_tmp->start)) {
          /* fragment overlaps with previous or following, throw away */
          return IP_REASS_VALIDATE_PBUF_DROPPED;
        }
#endif /* IP_REASS_CHECK_OVERLAP */

        iprh_prev->next_pbuf = new_p;

        if (iprh_prev->end != iprh->start) {
          /* There is a fragment missing between the current
           * and the previous fragment */
          /* 表示当前接收到的新的“分片”数据包前还有未接收到的“分片”数据包 */
          valid = 0;
        }
      } else {
      
#if IP_REASS_CHECK_OVERLAP
        if (iprh->end > iprh_tmp->start) {
          /* fragment overlaps with following, throw away */
          return IP_REASS_VALIDATE_PBUF_DROPPED;
        }
#endif /* IP_REASS_CHECK_OVERLAP */

        /* fragment with the lowest offset */
        ipr->p = new_p;
      }
      break;
    } else if (iprh->start == iprh_tmp->start) {
      /* received the same datagram twice: no need to keep the datagram */
      return IP_REASS_VALIDATE_PBUF_DROPPED;
#if IP_REASS_CHECK_OVERLAP
    } else if (iprh->start < iprh_tmp->end) {
      /* overlap: no need to keep the new datagram */
      return IP_REASS_VALIDATE_PBUF_DROPPED;
#endif /* IP_REASS_CHECK_OVERLAP */
    } else {
      /* Check if the fragments received so far have no holes. */
      if (iprh_prev != NULL) {
        if (iprh_prev->end != iprh_tmp->start) {
          /* There is a fragment missing between the current
           * and the previous fragment */
          valid = 0;
        }
      }
    }
    q = iprh_tmp->next_pbuf;
    iprh_prev = iprh_tmp;
  }

  /* If q is NULL, then we made it to the end of the list. Determine what to do now */
  /* 如果当前接收的“分片”数据包按照地址排序后不在“完整”数据包链表的头部或者中间位置
   * 而是在“完整”数据包链表的尾部位置，则执行下面的逻辑 */
  if (q == NULL) {
    if (iprh_prev != NULL) {
      /* this is (for now), the fragment with the highest offset:
       * chain it to the last fragment */
       
#if IP_REASS_CHECK_OVERLAP
      LWIP_ASSERT("check fragments don't overlap", iprh_prev->end <= iprh->start);
#endif /* IP_REASS_CHECK_OVERLAP */

      /* 如果当前接收的“分片”数据包“不是”整个“完整”数据包中第一个接收到的“分片”数据包
       * 则直接把新接收到的“分片”数据包插入到“完整”数据包链表的尾部位置 */
      iprh_prev->next_pbuf = new_p;
      if (iprh_prev->end != iprh->start) {
        valid = 0;
      }
    } else {
    
#if IP_REASS_CHECK_OVERLAP
      LWIP_ASSERT("no previous fragment, this must be the first fragment!",
                  ipr->p == NULL);
#endif /* IP_REASS_CHECK_OVERLAP */

      /* this is the first fragment we ever received for this ip datagram */
      /* 执行到这表示当前接收的“分片”数据包是整个“完整”数据包中第一个接收到的“分片”数据包
       * 则把新接收到的“分片”数据包直接放到“完整”数据包的缓存队列项中 */
      ipr->p = new_p;
    }
  }

  /* At this point, the validation part begins: */
  /* If we already received the last fragment */
  /* 表示我们已经接收到了当前“完整”数据包的最后一个“分片”数据包 */
  if (is_last || ((ipr->flags & IP_REASS_FLAG_LASTFRAG) != 0)) {
  	
    /* and had no holes so far */
    /* 在此次接收的“分片”数据包所表示的地址空间之前没有空洞 */
    if (valid) {
      /* then check if the rest of the fragments is here */
      /* Check if the queue starts with the first datagram */

	  /* 如果当前正在重组的“完整”数据包的缓存队列项中没有负载数据包
	   * 或者当前正在重组的“完整”数据包还没有接收到第一个“分片”数据包
	   * 则表示当前正在重组的“完整”数据包还有没到达的“分片”数据包 */
      if ((ipr->p == NULL) || (((struct ip_reass_helper *)ipr->p->payload)->start != 0)) {
        valid = 0;
      } else {
        /* and check that there are no holes after this datagram */
        iprh_prev = iprh;
        q = iprh->next_pbuf;
		
	    /* 从当前接收到的“分片”数据包开始遍历在这之后的每一个“分片”数据包
	     * 并判断在这些“分片”数据包之间是否有空洞 */
        while (q != NULL) {
          iprh = (struct ip_reass_helper *)q->payload;

		  /* 如果每个“分片”数据包在地址上不连续则表示有空洞，所以当前正在
		   * 重组的“完整”数据包还有没到达的“分片”数据包 */
          if (iprh_prev->end != iprh->start) {
            valid = 0;
            break;
          }
		  
          iprh_prev = iprh;
          q = iprh->next_pbuf;
        }
		
        /* if still valid, all fragments are received
         * (because to the MF==0 already arrived */
        if (valid) {
          LWIP_ASSERT("sanity check", ipr->p != NULL);
          LWIP_ASSERT("sanity check",
                      ((struct ip_reass_helper *)ipr->p->payload) != iprh);
          LWIP_ASSERT("validate_datagram:next_pbuf!=NULL",
                      iprh->next_pbuf == NULL);
        }
      }
    }
    /* If valid is 0 here, there are some fragments missing in the middle
     * (since MF == 0 has already arrived). Such datagrams simply time out if
     * no more fragments are received... */
    return valid ? IP_REASS_VALIDATE_TELEGRAM_FINISHED : IP_REASS_VALIDATE_PBUF_QUEUED;
  }
  
  /* If we come here, not all fragments were received, yet! */
  return IP_REASS_VALIDATE_PBUF_QUEUED; /* not yet valid! */
}

/**
 * Reassembles incoming IP fragments into an IP datagram.
 *
 * @param p points to a pbuf chain of the fragment
 * @return NULL if reassembly is incomplete, ? otherwise
 */
/*********************************************************************************************************
** 函数名称: ip4_reass
** 功能描述: 把接收到的“分片”数据包插入到与其对应的“完整”数据包缓存队列项的“分片”数据包链表中
**         : 并返回是否已经接收到了这个“完整”数据包的所有“分片”数据包
** 输	 入: p - 接收到的“分片”数据包指针
** 输	 出: pbuf * - 如果接收到了“完整”数据包的所有“分片”数据包，则返回重组后的完整 pbuf 指针
**         : NULL - 没接收到“完整”数据包的所有“分片”数据包
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct pbuf *
ip4_reass(struct pbuf *p)
{
  struct pbuf *r;
  struct ip_hdr *fraghdr;
  struct ip_reassdata *ipr;
  struct ip_reass_helper *iprh;
  u16_t offset, len, clen;
  u8_t hlen;
  int valid;
  int is_last;

  IPFRAG_STATS_INC(ip_frag.recv);
  MIB2_STATS_INC(mib2.ipreasmreqds);

  fraghdr = (struct ip_hdr *)p->payload;

  /* 校验接收到的“分片”数据包 IP 协议头中的协议头长度字段值是否合法 */
  if (IPH_HL_BYTES(fraghdr) != IP_HLEN) {
    LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: IP options currently not supported!\n"));
    IPFRAG_STATS_INC(ip_frag.err);
    goto nullreturn;
  }

  offset = IPH_OFFSET_BYTES(fraghdr);
  len = lwip_ntohs(IPH_LEN(fraghdr));
  hlen = IPH_HL_BYTES(fraghdr);
  if (hlen > len) {
    /* invalid datagram */
    goto nullreturn;
  }

  /* 接收到的“分片”数据包有效负载数据长度 */
  len = (u16_t)(len - hlen);

  /* Check if we are allowed to enqueue more datagrams. */
  clen = pbuf_clen(p);

  /* 判断当前系统内已经缓存的重组“分片”数据包的 pbuf 链表长度是否已经超过预先设定的阈值 */
  if ((ip_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS) {

/* 尝试从当前系统内正在重组的所有“完整”数据包缓存队列链表中回收指定数量的 pbuf 然后再
 * 重新判断判断当前系统内已经缓存的重组“分片”数据包的 pbuf 链表长度是否已经超过预先设
 * 定的阈值，如果仍然超过预先设定的阈值，则丢弃新接收的“分片”数据包 */
#if IP_REASS_FREE_OLDEST
    if (!ip_reass_remove_oldest_datagram(fraghdr, clen) ||
        ((ip_reass_pbufcount + clen) > IP_REASS_MAX_PBUFS))
#endif /* IP_REASS_FREE_OLDEST */

    {
      /* No datagram could be freed and still too many pbufs enqueued */
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: Overflow condition: pbufct=%d, clen=%d, MAX=%d\n",
                                   ip_reass_pbufcount, clen, IP_REASS_MAX_PBUFS));
      IPFRAG_STATS_INC(ip_frag.memerr);
      /* @todo: send ICMP time exceeded here? */
      /* drop this pbuf */
      goto nullreturn;
    }
  }

  /* Look for the datagram the fragment belongs to in the current datagram queue,
   * remembering the previous in the queue for later dequeueing. */
  /* 遍历当前系统内正在重组的“完整”数据包缓存队列中的每一个“完整”数据包缓存队列项
   * 找到当前接收到的“分片”数据包所属的“完整”数据包缓存队列项 */
  for (ipr = reassdatagrams; ipr != NULL; ipr = ipr->next) {
    /* Check if the incoming fragment matches the one currently present
       in the reassembly buffer. If so, we proceed with copying the
       fragment into the buffer. */
    if (IP_ADDRESSES_AND_ID_MATCH(&ipr->iphdr, fraghdr)) {
      LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: matching previous fragment ID=%"X16_F"\n",
                                   lwip_ntohs(IPH_ID(fraghdr))));
      IPFRAG_STATS_INC(ip_frag.cachehit);
      break;
    }
  }

  /* 如果系统内没有和当前接收到的“分片”数据包匹配的“完整”数据包缓存队列项，则尝试
   * 从系统申请一个空闲的“完整”数据包 */
  if (ipr == NULL) {
    /* Enqueue a new datagram into the datagram queue */
    ipr = ip_reass_enqueue_new_datagram(fraghdr, clen);
    /* Bail if unable to enqueue */
    if (ipr == NULL) {
      goto nullreturn;
    }
  } else {
    /* 如果当前接收到的“分片”数据包是“完整”数据包的第一个“分片”数据包，并且在这之前
     * 还没接收到过第一个“分片”数据包，则更新当前正在重组的“完整”数据包缓存队列项中
     * 的 IP 协议头结构内容 */
    if (((lwip_ntohs(IPH_OFFSET(fraghdr)) & IP_OFFMASK) == 0) &&
        ((lwip_ntohs(IPH_OFFSET(&ipr->iphdr)) & IP_OFFMASK) != 0)) {
      /* ipr->iphdr is not the header from the first fragment, but fraghdr is
       * -> copy fraghdr into ipr->iphdr since we want to have the header
       * of the first fragment (for ICMP time exceeded and later, for copying
       * all options, if supported)*/
      SMEMCPY(&ipr->iphdr, fraghdr, IP_HLEN);
    }
  }

  /* At this point, we have either created a new entry or pointing
   * to an existing one */

  /* check for 'no more fragments', and update queue entry*/
  /* 如果当前接收到的“分片”数据包是“完整”数据包的最后一个“分片”数据包，则计算
   * 当前正在重组的“完整”数据包总负载数据长度 */
  is_last = (IPH_OFFSET(fraghdr) & PP_NTOHS(IP_MF)) == 0;
  if (is_last) {
    u16_t datagram_len = (u16_t)(offset + len);
    if ((datagram_len < offset) || (datagram_len > (0xFFFF - IP_HLEN))) {
      /* u16_t overflow, cannot handle this */
      goto nullreturn_ipr;
    }
  }
  
  /* find the right place to insert this pbuf */
  /* @todo: trim pbufs if fragments are overlapping */
  /* 把接收到的“分片”数据包按照升序地址排序后插入到指定的“完整”数据包缓存队列项
   * 的“分片”数据包链表中，并在插入之后判断当前正在重组的“完整”数据包是否已经接
   * 收到了所有“分片”数据包*/
  valid = ip_reass_chain_frag_into_datagram_and_validate(ipr, p, is_last);
  if (valid == IP_REASS_VALIDATE_PBUF_DROPPED) {
    goto nullreturn_ipr;
  }
  
  /* if we come here, the pbuf has been enqueued */

  /* Track the current number of pbufs current 'in-flight', in order to limit
     the number of fragments that may be enqueued at any one time
     (overflow checked by testing against IP_REASS_MAX_PBUFS) */
  /* 更新当前系统内在重组数据包缓存队列中的所有“分片”数据包的 pbuf 链表长度 */
  ip_reass_pbufcount = (u16_t)(ip_reass_pbufcount + clen);

  /* 如果当前接收到的“分片”数据包是“完整”数据包的最后一个“分片”数据包，则更新
   * 正在重组的“完整”数据包缓存队列项中的相关成员值 */
  if (is_last) {
    u16_t datagram_len = (u16_t)(offset + len);
    ipr->datagram_len = datagram_len;
    ipr->flags |= IP_REASS_FLAG_LASTFRAG;
    LWIP_DEBUGF(IP_REASS_DEBUG,
                ("ip4_reass: last fragment seen, total len %"S16_F"\n",
                 ipr->datagram_len));
  }

  /* 表示当前的“完整”数据包在重组过程中，已经接收到全部的“分片”数据包 */
  if (valid == IP_REASS_VALIDATE_TELEGRAM_FINISHED) {
    struct ip_reassdata *ipr_prev;
    /* the totally last fragment (flag more fragments = 0) was received at least
     * once AND all fragments are received */
    u16_t datagram_len = (u16_t)(ipr->datagram_len + IP_HLEN);

    /* save the second pbuf before copying the header over the pointer */
	/* 先把当前重组完成的“完整”数据包的第二个“分片”数据包的地址记录下来 */
    r = ((struct ip_reass_helper *)ipr->p->payload)->next_pbuf;

    /* copy the original ip header back to the first pbuf */
	/* 把当前重组完成的“完整”数据包缓存队列项中的 IP 协议头信息恢复到
	 * 第一个“分片”数据包的 IP 协议头位置 */
    fraghdr = (struct ip_hdr *)(ipr->p->payload);
    SMEMCPY(fraghdr, &ipr->iphdr, IP_HLEN);
    IPH_LEN_SET(fraghdr, lwip_htons(datagram_len));
    IPH_OFFSET_SET(fraghdr, 0);
    IPH_CHKSUM_SET(fraghdr, 0);
	
    /* @todo: do we need to set/calculate the correct checksum? */
	/* 计算并设置当前重组完成的“完整”数据包的第一个“分片”数据包的 IP 协议头校验和字段值 */
#if CHECKSUM_GEN_IP
    IF__NETIF_CHECKSUM_ENABLED(ip_current_input_netif(), NETIF_CHECKSUM_GEN_IP) {
      IPH_CHKSUM_SET(fraghdr, inet_chksum(fraghdr, IP_HLEN));
    }
#endif /* CHECKSUM_GEN_IP */

    p = ipr->p;

    /* chain together the pbufs contained within the reass_data list. */
	/* 把当前重组完成的“完整”数据包的所有“分片”数据包的 pbuf 串联成一个完整的 pbuf chain */
    while (r != NULL) {
      iprh = (struct ip_reass_helper *)r->payload;

      /* hide the ip header for every succeeding fragment */
      pbuf_remove_header(r, IP_HLEN);
      pbuf_cat(p, r);
      r = iprh->next_pbuf;
    }

    /* find the previous entry in the linked list */
	/* 找到当前重组完成的“完整”数据包缓存队列项在全局缓存队列链表中的前驱指针 */
    if (ipr == reassdatagrams) {
      ipr_prev = NULL;
    } else {
      for (ipr_prev = reassdatagrams; ipr_prev != NULL; ipr_prev = ipr_prev->next) {
        if (ipr_prev->next == ipr) {
          break;
        }
      }
    }

    /* release the sources allocate for the fragment queue entry */
	/* 把当前重组完成的“完整”数据包缓存队列项从全局缓存队列链表中移除 */
    ip_reass_dequeue_datagram(ipr, ipr_prev);

    /* and adjust the number of pbufs currently queued for reassembly. */
	/* 更新当前系统内在重组数据包缓存队列中的所有“分片”数据包的 pbuf 链表长度计数变量值 */
    clen = pbuf_clen(p);
    LWIP_ASSERT("ip_reass_pbufcount >= clen", ip_reass_pbufcount >= clen);
    ip_reass_pbufcount = (u16_t)(ip_reass_pbufcount - clen);

    MIB2_STATS_INC(mib2.ipreasmoks);

    /* Return the pbuf chain */
    return p;
  }
  
  /* the datagram is not (yet?) reassembled completely */
  LWIP_DEBUGF(IP_REASS_DEBUG, ("ip_reass_pbufcount: %d out\n", ip_reass_pbufcount));
  return NULL;

nullreturn_ipr:
  LWIP_ASSERT("ipr != NULL", ipr != NULL);
  if (ipr->p == NULL) {
    /* dropped pbuf after creating a new datagram entry: remove the entry, too */
    LWIP_ASSERT("not firstalthough just enqueued", ipr == reassdatagrams);
    ip_reass_dequeue_datagram(ipr, NULL);
  }

nullreturn:
  LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: nullreturn\n"));
  IPFRAG_STATS_INC(ip_frag.drop);
  pbuf_free(p);
  return NULL;
}
#endif /* IP_REASSEMBLY */

#if IP_FRAG
#if !LWIP_NETIF_TX_SINGLE_PBUF
/** Allocate a new struct pbuf_custom_ref */
/*********************************************************************************************************
** 函数名称: ip_frag_alloc_pbuf_custom_ref
** 功能描述: 从指定的内存池中申请一个 struct pbuf_custom_ref 结构体空间
** 输	 入: 
** 输	 出: pbuf_custom_ref * - 申请到的结构体空间指针
**         : NULL - 申请失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static struct pbuf_custom_ref *
ip_frag_alloc_pbuf_custom_ref(void)
{
  return (struct pbuf_custom_ref *)memp_malloc(MEMP_FRAG_PBUF);
}

/** Free a struct pbuf_custom_ref */
/*********************************************************************************************************
** 函数名称: ip_frag_free_pbuf_custom_ref
** 功能描述: 释放一个 struct pbuf_custom_ref 结构体空间到指定的内存池中
** 输	 入: p - 要释放的结构体空间指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
ip_frag_free_pbuf_custom_ref(struct pbuf_custom_ref *p)
{
  LWIP_ASSERT("p != NULL", p != NULL);
  memp_free(MEMP_FRAG_PBUF, p);
}

/** Free-callback function to free a 'struct pbuf_custom_ref', called by
 * pbuf_free. */
/*********************************************************************************************************
** 函数名称: ipfrag_free_pbuf_custom
** 功能描述: 释放一个指定的 struct pbuf_custom_ref 类型 pbuf 实现函数
** 输	 入: p - 要释放的空间指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
ipfrag_free_pbuf_custom(struct pbuf *p)
{
  struct pbuf_custom_ref *pcr = (struct pbuf_custom_ref *)p;
  LWIP_ASSERT("pcr != NULL", pcr != NULL);
  LWIP_ASSERT("pcr == p", (void *)pcr == (void *)p);
  
  if (pcr->original != NULL) {
    pbuf_free(pcr->original);
  }
  
  ip_frag_free_pbuf_custom_ref(pcr);
}
#endif /* !LWIP_NETIF_TX_SINGLE_PBUF */

/**
 * Fragment an IP datagram if too large for the netif.
 *
 * Chop the datagram in MTU sized chunks and send them in order
 * by pointing PBUF_REFs into p.
 *
 * @param p ip packet to send
 * @param netif the netif on which to send
 * @param dest destination ip address to which to send
 *
 * @return ERR_OK if sent successfully, err_t otherwise
 */
/*********************************************************************************************************
** 函数名称: ip4_frag
** 功能描述: 把指定的“完整”数据包拆分、组装成多个“分片”数据包，并把组装后的“分片”数据包分别发送出去
** 输	 入: p - 需要发送的网络数据包
**         : netif - 发送数据使用的网络接口指针
**         : dest - 目的 IPv4 地址
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
ip4_frag(struct pbuf *p, struct netif *netif, const ip4_addr_t *dest)
{
  struct pbuf *rambuf;
  
#if !LWIP_NETIF_TX_SINGLE_PBUF
  struct pbuf *newpbuf;
  u16_t newpbuflen = 0;
  u16_t left_to_copy;
#endif

  struct ip_hdr *original_iphdr;
  struct ip_hdr *iphdr;

  /* 表示当前网络接口，在网络协议层，每个分片数据包负载空间的最大字节数
   * 且按照 8 字节向下对齐 */
  const u16_t nfb = (u16_t)((netif->mtu - IP_HLEN) / 8);
  
  u16_t left, fragsize;

  /* 用来跟踪分片数据包协议头中的偏移量字段值 */
  u16_t ofo;

  int last;

  /* 用来记录需要发送的负载数据在当前 pbuf->payload 中的偏移量 */
  u16_t poff = IP_HLEN;

  u16_t tmp;
  int mf_set;

  original_iphdr = (struct ip_hdr *)p->payload;
  iphdr = original_iphdr;

  /* 校验 IP 协议头长度，目前网络数据包分片不支持 IP “选项”扩展字段 */
  if (IPH_HL_BYTES(iphdr) != IP_HLEN) {
    /* ip4_frag() does not support IP options */
    return ERR_VAL;
  }
  
  LWIP_ERROR("ip4_frag(): pbuf too short", p->len >= IP_HLEN, return ERR_VAL);

  /* Save original offset */
  tmp = lwip_ntohs(IPH_OFFSET(iphdr));
  ofo = tmp & IP_OFFMASK;
  
  /* already fragmented? if so, the last fragment we create must have MF, too */
  /* 用来判断当前执行的是否是二次分片 */
  mf_set = tmp & IP_MF;

  /* 表示去掉 IP 协议头后，负载数据空间长度 */
  left = (u16_t)(p->tot_len - IP_HLEN);

  while (left) {
    /* Fill this fragment */
    /* 计算本次的“分片”数据包长度 */
    fragsize = LWIP_MIN(left, (u16_t)(nfb * 8));

/* 表示在网络层发送数据包的时候，每次发送的网络数据包是否需要存储在一个物理地址
 * 连续的 pbuf 缓冲区空间中，这样做的弊端是每个“分片”数据包都需要执行一次数据拷贝 */
#if LWIP_NETIF_TX_SINGLE_PBUF
    rambuf = pbuf_alloc(PBUF_IP, fragsize, PBUF_RAM);
    if (rambuf == NULL) {
      goto memerr;
    }
	
    LWIP_ASSERT("this needs a pbuf in one piece!",
                (rambuf->len == rambuf->tot_len) && (rambuf->next == NULL));

	/* 从“完整”数据包中指定的偏移量位置处复制指定字节数的数据到指定的 pbuf 中 */
    poff += pbuf_copy_partial(p, rambuf->payload, fragsize, poff);
	
    /* make room for the IP header */
    if (pbuf_add_header(rambuf, IP_HLEN)) {
      pbuf_free(rambuf);
      goto memerr;
    }

    /* fill in the IP header */
    /* 为“分片”数据包添加 IP 协议头数据 */
    SMEMCPY(rambuf->payload, original_iphdr, IP_HLEN);
    iphdr = (struct ip_hdr *)rambuf->payload;
	
#else /* LWIP_NETIF_TX_SINGLE_PBUF */

    /* When not using a static buffer, create a chain of pbufs.
     * The first will be a PBUF_RAM holding the link and IP header.
     * The rest will be PBUF_REFs mirroring the pbuf chain to be fragged,
     * but limited to the size of an mtu.
     */
    /* 为了保证链路层协议头和 IP 层协议头在物理地址连续的内存块中，所以这个位置
     * 申请了一个用来存储链路层协议头和 IP 层协议头的地址连续的内存空间块，因为
     * 在协议栈链路层添加以太网协议头的时候，会通过移动当前网络数据包的 pbuf->payload
     * 指针来“显露”处为链路层以太网协议头预分配的内存空间，所以这个位置需要申请
     * 一个同时包含链路层协议头和 IP 层协议头的物理地址连续的内存块 */
    rambuf = pbuf_alloc(PBUF_LINK, IP_HLEN, PBUF_RAM);
    if (rambuf == NULL) {
      goto memerr;
    }
	
    LWIP_ASSERT("this needs a pbuf in one piece!",
                (rambuf->len >= (IP_HLEN)));

	/* 复制 IP 层协议头数据到新申请的物理内存块中 */
    SMEMCPY(rambuf->payload, original_iphdr, IP_HLEN);
    iphdr = (struct ip_hdr *)rambuf->payload;

    /* 因为链路层协议头会在 arp 模块自动填充，所以这个位置不需要填充链路层协议头数据 */
	
    left_to_copy = fragsize;

	/* 从当前未发送的“完整”数据包的 pbuf 负载空间中取出指定字节数的负载数据，拼接成一个
	 * 表示“分片”数据包的 pbuf chain */
    while (left_to_copy) {
      struct pbuf_custom_ref *pcr;

	  /* 计算当前“完整”数据包的 pbuf 中还剩下的、未发送的负载数据字节数 */
      u16_t plen = (u16_t)(p->len - poff);

	  LWIP_ASSERT("p->len >= poff", p->len >= poff);

      newpbuflen = LWIP_MIN(left_to_copy, plen);
	  
      /* Is this pbuf already empty? */
	  /* 如果“完整”数据包的当前 pbuf 负载数据已经全部发送完成，则移动到下一个待发送的 pbuf 处 */
      if (!newpbuflen) {
        poff = 0;
        p = p->next;
        continue;
      }

	  /* 申请一个 struct pbuf_custom_ref 结构体空间 */
      pcr = ip_frag_alloc_pbuf_custom_ref();
      if (pcr == NULL) {
        pbuf_free(rambuf);
        goto memerr;
      }
	  
      /* Mirror this pbuf, although we might not need all of it. */
	  /* 通过自定义类型        pbuf 直接映射需要分片的“完整”数据包的“一段”负载空间数据
	   * 这样做的好处是可以减少不必要的内存拷贝操作 */
      newpbuf = pbuf_alloced_custom(PBUF_RAW, newpbuflen, PBUF_REF, &pcr->pc,
                                    (u8_t *)p->payload + poff, newpbuflen);
      if (newpbuf == NULL) {
        ip_frag_free_pbuf_custom_ref(pcr);
        pbuf_free(rambuf);
        goto memerr;
      }

	  /* 更新并设置相关数据，因为上面申请自定义类型的 pbuf 时在                         pbuf->flags 字段
	   * 中添加了 PBUF_FLAG_IS_CUSTOM 标志，所以在执行             pbuf_free 的时候会通过用户
	   * 提供的释放内存函数释放 pbuf，即 ipfrag_free_pbuf_custom              函数 */
      pbuf_ref(p);
      pcr->original = p;
      pcr->pc.custom_free_function = ipfrag_free_pbuf_custom;

      /* Add it to end of rambuf's chain, but using pbuf_cat, not pbuf_chain
       * so that it is removed when pbuf_dechain is later called on rambuf.
       */
      /* 把当前创建的 custom pbuf 添加到当前待发送的           “分片”数据包的 pbuf chain       中 */
      pbuf_cat(rambuf, newpbuf);
	  
      left_to_copy = (u16_t)(left_to_copy - newpbuflen);

	  /* 如果“完整”数据包的当前 pbuf 负载数据不足以拼接一个“分片”数据包，则移动到
	   * “完整”数据包的下一个 pbuf 处继续拼接，直到拼接出一个完整的“分片”数据包 */
      if (left_to_copy) {
        poff = 0;
        p = p->next;
      }
	  
    }

    /* 记录当前待发送的数据在“完整”数据包的当前的                     pbuf 负载空间中的偏移量 */
    poff = (u16_t)(poff + newpbuflen);
	
#endif /* LWIP_NETIF_TX_SINGLE_PBUF */

    /* Correct header */
    /* 判断当前待发送的“分片”数据包是否是“完整”数据包的最后一个“分片”数据包 */
    last = (left <= netif->mtu - IP_HLEN);

    /* Set new offset and MF flag */
	/* 设置当前待发送的“分片”数据包 IP 协议头中的 Fragment Offset 字段值和 MF 字段值 */
    tmp = (IP_OFFMASK & (ofo));
    if (!last || mf_set) {
      /* the last fragment has MF set if the input frame had it */
      tmp = tmp | IP_MF;
    }	
    IPH_OFFSET_SET(iphdr, lwip_htons(tmp));

	/* 设置当前待发送的“分片”数据包 IP 协议头中的 Total Length 字段值 */
    IPH_LEN_SET(iphdr, lwip_htons((u16_t)(fragsize + IP_HLEN)));

	/* 设置当前待发送的“分片”数据包 IP 协议头中的 Header Checksum 字段值 */
    IPH_CHKSUM_SET(iphdr, 0);
#if CHECKSUM_GEN_IP
    IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_IP) {
      IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, IP_HLEN));
    }
#endif /* CHECKSUM_GEN_IP */

    /* No need for separate header pbuf - we allowed room for it in rambuf
     * when allocated.
     */
    /* 把组装好的“分片”数据包通过下层协议模块发送到目的设备处 */
    netif->output(netif, rambuf, dest);
    IPFRAG_STATS_INC(ip_frag.xmit);

    /* Unfortunately we can't reuse rambuf - the hardware may still be
     * using the buffer. Instead we free it (and the ensuing chain) and
     * recreate it next time round the loop. If we're lucky the hardware
     * will have already sent the packet, the free will really free, and
     * there will be zero memory penalty.
     */
    /* 尝试释放使用完的“分片”数据包占用的 custom pbuf 内存空间，因为在这
     * 个位置，硬件可能还没有把我们需要发送的“分片”数据包发送完毕，所以
     * 在我们调用完 pbuf_free 的时候，不一定会真的释放掉这个 custom pbuf 
     * 内存空间 */
    pbuf_free(rambuf);

	/* 更新相关变量值，准备组装并发送下一个“分片”数据包 */
    left = (u16_t)(left - fragsize);
    ofo = (u16_t)(ofo + nfb);
	
  }
  MIB2_STATS_INC(mib2.ipfragoks);
  return ERR_OK;
memerr:
  MIB2_STATS_INC(mib2.ipfragfails);
  return ERR_MEM;
}
#endif /* IP_FRAG */

#endif /* LWIP_IPV4 */
