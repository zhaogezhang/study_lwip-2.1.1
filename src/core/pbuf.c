/**
 * @file
 * Packet buffer management
 */

/**
 * @defgroup pbuf Packet buffers (PBUF)
 * @ingroup infrastructure
 *
 * Packets are built from the pbuf data structure. It supports dynamic
 * memory allocation for packet contents or can reference externally
 * managed packet contents both in RAM and ROM. Quick allocation for
 * incoming packets is provided through pools with fixed sized pbufs.
 *
 * A packet may span over multiple pbufs, chained as a singly linked
 * list. This is called a "pbuf chain".
 *
 * Multiple packets may be queued, also using this singly linked list.
 * This is called a "packet queue".
 *
 * So, a packet queue consists of one or more pbuf chains, each of
 * which consist of one or more pbufs. CURRENTLY, PACKET QUEUES ARE
 * NOT SUPPORTED!!! Use helper structs to queue multiple packets.
 *
 * The differences between a pbuf chain and a packet queue are very
 * precise but subtle.
 *
 * The last pbuf of a packet has a ->tot_len field that equals the
 * ->len field. It can be found by traversing the list. If the last
 * pbuf of a packet has a ->next field other than NULL, more packets
 * are on the queue.
 *
 * Therefore, looping through a pbuf of a single packet, has an
 * loop end condition (tot_len == p->len), NOT (next == NULL).
 *
 * Example of custom pbuf usage: @ref zerocopyrx
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
/* 在 LWIP 协议栈中，pbuf chain 组织结构如下：
 * 
 *               first  pbuf 内存单元
 *          -----------------------------
 *          |                           |
 *          |    SIZEOF_STRUCT_PBUF     |
 *          |                  next     | ---
 *          |---------------------------|   |
 *          |                           |   |
 *          |    protocol header len    |   |
 *          |                           |   |
 *          |---------------------------|   |
 *          |                           |   |
 *          |                           |   |
 *          |     pbuf payload data     |   |
 *          |                           |   |
 *          |                           |   |
 *          -----------------------------   |
 *                                          |
 *                                          |
 *              second  pbuf 内存单元           |
 *          ----------------------------- <--
 *          |                           |
 *          |    SIZEOF_STRUCT_PBUF     |
 *          |                  next     | ---
 *          |---------------------------|   |
 *          |                           |   |
 *          |                           |   |
 *          |     pbuf payload data     |   |
 *          |                           |   |
 *          |                           |   |
 *          -----------------------------   |
 *                                          |
 *               third  pbuf 内存单元           |
 *          ----------------------------- <--
 *          |                           |
 *          |    SIZEOF_STRUCT_PBUF     |
 *          |                  next     | ---
 *          |---------------------------|   |
 *          |                           |   |
 *          |                           |   |
 *          |     pbuf payload data     |   |
 *          |                           |   |
 *          |                           |   |
 *          -----------------------------   |
 *                                          |
 *                                          V
 */

#include "lwip/opt.h"

#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#if LWIP_TCP && TCP_QUEUE_OOSEQ
#include "lwip/priv/tcp_priv.h"
#endif
#if LWIP_CHECKSUM_ON_COPY
#include "lwip/inet_chksum.h"
#endif

#include <string.h>

/* 计算 struct pbuf 在 lwip 设定的对齐方式下，占用空间字节数 */
#define SIZEOF_STRUCT_PBUF        LWIP_MEM_ALIGN_SIZE(sizeof(struct pbuf))

/* Since the pool is created in memp, PBUF_POOL_BUFSIZE will be automatically
   aligned there. Therefore, PBUF_POOL_BUFSIZE_ALIGNED can be used here. */
/* 表示网卡接收数据使用的 PBUF_POOL 内存池对象中，一个内存池单元元素空间大小，用来存储一个数据帧数据 */
#define PBUF_POOL_BUFSIZE_ALIGNED LWIP_MEM_ALIGN_SIZE(PBUF_POOL_BUFSIZE)

static const struct pbuf *
pbuf_skip_const(const struct pbuf *in, u16_t in_offset, u16_t *out_offset);

#if !LWIP_TCP || !TCP_QUEUE_OOSEQ || !PBUF_POOL_FREE_OOSEQ
#define PBUF_POOL_IS_EMPTY()
#else /* !LWIP_TCP || !TCP_QUEUE_OOSEQ || !PBUF_POOL_FREE_OOSEQ */

#if !NO_SYS
#ifndef PBUF_POOL_FREE_OOSEQ_QUEUE_CALL
#include "lwip/tcpip.h"
/* 通过 tcpip_try_callback 回调回收 tcp_active_pcbs 链表上的所有 out of sequence 数据包内存 */
#define PBUF_POOL_FREE_OOSEQ_QUEUE_CALL()  do { \
  if (tcpip_try_callback(pbuf_free_ooseq_callback, NULL) != ERR_OK) { \
      SYS_ARCH_PROTECT(old_level); \
      pbuf_free_ooseq_pending = 0; \
      SYS_ARCH_UNPROTECT(old_level); \
  } } while(0)
#endif /* PBUF_POOL_FREE_OOSEQ_QUEUE_CALL */
#endif /* !NO_SYS */

volatile u8_t pbuf_free_ooseq_pending;
#define PBUF_POOL_IS_EMPTY() pbuf_pool_is_empty()

/**
 * Attempt to reclaim some memory from queued out-of-sequence TCP segments
 * if we run out of pool pbufs. It's better to give priority to new packets
 * if we're running out.
 *
 * This must be done in the correct thread context therefore this function
 * can only be used with NO_SYS=0 and through tcpip_callback.
 */
/*********************************************************************************************************
** 函数名称: pbuf_free_ooseq
** 功能描述: 遍历 tcp_active_pcbs 链表上的每一个 tcp_pcb 并释放上面所有 out of sequence 数据包
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
#if !NO_SYS
static
#endif /* !NO_SYS */
void
pbuf_free_ooseq(void)
{
  struct tcp_pcb *pcb;
  SYS_ARCH_SET(pbuf_free_ooseq_pending, 0);

  for (pcb = tcp_active_pcbs; NULL != pcb; pcb = pcb->next) {
    if (pcb->ooseq != NULL) {
      /** Free the ooseq pbufs of one PCB only */
      LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_free_ooseq: freeing out-of-sequence pbufs\n"));
      tcp_free_ooseq(pcb);
      return;
    }
  }
}

#if !NO_SYS
/**
 * Just a callback function for tcpip_callback() that calls pbuf_free_ooseq().
 */
/*********************************************************************************************************
** 函数名称: pbuf_free_ooseq_callback
** 功能描述: 遍历 tcp_active_pcbs 链表上的每一个 tcp_pcb 并释放上面所有 out of sequence 数据包
** 注     释: 这是一个回调函数，通过 tcpip_callback 执行
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
pbuf_free_ooseq_callback(void *arg)
{
  LWIP_UNUSED_ARG(arg);
  pbuf_free_ooseq();
}
#endif /* !NO_SYS */

/** Queue a call to pbuf_free_ooseq if not already queued. */
/*********************************************************************************************************
** 函数名称: pbuf_pool_is_empty
** 功能描述: 如果当前系统没有待执行的回收 ooseq 的回调函数，则通过 tcpip_try_callback 启动一个
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
pbuf_pool_is_empty(void)
{
#ifndef PBUF_POOL_FREE_OOSEQ_QUEUE_CALL
  SYS_ARCH_SET(pbuf_free_ooseq_pending, 1);
#else /* PBUF_POOL_FREE_OOSEQ_QUEUE_CALL */
  u8_t queued;
  SYS_ARCH_DECL_PROTECT(old_level);
  SYS_ARCH_PROTECT(old_level);
  queued = pbuf_free_ooseq_pending;
  pbuf_free_ooseq_pending = 1;
  SYS_ARCH_UNPROTECT(old_level);

  if (!queued) {
    /* queue a call to pbuf_free_ooseq if not already queued */
    PBUF_POOL_FREE_OOSEQ_QUEUE_CALL();
  }
#endif /* PBUF_POOL_FREE_OOSEQ_QUEUE_CALL */
}
#endif /* !LWIP_TCP || !TCP_QUEUE_OOSEQ || !PBUF_POOL_FREE_OOSEQ */

/* Initialize members of struct pbuf after allocation */
/*********************************************************************************************************
** 函数名称: pbuf_init_alloced_pbuf
** 功能描述: 初始化指定的 pbuf 字段成员到指定的值
** 注     释: 刚分配的、还没使用的 pbuf 引用计数默认为 1
** 输	 入: p - 要初始化的 pubf 指针
**         : payload - 当前 pbuf 负载数据空间起始地址
**         : tot_len - 当前 pbuf tot_len 字段值
**         : len -     当前 pbuf len 字段值
**         : type -    当前 pbuf 类型
**         : flags -   当前 pbuf flags 字段值
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
pbuf_init_alloced_pbuf(struct pbuf *p, void *payload, u16_t tot_len, u16_t len, pbuf_type type, u8_t flags)
{
  p->next = NULL;
  p->payload = payload;
  p->tot_len = tot_len;
  p->len = len;
  p->type_internal = (u8_t)type;
  p->flags = flags;
  p->ref = 1;
  p->if_idx = NETIF_NO_INDEX;
}

/**
 * @ingroup pbuf
 * Allocates a pbuf of the given type (possibly a chain for PBUF_POOL type).
 *
 * The actual memory allocated for the pbuf is determined by the
 * layer at which the pbuf is allocated and the requested size
 * (from the size parameter).
 *
 * @param layer header size
 * @param length size of the pbuf's payload
 * @param type this parameter decides how and where the pbuf
 * should be allocated as follows:
 *
 * - PBUF_RAM: buffer memory for pbuf is allocated as one large
 *             chunk. This includes protocol headers as well.
 * - PBUF_ROM: no buffer memory is allocated for the pbuf, even for
 *             protocol headers. Additional headers must be prepended
 *             by allocating another pbuf and chain in to the front of
 *             the ROM pbuf. It is assumed that the memory used is really
 *             similar to ROM in that it is immutable and will not be
 *             changed. Memory which is dynamic should generally not
 *             be attached to PBUF_ROM pbufs. Use PBUF_REF instead.
 * - PBUF_REF: no buffer memory is allocated for the pbuf, even for
 *             protocol headers. It is assumed that the pbuf is only
 *             being used in a single thread. If the pbuf gets queued,
 *             then pbuf_take should be called to copy the buffer.
 * - PBUF_POOL: the pbuf is allocated as a pbuf chain, with pbufs from
 *              the pbuf pool that is allocated during pbuf_init().
 *
 * @return the allocated pbuf. If multiple pbufs where allocated, this
 * is the first pbuf of a pbuf chain.
 */
/*********************************************************************************************************
** 函数名称: pbuf_alloc
** 功能描述: 申请一个指定 TCP/IP 协议层（预留协议头需要的空间）、指定要申请的内存空间大小和指定类型的
**         : pbuf，通过 pbuf_alloc 申请到的如果是 pbuf chain，那么 pbuf chain 链表上的每个 pbuf 成员
**         : 引用计数都是 1（因为默认情况，刚申请的 pbuf 引用计数是 1）
** 输	 入: layer - TCP/IP 协议层（协议头需要的空间字节数）
**		   : length - 要申请的 pbuf 负载空间大小
**		   : type - 要申请的 pbuf 类型
** 输	 出: p - 成功申请的 pbuf 指针
**		   : NULL - 申请失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct pbuf *
pbuf_alloc(pbuf_layer layer, u16_t length, pbuf_type type)
{
  struct pbuf *p;
  u16_t offset = (u16_t)layer;
  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_alloc(length=%"U16_F")\n", length));

  switch (type) {
    case PBUF_REF: /* fall through */
    case PBUF_ROM:
      p = pbuf_alloc_reference(NULL, length, type);
      break;

	/* 常在网卡接收数据时使用这种类型的 pbuf，如果要申请的内存空间较大，会返回一个 pbuf chain */
    case PBUF_POOL: {
      struct pbuf *q, *last;
      u16_t rem_len; /* remaining length */
      p = NULL;
      last = NULL;
      rem_len = length;
	  
      do {
        u16_t qlen;
		
  	    /* 从 PBUF_POOL 内存池中申请内存空间 */
        q = (struct pbuf *)memp_malloc(MEMP_PBUF_POOL);
        if (q == NULL) {
          PBUF_POOL_IS_EMPTY();
          /* free chain so far allocated */
		  /* 如果 PBUF_POOL 内存池中的内存空间不足且成功申请了部分内存，则释放那些成功申请的部分内存 */
          if (p) {
            pbuf_free(p);
          }
          /* bail out unsuccessfully */
          return NULL;
        }

		/* 因为是从 MEMP_PBUF_POOL 内存池中申请内存，而 MEMP_PBUF_POOL 内存池每次最大可以申请 PBUF_POOL_BUFSIZE_ALIGNED
		 * 个字节内存空间，所以在需要申请大量内存时，会返回一个 pbuf chain，qlen 变量计算了本次需要从 MEMP_PBUF_POOL
		 * 中申请内存空间的字节数 */
        qlen = LWIP_MIN(rem_len, (u16_t)(PBUF_POOL_BUFSIZE_ALIGNED - LWIP_MEM_ALIGN_SIZE(offset)));

		pbuf_init_alloced_pbuf(q, LWIP_MEM_ALIGN((void *)((u8_t *)q + SIZEOF_STRUCT_PBUF + offset)),
                               rem_len, qlen, type, 0);
        LWIP_ASSERT("pbuf_alloc: pbuf q->payload properly aligned",
                    ((mem_ptr_t)q->payload % MEM_ALIGNMENT) == 0);
        LWIP_ASSERT("PBUF_POOL_BUFSIZE must be bigger than MEM_ALIGNMENT",
                    (PBUF_POOL_BUFSIZE_ALIGNED - LWIP_MEM_ALIGN_SIZE(offset)) > 0 );
        if (p == NULL) {
          /* allocated head of pbuf chain (into p) */
          p = q;
        } else {
          /* make previous pbuf point to this pbuf */
		  /* 如果是 pbuf chain，则把新申请的 pbuf 插入到之前申请的 pbuf 链表尾部 */
          last->next = q;
        }
        last = q;
        rem_len = (u16_t)(rem_len - qlen);
        offset = 0;
      } while (rem_len > 0);
      break;
    }

	/* 常在发送数据时使用这种类型的 pbuf，因为是从内存堆中申请内存，所以申请后的 pbuf 是一个完成内存块 */
    case PBUF_RAM: {
      u16_t payload_len = (u16_t)(LWIP_MEM_ALIGN_SIZE(offset) + LWIP_MEM_ALIGN_SIZE(length));
      mem_size_t alloc_len = (mem_size_t)(LWIP_MEM_ALIGN_SIZE(SIZEOF_STRUCT_PBUF) + payload_len);

      /* bug #50040: Check for integer overflow when calculating alloc_len */
      if ((payload_len < LWIP_MEM_ALIGN_SIZE(length)) ||
          (alloc_len < LWIP_MEM_ALIGN_SIZE(length))) {
        return NULL;
      }

      /* If pbuf is to be allocated in RAM, allocate memory for it. */
      p = (struct pbuf *)mem_malloc(alloc_len);
      if (p == NULL) {
        return NULL;
      }
      pbuf_init_alloced_pbuf(p, LWIP_MEM_ALIGN((void *)((u8_t *)p + SIZEOF_STRUCT_PBUF + offset)),
                             length, length, type, 0);
      LWIP_ASSERT("pbuf_alloc: pbuf->payload properly aligned",
                  ((mem_ptr_t)p->payload % MEM_ALIGNMENT) == 0);
      break;
    }
    default:
      LWIP_ASSERT("pbuf_alloc: erroneous type", 0);
      return NULL;
  }
  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_alloc(length=%"U16_F") == %p\n", length, (void *)p));
  return p;
}

/**
 * @ingroup pbuf
 * Allocates a pbuf for referenced data.
 * Referenced data can be volatile (PBUF_REF) or long-lived (PBUF_ROM).
 *
 * The actual memory allocated for the pbuf is determined by the
 * layer at which the pbuf is allocated and the requested size
 * (from the size parameter).
 *
 * @param payload referenced payload
 * @param length size of the pbuf's payload
 * @param type this parameter decides how and where the pbuf
 * should be allocated as follows:
 *
 * - PBUF_ROM: It is assumed that the memory used is really
 *             similar to ROM in that it is immutable and will not be
 *             changed. Memory which is dynamic should generally not
 *             be attached to PBUF_ROM pbufs. Use PBUF_REF instead.
 * - PBUF_REF: It is assumed that the pbuf is only
 *             being used in a single thread. If the pbuf gets queued,
 *             then pbuf_take should be called to copy the buffer.
 *
 * @return the allocated pbuf.
 */
/*********************************************************************************************************
** 函数名称: pbuf_alloc_reference
** 功能描述: 从 MEMP_PBUF 中申请一个 PBUF_REF/ROM 类型的 pbuf，即只申请 struct pbuf 结构体空间
** 输	 入: payload - 申请后 pbuf 负载数据起始地址
**		   : length - 申请后 pbuf 包含的应用负载数据长度
**		   : type - 申请的 pbuf 类型
** 输	 出: p - 成功申请的 struct pbuf 指针
**		   : NULL - 申请失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct pbuf *
pbuf_alloc_reference(void *payload, u16_t length, pbuf_type type)
{
  struct pbuf *p;
  LWIP_ASSERT("invalid pbuf_type", (type == PBUF_REF) || (type == PBUF_ROM));
  /* only allocate memory for the pbuf structure */
  p = (struct pbuf *)memp_malloc(MEMP_PBUF);
  if (p == NULL) {
    LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                ("pbuf_alloc_reference: Could not allocate MEMP_PBUF for PBUF_%s.\n",
                 (type == PBUF_ROM) ? "ROM" : "REF"));
    return NULL;
  }
  pbuf_init_alloced_pbuf(p, payload, length, length, type, 0);
  return p;
}


#if LWIP_SUPPORT_CUSTOM_PBUF
/**
 * @ingroup pbuf
 * Initialize a custom pbuf (already allocated).
 * Example of custom pbuf usage: @ref zerocopyrx
 *
 * @param l header size
 * @param length size of the pbuf's payload
 * @param type type of the pbuf (only used to treat the pbuf accordingly, as
 *        this function allocates no memory)
 * @param p pointer to the custom pbuf to initialize (already allocated)
 * @param payload_mem pointer to the buffer that is used for payload and headers,
 *        must be at least big enough to hold 'length' plus the header size,
 *        may be NULL if set later.
 *        ATTENTION: The caller is responsible for correct alignment of this buffer!!
 * @param payload_mem_len the size of the 'payload_mem' buffer, must be at least
 *        big enough to hold 'length' plus the header size
 */
/*********************************************************************************************************
** 函数名称: pbuf_alloced_custom
** 功能描述: 初始化一个指定的、用户自定义的 pbuf_custom 结构 
** 输	 入: l - 当前 pbuf_custom 中协议头空间字节数
**		   : length - 初始化后 pbuf_custom 包含的“应用”负载数据长度
**		   : type - 初始化后 pbuf_custom 类型
**         : p - 需要初始化的 pbuf_custom 指针
**         : payload_mem - 调用者提供的 pbuf_custom 的内存空间指针（包括应用负载数据和协议头数据） 
**         : payload_mem_len - 调用者提供的 pbuf_custom 的内存空间长度
** 输	 出: p->pbuf - 成功申请的 struct pbuf 指针
**		   : NULL - 申请失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct pbuf *
pbuf_alloced_custom(pbuf_layer l, u16_t length, pbuf_type type, struct pbuf_custom *p,
                    void *payload_mem, u16_t payload_mem_len)
{
  u16_t offset = (u16_t)l;
  void *payload;
  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_alloced_custom(length=%"U16_F")\n", length));

  /* 如果传入的自定义缓冲区大小不够大，则直接返回 NULL */
  if (LWIP_MEM_ALIGN_SIZE(offset) + length > payload_mem_len) {
    LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_LEVEL_WARNING, ("pbuf_alloced_custom(length=%"U16_F") buffer too short\n", length));
    return NULL;
  }

  if (payload_mem != NULL) {
    payload = (u8_t *)payload_mem + LWIP_MEM_ALIGN_SIZE(offset);
  } else {
    payload = NULL;
  }
  pbuf_init_alloced_pbuf(&p->pbuf, payload, length, length, type, PBUF_FLAG_IS_CUSTOM);
  return &p->pbuf;
}
#endif /* LWIP_SUPPORT_CUSTOM_PBUF */

/**
 * @ingroup pbuf
 * Shrink a pbuf chain to a desired length.
 *
 * @param p pbuf to shrink.
 * @param new_len desired new length of pbuf chain
 *
 * Depending on the desired length, the first few pbufs in a chain might
 * be skipped and left unchanged. The new last pbuf in the chain will be
 * resized, and any remaining pbufs will be freed.
 *
 * @note If the pbuf is ROM/REF, only the ->tot_len and ->len fields are adjusted.
 * @note May not be called on a packet queue.
 *
 * @note Despite its name, pbuf_realloc cannot grow the size of a pbuf (chain).
 */
/*********************************************************************************************************
** 函数名称: pbuf_realloc
** 功能描述: 收缩指定的 pbuf 应用负载空间长度到指定的值（把 pbuf 链表尾部多余的 pbuf 释放掉）
** 输	 入: p - 需要收缩的 pbuf 指针
**		   : new_len - 收缩后的 pbuf 应用负载空间长度
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
pbuf_realloc(struct pbuf *p, u16_t new_len)
{
  struct pbuf *q;
  u16_t rem_len; /* remaining length */
  u16_t shrink;

  LWIP_ASSERT("pbuf_realloc: p != NULL", p != NULL);

  /* desired length larger than current length? */
  /* 当前版本不支持 pbuf 空间扩展功能 */
  if (new_len >= p->tot_len) {
    /* enlarging not yet supported */
    return;
  }

  /* the pbuf chain grows by (new_len - p->tot_len) bytes
   * (which may be negative in case of shrinking) */
  shrink = (u16_t)(p->tot_len - new_len);

  /* first, step over any pbufs that should remain in the chain */
  rem_len = new_len;
  q = p;
  
  /* should this pbuf be kept? */
  /* 从 pbuf 链表头开始遍历，根据长度信息找到需要执行收缩操作的 pbuf 节点位置 */
  while (rem_len > q->len) {
    /* decrease remaining length by pbuf length */
    rem_len = (u16_t)(rem_len - q->len);
    /* decrease total length indicator */
    q->tot_len = (u16_t)(q->tot_len - shrink);
    /* proceed to next pbuf in chain */
    q = q->next;
    LWIP_ASSERT("pbuf_realloc: q != NULL", q != NULL);
  }
  
  /* we have now reached the new last pbuf (in q) */
  /* rem_len == desired length for pbuf q */

  /* shrink allocated memory for PBUF_RAM */
  /* (other types merely adjust their length fields */
  if (pbuf_match_allocsrc(q, PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP) && (rem_len != q->len)
#if LWIP_SUPPORT_CUSTOM_PBUF
      /* 因为用户自定的 pbuf 需要用户自己回收，所以我们不能对用户自定义的 pbuf 执行收缩操作 */
      && ((q->flags & PBUF_FLAG_IS_CUSTOM) == 0)
#endif /* LWIP_SUPPORT_CUSTOM_PBUF */
     ) {
    /* reallocate and adjust the length of the pbuf that will be split */
	/* 因为是从内存堆中申请的 pbuf，所以  pbuf 的 struct pbuf 结构和后面的负载数据空间是连续的
	 * 所以 (u8_t *)q->payload - (u8_t *)q 计算后的结果等于“头部”长度 */
    q = (struct pbuf *)mem_trim(q, (mem_size_t)(((u8_t *)q->payload - (u8_t *)q) + rem_len));
    LWIP_ASSERT("mem_trim returned q == NULL", q != NULL);
  }
  /* adjust length fields for new last pbuf */
  q->len = rem_len;
  q->tot_len = q->len;

  /* any remaining pbufs in chain? */
  /* 从原来的 pbuf 链表上把那些不需要的 pbuf 所占用的空间释放掉 */
  if (q->next != NULL) {
    /* free remaining pbufs in chain */
    pbuf_free(q->next);
  }
  /* q is last packet in chain */
  q->next = NULL;

}

/**
 * Adjusts the payload pointer to reveal headers in the payload.
 * @see pbuf_add_header.
 *
 * @param p pbuf to change the header size.
 * @param header_size_increment Number of bytes to increment header size.
 * @param force Allow 'header_size_increment > 0' for PBUF_REF/PBUF_ROM types
 *
 * @return non-zero on failure, zero on success.
 *
 */
/*********************************************************************************************************
** 函数名称: pbuf_add_header_impl
** 功能描述: 把指定的 pbuf 负载数据指针向前调整指定字节数，这样就可以把“隐藏”的协议头数据“放到”负载
**         : 数据空间中，我们就可以通过 pbuf->payload 指针访问协议头数据了
** 输	 入: p - 需要调整的 pbuf 指针
**		   : header_size_increment - 要显示出来的协议头长度
**         : force - 如果 pbuf 的 struct pbuf 和 payload 在地址上不连续，是否仍然调整 payload 指针位置
** 输	 出: 0 - 执行成功
**         : 1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static u8_t
pbuf_add_header_impl(struct pbuf *p, size_t header_size_increment, u8_t force)
{
  u16_t type_internal;
  void *payload;
  u16_t increment_magnitude;

  LWIP_ASSERT("p != NULL", p != NULL);
  if ((p == NULL) || (header_size_increment > 0xFFFF)) {
    return 1;
  }
  if (header_size_increment == 0) {
    return 0;
  }

  increment_magnitude = (u16_t)header_size_increment;
  /* Do not allow tot_len to wrap as a result. */
  if ((u16_t)(increment_magnitude + p->tot_len) < increment_magnitude) {
    return 1;
  }

  type_internal = p->type_internal;

  /* pbuf types containing payloads? */
  if (type_internal & PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS) {
    /* set new payload pointer */
    /* 如果 pbuf 的 struct pbuf 和 payload 在地址上连续，则根据需要添加的头部长度，调整 pbuf 的负载指针位置 */
    payload = (u8_t *)p->payload - header_size_increment;
    /* boundary check fails? */

    /* 检查调整后的负载指针位置是否向前越界（即是否处于 struct pbuf 结构中）*/
    if ((u8_t *)payload < (u8_t *)p + SIZEOF_STRUCT_PBUF) {
      LWIP_DEBUGF( PBUF_DEBUG | LWIP_DBG_TRACE,
                   ("pbuf_add_header: failed as %p < %p (not enough space for new header size)\n",
                    (void *)payload, (void *)((u8_t *)p + SIZEOF_STRUCT_PBUF)));
      /* bail out unsuccessfully */
      return 1;
    }
    /* pbuf types referring to external payloads? */
  } else {
    /* hide a header in the payload? */
    if (force) {
      payload = (u8_t *)p->payload - header_size_increment;
    } else {
      /* cannot expand payload to front (yet!)
       * bail out unsuccessfully */
      return 1;
    }
  }
  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_add_header: old %p new %p (%"U16_F")\n",
              (void *)p->payload, (void *)payload, increment_magnitude));

  /* modify pbuf fields */
  p->payload = payload;
  p->len = (u16_t)(p->len + increment_magnitude);
  p->tot_len = (u16_t)(p->tot_len + increment_magnitude);


  return 0;
}

/**
 * Adjusts the payload pointer to reveal headers in the payload.
 *
 * Adjusts the ->payload pointer so that space for a header
 * appears in the pbuf payload.
 *
 * The ->payload, ->tot_len and ->len fields are adjusted.
 *
 * @param p pbuf to change the header size.
 * @param header_size_increment Number of bytes to increment header size which
 *          increases the size of the pbuf. New space is on the front.
 *          If header_size_increment is 0, this function does nothing and returns successful.
 *
 * PBUF_ROM and PBUF_REF type buffers cannot have their sizes increased, so
 * the call will fail. A check is made that the increase in header size does
 * not move the payload pointer in front of the start of the buffer.
 *
 * @return non-zero on failure, zero on success.
 *
 */
/*********************************************************************************************************
** 函数名称: pbuf_add_header
** 功能描述: 把指定的 pbuf 负载数据指针向前调整指定字节数，这样就可以通过 pbuf->payload 访问协议头数据了
** 输	 入: p - 需要调整的 pbuf 指针
**		   : header_size_increment - 要显示出来的协议头长度
** 输	 出: 0 - 执行成功
**         : 1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
pbuf_add_header(struct pbuf *p, size_t header_size_increment)
{
  return pbuf_add_header_impl(p, header_size_increment, 0);
}

/**
 * Same as @ref pbuf_add_header but does not check if 'header_size > 0' is allowed.
 * This is used internally only, to allow PBUF_REF for RX.
 */
/*********************************************************************************************************
** 函数名称: pbuf_add_header_force
** 功能描述: 把指定的 pbuf 负载数据指针向前调整指定字节数，这样就可以通过 pbuf->payload 访问协议头数据了
**         : 如果 pbuf 的 struct pbuf 和 payload 在地址上不连续，仍然调整 payload 指针位置
** 输	 入: p - 需要调整的 pbuf 指针
**		   : header_size_increment - 要显示出来的协议头长度
** 输	 出: 0 - 执行成功
**         : 1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
pbuf_add_header_force(struct pbuf *p, size_t header_size_increment)
{
  return pbuf_add_header_impl(p, header_size_increment, 1);
}

/**
 * Adjusts the payload pointer to hide headers in the payload.
 *
 * Adjusts the ->payload pointer so that space for a header
 * disappears in the pbuf payload.
 *
 * The ->payload, ->tot_len and ->len fields are adjusted.
 *
 * @param p pbuf to change the header size.
 * @param header_size_decrement Number of bytes to decrement header size which
 *          decreases the size of the pbuf.
 *          If header_size_decrement is 0, this function does nothing and returns successful.
 * @return non-zero on failure, zero on success.
 *
 */
/*********************************************************************************************************
** 函数名称: pbuf_remove_header
** 功能描述: 把指定的 pbuf 负载数据指针向后调整指定字节数，这样就可以把协议头从 pbuf->payload 中移除
**         : 这样接下来通过 pbuf->payload 指针访问的就是协议负载数据了
** 输	 入: p - 需要调整的 pbuf 指针
**		   : header_size_increment - 要隐藏的协议头长度
** 输	 出: 0 - 执行成功
**		   : 1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
pbuf_remove_header(struct pbuf *p, size_t header_size_decrement)
{
  void *payload;
  u16_t increment_magnitude;

  LWIP_ASSERT("p != NULL", p != NULL);
  if ((p == NULL) || (header_size_decrement > 0xFFFF)) {
    return 1;
  }
  if (header_size_decrement == 0) {
    return 0;
  }

  increment_magnitude = (u16_t)header_size_decrement;
  /* Check that we aren't going to move off the end of the pbuf */
  LWIP_ERROR("increment_magnitude <= p->len", (increment_magnitude <= p->len), return 1;);

  /* remember current payload pointer */
  payload = p->payload;
  LWIP_UNUSED_ARG(payload); /* only used in LWIP_DEBUGF below */

  /* increase payload pointer (guarded by length check above) */
  p->payload = (u8_t *)p->payload + header_size_decrement;
  /* modify pbuf length fields */
  p->len = (u16_t)(p->len - increment_magnitude);
  p->tot_len = (u16_t)(p->tot_len - increment_magnitude);

  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_remove_header: old %p new %p (%"U16_F")\n",
              (void *)payload, (void *)p->payload, increment_magnitude));

  return 0;
}

/*********************************************************************************************************
** 函数名称: pbuf_header_impl
** 功能描述: 把指定的 pbuf 的负载指针（pbuf->payload）位置向前（显示协议头数据，header_size_increment 大于零）
**         : 或者向后（隐藏协议头数据，header_size_increment 小于零）调整指定字节数
** 输	 入: p - 需要调整的 pbuf 指针
**		   : header_size_increment - 要调整的协议头长度
**         : force - 如果 pbuf 的 struct pbuf 和 payload 在地址上不连续，是否仍然调整 payload 指针位置
** 输	 出: 0 - 执行成功
**		   : 1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static u8_t
pbuf_header_impl(struct pbuf *p, s16_t header_size_increment, u8_t force)
{
  if (header_size_increment < 0) {
    return pbuf_remove_header(p, (size_t) - header_size_increment);
  } else {
    return pbuf_add_header_impl(p, (size_t)header_size_increment, force);
  }
}

/**
 * Adjusts the payload pointer to hide or reveal headers in the payload.
 *
 * Adjusts the ->payload pointer so that space for a header
 * (dis)appears in the pbuf payload.
 *
 * The ->payload, ->tot_len and ->len fields are adjusted.
 *
 * @param p pbuf to change the header size.
 * @param header_size_increment Number of bytes to increment header size which
 * increases the size of the pbuf. New space is on the front.
 * (Using a negative value decreases the header size.)
 * If header_size_increment is 0, this function does nothing and returns successful.
 *
 * PBUF_ROM and PBUF_REF type buffers cannot have their sizes increased, so
 * the call will fail. A check is made that the increase in header size does
 * not move the payload pointer in front of the start of the buffer.
 * @return non-zero on failure, zero on success.
 *
 */
/*********************************************************************************************************
** 函数名称: pbuf_header
** 功能描述: 把指定的 pbuf 的负载指针（pbuf->payload）位置向前（显示协议头数据，header_size_increment 大于零）
**		   : 或者向后（隐藏协议头数据，header_size_increment 小于零）调整指定字节数
** 注     释: 如果 pbuf 的 struct pbuf 和 payload 在地址上不连续，则不调整 payload 指针位置
** 输	 入: p - 需要调整的 pbuf 指针
**		   : header_size_increment - 要调整的协议头长度
** 输	 出: 0 - 执行成功
**		   : 1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
pbuf_header(struct pbuf *p, s16_t header_size_increment)
{
  return pbuf_header_impl(p, header_size_increment, 0);
}

/**
 * Same as pbuf_header but does not check if 'header_size > 0' is allowed.
 * This is used internally only, to allow PBUF_REF for RX.
 */
/*********************************************************************************************************
** 函数名称: pbuf_header_force
** 功能描述: 把指定的 pbuf 的负载指针（pbuf->payload）位置向前（显示协议头数据，header_size_increment 大于零）
**		   : 或者向后（隐藏协议头数据，header_size_increment 小于零）调整指定字节数
** 注	 释: 如果 pbuf 的 struct pbuf 和 payload 在地址上不连续，则仍然调整 payload 指针位置
** 输	 入: p - 需要调整的 pbuf 指针
**		   : header_size_increment - 要调整的协议头长度
** 输	 出: 0 - 执行成功
**		   : 1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
pbuf_header_force(struct pbuf *p, s16_t header_size_increment)
{
  return pbuf_header_impl(p, header_size_increment, 1);
}

/** Similar to pbuf_header(-size) but de-refs header pbufs for (size >= p->len)
 *
 * @param q pbufs to operate on
 * @param size The number of bytes to remove from the beginning of the pbuf list.
 *             While size >= p->len, pbufs are freed.
 *        ATTENTION: this is the opposite direction as @ref pbuf_header, but
 *                   takes an u16_t not s16_t!
 * @return the new head pbuf
 */
/*********************************************************************************************************
** 函数名称: pbuf_free_header
** 功能描述: 从指定的 pbuf 的链表头部开始，移除指定字节数的内存空间，并释放空闲的 pbuf
** 输	 入: q - 需要调整的 pbuf 指针
**		   : size - 要释放的空间字节数
** 输	 出: p - 移除指定空间后的 pbuf 指针
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct pbuf *
pbuf_free_header(struct pbuf *q, u16_t size)
{
  struct pbuf *p = q;
  u16_t free_left = size;
  
  while (free_left && p) {
    if (free_left >= p->len) {
      struct pbuf *f = p;
      free_left = (u16_t)(free_left - p->len);
      p = p->next;
      f->next = 0;
      pbuf_free(f);
    } else {
      pbuf_remove_header(p, free_left);
      free_left = 0;
    }
  }
  return p;
}

/**
 * @ingroup pbuf
 * Dereference a pbuf chain or queue and deallocate any no-longer-used
 * pbufs at the head of this chain or queue.
 *
 * Decrements the pbuf reference count. If it reaches zero, the pbuf is
 * deallocated.
 *
 * For a pbuf chain, this is repeated for each pbuf in the chain,
 * up to the first pbuf which has a non-zero reference count after
 * decrementing. So, when all reference counts are one, the whole
 * chain is free'd.
 *
 * @param p The pbuf (chain) to be dereferenced.
 *
 * @return the number of pbufs that were de-allocated
 * from the head of the chain.
 *
 * @note MUST NOT be called on a packet queue (Not verified to work yet).
 * @note the reference counter of a pbuf equals the number of pointers
 * that refer to the pbuf (or into the pbuf).
 *
 * @internal examples:
 *
 * Assuming existing chains a->b->c with the following reference
 * counts, calling pbuf_free(a) results in:
 *
 * 1->2->3 becomes ...1->3
 * 3->3->3 becomes 2->3->3
 * 1->1->2 becomes ......1
 * 2->1->1 becomes 1->1->1
 * 1->1->1 becomes .......
 *
 */
/*********************************************************************************************************
** 函数名称: pbuf_free
** 功能描述: 从指定的 pbuf or pbuf chain 链表表头位置开始尝试回收空闲 pbuf 成员
** 注     释: 1. 在 pbuf chain 中，因为所有的 pbuf 都是通过 struct pbuf 中的单向链表链接起来的且所有前驱
**  	   :    都指向和他相邻的后驱，所以，非表头的 pbuf 成员引用计数永远不可能为 0，所以在释放 pbuf 的
**  	   :    时候只需要检查链表表头成员即可，如果表头成员被释放（引用计数为 0），然后把表头向后移动
**         : 2. 如果一个 pbuf chain 没有被其他模块引用，那么通过                   pbuf_cat 连接起来的 pbuf chain 上所有非
**         :    表头 pbuf 的引用计数都是 1（因为刚申请的 pbuf 引用计数默认为 1，而 pbuf_cat 不会增加 pbuf
**         :    的引用计数），所以在执行这个函数的时候会回收 pbuf chain 链表上的所有成员，如果这个 pbuf
**         :    chain 被其他模块引用了（链表头被被其他模块引用），那么在本次调用 pbuf_free 的时候是不会
**         :    释放所有 pbuf 成员，而是在其他的、最后一个引用模块中调用 pbuf_free 接口的时候被释放的
**         : 3. 如果一个 pbuf chain 没有被其他模块引用，那么通过                   pbuf_chain 连接起来的 pbuf chain 中除了
**         :    连接点后端的 pbuf 成员引用计数为 2，其他所有的 pbuf 成员引用计数仍然为 1，所以调用 pbuf_free
**         :    后，在 pbuf_chain 连接点前段的所有 pbuf 成员都会被回收
** 输	 入: p - 需要回收的 pbuf chain 指针
** 输	 出: count - 从 pbuf chain 中释放的 pbuf 成员个数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
pbuf_free(struct pbuf *p)
{
  u8_t alloc_src;
  struct pbuf *q;
  u8_t count;

  if (p == NULL) {
    LWIP_ASSERT("p != NULL", p != NULL);
    /* if assertions are disabled, proceed with debug output */
    LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                ("pbuf_free(p == NULL) was called.\n"));
    return 0;
  }
  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_free(%p)\n", (void *)p));

  PERF_START;

  count = 0;
  /* de-allocate all consecutive pbufs from the head of the chain that
   * obtain a zero reference count after decrementing*/
  while (p != NULL) {
    LWIP_PBUF_REF_T ref;
    SYS_ARCH_DECL_PROTECT(old_level);
    /* Since decrementing ref cannot be guaranteed to be a single machine operation
     * we must protect it. We put the new ref into a local variable to prevent
     * further protection. */
    SYS_ARCH_PROTECT(old_level);
    /* all pbufs in a chain are referenced at least once */
    LWIP_ASSERT("pbuf_free: p->ref > 0", p->ref > 0);
    /* decrease reference count (number of pointers to pbuf) */
	/* */
	ref = --(p->ref);

	SYS_ARCH_UNPROTECT(old_level);
    /* this pbuf is no longer referenced to? */
	/* 在 pbuf chain 中，因为所有的 pbuf 都是通过 struct pbuf 中的单向链表链接起来的且所有前驱
 	 * 都指向和他相邻的后驱，所以，非表头的 pbuf 引用计数永远不可能为 0，所以在释放 pbuf 的时候
 	 * 只需要检查链表表头成员即可，如果表头成员被释放（引用计数为 0），然后把表头向后移动 */
    if (ref == 0) {
      /* remember next pbuf in chain for next iteration */
      q = p->next;
      LWIP_DEBUGF( PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_free: deallocating %p\n", (void *)p));
      alloc_src = pbuf_get_allocsrc(p);
#if LWIP_SUPPORT_CUSTOM_PBUF
      /* is this a custom pbuf? */
      /* 如果当前 pbuf 是用户自定义的 pbuf，则通过用户设置的回收内存函数 pbuf->custom_free_function 
       * 来回收这个 pbuf_custom 结构所占用的内存空间 */
      if ((p->flags & PBUF_FLAG_IS_CUSTOM) != 0) {
        struct pbuf_custom *pc = (struct pbuf_custom *)p;
        LWIP_ASSERT("pc->custom_free_function != NULL", pc->custom_free_function != NULL);
        pc->custom_free_function(p);
      } else
#endif /* LWIP_SUPPORT_CUSTOM_PBUF */
      {
		/* 如果当前 pbuf 不是用户自定义的，则根据其类型分别调用对应的内存回收接口 */
	  
        /* is this a pbuf from the pool? */
        if (alloc_src == PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF_POOL) {
          memp_free(MEMP_PBUF_POOL, p);
          /* is this a ROM or RAM referencing pbuf? */
        } else if (alloc_src == PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF) {
          memp_free(MEMP_PBUF, p);
          /* type == PBUF_RAM */
        } else if (alloc_src == PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP) {
          mem_free(p);
        } else {
          /* @todo: support freeing other types */
          LWIP_ASSERT("invalid pbuf type", 0);
        }
      }
      count++;
      /* proceed to next pbuf */
	  /* pbuf chain 表头成员已经被释放，把表头指针向后移动一个位置 */
      p = q;
      /* p->ref > 0, this pbuf is still referenced to */
      /* (and so the remaining pbufs in chain as well) */
    } else {
      LWIP_DEBUGF( PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_free: %p has ref %"U16_F", ending here.\n", (void *)p, (u16_t)ref));
      /* stop walking through the chain */
	  /* 如果 pbuf chain 当前表头成员引用计数不是 0，则表示 pbuf chain 中没有需要释放的 pbuf 成员，则直接退出 */
      p = NULL;
    }
  }
  PERF_STOP("pbuf_free");
  /* return number of de-allocated pbufs */
  return count;
}

/**
 * Count number of pbufs in a chain
 *
 * @param p first pbuf of chain
 * @return the number of pbufs in a chain
 */
/*********************************************************************************************************
** 函数名称: pbuf_clen
** 功能描述: 统计指定的 pbuf chain 链表长度，即有效的 pbuf 成员个数
** 输	 入: p - 需要统计的 pbuf  指针
** 输	 出: len - pbuf chain 的成员个数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u16_t
pbuf_clen(const struct pbuf *p)
{
  u16_t len;

  len = 0;
  while (p != NULL) {
    ++len;
    p = p->next;
  }
  return len;
}

/**
 * @ingroup pbuf
 * Increment the reference count of the pbuf.
 *
 * @param p pbuf to increase reference counter of
 *
 */
/*********************************************************************************************************
** 函数名称: pbuf_ref
** 功能描述: 把指定的 pbuf 成员引用计数加 1
** 输	 入: p - 需要操作的 pbuf	指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
pbuf_ref(struct pbuf *p)
{
  /* pbuf given? */
  if (p != NULL) {
    SYS_ARCH_SET(p->ref, (LWIP_PBUF_REF_T)(p->ref + 1));
    LWIP_ASSERT("pbuf ref overflow", p->ref > 0);
  }
}

/**
 * @ingroup pbuf
 * Concatenate two pbufs (each may be a pbuf chain) and take over
 * the caller's reference of the tail pbuf.
 *
 * @note The caller MAY NOT reference the tail pbuf afterwards.
 * Use pbuf_chain() for that purpose.
 *
 * This function explicitly does not check for tot_len overflow to prevent
 * failing to queue too long pbufs. This can produce invalid pbufs, so
 * handle with care!
 *
 * @see pbuf_chain()
 */
/*********************************************************************************************************
** 函数名称: pbuf_cat
** 功能描述: 把两个指定的 pbuf chain 合并成一个 pbuf chain，即把指定的尾部方向 pbuf chain 链表链接到
**         : 指定的 pbuf chain 头部方向链表上
** 注     释: 比较重要的一个信息是，在执行 pbuf_cat 时并没有增加 pbuf 的引用计数，而 pbuf 在申请后默认
**         : 引用计数值为 1，所以通过 pbuf_cat            链接在一起的 pbuf chain 的 pbuf 成员引用计数都为 1
** 输	 入: h - 合并后处于链表头的 pbuf chain 指针
**         : t - 合并后处于链表尾的 pbuf chain 指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
pbuf_cat(struct pbuf *h, struct pbuf *t)
{
  struct pbuf *p;

  LWIP_ERROR("(h != NULL) && (t != NULL) (programmer violates API)",
             ((h != NULL) && (t != NULL)), return;);

  /* proceed to last pbuf of chain */
  /* 调整头部方向的 pbuf chain 中每个 pbuf 成员（但是不包括链表尾部成员）的 tot_len 字段变量值 */
  for (p = h; p->next != NULL; p = p->next) {
    /* add total length of second chain to all totals of first chain */
    p->tot_len = (u16_t)(p->tot_len + t->tot_len);
  }
  
  /* { p is last pbuf of first h chain, p->next == NULL } */
  LWIP_ASSERT("p->tot_len == p->len (of last pbuf in chain)", p->tot_len == p->len);
  LWIP_ASSERT("p->next == NULL", p->next == NULL);
  /* add total length of second chain to last pbuf total of first chain */
  /* 调整头部方向的 pbuf chain 链表尾部成员的 tot_len 字段变量值 */
  p->tot_len = (u16_t)(p->tot_len + t->tot_len);

  /* chain last pbuf of head (p) with first of tail (t) */
  /* 把尾部方向的 pbuf chain 链表链接到头部方向的 pbuf chain 中 */
  p->next = t;
  
  /* p->next now references t, but the caller will drop its reference to t,
   * so netto there is no change to the reference count of t.
   */
  /* 因为调用这个接口的调用者自己会增加 t pbuf 的引用计数值，所以这个位置不需要显示增加了 */
}

/**
 * @ingroup pbuf
 * Chain two pbufs (or pbuf chains) together.
 *
 * The caller MUST call pbuf_free(t) once it has stopped
 * using it. Use pbuf_cat() instead if you no longer use t.
 *
 * @param h head pbuf (chain)
 * @param t tail pbuf (chain)
 * @note The pbufs MUST belong to the same packet.
 * @note MAY NOT be called on a packet queue.
 *
 * The ->tot_len fields of all pbufs of the head chain are adjusted.
 * The ->next field of the last pbuf of the head chain is adjusted.
 * The ->ref field of the first pbuf of the tail chain is adjusted.
 *
 */
/*********************************************************************************************************
** 函数名称: pbuf_chain
** 功能描述: 把两个指定的 pbuf chain 合并成一个 pbuf chain，即把指定的尾部方向 pbuf chain 链表链接到
**         : 指定的 pbuf chain 头部方向链表上，并把连接点后端 pbuf 的引用计数加 1，又因为 pbuf 在申请
**         : 后默认引用计数值为 1，所以连接点后端 pbuf 的引用计数至少为 2
** 输	 入: h - 合并后处于链表头的 pbuf chain 指针
**         : t - 合并后处于链表尾的 pbuf chain 指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
pbuf_chain(struct pbuf *h, struct pbuf *t)
{
  pbuf_cat(h, t);
  
  /* t is now referenced by h */
  /* 把两个 pbuf/pbuf chain 连接点后端的 pbuf 引用计数加 1 */
  pbuf_ref(t);
  
  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_chain: %p references %p\n", (void *)h, (void *)t));
}

/**
 * Dechains the first pbuf from its succeeding pbufs in the chain.
 *
 * Makes p->tot_len field equal to p->len.
 * @param p pbuf to dechain
 * @return remainder of the pbuf chain, or NULL if it was de-allocated.
 * @note May not be called on a packet queue.
 */
/*********************************************************************************************************
** 函数名称: pbuf_dechain
** 功能描述: 从指定的 pbuf chain 链表头部拿下一个 pbuf 成员，并尝试释放以 second pbuf 为表头的 pbuf chain
**         : 如果有 pbuf 成员被释放，则返回 NULL，如果没有释放任何 pbuf 成员，则返回 second pbuf 指针
** 输	 入: p - 提供 pbuf 的 pbuf/pbuf chain 指针
** 输	 出: q - 拿出一个 pbuf 后、余下的 pbuf/pbuf chain 指针
**         : NULL - 已经没有剩余的 pbuf 了
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct pbuf *
pbuf_dechain(struct pbuf *p)
{
  struct pbuf *q;
  u8_t tail_gone = 1;
  /* tail */
  q = p->next;
  /* pbuf has successor in chain? */
  if (q != NULL) {
    /* assert tot_len invariant: (p->tot_len == p->len + (p->next? p->next->tot_len: 0) */
    LWIP_ASSERT("p->tot_len == p->len + q->tot_len", q->tot_len == p->tot_len - p->len);
    /* enforce invariant if assertion is disabled */
    q->tot_len = (u16_t)(p->tot_len - p->len);
    /* decouple pbuf from remainder */
    p->next = NULL;
    /* total length of pbuf p is its own length only */
    p->tot_len = p->len;
    /* q is no longer referenced by p, free it */
    LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_dechain: unreferencing %p\n", (void *)q));

	/* 以为通过  pbuf_chain 连接起来的单体 pbuf          成员，在 pbuf     chain 中所有非表头的        pbuf 引用计数至少为     2
	 * 所以这个位置正常情况下都不会有 pbuf 成员空间被释放 */
    tail_gone = pbuf_free(q);
    if (tail_gone > 0) {
      LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE,
                  ("pbuf_dechain: deallocated %p (as it is no longer referenced)\n", (void *)q));
    }
    /* return remaining tail or NULL if deallocated */
  }
  /* assert tot_len invariant: (p->tot_len == p->len + (p->next? p->next->tot_len: 0) */
  LWIP_ASSERT("p->tot_len == p->len", p->tot_len == p->len);
  return ((tail_gone > 0) ? NULL : q);
}

/**
 * @ingroup pbuf
 * Create PBUF_RAM copies of pbufs.
 *
 * Used to queue packets on behalf of the lwIP stack, such as
 * ARP based queueing.
 *
 * @note You MUST explicitly use p = pbuf_take(p);
 *
 * @note Only one packet is copied, no packet queue!
 *
 * @param p_to pbuf destination of the copy
 * @param p_from pbuf source of the copy
 *
 * @return ERR_OK if pbuf was copied
 *         ERR_ARG if one of the pbufs is NULL or p_to is not big
 *                 enough to hold p_from
 */
/*********************************************************************************************************
** 函数名称: pbuf_copy
** 功能描述: 把指定的源 pbuf/pbuf chain 中所有“负载空间内容”复制到指定的目的 pbuf/pbuf chain 中
** 注     释: 复制的时候，不会复制被隐藏的协议头数据
** 输	 入: p_to - 目的 pbuf/pbuf chain 指针
**         : p_from - 源 pbuf/pbuf chain 指针
** 输	 出: ERR_OK - 复制成功
**         : ERR_ARG/ERR_VAL - 复制失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
pbuf_copy(struct pbuf *p_to, const struct pbuf *p_from)
{
  size_t offset_to = 0, offset_from = 0, len;

  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_copy(%p, %p)\n",
              (const void *)p_to, (const void *)p_from));

  /* is the target big enough to hold the source? */
  LWIP_ERROR("pbuf_copy: target not big enough to hold source", ((p_to != NULL) &&
             (p_from != NULL) && (p_to->tot_len >= p_from->tot_len)), return ERR_ARG;);

  /* iterate through pbuf chain */
  /* 分别遍历到 p_from（pbuf chain）链表上的每一个 pbuf 成员，然后复制每一个成员数据到 p_to 中 */
  do {
    /* copy one part of the original chain */
    /* 以为 pbuf chain 链表中的每一个 pbuf 成员地址空间是不连续的，所以我们在从 p_from 复制数据到
	 * p_to 的时候，需要取二者中“小”的值 */
    if ((p_to->len - offset_to) >= (p_from->len - offset_from)) {
      /* complete current p_from fits into current p_to */
      len = p_from->len - offset_from;
    } else {
      /* current p_from does not fit into current p_to */
      len = p_to->len - offset_to;
    }
	
    MEMCPY((u8_t *)p_to->payload + offset_to, (u8_t *)p_from->payload + offset_from, len);
    offset_to += len;
    offset_from += len;
    LWIP_ASSERT("offset_to <= p_to->len", offset_to <= p_to->len);
    LWIP_ASSERT("offset_from <= p_from->len", offset_from <= p_from->len);

	/* 如果源 pbuf chain 正在操作的 pbuf 数据已经全部被复制完成，则更新到下一个 pbuf 成员位置 */
    if (offset_from >= p_from->len) {
      /* on to next p_from (if any) */
      offset_from = 0;
      p_from = p_from->next;
    }

	/* 如果目标 pbuf chain 正在操作的 pbuf 空间已经存满了，则更新到下一个 pbuf 成员位置 */
    if (offset_to == p_to->len) {
      /* on to next p_to (if any) */
      offset_to = 0;
      p_to = p_to->next;
      LWIP_ERROR("p_to != NULL", (p_to != NULL) || (p_from == NULL), return ERR_ARG;);
    }

	/* 判断是否已经遍历到 p_from（pbuf chain）链表的最后一个 pbuf */
    if ((p_from != NULL) && (p_from->len == p_from->tot_len)) {
      /* don't copy more than one packet! */
      LWIP_ERROR("pbuf_copy() does not allow packet queues!",
                 (p_from->next == NULL), return ERR_VAL;);
    }
	
	/* 判断是否已经遍历到 p_to（pbuf chain）链表的最后一个 pbuf */
    if ((p_to != NULL) && (p_to->len == p_to->tot_len)) {
      /* don't copy more than one packet! */
      LWIP_ERROR("pbuf_copy() does not allow packet queues!",
                 (p_to->next == NULL), return ERR_VAL;);
    }
  } while (p_from);
  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_copy: end of chain reached.\n"));
  return ERR_OK;
}

/**
 * @ingroup pbuf
 * Copy (part of) the contents of a packet buffer
 * to an application supplied buffer.
 *
 * @param buf the pbuf from which to copy data
 * @param dataptr the application supplied buffer
 * @param len length of data to copy (dataptr must be big enough). No more
 * than buf->tot_len will be copied, irrespective of len
 * @param offset offset into the packet buffer from where to begin copying len bytes
 * @return the number of bytes copied, or 0 on failure
 */
/*********************************************************************************************************
** 函数名称: pbuf_copy_partial
** 功能描述: 从指定的 pbuf/pbuf chain 的负载空间指定位置开始，复制指定长度的数据到用户提供的缓冲区中
** 输	 入: buf - 提供数据的 pbuf/pbuf chain 指针
**		   : dataptr - 用户空间缓冲区地址
**		   : len - 需要复制的数据长度
**		   : offset - 复制 pbuf 负载数据的偏移位置
** 输	 出: copied_total - 成功复制的数据字节数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u16_t
pbuf_copy_partial(const struct pbuf *buf, void *dataptr, u16_t len, u16_t offset)
{
  const struct pbuf *p;
  u16_t left = 0;
  u16_t buf_copy_len;
  u16_t copied_total = 0;

  LWIP_ERROR("pbuf_copy_partial: invalid buf", (buf != NULL), return 0;);
  LWIP_ERROR("pbuf_copy_partial: invalid dataptr", (dataptr != NULL), return 0;);

  /* Note some systems use byte copy if dataptr or one of the pbuf payload pointers are unaligned. */
  /* 从指定的 pbuf/pbuf chain 表头开始遍历链表中的 pbuf 成员 */
  for (p = buf; len != 0 && p != NULL; p = p->next) {
    if ((offset != 0) && (offset >= p->len)) {
      /* don't copy from this buffer -> on to the next */
      offset = (u16_t)(offset - p->len);
    } else {
      /* copy from this buffer. maybe only partially. */
      buf_copy_len = (u16_t)(p->len - offset);
      if (buf_copy_len > len) {
        buf_copy_len = len;
      }
      /* copy the necessary parts of the buffer */
      MEMCPY(&((char *)dataptr)[left], &((char *)p->payload)[offset], buf_copy_len);
      copied_total = (u16_t)(copied_total + buf_copy_len);
      left = (u16_t)(left + buf_copy_len);
      len = (u16_t)(len - buf_copy_len);
      offset = 0;
    }
  }
  return copied_total;
}

/**
 * @ingroup pbuf
 * Get part of a pbuf's payload as contiguous memory. The returned memory is
 * either a pointer into the pbuf's payload or, if split over multiple pbufs,
 * a copy into the user-supplied buffer.
 *
 * @param p the pbuf from which to copy data
 * @param buffer the application supplied buffer
 * @param bufsize size of the application supplied buffer
 * @param len length of data to copy (dataptr must be big enough). No more
 * than buf->tot_len will be copied, irrespective of len
 * @param offset offset into the packet buffer from where to begin copying len bytes
 * @return the number of bytes copied, or 0 on failure
 */
/*********************************************************************************************************
** 函数名称: pbuf_get_contiguous
** 功能描述: 从指定的 pbuf/pbuf chain 的不连续的负载空间的指定位置开始，复制指定长度的数据到用户提供的
**         : 缓冲区中，并返回最终复制后数据缓冲区起始地址，执行完这个函数后，我们需要的数据在内存地址
**         : 空间中是连续的
** 注     释: 如果我们需要复制的所有数据都在 pbuf/pbuf chain 的某个 pbuf 上，为了执行效率，则不会从 pbuf
**         : 中把数据复制到用户提供的缓冲区中，只有在我们需要的数据跨越多个 pbuf 的时候，才会把这些分散
**         : 的数据统一复制到用户提供的连续缓冲区中
** 输	 入: p - 提供数据的 pbuf/pbuf chain 指针
**		   : buffer - 用户空间缓冲区地址
**		   : bufsize - 用户空间缓冲区长度
**		   : len - 需要复制的数据字节数
**         : offset - 从 pbuf/pbuf chain 负载空间复制数据的起始位置
** 输	 出: buffer - 复制数据后的缓冲区起始地址
**         : NULL - 复制失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void *
pbuf_get_contiguous(const struct pbuf *p, void *buffer, size_t bufsize, u16_t len, u16_t offset)
{
  const struct pbuf *q;
  u16_t out_offset;

  LWIP_ERROR("pbuf_get_contiguous: invalid buf", (p != NULL), return NULL;);
  LWIP_ERROR("pbuf_get_contiguous: invalid dataptr", (buffer != NULL), return NULL;);
  LWIP_ERROR("pbuf_get_contiguous: invalid dataptr", (bufsize >= len), return NULL;);

  q = pbuf_skip_const(p, offset, &out_offset);
  if (q != NULL) {
    if (q->len >= (out_offset + len)) {
      /* all data in this pbuf, return zero-copy */
      return (u8_t *)q->payload + out_offset;
    }
    /* need to copy */
    if (pbuf_copy_partial(q, buffer, len, out_offset) != len) {
      /* copying failed: pbuf is too short */
      return NULL;
    }
    return buffer;
  }
  /* pbuf is too short (offset does not fit in) */
  return NULL;
}

#if LWIP_TCP && TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
/**
 * This method modifies a 'pbuf chain', so that its total length is
 * smaller than 64K. The remainder of the original pbuf chain is stored
 * in *rest.
 * This function never creates new pbufs, but splits an existing chain
 * in two parts. The tot_len of the modified packet queue will likely be
 * smaller than 64K.
 * 'packet queues' are not supported by this function.
 *
 * @param p the pbuf queue to be split
 * @param rest pointer to store the remainder (after the first 64K)
 */
/*********************************************************************************************************
** 函数名称: pbuf_split_64k
** 功能描述: 从指定的 pbuf chain 链表头开始，以 64K 为边界分割 pbuf chain 链表，使分割后的头部 pbuf chain
**         : 链表负载总空间长度不超过 64K，并返回剩余的、超过 64K 的那部分 pbuf chain
** 输	 入: buf - 需要分割的 pbuf chain 指针
** 输	 出: p - 分割后，保留前面 64K 的 pbuf chain 指针
**         : rest - 如果 pbuf chain 的总负载空间大于 64K，则返回分割后剩余部分 pbuf chain 指针
**         : NULL - 表示 pbuf chain 的总负载空间不大于 64K，所以分割后没有剩余 pbuf chain
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void pbuf_split_64k(struct pbuf *p, struct pbuf **rest)
{
  *rest = NULL;

  /* 遍历 pbuf/pbuf chain 链表，但是不会处理链表上的最后一个 pbuf 成员 */
  if ((p != NULL) && (p->next != NULL)) {
    u16_t tot_len_front = p->len;
    struct pbuf *i = p;
    struct pbuf *r = p->next;

    /* continue until the total length (summed up as u16_t) overflows */
	/* 从 pbuf chain 链表头依次向后遍历并计算已经遍历的 pbuf chain 中负载空间总长度
	 * 直到负载空间总长度累计到 64K 边界时结束 */
	while ((r != NULL) && ((u16_t)(tot_len_front + r->len) >= tot_len_front)) {
      tot_len_front = (u16_t)(tot_len_front + r->len);
      i = r;
      r = r->next;
    }
	
    /* i now points to last packet of the first segment. Set next
       pointer to NULL */
    i->next = NULL;

    if (r != NULL) {
      /* Update the tot_len field in the first part */
	  /* 如果我们指定的 pbuf chain 链表被分割成了两部分，则在分割后需要更新头部链表中 
	   * 每个 pbuf 结构中的 tot_len 字段值 */
      for (i = p; i != NULL; i = i->next) {
        i->tot_len = (u16_t)(i->tot_len - r->tot_len);
        LWIP_ASSERT("tot_len/len mismatch in last pbuf",
                    (i->next != NULL) || (i->tot_len == i->len));
      }
	  
      if (p->flags & PBUF_FLAG_TCP_FIN) {
        r->flags |= PBUF_FLAG_TCP_FIN;
      }

      /* tot_len field in rest does not need modifications */
      /* reference counters do not need modifications */
      *rest = r;
    }
  }
}
#endif /* LWIP_TCP && TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */

/* Actual implementation of pbuf_skip() but returning const pointer... */
/*********************************************************************************************************
** 函数名称: pbuf_skip_const
** 功能描述: 从指定的 pbuf/pbuf chain 中的负载空间中，找到包含指定偏移量的 pbuf 以及偏移量的余数部分
**         : 所谓的偏移量余数部分指的是通过我们指定的偏移量找到 pbuf 之后，剩余的在 pbuf 内的偏移量
** 注     释: 这个函数返回的 pbuf 指针“是” const 类型
** 输	 入: in - 要操作的 pbuf/pbuf chain 指针
**		   : in_offset - 从 pbuf/pbuf chain 头部开始计算，需要跳过的负载空间偏移量
** 输	 出: out_offset - 偏移量的余数部分
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static const struct pbuf *
pbuf_skip_const(const struct pbuf *in, u16_t in_offset, u16_t *out_offset)
{
  u16_t offset_left = in_offset;
  const struct pbuf *q = in;

  /* get the correct pbuf */
  /* 从 pbuf/pbuf chain 链表头开始，找到负载空间偏移量为 in_offset 的 pbuf 位置 */
  while ((q != NULL) && (q->len <= offset_left)) {
    offset_left = (u16_t)(offset_left - q->len);
    q = q->next;
  }

  /* 返回在找到的 pbuf 内，负载偏移量字节数 */
  if (out_offset != NULL) {
    *out_offset = offset_left;
  }
  return q;
}

/**
 * @ingroup pbuf
 * Skip a number of bytes at the start of a pbuf
 *
 * @param in input pbuf
 * @param in_offset offset to skip
 * @param out_offset resulting offset in the returned pbuf
 * @return the pbuf in the queue where the offset is
 */
/*********************************************************************************************************
** 函数名称: pbuf_skip
** 功能描述: 从指定的 pbuf/pbuf chain 中的负载空间中，找到包含指定偏移量的 pbuf 以及偏移量的余数部分
**		   : 所谓的偏移量余数部分指的是通过我们指定的偏移量找到 pbuf 之后，剩余的在 pbuf 内的偏移量
** 注     释: 这个函数返回的 pbuf 指针“不是” const 类型
** 输	 入: in - 要操作的 pbuf/pbuf chain 指针
**		   : in_offset - 从 pbuf/pbuf chain 头部开始计算，需要跳过的负载空间偏移量
** 输	 出: out_offset - 偏移量的余数部分
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct pbuf *
pbuf_skip(struct pbuf *in, u16_t in_offset, u16_t *out_offset)
{
  const struct pbuf *out = pbuf_skip_const(in, in_offset, out_offset);
  return LWIP_CONST_CAST(struct pbuf *, out);
}

/**
 * @ingroup pbuf
 * Copy application supplied data into a pbuf.
 * This function can only be used to copy the equivalent of buf->tot_len data.
 *
 * @param buf pbuf to fill with data
 * @param dataptr application supplied data buffer
 * @param len length of the application supplied data buffer
 *
 * @return ERR_OK if successful, ERR_MEM if the pbuf is not big enough
 */
/*********************************************************************************************************
** 函数名称: pbuf_take
** 功能描述: 把用户缓冲区中的数据复制并填充到指定的 pbuf/pbuf chain 负载空间中
** 输	 入: buf - 用来存储用户数据的 pbuf/ pbuf chain 指针
**		   : dataptr - 需要复制到 pbuf/pbuf chain 中的用户数据缓冲区地址
**         : len -  需要复制到 pbuf/pbuf chain 中的用户数据长度
** 输	 出: ERR_OK - 复制成功
**         : ERR_ARG/ERR_MEM - 复制失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/ 
err_t
pbuf_take(struct pbuf *buf, const void *dataptr, u16_t len)
{
  struct pbuf *p;
  size_t buf_copy_len;
  size_t total_copy_len = len;
  size_t copied_total = 0;

  LWIP_ERROR("pbuf_take: invalid buf", (buf != NULL), return ERR_ARG;);
  LWIP_ERROR("pbuf_take: invalid dataptr", (dataptr != NULL), return ERR_ARG;);
  LWIP_ERROR("pbuf_take: buf not large enough", (buf->tot_len >= len), return ERR_MEM;);

  if ((buf == NULL) || (dataptr == NULL) || (buf->tot_len < len)) {
    return ERR_ARG;
  }

  /* Note some systems use byte copy if dataptr or one of the pbuf payload pointers are unaligned. */
  /* 从 pbuf/pbuf chain 链表头开始查找空闲 pbuf 用来存储用户数据 */
  for (p = buf; total_copy_len != 0; p = p->next) {
    LWIP_ASSERT("pbuf_take: invalid pbuf", p != NULL);
    buf_copy_len = total_copy_len;
    if (buf_copy_len > p->len) {
      /* this pbuf cannot hold all remaining data */
      buf_copy_len = p->len;
    }
    /* copy the necessary parts of the buffer */
    MEMCPY(p->payload, &((const char *)dataptr)[copied_total], buf_copy_len);
    total_copy_len -= buf_copy_len;
    copied_total += buf_copy_len;
  }
  LWIP_ASSERT("did not copy all data", total_copy_len == 0 && copied_total == len);
  return ERR_OK;
}

/**
 * @ingroup pbuf
 * Same as pbuf_take() but puts data at an offset
 *
 * @param buf pbuf to fill with data
 * @param dataptr application supplied data buffer
 * @param len length of the application supplied data buffer
 * @param offset offset in pbuf where to copy dataptr to
 *
 * @return ERR_OK if successful, ERR_MEM if the pbuf is not big enough
 */
/*********************************************************************************************************
** 函数名称: pbuf_take_at
** 功能描述: 把用户缓冲区中的数据复制并填充到指定的 pbuf/pbuf chain 负载空间的指定偏移量处的内存空间中
** 输	 入: buf - 用来存储用户数据的 pbuf/ pbuf chain 指针
**		   : dataptr - 需要复制到 pbuf/pbuf chain 中的用户数据缓冲区地址
**		   : len -	需要复制到 pbuf/pbuf chain 中的用户数据长度
**         : offset - 用户数据需要放到 pbuf/pbuf chain 负载空间的偏移量位置
** 输	 出: ERR_OK - 复制成功
**		   : ERR_ARG/ERR_MEM - 复制失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/ 
err_t
pbuf_take_at(struct pbuf *buf, const void *dataptr, u16_t len, u16_t offset)
{
  u16_t target_offset;
  struct pbuf *q = pbuf_skip(buf, offset, &target_offset);

  /* return requested data if pbuf is OK */
  if ((q != NULL) && (q->tot_len >= target_offset + len)) {
    u16_t remaining_len = len;
    const u8_t *src_ptr = (const u8_t *)dataptr;
    /* copy the part that goes into the first pbuf */
    u16_t first_copy_len;
    LWIP_ASSERT("check pbuf_skip result", target_offset < q->len);
    first_copy_len = (u16_t)LWIP_MIN(q->len - target_offset, len);
    MEMCPY(((u8_t *)q->payload) + target_offset, dataptr, first_copy_len);
    remaining_len = (u16_t)(remaining_len - first_copy_len);
    src_ptr += first_copy_len;
    if (remaining_len > 0) {
      return pbuf_take(q->next, src_ptr, remaining_len);
    }
    return ERR_OK;
  }
  return ERR_MEM;
}

/**
 * @ingroup pbuf
 * Creates a single pbuf out of a queue of pbufs.
 *
 * @remark: Either the source pbuf 'p' is freed by this function or the original
 *          pbuf 'p' is returned, therefore the caller has to check the result!
 *
 * @param p the source pbuf
 * @param layer pbuf_layer of the new pbuf
 *
 * @return a new, single pbuf (p->next is NULL)
 *         or the old pbuf if allocation fails
 */
/*********************************************************************************************************
** 函数名称: pbuf_coalesce
** 功能描述: 把一个负载空间不连续的 pbuf chain 中的“所有空间内容”复制到新申请的、地址连续的 pbuf 中
**         : 在复制完成后，把原来的那个负载空间不连续的 pbuf chain 释放掉，这个函数的效果等同于把负载
**         : 空间地址不连续的 pbuf/pbuf chain 转换成一个负载空间地址连续的 pbuf/pbuf chain
** 输	 入: p - 需要被转换的 pbuf/ pbuf chain 指针，负载空间不包含协议头数据
**		   : layer - 转换后的 pbuf/ pbuf chain 需要为协议头预留的内存空间字节数
** 输	 出: q - 转换后的 pbuf/ pbuf chain 指针
**		   : NULL - 转换失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct pbuf *
pbuf_coalesce(struct pbuf *p, pbuf_layer layer)
{
  struct pbuf *q;
  if (p->next == NULL) {
    return p;
  }

  /* 申请一个 PBUF_RAM 类型的 pbuf，然后把 p 指向的 pbuf/pbuf chain 所有负载空间内容
   * 都复制到新申请的这个 pbuf 中 */
  q = pbuf_clone(layer, PBUF_RAM, p);
  if (q == NULL) {
    /* @todo: what do we do now? */
    return p;
  }
  pbuf_free(p);
  return q;
}

/**
 * @ingroup pbuf
 * Allocates a new pbuf of same length (via pbuf_alloc()) and copies the source
 * pbuf into this new pbuf (using pbuf_copy()).
 *
 * @param layer pbuf_layer of the new pbuf
 * @param type this parameter decides how and where the pbuf should be allocated
 *             (@see pbuf_alloc())
 * @param p the source pbuf
 *
 * @return a new pbuf or NULL if allocation fails
 */
/*********************************************************************************************************
** 函数名称: pbuf_clone
** 功能描述: 申请一个和指定的 pbuf/pbuf chain 属性相同的 pbuf/pbuf chain，并把指定的 pbuf/pbuf chain 的
**         : 所有负载空间内容复制到新申请的这个 pbuf/pbuf chain 中，并返回新申请的 pbuf/pbuf chain 指针
** 注     释: 克隆的时候，不会复制被隐藏的协议头数据
** 输	 入: layer - 指定 pbuf/pbuf chain 的协议头空间字节数
**		   : type - 指定 pbuf/pbuf chain 类型
**		   : p - 需要克隆的 pbuf/pbuf chain 指针
** 输	 出: q - 复制成功后新的 pbuf/pbuf chain 指针
**		   : NULL - 复制失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct pbuf *
pbuf_clone(pbuf_layer layer, pbuf_type type, struct pbuf *p)
{
  struct pbuf *q;
  err_t err;
  q = pbuf_alloc(layer, p->tot_len, type);
  if (q == NULL) {
    return NULL;
  }
  err = pbuf_copy(q, p);
  LWIP_UNUSED_ARG(err); /* in case of LWIP_NOASSERT */
  LWIP_ASSERT("pbuf_copy failed", err == ERR_OK);
  return q;
}

#if LWIP_CHECKSUM_ON_COPY
/**
 * Copies data into a single pbuf (*not* into a pbuf queue!) and updates
 * the checksum while copying
 *
 * @param p the pbuf to copy data into
 * @param start_offset offset of p->payload where to copy the data to
 * @param dataptr data to copy into the pbuf
 * @param len length of data to copy into the pbuf
 * @param chksum pointer to the checksum which is updated
 * @return ERR_OK if successful, another error if the data does not fit
 *         within the (first) pbuf (no pbuf queues!)
 */
/*********************************************************************************************************
** 函数名称: pbuf_fill_chksum
** 功能描述: 把指定长度的用户数据复制到指定 pbuf 成员负载地址空间的指定偏移量处，并更新校验和的值
** 输	 入: p - 存储用户数据的 pbuf 指针
**		   : start_offset - 表示存储用户数据的空间在 pbuf 负载空间中的偏移量
**		   : dataptr - 用户数据缓冲区地址
**         : len - 用户数据长度
** 输	 出: chksum  - 上一次的校验和，在本次复制完成后，需要更新这个校验和的值
**		   : ERR_OK  - 复制成功
**		   : ERR_ARG - 复制失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
pbuf_fill_chksum(struct pbuf *p, u16_t start_offset, const void *dataptr,
                 u16_t len, u16_t *chksum)
{
  u32_t acc;
  u16_t copy_chksum;
  char *dst_ptr;
  LWIP_ASSERT("p != NULL", p != NULL);
  LWIP_ASSERT("dataptr != NULL", dataptr != NULL);
  LWIP_ASSERT("chksum != NULL", chksum != NULL);
  LWIP_ASSERT("len != 0", len != 0);

  if ((start_offset >= p->len) || (start_offset + len > p->len)) {
    return ERR_ARG;
  }

  dst_ptr = ((char *)p->payload) + start_offset;
  copy_chksum = LWIP_CHKSUM_COPY(dst_ptr, dataptr, len);
  if ((start_offset & 1) != 0) {
    copy_chksum = SWAP_BYTES_IN_WORD(copy_chksum);
  }

  /* 累加数据校验和值 */
  acc = *chksum;
  acc += copy_chksum;
  *chksum = FOLD_U32T(acc);
  
  return ERR_OK;
}
#endif /* LWIP_CHECKSUM_ON_COPY */

/**
 * @ingroup pbuf
 * Get one byte from the specified position in a pbuf
 * WARNING: returns zero for offset >= p->tot_len
 *
 * @param p pbuf to parse
 * @param offset offset into p of the byte to return
 * @return byte at an offset into p OR ZERO IF 'offset' >= p->tot_len
 */
/*********************************************************************************************************
** 函数名称: pbuf_get_at
** 功能描述: 读取指定的 pbuf/pbuf chain 的负载地址空间的指定偏移量处的字节数据内容
** 注     释: 如果读取失败，则默认表示读回来的数据是 0
** 输	 入: p - 要读取的 pbuf/pbuf chain 指针
**		   : offset - 要读取的字节数据在 pbuf/pbuf chain 负载地址空间中的偏移量
** 输	 出: ret - 读取到的字节数据内容
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
pbuf_get_at(const struct pbuf *p, u16_t offset)
{
  int ret = pbuf_try_get_at(p, offset);
  if (ret >= 0) {
    return (u8_t)ret;
  }
  return 0;
}

/**
 * @ingroup pbuf
 * Get one byte from the specified position in a pbuf
 *
 * @param p pbuf to parse
 * @param offset offset into p of the byte to return
 * @return byte at an offset into p [0..0xFF] OR negative if 'offset' >= p->tot_len
 */
/*********************************************************************************************************
** 函数名称: pbuf_try_get_at
** 功能描述: 尝试读取指定的 pbuf/pbuf chain 的负载地址空间的指定偏移量处的字节数据内容
** 输	 入: p - 要读取的 pbuf/pbuf chain 指针
**		   : offset - 要读取的字节数据在 pbuf/pbuf chain 负载地址空间中的偏移量
** 输	 出: int - 读取到的字节数据内容
**         : -1  - 读取失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int
pbuf_try_get_at(const struct pbuf *p, u16_t offset)
{
  u16_t q_idx;
  const struct pbuf *q = pbuf_skip_const(p, offset, &q_idx);

  /* return requested data if pbuf is OK */
  if ((q != NULL) && (q->len > q_idx)) {
    return ((u8_t *)q->payload)[q_idx];
  }
  return -1;
}

/**
 * @ingroup pbuf
 * Put one byte to the specified position in a pbuf
 * WARNING: silently ignores offset >= p->tot_len
 *
 * @param p pbuf to fill
 * @param offset offset into p of the byte to write
 * @param data byte to write at an offset into p
 */
/*********************************************************************************************************
** 函数名称: pbuf_put_at
** 功能描述: 向指定的 pbuf/pbuf chain 的负载地址空间的指定偏移量处写入指定的字节数据内容
** 输	 入: p - 要写的 pbuf/pbuf chain 指针
**		   : offset - 要写的字节数据在 pbuf/pbuf chain 负载地址空间中的偏移量
**         : data - 要写的字节数据内容
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
pbuf_put_at(struct pbuf *p, u16_t offset, u8_t data)
{
  u16_t q_idx;
  struct pbuf *q = pbuf_skip(p, offset, &q_idx);

  /* write requested data if pbuf is OK */
  if ((q != NULL) && (q->len > q_idx)) {
    ((u8_t *)q->payload)[q_idx] = data;
  }
}

/**
 * @ingroup pbuf
 * Compare pbuf contents at specified offset with memory s2, both of length n
 *
 * @param p pbuf to compare
 * @param offset offset into p at which to start comparing
 * @param s2 buffer to compare
 * @param n length of buffer to compare
 * @return zero if equal, nonzero otherwise
 *         (0xffff if p is too short, diffoffset+1 otherwise)
 */
/*********************************************************************************************************
** 函数名称: pbuf_memcmp
** 功能描述: 把指定长度的用户数据和指定的 pbuf/pbuf chain 中指定偏移量的负载地址空间中的内容作比较
**         : 并返回比较结果
** 输	 入: p - 要比较的 pbuf/pbuf chain 指针
**		   : offset - 要比较的数据在 pbuf/pbuf chain 负载地址空间中的偏移量
**		   : s2 - 要比较的用户数据缓存地址
**         : n - 要比较的用户数据长度
** 输	 出: 0 - 数据内容相同
**         : 0 < x < 0xFFFF - 不同的数据在用户缓冲中的索引值
**         : 0xFFFF - 可能数据不同，也可能 pbuf/pbuf chain 负载空间不足
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u16_t
pbuf_memcmp(const struct pbuf *p, u16_t offset, const void *s2, u16_t n)
{
  u16_t start = offset;
  const struct pbuf *q = p;
  u16_t i;

  /* pbuf long enough to perform check? */
  if (p->tot_len < (offset + n)) {
    return 0xffff;
  }

  /* get the correct pbuf from chain. We know it succeeds because of p->tot_len check above. */
  while ((q != NULL) && (q->len <= start)) {
    start = (u16_t)(start - q->len);
    q = q->next;
  }

  /* return requested data if pbuf is OK */
  for (i = 0; i < n; i++) {
    /* We know pbuf_get_at() succeeds because of p->tot_len check above. */
    u8_t a = pbuf_get_at(q, (u16_t)(start + i));
    u8_t b = ((const u8_t *)s2)[i];
    if (a != b) {
      return (u16_t)LWIP_MIN(i + 1, 0xFFFF);
    }
  }
  return 0;
}

/**
 * @ingroup pbuf
 * Find occurrence of mem (with length mem_len) in pbuf p, starting at offset
 * start_offset.
 *
 * @param p pbuf to search, maximum length is 0xFFFE since 0xFFFF is used as
 *        return value 'not found'
 * @param mem search for the contents of this buffer
 * @param mem_len length of 'mem'
 * @param start_offset offset into p at which to start searching
 * @return 0xFFFF if substr was not found in p or the index where it was found
 */
/*********************************************************************************************************
** 函数名称: pbuf_memfind
** 功能描述: 在指定的 pbuf/pbuf chain 的负载地址空间中查找指定的数据内容的起始地址
** 输	 入: p - 要查找的 pbuf/pbuf chain 指针
**		   : mem - 要查找的数据内容缓冲区地址
**		   : mem_len - 要查找的数据内容长度
**		   : start_offset - 要查找的 pbuf/pbuf chain 负载地址空间起始偏移量
** 输	 出: 0 < x < 0xFFFF - 找到的数据和查找数据起点位置之间的字节数
**		   : 0xFFFF - 没有和指定内容相同的数据
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u16_t
pbuf_memfind(const struct pbuf *p, const void *mem, u16_t mem_len, u16_t start_offset)
{
  u16_t i;
  u16_t max_cmp_start = (u16_t)(p->tot_len - mem_len);
  if (p->tot_len >= mem_len + start_offset) {
    for (i = start_offset; i <= max_cmp_start; i++) {
      u16_t plus = pbuf_memcmp(p, i, mem, mem_len);
      if (plus == 0) {
        return i;
      }
    }
  }
  return 0xFFFF;
}

/**
 * Find occurrence of substr with length substr_len in pbuf p, start at offset
 * start_offset
 * WARNING: in contrast to strstr(), this one does not stop at the first \0 in
 * the pbuf/source string!
 *
 * @param p pbuf to search, maximum length is 0xFFFE since 0xFFFF is used as
 *        return value 'not found'
 * @param substr string to search for in p, maximum length is 0xFFFE
 * @return 0xFFFF if substr was not found in p or the index where it was found
 */
/*********************************************************************************************************
** 函数名称: pbuf_strstr
** 功能描述: 在指定的 pbuf/pbuf chain 的负载地址空间中查找指定的字符串内容，并返回这个字符串在
**         : pbuf/pbuf chain 负载地址空间中的偏移量
** 输	 入: p - 要查找的 pbuf/pbuf chain 指针
**		   : substr - 要查找的字符串地址
** 输	 出: 0 < x < 0xFFFF - 找到的数字符串在 pbuf/pbuf chain 负载地址空间中的偏移量
**		   : 0xFFFF - 没找到指定的字符串
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u16_t
pbuf_strstr(const struct pbuf *p, const char *substr)
{
  size_t substr_len;
  if ((substr == NULL) || (substr[0] == 0) || (p->tot_len == 0xFFFF)) {
    return 0xFFFF;
  }
  substr_len = strlen(substr);
  if (substr_len >= 0xFFFF) {
    return 0xFFFF;
  }
  return pbuf_memfind(p, substr, (u16_t)substr_len, 0);
}
