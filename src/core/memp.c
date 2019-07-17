/**
 * @file
 * Dynamic pool memory manager
 *
 * lwIP has dedicated pools for many structures (netconn, protocol control blocks,
 * packet buffers, ...). All these pools are managed here.
 *
 * @defgroup mempool Memory pools
 * @ingroup infrastructure
 * Custom memory pools
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
/* 在 lwip 内存池分配算法中，一个内存池对象的每个原始内存单元是通过 struct memp 链表
 * 链接起来的，具体结构如下图：
 *
 *    desc->tab ---
 *                |
 *                V
 *    -----------------------------
 *    | struct memp (link list)   |
 *    |              next         | ---  
 *    |---------------------------|   |
 *    |                           |   |
 *    |        other space        |   |
 *    |                           |   |
 *    -----------------------------   |
 *                                    |
 *    ----------------------------- <-|  
 *    | struct memp (link list)   |
 *    |              next         | ---  
 *    |---------------------------|   |
 *    |                           |   |
 *    |        other space        |   |
 *    |                           |   |
 *    -----------------------------   |
 *                                    |
 *    ----------------------------- <-|
 *    | struct memp (link list)   |
 *    |              next         | ---  
 *    |---------------------------|   |
 *    |                           |   |
 *    |        other space        |   |
 *    |                           |   |
 *    -----------------------------   |
 *                                    V
 *
 * 在 lwip 内存池分配算法中，每个原始内存单元的布局结构和是否开启 MEMP_OVERFLOW_CHECK
 * 功能有关，下面分别描述开启和不开启的两种情况时的布局结构
 * 1. 在开启 MEMP_OVERFLOW_CHECK 功能时布局如下：
 *
 *          原始内存单元布局
 *    -----------------------------
 *    |   struct memp (link list) |
 *    |---------------------------|
 *    |   SANITY_REGION_BEFORE    |
 *    |---------------------------|
 *    |                           |
 *    |     用户内存单元空间              |
 *    |                           |
 *    -----------------------------
 *
 * 2. 在不开启 MEMP_OVERFLOW_CHECK 功能时布局如下：
 *
 *          原始内存单元布局
 *    -----------------------------
 *    |   struct memp (link list) |
 *    |---------------------------|
 *    |                           |
 *    |     用户内存单元空间              |
 *    |                           |
 *    -----------------------------
 */ 
#include "lwip/opt.h"

#include "lwip/memp.h"
#include "lwip/sys.h"
#include "lwip/stats.h"

#include <string.h>

/* Make sure we include everything we need for size calculation required by memp_std.h */
#include "lwip/pbuf.h"
#include "lwip/raw.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/altcp.h"
#include "lwip/ip4_frag.h"
#include "lwip/netbuf.h"
#include "lwip/api.h"
#include "lwip/priv/tcpip_priv.h"
#include "lwip/priv/api_msg.h"
#include "lwip/priv/sockets_priv.h"
#include "lwip/etharp.h"
#include "lwip/igmp.h"
#include "lwip/timeouts.h"
/* needed by default MEMP_NUM_SYS_TIMEOUT */
#include "netif/ppp/ppp_opts.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "lwip/priv/nd6_priv.h"
#include "lwip/ip6_frag.h"
#include "lwip/mld6.h"

/* 为当前 lwip 系统中的每一个内存池对象声明一个 struct memp_desc 结构体以及对应的内存池空间 */
#define LWIP_MEMPOOL(name,num,size,desc) LWIP_MEMPOOL_DECLARE(name,num,size,desc)
#include "lwip/priv/memp_std.h"

/* memp 模块中的全局变量，用来保存 lwip 中所有内存池描述符指针，这些内存池指针指向了上面通过
 * LWIP_MEMPOOL_DECLARE 声明创建的内存池对象，包括 MEMPOOL、MALLOC_MEMPOOL 和 PBUF_MEMPOOL */
const struct memp_desc *const memp_pools[MEMP_MAX] = {
#define LWIP_MEMPOOL(name,num,size,desc) &memp_ ## name,
#include "lwip/priv/memp_std.h"
};

#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif

/* 因为在使能 MEMP_MEM_MALLOC 的情况下，MEMP_OVERFLOW_CHECK 合法值都不大于 1
 * 所以如果这个值大于等于 2，则调整为 1 */
#if MEMP_MEM_MALLOC && MEMP_OVERFLOW_CHECK >= 2
#undef MEMP_OVERFLOW_CHECK
/* MEMP_OVERFLOW_CHECK >= 2 does not work with MEMP_MEM_MALLOC, use 1 instead */
#define MEMP_OVERFLOW_CHECK 1
#endif

#if MEMP_SANITY_CHECK && !MEMP_MEM_MALLOC
/**
 * Check that memp-lists don't form a circle, using "Floyd's cycle-finding algorithm".
 */
/*********************************************************************************************************
** 函数名称: memp_sanity
** 功能描述: 校验指定的 memp 链表是否正常，即是否是闭环状态，如果是闭环状态，表示处于异常状态
** 输	 入: desc - 要校验的 memp 描述符
** 输	 出: 0 - memp 链表是闭环
**         : 1 - memp 链表不是闭环
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int
memp_sanity(const struct memp_desc *desc)
{
  struct memp *t, *h;

  t = *desc->tab;
  if (t != NULL) {
    for (h = t->next; (t != NULL) && (h != NULL); t = t->next,
         h = ((h->next != NULL) ? h->next->next : NULL)) {
      if (t == h) {
        return 0;
      }
    }
  }

  return 1;
}
#endif /* MEMP_SANITY_CHECK && !MEMP_MEM_MALLOC */

#if MEMP_OVERFLOW_CHECK
/**
 * Check if a memp element was victim of an overflow or underflow
 * (e.g. the restricted area after/before it has been altered)
 *
 * @param p the memp element to check
 * @param desc the pool p comes from
 */
/*********************************************************************************************************
** 函数名称: memp_overflow_check_element
** 功能描述: 检查指定的 memp 内存单元元素是否发生过越界访问
** 输	 入: p - 要校验的 memp 原始内存单元元素起始地址
**         : desc - 要校验的 memp 内存池对象指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
memp_overflow_check_element(struct memp *p, const struct memp_desc *desc)
{
  mem_overflow_check_raw((u8_t *)p + MEMP_SIZE, desc->size, "pool ", desc->desc);
}

/**
 * Initialize the restricted area of on memp element.
 */
/*********************************************************************************************************
** 函数名称: memp_overflow_init_element
** 功能描述: 初始化指定的 memp 内存单元元素前后的越界访问区内容
** 输	 入: p - 要校验的 memp 原始内存单元元素起始地址
**		   : desc - 要校验的 memp 内存池对象指针
** 输	 出:
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
memp_overflow_init_element(struct memp *p, const struct memp_desc *desc)
{
  mem_overflow_init_raw((u8_t *)p + MEMP_SIZE, desc->size);
}

#if MEMP_OVERFLOW_CHECK >= 2
/**
 * Do an overflow check for all elements in every pool.
 *
 * @see memp_overflow_check_element for a description of the check
 */
/*********************************************************************************************************
** 函数名称: memp_overflow_check_all
** 功能描述: 分别遍历当前 lwip 系统中每个内存池对象中的内存单元元素是否发生过内存访问越界
**         : 如果出现过内存访问越界操作，则直接 assert
** 输	 入: 
** 输	 出:
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
memp_overflow_check_all(void)
{
  u16_t i, j;
  struct memp *p;
  SYS_ARCH_DECL_PROTECT(old_level);
  SYS_ARCH_PROTECT(old_level);

  /* 分别遍历系统中每一个内存池对象 memp_desc */
  for (i = 0; i < MEMP_MAX; ++i) {
    p = (struct memp *)LWIP_MEM_ALIGN(memp_pools[i]->base);

    /* 分别遍历系统中每一个内存池对象 memp_desc 中的每一个内存单元元素 memp */
    for (j = 0; j < memp_pools[i]->num; ++j) {
      memp_overflow_check_element(p, memp_pools[i]);
      p = LWIP_ALIGNMENT_CAST(struct memp *, ((u8_t *)p + MEMP_SIZE + memp_pools[i]->size + MEM_SANITY_REGION_AFTER_ALIGNED));
    }
  }
  SYS_ARCH_UNPROTECT(old_level);
}
#endif /* MEMP_OVERFLOW_CHECK >= 2 */
#endif /* MEMP_OVERFLOW_CHECK */

/**
 * Initialize custom memory pool.
 * Related functions: memp_malloc_pool, memp_free_pool
 *
 * @param desc pool to initialize
 */
/*********************************************************************************************************
** 函数名称: memp_init_pool
** 功能描述: 初始化一个指定的内存池对象，把内存池对象中的每个内存单元元素通过 struct memp 链表连接起来
** 输	 入: desc - 要初始化的内存池对象指针
** 输	 出:
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
memp_init_pool(const struct memp_desc *desc)
{
#if MEMP_MEM_MALLOC
  LWIP_UNUSED_ARG(desc);
#else
  int i;
  struct memp *memp;

  *desc->tab = NULL;

  /* 获取当前内存池对象内存空间中的第一个内存单元元素的 struct memp 地址 */
  memp = (struct memp *)LWIP_MEM_ALIGN(desc->base);

  /* 如果开启 MEMP_MEM_INIT，则把内存池对象的内存空间清空为 0 */
#if MEMP_MEM_INIT
  /* force memset on pool memory */
  memset(memp, 0, (size_t)desc->num * (MEMP_SIZE + desc->size
#if MEMP_OVERFLOW_CHECK
                                       + MEM_SANITY_REGION_AFTER_ALIGNED
#endif
                                      ));
#endif

  /* create a linked list of memp elements */
  /* 把指定的内存池对象中的内存空间通过 struct memp 链表连接起来 */
  for (i = 0; i < desc->num; ++i) {
    memp->next = *desc->tab;
    *desc->tab = memp;
#if MEMP_OVERFLOW_CHECK
    memp_overflow_init_element(memp, desc);
#endif /* MEMP_OVERFLOW_CHECK */
    /* cast through void* to get rid of alignment warnings */
    memp = (struct memp *)(void *)((u8_t *)memp + MEMP_SIZE + desc->size
#if MEMP_OVERFLOW_CHECK
                                   + MEM_SANITY_REGION_AFTER_ALIGNED
#endif
                                  );
  }
#if MEMP_STATS
  desc->stats->avail = desc->num;
#endif /* MEMP_STATS */
#endif /* !MEMP_MEM_MALLOC */

#if MEMP_STATS && (defined(LWIP_DEBUG) || LWIP_STATS_DISPLAY)
  desc->stats->name  = desc->desc;
#endif /* MEMP_STATS && (defined(LWIP_DEBUG) || LWIP_STATS_DISPLAY) */
}

/**
 * Initializes lwIP built-in pools.
 * Related functions: memp_malloc, memp_free
 *
 * Carves out memp_memory into linked lists for each pool-type.
 */
/*********************************************************************************************************
** 函数名称: memp_init
** 功能描述: 初始化当前 lwip 系统中的每一个内存池对象，把内存池对象中的每个内存单元元素通过 struct memp 
**         : 链表连接起来，并在初始化之后校验每个内存池是否出现过内存访问越界操作
** 输	 入:
** 输	 出:
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
memp_init(void)
{
  u16_t i;

  /* for every pool: */
  for (i = 0; i < LWIP_ARRAYSIZE(memp_pools); i++) {
    memp_init_pool(memp_pools[i]);

#if LWIP_STATS && MEMP_STATS
    lwip_stats.memp[i] = memp_pools[i]->stats;
#endif
  }

#if MEMP_OVERFLOW_CHECK >= 2
  /* check everything a first time to see if it worked */
  memp_overflow_check_all();
#endif /* MEMP_OVERFLOW_CHECK >= 2 */
}
/*********************************************************************************************************
** 函数名称: do_memp_malloc_pool or do_memp_malloc_pool_fn
** 功能描述: 从指定的内存池对象中拿出一个空闲的内存单元元素
** 输	 入: desc - 提供内存单元元素的内存池对象
** 输	 出: u8_t * - 用户内存单元元素起始地址
**         : NULL - 申请失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void *
#if !MEMP_OVERFLOW_CHECK
/* 不执行内存池内存访问越界检查的内存单元元素申请函数 */
do_memp_malloc_pool(const struct memp_desc *desc)
#else
/* 需要执行内存池内存访问越界检查的内存单元元素申请函数 */
do_memp_malloc_pool_fn(const struct memp_desc *desc, const char *file, const int line)
#endif
{
  struct memp *memp;
  SYS_ARCH_DECL_PROTECT(old_level);

/* 如果 MEMP_MEM_MALLOC 设置为 1，表示 lwip 内存池申请的内存是通过内存堆算法实现的 
 * 所以我们直接通过内存堆分配内存接口获取我们需要的内存，如果 MEMP_MEM_MALLOC 设置
 * 为 0，表示内存池使用自己的分配算法，所以我们从内存池中获取需要的内存单元 */
#if MEMP_MEM_MALLOC
  memp = (struct memp *)mem_malloc(MEMP_SIZE + MEMP_ALIGN_SIZE(desc->size));
  SYS_ARCH_PROTECT(old_level);
#else /* MEMP_MEM_MALLOC */
  SYS_ARCH_PROTECT(old_level);

  memp = *desc->tab;
#endif /* MEMP_MEM_MALLOC */

  if (memp != NULL) {
#if !MEMP_MEM_MALLOC
#if MEMP_OVERFLOW_CHECK == 1
    memp_overflow_check_element(memp, desc);
#endif /* MEMP_OVERFLOW_CHECK */
	/* 更新当前内存池对象的 tab 地址，使其指向下一个空闲内存单元元素地址 */
    *desc->tab = memp->next;
#if MEMP_OVERFLOW_CHECK
    memp->next = NULL;
#endif /* MEMP_OVERFLOW_CHECK */
#endif /* !MEMP_MEM_MALLOC */

/* 如果开启了内存访问越界检查，则记录申请当前内存单元元素的调用者所在文件以及行数 */
#if MEMP_OVERFLOW_CHECK
    memp->file = file;
    memp->line = line;
#if MEMP_MEM_MALLOC
    memp_overflow_init_element(memp, desc);
#endif /* MEMP_MEM_MALLOC */
#endif /* MEMP_OVERFLOW_CHECK */
    LWIP_ASSERT("memp_malloc: memp properly aligned",
                ((mem_ptr_t)memp % MEM_ALIGNMENT) == 0);
#if MEMP_STATS
    desc->stats->used++;
    if (desc->stats->used > desc->stats->max) {
      desc->stats->max = desc->stats->used;
    }
#endif
    SYS_ARCH_UNPROTECT(old_level);
    /* cast through u8_t* to get rid of alignment warnings */
    return ((u8_t *)memp + MEMP_SIZE);
  } else {
#if MEMP_STATS
    desc->stats->err++;
#endif
    SYS_ARCH_UNPROTECT(old_level);
    LWIP_DEBUGF(MEMP_DEBUG | LWIP_DBG_LEVEL_SERIOUS, ("memp_malloc: out of memory in pool %s\n", desc->desc));
  }

  return NULL;
}

/**
 * Get an element from a custom pool.
 *
 * @param desc the pool to get an element from
 *
 * @return a pointer to the allocated memory or a NULL pointer on error
 */
/*********************************************************************************************************
** 函数名称: memp_malloc_pool or memp_malloc_pool_fn
** 功能描述: 从指定的内存池对象中拿出一个空闲的内存单元元素
** 输	 入: desc - 提供内存单元元素的内存池对象
** 输	 出: void * - 用户内存单元元素起始地址
**		   : NULL - 申请失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void *
#if !MEMP_OVERFLOW_CHECK
memp_malloc_pool(const struct memp_desc *desc)
#else
memp_malloc_pool_fn(const struct memp_desc *desc, const char *file, const int line)
#endif
{
  LWIP_ASSERT("invalid pool desc", desc != NULL);
  if (desc == NULL) {
    return NULL;
  }

#if !MEMP_OVERFLOW_CHECK
  return do_memp_malloc_pool(desc);
#else
  return do_memp_malloc_pool_fn(desc, file, line);
#endif
}

/**
 * Get an element from a specific pool.
 *
 * @param type the pool to get an element from
 *
 * @return a pointer to the allocated memory or a NULL pointer on error
 */
/*********************************************************************************************************
** 函数名称: memp_malloc or memp_malloc_fn
** 功能描述: 从指定索引的内存池中拿出一个空闲的内存单元元素
** 输	 入: type - 提供内存单元元素的内存池索引
** 输	 出: void * - 用户内存单元元素起始地址
**		   : NULL - 申请失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void *
#if !MEMP_OVERFLOW_CHECK
memp_malloc(memp_t type)
#else
memp_malloc_fn(memp_t type, const char *file, const int line)
#endif
{
  void *memp;
  LWIP_ERROR("memp_malloc: type < MEMP_MAX", (type < MEMP_MAX), return NULL;);

#if MEMP_OVERFLOW_CHECK >= 2
  memp_overflow_check_all();
#endif /* MEMP_OVERFLOW_CHECK >= 2 */

#if !MEMP_OVERFLOW_CHECK
  memp = do_memp_malloc_pool(memp_pools[type]);
#else
  memp = do_memp_malloc_pool_fn(memp_pools[type], file, line);
#endif

  return memp;
}
/*********************************************************************************************************
** 函数名称: do_memp_free_pool
** 功能描述: 向指定的内存池对象中释放一个内存单元元素
** 输	 入: desc - 存储释放内存单元元素的内存池对象
**         : mem - 需要释放的用户内存单元元素起始地址
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
do_memp_free_pool(const struct memp_desc *desc, void *mem)
{
  struct memp *memp;
  SYS_ARCH_DECL_PROTECT(old_level);

  LWIP_ASSERT("memp_free: mem properly aligned",
              ((mem_ptr_t)mem % MEM_ALIGNMENT) == 0);

  /* cast through void* to get rid of alignment warnings */
  memp = (struct memp *)(void *)((u8_t *)mem - MEMP_SIZE);

  SYS_ARCH_PROTECT(old_level);

#if MEMP_OVERFLOW_CHECK == 1
  memp_overflow_check_element(memp, desc);
#endif /* MEMP_OVERFLOW_CHECK */

#if MEMP_STATS
  desc->stats->used--;
#endif

#if MEMP_MEM_MALLOC
  LWIP_UNUSED_ARG(desc);
  SYS_ARCH_UNPROTECT(old_level);
  mem_free(memp);
#else /* MEMP_MEM_MALLOC */
  /* 把需要释放的内存单元元素插入到指定的内存对象空闲链表中 */
  memp->next = *desc->tab;
  *desc->tab = memp;

#if MEMP_SANITY_CHECK
  LWIP_ASSERT("memp sanity", memp_sanity(desc));
#endif /* MEMP_SANITY_CHECK */

  SYS_ARCH_UNPROTECT(old_level);
#endif /* !MEMP_MEM_MALLOC */
}

/**
 * Put a custom pool element back into its pool.
 *
 * @param desc the pool where to put mem
 * @param mem the memp element to free
 */
/*********************************************************************************************************
** 函数名称: memp_free_pool
** 功能描述: 向指定的内存池对象中释放一个内存单元元素
** 输	 入: desc - 存储释放内存单元元素的内存池对象
**		   : mem - 需要释放的用户内存单元元素起始地址
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
memp_free_pool(const struct memp_desc *desc, void *mem)
{
  LWIP_ASSERT("invalid pool desc", desc != NULL);
  if ((desc == NULL) || (mem == NULL)) {
    return;
  }

  do_memp_free_pool(desc, mem);
}

/**
 * Put an element back into its pool.
 *
 * @param type the pool where to put mem
 * @param mem the memp element to free
 */
/*********************************************************************************************************
** 函数名称: memp_free_pool
** 功能描述: 向指定索引的内存池对象中释放一个内存单元元素
** 输	 入: type - 存储释放内存单元元素的内存池索引值
**		   : mem - 需要释放的用户内存单元元素起始地址
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
memp_free(memp_t type, void *mem)
{
#ifdef LWIP_HOOK_MEMP_AVAILABLE
  struct memp *old_first;
#endif

  LWIP_ERROR("memp_free: type < MEMP_MAX", (type < MEMP_MAX), return;);

  if (mem == NULL) {
    return;
  }

#if MEMP_OVERFLOW_CHECK >= 2
  memp_overflow_check_all();
#endif /* MEMP_OVERFLOW_CHECK >= 2 */

#ifdef LWIP_HOOK_MEMP_AVAILABLE
  old_first = *memp_pools[type]->tab;
#endif

  do_memp_free_pool(memp_pools[type], mem);

#ifdef LWIP_HOOK_MEMP_AVAILABLE
  if (old_first == NULL) {
    LWIP_HOOK_MEMP_AVAILABLE(type);
  }
#endif
}
