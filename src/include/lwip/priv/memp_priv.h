/**
 * @file
 * memory pools lwIP internal implementations (do not use in application code)
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

#ifndef LWIP_HDR_MEMP_PRIV_H
#define LWIP_HDR_MEMP_PRIV_H

#include "lwip/opt.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "lwip/mem.h"
#include "lwip/priv/mem_priv.h"

#if MEMP_OVERFLOW_CHECK


/* MEMP_SIZE: save space for struct memp and for sanity check */
/* 如果在 memp 模块中开启了内存访问越界检查，那么在每个用户内存单元前会预留出部分空间
 * 用来存储 struct memp 结构体以及越界访问检查的安全区数据 */
#define MEMP_SIZE          (LWIP_MEM_ALIGN_SIZE(sizeof(struct memp)) + MEM_SANITY_REGION_BEFORE_ALIGNED)

#define MEMP_ALIGN_SIZE(x) (LWIP_MEM_ALIGN_SIZE(x) + MEM_SANITY_REGION_AFTER_ALIGNED)

#else /* MEMP_OVERFLOW_CHECK */

/* No sanity checks
 * We don't need to preserve the struct memp while not allocated, so we
 * can save a little space and set MEMP_SIZE to 0.
 */
#define MEMP_SIZE           0
#define MEMP_ALIGN_SIZE(x) (LWIP_MEM_ALIGN_SIZE(x))

#endif /* MEMP_OVERFLOW_CHECK */

#if !MEMP_MEM_MALLOC || MEMP_OVERFLOW_CHECK
/* 这个结构体描述了内存池对象中的一个原始内存元素 */
struct memp {
  struct memp *next;
#if MEMP_OVERFLOW_CHECK
  /* 记录申请当前内存单元元素调用者所在的文件名 */
  const char *file;

  /* 记录申请当前内存单元元素调用者所在文件的行数 */
  int line;
#endif /* MEMP_OVERFLOW_CHECK */
};
#endif /* !MEMP_MEM_MALLOC || MEMP_OVERFLOW_CHECK */

/* 如果使用自定义的内存池来为 mem_malloc 动态内存管理算法提供堆空间，那么我们需要创建 lwippools.h 
 * 文件并在这个文件中添加自定义的内存池，通过下面的枚举变量来表示自定义内存池下标索引值范围，定义
 * 自定义内存池格式如下（因为内存堆分配算法是从 MALLOC_MEMPOOL_START 依次向后查找满足分配需求的内
 * 存单元，如果找到满足分配需求的内存单元就会立即返回，所以我们在为内存堆创建内存池的时候，需要按
 * 照内存池元素字节空间大小、按照从小到大的顺序依次创建）：
 * LWIP_MALLOC_MEMPOOL_START
 * LWIP_MALLOC_MEMPOOL(20, 256)
 * LWIP_MALLOC_MEMPOOL(10, 512)
 * LWIP_MALLOC_MEMPOOL(5, 1512)
 * LWIP_MALLOC_MEMPOOL_END */
#if MEM_USE_POOLS && MEMP_USE_CUSTOM_POOLS
/* Use a helper type to get the start and end of the user "memory pools" for mem_malloc */
typedef enum {
    /* Get the first (via:
       MEMP_POOL_HELPER_START = ((u8_t) 1*MEMP_POOL_A + 0*MEMP_POOL_B + 0*MEMP_POOL_C + 0)
       其中 MEMP_POOL_A 代表的是用户自定义内存池起始索引值，在 memp.h 文件的 memp_t 变量中
       定义的，对应的内存池创建宏是 memp_std.h 文件中的 LWIP_MALLOC_MEMPOOL */
    MEMP_POOL_HELPER_FIRST = ((u8_t)
#define LWIP_MEMPOOL(name,num,size,desc)
#define LWIP_MALLOC_MEMPOOL_START 1
#define LWIP_MALLOC_MEMPOOL(num, size) * MEMP_POOL_##size + 0
#define LWIP_MALLOC_MEMPOOL_END
#include "lwip/priv/memp_std.h"
    ) ,
    /* Get the last (via:
       MEMP_POOL_HELPER_END = ((u8_t) 0 + MEMP_POOL_A*0 + MEMP_POOL_B*0 + MEMP_POOL_C*1) 
       其中 MEMP_POOL_C 代表的是用户自定义内存池结束索引值，在 memp.h 文件的 memp_t 变量中
       定义的，对应的内存池创建宏是 memp_std.h 文件中的 LWIP_MALLOC_MEMPOOL */
    MEMP_POOL_HELPER_LAST = ((u8_t)
#define LWIP_MEMPOOL(name,num,size,desc)
#define LWIP_MALLOC_MEMPOOL_START
#define LWIP_MALLOC_MEMPOOL(num, size) 0 + MEMP_POOL_##size *
#define LWIP_MALLOC_MEMPOOL_END 1
#include "lwip/priv/memp_std.h"
    )
} memp_pool_helper_t;

/* The actual start and stop values are here (cast them over)
   We use this helper type and these defines so we can avoid using const memp_t values */
#define MEMP_POOL_FIRST ((memp_t) MEMP_POOL_HELPER_FIRST)
#define MEMP_POOL_LAST   ((memp_t) MEMP_POOL_HELPER_LAST)
#endif /* MEM_USE_POOLS && MEMP_USE_CUSTOM_POOLS */

/** Memory pool descriptor */
/* 这个结构体描述了内存池中的一个内存池对象 */
struct memp_desc {
#if defined(LWIP_DEBUG) || MEMP_OVERFLOW_CHECK || LWIP_STATS_DISPLAY
  /** Textual description */
  const char *desc;
#endif /* LWIP_DEBUG || MEMP_OVERFLOW_CHECK || LWIP_STATS_DISPLAY */
#if MEMP_STATS
  /** Statistics */
  struct stats_mem *stats;
#endif

  /** Element size */
  /* 当前内存池对象中每个原始内存单元元素字节空间大小 */
  u16_t size;

#if !MEMP_MEM_MALLOC
  /** Number of elements */
  /* 当前内存池对象中一共包含的原始内存单元元素个数 */
  u16_t num;

  /** Base address */
  /* 当前内存池对象总体内存空间的起始地址 */
  u8_t *base;

  /** First free element of each pool. Elements form a linked list. */
  /* 当前内存池对象中第一个空闲的原始内存单元元素地址 */
  struct memp **tab;
#endif /* MEMP_MEM_MALLOC */
};

#if defined(LWIP_DEBUG) || MEMP_OVERFLOW_CHECK || LWIP_STATS_DISPLAY
#define DECLARE_LWIP_MEMPOOL_DESC(desc) (desc),
#else
#define DECLARE_LWIP_MEMPOOL_DESC(desc)
#endif

#if MEMP_STATS
#define LWIP_MEMPOOL_DECLARE_STATS_INSTANCE(name) static struct stats_mem name;
#define LWIP_MEMPOOL_DECLARE_STATS_REFERENCE(name) &name,
#else
#define LWIP_MEMPOOL_DECLARE_STATS_INSTANCE(name)
#define LWIP_MEMPOOL_DECLARE_STATS_REFERENCE(name)
#endif

void memp_init_pool(const struct memp_desc *desc);

#if MEMP_OVERFLOW_CHECK
void *memp_malloc_pool_fn(const struct memp_desc* desc, const char* file, const int line);
#define memp_malloc_pool(d) memp_malloc_pool_fn((d), __FILE__, __LINE__)
#else
void *memp_malloc_pool(const struct memp_desc *desc);
#endif
void  memp_free_pool(const struct memp_desc* desc, void *mem);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_MEMP_PRIV_H */
