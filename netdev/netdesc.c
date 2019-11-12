/**
 * @file
 * Lwip platform independent driver interface.
 * This set of driver Tx/Rx descriptor helper,
 * as much as possible compatible with different versions of LwIP
 * Verification using sylixos(tm) real-time operating system
 */

/*
 * Copyright (c) 2006-2019 SylixOS Group.
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
 * 4. This code has been or is applying for intellectual property protection
 *    and can only be used with acoinfo software products.
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
 * Author: Han.hui <hanhui@acoinfo.com>
 *
 */

#define  __SYLIXOS_KERNEL
#include "lwip/mem.h"
#include "lwip/sys.h"
#include "lwip/pbuf.h"

#if LW_CFG_NET_DEV_DESC_HELPER_EN > 0

#include "unistd.h"
#include "string.h"
#include "netdev.h"

#ifndef NETDEV_DESC_EACH_BUF_MIN_SIZE
#define NETDEV_DESC_EACH_BUF_MIN_SIZE   1280
#endif /* !NETDEV_DESC_EACH_BUF_MIN_SIZE */

/* delete descriptor Tx buffer array */
/*********************************************************************************************************
** 函数名称: netdev_desc_tx_buf_delete
** 功能描述: 释放指定 netdev_desc_helper 的发送缓冲区所占用的内存空间
** 输	 入: helper - 需要删除发送缓冲区的 netdev_desc_helper 指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void netdev_desc_tx_buf_delete (struct netdev_desc_helper *helper)
{
  void *fbuf;
  size_t page_size;
  struct netdev_desc_buf *tx_buf;
  int i, nbufs_per_page;

#if LW_CFG_VMM_EN > 0
  page_size = getpagesize();
#else /* LW_CFG_VMM_EN */
  page_size = 4 * LW_CFG_KB_SIZE;
#endif /* !LW_CFG_VMM_EN */

  tx_buf = helper->tx_buf;
  helper->tx_buf = NULL;

  if (page_size >= helper->each_buf_size) {
    nbufs_per_page = page_size / helper->each_buf_size;
    for (i = 0; i < helper->tx_buf_cnt; i++) {
      if (!(i % nbufs_per_page) && tx_buf[i].buffer) {
        fbuf = (void *)((addr_t)tx_buf[i].buffer - helper->pad_size);
#if LW_CFG_VMM_EN > 0
        vmmDmaFree(fbuf);
#else /* LW_CFG_VMM_EN */
        sys_free(fbuf);
#endif /* !LW_CFG_VMM_EN */
      }
    }

  } else {
    for (i = 0; i < helper->tx_buf_cnt; i++) {
      if (tx_buf[i].buffer) {
        fbuf = (void *)((addr_t)tx_buf[i].buffer - helper->pad_size);
#if LW_CFG_VMM_EN > 0
        vmmDmaFree(fbuf);
#else /* LW_CFG_VMM_EN */
        sys_free(fbuf);
#endif /* !LW_CFG_VMM_EN */
      }
    }
  }

  sys_free(tx_buf);
}

/* create descriptor Tx buffer array */
/*********************************************************************************************************
** 函数名称: netdev_desc_tx_buf_create
** 功能描述: 为指定的 netdev_desc_helper 创建发送缓冲区
** 输	 入: helper - 需要创建发送缓冲区的 netdev_desc_helper 指针
** 输	 出: 0 - 创建成功
**         : -1 - 创建失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int netdev_desc_tx_buf_create (struct netdev_desc_helper *helper)
{
  void *stbuf = NULL; /* avoid warning */
  size_t page_size;
  struct netdev_desc_buf *tx_buf;
  int i, nbufs_per_page, npages_per_buf;

  /* 为指定个数的发送缓冲区描述符申请内存（描述符内存）*/
  tx_buf = (struct netdev_desc_buf *)sys_zalloc(sizeof(struct netdev_desc_buf) * helper->tx_buf_cnt);
  if (!tx_buf) {
    return (-1);
  }

#if LW_CFG_VMM_EN > 0
  page_size = getpagesize();
#else /* LW_CFG_VMM_EN */
  page_size = 4 * LW_CFG_KB_SIZE;
#endif /* !LW_CFG_VMM_EN */

  /* 为指定的 netdev_desc_helper 创建“静态”发送缓冲区 */
  if (page_size >= helper->each_buf_size) {
    nbufs_per_page = page_size / helper->each_buf_size;
    for (i = 0; i < helper->tx_buf_cnt; i++) {
      if (i % nbufs_per_page) {

	  	  /* 把指定内存页中的“静态”发送缓冲区串联起来 */
          stbuf = (void *)((addr_t)stbuf + helper->each_buf_size);
          tx_buf[i].buffer = (void *)((addr_t)stbuf + helper->pad_size);

      } else {

	    /* 为指定个数的“静态”发送缓冲区申请内存（用来存储数据的缓冲区内存）*/
#if LW_CFG_VMM_EN > 0
        stbuf = vmmDmaAllocAlignWithFlags(page_size, page_size, helper->cache_ts_flags);
#else /* LW_CFG_VMM_EN */
        stbuf = sys_malloc(page_size);
#endif /* !LW_CFG_VMM_EN */
        if (!stbuf) {
          goto error;
        }
        tx_buf[i].buffer = (void *)((addr_t)stbuf + helper->pad_size);
      }
    }

  } else {
    npages_per_buf = ROUND_UP(helper->each_buf_size, page_size) / page_size;
    for (i = 0; i < helper->tx_buf_cnt; i++) {
#if LW_CFG_VMM_EN > 0
      stbuf = vmmDmaAllocAlignWithFlags(npages_per_buf * page_size, page_size, helper->cache_ts_flags);
#else /* LW_CFG_VMM_EN */
      stbuf = sys_malloc(npages_per_buf * page_size);
#endif /* !LW_CFG_VMM_EN */
      if (!stbuf) {
        goto error;
      }
      tx_buf[i].buffer = (void *)((addr_t)stbuf + helper->pad_size);
    }
  }

  helper->tx_buf = tx_buf;
  return (0);

error:
  helper->tx_buf = tx_buf;

  /* 释放指定 netdev_desc_helper 的发送缓冲区所占用的内存空间 */
  netdev_desc_tx_buf_delete(helper);
  return (-1);
}

/* delete descriptor Tx buffer array */
/*********************************************************************************************************
** 函数名称: netdev_desc_rx_buf_delete
** 功能描述: 释放指定 netdev_desc_helper 的接收缓冲区所占用的内存空间
** 输	 入: helper - 需要删除接收缓冲区的 netdev_desc_helper 指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void netdev_desc_rx_buf_delete (struct netdev_desc_helper *helper)
{
  void *fbuf;
  size_t page_size;
  struct netdev_desc_buf *rx_buf;
  int i, nbufs_per_page;

#if LW_CFG_VMM_EN > 0
  page_size = getpagesize();
#else /* LW_CFG_VMM_EN */
  page_size = 4 * LW_CFG_KB_SIZE;
#endif /* !LW_CFG_VMM_EN */

  rx_buf = helper->rx_buf;
  helper->rx_buf = NULL;

  if (page_size >= helper->each_buf_size) {
    nbufs_per_page = page_size / helper->each_buf_size;
    for (i = 0; i < helper->rx_buf_cnt; i++) {
#if LW_CFG_NET_DEV_ZCBUF_EN > 0
      if (rx_buf[i].p) {
        netdev_zc_pbuf_free(rx_buf[i].p);
      }
#endif /* LW_CFG_NET_DEV_ZCBUF_EN */
      if (!(i % nbufs_per_page) && rx_buf[i].buffer) {
        fbuf = (void *)((addr_t)rx_buf[i].buffer - helper->pad_size);
#if LW_CFG_VMM_EN > 0
        vmmDmaFree(fbuf);
#else /* LW_CFG_VMM_EN */
        sys_free(fbuf);
#endif /* !LW_CFG_VMM_EN */
      }
    }

  } else {
    for (i = 0; i < helper->rx_buf_cnt; i++) {
#if LW_CFG_NET_DEV_ZCBUF_EN > 0
      if (rx_buf[i].p) {
        netdev_zc_pbuf_free(rx_buf[i].p);
      }
#endif /* LW_CFG_NET_DEV_ZCBUF_EN */
      if (rx_buf[i].buffer) {
        fbuf = (void *)((addr_t)rx_buf[i].buffer - helper->pad_size);
#if LW_CFG_VMM_EN > 0
        vmmDmaFree(fbuf);
#else /* LW_CFG_VMM_EN */
        sys_free(fbuf);
#endif /* !LW_CFG_VMM_EN */
      }
    }
  }

  sys_free(rx_buf);
}

/* create descriptor Rx buffer array */
/*********************************************************************************************************
** 函数名称: netdev_desc_rx_buf_create
** 功能描述: 为指定的 netdev_desc_helper 创建接收缓冲区
** 输	 入: helper - 需要创建发送缓冲区的 netdev_desc_helper 指针
** 输	 出: 0 - 创建成功
**         : -1 - 创建失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int netdev_desc_rx_buf_create (struct netdev_desc_helper *helper)
{
  void *stbuf = NULL; /* avoid warning */
  size_t page_size;
  struct netdev_desc_buf *rx_buf;
  int i, nbufs_per_page, npages_per_buf;

  /* 为指定个数的接收缓冲区描述符申请内存（描述符内存）*/
  rx_buf = (struct netdev_desc_buf *)sys_zalloc(sizeof(struct netdev_desc_buf) * helper->rx_buf_cnt);
  if (!rx_buf) {
    return (-1);
  }

#if LW_CFG_VMM_EN > 0
  page_size = getpagesize();
#else /* LW_CFG_VMM_EN */
  page_size = 4 * LW_CFG_KB_SIZE;
#endif /* !LW_CFG_VMM_EN */

  /* 为指定的 netdev_desc_helper 创建“静态”接收缓冲区 */
  if (page_size >= helper->each_buf_size) {
    nbufs_per_page = page_size / helper->each_buf_size;
    for (i = 0; i < helper->rx_buf_cnt; i++) {
      if (i % nbufs_per_page) {

	  
	    /* 把指定内存页中的“静态”接收缓冲区串联起来 */
        stbuf = (void *)((addr_t)stbuf + helper->each_buf_size);
        rx_buf[i].buffer = (void *)((addr_t)stbuf + helper->pad_size);
      } else {
	    
	    /* 为指定个数的“静态”接收缓冲区申请内存（用来存储数据的缓冲区内存）*/
#if LW_CFG_VMM_EN > 0
        stbuf = vmmDmaAllocAlignWithFlags(page_size, page_size, helper->cache_rs_flags);
#else /* LW_CFG_VMM_EN */
        stbuf = sys_malloc(page_size);
#endif /* !LW_CFG_VMM_EN */
        if (!stbuf) {
          goto error;
        }
        rx_buf[i].buffer = (void *)((addr_t)stbuf + helper->pad_size);
      }
    }

  } else {
    npages_per_buf = ROUND_UP(helper->each_buf_size, page_size) / page_size;
    for (i = 0; i < helper->rx_buf_cnt; i++) {
#if LW_CFG_VMM_EN > 0
      stbuf = vmmDmaAllocAlignWithFlags(npages_per_buf * page_size, page_size, helper->cache_rs_flags);
#else /* LW_CFG_VMM_EN */
      stbuf = sys_malloc(npages_per_buf * page_size);
#endif /* !LW_CFG_VMM_EN */
      if (!stbuf) {
        goto error;
      }
      rx_buf[i].buffer = (void *)((addr_t)stbuf + helper->pad_size);
    }
  }

  helper->rx_buf = rx_buf;
  return (0);

error:
  helper->rx_buf = rx_buf;
  
  /* 释放指定 netdev_desc_helper 的发送缓冲区所占用的内存空间 */
  netdev_desc_rx_buf_delete(helper);
  return (-1);
}

/* create descriptor helper */
/*********************************************************************************************************
** 函数名称: netdev_desc_helper_create
** 功能描述: 根据指定的参数创建一个 netdev_desc_helper 结构
** 输	 入: each_buf_size - 创建的 netdev_desc_helper 中每个缓冲区空间字节数
**         : pad_size - 创建的 netdev_desc_helper 中每个缓冲区需要添加的 pad 字节数
**         : cache_ts_en - 表示是否使能发送静态缓冲区的 cache 功能
**         : cache_rs_en - 表示是否使能接收静态缓冲区的 cache 功能
**         : cache_zc_en - 表示是否使能接收零拷贝缓冲区的 cache 功能
**         : tx_buf_cnt - 表示需要创建的发送缓冲区个数
**         : rx_buf_cnt - 表示需要创建的接收缓冲区个数
**         : tx_zc_en - 表示是否使能发送零拷贝功能
**         : rx_zc_cnt - 表示需要申请的接收零拷贝缓冲区个数
** 输	 出: helper - 成功创建的 netdev_desc_helper 结构指针
**         : NULL - 创建失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct netdev_desc_helper *
netdev_desc_helper_create (size_t each_buf_size, size_t pad_size,
                           int cache_ts_en, int cache_rs_en, int cache_zc_en,
                           int tx_buf_cnt, int rx_buf_cnt, int tx_zc_en, int rx_zc_cnt)
{
  struct netdev_desc_helper *helper;
  size_t cache_line;

  if ((tx_buf_cnt < 0) || (rx_buf_cnt < 0)) {
    return (NULL);
  }

  each_buf_size += pad_size;
  if (each_buf_size < NETDEV_DESC_EACH_BUF_MIN_SIZE) {
    return (NULL);
  }

#if LW_CFG_CACHE_EN > 0
  cache_line = cacheLine(DATA_CACHE);
#else /* LW_CFG_CACHE_EN */
#ifdef LW_CFG_CPU_ARCH_CACHE_LINE
  cache_line = LW_CFG_CPU_ARCH_CACHE_LINE;
#else
  cache_line = 32;
#endif /* LW_CFG_CPU_ARCH_CACHE_LINE */
#endif /* !LW_CFG_CACHE_EN */

  each_buf_size = ROUND_UP(each_buf_size, cache_line);

  /* 申请   netdev_desc_helper 结构需要的内存空间 */
  helper = (struct netdev_desc_helper *)sys_zalloc(sizeof(struct netdev_desc_helper));
  if (!helper) {
    return (NULL);
  }

  helper->tx_buf_cnt = tx_buf_cnt;
  helper->rx_buf_cnt = rx_buf_cnt;

  helper->each_buf_size = each_buf_size;
  helper->pad_size = pad_size;
  helper->tx_zc_en = tx_zc_en;
  helper->rx_zc_cnt = rx_zc_cnt;

  /* 根据当前系统 cache 属性已经函数参数初始化 cache 相关变量 */
#if LW_CFG_CACHE_EN > 0
  if (cacheGetMode(DATA_CACHE) & CACHE_SNOOP_ENABLE) {  /* cache has snoop unit */
    helper->cache_zc_flags   = LW_VMM_FLAG_RDWR;
    helper->cache_ts_flags   = LW_VMM_FLAG_RDWR;
    helper->cache_rs_flags   = LW_VMM_FLAG_RDWR;
    helper->cache_pb_flush   = 0;
    helper->cache_ts_flush   = 0;
    helper->cache_zc_invalid = 0;
    helper->cache_rs_invalid = 0;

  } else {
    if (cacheGetMode(DATA_CACHE) & CACHE_WRITETHROUGH) { /* cache is writethrough */
      helper->cache_ts_flags = LW_VMM_FLAG_RDWR;
      helper->cache_pb_flush = 0;
      helper->cache_ts_flush = 0;

    } else {
      helper->cache_pb_flush = 1; /* must flush send pbuf */
      if (cache_ts_en) {
        helper->cache_ts_flags = LW_VMM_FLAG_RDWR; /* send static buffer has cache */
        helper->cache_ts_flush = 1;

      } else {
        helper->cache_ts_flags = LW_VMM_FLAG_DMA; /* send static buffer no cache */
        helper->cache_ts_flush = 0;
      }
    }

    if (cache_rs_en) { /* recv static buffer has cache */
      helper->cache_rs_flags   = LW_VMM_FLAG_RDWR;
      helper->cache_rs_invalid = 1;

    } else {
      helper->cache_rs_flags   = LW_VMM_FLAG_DMA;
      helper->cache_rs_invalid = 0;
    }

    if (cache_zc_en) { /* recv zc buffer has cache */
      helper->cache_zc_flags   = LW_VMM_FLAG_RDWR;
      helper->cache_zc_invalid = 1;

    } else {
      helper->cache_zc_flags   = LW_VMM_FLAG_DMA;
      helper->cache_zc_invalid = 0;
    }
  }
#endif /* !LW_CFG_CACHE_EN */

  /* 为当前的 netdev_desc_helper 创建接收零拷贝需要使用的缓冲区空间 */
#if LW_CFG_NET_DEV_ZCBUF_EN > 0
  if (rx_zc_cnt > 0) {
    size_t page_size;
    size_t blk_size;

    /* each_buf_size add zc_buf size */
    blk_size = each_buf_size + sizeof(struct pbuf_custom) + sizeof(void *);
    blk_size = ROUND_UP(blk_size, cache_line);

#if LW_CFG_VMM_EN > 0
    page_size = getpagesize();
    helper->rx_zpmem = vmmDmaAllocAlignWithFlags(rx_zc_cnt * blk_size, page_size, helper->cache_zc_flags);
#else /* LW_CFG_VMM_EN */
    page_size = 4 * LW_CFG_KB_SIZE;
    helper->rx_zpmem = sys_malloc_align(rx_zc_cnt * blk_size, page_size);
#endif /* !LW_CFG_VMM_EN */

    if (!helper->rx_zpmem) {
      goto error;
    }

    /* 根据指定参数创建一个接收零拷贝使用的缓冲池结构 */
    helper->rx_hzcpool = netdev_zc_pbuf_pool_create((addr_t)helper->rx_zpmem, rx_zc_cnt, blk_size);
    if (!helper->rx_hzcpool) {
      goto error;
    }
  }
#endif /* LW_CFG_NET_DEV_ZCBUF_EN */

  /* 为指定的 netdev_desc_helper 创建发送缓冲区 */
  if (netdev_desc_tx_buf_create(helper)) {
    goto error;
  }

  /* 为指定的 netdev_desc_helper 创建接收缓冲区 */
  if (netdev_desc_rx_buf_create(helper)) {
    goto error;
  }

  return (helper);

error:
#if LW_CFG_NET_DEV_ZCBUF_EN > 0
  if (rx_zc_cnt > 0) {
    if (helper->rx_hzcpool) {
      netdev_zc_pbuf_pool_delete(helper->rx_hzcpool, 1);
    }

    if (helper->rx_zpmem) {
#if LW_CFG_VMM_EN > 0
      vmmDmaFree(helper->rx_zpmem);
#else /* LW_CFG_VMM_EN */
      sys_free(helper->rx_zpmem);
#endif /* !LW_CFG_VMM_EN */
    }
  }
#endif /* LW_CFG_NET_DEV_ZCBUF_EN */

  sys_free(helper);

  return (NULL);
}

/* delete descriptor helper (you must STOP netdev hardware first!) */
/*********************************************************************************************************
** 函数名称: netdev_desc_helper_delete
** 功能描述: 释放指定 netdev_desc_helper 结构及其成员所占用的所有内存空间
** 输	 入: helper - 需要创建发送缓冲区的 netdev_desc_helper 指针
** 输	 出: 0 - 操作成功
**         : -1 - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int netdev_desc_helper_delete (struct netdev_desc_helper *helper)
{
  if (!helper) {
    return (-1);
  }

  /* 释放指定 netdev_desc_helper 的发送缓冲区所占用的内存空间 */
  netdev_desc_tx_buf_delete(helper);

  /* 释放指定 netdev_desc_helper 的接收缓冲区所占用的内存空间 */
  netdev_desc_rx_buf_delete(helper);

#if LW_CFG_NET_DEV_ZCBUF_EN > 0
  if (helper->rx_hzcpool) {
    int i;
    struct pbuf *p;

    /* recycle all pbuf */
    for (i = 0; i < helper->rx_zc_cnt; i++) {
      do {
	  	/* 从指定的缓冲池中根据指定参数申请一个缓冲区空间并初始化成 custom pbuf 结构 */
        p = netdev_zc_pbuf_alloc(helper->rx_hzcpool, LW_OPTION_WAIT_INFINITE);
      } while (!p);
    }

    /* 释放指定的缓冲池管理数据结构所占用的内存空间 */
    netdev_zc_pbuf_pool_delete(helper->rx_hzcpool, 1);

/* 释放接收数据零拷贝使用的接收缓冲池内存空间 */
#if LW_CFG_VMM_EN > 0
    vmmDmaFree(helper->rx_zpmem);
#else /* LW_CFG_VMM_EN */
    sys_free(helper->rx_zpmem);
#endif /* !LW_CFG_VMM_EN */
  }
#endif /* LW_CFG_NET_DEV_ZCBUF_EN */

  /* 释放指定 netdev_desc_helper 结构占用的内存空间 */
  sys_free(helper);

  return (0);
}

/* netdev_desc_tx_prepare (you must ensure 'idx' is valid) */
/*********************************************************************************************************
** 函数名称: netdev_desc_tx_prepare
** 功能描述: 从指定的 helper 的指定 idx 处为待发送的数据准备缓冲区空间，在发送数据之前调用
** 输	 入: helper - 当前系统使用的 netdev_desc_helper 结构指针
**         : idx - 本次操作对应的缓冲区索引值
**         : p - 包含了待发送数据的 pbuf 结构指针
** 输	 出: NETDEV_DESC_PBUF - 表示使用零拷贝功能的 pbuf 缓冲区
**         : NETDEV_DESC_SBUF - 表示使用指定 helper 的静态缓冲区
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
netdev_desc_btype netdev_desc_tx_prepare (struct netdev_desc_helper *helper, int idx, struct pbuf *p)
{
  struct netdev_desc_buf *tx_buf;

  /* 获取指定 netdev_desc_helper 中指定索引的缓冲区内存首地址 */
  tx_buf = NETDEV_TX_DESC_BUF(helper, idx);

  /* 如果指定的 pbuf 结构为非易失性内存并且系统使能的发送零拷贝，则直接使用函数参数指定的 pbuf 结构
   * 否则把函数参数指定的 pbuf 结构中的数据复制到当前 helper 结构对应位置处的静态缓冲区空间中，并返
   * 回当前使用的缓冲区空间类型 */
  if (NETDEV_TX_CAN_REF_PBUF(p) && helper->tx_zc_en) {
    pbuf_ref(p);
    tx_buf->p = p;
#if LW_CFG_CACHE_EN > 0
    if (helper->cache_pb_flush) {
      cacheFlush(DATA_CACHE, p->payload, p->tot_len);
    }
#endif /* LW_CFG_CACHE_EN */
    return (NETDEV_DESC_PBUF);

  } else {
    LWIP_ASSERT("buffer length to long!", p->tot_len <= helper->each_buf_size);
    pbuf_copy_partial(p, tx_buf->buffer, p->tot_len, 0);
#if LW_CFG_CACHE_EN > 0
    if (helper->cache_ts_flush) {
      cacheFlush(DATA_CACHE, tx_buf->buffer, p->tot_len);
    }
#endif /* LW_CFG_CACHE_EN */
    return (NETDEV_DESC_SBUF);
  }
}

/* netdev_desc_tx_clean (you must ensure 'idx' is valid) */
/*********************************************************************************************************
** 函数名称: netdev_desc_tx_clean
** 功能描述: 回收指定的 helper 的指定 idx 处的缓冲区空间，在数据包发送完成时调用
** 输	 入: helper - 需要回收缓冲区空间的 netdev_desc_helper 结构指针
**         : idx - 本次操作对应的缓冲区索引值
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_desc_tx_clean (struct netdev_desc_helper *helper, int idx)
{
  struct netdev_desc_buf *tx_buf;

  /* 获取指定 netdev_desc_helper 中指定索引的缓冲区内存首地址 */
  tx_buf = NETDEV_TX_DESC_BUF(helper, idx);

  if (tx_buf->p) {
    pbuf_free(tx_buf->p);
    tx_buf->p = NULL;
  }
}

/* netdev_desc_rx_input (you must ensure 'idx' is valid) */
/*********************************************************************************************************
** 函数名称: netdev_desc_rx_input
** 功能描述: 返回指定 netdev_desc_helper 结构中指定索引位置处的接收缓冲区存储的数据对应的 pbuf 结构指针
** 注     释: 在查找指定位置处的接收缓冲区时，会根据这个缓冲区的 rx_buf->p 指针判断当前使用的是零拷贝缓
**         : 冲区还是静态缓冲区，如果使用的是零拷贝缓冲区则直接返回这个 pbuf 结构的指针即可，如果使用
**         : 的是静态缓冲区，则需要申请一个 pbuf 结构，把静态缓冲区中的网络数据包复制到这个 pbuf 中，然后
**         : 返回新申请的 pbuf 结构指针，在处理接收到的数据包前调用
** 输	 入: helper - 需要查找的 netdev_desc_helper 结构指针
**         : idx - 需要查找的接收缓冲区的索引值
**         : len - 在指定位置处的接收缓冲区中存储的数据字节数
** 输	 出: p - 指定位置处存储的网络数据包对应的 pbuf 结构指针
**         : NULL - 查找失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct pbuf *netdev_desc_rx_input (struct netdev_desc_helper *helper, int idx, int len)
{
  struct pbuf *p;
  struct netdev_desc_buf *rx_buf;

  /* 获取指定 netdev_desc_helper 中指定索引的缓冲区内存首地址 */
  rx_buf = NETDEV_RX_DESC_BUF(helper, idx);

  /* 如果指定索引位置处的缓冲区空间的 rx_buf->p 指针不为空，表示使用的是接收零拷贝缓冲区
   * 如果 rx_buf->p 指针为空，表示使用的是接收静态缓冲区 */
  if (rx_buf->p) {
  	/* 获取指定索引处的零拷贝缓冲区空间中存储数的 pbuf 结构指针*/
    p = rx_buf->p;
    p->tot_len = p->len = (u16_t)len;

	/* 回收当前的零拷贝缓冲区空间结构 */
    rx_buf->p = NULL;
	
#if LW_CFG_CACHE_EN > 0
    if (helper->cache_zc_invalid) {
      cacheInvalidate(DATA_CACHE, p->payload, p->tot_len);
    }
#endif /* LW_CFG_CACHE_EN */

  } else {

    /* 从当前系统内申请指定负载空间的 pbuf 结构并在其头部预留出 ETH_PAD_SIZE + SIZEOF_VLAN_HDR
       字节数的空间 */
    p = netdev_pbuf_alloc((u16_t)len);
    if (!p) {
      return (NULL);
    }
	
#if LW_CFG_CACHE_EN > 0
    if (helper->cache_rs_invalid) {
      cacheInvalidate(DATA_CACHE, rx_buf->buffer, len);
    }
#endif /* LW_CFG_CACHE_EN */

    /* 把存储在静态缓冲区中的数据复制到刚刚申请的 pbuf 结构负载空间中 */
    pbuf_take(p, rx_buf->buffer, (u16_t)len);
  }

  return (p);
}

/* netdev_desc_rx_input_offset (you must ensure 'idx' is valid) */
/*********************************************************************************************************
** 函数名称: netdev_desc_rx_input_offset
** 功能描述: 看上面的 netdev_desc_rx_input 函数注释即可
** 输	 入: helper - 需要查找的 netdev_desc_helper 结构指针
**         : idx - 需要查找的接收缓冲区的索引值
**         : len - 在指定位置处的接收缓冲区中存储的数据字节数
**         : offset - 有效网络数据包在接收静态缓冲区中的偏移量
** 输	 出: p - 指定位置处存储的网络数据包对应的 pbuf 结构指针
**         : NULL - 查找失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct pbuf *netdev_desc_rx_input_offset (struct netdev_desc_helper *helper, int idx, int len, int offset)
{
  struct pbuf *p;
  struct netdev_desc_buf *rx_buf;

  rx_buf = NETDEV_RX_DESC_BUF(helper, idx);
  if (rx_buf->p) {
    p = rx_buf->p;
    p->tot_len = p->len = (u16_t)len;
    rx_buf->p = NULL;
#if LW_CFG_CACHE_EN > 0
    if (helper->cache_zc_invalid) {
      cacheInvalidate(DATA_CACHE, p->payload, p->tot_len);
    }
#endif /* LW_CFG_CACHE_EN */

  } else {
    p = netdev_pbuf_alloc((u16_t)len);
    if (!p) {
      return (NULL);
    }
#if LW_CFG_CACHE_EN > 0
    if (helper->cache_rs_invalid) {
      cacheInvalidate(DATA_CACHE, (char *)rx_buf->buffer + offset, len);
    }
#endif /* LW_CFG_CACHE_EN */
    pbuf_take(p, (char *)rx_buf->buffer + offset, (u16_t)len);
  }

  return (p);
}

/* netdev_desc_rx_refill (you must ensure 'idx' is valid) */
/*********************************************************************************************************
** 函数名称: netdev_desc_rx_refill
** 功能描述: 确定指定的 netdev_desc_helper 结构指定索引处的缓冲区使用的缓冲区空间类型，用来存储将来
**         : 接收到的网络数据包数据，在数据包接收完成后调用
** 输	 入: helper - 指定的 netdev_desc_helper 结构指定
**         : idx - 指定的缓冲区的索引位置
** 输	 出: NETDEV_DESC_PBUF - 表示指定位置的缓冲区使用的缓冲区类型为 pbuf
**         : NETDEV_DESC_SBUF - 表示指定位置的缓冲区使用的缓冲区类型为静态缓冲区
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
netdev_desc_btype netdev_desc_rx_refill (struct netdev_desc_helper *helper, int idx)
{
#if LW_CFG_NET_DEV_ZCBUF_EN > 0
  struct netdev_desc_buf *rx_buf;

  /* 获取指定 netdev_desc_helper 中指定索引的缓冲区内存首地址 */
  rx_buf = NETDEV_RX_DESC_BUF(helper, idx);

  if (rx_buf->p) {
    return (NETDEV_DESC_PBUF);
  }

  if (helper->rx_hzcpool) {
  	/* 从指定的缓冲池中根据指定参数申请一个缓冲区空间并初始化成 custom pbuf 结构 */
    rx_buf->p = netdev_zc_pbuf_alloc(helper->rx_hzcpool, LW_OPTION_NOT_WAIT);
    if (rx_buf->p) {
#if LW_CFG_CACHE_EN > 0
      if (helper->cache_zc_invalid) {
        cacheInvalidate(DATA_CACHE, rx_buf->p->payload, rx_buf->p->tot_len);
      }
#endif /* LW_CFG_CACHE_EN */
      return (NETDEV_DESC_PBUF);
    }
  }
#endif /* LW_CFG_NET_DEV_ZCBUF_EN */

  return (NETDEV_DESC_SBUF);
}

/* netdev_desc_rx_refill_res (you must ensure 'idx' is valid) */
/*********************************************************************************************************
** 函数名称: netdev_desc_rx_refill_res
** 功能描述: 看上面的 netdev_desc_rx_refill 函数注释即可
** 输	 入: helper - 指定的 netdev_desc_helper 结构指定
**         : idx - 指定的缓冲区的索引位置
**         : res - 表示在发送缓冲区 pbuf 结构头部保留的空间字节数
** 输	 出: NETDEV_DESC_PBUF - 表示指定位置的缓冲区使用的缓冲区类型为 pbuf
**         : NETDEV_DESC_SBUF - 表示指定位置的缓冲区使用的缓冲区类型为静态缓冲区
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
netdev_desc_btype netdev_desc_rx_refill_res (struct netdev_desc_helper *helper, int idx, UINT16 res)
{
#if LW_CFG_NET_DEV_ZCBUF_EN > 0
  struct netdev_desc_buf *rx_buf;

  rx_buf = NETDEV_RX_DESC_BUF(helper, idx);
  if (rx_buf->p) {
    return (NETDEV_DESC_PBUF);
  }

  if (helper->rx_hzcpool) {

    /* 从指定的缓冲池中根据指定参数申请一个缓冲区空间并初始化成 custom pbuf 结构 */
    rx_buf->p = netdev_zc_pbuf_alloc_res(helper->rx_hzcpool, LW_OPTION_NOT_WAIT, res);
    if (rx_buf->p) {
#if LW_CFG_CACHE_EN > 0
      if (helper->cache_zc_invalid) {
        cacheInvalidate(DATA_CACHE, rx_buf->p->payload, rx_buf->p->tot_len);
      }
#endif /* LW_CFG_CACHE_EN */
      return (NETDEV_DESC_PBUF);
    }
  }
#endif /* LW_CFG_NET_DEV_ZCBUF_EN */

  return (NETDEV_DESC_SBUF);
}

#endif /* LW_CFG_NET_DEV_DESC_HELPER_EN > 0 */
/*
 * end
 */
