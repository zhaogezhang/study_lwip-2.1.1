/**
 * @file
 * Lwip platform independent driver interface.
 * This set of driver interface shields the netif details, 
 * as much as possible compatible with different versions of LwIP
 * Verification using sylixos(tm) real-time operating system
 */

/*
 * Copyright (c) 2006-2018 SylixOS Group.
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

#if LW_CFG_NET_DEV_TXQ_EN > 0

#include "netdev.h"

#ifndef LW_CFG_NET_DEV_TXQ_MIN
#define LW_CFG_NET_DEV_TXQ_MIN  16
#endif

#ifndef LW_CFG_NET_DEV_TXQ_MAX
#define LW_CFG_NET_DEV_TXQ_MAX  LW_CFG_LWIP_NUM_NETBUF
#endif

/*
 * netdev_txq_lock
 */
static LW_SPINLOCK_CA_DEFINE_CACHE_ALIGN(netdev_txq_sl) = LW_SPIN_CA_INITIALIZER;

/*
 * netdev_txq_desc
 */
/* 发送队列成员结构，在发送队列中的每一个成员通过链表的方式链接在一起 */
union netdev_txq_desc {
  union netdev_txq_desc *next;   /* buffer free link */
  struct pbuf *p;   /* packet */
};

/*
 * netdev_txq_ctl
 */
struct netdev_txq_ctl {
  sys_mbox_t txq_mbox;  /* txmsg */
  sys_sem_t txq_semquit; /* tx-thread quit sem */
  
  int txq_len;                     /* 表示当前发送队列一共包含的队列成员个数 */
  int txq_txquit; /* tx-thread quit */
  BOOL txq_block; /* send message with block */
  
  /* txdesc buffer */
  union netdev_txq_desc *txq_mem;  /* 表示当前发送队列中为队列成员分配的内存首地址 */
  union netdev_txq_desc *txq_free; /* 表示当前发送队列中第一个空闲成员的地址 */
};

/* netdev txqueue desc allocate */
/*********************************************************************************************************
** 函数名称: netdev_txq_desc_alloc
** 功能描述: 从指定的发送队列中申请一个空闲成员
** 注     释: 这个函数没有处理指定的发送队列为空的情况
** 输	 入: txq_ctl - 指定的发送队列指针
** 输	 出: desc - 成功申请的队列成员指针
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static LW_INLINE union netdev_txq_desc *
netdev_txq_desc_alloc (struct netdev_txq_ctl *txq_ctl)
{
  union netdev_txq_desc *desc;
  INTREG level;
  
  LW_SPIN_LOCK_QUICK(&netdev_txq_sl.SLCA_sl, &level);
  desc = txq_ctl->txq_free;
  if (desc) {
    txq_ctl->txq_free = desc->next;
  }
  LW_SPIN_UNLOCK_QUICK(&netdev_txq_sl.SLCA_sl, level);
  
  return (desc);
}

/* netdev txqueue desc free */
/*********************************************************************************************************
** 函数名称: netdev_txq_desc_free
** 功能描述: 释放一个指定的队列成员到指定的发送队列中
** 输	 入: txq_ctl - 指定的发送队列指针
**         : desc - 需要释放的队列成员
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static LW_INLINE void 
netdev_txq_desc_free (struct netdev_txq_ctl *txq_ctl, union netdev_txq_desc *desc)
{
  INTREG level;
  
  LW_SPIN_LOCK_QUICK(&netdev_txq_sl.SLCA_sl, &level);
  desc->next = txq_ctl->txq_free;
  txq_ctl->txq_free = desc;
  LW_SPIN_UNLOCK_QUICK(&netdev_txq_sl.SLCA_sl, level);
}

/* netdev txqueue thread */
/*********************************************************************************************************
** 函数名称: netdev_txq_proc
** 功能描述: 网络协议栈的发送队列处理线程函数，用来循环获取待发送的网络数据包，然后通过调用网卡设备的
**         : 发送函数把网络数据包发送出去，并回收 pbuf 数据包占用的内存空间到发送队列 
** 输	 入: arg - 线程参数
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void netdev_txq_proc (void *arg)
{
  netdev_t *netdev = (netdev_t *)arg;
  struct netdev_txq_ctl *txq_ctl = (struct netdev_txq_ctl *)netdev->kern_txq;
  union netdev_txq_desc *desc;

  for (;;) {
    sys_mbox_fetch(&txq_ctl->txq_mbox, (void **)&desc);
    if (LW_UNLIKELY(!desc->p)) {
      txq_ctl->txq_txquit = 1;
      KN_SMP_WMB();
      sys_sem_signal(&txq_ctl->txq_semquit);
      LW_THREAD_UNSAFE(); /* quit from safe mode */
      return;
    }
    
#if ETH_PAD_SIZE /* delete immediately after sending, without pairing. */
    if (netdev->net_type == NETDEV_TYPE_ETHERNET) { /* ethernet */
      pbuf_header(desc->p, -ETH_PAD_SIZE);
    }
#endif

    /* 发送并回收指定的 pbuf 数据包 */
    netdev->drv->transmit(netdev, desc->p);
    pbuf_free(desc->p);
    netdev_txq_desc_free(txq_ctl, desc);
  }
}

/* pbuf is HEAP or POOL? ref it */
/*********************************************************************************************************
** 函数名称: netdev_txq_can_ref
** 功能描述: 判断指定的 pbuf 是否可以当做发送零拷贝缓冲区
** 输	 入: p - 需要判断的 pbuf 指针
** 输	 出: 1 - 可以用作发送零拷贝缓冲区
**         : 0 - 不可以用作发送零拷贝缓冲区
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static LW_INLINE int 
netdev_txq_can_ref (struct pbuf *p)
{
  while (p) {
    if (!PBUF_NEEDS_COPY(p)) {
      p = p->next;
    } else {
      return (0);
    }
  }
  
  return (1);
}

/* netdev txqueue transmit */
/*********************************************************************************************************
** 函数名称: netdev_txq_transmit
** 功能描述: 以发送队列的方式从指定网卡设备发送指定的网络数据包
** 输	 入: netdev - 指定的网卡设备指针
**         : p - 待发送的网络数据包
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t  netdev_txq_transmit (netdev_t *netdev, struct pbuf *p)
{
  struct netdev_txq_ctl *txq_ctl = (struct netdev_txq_ctl *)netdev->kern_txq;
  union netdev_txq_desc *desc;

  /* 从指定的发送队列中申请一个空闲成员 */
  desc = netdev_txq_desc_alloc(txq_ctl);
  if (LW_UNLIKELY(!desc)) {
    netdev_linkinfo_memerr_inc(netdev);
    return (ERR_IF);
  }

  /* 判断指定的 pbuf 是否可以当做发送零拷贝缓冲区，如果可以则直接使用，如果不可以
   * 则把这个 pbuf 中的数据克隆到新的 pbuf 中 */
  if (netdev_txq_can_ref(p)) {
    pbuf_ref(p);
    desc->p = p;
  
  } else {
    desc->p = pbuf_clone(PBUF_RAW, PBUF_POOL, p);
    if (!desc->p) {
      desc->p = pbuf_clone(PBUF_RAW, PBUF_RAM, p);
      if (!desc->p) {
        netdev_txq_desc_free(txq_ctl, desc);
        netdev_linkinfo_memerr_inc(netdev);
        return (ERR_MEM);
      }
    }
  }

  /* 给发送队列线程函数发送一个消息邮箱，让其把待发送的网络数据包发送出去 */
  if (txq_ctl->txq_block) {
    sys_mbox_post(&txq_ctl->txq_mbox, desc);
  
  } else {
    if (sys_mbox_trypost(&txq_ctl->txq_mbox, desc)) {
      pbuf_free(desc->p);
      netdev_txq_desc_free(txq_ctl, desc);
      netdev_linkinfo_err_inc(netdev);
      return (ERR_BUF);
    }
  }
  
  return (ERR_OK);
}

/* enable netdev txqueue */
/*********************************************************************************************************
** 函数名称: netdev_txq_enable
** 功能描述: 为指定的网卡设备创建一个发送队列并使能发送队列功能
** 输	 入: netdev - 指定的网卡设备指针
**         : txq - 指定的发送队列参数
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_txq_enable (netdev_t *netdev, struct netdev_txq *txq)
{
  int i, errlevel = 0;
  UINT32 len;
  struct netdev_txq_ctl *txq_ctl;
  union netdev_txq_desc *desc;

  if (netdev->kern_txq) {
    return (0); /* already enabled */
  }
  
  if (netdev->init_flags & NETDEV_INIT_NO_TXQ) {
    errno = ENOTSUP;
    return (-1);
  }
  
  if (!txq || (txq->txq_len <= 0)) {
    errno = EINVAL;
    return (-1);
  }
  
  if (txq->txq_len > LW_CFG_NET_DEV_TXQ_MAX) {
    len = LW_CFG_NET_DEV_TXQ_MAX;
  } else if (txq->txq_len < LW_CFG_NET_DEV_TXQ_MIN) {
    len = LW_CFG_NET_DEV_TXQ_MIN;
  } else {
    len = txq->txq_len;
  }

  /* 分配发送队列管理数据结构需要的内存空间 */
  txq_ctl = (struct netdev_txq_ctl *)mem_malloc(sizeof(struct netdev_txq_ctl));
  if (!txq_ctl) {
    errno = ENOMEM;
    return (-1);
  }

  /* 分配发送队列中所有队列成员需要的内存空间 */
  txq_ctl->txq_mem = (union netdev_txq_desc *)mem_malloc(sizeof(union netdev_txq_desc) * (len + 2));
  if (!txq_ctl->txq_mem) {
    errno = ENOMEM;
    errlevel = 1;
    goto error;
  }
  
  if (sys_mbox_new(&txq_ctl->txq_mbox, len) != ERR_OK) {
    errlevel = 2;
    goto error;
  }
  
  if (sys_sem_new(&txq_ctl->txq_semquit, 0) != ERR_OK) {
    errlevel = 3;
    goto error;
  }
  
  txq_ctl->txq_len = len;
  txq_ctl->txq_block = txq->txq_block;
  txq_ctl->txq_txquit = 0;
  txq_ctl->txq_free = NULL;
  
  desc = txq_ctl->txq_mem;
  for (i = 0; i < len + 2; i++) {
    desc->next = txq_ctl->txq_free;
    txq_ctl->txq_free = desc;
    desc++;
  }
  
  netdev->kern_txq = (void *)txq_ctl;
  
  if (!sys_thread_new(NETDEVTXQ_THREAD_NAME, netdev_txq_proc, 
                      (void *)netdev, NETDEVTXQ_THREAD_STACKSIZE, NETDEVTXQ_THREAD_PRIO)) {
    errlevel = 4;
    goto error;
  }
  
  return (0);
  
error:
  if (errlevel > 3) {
    sys_sem_free(&txq_ctl->txq_semquit);
  }
  if (errlevel > 2) {
    sys_mbox_free(&txq_ctl->txq_mbox);
  }
  if (errlevel > 1) {
    mem_free(txq_ctl->txq_mem);
  }
  if (errlevel > 0) {
    mem_free(txq_ctl);
  }
  return (-1);
}

/* disable netdev txqueue */
/*********************************************************************************************************
** 函数名称: netdev_txq_disable
** 功能描述: 释放指定的网卡设备的发送队列占用的内存资源并关闭发送队列功能
** 输	 入: netdev - 指定的网卡设备指针
** 输	 出: 0 - 执行成功
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_txq_disable (netdev_t *netdev)
{
  struct netdev_txq_ctl *txq_ctl;
  static union netdev_txq_desc desc_quit = {NULL};
  union netdev_txq_desc *desc;

  if (!netdev->kern_txq) {
    return (0);
  }
  
  txq_ctl = (struct netdev_txq_ctl *)netdev->kern_txq;
  netdev->kern_txq = NULL;
  KN_SMP_MB();
  
  while (!txq_ctl->txq_txquit) {
    sys_mbox_post_prio(&txq_ctl->txq_mbox, &desc_quit, 7);
    sys_sem_wait(&txq_ctl->txq_semquit);
  }
  
  for (;;) {
    if (sys_mbox_tryfetch(&txq_ctl->txq_mbox, (void **)&desc)) {
      break;
    }
    if (desc->p) {
      pbuf_free(desc->p);
    }
  }
  
  sys_sem_free(&txq_ctl->txq_semquit);
  sys_mbox_free(&txq_ctl->txq_mbox);
  mem_free(txq_ctl->txq_mem);
  mem_free(txq_ctl);

  return (0);
}

/* netdev txqueue is enable */
/*********************************************************************************************************
** 函数名称: netdev_txq_isenable
** 功能描述: 判断指定的网卡设备的发送队列功能是否使能
** 输	 入: netdev - 指定的网卡设备指针
** 输	 出: 1 - 已经使能
**         : 0 - 没有使能
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_txq_isenable (netdev_t *netdev)
{
  if (netdev->kern_txq) {
    return (1);
  }
  
  return (0);
}

/* netdev txqueue length */
/*********************************************************************************************************
** 函数名称: netdev_txq_length
** 功能描述: 获取指定网卡设备发送队列中一共包含的队列成员个数
** 输	 入: netdev - 指定的网卡设备指针
** 输	 出: int - 指定网卡设备发送队列成员个数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_txq_length (netdev_t *netdev)
{
  struct netdev_txq_ctl *txq_ctl;
  
  if (!netdev->kern_txq) {
    return (0);
  }
  
  txq_ctl = (struct netdev_txq_ctl *)netdev->kern_txq;
  
  return (txq_ctl->txq_len);
}

#endif /* LW_CFG_NET_DEV_TXQ_EN > 0 */
/*
 * end
 */
