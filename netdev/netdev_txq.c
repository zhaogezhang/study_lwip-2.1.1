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
  
  int txq_len;
  int txq_txquit; /* tx-thread quit */
  BOOL txq_block; /* send message with block */
  
  /* txdesc buffer */
  union netdev_txq_desc *txq_mem;
  union netdev_txq_desc *txq_free;
};

/* netdev txqueue desc allocate */
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

    netdev->drv->transmit(netdev, desc->p);
    pbuf_free(desc->p);
    netdev_txq_desc_free(txq_ctl, desc);
  }
}

/* pbuf is HEAP or POOL? ref it */
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
err_t  netdev_txq_transmit (netdev_t *netdev, struct pbuf *p)
{
  struct netdev_txq_ctl *txq_ctl = (struct netdev_txq_ctl *)netdev->kern_txq;
  union netdev_txq_desc *desc;
  
  desc = netdev_txq_desc_alloc(txq_ctl);
  if (LW_UNLIKELY(!desc)) {
    netdev_linkinfo_memerr_inc(netdev);
    return (ERR_IF);
  }
  
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
  
  txq_ctl = (struct netdev_txq_ctl *)mem_malloc(sizeof(struct netdev_txq_ctl));
  if (!txq_ctl) {
    errno = ENOMEM;
    return (-1);
  }
  
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
int  netdev_txq_isenable (netdev_t *netdev)
{
  if (netdev->kern_txq) {
    return (1);
  }
  
  return (0);
}

/* netdev txqueue length */
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
