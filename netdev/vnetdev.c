/**
 * @file
 * virtual net device driver.
 * as much as possible compatible with different versions of LwIP
 * Verification using sylixos(tm) real-time operating system
 */

/*
 * Copyright (c) 2006-2017 SylixOS Group.
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

#define  __SYLIXOS_STDIO
#define  __SYLIXOS_KERNEL
#include "SylixOS.h"

#if LW_CFG_NET_VNETDEV_EN > 0

#include "lwip/mem.h"
#include "lwip/netif.h"
#include "netdev.h"
#include "vnetdev.h"

/* virtual netdev pbuf free hook */
/*********************************************************************************************************
** 函数名称: vnetdev_pbuf_free
** 功能描述: 释放虚拟网卡的 pbuf 缓冲区占用的内存资源
** 输	 入: p - 需要释放的 pbuf 指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void vnetdev_pbuf_free (struct pbuf *p)
{
  struct vnd_q *vndq = _LIST_ENTRY(p, struct vnd_q, p);
  
  mem_free(vndq);
}

/* virtual netdev pbuf alloc */
/*********************************************************************************************************
** 函数名称: vnetdev_pbuf_alloc
** 功能描述: 根据指定的 pbuf 申请一个与其对应的虚拟网卡缓冲区，并把这个 pbuf 中的数据复制到新申请的
**         : 虚拟网卡缓冲区中
** 输	 入: p - 需要复制的 pbuf 指针
** 输	 出: vndq - 成功申请的虚拟网卡缓冲区
**         : NULL - 申请失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static struct vnd_q *vnetdev_pbuf_alloc (struct pbuf *p)
{
  struct vnd_q *vndq;
  struct pbuf *ret;
  u16_t reserve = ETH_PAD_SIZE + SIZEOF_VLAN_HDR;
  u16_t tot_len = (u16_t)(reserve + p->tot_len);

  /* 为要创建的虚拟网卡缓冲区申请适当内存空间 */
  vndq = (struct vnd_q *)mem_malloc(ROUND_UP(sizeof(struct vnd_q), MEM_ALIGNMENT) + tot_len);
  if (vndq == NULL) {
    return (NULL);
  }

  /* 初始化新申请的虚拟网卡缓冲区 */  
  vndq->p.custom_free_function = vnetdev_pbuf_free;
  ret = pbuf_alloced_custom(PBUF_RAW, tot_len, PBUF_POOL, &vndq->p,
                            (char *)vndq + ROUND_UP(sizeof(struct vnd_q), MEM_ALIGNMENT), 
                            tot_len);
  if (ret) {
  	/* 保留虚拟网卡缓冲区协议头并复制指定 pbuf 数据到虚拟网卡缓冲区中 */
    pbuf_header(ret, (u16_t)-reserve);
    pbuf_copy(ret, p);
  }
  
  return (vndq);
}

/* virtual netdev functions: ioctl */
/*********************************************************************************************************
** 函数名称: vnetdev_ioctl
** 功能描述: 指定虚拟网卡的 IOCTL 函数，目前只支持设置虚拟网卡的 MTU 命令
** 输	 入: netdev - 指定的虚拟网卡设备指针
**         : cmd - 本次执行的命令
**         : arg - 本次执行命令的参数
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int vnetdev_ioctl (struct netdev *netdev, int cmd, void *arg)
{
  struct ifreq *pifreq = (struct ifreq *)arg;

  if (cmd == SIOCSIFMTU) {
    if (pifreq && 
        (pifreq->ifr_mtu >= VNETDEV_MTU_MIN) &&
        (pifreq->ifr_mtu <= VNETDEV_MTU_MAX)) {
      netdev->mtu = pifreq->ifr_mtu;
      return (0);
    }
  }
  
  return (-1);
}

/* virtual netdev functions: transmit */
/*********************************************************************************************************
** 函数名称: vnetdev_transmit
** 功能描述: 虚拟网卡驱动数据包发送函数
** 输	 入: netdev - 指定的虚拟网卡设备指针
**         : p - 待发送是网络数据包
** 输	 出:  0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int vnetdev_transmit (struct netdev *netdev, struct pbuf *p)
{
  struct vnetdev *vnetdev = (struct vnetdev *)netdev;
  struct netif *netif = (struct netif *)netdev->sys;
  struct vnd_q *vndq;
  
  if (!netif_is_link_up(netif)) {
    return (-1);
  }

  /* 判断当前虚拟网卡缓冲区是否可以缓存待发送的网络数据包 */
  if ((vnetdev->cur_size + p->tot_len) > vnetdev->buf_size) {
error:
    netdev_linkinfo_drop_inc(netdev);
    netdev_statinfo_discards_inc(netdev, LINK_OUTPUT);
    return (-1);
  }

  /* 申请一个虚拟网卡使用的 pbuf 缓冲区结构 */
  vndq = vnetdev_pbuf_alloc(p);
  if (vndq == NULL) {
    goto error;
  }
  
  _List_Ring_Add_Ahead(&vndq->ring, &vnetdev->q); /* put to queue */
  vnetdev->cur_size += p->tot_len;

  /* 统计当前网卡数据包信息 */
  netdev_linkinfo_xmit_inc(netdev);
  netdev_statinfo_total_add(netdev, LINK_OUTPUT, p->tot_len);
  if (((UINT8 *)p->payload)[0] & 1) {
    netdev_statinfo_mcasts_inc(netdev, LINK_OUTPUT);
  } else {
    netdev_statinfo_ucasts_inc(netdev, LINK_OUTPUT);
  }

  /* 调用虚拟网卡的 notify 函数，表示有数据可读 */
  vnetdev->notify(vnetdev);
  return (0);
}

/* virtual netdev functions: receive */
/*********************************************************************************************************
** 函数名称: vnetdev_receive
** 功能描述: 虚拟网卡驱动数据包接收函数
** 注     释: 目前这个函数没有具体操作
** 输	 入: netdev - 指定的虚拟网卡设备指针
**         : input - 用来把数据包分发到协议栈的函数指针
** 输	 出:  
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void vnetdev_receive (struct netdev *netdev, int (*input)(struct netdev *, struct pbuf *))
{
  _BugHandle(TRUE, TRUE, "Bug in here!\r\n");
}

/* virtual netdev functions: rxmode */
/*********************************************************************************************************
** 函数名称: vnetdev_rxmode
** 功能描述: 虚拟网卡驱动接收模式设置函数
** 注     释: 目前虚拟网卡接收所有数据包
** 输	 入: netdev - 指定的虚拟网卡设备指针
**         : flags - 操作标志参数
** 输	 出:  
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int vnetdev_rxmode (struct netdev *netdev, int flags)
{
  return (0); /* receive all packet with vnetdev_put() */
}

/* create a virtual netdev */
/*********************************************************************************************************
** 函数名称: vnetdev_add
** 功能描述: 根据指定的虚拟网卡参数创建一个虚拟网卡设备
** 输	 入: netdev - 指定的虚拟网卡设备指针
**         : notify - 虚拟网卡 notify 函数指针，表示有数据可读
**         : bsize - 虚拟网卡发送缓冲区大小
**         : id - 虚拟网卡 id 值
**         : type - 虚拟网卡网络类型
**         : priv - 为虚拟网卡设备指定的私有数据指针
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int vnetdev_add (struct vnetdev *vnetdev, vndnotify notify, size_t bsize, int id, int type, void *priv)
{
  static const UINT8 emty_mac[6] = {0, 0, 0, 0, 0, 0};
  static struct netdev_funcs vnetdev_funcs = {
    NULL, NULL, NULL,NULL, 
    vnetdev_ioctl, 
    vnetdev_rxmode, 
    vnetdev_transmit,
    vnetdev_receive
  };
  
  int  if_flags;
  int  rd;
  time_t tm;
  struct netdev *netdev = &vnetdev->netdev;

  vnetdev->id = id;
  vnetdev->type = type;
  vnetdev->notify = notify; /* save notify function */
  vnetdev->buf_size = bsize;

  netdev->magic_no = NETDEV_MAGIC;
  snprintf(netdev->dev_name, IF_NAMESIZE, "vnd-%d", id);
  lib_strcpy(netdev->if_name, "vn");
  netdev->if_hostname = "VND@SylixOS";
  
  netdev->init_flags = NETDEV_INIT_LOAD_PARAM
                     | NETDEV_INIT_LOAD_DNS
                     | NETDEV_INIT_IPV6_AUTOCFG
                     | NETDEV_INIT_NO_TXQ; /* do not use txqueue */
  netdev->chksum_flags = NETDEV_CHKSUM_ENABLE_ALL; /* we need soft chksum */
  
  if (type == IF_VND_TYPE_RAW) {
    netdev->net_type = NETDEV_TYPE_RAW;
    if_flags = IFF_UP | IFF_POINTOPOINT;
  
  } else {
    netdev->net_type = NETDEV_TYPE_ETHERNET;
    if_flags = IFF_UP | IFF_BROADCAST | IFF_MULTICAST;
  }
  
  netdev->speed = 0;
  netdev->mtu = VNETDEV_MTU_DEF;
  netdev->hwaddr_len = ETH_ALEN;
  netdev->priv = priv;
  netdev->drv = &vnetdev_funcs;
  
  if ((netdev->net_type == NETDEV_TYPE_ETHERNET) && 
      !lib_memcmp(emty_mac, netdev->hwaddr, ETH_ALEN)) {
    lib_time(&tm);
    lib_srand((uint_t)tm);

	/* 通过系统随机数为当前虚拟网卡指定设备物理地址 */
    rd = lib_rand();
    netdev->hwaddr[0] = (UINT8)((rd >> 24) & 0xfe);
    netdev->hwaddr[1] = (UINT8)(rd >> 16);
    netdev->hwaddr[2] = (UINT8)(rd >> 8);
    netdev->hwaddr[3] = (UINT8)(rd);
    rd = lib_rand();
    netdev->hwaddr[4] = (UINT8)(rd >> 8);
    netdev->hwaddr[5] = (UINT8)(rd);
  }

  /* 根据指定的参数初始化指定的网络接口并把这个网络接口添加到系统内 */
  return (netdev_add(netdev, NULL, NULL, NULL, if_flags));
}

/* delete a virtual netdev */
/*********************************************************************************************************
** 函数名称: vnetdev_delete
** 功能描述: 从系统中删除指定的虚拟网卡设备并释放其占用的所有资源
** 输	 入: vnetdev - 需要删除的虚拟网卡设备指针
** 输	 出: 0 - 执行完成
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int vnetdev_delete (struct vnetdev *vnetdev)
{
  struct netdev *netdev = &vnetdev->netdev;
  PLW_LIST_RING pring;
  struct vnd_q *vndq;

  /* 删除当前系统内指定的网络接口并释放其占用的资源 */
  netdev_delete(netdev);

  /* 遍历当前虚拟网卡的接收队列并释放接收队列中的所有数据包 */
  while (vnetdev->q) {
    pring = _list_ring_get_prev(vnetdev->q);
    vndq = (struct vnd_q *)pring;
    _List_Ring_Del(&vndq->ring, &vnetdev->q);
    pbuf_free(&vndq->p.pbuf); /* delete all buffer */
  }
  
  return (0);
}

/* virtual netdev set linkup */
/*********************************************************************************************************
** 函数名称: vnetdev_linkup
** 功能描述: 根据指定的参数更新指定虚拟网卡的链路状态
** 输	 入: vnetdev - 指定的虚拟网卡指针
**         : up - 指定的链路状态
** 输	 出: 0 - 执行完成
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int vnetdev_linkup (struct vnetdev *vnetdev, int up)
{
  struct netdev *netdev = &vnetdev->netdev;
  struct netif *netif = (struct netif *)netdev->sys;
  PLW_LIST_RING pring;
  struct vnd_q *vndq;

  if (up) {
    netif_set_link_up(netif);
  
  } else {
    netif_set_link_down(netif);
    while (vnetdev->q) {
      pring = _list_ring_get_prev(vnetdev->q);
      vndq = (struct vnd_q *)pring;
      _List_Ring_Del(&vndq->ring, &vnetdev->q);
      pbuf_free(&vndq->p.pbuf); /* delete all buffer */
    }
  }
  
  return (0);
}

/* put a packet to virtual netdev as a recv */
/*********************************************************************************************************
** 函数名称: vnetdev_put
** 功能描述: 虚拟网卡的数据包分发函数，在接收到数据包时调用，用来把接收到的数据包分发到上层协议栈
** 输	 入: vnetdev - 指定的虚拟网卡指针
**         : p - 接收到的网络数据包
** 输	 出: 0 - 执行完成
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int vnetdev_put (struct vnetdev *vnetdev, struct pbuf *p)
{
  struct netdev *netdev = &vnetdev->netdev;
  struct netif *netif = (struct netif *)netdev->sys;
  int mcast = ((UINT8 *)p->payload)[0] & 1;
  
  if (!netif_is_link_up(netif)) {
    return (-1);
  }
  
  if (vnetdev->type == IF_VND_TYPE_ETHERNET) {
    /* NOTICE: virtual net device recv not use netdev receive function 
     *         so we MUST move a pad size */
#if ETH_PAD_SIZE
    pbuf_header(p, ETH_PAD_SIZE);
#endif
  }

  /* 把接收到的数据包分发到上层协议栈 */
  if (netif->input(p, netif)) {
    netdev_linkinfo_drop_inc(netdev);
    netdev_statinfo_discards_inc(netdev, LINK_INPUT);
    return (-1);
  }

  /* 统计当前虚拟网卡的数据包信息 */
  netdev_linkinfo_recv_inc(netdev);
  netdev_statinfo_total_add(netdev, LINK_INPUT, p->tot_len);
  if (mcast) {
    netdev_statinfo_mcasts_inc(netdev, LINK_INPUT);
  } else {
    netdev_statinfo_ucasts_inc(netdev, LINK_INPUT);
  }
  return (0);
}

/* get a packet from virtual netdev as a send */
/*********************************************************************************************************
** 函数名称: vnetdev_get
** 功能描述: 从指定的虚拟网卡数据包接收队列中取出一个数据包，并返回这个数据包的 pbuf 结构指针
** 输	 入: vnetdev - 指定的虚拟网卡指针
** 输	 出: vndq->p.pbuf - 成功获取的数据包 pbuf 指针
**         : NULL - 获取数据包失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct pbuf *vnetdev_get (struct vnetdev *vnetdev)
{
  PLW_LIST_RING pring;
  struct vnd_q *vndq;
  
  if (vnetdev->q) {
    pring = _list_ring_get_prev(vnetdev->q);
    vndq = (struct vnd_q *)pring;
    vnetdev->cur_size -= vndq->p.pbuf.tot_len;
    _List_Ring_Del(&vndq->ring, &vnetdev->q);
    return (&vndq->p.pbuf);
  }
  
  return (NULL);
}

/* get total bytes in virtual netdev buffer */
/*********************************************************************************************************
** 函数名称: vnetdev_nread
** 功能描述: 获取指定虚拟网卡数据包接收缓冲区中的数据包字节数
** 输	 入: vnetdev - 指定的虚拟网卡指针
** 输	 出: vnetdev->cur_size - 指定虚拟网卡接收缓冲区数据字节数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int vnetdev_nread (struct vnetdev *vnetdev)
{
  return ((int)vnetdev->cur_size);
}

/* get next input packet bytes */
/*********************************************************************************************************
** 函数名称: vnetdev_nrbytes
** 功能描述: 获取指定虚拟网卡在接收队列中下一个待处理的数据包长度字节数
** 输	 入: vnetdev - 指定的虚拟网卡指针
** 输	 出: vndq->p.pbuf.tot_len - 下一个接收数据包长度
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int vnetdev_nrbytes (struct vnetdev *vnetdev)
{
  PLW_LIST_RING pring;
  struct vnd_q *vndq;
  
  if (vnetdev->q) {
    pring = _list_ring_get_prev(vnetdev->q);
    vndq = (struct vnd_q *)pring;
    return (vndq->p.pbuf.tot_len);
  }
  
  return (0);
}

/* get virtual netdev mtu */
/*********************************************************************************************************
** 函数名称: vnetdev_mtu
** 功能描述: 获取指定虚拟网卡的 MTU 大小
** 输	 入: vnetdev - 指定的虚拟网卡指针
** 输	 出: vnetdev->netdev.mtu - 虚拟网卡 MTU 大小
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int vnetdev_mtu (struct vnetdev *vnetdev)
{
  return (vnetdev->netdev.mtu);
}

/* get virtual netdev max packet len */
/*********************************************************************************************************
** 函数名称: vnetdev_maxplen
** 功能描述: 获取指定虚拟网卡的最大数据包大小
** 输	 入: vnetdev - 指定的虚拟网卡指针
** 输	 出: int - 虚拟网卡最大数据包大小
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int vnetdev_maxplen (struct vnetdev *vnetdev)
{
  if (vnetdev->type == IF_VND_TYPE_ETHERNET) {
    return (vnetdev->netdev.mtu + ETH_HLEN + SIZEOF_VLAN_HDR);
  } else {
    return (vnetdev->netdev.mtu);
  }
}

/* flush virtual netdev buffer */
/*********************************************************************************************************
** 函数名称: vnetdev_flush
** 功能描述: 释放指定虚拟网卡接收队列中所有数据包
** 输	 入: vnetdev - 指定的虚拟网卡指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void vnetdev_flush (struct vnetdev *vnetdev)
{
  PLW_LIST_RING pring;
  struct vnd_q *vndq;

  while (vnetdev->q) {
    pring = _list_ring_get_prev(vnetdev->q);
    vndq = (struct vnd_q *)pring;
    _List_Ring_Del(&vndq->ring, &vnetdev->q);
    pbuf_free(&vndq->p.pbuf); /* delete all buffer */
  }
}

/* set virtual netdev buffer size */
/*********************************************************************************************************
** 函数名称: vnetdev_bufsize
** 功能描述: 设置指定虚拟网卡发送缓存区大小
** 输	 入: vnetdev - 指定的虚拟网卡指针
**         : bsize - 要设置的发送缓冲区大小
** 输	 出: 0 - 设置成功
**         : -1 - 设置失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int vnetdev_bufsize (struct vnetdev *vnetdev, size_t bsize)
{
  /* 发送缓冲区至少可以包含一个最大虚拟网卡数据包 */
  if (bsize < vnetdev->netdev.mtu) {
    return (-1);
  }
  
  vnetdev->buf_size = bsize;
  return (0);
}

/* set virtual netdev checksum enable/disable */
/*********************************************************************************************************
** 函数名称: vnetdev_checksum
** 功能描述: 设置指定的虚拟网卡发送/接收数据包校验和处理标志变量值
** 输	 入: vnetdev - 指定的虚拟网卡指针
**         : gen_en - 表示是否由协议栈计算发送数据包校验和
**         : chk_en - 表示是否由协议栈检查接收数据包校验和
** 输	 出: 0 - 执行完成
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int vnetdev_checksum (struct vnetdev *vnetdev, int gen_en, int chk_en)
{
  UINT32 chksum_flags;
  struct netif *netif;
  
  chksum_flags = vnetdev->netdev.chksum_flags;
  if (gen_en) {
    chksum_flags |= (NETDEV_CHKSUM_GEN_IP | NETDEV_CHKSUM_GEN_UDP | NETDEV_CHKSUM_GEN_TCP | 
                     NETDEV_CHKSUM_GEN_ICMP | NETDEV_CHKSUM_GEN_ICMP6);
  } else {
    chksum_flags &= ~(NETDEV_CHKSUM_GEN_IP | NETDEV_CHKSUM_GEN_UDP | NETDEV_CHKSUM_GEN_TCP | 
                      NETDEV_CHKSUM_GEN_ICMP | NETDEV_CHKSUM_GEN_ICMP6);
  }
  
  if (chk_en) {
    chksum_flags |= (NETDEV_CHKSUM_CHECK_IP | NETDEV_CHKSUM_CHECK_UDP | NETDEV_CHKSUM_CHECK_TCP | 
                     NETDEV_CHKSUM_CHECK_ICMP | NETDEV_CHKSUM_CHECK_ICMP6);
  } else {
    chksum_flags &= ~(NETDEV_CHKSUM_CHECK_IP | NETDEV_CHKSUM_CHECK_UDP | NETDEV_CHKSUM_CHECK_TCP | 
                      NETDEV_CHKSUM_CHECK_ICMP | NETDEV_CHKSUM_CHECK_ICMP6);
  }
  
  if (chksum_flags != vnetdev->netdev.chksum_flags) {
    vnetdev->netdev.chksum_flags = chksum_flags;
    netif = (struct netif *)vnetdev->netdev.sys;
    netif->chksum_flags = (UINT16)chksum_flags;
  }
  
  return (0);
}

#endif /* LW_CFG_NET_VNETDEV_EN */
/*
 * end
 */
