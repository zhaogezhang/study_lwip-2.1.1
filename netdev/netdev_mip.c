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
#include "lwip/pbuf.h"
#include "lwip/inet.h"
#include "lwip/snmp.h"
#include "lwip/netif.h"
#include "lwip/netifapi.h"
#include "lwip/etharp.h"
#include "lwip/tcpip.h"

#if LW_CFG_NET_NETDEV_MIP_EN > 0

#include "string.h"
#include "netdev.h"

/* add a IP to netdev init callback */
/*********************************************************************************************************
** 函数名称: netdev_mipif_init
** 功能描述: 根据指定的主机网卡设备信息初始化指定的从机网口设备
** 输	 入: mipif - 需要创建的虚拟网口设备指针
** 输	 出: ERR_OK - 创建成功
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t netdev_mipif_init (struct netif *mipif)
{
  /* 获取需要创建的从机网卡设备所属的主机网卡设备指针（即我们指定的网卡设备）*/
  netdev_t *netdev = (netdev_t *)(mipif->state);
  struct netif *netif = (struct netif *)netdev->sys;
  
#if LWIP_NETIF_HOSTNAME
  mipif->hostname = netif->hostname;
#endif /* LWIP_NETIF_HOSTNAME */

  /* 初始化从机网口设备名 */
  mipif->name[0] = 'm';
  mipif->name[1] = 'i';

  /* 复制指定网口设备的函数信息和参数信息到新创建的从机网口设备中 */
  MIB2_INIT_NETIF(mipif, netif->link_type, netif->link_speed);

  /* no ipv6, no multicast, no promisc */
  mipif->flags = (u8_t)(netif->flags & ~(NETIF_FLAG_IGMP | NETIF_FLAG_MLD6));

  mipif->output = netif->output;
  mipif->linkoutput = netif->linkoutput;
  
  mipif->mtu = netif->mtu;
  mipif->chksum_flags = netif->chksum_flags;

  mipif->hwaddr_len = netif->hwaddr_len;
  MEMCPY(mipif->hwaddr, netif->hwaddr, netif->hwaddr_len);

  netif_set_tcp_ack_freq(mipif, netif->tcp_ack_freq);
  netif_set_tcp_wnd(mipif, netif->tcp_wnd);

  /* link to list */
  /* 把当前新创建的从机网口设备添加到指定主机网口设备的从机网口设备链表上 */
  mipif->mipif = netif->mipif;
  netif->mipif = mipif;
  mipif->masterif = netif;
  
  return (ERR_OK);
}

/* add a IP to netdev (use slave interface) */
/*********************************************************************************************************
** 函数名称: netdev_mipif_add
** 功能描述: 为指定的网卡设备创建一个指定参数的从机网卡设备
** 输	 入: netdev - 需要创建从机网卡设备的网卡设备指针
**         : ip4 - 从机网卡是 IP 地址
**         : netmask4 - 从机网卡的网络掩码地址
**         : gw4 - 从机网卡的网关地址
** 输	 出: 0 - 创建成功
**         : -1 - 创建失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int netdev_mipif_add (netdev_t *netdev, const ip4_addr_t *ip4, 
                      const ip4_addr_t *netmask4, const ip4_addr_t *gw4)
{
  struct netif *netif, *mipif;
  
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    errno = EINVAL;
    return (-1);
  }
  
  if (ip4_addr_isany(ip4)) {
    errno = EINVAL;
    return (-1);
  }

  /* 获取指定网卡设备的网络接口指针 */
  netif = (struct netif *)netdev->sys;

  /* 判断新创建的从机接口 IP 地址和其所属网口 IP 地址是否相同 */
  if (ip4_addr_cmp(netif_ip4_addr(netif), ip4)) {
    errno = EADDRINUSE;
    return (-1);
  }

  /* 遍历指定网络接口的从机接口链表，判断新创建的从机接口设备是否已经存在 */
  NETIF_MIPIF_FOREACH(netif, mipif) {
    if (ip4_addr_cmp(netif_ip4_addr(mipif), ip4)) {
      errno = EADDRINUSE;
      return (-1);
    }
  }
  
  mipif = (struct netif *)mem_malloc(sizeof(struct netif));
  if (!mipif) {
    errno = ENOMEM;
    return (-1);
  }
  lib_bzero(mipif, sizeof(struct netif));

  /* 为指定的网卡设备创建并初始化一个新的从机网口设备 */
  if (netifapi_netif_add(mipif, ip4, netmask4, gw4, netdev, netdev_mipif_init, tcpip_input)) {
    errno = ENOSPC;
    return (-1);
  }
  
  return (0);
}

/* delete a IP from netdev (use slave interface) */
/*********************************************************************************************************
** 函数名称: netdev_mipif_delete
** 功能描述: 从指定网卡设备的从机网卡设备链表中删除指定 IP 地址的从机网卡设备
** 输	 入: netdev - 需要删除从机网卡设备的网卡设备指针
**         : ip4 - 需要删除的从机网卡设备 IP 地址
** 输	 出: 0 - 移除成功
**         : -1 - 移除失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int netdev_mipif_delete (netdev_t *netdev, const ip4_addr_t *ip4)
{
  struct netif *netif, *mipif, *tmp;
  
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    errno = EINVAL;
    return (-1);
  }

  /* 判断待删除的 IP 地址是否合法 */
  if (ip4_addr_isany(ip4)) {
    errno = EINVAL;
    return (-1);
  }

  /* 获取指定网卡设备的网络接口指针 */
  netif = (struct netif *)netdev->sys;
  if (!netif->mipif) {
    errno = EINVAL;
    return (-1);
  }
  
  mipif = netif->mipif;
  
  if (ip4_addr_cmp(netif_ip4_addr(mipif), ip4)) {
    netif->mipif = mipif->mipif;
    
  } else {
    tmp = mipif;

    /* 遍历指定网卡的从机网卡链表，查找和指定 IP 地址匹配的从机网卡设备 */
    for (mipif = mipif->mipif; mipif != NULL; mipif = mipif->mipif) {
      if (ip4_addr_cmp(netif_ip4_addr(mipif), ip4)) {
	  	/* 如果找到匹配的从机网卡设备，则从链表中删除 */
        tmp->mipif = mipif->mipif;
        break;
      }
      tmp = mipif;
    }
  }

  /* 调用指定从机网卡设备移除回调函数并释放占用的内存资源 */
  if (mipif) {
    netifapi_netif_remove(mipif);
    mem_free(mipif);
    return (0);
  }
  
  errno = EINVAL;
  return (-1);
}

/* clean all slave interface */
/*********************************************************************************************************
** 函数名称: netdev_mipif_clean
** 功能描述: 删除指定网卡设备上所有的从机网卡设备
** 输	 入: netdev - 需要删除从机网卡设备的主机网卡设备指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_mipif_clean (netdev_t *netdev)
{
  struct netif *netif, *mipif, *tmp;

  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return;
  }
  
  netif = (struct netif *)netdev->sys;
  mipif = netif->mipif;
  
  while (mipif) {
    tmp = mipif->mipif;
    netifapi_netif_remove(mipif);
    mem_free(mipif);
    mipif = tmp;
  }
}

/* set all slave interface update mtu, linkup, updown */
/*********************************************************************************************************
** 函数名称: netdev_mipif_update
** 功能描述: 遍历指定主机网卡设备的从机网卡设备链表，根据主机网卡设备网卡速度、链路状态和 MTU 大小
**         : 信息更新所有从机网卡设备的网卡速度、链路状态和 MTU 大小信息
** 注     释: 这个函数在主机网卡设备信息发生变化时候调用，用来把变化同步到所有从机网卡设备中
** 输	 入: netdev - 需要同步参数的主机网卡设备指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_mipif_update (netdev_t *netdev)
{
  struct netif *netif, *mipif;
  
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return;
  }
  
  netif = (struct netif *)netdev->sys;

  /* 遍历指定主机网卡设备的从机网卡设备链表，根据主机网卡设备信息更新所有从机网卡设备信息 */
  NETIF_MIPIF_FOREACH(netif, mipif) {
    mipif->mtu = netif->mtu;
    mipif->link_speed = netif->link_speed;
    if ((mipif->flags & NETIF_FLAG_UP) && !(netif->flags & NETIF_FLAG_UP)) {
      netif_set_down(mipif);
    } else if (!(mipif->flags & NETIF_FLAG_UP) && (netif->flags & NETIF_FLAG_UP)) {
      netif_set_up(mipif);
    }
    mipif->flags = (u8_t)(netif->flags & ~(NETIF_FLAG_IGMP | NETIF_FLAG_MLD6));
  }
}

/* set all slave interface update tcp ack freq, tcp wnd */
/*********************************************************************************************************
** 函数名称: netdev_mipif_tcpupd
** 功能描述: 遍历指定主机网卡设备的从机网卡设备链表，根据主机网卡设备的 tcp 应答频率和窗口大小信息
**         : 更新所有从机网卡的 tcp 应答频率和窗口大小信息
** 注     释: 这个函数在主机网卡设备信息发生变化时候调用，用来把变化同步到所有从机网卡设备中
** 输	 入: netdev - 需要同步参数的主机网卡设备指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_mipif_tcpupd (netdev_t *netdev)
{
  struct netif *netif, *mipif;
  
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return;
  }
  
  netif = (struct netif *)netdev->sys;
  
  NETIF_MIPIF_FOREACH(netif, mipif) {
    netif_set_tcp_ack_freq(mipif, netif->tcp_ack_freq);
    netif_set_tcp_wnd(mipif, netif->tcp_wnd);
  }
}

/* set all slave interface hwaddr */
/*********************************************************************************************************
** 函数名称: netdev_mipif_tcpupd
** 功能描述: 遍历指定主机网卡设备的从机网卡设备链表，根据主机网卡设备的硬件设备地址信息更新所有
**         : 从机网卡的硬件设备地址信息
** 注     释: 这个函数在主机网卡设备信息发生变化时候调用，用来把变化同步到所有从机网卡设备中
** 输	 入: netdev - 需要同步参数的主机网卡设备指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_mipif_hwaddr (netdev_t *netdev)
{
  struct netif *netif, *mipif;
  
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return;
  }
  
  netif = (struct netif *)netdev->sys;
  
  NETIF_MIPIF_FOREACH(netif, mipif) {
    MEMCPY(mipif->hwaddr, netif->hwaddr, netif->hwaddr_len);
  }
}

/* set all slave interface find */
/*********************************************************************************************************
** 函数名称: netdev_mipif_tcpupd
** 功能描述: 根据接收到的数据包的目的 IP 地址找到一个合适的、用来处理接收到的数据包的网络接口
** 注     释: 这个函数在主机网卡设备接收到链路层数据包的时候调用
** 输	 入: netdev - 接收到数据包的主机网卡设备指针
**         : p - 接收到的链路层数据包
** 输	 出: netif - 用来处理接收到的数据包的设备接口指针
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct netif *netdev_mipif_search (netdev_t *netdev, struct pbuf *p)
{
  u16_t next_offset;
  u16_t type;
  ip4_addr_t destip;
  struct netif *netif, *mipif;
  
  netif = (struct netif *)netdev->sys;
  
  destip.addr = IPADDR_ANY;
  
  if (netif->flags & (NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET)) {
    struct eth_hdr *ethhdr = (struct eth_hdr *)p->payload;
    next_offset = SIZEOF_ETH_HDR;
    if (LW_UNLIKELY(p->len < SIZEOF_ETH_HDR)) {
      return (netif);
    }
    
    type = ethhdr->type;
    if (type == PP_HTONS(ETHTYPE_VLAN)) {
      struct eth_vlan_hdr *vlan = (struct eth_vlan_hdr *)(((char *)ethhdr) + SIZEOF_ETH_HDR);
      if (LW_UNLIKELY(p->len < SIZEOF_ETH_HDR + SIZEOF_VLAN_HDR)) {
        return (netif);
      }
      next_offset = SIZEOF_ETH_HDR + SIZEOF_VLAN_HDR;
      type = vlan->tpid;
    }
    
    switch (type) {
    
    case PP_HTONS(ETHTYPE_ARP):
    case PP_HTONS(ETHTYPE_RARP): {
        struct etharp_hdr *arphdr = (struct etharp_hdr *)((u8_t *)p->payload + next_offset);
        if (LW_UNLIKELY(p->len < next_offset + SIZEOF_ETHARP_HDR)) {
          return (netif);
        }
#if BYTE_ORDER == BIG_ENDIAN
        destip.addr = (arphdr->dipaddr.addrw[0] << 16) | arphdr->dipaddr.addrw[1];
#else
        destip.addr = (arphdr->dipaddr.addrw[1] << 16) | arphdr->dipaddr.addrw[0];
#endif
      }
      break;
      
    case PP_HTONS(ETHTYPE_IP): {
        struct ip_hdr *iphdr = (struct ip_hdr *)((char *)p->payload + next_offset);
        if (LW_UNLIKELY(p->len < next_offset + IP_HLEN)) {
          return (netif);
        }
        if (IPH_V(iphdr) != 4) {
          return (netif);
        }
        destip.addr = iphdr->dest.addr;
      }
      break;
      
    default:
      return (netif);
    }
  
  } else {
    struct ip_hdr *iphdr = (struct ip_hdr *)((char *)p->payload);
    if (LW_UNLIKELY(p->len < IP_HLEN)) {
      return (netif);
    }
    if (IPH_V(iphdr) != 4) {
      return (netif);
    }
    destip.addr = iphdr->dest.addr;
  }
  
  if (ip4_addr_cmp(netif_ip4_addr(netif), &destip)) {
    return (netif);
  }

  /* 遍历指定主机网卡设备的从机网卡设备链表，查找和指定目的 IP 地址匹配的从机网卡设备 */
  NETIF_MIPIF_FOREACH(netif, mipif) {
    /* 如果找到和指定目的 IP 匹配的从机网卡设备，则返回这个从机网卡设备指针 */
    if (ip4_addr_cmp(netif_ip4_addr(mipif), &destip)) {
      return (mipif);
    }
  }
  
  return (netif);
}

#endif /* LW_CFG_NET_NETDEV_MIP_EN */
/*
 * end
 */
