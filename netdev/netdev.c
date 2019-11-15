/**
 * @file
 * Lwip platform independent driver interface.
 * This set of driver interface shields the netif details, 
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

#define  __SYLIXOS_KERNEL
#include "lwip/pbuf.h"
#include "lwip/inet.h"
#include "lwip/ethip6.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/netifapi.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/tcpip.h"
#include "lwip/sockets.h"
#include "netif/ethernet.h"
#include "netif/lowpan6.h"
#include "netif/lowpan6_ble.h"
#include "net/if_arp.h"
#include "net/if_lock.h"
#include "net/if_flags.h"
#include "net/if_param.h"
#include "net/if_ether.h"

#define NETDEV_RECEIVE_ARG_3    1

#include "string.h"
#include "netdev.h"
#include "netdev_mip.h"

#if LW_CFG_NET_DEV_TXQ_EN > 0
#include "netdev_txq.h"
#endif /* LW_CFG_NET_DEV_TXQ_EN > 0 */

#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif

#if LW_CFG_NET_DEV_BRIDGE_EN > 0
extern void  netbr_sub_delete_hook(netdev_t *netdev);
#endif /* LW_CFG_NET_DEV_BONDING_EN > 0 */

#if LW_CFG_NET_DEV_BONDING_EN > 0
extern void  netbd_sub_delete_hook(netdev_t *netdev);
#endif /* LW_CFG_NET_DEV_BONDING_EN > 0 */

#define NETDEV_INIT(netdev)                 if ((netdev)->drv->init) { (netdev)->drv->init((netdev)); }
#define NETDEV_UP(netdev)                   if ((netdev)->drv->up) { (netdev)->drv->up((netdev)); }
#define NETDEV_DOWN(netdev)                 if ((netdev)->drv->down) { (netdev)->drv->down((netdev)); }
#define NETDEV_REMOVE(netdev)               if ((netdev)->drv->remove) { (netdev)->drv->remove((netdev)); }
#define NETDEV_IOCTL(netdev, a, b)          if ((netdev)->drv->ioctl) { (netdev)->drv->ioctl((netdev), (a), (b)); }
#define NETDEV_PROMISC(netdev, a, b)        if ((netdev)->drv->promisc) { (netdev)->drv->promisc((netdev), (a), (b)); }
#define NETDEV_RXMODE(netdev, a)            if ((netdev)->drv->rxmode) { (netdev)->drv->rxmode((netdev), (a)); }
#define NETDEV_TRANSMIT(netdev, a)          (netdev)->drv->transmit((netdev), (a))
#define NETDEV_RECEIVE(netdev, input, a)    (netdev)->drv->receive((netdev), (input), (a))

/* functions declaration */
static struct netdev_mac *netdev_macfilter_find(netdev_t *netdev, const UINT8 hwaddr[], struct netdev_mac **prev_save);
static void netdev_macfilter_clean(netdev_t *netdev);

/* lowpan6 timer */
#if LWIP_IPV6
static u8_t lowpan6_timer = 0;

/* Helper function that calls the 6LoWPAN timer and reschedules itself */
static void netdev_lowpan6_timer (void *arg)
{
  lowpan6_tmr();
  if (lowpan6_timer) {
    sys_timeout(LOWPAN6_TMR_INTERVAL, netdev_lowpan6_timer, arg);
  }
}
#endif /* LWIP_IPV6 */

/* lwip netif linkup hook function */
/*********************************************************************************************************
** 函数名称: netdev_netif_linkup
** 功能描述: 根据指定网络接口的状态设置它的 IFF_RUNNING 标志
** 输	 入: netif - 指定的网络接口指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void  netdev_netif_linkup (struct netif *netif)
{
  netdev_t *netdev = (netdev_t *)(netif->state);

  if (netif_is_flag_set(netif, NETIF_FLAG_LINK_UP)) {
    netdev->if_flags |= IFF_RUNNING;
  } else {
    netdev->if_flags &= ~IFF_RUNNING;
  }
}

/* lwip netif up hook function */
/*********************************************************************************************************
** 函数名称: netdev_netif_up
** 功能描述: 在网络接口上线时调用，用来初始化指定的网络接口并设置 IFF_UP 标志
** 输	 入: netif - 指定的网络接口指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void  netdev_netif_up (struct netif *netif)
{
  netdev_t *netdev = (netdev_t *)(netif->state);
  
  NETDEV_UP(netdev);
  netdev->if_flags |= IFF_UP;
  
#if LW_CFG_NET_NETDEV_MIP_EN > 0
  netdev_mipif_update(netdev);
#endif /* LW_CFG_NET_NETDEV_MIP_EN */
}

/* lwip netif down hook function */
/*********************************************************************************************************
** 函数名称: netdev_netif_down
** 功能描述: 在网络接口下线时调用，用来逆初始化指定的网络接口并清除 IFF_UP 标志
** 输	 入: netif - 指定的网络接口指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void  netdev_netif_down (struct netif *netif)
{
  netdev_t *netdev = (netdev_t *)(netif->state);
  
  NETDEV_DOWN(netdev);
  netdev->if_flags &= ~IFF_UP;
  
#if LW_CFG_NET_NETDEV_MIP_EN > 0
  netdev_mipif_update(netdev);
#endif /* LW_CFG_NET_NETDEV_MIP_EN */
}

/* lwip netif remove hook function */
/*********************************************************************************************************
** 函数名称: netdev_netif_remove
** 功能描述: 在网络接口移除时调用，用来释放指定网络接口占用的资源
** 输	 入: netif - 指定的网络接口指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void  netdev_netif_remove (struct netif *netif)
{
  netdev_t *netdev = (netdev_t *)(netif->state);
  
#if LW_CFG_NET_NETDEV_MIP_EN > 0
  netdev_mipif_clean(netdev);
#endif /* LW_CFG_NET_NETDEV_MIP_EN */

#if LW_CFG_NET_DEV_TXQ_EN > 0
  /* 释放指定的网卡设备的发送队列占用的内存资源并关闭发送队列功能 */
  netdev_txq_disable(netdev);
#endif /* LW_CFG_NET_DEV_TXQ_EN */

  NETDEV_REMOVE(netdev);
}

/* lwip netif igmp mac filter hook function */
/*********************************************************************************************************
** 函数名称: netdev_netif_igmp_mac_filter
** 功能描述: 对指定的网络接口的 IPV4 组播过滤地址列表执行指定的操作
** 输	 入: netif - 指定的网络接口指针
**         : group - 指定的组播地址
**         : action - 指定的操作类型（添加/删除）
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t  netdev_netif_igmp_mac_filter (struct netif *netif,
                                            const ip4_addr_t *group, 
                                            enum netif_mac_filter_action action)
{
  netdev_t *netdev = (netdev_t *)(netif->state);
  struct netdev_mac *mac, *prev;
  UINT8 hwaddr[NETIF_MAX_HWADDR_LEN];
  int flags;
  
  if (netdev->net_type != NETDEV_TYPE_ETHERNET) {
    return (ERR_OK);
  }
  
  if (!ip4_addr_ismulticast(group)) {
    return (ERR_VAL);
  }

  /* 把指定的组播地址转换成与其对饮的 mac 地址 */
  hwaddr[0] = LL_IP4_MULTICAST_ADDR_0;
  hwaddr[1] = LL_IP4_MULTICAST_ADDR_1;
  hwaddr[2] = LL_IP4_MULTICAST_ADDR_2;
  hwaddr[3] = ip4_addr2(group) & 0x7f;
  hwaddr[4] = ip4_addr3(group);
  hwaddr[5] = ip4_addr4(group);

  /* 通过遍历指定的网络接口的组播过滤地址列表判断指定的地址是否存在 */
  mac = netdev_macfilter_find(netdev, hwaddr, &prev);
  if (action == NETIF_DEL_MAC_FILTER) {
    if (!mac) {
      return (ERR_VAL);
    }
    if (mac->ref > 1) {
      mac->ref--;
      return (ERR_OK);
    }

	/* 把指定的 mac 地址从指定设备的组播地址链表中删除 */
    if (prev) {
      prev->next = mac->next;
    } else {
      netdev->mac_filter = mac->next;
    }
    
    mem_free(mac);
    netif_set_maddr_hook(netif, group, 0);
    
    flags = netif_get_flags(netif);
    if (!(flags & (IFF_PROMISC | IFF_ALLMULTI))) {
      NETDEV_RXMODE(netdev, flags);
    }
    
  } else {
    if (mac) {
      mac->ref++;
      return (ERR_OK);
    }
    
    mac = (struct netdev_mac *)mem_malloc(sizeof(struct netdev_mac));
    if (!mac) {
      return (ERR_MEM);
    }
    
    mac->nouse = NULL;
    mac->type  = NETDEV_MAC_TYPE_MULTICAST;
    mac->ref   = 1;
    MEMCPY(mac->hwaddr, hwaddr, netdev->hwaddr_len);

    /* 把指定的 mac 地址添加到指定的设备的组播地址链表中 */
    mac->next = netdev->mac_filter;
    netdev->mac_filter = mac;
    netif_set_maddr_hook(netif, group, 1);
    
    flags = netif_get_flags(netif);
    if (!(flags & (IFF_PROMISC | IFF_ALLMULTI))) {
      NETDEV_RXMODE(netdev, flags);
    }
  }
  
  return (ERR_OK);
}

#if LWIP_IPV6 && LWIP_IPV6_MLD
/* lwip netif mld mac filter hook function */
/*********************************************************************************************************
** 函数名称: netdev_netif_mld_mac_filter
** 功能描述: 对指定的网络接口的 IPV6 组播过滤地址列表执行指定的操作
** 输	 入: netif - 指定的网络接口指针
**         : group - 指定的组播地址
**         : action - 指定的操作类型（添加/删除）
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t  netdev_netif_mld_mac_filter (struct netif *netif,
                                           const ip6_addr_t *group, 
                                           enum netif_mac_filter_action action)
{
  netdev_t *netdev = (netdev_t *)(netif->state);
  struct netdev_mac *mac, *prev;
  UINT8 hwaddr[NETIF_MAX_HWADDR_LEN];
  int flags;
  
  if (netdev->net_type != NETDEV_TYPE_ETHERNET) {
    return (ERR_OK);
  }
  
  if (!ip6_addr_ismulticast(group)) {
    return (ERR_VAL);
  }
  
  hwaddr[0] = LL_IP6_MULTICAST_ADDR_0;
  hwaddr[1] = LL_IP6_MULTICAST_ADDR_1;
  hwaddr[2] = ((UINT8 *)(&(group->addr[3])))[0];
  hwaddr[3] = ((UINT8 *)(&(group->addr[3])))[1];
  hwaddr[4] = ((UINT8 *)(&(group->addr[3])))[2];
  hwaddr[5] = ((UINT8 *)(&(group->addr[3])))[3];
  
  mac = netdev_macfilter_find(netdev, hwaddr, &prev);
  if (action == NETIF_DEL_MAC_FILTER) {
    if (!mac) {
      return (ERR_VAL);
    }
    if (mac->ref > 1) {
      mac->ref--;
      return (ERR_OK);
    }
    if (prev) {
      prev->next = mac->next;
    } else {
      netdev->mac_filter = mac->next;
    }
    
    mem_free(mac);
    netif_set_maddr6_hook(netif, group, 0);
    
    flags = netif_get_flags(netif);
    if (!(flags & (IFF_PROMISC | IFF_ALLMULTI))) {
      NETDEV_RXMODE(netdev, flags);
    }
    
  } else {
    if (mac) {
      mac->ref++;
      return (ERR_OK);
    }
    
    mac = (struct netdev_mac *)mem_malloc(sizeof(struct netdev_mac));
    if (!mac) {
      return (ERR_MEM);
    }
    
    mac->nouse = NULL;
    mac->type  = NETDEV_MAC_TYPE_MULTICAST;
    mac->ref   = 1;
    MEMCPY(mac->hwaddr, hwaddr, netdev->hwaddr_len);
    
    mac->next = netdev->mac_filter;
    netdev->mac_filter = mac;
    netif_set_maddr6_hook(netif, group, 1);
    
    flags = netif_get_flags(netif);
    if (!(flags & (IFF_PROMISC | IFF_ALLMULTI))) {
      NETDEV_RXMODE(netdev, flags);
    }
  }
  
  return (ERR_OK);
}
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */

/* lwip netif ioctl hook function */
/*********************************************************************************************************
** 函数名称: netdev_netif_ioctl
** 功能描述: 执行指定网络接口的 ioctl 命令
** 输	 入: netif - 指定的网络接口指针
**         : cmd - 需要执行的命令
**         : arg - 执行的命令参数
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int  netdev_netif_ioctl (struct netif *netif, int cmd, void *arg)
{
  netdev_t *netdev = (netdev_t *)(netif->state);
  struct ifreq *ifreq;
  err_t err = ERR_VAL;
  int flags;
  int ret = -1;
  
  switch (cmd) {

  case SIOCSIFHWADDR:  /* set hwaddr */
    if (netdev->drv->ioctl) {
      ifreq = (struct ifreq *)arg;
      ret = netdev->drv->ioctl(netdev, cmd, arg);
      if (ret == 0) {
        MEMCPY(netdev->hwaddr, ifreq->ifr_hwaddr.sa_data, netdev->hwaddr_len);
#if LW_CFG_NET_NETDEV_MIP_EN > 0
        netdev_mipif_hwaddr(netdev);
#endif /* LW_CFG_NET_NETDEV_MIP_EN */
      }
    }
    break;

  case SIOCSIFMTU:    /* set mtu */
    if (netdev->drv->ioctl) {
      ifreq = (struct ifreq *)arg;
      ret = netdev->drv->ioctl(netdev, cmd, arg);
      if (ret == 0) {
        netdev->mtu = ifreq->ifr_mtu;
#if LW_CFG_NET_NETDEV_MIP_EN > 0
        netdev_mipif_update(netdev);
#endif /* LW_CFG_NET_NETDEV_MIP_EN */
      }
    }
    break;

  case SIOCSIFFLAGS:  /* set flags */
    if (netdev->drv->rxmode) {
      ifreq = (struct ifreq *)arg;
      flags = netif_get_flags(netif);
      if ((flags & (IFF_PROMISC | IFF_ALLMULTI)) != 
          (ifreq->ifr_flags & (IFF_PROMISC | IFF_ALLMULTI))) { /* rx mode changed */
        ret = netdev->drv->rxmode(netdev, ifreq->ifr_flags);
      } else {
        ret = 0; /* do not allow to change other flags */
      }
    }
    break;

  case SIOCADDMULTI:  /* add / del mcast addr */
  case SIOCDELMULTI:
    ifreq = (struct ifreq *)arg;
    if (ifreq->ifr_addr.sa_family == AF_INET) {
      ip4_addr_t group4;
      inet_addr_to_ip4addr(&group4, &((struct sockaddr_in *)&ifreq->ifr_addr)->sin_addr);
      err = netdev_netif_igmp_mac_filter(netif, &group4, ((cmd == SIOCADDMULTI) ? 
                                         NETIF_ADD_MAC_FILTER : NETIF_DEL_MAC_FILTER));
    }
#if LWIP_IPV6 && LWIP_IPV6_MLD
      else if (ifreq->ifr_addr.sa_family == AF_INET6) {
      ip6_addr_t group6;
      inet6_addr_to_ip6addr(&group6, &((struct sockaddr_in6 *)&ifreq->ifr_addr)->sin6_addr);
      err = netdev_netif_mld_mac_filter(netif, &group6, ((cmd == SIOCADDMULTI) ? 
                                        NETIF_ADD_MAC_FILTER : NETIF_DEL_MAC_FILTER));
    }
#endif
    if (err) {
      if (err == ERR_MEM) {
        errno = ENOMEM;
      } else if (err == ERR_VAL) {
        errno = EINVAL;
      }
    } else {
      ret = 0;
    }
    break;

  default:
    if (netdev->drv->ioctl) {
      ret = netdev->drv->ioctl(netdev, cmd, arg);
    }
    break;
  }
  
  return (ret);
}

/* lwip netif null output4 hook function */
static err_t  netdev_netif_nulloutput4 (struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
  return (ERR_IF);
}

/* lwip netif rawoutput hook function */
static err_t  netdev_netif_rawoutput4 (struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
  netdev_t *netdev = (netdev_t *)(netif->state);
  int ret;

  ret = NETDEV_TRANSMIT(netdev, p);
  if (ret < 0) {
    return (ERR_IF);
  }
  
  return (ERR_OK);
}

#if LWIP_IPV6
static err_t  netdev_netif_rawoutput6 (struct netif *netif, struct pbuf *p, const ip6_addr_t *ip6addr)
{
  netdev_t *netdev = (netdev_t *)(netif->state);
  int ret;

  ret = NETDEV_TRANSMIT(netdev, p);
  if (ret < 0) {
    return (ERR_IF);
  }
  
  return (ERR_OK);
}
#endif /* LWIP_IPV6 */

/* lwip netif linkoutput hook function */
/*********************************************************************************************************
** 函数名称: netdev_netif_linkoutput
** 功能描述: 通过指定的网络接口把指定的以太网数据帧发送出去
** 输	 入: netif - 指定的网络接口指针
**         : p - 待发送的以太网数据帧
** 输	 出: err_t - 发送状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t  netdev_netif_linkoutput (struct netif *netif, struct pbuf *p)
{
  netdev_t *netdev = (netdev_t *)(netif->state);
  int ret;

#if LW_CFG_NET_DEV_TXQ_EN > 0
  /* 以发送队列的方式从指定网卡设备发送指定的网络数据包 */
  if (netdev->kern_txq) {
    return (netdev_txq_transmit(netdev, p));
  }
#endif

  if (netdev->net_type == NETDEV_TYPE_ETHERNET) { /* ethernet */
#if ETH_PAD_SIZE
    pbuf_header(p, -ETH_PAD_SIZE);
#endif

    ret = NETDEV_TRANSMIT(netdev, p);
  
#if ETH_PAD_SIZE
    pbuf_header(p, ETH_PAD_SIZE);
#endif

  } else {
    ret = NETDEV_TRANSMIT(netdev, p);
  }

  if (ret < 0) {
    return (ERR_IF);
  }
  
  return (ERR_OK);
}

/* lwip netif linkinput hook function */
/*********************************************************************************************************
** 函数名称: netdev_netif_linkinput
** 功能描述: 处理指定网卡设备接收到的数据包并根据网卡设备类型把接收到的数据包分发到协议栈上层
** 输	 入: netif - 指定的网络接口指针
**         : p - 接收到的数据包
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int  netdev_netif_linkinput (netdev_t *netdev, struct pbuf *p)
{
  err_t err;
  struct netif *netif = (struct netif *)netdev->sys;
  struct eth_hdr *eh;
  
  /* fixed pad */
  /* 处理当前数据包的 pad 数据并调整 pbuf 负载长度变量值 */
  if (netdev->net_type == NETDEV_TYPE_ETHERNET) {
#if ETH_PAD_SIZE
    pbuf_header(p, ETH_PAD_SIZE);
#endif

    /* adjust pbuf length */
    eh = (struct eth_hdr *)p->payload;
    if (eh->type == PP_HTONS(ETHTYPE_VLAN)) {
      if (p->tot_len > (netif->mtu + SIZEOF_ETH_HDR + SIZEOF_VLAN_HDR)) {
        pbuf_realloc(p, (u16_t)(netif->mtu + SIZEOF_ETH_HDR + SIZEOF_VLAN_HDR));
      }
    
    } else {
      if (p->tot_len > (netif->mtu + SIZEOF_ETH_HDR)) {
        pbuf_realloc(p, (u16_t)(netif->mtu + SIZEOF_ETH_HDR));
      }
    }
  }

  /* 输入防火墙处理函数 */
  if (netif->inner_fw && netif->inner_fw(netif, p)) {
    return (0); /* inner firewall eaten */
  }

  /* 输出防火墙处理函数 */
  if (netif->outer_fw && netif->outer_fw(netdev, p)) {
    return (0); /* outer firewall eaten */
  }

  /* 轮训接收数据包处理函数 */
  if (netdev->poll.poll_mode == NETDEV_POLLMODE_EN) {
    if (netdev->poll.poll_input(netdev, p)) {
      return (0); /* poll hook eaten */
    }
  }

#if LW_CFG_NET_NETDEV_MIP_EN > 0
  if (netif->mipif) {
    netif = netdev_mipif_search(netdev, p);
  }
#endif /* LW_CFG_NET_NETDEV_MIP_EN */

  /* 根据当前网卡设备类型分发当前接收到的数据包到协议栈上层 */
  switch (netdev->net_type) {
  
  case NETDEV_TYPE_RAW:
  case NETDEV_TYPE_ETHERNET:
    err = netif->input(p, netif);
    break;
    
#if LWIP_IPV6
  case NETDEV_TYPE_LOWPAN:
    err = tcpip_6lowpan_input(p, netif);
    break;
    
  case NETDEV_TYPE_LOWPAN_BLE:
    err = tcpip_rfc7668_input(p, netif);
    break;
#endif /* LWIP_IPV6 */
  
  default:
    return (-1);
  }
  
  return ((err) ? (-1) : (0));
}

/* lwip netif linkup changed */
/*********************************************************************************************************
** 函数名称: netdev_netif_set_linkup
** 功能描述: 设置指定网络接口的链路状态已经链路层网络速度信息，在链路信息发生变化时调用
** 输	 入: netif - 指定的网络接口指针
**         : linkup - 链路状态
**         :      1 - link up
**         :      0 - link down
**         : speed_high - 链路层速度高 32 位数值（bps）
**         : speed_low -  链路层速度低 32 位数值（bps）
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void  netdev_netif_set_linkup (netdev_t *netdev, int linkup, UINT32 speed_high, UINT32 speed_low)
{
  UINT64 speed = ((UINT64)speed_high << 32) + speed_low;
  struct netif *netif;
  
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return;
  }
  
  netif = (struct netif *)netdev->sys;
  
  if (linkup) {
    netif->ts = sys_jiffies();
    netdev->speed = speed;
    
    if (!netif->ext_ctl) { /* not in net bridge or bonding */
      netifapi_netif_set_link_up(netif);
    } else {
      netif_set_flags(netif, NETIF_FLAG_LINK_UP);
      netdev_netif_linkup(netif);
    }

    if (speed > 0xffffffff) {
      netif->link_speed = 0;
    } else {
      netif->link_speed = (u32_t)speed;
    }
  
  } else {
    if (!netif->ext_ctl) { /* not in net bridge or bonding */
      netifapi_netif_set_link_down(netif);
    } else {
      netif_clear_flags(netif, NETIF_FLAG_LINK_UP);
      netdev_netif_linkup(netif);
    }
  }
  
#if LW_CFG_NET_NETDEV_MIP_EN > 0
  netdev_mipif_update(netdev);
#endif /* LW_CFG_NET_NETDEV_MIP_EN */
}

/* lwip netif add call back function */
/*********************************************************************************************************
** 函数名称: netdev_netif_init
** 功能描述: 初始化指定的网络接口
** 输	 入: netif - 指定的网络接口指针
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t  netdev_netif_init (struct netif *netif)
{
  netdev_t *netdev = (netdev_t *)(netif->state);

#if LWIP_NETIF_HOSTNAME
  netif->hostname = netdev->if_hostname;
#endif /* LWIP_NETIF_HOSTNAME */

  netif->name[0] = netdev->if_name[0];
  netif->name[1] = netdev->if_name[1];

  switch (netdev->net_type) {
  
  case NETDEV_TYPE_ETHERNET:
    MIB2_INIT_NETIF(netif, snmp_ifType_ethernet_csmacd, (u32_t)netdev->speed);
    netif->flags = NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;
    netif->output = etharp_output;
#if LWIP_IPV6
    netif->output_ip6 = ethip6_output;
#endif /* LWIP_IPV6 */
    netif->ar_hrd = ARPHRD_ETHER;
    break;
    
  case NETDEV_TYPE_LOWPAN:
    MIB2_INIT_NETIF(netif, snmp_ifType_ieee802154, 0);
    netif->flags = NETIF_FLAG_BROADCAST;
    netif->output = netdev_netif_nulloutput4;
#if LWIP_IPV6
    netif->output_ip6 = lowpan6_output;
    if (!lowpan6_timer) {
      sys_timeout(LOWPAN6_TMR_INTERVAL, netdev_lowpan6_timer, NULL);
      lowpan6_timer = 1;
    }
#endif /* LWIP_IPV6 */
    netif->ar_hrd = ARPHRD_IEEE802154;
    break;
    
  case NETDEV_TYPE_LOWPAN_BLE:
    MIB2_INIT_NETIF(netif, snmp_ifType_ieee802154, 0);
    netif->flags = 0;
    netif->output = netdev_netif_nulloutput4;
#if LWIP_IPV6
    netif->output_ip6 = rfc7668_output;
    if (netdev->hwaddr_len >= 8) {
      rfc7668_set_local_addr_eui64(netif, netdev->hwaddr, netif->hwaddr_len);
    } else {
      rfc7668_set_local_addr_mac48(netif, netdev->hwaddr, netif->hwaddr_len, 0); /* not public ? */
    }
#endif /* LWIP_IPV6 */
    netif->ar_hrd = ARPHRD_IEEE802154;
    break;
  
  default:
    MIB2_INIT_NETIF(netif, snmp_ifType_other, (u32_t)netdev->speed);
    netif->flags = 0;
    netif->output = netdev_netif_rawoutput4;
#if LWIP_IPV6
    netif->output_ip6 = netdev_netif_rawoutput6;
#endif /* LWIP_IPV6 */
    netif->ar_hrd = ARPHRD_VOID;
    break;
  }
  
  netif->linkoutput = netdev_netif_linkoutput;

  netif->mtu = (u16_t)netdev->mtu;
  
  netif->chksum_flags = (u16_t)netdev->chksum_flags;
  
#if LWIP_IPV6
  if (netdev->init_flags & NETDEV_INIT_IPV6_AUTOCFG) {
    netif_set_ip6_autoconfig_enabled(netif, 1);
  }
#endif /* LWIP_IPV6 */
  
  if (netdev->if_flags & IFF_UP) {
    netif->flags |= NETIF_FLAG_UP;
  }
  
  if (netdev->if_flags & IFF_BROADCAST) {
    netif->flags |= NETIF_FLAG_BROADCAST;
  }
  
  if (netdev->if_flags & IFF_POINTOPOINT) {
    netif->flags &= ~NETIF_FLAG_BROADCAST;
  }
  
  if (netdev->if_flags & IFF_RUNNING) {
    netif->flags |= NETIF_FLAG_LINK_UP;
  }
  
  if (netdev->if_flags & IFF_MULTICAST) {
    netif->flags |= NETIF_FLAG_IGMP | NETIF_FLAG_MLD6;
    if (netdev->net_type == NETDEV_TYPE_ETHERNET) {
#if LWIP_IPV4 && LWIP_IGMP
      netif->igmp_mac_filter = netdev_netif_igmp_mac_filter;
#endif /* LWIP_IPV4 && LWIP_IGMP */
#if LWIP_IPV6 && LWIP_IPV6_MLD
      netif->mld_mac_filter = netdev_netif_mld_mac_filter;
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */
    }
  }
  
  if (netdev->if_flags & IFF_NOARP) {
    netif->flags &= ~NETIF_FLAG_ETHARP;
  }
  
#if LWIP_NETIF_REMOVE_CALLBACK
  netif->remove_callback = netdev_netif_remove;
#endif /* LWIP_NETIF_REMOVE_CALLBACK */
  
  netif->link_callback = netdev_netif_linkup;
  netif->up = netdev_netif_up;
  netif->down = netdev_netif_down;
  netif->ioctl = netdev_netif_ioctl;
  
  netif->flags2 = 0;
  if (netdev->if_flags & IFF_PROMISC) {
    netif->flags2 |= NETIF_FLAG2_PROMISC;
  }
  if (netdev->if_flags & IFF_ALLMULTI) {
    netif->flags2 |= NETIF_FLAG2_ALLMULTI;
  }
  
  if (!(netdev->init_flags & NETDEV_INIT_DO_NOT)) {
    if (netdev->drv->init) {
      if (netdev->drv->init(netdev) < 0) {
        return (ERR_IF);
      } 
    }
  }
  
  /* Update netif hwaddr */
  netif->hwaddr_len = (u8_t)((netdev->hwaddr_len < NETIF_MAX_HWADDR_LEN)
                    ? netdev->hwaddr_len
                    : NETIF_MAX_HWADDR_LEN);

  MEMCPY(netif->hwaddr, netdev->hwaddr, netif->hwaddr_len);
  
  if (netdev->if_flags & IFF_UP) {
    NETDEV_UP(netdev);
  }
  
#if LWIP_IPV6 && LWIP_IPV6_MLD
  /*
   * For hardware/netifs that implement MAC filtering.
   * All-nodes link-local is handled by default, so we must let the hardware know
   * to allow multicast packets in.
   * Should set mld_mac_filter previously. */
  if (netif->mld_mac_filter != NULL) {
    ip6_addr_t ip6_allnodes_ll;
    ip6_addr_set_allnodes_linklocal(&ip6_allnodes_ll);
    netif->mld_mac_filter(netif, &ip6_allnodes_ll, NETIF_ADD_MAC_FILTER);
  }
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */

  NETDEV_RXMODE(netdev, netdev->if_flags); /* init rxmode */

  return (ERR_OK);
}

#if LW_CFG_NET_IPV6 > 0
/* load ipv6 parameter */
static void netdev_netif_ipv6init (struct netif *netif, void  *ifparam)
{
  err_t err;
  int idx;
  ip6_addr_t ip6;
  
  for (idx = 0; idx < LWIP_IPV6_NUM_ADDRESSES; idx++) {
    if (if_param_getipaddr_6(ifparam, idx, &ip6) < 0) {
      break;
    }
    LOCK_TCPIP_CORE(); /* must lock tcpip core */
    err = netif_add_ip6_address(netif, &ip6, NULL);
    UNLOCK_TCPIP_CORE();
    if (!err) {
      break;
    }
  }
  
  if (if_param_getgw_6(ifparam, &ip6)) {
    return;
  }
  LOCK_TCPIP_CORE(); /* must lock tcpip core */
  netif_ip6_gw_set(netif, &ip6);
  UNLOCK_TCPIP_CORE();
}
#endif /* LW_CFG_NET_IPV6 */

#if LW_CFG_NET_NETDEV_MIP_EN > 0
/* load mip parameter */
static void netdev_netif_mipinit (netdev_t *netdev, void  *ifparam)
{
  int idx;
  ip4_addr_t ip4, netmask4, gw4;
  
  for (idx = 0; idx < LW_CFG_NET_DEV_MAX; idx++) {
    if (if_param_getmipaddr(ifparam, idx, &ip4) < 0) {
      break;
    }
    if (if_param_getmnetmask(ifparam, idx, &netmask4) < 0) {
      netmask4.addr = IPADDR_ANY;
    }
    if (if_param_getmgw(ifparam, idx, &gw4) < 0) {
      gw4.addr = IPADDR_ANY;
    }
    if (netdev_mipif_add(netdev, &ip4, &netmask4, &gw4) < 0) {
      break;
    }
  }
}
#endif /* LW_CFG_NET_NETDEV_MIP_EN */

/* netdev driver call the following functions add a network interface,
 * if this device not in '/etc/if_param.ini' ip, netmask, gw is default configuration.
 * 'if_flags' defined in net/if.h such as IFF_UP, IFF_BROADCAST, IFF_RUNNING, IFF_NOARP, IFF_MULTICAST, IFF_PROMISC ... */
/*********************************************************************************************************
** 函数名称: netdev_add
** 功能描述: 根据指定的参数初始化指定的网络接口并把这个网络接口添加到系统内
** 输	 入: netdev - 指定的网络接口指针
**         : ip - 网卡设备默认 IP 地址
**         : netmask - 网卡设备默认网络掩码值
**         : gw - 网卡设备默认网关地址
**         : if_flags - 网卡设备接口标志
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_add (netdev_t *netdev, const char *ip, const char *netmask, const char *gw, int if_flags)
{
  ip4_addr_t ip4, netmask4, gw4;
  struct netif *netif;
  struct netdev_funcs *drv;
  void  *ifparam = NULL;
  int  i, enable, def, dhcp;
  char macstr[32];
  int mac[NETIF_MAX_HWADDR_LEN];
  int tcp_ack_freq = LWIP_NETIF_TCP_ACK_FREQ_MIN;
  int tcp_wnd = TCP_WND;
  
#if LWIP_IPV6
  int autocfg;
#endif

#if LW_CFG_NET_DEV_TXQ_EN > 0
  struct netdev_txq txq = {0, 1};
#endif

  if (!netdev || (netdev->magic_no != NETDEV_MAGIC) || !netdev->drv) {
    _DebugHandle(__ERRORMESSAGE_LEVEL, 
                 "netdev driver version not matching to current system.\r\n");
    return (-1);
  }
  
  if ((netdev->if_name[0] == '\0') || (netdev->if_name[1] == '\0')) {
    return (-1);
  }
  
  if ((netdev->hwaddr_len != 6) && (netdev->hwaddr_len != 8)) {
    return (-1);
  }
  
  drv = netdev->drv;
  if (!drv->transmit || !drv->receive) {
    return (-1);
  }
  
  netif = (struct netif *)netdev->sys;
  lib_bzero(netif, sizeof(struct netif));

  /* 初始化默认 IP 地址 */
  if (ip) {
    ip4.addr = inet_addr(ip);
  } else {
    ip4.addr = IPADDR_ANY;
  }
  
  /* 初始化默认网络掩码值 */
  if (netmask) {
    netmask4.addr = inet_addr(netmask);
  } else {
    netmask4.addr = IPADDR_ANY;
  }
  
  /* 初始化默认网关地址 */
  if (gw) {
    gw4.addr = inet_addr(gw);
  } else {
    gw4.addr = IPADDR_ANY;
  }
  
  netdev->if_flags = if_flags;
  netdev->mac_filter = NULL;
  netdev->poll.poll_mode = NETDEV_POLLMODE_DIS; /* Initialize to normal mode */

  /* 从网络配置文件加载网口参数来初始化当前网卡设备接口 */
  if (netdev->init_flags & NETDEV_INIT_LOAD_PARAM) {
    ifparam = if_param_load(netdev->dev_name);
    if (ifparam) {
      if_param_getenable(ifparam, &enable);
      if (enable) {
        netdev->if_flags |= IFF_UP;
      } else {
        netdev->if_flags &= ~IFF_UP;
      }
    
      if_param_getdefault(ifparam, &def);
      if (def) {
        netdev->init_flags |= NETDEV_INIT_AS_DEFAULT;
      } else {
        netdev->init_flags &= ~NETDEV_INIT_AS_DEFAULT;
      }
      
      if_param_getipaddr(ifparam, &ip4);
      if_param_getnetmask(ifparam, &netmask4);
      if_param_getgw(ifparam, &gw4);

      if (!if_param_getmac(ifparam, macstr, sizeof(macstr))) {
        if (netdev->hwaddr_len == 6) {
          if (sscanf(macstr, "%x:%x:%x:%x:%x:%x", 
                     &mac[0], &mac[1], &mac[2], 
                     &mac[3], &mac[4], &mac[5]) == 6) {
            for (i = 0; i < 6; i++) {
              netdev->hwaddr[i] = (UINT8)mac[i];
            }
          }
        } else {
          if (sscanf(macstr, "%x:%x:%x:%x:%x:%x:%x:%x", 
                     &mac[0], &mac[1], &mac[2], &mac[3], 
                     &mac[4], &mac[5], &mac[6], &mac[7]) == 8) {
            for (i = 0; i < 8; i++) {
              netdev->hwaddr[i] = (UINT8)mac[i];
            }
          }
        }
      }
      
#if LWIP_IPV6
      if (!if_param_ipv6autocfg(ifparam, &autocfg)) {
        if (autocfg) {
          netdev->init_flags |= NETDEV_INIT_IPV6_AUTOCFG;
        } else {
          netdev->init_flags &= ~NETDEV_INIT_IPV6_AUTOCFG;
        }
      }
#endif /* LWIP_IPV6 */
      
#if LWIP_DHCP > 0
      if (!(netdev->init_flags & NETDEV_INIT_USE_DHCP)) {
        if_param_getdhcp(ifparam, &dhcp);
        if (dhcp) {
          netdev->init_flags |= NETDEV_INIT_USE_DHCP;
        }
      }
      if (netdev->init_flags & NETDEV_INIT_USE_DHCP) {
        ip4.addr = IPADDR_ANY;
        netmask4.addr = IPADDR_ANY;
        gw4.addr = IPADDR_ANY;
      }
#endif /* LWIP_DHCP */

#if LWIP_IPV6_DHCP6 > 0
      if (!(netdev->init_flags & NETDEV_INIT_USE_DHCP6)) {
        if_param_getdhcp6(ifparam, &dhcp);
        if (dhcp) {
          netdev->init_flags |= NETDEV_INIT_USE_DHCP6;
        }
      }
#endif /* LWIP_IPV6_DHCP6 */

#if LW_CFG_NET_DEV_TXQ_EN > 0
      if_param_gettxqueue(ifparam, &txq.txq_len);
      if_param_gettxqblock(ifparam, &txq.txq_block);
#endif /* LW_CFG_NET_DEV_TXQ_EN */

      if_param_tcpackfreq(ifparam, &tcp_ack_freq);
      if (tcp_ack_freq < LWIP_NETIF_TCP_ACK_FREQ_MIN) {
        tcp_ack_freq = LWIP_NETIF_TCP_ACK_FREQ_MIN; /* Min 2 */
      
      } else if (tcp_ack_freq > LWIP_NETIF_TCP_ACK_FREQ_MAX) {
        tcp_ack_freq = LWIP_NETIF_TCP_ACK_FREQ_MAX; /* Max 127 */
      }
      
      if_param_tcpwnd(ifparam, &tcp_wnd);
      if (tcp_wnd < (2 * TCP_MSS)) {
        tcp_wnd = (2 * TCP_MSS);
      
      } else if (tcp_wnd > 0xffffu << TCP_RCV_SCALE) {
        tcp_wnd = 0xffffu << TCP_RCV_SCALE;
      }
    }
  }

  /* 从网络配置文件加载 DNS 参数来初始化当前网卡 DNS */
  if (netdev->init_flags & NETDEV_INIT_LOAD_DNS) {
    if_param_syncdns();
  }

  /* 向当前系统内添加一个新的网络接口设备 */
  if (netifapi_netif_add(netif, &ip4, &netmask4, &gw4, netdev, netdev_netif_init, tcpip_input)) {
    if (ifparam) {
      if_param_unload(ifparam);
    }
    return (-1);
  }
  
  netif_set_tcp_ack_freq(netif, (u8_t)tcp_ack_freq);
  netif_set_tcp_wnd(netif, (u32_t)tcp_wnd);

  netif_get_name(netif, netdev->if_name); /* update netdev if_name */
  
#if LW_CFG_NET_DEV_TXQ_EN > 0
  if (txq.txq_len > 0) {
    netdev_txq_enable(netdev, &txq);
  }
#endif /* LW_CFG_NET_DEV_TXQ_EN */
  
#if LW_CFG_NET_IPV6 > 0
  if (ifparam) {
    netdev_netif_ipv6init(netif, ifparam);
  }
#endif /* LW_CFG_NET_IPV6 */
  
#if LW_CFG_NET_NETDEV_MIP_EN > 0
  if (ifparam) {
    netdev_netif_mipinit(netdev, ifparam);
  }
#endif /* LW_CFG_NET_NETDEV_MIP_EN */
  
  if (ifparam) {
    if_param_unload(ifparam);
  }

#if LWIP_IPV6
  switch (netdev->net_type) {
  
  case NETDEV_TYPE_ETHERNET:
    netif_create_ip6_linklocal_address(netif, 1);
    break;
    
  case NETDEV_TYPE_LOWPAN:
  case NETDEV_TYPE_LOWPAN_BLE:
    netif_create_ip6_linklocal_address(netif, 0);
    break;

  default:
    break;
  }
#endif /* LWIP_IPV6 */
  
  if (netdev->init_flags & NETDEV_INIT_AS_DEFAULT) {
    netifapi_netif_set_default(netif);
  }
  
#if LWIP_DHCP > 0
  if (netdev->init_flags & NETDEV_INIT_USE_DHCP) {
    netif->flags2 |= NETIF_FLAG2_DHCP;
    netifapi_dhcp_start(netif);
  }
#endif /* LWIP_DHCP */

#if LWIP_IPV6_DHCP6 > 0
  if (netdev->init_flags & NETDEV_INIT_USE_DHCP6) {
    netif->flags2 |= NETIF_FLAG2_DHCP6;
    netifapi_dhcp6_enable_stateless(netif);
  }
#endif /* LWIP_IPV6_DHCP6 > 0 */

  return (0);
}

/* netdev driver call the following functions delete a network interface 
 * WARNING: You MUST DO NOT lock device then call this function, it will cause a deadlock with TCP LOCK */
/*********************************************************************************************************
** 函数名称: netdev_delete
** 功能描述: 删除当前系统内指定的网络接口并释放其占用的资源
** 输	 入: netdev - 指定的网络接口指针
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_delete (netdev_t *netdev)
{
  struct netif *netif, *tmp_netif;
  
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  netif = (struct netif *)netdev->sys;
  
  LWIP_IF_LIST_LOCK(LW_TRUE);

#if LW_CFG_NET_DEV_BRIDGE_EN > 0
  netbr_sub_delete_hook(netdev);
#endif /* LW_CFG_NET_DEV_BONDING_EN > 0 */

#if LW_CFG_NET_DEV_BONDING_EN > 0
  netbd_sub_delete_hook(netdev);
#endif /* LW_CFG_NET_DEV_BONDING_EN > 0 */
  
  NETIF_FOREACH(tmp_netif) {
    if (tmp_netif == netif) {
      break;
    }
  }
  if (tmp_netif) {
    netifapi_netif_remove(netif);
  }
  LWIP_IF_LIST_UNLOCK();
  
  netdev_macfilter_clean(netdev);
  netJobDeleteEx(LW_NETJOB_Q_ALL, 1, NULL, netdev, 0, 0, 0, 0, 0); /* delete all netjob message */
  
  return (0);
}

/* netdev driver get netdev index */
/*********************************************************************************************************
** 函数名称: netdev_index
** 功能描述: 获取指定网络接口设备在当前系统内的索引值
** 输	 入: netdev - 指定的网络接口指针
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
**         : index - 指定网路接口的索引值
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_index (netdev_t *netdev, unsigned int *index)
{
  struct netif *netif;
  
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  netif = (struct netif *)netdev->sys;
  
  if (index) {
    *index = netif_get_index(netif);
    return (0);
    
  } else {
    return (-1);
  }
}

/* netdev set firewall */
/*********************************************************************************************************
** 函数名称: netdev_firewall
** 功能描述: 设置指定网络接口的输出防火墙函数指针
** 输	 入: netdev - 指定的网络接口指针
**         : fw - 输出防火墙函数指针
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_firewall (netdev_t *netdev, int (*fw)(netdev_t *, struct pbuf *))
{
  struct netif *netif;

  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  netif = (struct netif *)netdev->sys;
  netif->outer_fw = (int (*)(void *, struct pbuf *))fw;
  
  return (0);
}

/* netdev set qoshook */
/*********************************************************************************************************
** 函数名称: netdev_qoshook
** 功能描述: 设置指定网络接口的输出方向的 QOS 函数指针
** 输	 入: netdev - 指定的网络接口指针
**         : qos - QOS 函数指针
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_qoshook (netdev_t *netdev, UINT8 (*qos)(netdev_t *, struct pbuf *, UINT8, UINT8, UINT16, UINT8 *))
{
  struct netif *netif;

  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  netif = (struct netif *)netdev->sys;
  netif->outer_qos = (u8_t (*)(void *, struct pbuf *, u8_t, u8_t, u16_t, u8_t *))qos;
  
  return (0);
}

/* netdev traversal */
/*********************************************************************************************************
** 函数名称: netdev_foreache
** 功能描述: 遍历当前系统内的每一个网络接口，当这个网络接口的 ioctl 函数指针是 netdev_netif_ioctl，则
**         : 在这个网路接口上调用指定的操作函数
** 输	 入: pfunc - 当 ioctl 函数指针匹配时需要调用的操作函数
**         : arg1.arg5 - 指定的操作函数参数
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_foreache (FUNCPTR pfunc, void *arg0, void *arg1, 
                      void *arg2, void *arg3, void *arg4, void *arg5)
{
  struct netif *netif;
  netdev_t     *netdev;
  
  if (!pfunc) {
    return (-1);
  }
  
  NETIF_FOREACH(netif) {
    if (netif->ioctl == netdev_netif_ioctl) {
      netdev = (netdev_t *)(netif->state);
      if (pfunc(netdev, arg0, arg1, arg2, arg3, arg4, arg5)) {
        break;
      }
    }
  }
  
  return (0);
}

/* netdev start poll mode */
/*********************************************************************************************************
** 函数名称: netdev_poll_enable
** 功能描述: 设置指定网卡设备的轮训接收数据包函数指针并使能其轮训接收数据包功能并关闭网卡设备中断
** 输	 入: netdev - 指定的网络接口指针
**         : poll_input - 轮训接收函数指针
**         : poll_arg - 轮训接收函数参数
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_poll_enable (netdev_t *netdev, int (*poll_input)(struct netdev *, struct pbuf *), void *poll_arg)
{
  if (!netdev || !poll_input || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  if (!netdev->drv->pollrecv || !netdev->drv->intctl) {
    errno = ENOTSUP;
    return (-1);
  }
  
  if (netdev->poll.poll_mode == NETDEV_POLLMODE_EN) {
    errno = EBUSY;
    return (-1);
  }
  
  if (netdev->drv->intctl(netdev, 0)) {
    return (-1);
  }
  
  netdev->poll.poll_arg = poll_arg;
  netdev->poll.poll_input = poll_input;
  netdev->poll.poll_mode = NETDEV_POLLMODE_EN;
  
  return (0);
}

/* netdev stop poll mode */
/*********************************************************************************************************
** 函数名称: netdev_poll_disable
** 功能描述: 关闭指定网卡设备的轮训接收数据包功能并使能网卡设备中断
** 输	 入: netdev - 指定的网络接口指针
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_poll_disable (netdev_t *netdev)
{
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  if (netdev->poll.poll_mode == NETDEV_POLLMODE_DIS) {
    return (0);
  }
  
  netdev->poll.poll_mode = NETDEV_POLLMODE_DIS;
  netdev->drv->intctl(netdev, 1);
  
  return (0);
}

/* netdev poll mode service */
/*********************************************************************************************************
** 函数名称: netdev_poll_svc
** 功能描述: 
** 输	 入: netdev - 指定的网络接口指针
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_poll_svc (netdev_t *netdev)
{
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  if (netdev->poll.poll_mode == NETDEV_POLLMODE_DIS) {
    return (-1);
  }
  
  if (netdev->drv->pollrecv) {
    netdev->drv->pollrecv(netdev);
  }
  
  return (0);
}

/* netdev find (MUST in NETIF_LOCK mode) */
/*********************************************************************************************************
** 函数名称: netdev_find_by_index
** 功能描述: 查找当前系统内指定索引值的网络接口设备
** 输	 入: netdev - 指定的设备索引值
** 输	 出: netdev_t - 找到的网卡设备指针
**         : NULL - 没找到对应的网卡设备
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
netdev_t *netdev_find_by_index (unsigned int index)
{
  struct netif *netif;
  netdev_t     *netdev;
  
  netif = netif_get_by_index((u8_t)index);
  if (netif && (netif->ioctl == netdev_netif_ioctl)) {
    netdev = (netdev_t *)(netif->state);
    if (netdev && (netdev->magic_no == NETDEV_MAGIC)) {
      return (netdev);
    }
  }
  
  return (NULL);
}

/*********************************************************************************************************
** 函数名称: netdev_find_by_ifname
** 功能描述: 查找当前系统内指定网路接口名的网络接口设备
** 输	 入: if_name - 指定的接口名
** 输	 出: netdev_t - 找到的网卡设备指针
**         : NULL - 没找到对应的网卡设备
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
netdev_t *netdev_find_by_ifname (const char *if_name)
{
  struct netif *netif;
  netdev_t     *netdev;
  
  if (!if_name) {
    return (NULL);
  }
  
  netif = netif_find(if_name);
  if (netif && (netif->ioctl == netdev_netif_ioctl)) {
    netdev = (netdev_t *)(netif->state);
    if (netdev && (netdev->magic_no == NETDEV_MAGIC)) {
      return (netdev);
    }
  }
  
  return (NULL);
}

/*********************************************************************************************************
** 函数名称: netdev_find_by_devname
** 功能描述: 查找当前系统内指定网卡设备名的网络接口设备
** 输	 入: if_name - 指定的设备名
** 输	 出: netdev_t - 找到的网卡设备指针
**         : NULL - 没找到对应的网卡设备
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
netdev_t *netdev_find_by_devname (const char *dev_name)
{
  struct netif *netif;
  netdev_t     *netdev;

  if (!dev_name) {
    return (NULL);
  }
  
  NETIF_FOREACH(netif) {
    if (netif->ioctl == netdev_netif_ioctl) {
      netdev = (netdev_t *)(netif->state);
      if (netdev && (netdev->magic_no == NETDEV_MAGIC)) {
        if (lib_strcmp(netdev->dev_name, dev_name) == 0) {
          return (netdev);
        }
      }
    }
  }
  
  return (NULL);
}

/* netdev get name */
/*********************************************************************************************************
** 函数名称: netdev_ifname
** 功能描述: 获取指定网卡设备的网络接口名
** 输	 入: netdev - 指定的网卡设备指针
** 输	 出: 0 - 获取成功
**         : -1 - 获取失败
**         : ifname - 获取到的网络接口名
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_ifname (netdev_t *netdev, char *ifname)
{
  struct netif *netif;
  
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  netif = (struct netif *)netdev->sys;
  if (ifname) {
    netif_get_name(netif, ifname);
  }
  
  return (0);
}

/* netdev set/get format of hardware address
 * NOTICE: you can call these function after netdev_add() */
int  netdev_set_ar_hdr (netdev_t *netdev, UINT16 ar_hdr)
{
  struct netif *netif;

  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }

  netif = (struct netif *)netdev->sys;

  netif->ar_hrd = ar_hdr;

  return (0);
}

int  netdev_get_ar_hdr (netdev_t *netdev, UINT16 *ar_hdr)
{
  struct netif *netif;

  if (!netdev || !ar_hdr || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }

  netif = (struct netif *)netdev->sys;

  *ar_hdr = netif->ar_hrd;

  return (0);
}

/* netdev set/get tcp ack frequecy 
 * NOTICE: you can call these function after netdev_add() */
/*********************************************************************************************************
** 函数名称: netdev_set_tcpaf
** 功能描述: 设置指定网卡设备的 tcp 应答频率
** 输	 入: netdev - 指定的网卡设备指针
**         : tcpaf - 需要设置的 tcp 应答频率
** 输	 出: 0 - 操作成功
**         : -1 - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_set_tcpaf (netdev_t *netdev, UINT8 tcpaf)
{
  struct netif *netif;
  
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  netif = (struct netif *)netdev->sys;
  
  if (tcpaf < LWIP_NETIF_TCP_ACK_FREQ_MIN) {
    tcpaf = LWIP_NETIF_TCP_ACK_FREQ_MIN;
  
  } else if (tcpaf > LWIP_NETIF_TCP_ACK_FREQ_MAX) {
    tcpaf = LWIP_NETIF_TCP_ACK_FREQ_MAX;
  }
  
  netif_set_tcp_ack_freq(netif, tcpaf);
  
#if LW_CFG_NET_NETDEV_MIP_EN > 0
  netdev_mipif_tcpupd(netdev);
#endif /* LW_CFG_NET_NETDEV_MIP_EN */
  
  return (0);
}

/*********************************************************************************************************
** 函数名称: netdev_get_tcpaf
** 功能描述: 获取指定网卡设备的 tcp 应答频率
** 输	 入: netdev - 指定的网卡设备指针
**         : tcpaf - 获取到的 tcp 应答频率
** 输	 出: 0 - 操作成功
**         : -1 - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_get_tcpaf (netdev_t *netdev, UINT8 *tcpaf)
{
  struct netif *netif;
  
  if (!netdev || !tcpaf || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  netif = (struct netif *)netdev->sys;
  
  *tcpaf = netif_get_tcp_ack_freq(netif);
  
  return (0);
}

/* netdev set/get tcp window size
 * NOTICE: you can call these function after netdev_add() */
/*********************************************************************************************************
** 函数名称: netdev_set_tcpwnd
** 功能描述: 设置指定网卡设备的 tcp 窗口大小
** 输	 入: netdev - 指定的网卡设备指针
**         : tcpwnd - 要设置的 tcp 窗口大小
** 输	 出: 0 - 操作成功
**         : -1 - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_set_tcpwnd (netdev_t *netdev, UINT32 tcpwnd)
{
  struct netif *netif;
  
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  netif = (struct netif *)netdev->sys;
  
  if (tcpwnd < (2 * TCP_MSS)) {
    tcpwnd = (2 * TCP_MSS);
  
  } else if (tcpwnd > 0xffffu << TCP_RCV_SCALE) {
    tcpwnd = 0xffffu << TCP_RCV_SCALE;
  }
  
  netif_set_tcp_wnd(netif, tcpwnd);
  
#if LW_CFG_NET_NETDEV_MIP_EN > 0
  netdev_mipif_tcpupd(netdev);
#endif /* LW_CFG_NET_NETDEV_MIP_EN */
  
  return (0);
}

/*********************************************************************************************************
** 函数名称: netdev_get_tcpwnd
** 功能描述: 获取指定网卡设备的 tcp 窗口大小
** 输	 入: netdev - 指定的网卡设备指针
**         : tcpwnd - 获取到的 tcp 窗口大小
** 输	 出: 0 - 操作成功
**         : -1 - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_get_tcpwnd (netdev_t *netdev, UINT32 *tcpwnd)
{
  struct netif *netif;
  
  if (!netdev || !tcpwnd || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  netif = (struct netif *)netdev->sys;
  
  *tcpwnd = netif_get_tcp_wnd(netif);
  
  return (0);
}

/* if netdev link status changed has been detected, 
 * driver must call the following functions 
 * NOTICE: In order to avoid deadlocks (between TCPIP LOCK and Device Lock. so wei use netjob do this) */
/*********************************************************************************************************
** 函数名称: netdev_set_linkup
** 功能描述: 设置指定网络接口的链路状态已经链路层网络速度信息，在链路信息发生变化时调用
** 输	 入: netdev - 指定的网卡设备指针
**         : linkup - 链路状态
**         : speed - 链路层速度（bps）
** 输	 出: 0 - 操作成功
**         : -1 - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_set_linkup (netdev_t *netdev, int linkup, UINT64 speed)
{
  UINT32 speed_high = (UINT32)((speed >> 32) & 0xffffffff);
  UINT32 speed_low = (UINT32)(speed & 0xffffffff);

  return (netJobAdd(netdev_netif_set_linkup, netdev,
                    (void *)linkup, (void *)speed_high, (void *)speed_low, 0, 0));
}

/*********************************************************************************************************
** 函数名称: netdev_get_linkup
** 功能描述: 获取指定网络接口的链路状态
** 输	 入: netdev - 指定的网卡设备指针
** 输	 出: 0 - 操作成功
**         : -1 - 操作失败
**         : linkup - 获取到的链路状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_get_linkup (netdev_t *netdev, int *linkup)
{
  struct netif *netif;
  
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  netif = (struct netif *)netdev->sys;
  
  if (linkup) {
    if (netif_is_link_up(netif)) {
      *linkup = 1;
    } else {
      *linkup = 0;
    }
  }
  
  return (0);
}

/* netdev linkup watchdog function 
 * NOTICE: one netdev can ONLY add one linkup_wd function.
 *         when netdev removed driver must delete watchdog function manually. */
/*********************************************************************************************************
** 函数名称: netdev_linkup_wd_add
** 功能描述: 为指定的网卡设备设置链路检测函数，主要在设备热插拔时检测并更新网卡设备链路状态
** 输	 入: netdev - 指定的网卡设备指针
**         : linkup_wd - 检测并更新网卡设备链路状态的函数指针
** 输	 出: 0 - 操作成功
**         : -1 - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_linkup_wd_add (netdev_t *netdev, void  (*linkup_wd)(netdev_t *))
{
#if LW_CFG_HOTPLUG_EN > 0
  if (netdev && linkup_wd) {
    return (hotplugPollAdd(linkup_wd, netdev));
  }
#endif /* LW_CFG_HOTPLUG_EN */
  return (-1);
}

/*********************************************************************************************************
** 函数名称: netdev_linkup_wd_delete
** 功能描述: 删除指定网卡设备的链路热插拔检测函数
** 输	 入: netdev - 指定的网卡设备指针
**         : linkup_wd - 检测并更新网卡设备链路状态的函数指针
** 输	 出: 0 - 操作成功
**         : -1 - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_linkup_wd_delete (netdev_t *netdev, void  (*linkup_wd)(netdev_t *))
{
#if LW_CFG_HOTPLUG_EN > 0
  if (netdev && linkup_wd) {
    return (hotplugPollDelete(linkup_wd, netdev));
  }
#endif /* LW_CFG_HOTPLUG_EN */
  return (-1);
}

/* netdev mac filter is empty */
int  netdev_macfilter_isempty (netdev_t *netdev)
{
  return (!netdev->mac_filter);
}

/* netdev mac filter cnt */
int  netdev_macfilter_count (netdev_t *netdev)
{
  struct netdev_mac *ha;
  int cnt = 0;
  
  NETDEV_MACFILTER_FOREACH(netdev, ha) {
    cnt++;
  }
  
  return (cnt);
}

/* netdev mac filter add a hwaddr and allow to recv */
/*********************************************************************************************************
** 函数名称: netdev_macfilter_add
** 功能描述: 向指定网卡设备的硬件设备地址过滤链表中添加新的地址过滤成员
** 输	 入: netdev - 指定的网卡设备指针
**         : hwaddr - 需要添加的新的硬件过滤地址
** 输	 出: 0 - 操作成功
**         : -1 - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_macfilter_add (netdev_t *netdev, const UINT8 hwaddr[])
{
  struct netdev_mac *mac, *prev;
  int type, flags;
  
  if (netdev->net_type != NETDEV_TYPE_ETHERNET) {
    return (-1);
  }
  
  if ((hwaddr[0] == LL_IP4_MULTICAST_ADDR_0) &&
      (hwaddr[1] == LL_IP4_MULTICAST_ADDR_1) &&
      (hwaddr[2] == LL_IP4_MULTICAST_ADDR_2)) {
    type = NETDEV_MAC_TYPE_MULTICAST;
  
  } else if ((hwaddr[0] == LL_IP6_MULTICAST_ADDR_0) &&
             (hwaddr[1] == LL_IP6_MULTICAST_ADDR_1)) {
    type = NETDEV_MAC_TYPE_MULTICAST;
  
  } else {
    type = NETDEV_MAC_TYPE_UNICAST;
  }
  
  mac = netdev_macfilter_find(netdev, hwaddr, &prev);
  if (mac) {
    mac->ref++;
    return (0);
  }
  
  mac = (struct netdev_mac *)mem_malloc(sizeof(struct netdev_mac));
  if (!mac) {
    errno = ENOMEM;
    return (-1);
  }
  
  mac->nouse = NULL;
  mac->type  = type;
  mac->ref   = 1;
  MEMCPY(mac->hwaddr, hwaddr, netdev->hwaddr_len);
  
  mac->next = netdev->mac_filter;
  netdev->mac_filter = mac;
  
  flags = netif_get_flags((struct netif *)(netdev->sys));
  if (!(flags & (IFF_PROMISC | IFF_ALLMULTI)) || 
      (type != NETDEV_MAC_TYPE_MULTICAST)) {
    NETDEV_RXMODE(netdev, flags);
  }
  
  return (0);
}

/* netdev mac filter delete a hwaddr */
/*********************************************************************************************************
** 函数名称: netdev_macfilter_delete
** 功能描述: 从指定网卡设备的硬件设备地址过滤链表中删除指定的地址过滤成员
** 输	 入: netdev - 指定的网卡设备指针
**         : hwaddr - 需要删除的硬件过滤地址
** 输	 出: 0 - 操作成功
**         : -1 - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_macfilter_delete (netdev_t *netdev, const UINT8 hwaddr[])
{
  struct netdev_mac *mac, *prev;
  int type, flags;
  
  if (netdev->net_type != NETDEV_TYPE_ETHERNET) {
    return (-1);
  }
  
  mac = netdev_macfilter_find(netdev, hwaddr, &prev);
  if (!mac) {
    errno = EINVAL;
    return (-1);
  }
  
  if (mac->ref > 1) {
    mac->ref--;
    return (0);
  }
  
  if (prev) {
    prev->next = mac->next;
  } else {
    netdev->mac_filter = mac->next;
  }
  
  type = mac->type;
  mem_free(mac);
  
  flags = netif_get_flags((struct netif *)(netdev->sys));
  if (!(flags & (IFF_PROMISC | IFF_ALLMULTI)) || 
      (type != NETDEV_MAC_TYPE_MULTICAST)) {
    NETDEV_RXMODE(netdev, flags);
  }
  
  return (0);
}

/* netdev mac filter find */
/*********************************************************************************************************
** 函数名称: netdev_macfilter_find
** 功能描述: 通过遍历指定的网络接口的组播过滤地址列表判断指定的地址是否存在
** 输	 入: netif - 指定的网络接口指针
**         : hwaddr - 指定的组播地址
**         : prev_save - 如果存在，表示找到的组播地址前向成员指针
** 输	 出: ha - 找到的组播地址成员指针
**         : prev_save - 找到的组播地址前向成员指针
**         : NULL - 表示没找到指定的组播地址
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static struct netdev_mac *netdev_macfilter_find (netdev_t *netdev, const UINT8 hwaddr[], struct netdev_mac **prev_save)
{
  struct netdev_mac *ha;
  struct netdev_mac *prev = NULL;
  
  NETDEV_MACFILTER_FOREACH(netdev, ha) {
    if (!lib_memcmp(ha->hwaddr, hwaddr, netdev->hwaddr_len)) {
      if (prev_save) {
        *prev_save = prev;
      }
      return (ha);
    }
    prev = ha;
  }
  
  return (NULL);
}

/* netdev mac filter clean */
/*********************************************************************************************************
** 函数名称: netdev_macfilter_clean
** 功能描述: 把指定网卡设备的所有硬件过滤地址链表中的成员全部清除并释放其占用的内存资源
** 输	 入: netdev - 指定的网卡设备指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void netdev_macfilter_clean (netdev_t *netdev)
{
  struct netdev_mac *ha;
  
  while (netdev->mac_filter) {
    ha = netdev->mac_filter;
    netdev->mac_filter = ha->next;
    mem_free(ha);
  }
}

/* if netdev detected a packet in netdev buffer, driver can call this function to receive this packet.
   notify:0 can transmit 1: can receive 
   qen:0 do not use netjob queue 1:use netjob queue */
/*********************************************************************************************************
** 函数名称: netdev_notify
** 功能描述: 处理指定网卡设备接收到的数据包并根据网卡设备类型把接收到的数据包分发到协议栈上层
** 输	 入: netdev - 指定的网卡设备指针
**         : inout - 数据包传输方向，必须是 LINK_INPUT
**         : q_en - 是否通过工作队列来执行数据包处理函数
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_notify (struct netdev *netdev, netdev_inout inout, int q_en)
{
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  if (inout != LINK_INPUT) {
    return (0);
  }
  
  if (q_en) {
    if (netJobAdd(netdev->drv->receive, netdev, 
                  (void *)netdev_netif_linkinput, 0, 0, 0, 0) == 0) {
      return (0);
    
    } else {
      return (-1);
    }
  }
  
  NETDEV_RECEIVE(netdev, netdev_netif_linkinput, NULL);
  
  return (0);
}

int  netdev_notify_ex (struct netdev *netdev, netdev_inout inout, int q_en, unsigned int qindex)
{
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  if (inout != LINK_INPUT) {
    return (0);
  }
  
  if (q_en) {
    if (netJobAddEx(qindex, netdev->drv->receive, netdev, 
                    (void *)netdev_netif_linkinput, 0, 0, 0, 0) == 0) {
      return (0);
    
    } else {
      return (-1);
    }
  }
  
  NETDEV_RECEIVE(netdev, netdev_netif_linkinput, NULL);
  
  return (0);
}

int  netdev_notify_ex_arg (struct netdev *netdev, netdev_inout inout, int q_en, unsigned int qindex, void *arg)
{
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  if (inout != LINK_INPUT) {
    return (0);
  }
  
  if (q_en) {
    if (netJobAddEx(qindex, netdev->drv->receive, netdev, 
                    (void *)netdev_netif_linkinput, arg, 0, 0, 0) == 0) {
      return (0);
    
    } else {
      return (-1);
    }
  }
  
  NETDEV_RECEIVE(netdev, netdev_netif_linkinput, arg);
  
  return (0);
}

/*********************************************************************************************************
** 函数名称: netdev_notify_clear
** 功能描述: 从当前系统内的网卡数据包处理工作队列中删除待执行的工作 job
** 输	 入: netdev - 指定的网卡设备指针
** 输	 出: 0 - 执行成功
**         : -1 - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int  netdev_notify_clear (struct netdev *netdev)
{
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  netJobDelete(2, netdev->drv->receive, netdev, 
               (void *)netdev_netif_linkinput, 0, 0, 0, 0);
               
  return (0);
}

int  netdev_notify_clear_ex (struct netdev *netdev, unsigned int qindex)
{
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  netJobDeleteEx(qindex, 2, netdev->drv->receive, netdev, 
                 (void *)netdev_netif_linkinput, 0, 0, 0, 0);
               
  return (0);
}

int  netdev_notify_clear_ex_arg (struct netdev *netdev, unsigned int qindex, void *arg)
{
  if (!netdev || (netdev->magic_no != NETDEV_MAGIC)) {
    return (-1);
  }
  
  netJobDeleteEx(qindex, 3, netdev->drv->receive, netdev, 
                 (void *)netdev_netif_linkinput, arg, 0, 0, 0);
               
  return (0);
}

/* netdev statistical information update functions in:1 input 0:output */
/*********************************************************************************************************
** 函数名称: netdev_statinfo_total_add
** 功能描述: 统计指定网卡设备指定数据包方向一共处理过的数据字节数
** 输	 入: netdev - 指定的网卡设备指针
**         : inout - 数据包方向
**         : bytes - 本次统计的字节数
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_statinfo_total_add (netdev_t *netdev, netdev_inout inout, UINT32 bytes)
{
  struct netif *netif = (struct netif *)netdev->sys;
  
  if (inout == LINK_INPUT) {
    snmp_add_ifinoctets(netif, bytes);
  
  } else {
    snmp_add_ifoutoctets(netif, bytes);
  }
}

/*********************************************************************************************************
** 函数名称: netdev_statinfo_ucasts_inc
** 功能描述: 统计指定网卡设备指定数据包方向处理过的单播数据包包数
** 输	 入: netdev - 指定的网卡设备指针
**         : inout - 数据包方向
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_statinfo_ucasts_inc (netdev_t *netdev, netdev_inout inout)
{
  struct netif *netif = (struct netif *)netdev->sys;
  
  if (inout == LINK_INPUT) {
    snmp_inc_ifinucastpkts(netif);
  
  } else {
    snmp_inc_ifoutucastpkts(netif);
  }
}

/*********************************************************************************************************
** 函数名称: netdev_statinfo_mcasts_inc
** 功能描述: 统计指定网卡设备指定数据包方向处理过的多播数据包包数
** 输	 入: netdev - 指定的网卡设备指针
**         : inout - 数据包方向
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_statinfo_mcasts_inc (netdev_t *netdev, netdev_inout inout)
{
  struct netif *netif = (struct netif *)netdev->sys;
  
  if (inout == LINK_INPUT) {
    snmp_inc_ifinnucastpkts(netif);
  
  } else {
    snmp_inc_ifoutnucastpkts(netif);
  }
}

/*********************************************************************************************************
** 函数名称: netdev_statinfo_discards_inc
** 功能描述: 统计指定网卡设备指定数据包方向丢弃的数据包包数
** 输	 入: netdev - 指定的网卡设备指针
**         : inout - 数据包方向
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_statinfo_discards_inc (netdev_t *netdev, netdev_inout inout)
{
  struct netif *netif = (struct netif *)netdev->sys;
  
  if (inout == LINK_INPUT) {
    snmp_inc_ifindiscards(netif);
  
  } else {
    snmp_inc_ifoutdiscards(netif);
  }
}

/*********************************************************************************************************
** 函数名称: netdev_statinfo_errors_inc
** 功能描述: 统计指定网卡设备指定数据包方向错误的数据包包数
** 输	 入: netdev - 指定的网卡设备指针
**         : inout - 数据包方向
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_statinfo_errors_inc (netdev_t *netdev, netdev_inout inout)
{
  struct netif *netif = (struct netif *)netdev->sys;
  
  if (inout == LINK_INPUT) {
    snmp_inc_ifinerrors(netif);
  
  } else {
    snmp_inc_ifouterrors(netif);
  }
}

void netdev_statinfo_collisions_inc (netdev_t *netdev)
{
  struct netif *netif = (struct netif *)netdev->sys;
  
  snmp_inc_ifcollisions(netif);
}

/* atomic inc/dec */
#if LW_CFG_NET_DEV_TXQ_EN > 0 /* lwip_stats.link is 32bits */
#define LINK_STATS_INC_ATOMIC(x) \
  { \
    atomic_t *atomic = (atomic_t *)&lwip_stats.x; \
    __LW_ATOMIC_INC(atomic); \
  }
#endif /* LW_CFG_NET_DEV_TXQ_EN */

/* netdev link statistical information update functions */
/*********************************************************************************************************
** 函数名称: netdev_linkinfo_err_inc
** 功能描述: 统计指定网卡设备链路层所有类型错误计数值
** 输	 入: netdev - 指定的网卡设备指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_linkinfo_err_inc (netdev_t *netdev)
{
#if LW_CFG_NET_DEV_TXQ_EN > 0
  if (netdev->kern_txq) {
    LINK_STATS_INC_ATOMIC(link.err);
  } else
#endif /* LW_CFG_NET_DEV_TXQ_EN */
  {
    LINK_STATS_INC(link.err);
  }
}

/*********************************************************************************************************
** 函数名称: netdev_linkinfo_lenerr_inc
** 功能描述: 统计指定网卡设备链路层包长度错误计数值
** 输	 入: netdev - 指定的网卡设备指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_linkinfo_lenerr_inc(netdev_t *netdev)
{
#if LW_CFG_NET_DEV_TXQ_EN > 0
  if (netdev->kern_txq) {
    LINK_STATS_INC_ATOMIC(link.lenerr);
  } else
#endif /* LW_CFG_NET_DEV_TXQ_EN */
  {
    LINK_STATS_INC(link.lenerr);
  }
}

/*********************************************************************************************************
** 函数名称: netdev_linkinfo_chkerr_inc
** 功能描述: 统计指定网卡设备链路层包校验错误计数值
** 输	 入: netdev - 指定的网卡设备指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_linkinfo_chkerr_inc(netdev_t *netdev)
{
#if LW_CFG_NET_DEV_TXQ_EN > 0
  if (netdev->kern_txq) {
    LINK_STATS_INC_ATOMIC(link.chkerr);
  } else
#endif /* LW_CFG_NET_DEV_TXQ_EN */
  {
    LINK_STATS_INC(link.chkerr);
  }
}

/*********************************************************************************************************
** 函数名称: netdev_linkinfo_memerr_inc
** 功能描述: 统计指定网卡设备链路层内存错误计数值
** 输	 入: netdev - 指定的网卡设备指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_linkinfo_memerr_inc(netdev_t *netdev)
{
#if LW_CFG_NET_DEV_TXQ_EN > 0
  if (netdev->kern_txq) {
    LINK_STATS_INC_ATOMIC(link.memerr);
  } else
#endif /* LW_CFG_NET_DEV_TXQ_EN */
  {
    LINK_STATS_INC(link.memerr);
  }
}

/*********************************************************************************************************
** 函数名称: netdev_linkinfo_drop_inc
** 功能描述: 统计指定网卡设备链路层丢包计数值
** 输	 入: netdev - 指定的网卡设备指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_linkinfo_drop_inc(netdev_t *netdev)
{
#if LW_CFG_NET_DEV_TXQ_EN > 0
  if (netdev->kern_txq) {
    LINK_STATS_INC_ATOMIC(link.drop);
  } else
#endif /* LW_CFG_NET_DEV_TXQ_EN */
  {
    LINK_STATS_INC(link.drop);
  }
}

/*********************************************************************************************************
** 函数名称: netdev_linkinfo_recv_inc
** 功能描述: 统计指定网卡设备链路层接收数据包计数值
** 输	 入: netdev - 指定的网卡设备指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_linkinfo_recv_inc(netdev_t *netdev)
{
#if LW_CFG_NET_DEV_TXQ_EN > 0
  if (netdev->kern_txq) {
    LINK_STATS_INC_ATOMIC(link.recv);
  } else
#endif /* LW_CFG_NET_DEV_TXQ_EN */
  {
    LINK_STATS_INC(link.recv);
  }
}

/*********************************************************************************************************
** 函数名称: netdev_linkinfo_xmit_inc
** 功能描述: 统计指定网卡设备链路层发送数据包计数值
** 输	 入: netdev - 指定的网卡设备指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_linkinfo_xmit_inc(netdev_t *netdev)
{
#if LW_CFG_NET_DEV_TXQ_EN > 0
  if (netdev->kern_txq) {
    LINK_STATS_INC_ATOMIC(link.xmit);
  } else
#endif /* LW_CFG_NET_DEV_TXQ_EN */
  {
    LINK_STATS_INC(link.xmit);
  }
}

/* netdev input buffer get 
 * reserve: ETH_PAD_SIZE + SIZEOF_VLAN_HDR size. */
/*********************************************************************************************************
** 函数名称: netdev_pbuf_alloc
** 功能描述: 从当前系统内申请指定负载空间的 pbuf 结构并在其头部预留出 ETH_PAD_SIZE + SIZEOF_VLAN_HDR
**		   : 字节数的空间
** 输	 入: len - 需要申请的 pbuf 负载空间大小
** 输	 出: p - 成功申请的 pbuf 指针
**		   : NULL - 申请失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct pbuf *netdev_pbuf_alloc (UINT16 len)
{
  u16_t reserve = ETH_PAD_SIZE + SIZEOF_VLAN_HDR;

  /* 申请一个指定 TCP/IP 协议层（预留协议头需要的空间）、指定要申请的内存空间大小和指定类型的 pbuf */
  struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)(len + reserve), PBUF_POOL);

  if (p) {
    /* 把指定的 pbuf 的负载指针（pbuf->payload）位置向前（显示协议头数据，header_size_increment 大于零）
       或者向后（隐藏协议头数据，header_size_increment 小于零）调整指定字节数 */
    pbuf_header(p, (u16_t)-reserve);
  }
  
  return (p);
}

/*********************************************************************************************************
** 函数名称: netdev_pbuf_free
** 功能描述: 释放指定的 pbuf 数据包结构
** 输	 入: p - 需要释放的 pbuf 数据包结构指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void netdev_pbuf_free (struct pbuf *p)
{
  pbuf_free(p);
}

/*********************************************************************************************************
** 函数名称: netdev_pbuf_alloc_ram
** 功能描述: 从当前系统内申请指定负载空间的 pbuf 结构并在其头部预留出指定字节数的空间
** 输	 入: len - 需要申请的 pbuf 负载空间大小
**		   : res - 需要预留的空间字节数
** 输	 出: p - 成功申请的 pbuf 指针
**		   : NULL - 申请失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct pbuf *netdev_pbuf_alloc_ram (UINT16 len, UINT16 res)
{
  struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)(len + res), PBUF_POOL);
  
  if (p) {
    pbuf_header(p, (u16_t)-res);
  }
  
  return (p);
}

/* netdev transmit function can ref this packet? */
/*********************************************************************************************************
** 函数名称: netdev_pbuf_can_ref
** 功能描述: 判断指定的 pbuf 数据结构是否可以用来当做零拷贝数据包缓冲区
** 输	 入: p - 需要判断的 pbuf 数据结构
** 输	 出: TRUE - 可以当做零拷贝数据包缓冲区
**		   : FALSE - 不可以当做零拷贝数据包缓冲区
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
BOOL netdev_pbuf_can_ref (struct pbuf *p)
{
  if (p->tot_len == p->len) {
    if (!PBUF_NEEDS_COPY(p)) {
      return (TRUE);
    }
  }
  
  return (FALSE);
}

/* get netdev data buffer */
/*********************************************************************************************************
** 函数名称: netdev_pbuf_data
** 功能描述: 获取指定的 pbuf 数据包结构的负载空间指针
** 输	 入: p - 指定的 pbuf 数据结构
** 输	 出: void * - 获取到的负载空间指针
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void *netdev_pbuf_data (struct pbuf *p)
{
  return (p->payload);
}

/* netdev input buffer push */
/*********************************************************************************************************
** 函数名称: netdev_pbuf_push
** 功能描述: 把指定的 pbuf 的负载指针（pbuf->payload）位置向“前”调整指定字节数
** 输	 入: p - 指定的 pbuf 数据结构
**         : len - 需要移动的字节数
** 输	 出: UINT8 * - 移动后的 pbuf 负载空间地址
**         : NULL - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
UINT8 *netdev_pbuf_push (struct pbuf *p, UINT16 len)
{
  if (p) {
    if (pbuf_header(p, (s16_t)len) == 0) {
      return ((UINT8 *)p->payload);
    }
  }
  
  return (NULL);
}

/* netdev input buffer pop */
/*********************************************************************************************************
** 函数名称: netdev_pbuf_push
** 功能描述: 把指定的 pbuf 的负载指针（pbuf->payload）位置向“后”调整指定字节数
** 输	 入: p - 指定的 pbuf 数据结构
**         : len - 需要移动的字节数
** 输	 出: UINT8 * - 移动后的 pbuf 负载空间地址
**         : NULL - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
UINT8 *netdev_pbuf_pull (struct pbuf *p, UINT16 len)
{
  if (p) {
    if (pbuf_header(p, (s16_t)-len) == 0) {
      return ((UINT8 *)p->payload);
    }
  }
  
  return (NULL);
}

/* netdev input buffer cat */
/*********************************************************************************************************
** 函数名称: netdev_pbuf_push
** 功能描述: 把指定的两个 pbuf 结构链接到一起，组成一个 pbuf 结构
** 输	 入: h - 放在头部的 pbuf 结构
**         : t - 放在尾部的 pbuf 结构
**         : ref_t - 表示链接后，尾部的 pbuf 是否需要增加引用计数
** 输	 出: 0 - 操作成功
**         : -1 - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int netdev_pbuf_link (struct pbuf *h, struct pbuf *t, BOOL ref_t)
{
  if (h && t) {
    if (ref_t) {
	  /* 把两个指定的 pbuf chain 合并成一个 pbuf chain，即把指定的尾部方向 pbuf chain 链表链接到
         指定的 pbuf chain 头部方向链表上，并把连接点后端 pbuf 的引用计数加 1，又因为 pbuf 在申请
         后默认引用计数值为 1，所以连接点后端 pbuf 的引用计数至少为 2 */
      pbuf_chain(h, t);
    } else {
      /* 把两个指定的 pbuf chain 合并成一个 pbuf chain，即把指定的尾部方向 pbuf chain 链表链接到
         指定的 pbuf chain 头部方向链表上，但是连接点后端 pbuf 的引用计数“不”加 1 */
      pbuf_cat(h, t);
    }
    return (0);
  }
  
  return (-1);
}

/* netdev input buffer trunc */
/*********************************************************************************************************
** 函数名称: netdev_pbuf_push
** 功能描述: 收缩指定的 pbuf 应用负载空间长度到指定的值（把 pbuf 链表尾部多余的 pbuf 释放掉）
** 输	 入: p - 需要收缩的 pbuf 指针
**		   : len - 收缩后的 pbuf 应用负载空间长度
** 输	 出: 0 - 操作成功
**         : -1 - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int netdev_pbuf_trunc (struct pbuf *p, UINT16 len)
{
  if (p && (p->tot_len >= len)) {
    pbuf_realloc(p, len);
    return (0);
  }
  
  return (-1);
}

/* netdev buffer get vlan info */
/*********************************************************************************************************
** 函数名称: netdev_pbuf_vlan_present
** 功能描述: 判断指定的以太网数据帧是否包含 VLAN 字段数据
** 输	 入: p - 需要判断的以太网数据帧
** 输	 出: 1 - 包含 VLAN 字段数据
**         : 0 - 不包含 VLAN 字段数据
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int netdev_pbuf_vlan_present (struct pbuf *p)
{
  struct eth_hdr *ethhdr = (struct eth_hdr *)((u8_t *)p->payload - ETH_PAD_SIZE);
  
  return (ethhdr->type == PP_HTONS(ETHTYPE_VLAN));
}

/*********************************************************************************************************
** 函数名称: netdev_pbuf_vlan_id
** 功能描述: 获取指定的以太网数据帧中的 VLAN 字段中的 VLAN ID 字段数据内容
** 输	 入: p - 指定的以太网数据帧
** 输	 出: 1 - 包含 VLAN 字段数据
**         : 0 - 不包含 VLAN 字段数据
**         : vlanid - 获取到的 VLAN ID 字段数据内容
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int netdev_pbuf_vlan_id (struct pbuf *p, UINT16 *vlanid)
{
  struct eth_hdr *ethhdr = (struct eth_hdr *)((u8_t *)p->payload - ETH_PAD_SIZE);

  if ((ethhdr->type == PP_HTONS(ETHTYPE_VLAN)) && (p->len >= ETH_HLEN + 4)) {
    struct eth_vlan_hdr *vlan = (struct eth_vlan_hdr *)(((u8_t *)ethhdr) + SIZEOF_ETH_HDR);
    if (vlanid) {
      *vlanid = vlan->prio_vid;
    }
    return (0);
  }
  
  return (-1);
}

/*********************************************************************************************************
** 函数名称: netdev_pbuf_vlan_proto
** 功能描述: 获取指定的以太网数据帧中的 VLAN 字段中的 VLAN PROTO 字段数据内容
** 输	 入: p - 指定的以太网数据帧
** 输	 出: 1 - 包含 VLAN 字段数据
**         : 0 - 不包含 VLAN 字段数据
**         : vlanproto - 获取到的 VLAN PROTO 字段数据内容
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
int netdev_pbuf_vlan_proto (struct pbuf *p, UINT16 *vlanproto)
{
  struct eth_hdr *ethhdr = (struct eth_hdr *)((u8_t *)p->payload - ETH_PAD_SIZE);

  if ((ethhdr->type == PP_HTONS(ETHTYPE_VLAN)) && (p->len >= ETH_HLEN + 4)) {
    struct eth_vlan_hdr *vlan = (struct eth_vlan_hdr *)(((u8_t *)ethhdr) + SIZEOF_ETH_HDR);
    if (vlanproto) {
      *vlanproto = vlan->tpid;
    }
    return (0);
  }
  
  return (-1);
}

#if LW_CFG_NET_DEV_PROTO_ANALYSIS > 0

/* netdev buffer get ethernet & vlan header */
/*********************************************************************************************************
** 函数名称: netdev_pbuf_ethhdr
** 功能描述: 获取指定的以太网数据帧的帧头地址以及帧头字节长度
** 输	 入: p - 指定的以太网数据帧
** 输	 出: ethhdr - 获取到的以太网帧头地址
**         : hdrlen - 获取到的以太网帧头字节长度
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct eth_hdr *netdev_pbuf_ethhdr (struct pbuf *p, int *hdrlen)
{
  struct eth_hdr *ethhdr = (struct eth_hdr *)((u8_t *)p->payload - ETH_PAD_SIZE);
  
  if (hdrlen) {
    *hdrlen = ETH_HLEN;
  }
  
  return (ethhdr);
}

/*********************************************************************************************************
** 函数名称: netdev_pbuf_vlanhdr
** 功能描述: 获取指定的以太网数据帧的 VLAN 头地址以及 VLAN 头字节长度
** 输	 入: p - 指定的以太网数据帧
** 输	 出: vlan - 获取到的 VLAN 头地址
**         : hdrlen - 获取到的 VLAN 头字节长度
**         : NULL - 当前帧没有 VLAN 头信息
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct eth_vlan_hdr *netdev_pbuf_vlanhdr (struct pbuf *p, int *hdrlen)
{
  struct eth_hdr *ethhdr = (struct eth_hdr *)((u8_t *)p->payload - ETH_PAD_SIZE);

  if (ethhdr->type == PP_HTONS(ETHTYPE_VLAN) && (p->len >= ETH_HLEN + 4)) {
    struct eth_vlan_hdr *vlan = (struct eth_vlan_hdr *)(((u8_t *)ethhdr) + SIZEOF_ETH_HDR);
    if (hdrlen) {
      *hdrlen = 4;
    }
    return (vlan);
  }
  
  return (NULL);
}

/* netdev buffer get proto header */
/*********************************************************************************************************
** 函数名称: netdev_pbuf_iphdr
** 功能描述: 获取指定的以太网数据帧的 IP 头地址以及 IP 头字节长度
** 输	 入: p - 指定的以太网数据帧
**         : offset - IP 协议头在指定以太网数据帧中的偏移量
** 输	 出: iphdr - 获取到的 IP 头地址
**         : hdrlen - 获取到的 IP 头字节长度
**         : NULL - 获取失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct ip_hdr *netdev_pbuf_iphdr (struct pbuf *p, int offset, int *hdrlen)
{
  struct pbuf *q;
  u16_t out_offset;

  /* 从指定的 pbuf/pbuf chain 中的负载空间中，找到包含指定偏移量的 pbuf 以及偏移量的余数部分
     所谓的偏移量余数部分指的是通过我们指定的偏移量找到 pbuf 之后，剩余的在 pbuf 内的偏移量 */
  q = pbuf_skip(p, (u16_t)offset, &out_offset);
  if (!q) {
    return (NULL);
  }
  
  if (q->len >= (u16_t)out_offset + IP_HLEN) {
    struct ip_hdr *iphdr = (struct ip_hdr *)((u8_t *)q->payload + out_offset);
    if (hdrlen) {
      *hdrlen = IPH_HL(iphdr) << 2;
    }
    return (iphdr);
  }
  
  return (NULL);
}

struct ip6_hdr *netdev_pbuf_ip6hdr (struct pbuf *p, int offset, int *hdrlen, int *tothdrlen, int *tproto)
{
  struct pbuf *q;
  u16_t out_offset;
  
  q = pbuf_skip(p, (u16_t)offset, &out_offset);
  if (!q) {
    return (NULL);
  }
  
  if (q->len >= (u16_t)out_offset + IP6_HLEN) {
    struct ip6_hdr *ip6hdr = (struct ip6_hdr *)((u8_t *)q->payload + offset);
    if (hdrlen) {
      *hdrlen = IP6_HLEN;
    }
    if (tothdrlen) {
      u8_t *hdr;
      int hlen, nexth;
    
      *tothdrlen = IP6_HLEN;
      hdr = (u8_t *)ip6hdr + IP6_HLEN;
      nexth = IP6H_NEXTH(ip6hdr);
      while (nexth != IP6_NEXTH_NONE) {
        switch (nexth) {
        
        case IP6_NEXTH_HOPBYHOP:
        case IP6_NEXTH_DESTOPTS:
        case IP6_NEXTH_ROUTING:
          nexth = *hdr;
          hlen = 8 * (1 + *(hdr + 1));
          (*tothdrlen) += hlen;
          hdr += hlen;
          break;
        
        case IP6_NEXTH_FRAGMENT:
          nexth = *hdr;
          hlen = 8;
          (*tothdrlen) += hlen;
          hdr += hlen;
          break;
          
        default:
          goto out;
          break;
        }
      }
out:
      if (tproto) {
        *tproto = nexth;
      }
    }
    return (ip6hdr);
  }
  
  return (NULL);
}

/*********************************************************************************************************
** 函数名称: netdev_pbuf_tcphdr
** 功能描述: 获取指定的以太网数据帧的 TCP 头地址以及 TCP 头字节长度
** 输	 入: p - 指定的以太网数据帧
**         : offset - TCP 协议头在指定以太网数据帧中的偏移量
** 输	 出: iphdr - 获取到的 TCP 头地址
**         : hdrlen - 获取到的 TCP 头字节长度
**         : NULL - 获取失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct tcp_hdr *netdev_pbuf_tcphdr (struct pbuf *p, int offset, int *hdrlen)
{
  struct pbuf *q;
  u16_t out_offset;

  q = pbuf_skip(p, (u16_t)offset, &out_offset);
  if (!q) {
    return (NULL);
  }
  
  if (q->len >= (u16_t)out_offset + TCP_HLEN) {
    struct tcp_hdr *tcphdr = (struct tcp_hdr *)((u8_t *)q->payload + out_offset);
    if (hdrlen) {
      *hdrlen = TCPH_HDRLEN(tcphdr) << 2;
    }
    return (tcphdr);
  }
  
  return (NULL);
}

/*********************************************************************************************************
** 函数名称: netdev_pbuf_udphdr
** 功能描述: 获取指定的以太网数据帧的 UDP 头地址以及 UDP 头字节长度
** 输	 入: p - 指定的以太网数据帧
**         : offset - UDP 协议头在指定以太网数据帧中的偏移量
** 输	 出: iphdr - 获取到的 UDP 头地址
**         : hdrlen - 获取到的 UDP 头字节长度
**         : NULL - 获取失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct udp_hdr *netdev_pbuf_udphdr (struct pbuf *p, int offset, int *hdrlen)
{
  struct pbuf *q;
  u16_t out_offset;

  q = pbuf_skip(p, (u16_t)offset, &out_offset);
  if (!q) {
    return (NULL);
  }
  
  if (q->len >= (u16_t)out_offset + UDP_HLEN) {
    struct udp_hdr *udphdr = (struct udp_hdr *)((u8_t *)q->payload + out_offset);
    if (hdrlen) {
      *hdrlen = UDP_HLEN;
    }
    return (udphdr);
  }
  
  return (NULL);
}

#endif /* LW_CFG_NET_DEV_PROTO_ANALYSIS */
/*
 * end
 */
