/**
 * @file
 * lwIP network interface abstraction
 *
 * @defgroup netif Network interface (NETIF)
 * @ingroup callbackstyle_api
 *
 * @defgroup netif_ip4 IPv4 address handling
 * @ingroup netif
 *
 * @defgroup netif_ip6 IPv6 address handling
 * @ingroup netif
 *
 * @defgroup netif_cd Client data handling
 * Store data (void*) on a netif for application usage.
 * @see @ref LWIP_NUM_NETIF_CLIENT_DATA
 * @ingroup netif
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
 */

#include "lwip/opt.h"

#include <string.h> /* memset */
#include <stdlib.h> /* atoi */

#include "lwip/def.h"
#include "lwip/ip_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/udp.h"
#include "lwip/priv/raw_priv.h"
#include "lwip/snmp.h"
#include "lwip/igmp.h"
#include "lwip/etharp.h"
#include "lwip/stats.h"
#include "lwip/sys.h"
#include "lwip/ip.h"
#if ENABLE_LOOPBACK
#if LWIP_NETIF_LOOPBACK_MULTITHREADING
#include "lwip/tcpip.h"
#endif /* LWIP_NETIF_LOOPBACK_MULTITHREADING */
#endif /* ENABLE_LOOPBACK */

#include "netif/ethernet.h"

#if LWIP_AUTOIP
#include "lwip/autoip.h"
#endif /* LWIP_AUTOIP */
#if LWIP_DHCP
#include "lwip/dhcp.h"
#endif /* LWIP_DHCP */
#if LWIP_IPV6_DHCP6
#include "lwip/dhcp6.h"
#endif /* LWIP_IPV6_DHCP6 */
#if LWIP_IPV6_MLD
#include "lwip/mld6.h"
#endif /* LWIP_IPV6_MLD */
#if LWIP_IPV6
#include "lwip/nd6.h"
#endif

/* 获取指定网路接口的 status_callback 函数指针 */
#if LWIP_NETIF_STATUS_CALLBACK
#define NETIF_STATUS_CALLBACK(n) do{ if (n->status_callback) { (n->status_callback)(n); }}while(0)
#else
#define NETIF_STATUS_CALLBACK(n)
#endif /* LWIP_NETIF_STATUS_CALLBACK */

/* 获取指定网路接口的 link_callback 函数指针 */
#if LWIP_NETIF_LINK_CALLBACK
#define NETIF_LINK_CALLBACK(n) do{ if (n->link_callback) { (n->link_callback)(n); }}while(0)
#else
#define NETIF_LINK_CALLBACK(n)
#endif /* LWIP_NETIF_LINK_CALLBACK */

#if LWIP_NETIF_EXT_STATUS_CALLBACK
static netif_ext_callback_t *ext_callback;
#endif

#if !LWIP_SINGLE_NETIF
/* 通过链表的方式记录当前系统中所有网络接口（非回环网路接口）*/
struct netif *netif_list;
#endif /* !LWIP_SINGLE_NETIF */

/* 记录当前系统默认使用的网络接口指针（非回环网路接口）*/
struct netif *netif_default;

#define netif_index_to_num(index)   ((index) - 1)

/* 全局变量，表示当前系统内已经添加的网络接口个数，或者为下一个添加到网络接口分配的网络接口号 */
static u8_t netif_num;

#if LWIP_NUM_NETIF_CLIENT_DATA > 0
/* 全局变量，表示当前系统内可以分配的 client id，在每次分配后，都会自动加 1，指向下一个空闲的 client id 号 */
static u8_t netif_client_id;
#endif

#define NETIF_REPORT_TYPE_IPV4  0x01
#define NETIF_REPORT_TYPE_IPV6  0x02
static void netif_issue_reports(struct netif *netif, u8_t report_type);

#if LWIP_IPV6
static err_t netif_null_output_ip6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr);
#endif /* LWIP_IPV6 */
#if LWIP_IPV4
static err_t netif_null_output_ip4(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr);
#endif /* LWIP_IPV4 */

/* 如果系统支持回环网络接口功能，则定义和回环网络相关的数据结构及功能函数 */
#if LWIP_HAVE_LOOPIF

#if LWIP_IPV4
static err_t netif_loop_output_ipv4(struct netif *netif, struct pbuf *p, const ip4_addr_t *addr);
#endif
#if LWIP_IPV6
static err_t netif_loop_output_ipv6(struct netif *netif, struct pbuf *p, const ip6_addr_t *addr);
#endif

/* 表示回环网络接口结构 */
static struct netif loop_netif;

/**
 * Initialize a lwip network interface structure for a loopback interface
 *
 * @param netif the lwip network interface structure for this loopif
 * @return ERR_OK if the loopif is initialized
 *         ERR_MEM if private data couldn't be allocated
 */
/*********************************************************************************************************
** 函数名称: netif_loopif_init
** 功能描述: 初始化指定的回环网络接口指针
** 输	 入: netif - 需要初始化的回环网络接口指针
** 输	 出: ERR_OK - 初始化完成
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
netif_loopif_init(struct netif *netif)
{
  LWIP_ASSERT("netif_loopif_init: invalid netif", netif != NULL);

  /* initialize the snmp variables and counters inside the struct netif
   * ifSpeed: no assumption can be made!
   */
  /* 初始化 MIB2 管理信息库（manage information base）相关结构信息 */
  MIB2_INIT_NETIF(netif, snmp_ifType_softwareLoopback, 0);

  /* 设置回环网络接口缩写名 */
  netif->name[0] = 'l';
  netif->name[1] = 'o';
  
#if LWIP_IPV4
  netif->output = netif_loop_output_ipv4;
#endif
#if LWIP_IPV6
  netif->output_ip6 = netif_loop_output_ipv6;
#endif

/* 如果本地回环网络支持多播功能，则设置网络接口的 NETIF_FLAG_IGMP 标志 */
#if LWIP_LOOPIF_MULTICAST
  netif_set_flags(netif, NETIF_FLAG_IGMP);
#endif

  NETIF_SET_CHECKSUM_CTRL(netif, NETIF_CHECKSUM_DISABLE_ALL);
  return ERR_OK;
}
#endif /* LWIP_HAVE_LOOPIF */

/*********************************************************************************************************
** 函数名称: netif_init
** 功能描述: 初始化并创建一个本地回环网络接口
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_init(void)
{
#if LWIP_HAVE_LOOPIF
#if LWIP_IPV4
/* 初始化回环网络相关变量 */
#define LOOPIF_ADDRINIT &loop_ipaddr, &loop_netmask, &loop_gw,
  ip4_addr_t loop_ipaddr, loop_netmask, loop_gw;
  IP4_ADDR(&loop_gw, 127, 0, 0, 1);
  IP4_ADDR(&loop_ipaddr, 127, 0, 0, 1);
  IP4_ADDR(&loop_netmask, 255, 0, 0, 0);
#else /* LWIP_IPV4 */
#define LOOPIF_ADDRINIT
#endif /* LWIP_IPV4 */

#if NO_SYS
  netif_add(&loop_netif, LOOPIF_ADDRINIT NULL, netif_loopif_init, ip_input);
#else  /* NO_SYS */
  netif_add(&loop_netif, LOOPIF_ADDRINIT NULL, netif_loopif_init, tcpip_input);
#endif /* NO_SYS */

#if LWIP_IPV6
  IP_ADDR6_HOST(loop_netif.ip6_addr, 0, 0, 0, 0x00000001UL);
  loop_netif.ip6_addr_state[0] = IP6_ADDR_VALID;
#endif /* LWIP_IPV6 */

  netif_set_link_up(&loop_netif);
  netif_set_up(&loop_netif);

#endif /* LWIP_HAVE_LOOPIF */
}

/**
 * @ingroup lwip_nosys
 * Forwards a received packet for input processing with
 * ethernet_input() or ip_input() depending on netif flags.
 * Don't call directly, pass to netif_add() and call
 * netif->input().
 * Only works if the netif driver correctly sets
 * NETIF_FLAG_ETHARP and/or NETIF_FLAG_ETHERNET flag!
 */
/*********************************************************************************************************
** 函数名称: netif_input
** 功能描述: 当网卡驱动接收到一个数据帧的时候，通过这个函数，把接收到的数据包传到协议栈上层来处理
** 输	 入: p - 接收到的数据
**         : inp - 接收到数据的网络接口指针
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
netif_input(struct pbuf *p, struct netif *inp)
{
  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ASSERT("netif_input: invalid pbuf", p != NULL);
  LWIP_ASSERT("netif_input: invalid netif", inp != NULL);

#if LWIP_ETHERNET
  if (inp->flags & (NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET)) {
    return ethernet_input(p, inp);
  } else
#endif /* LWIP_ETHERNET */
    return ip_input(p, inp);
}

/**
 * @ingroup netif
 * Add a network interface to the list of lwIP netifs.
 *
 * Same as @ref netif_add but without IPv4 addresses
 */
/*********************************************************************************************************
** 函数名称: netif_add_noaddr
** 功能描述: 添加一个使用 ANY 地址信息的网络接口
** 输	 入: netif - 要添加的网络接口指针
**		   : state - 由设备驱动指定的，存储在网络接口中的私有数据
**         : init - 初始化网络接口的函数指针
**         : input - 把网卡接收的以太网数据帧上传给协议栈的函数指针
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct netif *
netif_add_noaddr(struct netif *netif, void *state, netif_init_fn init, netif_input_fn input)
{
  return netif_add(netif,
#if LWIP_IPV4
                   NULL, NULL, NULL,
#endif /* LWIP_IPV4*/
                   state, init, input);
}

/**
 * @ingroup netif
 * Add a network interface to the list of lwIP netifs.
 *
 * @param netif a pre-allocated netif structure
 * @param ipaddr IP address for the new netif
 * @param netmask network mask for the new netif
 * @param gw default gateway IP address for the new netif
 * @param state opaque data passed to the new netif
 * @param init callback function that initializes the interface
 * @param input callback function that is called to pass
 * ingress packets up in the protocol layer stack.\n
 * It is recommended to use a function that passes the input directly
 * to the stack (netif_input(), NO_SYS=1 mode) or via sending a
 * message to TCPIP thread (tcpip_input(), NO_SYS=0 mode).\n
 * These functions use netif flags NETIF_FLAG_ETHARP and NETIF_FLAG_ETHERNET
 * to decide whether to forward to ethernet_input() or ip_input().
 * In other words, the functions only work when the netif
 * driver is implemented correctly!\n
 * Most members of struct netif should be be initialized by the
 * netif init function = netif driver (init parameter of this function).\n
 * IPv6: Don't forget to call netif_create_ip6_linklocal_address() after
 * setting the MAC address in struct netif.hwaddr
 * (IPv6 requires a link-local address).
 *
 * @return netif, or NULL if failed.
 */
/*********************************************************************************************************
** 函数名称: netif_add
** 功能描述: 添加一个指定地址信息的网络接口到当前协议栈中，并通知相关单元模块进行数据同步，然后调用
**         : 用户指定的网络接口初始化函数
** 输	 入: netif - 要添加的网络接口指针
**		   : ipaddr - 新的网络接口的 IPv4 地址
**		   : netmask - 新的网络接口的网络掩码 IPv4 地址
**		   : gw - 新的网络接口的网关 IPv4 地址
**		   : state - 由设备驱动指定的，存储在网络接口中的私有数据
**		   : init - 初始化网络接口的函数指针
**		   : input - 把网卡接收的以太网数据帧上传给协议栈的函数指针
** 输	 出: netif - 添加的网络接口指针
**         : NULL - 添加失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct netif *
netif_add(struct netif *netif,
#if LWIP_IPV4
          const ip4_addr_t *ipaddr, const ip4_addr_t *netmask, const ip4_addr_t *gw,
#endif /* LWIP_IPV4 */
          void *state, netif_init_fn init, netif_input_fn input)
{
#if LWIP_IPV6
  s8_t i;
#endif

  LWIP_ASSERT_CORE_LOCKED();

#if LWIP_SINGLE_NETIF
  if (netif_default != NULL) {
    LWIP_ASSERT("single netif already set", 0);
    return NULL;
  }
#endif

  LWIP_ERROR("netif_add: invalid netif", netif != NULL, return NULL);
  LWIP_ERROR("netif_add: No init function given", init != NULL, return NULL);

/* 设置默认的 IPv4 相关地址信息 */
#if LWIP_IPV4
  /* 如果在调用函数时没有设置 IPv4 相关地址信息，则默认设置为 ANY 地址 */
  if (ipaddr == NULL) {
    ipaddr = ip_2_ip4(IP4_ADDR_ANY);
  }
  if (netmask == NULL) {
    netmask = ip_2_ip4(IP4_ADDR_ANY);
  }
  if (gw == NULL) {
    gw = ip_2_ip4(IP4_ADDR_ANY);
  }

  /* reset new interface configuration state */
  ip_addr_set_zero_ip4(&netif->ip_addr);
  ip_addr_set_zero_ip4(&netif->netmask);
  ip_addr_set_zero_ip4(&netif->gw);
  netif->output = netif_null_output_ip4;
#endif /* LWIP_IPV4 */

/* 设置默认的 IPv6 相关地址信息 */
#if LWIP_IPV6
  for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
    ip_addr_set_zero_ip6(&netif->ip6_addr[i]);
    netif->ip6_addr_state[i] = IP6_ADDR_INVALID;
#if LWIP_IPV6_ADDRESS_LIFETIMES
    netif->ip6_addr_valid_life[i] = IP6_ADDR_LIFE_STATIC;
    netif->ip6_addr_pref_life[i] = IP6_ADDR_LIFE_STATIC;
#endif /* LWIP_IPV6_ADDRESS_LIFETIMES */
  }
  netif->output_ip6 = netif_null_output_ip6;
#endif /* LWIP_IPV6 */

  NETIF_SET_CHECKSUM_CTRL(netif, NETIF_CHECKSUM_ENABLE_ALL);
  netif->mtu = 0;
  netif->flags = 0;
#ifdef netif_get_client_data
  memset(netif->client_data, 0, sizeof(netif->client_data));
#endif /* LWIP_NUM_NETIF_CLIENT_DATA */

#if LWIP_IPV6
#if LWIP_IPV6_AUTOCONFIG
  /* IPv6 address autoconfiguration not enabled by default */
  /* IPv6 自动分配地址功能默认不开启 */
  netif->ip6_autoconfig_enabled = 0;
#endif /* LWIP_IPV6_AUTOCONFIG */
  nd6_restart_netif(netif);
#endif /* LWIP_IPV6 */

#if LWIP_NETIF_STATUS_CALLBACK
  netif->status_callback = NULL;
#endif /* LWIP_NETIF_STATUS_CALLBACK */

#if LWIP_NETIF_LINK_CALLBACK
  netif->link_callback = NULL;
#endif /* LWIP_NETIF_LINK_CALLBACK */

#if LWIP_IGMP
  netif->igmp_mac_filter = NULL;
#endif /* LWIP_IGMP */

#if LWIP_IPV6 && LWIP_IPV6_MLD
  netif->mld_mac_filter = NULL;
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */

#if ENABLE_LOOPBACK
  netif->loop_first = NULL;
  netif->loop_last = NULL;
#endif /* ENABLE_LOOPBACK */

  /* remember netif specific state information data */
  netif->state = state;
  netif->num = netif_num;
  netif->input = input;

  NETIF_RESET_HINTS(netif);
#if ENABLE_LOOPBACK && LWIP_LOOPBACK_MAX_PBUFS
  netif->loop_cnt_current = 0;
#endif /* ENABLE_LOOPBACK && LWIP_LOOPBACK_MAX_PBUFS */

#if LWIP_IPV4
  /* 设置指定网络接口的 IPv4 地址信息，并通知相关单元模块进行数据同步 */
  netif_set_addr(netif, ipaddr, netmask, gw);
#endif /* LWIP_IPV4 */

  /* call user specified initialization function for netif */
  /* 调用用户指定的网络接口初始化函数 */
  if (init(netif) != ERR_OK) {
    return NULL;
  }
  
#if LWIP_IPV6 && LWIP_ND6_ALLOW_RA_UPDATES
  /* Initialize the MTU for IPv6 to the one set by the netif driver.
     This can be updated later by RA. */
  netif->mtu6 = netif->mtu;
#endif /* LWIP_IPV6 && LWIP_ND6_ALLOW_RA_UPDATES */

#if !LWIP_SINGLE_NETIF
  /* Assign a unique netif number in the range [0..254], so that (num+1) can
     serve as an interface index that fits in a u8_t.
     We assume that the new netif has not yet been added to the list here.
     This algorithm is O(n^2), but that should be OK for lwIP.
     */
  {
    struct netif *netif2;
    int num_netifs;
    do {
      if (netif->num == 255) {
        netif->num = 0;
      }
      num_netifs = 0;
      for (netif2 = netif_list; netif2 != NULL; netif2 = netif2->next) {
        LWIP_ASSERT("netif already added", netif2 != netif);
        num_netifs++;
        LWIP_ASSERT("too many netifs, max. supported number is 255", num_netifs <= 255);
        if (netif2->num == netif->num) {
          netif->num++;
          break;
        }
      }
    } while (netif2 != NULL);
  }

  /* 表示当前系统内已经添加的网络接口个数，或者为下一个添加到网络接口分配的网络接口号 */
  if (netif->num == 254) {
    netif_num = 0;
  } else {
    netif_num = (u8_t)(netif->num + 1);
  }

  /* add this netif to the list */
  /* 把新的网络接口添加到全局网络接口链表中 */
  netif->next = netif_list;
  netif_list = netif;
  
#endif /* "LWIP_SINGLE_NETIF */
  mib2_netif_added(netif);

#if LWIP_IGMP
  /* start IGMP processing */
  if (netif->flags & NETIF_FLAG_IGMP) {
  	/* 启动 IGMP 进程 */
    igmp_start(netif);
  }
#endif /* LWIP_IGMP */

  LWIP_DEBUGF(NETIF_DEBUG, ("netif: added interface %c%c IP",
                            netif->name[0], netif->name[1]));
#if LWIP_IPV4
  LWIP_DEBUGF(NETIF_DEBUG, (" addr "));
  ip4_addr_debug_print(NETIF_DEBUG, ipaddr);
  LWIP_DEBUGF(NETIF_DEBUG, (" netmask "));
  ip4_addr_debug_print(NETIF_DEBUG, netmask);
  LWIP_DEBUGF(NETIF_DEBUG, (" gw "));
  ip4_addr_debug_print(NETIF_DEBUG, gw);
#endif /* LWIP_IPV4 */
  LWIP_DEBUGF(NETIF_DEBUG, ("\n"));

  /* 分别向当前系统 ext_callback 中的每个回调函数发送一个指定的事件 */
  netif_invoke_ext_callback(netif, LWIP_NSC_NETIF_ADDED, NULL);

  return netif;
}

/*********************************************************************************************************
** 函数名称: netif_do_ip_addr_changed
** 功能描述: 在网络地址信息发生变化时，调用这个函数通知协议栈中其他相关协议层变化前后的地址信息
**         : 这样其他的协议层可以根据变化的地址信息做相应处理
** 输     入: old_addr - 旧的	IPv4 地址
**		   : new_addr - 新的 IPv4 地址
** 输     出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
netif_do_ip_addr_changed(const ip_addr_t *old_addr, const ip_addr_t *new_addr)
{
#if LWIP_TCP
  tcp_netif_ip_addr_changed(old_addr, new_addr);
#endif /* LWIP_TCP */

#if LWIP_UDP
  udp_netif_ip_addr_changed(old_addr, new_addr);
#endif /* LWIP_UDP */

#if LWIP_RAW
  raw_netif_ip_addr_changed(old_addr, new_addr);
#endif /* LWIP_RAW */
}

#if LWIP_IPV4
/*********************************************************************************************************
** 函数名称: netif_do_set_ipaddr
** 功能描述: 设置指定网络接口的 IPv4 地址信息，并通知相关单元同步旧的地址信息到新的地址信息
** 输	 入: netif - 要设置地址的网络接口指针
**		   : ipaddr - 新的 IPv4 地址
**		   : old_addr - 旧的    IPv4 地址
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int
netif_do_set_ipaddr(struct netif *netif, const ip4_addr_t *ipaddr, ip_addr_t *old_addr)
{
  LWIP_ASSERT("invalid pointer", ipaddr != NULL);
  LWIP_ASSERT("invalid pointer", old_addr != NULL);

  /* address is actually being changed? */
  /* 如果新设置的 IPv4 地址和之前的不一样，则执行相关操作 */
  if (ip4_addr_cmp(ipaddr, netif_ip4_addr(netif)) == 0) {
    ip_addr_t new_addr;
    *ip_2_ip4(&new_addr) = *ipaddr;
    IP_SET_TYPE_VAL(new_addr, IPADDR_TYPE_V4);

	/* 把旧的 IPv4 地址信息复制到 old_addr 中 */
    ip_addr_copy(*old_addr, *netif_ip_addr4(netif));

    LWIP_DEBUGF(NETIF_DEBUG | LWIP_DBG_STATE, ("netif_set_ipaddr: netif address being changed\n"));

	/* 通知协议栈中其他协议层变化的地址信息 */
    netif_do_ip_addr_changed(old_addr, &new_addr);

    /* 删除旧的 IPv4 地址相关 MIB2 信息 */
    mib2_remove_ip4(netif);
    mib2_remove_route_ip4(0, netif);
	
    /* set new IP address to netif */
    ip4_addr_set(ip_2_ip4(&netif->ip_addr), ipaddr);
    IP_SET_TYPE_VAL(netif->ip_addr, IPADDR_TYPE_V4);
	
    /* 添加新的 IPv4 地址相关 MIB2 信息 */
    mib2_add_ip4(netif);
    mib2_add_route_ip4(0, netif);

	/* 向协议栈其他相关模块或者和当前网络接口相关的设备节点发送一个事件
	 * 使其同步旧的数据到新的数据 */
    netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV4);

    /* 执行指定网路接口的 status_callback 函数 */
    NETIF_STATUS_CALLBACK(netif);
    return 1; /* address changed */
  }
  return 0; /* address unchanged */
}

/**
 * @ingroup netif_ip4
 * Change the IP address of a network interface
 *
 * @param netif the network interface to change
 * @param ipaddr the new IP address
 *
 * @note call netif_set_addr() if you also want to change netmask and
 * default gateway
 */
/*********************************************************************************************************
** 函数名称: netif_set_ipaddr
** 功能描述: 设置指定网络接口的 IPv4 地址信息，并通知相关单元同步旧的地址信息到新的地址信息
** 注     释: 这个函数支持“用户自定义”的扩展回调（钩子）函数功能
** 输	 入: netif - 要设置地址的网络接口指针
**		   : ipaddr - 新的 IPv4 地址
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_set_ipaddr(struct netif *netif, const ip4_addr_t *ipaddr)
{
  ip_addr_t old_addr;

  LWIP_ERROR("netif_set_ipaddr: invalid netif", netif != NULL, return);

  /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
  if (ipaddr == NULL) {
    ipaddr = IP4_ADDR_ANY4;
  }

  LWIP_ASSERT_CORE_LOCKED();

  if (netif_do_set_ipaddr(netif, ipaddr, &old_addr)) {
  	/* 只有在地址真的发生改变的时候才会通过扩展回调函数指针发送事件 */
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    netif_ext_callback_args_t args;
    args.ipv4_changed.old_address = &old_addr;
    netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_ADDRESS_CHANGED, &args);
#endif
  }
}

/*********************************************************************************************************
** 函数名称: netif_do_set_netmask
** 功能描述: 设置指定网络接口的网络地址掩码 IPv4 信息，并更新相关 MIB2 信息库数据
** 输	 入: netif - 要设置网络掩码的网络接口指针
**		   : netmask - 新的网络掩码
**		   : old_nm - 旧的网络掩码
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int
netif_do_set_netmask(struct netif *netif, const ip4_addr_t *netmask, ip_addr_t *old_nm)
{
  /* address is actually being changed? */
  if (ip4_addr_cmp(netmask, netif_ip4_netmask(netif)) == 0) {
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    LWIP_ASSERT("invalid pointer", old_nm != NULL);
    ip_addr_copy(*old_nm, *netif_ip_netmask4(netif));
#else
    LWIP_UNUSED_ARG(old_nm);
#endif
    mib2_remove_route_ip4(0, netif);
    /* set new netmask to netif */
    ip4_addr_set(ip_2_ip4(&netif->netmask), netmask);
    IP_SET_TYPE_VAL(netif->netmask, IPADDR_TYPE_V4);
    mib2_add_route_ip4(0, netif);
    LWIP_DEBUGF(NETIF_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("netif: netmask of interface %c%c set to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                netif->name[0], netif->name[1],
                ip4_addr1_16(netif_ip4_netmask(netif)),
                ip4_addr2_16(netif_ip4_netmask(netif)),
                ip4_addr3_16(netif_ip4_netmask(netif)),
                ip4_addr4_16(netif_ip4_netmask(netif))));
    return 1; /* netmask changed */
  }
  return 0; /* netmask unchanged */
}

/**
 * @ingroup netif_ip4
 * Change the netmask of a network interface
 *
 * @param netif the network interface to change
 * @param netmask the new netmask
 *
 * @note call netif_set_addr() if you also want to change ip address and
 * default gateway
 */
/*********************************************************************************************************
** 函数名称: netif_set_netmask
** 功能描述: 设置指定网络接口的网络地址掩码 IPv4 信息，并同步旧的地址信息到新的地址信息
** 注     释: 这个函数支持“用户自定义”的扩展回调（钩子）函数功能
** 输	 入: netif - 要设置网络地址掩码的网络接口指针
**		   : netmask - 新的网络掩码
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_set_netmask(struct netif *netif, const ip4_addr_t *netmask)
{
#if LWIP_NETIF_EXT_STATUS_CALLBACK
  ip_addr_t old_nm_val;
  ip_addr_t *old_nm = &old_nm_val;
#else
  ip_addr_t *old_nm = NULL;
#endif
  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("netif_set_netmask: invalid netif", netif != NULL, return);

  /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
  if (netmask == NULL) {
    netmask = IP4_ADDR_ANY4;
  }

  if (netif_do_set_netmask(netif, netmask, old_nm)) {
  	/* 只有在网络掩码真的发生改变的时候才会通过扩展回调函数指针发送事件 */
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    netif_ext_callback_args_t args;
    args.ipv4_changed.old_netmask = old_nm;
    netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_NETMASK_CHANGED, &args);
#endif
  }
}

/*********************************************************************************************************
** 函数名称: netif_do_set_gw
** 功能描述: 设置指定网络接口的网关地址 IPv4 信息
** 输	 入: netif - 要设置网关地址的网络接口指针
**		   : gw - 新的网关地址
**		   : old_gw - 旧的网关地址
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static int
netif_do_set_gw(struct netif *netif, const ip4_addr_t *gw, ip_addr_t *old_gw)
{
  /* address is actually being changed? */
  if (ip4_addr_cmp(gw, netif_ip4_gw(netif)) == 0) {
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    LWIP_ASSERT("invalid pointer", old_gw != NULL);
    ip_addr_copy(*old_gw, *netif_ip_gw4(netif));
#else
    LWIP_UNUSED_ARG(old_gw);
#endif

    ip4_addr_set(ip_2_ip4(&netif->gw), gw);
    IP_SET_TYPE_VAL(netif->gw, IPADDR_TYPE_V4);
    LWIP_DEBUGF(NETIF_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("netif: GW address of interface %c%c set to %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n",
                netif->name[0], netif->name[1],
                ip4_addr1_16(netif_ip4_gw(netif)),
                ip4_addr2_16(netif_ip4_gw(netif)),
                ip4_addr3_16(netif_ip4_gw(netif)),
                ip4_addr4_16(netif_ip4_gw(netif))));
    return 1; /* gateway changed */
  }
  return 0; /* gateway unchanged */
}

/**
 * @ingroup netif_ip4
 * Change the default gateway for a network interface
 *
 * @param netif the network interface to change
 * @param gw the new default gateway
 *
 * @note call netif_set_addr() if you also want to change ip address and netmask
 */
/*********************************************************************************************************
** 函数名称: netif_set_gw
** 功能描述: 设置指定网络接口的网关地址 IPv4 信息
** 注	 释: 这个函数支持“用户自定义”的扩展回调（钩子）函数功能
** 输	 入: netif - 要设置网关地址的网络接口指针
**		   : ipaddr - 新的网关地址
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_set_gw(struct netif *netif, const ip4_addr_t *gw)
{
#if LWIP_NETIF_EXT_STATUS_CALLBACK
  ip_addr_t old_gw_val;
  ip_addr_t *old_gw = &old_gw_val;
#else
  ip_addr_t *old_gw = NULL;
#endif
  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("netif_set_gw: invalid netif", netif != NULL, return);

  /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
  if (gw == NULL) {
    gw = IP4_ADDR_ANY4;
  }

  if (netif_do_set_gw(netif, gw, old_gw)) {
  	/* 只有在网关地址真的发生改变的时候才会通过扩展回调函数指针发送事件 */
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    netif_ext_callback_args_t args;
    args.ipv4_changed.old_gw = old_gw;
    netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_GATEWAY_CHANGED, &args);
#endif
  }
}

/**
 * @ingroup netif_ip4
 * Change IP address configuration for a network interface (including netmask
 * and default gateway).
 *
 * @param netif the network interface to change
 * @param ipaddr the new IP address
 * @param netmask the new netmask
 * @param gw the new default gateway
 */
/*********************************************************************************************************
** 函数名称: netif_set_addr
** 功能描述: 设置指定网络接口的 IPv4 地址信息，并通知相关单元模块进行数据同步
** 输	 入: netif - 要设置地址的网络接口指针
**		   : ipaddr - 要设置的 IPv4 地址
**		   : netmask - 要设置的网络掩码 IPv4 地址
**		   : gw - 要设置的网关 IPv4 地址
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_set_addr(struct netif *netif, const ip4_addr_t *ipaddr, const ip4_addr_t *netmask,
               const ip4_addr_t *gw)
{
#if LWIP_NETIF_EXT_STATUS_CALLBACK
  netif_nsc_reason_t change_reason = LWIP_NSC_NONE;
  netif_ext_callback_args_t cb_args;
  ip_addr_t old_nm_val;
  ip_addr_t old_gw_val;
  ip_addr_t *old_nm = &old_nm_val;
  ip_addr_t *old_gw = &old_gw_val;
#else
  ip_addr_t *old_nm = NULL;
  ip_addr_t *old_gw = NULL;
#endif
  ip_addr_t old_addr;
  int remove;

  LWIP_ASSERT_CORE_LOCKED();

  /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
  /* 如果没指定 IPv4 地址，则设置为 IPv4 ANY */
  if (ipaddr == NULL) {
    ipaddr = IP4_ADDR_ANY4;
  }
  if (netmask == NULL) {
    netmask = IP4_ADDR_ANY4;
  }
  if (gw == NULL) {
    gw = IP4_ADDR_ANY4;
  }

  remove = ip4_addr_isany(ipaddr);
  if (remove) {
    /* when removing an address, we have to remove it *before* changing netmask/gw
       to ensure that tcp RST segment can be sent correctly */
    /* 设置指定网络接口的 IPv4 地址信息，并通知相关单元同步旧的地址信息到新的地址信息 */
    if (netif_do_set_ipaddr(netif, ipaddr, &old_addr)) {
#if LWIP_NETIF_EXT_STATUS_CALLBACK
      change_reason |= LWIP_NSC_IPV4_ADDRESS_CHANGED;
      cb_args.ipv4_changed.old_address = &old_addr;
#endif
    }
  }

  /* 设置指定网络接口的网络地址掩码 IPv4 信息，并更新相关 MIB2 信息库数据 */
  if (netif_do_set_netmask(netif, netmask, old_nm)) {
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    change_reason |= LWIP_NSC_IPV4_NETMASK_CHANGED;
    cb_args.ipv4_changed.old_netmask = old_nm;
#endif
  }

  /* 设置指定网络接口的网关地址 IPv4 信息 */
  if (netif_do_set_gw(netif, gw, old_gw)) {
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    change_reason |= LWIP_NSC_IPV4_GATEWAY_CHANGED;
    cb_args.ipv4_changed.old_gw = old_gw;
#endif
  }
  
  if (!remove) {
    /* set ipaddr last to ensure netmask/gw have been set when status callback is called */
    /* 设置指定网络接口的 IPv4 地址信息，并通知相关单元同步旧的地址信息到新的地址信息 */
    if (netif_do_set_ipaddr(netif, ipaddr, &old_addr)) {
#if LWIP_NETIF_EXT_STATUS_CALLBACK
      change_reason |= LWIP_NSC_IPV4_ADDRESS_CHANGED;
      cb_args.ipv4_changed.old_address = &old_addr;
#endif
    }
  }

#if LWIP_NETIF_EXT_STATUS_CALLBACK
  if (change_reason != LWIP_NSC_NONE) {
    change_reason |= LWIP_NSC_IPV4_SETTINGS_CHANGED;
	/* 分别向当前系统 ext_callback 中的每个回调函数发送一个指定的事件 */
    netif_invoke_ext_callback(netif, change_reason, &cb_args);
  }
#endif
}
#endif /* LWIP_IPV4*/

/**
 * @ingroup netif
 * Remove a network interface from the list of lwIP netifs.
 *
 * @param netif the network interface to remove
 */
/*********************************************************************************************************
** 函数名称: netif_remove
** 功能描述: 从当前系统中移除指定的网络接口，并清除和这个网络接口相关的数据，然后调用相关回调函数发送事件
** 输	 入: netif - 要移除的网络接口指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_remove(struct netif *netif)
{
#if LWIP_IPV6
  int i;
#endif

  LWIP_ASSERT_CORE_LOCKED();

  if (netif == NULL) {
    return;
  }

  /* 分别向当前系统 ext_callback 中的每个回调函数发送一个指定的事件 */
  netif_invoke_ext_callback(netif, LWIP_NSC_NETIF_REMOVED, NULL);

#if LWIP_IPV4
  if (!ip4_addr_isany_val(*netif_ip4_addr(netif))) {
  	/* 通知协议栈中其他相关协议层变化前后的地址信息，这样其他的协议层可以根据变化的地址信息做相应处理 */
    netif_do_ip_addr_changed(netif_ip_addr4(netif), NULL);
  }

#if LWIP_IGMP
  /* stop IGMP processing */
  if (netif->flags & NETIF_FLAG_IGMP) {
  	/* 停止 IGMP 进程 */
    igmp_stop(netif);
  }
#endif /* LWIP_IGMP */
#endif /* LWIP_IPV4*/

#if LWIP_IPV6
  for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
    if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i))) {
      /* 通知协议栈中其他相关协议层变化前后的地址信息，这样其他的协议层可以根据变化的地址信息做相应处理 */
      netif_do_ip_addr_changed(netif_ip_addr6(netif, i), NULL);
    }
  }
#if LWIP_IPV6_MLD
  /* stop MLD processing */
  mld6_stop(netif);
#endif /* LWIP_IPV6_MLD */
#endif /* LWIP_IPV6 */

  /* 如果当前网络接口处于 UP 状态，则设置其状态为 DOWN */
  if (netif_is_up(netif)) {
    /* set netif down before removing (call callback function) */
    netif_set_down(netif);
  }

  mib2_remove_ip4(netif);

  /* this netif is default? */
  if (netif_default == netif) {
    /* reset default netif */
    netif_set_default(NULL);
  }
#if !LWIP_SINGLE_NETIF
  /*  is it the first netif? */
  if (netif_list == netif) {
    netif_list = netif->next;
  } else {
    /*  look for netif further down the list */
    struct netif *tmp_netif;

	/* 遍历当前系统中的每一个网络接口，找到当前的网络接口并从全局网络接口链表上移除 */
    NETIF_FOREACH(tmp_netif) {
      if (tmp_netif->next == netif) {
        tmp_netif->next = netif->next;
        break;
      }
    }
    if (tmp_netif == NULL) {
      return; /* netif is not on the list */
    }
  }
#endif /* !LWIP_SINGLE_NETIF */
  mib2_netif_removed(netif);

#if LWIP_NETIF_REMOVE_CALLBACK
  if (netif->remove_callback) {
    netif->remove_callback(netif);
  }
#endif /* LWIP_NETIF_REMOVE_CALLBACK */
  LWIP_DEBUGF( NETIF_DEBUG, ("netif_remove: removed netif\n") );
}

/**
 * @ingroup netif
 * Set a network interface as the default network interface
 * (used to output all packets for which no specific route is found)
 *
 * @param netif the default network interface
 */
/*********************************************************************************************************
** 函数名称: netif_set_default
** 功能描述: 设置指定的网络接口为当前系统默认使用的网络接口并更新相关记录数据
** 输	 入: netif - 要设置的默认网络接口指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_set_default(struct netif *netif)
{
  LWIP_ASSERT_CORE_LOCKED();

  if (netif == NULL) {
    /* remove default route */
    mib2_remove_route_ip4(1, netif);
  } else {
    /* install default route */
    mib2_add_route_ip4(1, netif);
  }
  netif_default = netif;
  LWIP_DEBUGF(NETIF_DEBUG, ("netif: setting default interface %c%c\n",
                            netif ? netif->name[0] : '\'', netif ? netif->name[1] : '\''));
}

/**
 * @ingroup netif
 * Bring an interface up, available for processing
 * traffic.
 */
/*********************************************************************************************************
** 函数名称: netif_set_up
** 功能描述: 设置指定的网络接口状态为 UP，并通过相关的回调函数向协议栈其他相关模块或者和当前网络接口
**         : 相关的设备节点发送事件
** 输	 入: netif - 要设置的为 UP 状态的网络接口指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_set_up(struct netif *netif)
{
  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("netif_set_up: invalid netif", netif != NULL, return);

  if (!(netif->flags & NETIF_FLAG_UP)) {
    netif_set_flags(netif, NETIF_FLAG_UP);

    MIB2_COPY_SYSUPTIME_TO(&netif->ts);

	/* 调用当前网路接口的 status_callback 回调函数 */
    NETIF_STATUS_CALLBACK(netif);

#if LWIP_NETIF_EXT_STATUS_CALLBACK
    {
      netif_ext_callback_args_t args;
      args.status_changed.state = 1;
      netif_invoke_ext_callback(netif, LWIP_NSC_STATUS_CHANGED, &args);
    }
#endif

    netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV4 | NETIF_REPORT_TYPE_IPV6);
#if LWIP_IPV6
    nd6_restart_netif(netif);
#endif /* LWIP_IPV6 */
  }
}

/** Send ARP/IGMP/MLD/RS events, e.g. on link-up/netif-up or addr-change
 */
/*********************************************************************************************************
** 函数名称: netif_issue_reports
** 功能描述: 在指定的网络接口状态或者地址改变的时候，通过调用这个函数向协议栈其他相关模块或者和当前
**         : 网络接口相关的设备节点发送一个事件让其根据事件同步信息，即把旧的数据同步到新的数据
** 输	 入: netif - 发生变化的网络接口指针
**		   : report_type -要发送的事件类型
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
netif_issue_reports(struct netif *netif, u8_t report_type)
{
  LWIP_ASSERT("netif_issue_reports: invalid netif", netif != NULL);

  /* Only send reports when both link and admin states are up */
  if (!(netif->flags & NETIF_FLAG_LINK_UP) ||
      !(netif->flags & NETIF_FLAG_UP)) {
    return;
  }

#if LWIP_IPV4
  if ((report_type & NETIF_REPORT_TYPE_IPV4) &&
      !ip4_addr_isany_val(*netif_ip4_addr(netif))) {
#if LWIP_ARP
    /* For Ethernet network interfaces, we would like to send a "gratuitous ARP" */
    if (netif->flags & (NETIF_FLAG_ETHARP)) {
  	  /* 为指定 IPv4 地址发送一个 "gratuitous ARP" 信息，接收到这个信息的
  	   * 设备节点会更新 arp 映射表信息到当前地址值 */
      etharp_gratuitous(netif);
    }
#endif /* LWIP_ARP */

#if LWIP_IGMP
    /* resend IGMP memberships */
    if (netif->flags & NETIF_FLAG_IGMP) {
      igmp_report_groups(netif);
    }
#endif /* LWIP_IGMP */
  }
#endif /* LWIP_IPV4 */

#if LWIP_IPV6
  if (report_type & NETIF_REPORT_TYPE_IPV6) {
#if LWIP_IPV6_MLD
    /* send mld memberships */
    mld6_report_groups(netif);
#endif /* LWIP_IPV6_MLD */
  }
#endif /* LWIP_IPV6 */
}

/**
 * @ingroup netif
 * Bring an interface down, disabling any traffic processing.
 */
/*********************************************************************************************************
** 函数名称: netif_set_down
** 功能描述: 清除指定的网络接口的 UP 标志，并清除和当前网络接口相关的 arp 缓存数据，然后调用相关回调函数
** 输	 入: netif - 要设置为 DOWN 状态的网络接口指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_set_down(struct netif *netif)
{
  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("netif_set_down: invalid netif", netif != NULL, return);

  if (netif->flags & NETIF_FLAG_UP) {
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    {
      netif_ext_callback_args_t args;
      args.status_changed.state = 0;
	  /* 分别向当前系统 ext_callback 中的每个回调函数发送一个指定的事件 */
      netif_invoke_ext_callback(netif, LWIP_NSC_STATUS_CHANGED, &args);
    }
#endif

    netif_clear_flags(netif, NETIF_FLAG_UP);
    MIB2_COPY_SYSUPTIME_TO(&netif->ts);

#if LWIP_IPV4 && LWIP_ARP
    if (netif->flags & NETIF_FLAG_ETHARP) {
	  /* 清空系统内和当前网络接口相关的所有 arp 缓存项 */
      etharp_cleanup_netif(netif);
    }
#endif /* LWIP_IPV4 && LWIP_ARP */

#if LWIP_IPV6
    nd6_cleanup_netif(netif);
#endif /* LWIP_IPV6 */

    /* 调用当前网路接口的 status_callback 函数 */
    NETIF_STATUS_CALLBACK(netif);
  }
}

#if LWIP_NETIF_STATUS_CALLBACK
/**
 * @ingroup netif
 * Set callback to be called when interface is brought up/down or address is changed while up
 */
/*********************************************************************************************************
** 函数名称: netif_set_status_callback
** 功能描述: 设置指定的网络接口的 status_callback 函数指针
** 输	 入: netif - 要设的网络接口指针
**         : status_callback - 要设置的 status_callback 函数指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_set_status_callback(struct netif *netif, netif_status_callback_fn status_callback)
{
  LWIP_ASSERT_CORE_LOCKED();

  if (netif) {
    netif->status_callback = status_callback;
  }
}
#endif /* LWIP_NETIF_STATUS_CALLBACK */

#if LWIP_NETIF_REMOVE_CALLBACK
/**
 * @ingroup netif
 * Set callback to be called when the interface has been removed
 */
/*********************************************************************************************************
** 函数名称: netif_set_remove_callback
** 功能描述: 设置指定的网络接口的 remove_callback 函数指针
** 输	 入: netif - 要设的网络接口指针
**		   : remove_callback - 要设置的 remove_callback 函数指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_set_remove_callback(struct netif *netif, netif_status_callback_fn remove_callback)
{
  LWIP_ASSERT_CORE_LOCKED();

  if (netif) {
    netif->remove_callback = remove_callback;
  }
}
#endif /* LWIP_NETIF_REMOVE_CALLBACK */

/**
 * @ingroup netif
 * Called by a driver when its link goes up
 */
/*********************************************************************************************************
** 函数名称: netif_set_link_up
** 功能描述: 设置指定的网络接口状态为 LINK_UP，并通知其他相关模块做相应的处理
** 注     释: 这个函数由驱动代码在链路状态变为 UP 的时候调用
** 输	 入: netif - 要设的网络接口指针 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_set_link_up(struct netif *netif)
{
  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("netif_set_link_up: invalid netif", netif != NULL, return);

  if (!(netif->flags & NETIF_FLAG_LINK_UP)) {
    netif_set_flags(netif, NETIF_FLAG_LINK_UP);

#if LWIP_DHCP
    dhcp_network_changed(netif);
#endif /* LWIP_DHCP */

#if LWIP_AUTOIP
    autoip_network_changed(netif);
#endif /* LWIP_AUTOIP */

    netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV4 | NETIF_REPORT_TYPE_IPV6);
#if LWIP_IPV6
    nd6_restart_netif(netif);
#endif /* LWIP_IPV6 */

    NETIF_LINK_CALLBACK(netif);
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    {
      netif_ext_callback_args_t args;
      args.link_changed.state = 1;
	  /* 分别向当前系统 ext_callback 中的每个回调函数发送一个指定的事件 */
      netif_invoke_ext_callback(netif, LWIP_NSC_LINK_CHANGED, &args);
    }
#endif
  }
}

/**
 * @ingroup netif
 * Called by a driver when its link goes down
 */
/*********************************************************************************************************
** 函数名称: netif_set_link_down
** 功能描述: 清除指定网络接口的 LINK_UP 标志，并调用相关的回调函数
** 注	 释: 这个函数由驱动代码在链路状态变为 DOWN 的时候调用
** 输	 入: netif - 要设的网络接口指针 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_set_link_down(struct netif *netif)
{
  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("netif_set_link_down: invalid netif", netif != NULL, return);

  if (netif->flags & NETIF_FLAG_LINK_UP) {
    netif_clear_flags(netif, NETIF_FLAG_LINK_UP);

    /* 调用当前网路接口的 link_callback 回调函数 */
    NETIF_LINK_CALLBACK(netif);
  
#if LWIP_NETIF_EXT_STATUS_CALLBACK
    {
      netif_ext_callback_args_t args;
      args.link_changed.state = 0;
	  /* 分别向当前系统 ext_callback 中的每个回调函数发送一个指定的事件 */
      netif_invoke_ext_callback(netif, LWIP_NSC_LINK_CHANGED, &args);
    }
#endif
  }
}

#if LWIP_NETIF_LINK_CALLBACK
/**
 * @ingroup netif
 * Set callback to be called when link is brought up/down
 */
/*********************************************************************************************************
** 函数名称: netif_set_link_callback
** 功能描述: 设置指定网络接口的 link_callback 回调函数指针
** 输	 入: netif - 要设置的网络接口指针
**         : link_callback - 要设置的 link_callback 回调函数指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_set_link_callback(struct netif *netif, netif_status_callback_fn link_callback)
{
  LWIP_ASSERT_CORE_LOCKED();

  if (netif) {
    netif->link_callback = link_callback;
  }
}
#endif /* LWIP_NETIF_LINK_CALLBACK */

#if ENABLE_LOOPBACK
/**
 * @ingroup netif
 * Send an IP packet to be received on the same netif (loopif-like).
 * The pbuf is simply copied and handed back to netif->input.
 * In multithreaded mode, this is done directly since netif->input must put
 * the packet on a queue.
 * In callback mode, the packet is put on an internal queue and is fed to
 * netif->input by netif_poll().
 *
 * @param netif the lwip network interface structure
 * @param p the (IP) packet to 'send'
 * @return ERR_OK if the packet has been sent
 *         ERR_MEM if the pbuf used to copy the packet couldn't be allocated
 */
/*********************************************************************************************************
** 函数名称: netif_loop_output
** 功能描述: 向指定的回环网络接口中发送一个数据包，如果是多线程环境，在发送完数据后，还要触发指定线程
**         : 执行数据接收回调函数
** 输	 入: netif - 回环网络接口指针
**		   : p - 要发送的数据包指针
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
netif_loop_output(struct netif *netif, struct pbuf *p)
{
  struct pbuf *r;
  err_t err;
  struct pbuf *last;
#if LWIP_LOOPBACK_MAX_PBUFS
  u16_t clen = 0;
#endif /* LWIP_LOOPBACK_MAX_PBUFS */

  /* If we have a loopif, SNMP counters are adjusted for it,
   * if not they are adjusted for 'netif'. */
#if MIB2_STATS
#if LWIP_HAVE_LOOPIF
  struct netif *stats_if = &loop_netif;
#else /* LWIP_HAVE_LOOPIF */
  struct netif *stats_if = netif;
#endif /* LWIP_HAVE_LOOPIF */
#endif /* MIB2_STATS */

#if LWIP_NETIF_LOOPBACK_MULTITHREADING
  u8_t schedule_poll = 0;
#endif /* LWIP_NETIF_LOOPBACK_MULTITHREADING */

  SYS_ARCH_DECL_PROTECT(lev);

  LWIP_ASSERT("netif_loop_output: invalid netif", netif != NULL);
  LWIP_ASSERT("netif_loop_output: invalid pbuf", p != NULL);

  /* Allocate a new pbuf */
  /* 申请一个新的 pbuf，用来存储接收的数据 */
  r = pbuf_alloc(PBUF_LINK, p->tot_len, PBUF_RAM);
  if (r == NULL) {
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.drop);
    MIB2_STATS_NETIF_INC(stats_if, ifoutdiscards);
    return ERR_MEM;
  }
  
#if LWIP_LOOPBACK_MAX_PBUFS
  clen = pbuf_clen(r);
  /* check for overflow or too many pbuf on queue */
  /* 如果当前网络接口的回环网络上的未处理数据包已经超出设置的限制，则丢弃当前要发送的数据包 */
  if (((netif->loop_cnt_current + clen) < netif->loop_cnt_current) ||
      ((netif->loop_cnt_current + clen) > LWIP_MIN(LWIP_LOOPBACK_MAX_PBUFS, 0xFFFF))) {
    pbuf_free(r);
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.drop);
    MIB2_STATS_NETIF_INC(stats_if, ifoutdiscards);
    return ERR_MEM;
  }
  netif->loop_cnt_current = (u16_t)(netif->loop_cnt_current + clen);
#endif /* LWIP_LOOPBACK_MAX_PBUFS */

  /* Copy the whole pbuf queue p into the single pbuf r */
  /* 把回环网络上向外发送的数据包直接复制到新申请的 pbuf 接收缓冲区中 */
  if ((err = pbuf_copy(r, p)) != ERR_OK) {
    pbuf_free(r);
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.drop);
    MIB2_STATS_NETIF_INC(stats_if, ifoutdiscards);
    return err;
  }

  /* Put the packet on a linked list which gets emptied through calling
     netif_poll(). */

  /* let last point to the last pbuf in chain r */
  /* 找到当前数据包链表中的最后一个 pbuf 成员指针，并赋值给 last 变量，主要是为了
   * 维护 netif->loop_last 的值 */
  for (last = r; last->next != NULL; last = last->next) {
    /* nothing to do here, just get to the last pbuf */
  }

  SYS_ARCH_PROTECT(lev);
  /* 把从回环网络上接收到是数据包添加到回环网络接收链表上 */
  if (netif->loop_first != NULL) {
    LWIP_ASSERT("if first != NULL, last must also be != NULL", netif->loop_last != NULL);
    netif->loop_last->next = r;
    netif->loop_last = last;
  } else {
    netif->loop_first = r;
    netif->loop_last = last;
#if LWIP_NETIF_LOOPBACK_MULTITHREADING
    /* No existing packets queued, schedule poll */
    schedule_poll = 1;
#endif /* LWIP_NETIF_LOOPBACK_MULTITHREADING */
  }
  SYS_ARCH_UNPROTECT(lev);

  LINK_STATS_INC(link.xmit);
  MIB2_STATS_NETIF_ADD(stats_if, ifoutoctets, p->tot_len);
  MIB2_STATS_NETIF_INC(stats_if, ifoutucastpkts);

#if LWIP_NETIF_LOOPBACK_MULTITHREADING
  /* For multithreading environment, schedule a call to netif_poll */
  if (schedule_poll) {
  	/* 通过 tcpip_thread 线程执行 netif_poll 回调函数 */
    tcpip_try_callback((tcpip_callback_fn)netif_poll, netif);
  }
#endif /* LWIP_NETIF_LOOPBACK_MULTITHREADING */

  return ERR_OK;
}

#if LWIP_HAVE_LOOPIF
#if LWIP_IPV4
/*********************************************************************************************************
** 函数名称: netif_loop_output_ipv4
** 功能描述: 在 IPv4 网络中，向指定的回环网络接口中发送一个数据包，如果是多线程环境，在发送完数据后
**         : 还要触发指定线程执行数据接收回调函数
** 输	 入: netif - 回环网络接口指针
**		   : p - 要发送的数据包指针
**         : addr - 回环网络 IPv4 地址
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
netif_loop_output_ipv4(struct netif *netif, struct pbuf *p, const ip4_addr_t *addr)
{
  LWIP_UNUSED_ARG(addr);
  return netif_loop_output(netif, p);
}
#endif /* LWIP_IPV4 */

#if LWIP_IPV6
/*********************************************************************************************************
** 函数名称: netif_loop_output_ipv4
** 功能描述: 在 IPv6 网络中，向指定的回环网络接口中发送一个数据包，如果是多线程环境，在发送完数据后
**         : 还要触发指定线程执行数据接收回调函数
** 输	 入: netif - 回环网络接口指针
**		   : p - 要发送的数据包指针
**         : addr - 回环网络 IPv6 地址
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
netif_loop_output_ipv6(struct netif *netif, struct pbuf *p, const ip6_addr_t *addr)
{
  LWIP_UNUSED_ARG(addr);
  return netif_loop_output(netif, p);
}
#endif /* LWIP_IPV6 */
#endif /* LWIP_HAVE_LOOPIF */


/**
 * Call netif_poll() in the main loop of your application. This is to prevent
 * reentering non-reentrant functions like tcp_input(). Packets passed to
 * netif_loop_output() are put on a list that is passed to netif->input() by
 * netif_poll().
 */
/*********************************************************************************************************
** 函数名称: netif_poll
** 功能描述: 在单机环境下，用来轮询指定的网络接口上的“回环网络数据包”
** 注     释: 这个函数是在回调模式下，在接收回环网络数据包时使用，通常在主循环中调用。lwip 协议栈除了支持
**         : 符合单机环境的回调模式，还支持符合系统环境的多线程模式
** 输	 入: netif - 要轮询的网络接口指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_poll(struct netif *netif)
{
  /* If we have a loopif, SNMP counters are adjusted for it,
   * if not they are adjusted for 'netif'. */
#if MIB2_STATS
#if LWIP_HAVE_LOOPIF
  struct netif *stats_if = &loop_netif;
#else /* LWIP_HAVE_LOOPIF */
  struct netif *stats_if = netif;
#endif /* LWIP_HAVE_LOOPIF */
#endif /* MIB2_STATS */

  SYS_ARCH_DECL_PROTECT(lev);

  LWIP_ASSERT("netif_poll: invalid netif", netif != NULL);

  /* Get a packet from the list. With SYS_LIGHTWEIGHT_PROT=1, this is protected */
  SYS_ARCH_PROTECT(lev);

  /* 从 netif->loop_first 链表头开始遍历每一个回环网络上接收到的 pbuf，然后以“数据帧”为单位
   * 向下区数据，并把取到的数据发送到协议栈的                     IP 层进行处理 */
  while (netif->loop_first != NULL) {
  	
  	/* 分别记录一个完成数据帧对应的 pbuf 链表的链表头位置和链表尾位置 */
    struct pbuf *in, *in_end;
	
#if LWIP_LOOPBACK_MAX_PBUFS
    /* 记录一个完成数据帧对应的 pbuf 链表的链表长度 */
    u8_t clen = 1;
#endif /* LWIP_LOOPBACK_MAX_PBUFS */

    in = in_end = netif->loop_first;

    /* 一个完整的数据帧可能由多个 pbuf              组成，形成一个链表，这个位置通过
     * in_end->len != in_end->tot_len 两个变量的值来找到当前完成数据帧所
     * 对应的 pbuf 链表的尾部成员位置，并统计当前数据帧链表长度 */
    while (in_end->len != in_end->tot_len) {
      LWIP_ASSERT("bogus pbuf: len != tot_len but next == NULL!", in_end->next != NULL);
      in_end = in_end->next;
#if LWIP_LOOPBACK_MAX_PBUFS
      clen++;
#endif /* LWIP_LOOPBACK_MAX_PBUFS */
    }
	
#if LWIP_LOOPBACK_MAX_PBUFS
    /* adjust the number of pbufs on queue */
    LWIP_ASSERT("netif->loop_cnt_current underflow",
                ((netif->loop_cnt_current - clen) < netif->loop_cnt_current));
    netif->loop_cnt_current = (u16_t)(netif->loop_cnt_current - clen);
#endif /* LWIP_LOOPBACK_MAX_PBUFS */

    /* 'in_end' now points to the last pbuf from 'in' */
    /* 移除一个完成数据帧对应的 pbuf 后，调整当前网络接口的 netif->loop_first = netif->loop_last */
    if (in_end == netif->loop_last) {
      /* this was the last pbuf in the list */
      netif->loop_first = netif->loop_last = NULL;
    } else {
      /* pop the pbuf off the list */
      netif->loop_first = in_end->next;
      LWIP_ASSERT("should not be null since first != last!", netif->loop_first != NULL);
    }
	
    /* De-queue the pbuf from its successors on the 'loop_' list. */
    in_end->next = NULL;
    SYS_ARCH_UNPROTECT(lev);

	/* 设置接收数据包的网络接口号 */
    in->if_idx = netif_get_index(netif);

    LINK_STATS_INC(link.recv);
    MIB2_STATS_NETIF_ADD(stats_if, ifinoctets, in->tot_len);
    MIB2_STATS_NETIF_INC(stats_if, ifinucastpkts);
	
    /* loopback packets are always IP packets! */
	/* 将接收的数据包向上发送到协议栈的 IP 层 */
    if (ip_input(in, netif) != ERR_OK) {
      pbuf_free(in);
    }
	
    SYS_ARCH_PROTECT(lev);
  }
  SYS_ARCH_UNPROTECT(lev);
}

#if !LWIP_NETIF_LOOPBACK_MULTITHREADING
/**
 * Calls netif_poll() for every netif on the netif_list.
 */
/*********************************************************************************************************
** 函数名称: netif_poll_all
** 功能描述: 在单机环境下，用来轮询当前系统内“所有”的网络接口上的“回环网络数据包”
** 注	 释: 这个函数是在回调模式下，在接收回环网络数据包时使用，通常在主循环中调用。lwip 协议栈除了支持
**		   : 符合单机环境的回调模式，还支持符合系统环境的多线程模式
** 输	 入: netif - 要轮询的网络接口指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_poll_all(void)
{
  struct netif *netif;
  /* loop through netifs */
  NETIF_FOREACH(netif) {
    netif_poll(netif);
  }
}
#endif /* !LWIP_NETIF_LOOPBACK_MULTITHREADING */
#endif /* ENABLE_LOOPBACK */

#if LWIP_NUM_NETIF_CLIENT_DATA > 0
/**
 * @ingroup netif_cd
 * Allocate an index to store data in client_data member of struct netif.
 * Returned value is an index in mentioned array.
 * @see LWIP_NUM_NETIF_CLIENT_DATA
 */
/*********************************************************************************************************
** 函数名称: netif_alloc_client_data_id
** 功能描述: 申请一个有效的 netif_client_id，用来在 struct netif->client_data 数组中存储数据时寻址使用
** 注     释: 因为系统中默认会占用 LWIP_NETIF_CLIENT_DATA_INDEX_MAX 个 client_id，所以我们只能申请在
**         : LWIP_NETIF_CLIENT_DATA_INDEX_MAX 之后的 client_id，所以在返回值的时候要加上这个偏移量
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
netif_alloc_client_data_id(void)
{
  u8_t result = netif_client_id;
  netif_client_id++;

  LWIP_ASSERT_CORE_LOCKED();

#if LWIP_NUM_NETIF_CLIENT_DATA > 256
#error LWIP_NUM_NETIF_CLIENT_DATA must be <= 256
#endif
  LWIP_ASSERT("Increase LWIP_NUM_NETIF_CLIENT_DATA in lwipopts.h", result < LWIP_NUM_NETIF_CLIENT_DATA);
  return (u8_t)(result + LWIP_NETIF_CLIENT_DATA_INDEX_MAX);
}
#endif

#if LWIP_IPV6
/**
 * @ingroup netif_ip6
 * Change an IPv6 address of a network interface
 *
 * @param netif the network interface to change
 * @param addr_idx index of the IPv6 address
 * @param addr6 the new IPv6 address
 *
 * @note call netif_ip6_addr_set_state() to set the address valid/temptative
 */
void
netif_ip6_addr_set(struct netif *netif, s8_t addr_idx, const ip6_addr_t *addr6)
{
  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ASSERT("netif_ip6_addr_set: invalid netif", netif != NULL);
  LWIP_ASSERT("netif_ip6_addr_set: invalid addr6", addr6 != NULL);

  netif_ip6_addr_set_parts(netif, addr_idx, addr6->addr[0], addr6->addr[1],
                           addr6->addr[2], addr6->addr[3]);
}

/*
 * Change an IPv6 address of a network interface (internal version taking 4 * u32_t)
 *
 * @param netif the network interface to change
 * @param addr_idx index of the IPv6 address
 * @param i0 word0 of the new IPv6 address
 * @param i1 word1 of the new IPv6 address
 * @param i2 word2 of the new IPv6 address
 * @param i3 word3 of the new IPv6 address
 */
void
netif_ip6_addr_set_parts(struct netif *netif, s8_t addr_idx, u32_t i0, u32_t i1, u32_t i2, u32_t i3)
{
  ip_addr_t old_addr;
  ip_addr_t new_ipaddr;
  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ASSERT("netif != NULL", netif != NULL);
  LWIP_ASSERT("invalid index", addr_idx < LWIP_IPV6_NUM_ADDRESSES);

  ip6_addr_copy(*ip_2_ip6(&old_addr), *netif_ip6_addr(netif, addr_idx));
  IP_SET_TYPE_VAL(old_addr, IPADDR_TYPE_V6);

  /* address is actually being changed? */
  if ((ip_2_ip6(&old_addr)->addr[0] != i0) || (ip_2_ip6(&old_addr)->addr[1] != i1) ||
      (ip_2_ip6(&old_addr)->addr[2] != i2) || (ip_2_ip6(&old_addr)->addr[3] != i3)) {
    LWIP_DEBUGF(NETIF_DEBUG | LWIP_DBG_STATE, ("netif_ip6_addr_set: netif address being changed\n"));

    IP_ADDR6(&new_ipaddr, i0, i1, i2, i3);
    ip6_addr_assign_zone(ip_2_ip6(&new_ipaddr), IP6_UNICAST, netif);

    if (ip6_addr_isvalid(netif_ip6_addr_state(netif, addr_idx))) {
      netif_do_ip_addr_changed(netif_ip_addr6(netif, addr_idx), &new_ipaddr);
    }
    /* @todo: remove/readd mib2 ip6 entries? */

    ip_addr_copy(netif->ip6_addr[addr_idx], new_ipaddr);

    if (ip6_addr_isvalid(netif_ip6_addr_state(netif, addr_idx))) {
      netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV6);
      NETIF_STATUS_CALLBACK(netif);
    }

#if LWIP_NETIF_EXT_STATUS_CALLBACK
    {
      netif_ext_callback_args_t args;
      args.ipv6_set.addr_index  = addr_idx;
      args.ipv6_set.old_address = &old_addr;
      netif_invoke_ext_callback(netif, LWIP_NSC_IPV6_SET, &args);
    }
#endif
  }

  LWIP_DEBUGF(NETIF_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("netif: IPv6 address %d of interface %c%c set to %s/0x%"X8_F"\n",
              addr_idx, netif->name[0], netif->name[1], ip6addr_ntoa(netif_ip6_addr(netif, addr_idx)),
              netif_ip6_addr_state(netif, addr_idx)));
}

/**
 * @ingroup netif_ip6
 * Change the state of an IPv6 address of a network interface
 * (INVALID, TEMPTATIVE, PREFERRED, DEPRECATED, where TEMPTATIVE
 * includes the number of checks done, see ip6_addr.h)
 *
 * @param netif the network interface to change
 * @param addr_idx index of the IPv6 address
 * @param state the new IPv6 address state
 */
void
netif_ip6_addr_set_state(struct netif *netif, s8_t addr_idx, u8_t state)
{
  u8_t old_state;
  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ASSERT("netif != NULL", netif != NULL);
  LWIP_ASSERT("invalid index", addr_idx < LWIP_IPV6_NUM_ADDRESSES);

  old_state = netif_ip6_addr_state(netif, addr_idx);
  /* state is actually being changed? */
  if (old_state != state) {
    u8_t old_valid = old_state & IP6_ADDR_VALID;
    u8_t new_valid = state & IP6_ADDR_VALID;
    LWIP_DEBUGF(NETIF_DEBUG | LWIP_DBG_STATE, ("netif_ip6_addr_set_state: netif address state being changed\n"));

#if LWIP_IPV6_MLD
    /* Reevaluate solicited-node multicast group membership. */
    if (netif->flags & NETIF_FLAG_MLD6) {
      nd6_adjust_mld_membership(netif, addr_idx, state);
    }
#endif /* LWIP_IPV6_MLD */

    if (old_valid && !new_valid) {
      /* address about to be removed by setting invalid */
      netif_do_ip_addr_changed(netif_ip_addr6(netif, addr_idx), NULL);
      /* @todo: remove mib2 ip6 entries? */
    }
    netif->ip6_addr_state[addr_idx] = state;

    if (!old_valid && new_valid) {
      /* address added by setting valid */
      /* This is a good moment to check that the address is properly zoned. */
      IP6_ADDR_ZONECHECK_NETIF(netif_ip6_addr(netif, addr_idx), netif);
      /* @todo: add mib2 ip6 entries? */
      netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV6);
    }
    if ((old_state & ~IP6_ADDR_TENTATIVE_COUNT_MASK) !=
        (state     & ~IP6_ADDR_TENTATIVE_COUNT_MASK)) {
      /* address state has changed -> call the callback function */
      NETIF_STATUS_CALLBACK(netif);
    }

#if LWIP_NETIF_EXT_STATUS_CALLBACK
    {
      netif_ext_callback_args_t args;
      args.ipv6_addr_state_changed.addr_index = addr_idx;
      args.ipv6_addr_state_changed.old_state  = old_state;
      args.ipv6_addr_state_changed.address    = netif_ip_addr6(netif, addr_idx);
      netif_invoke_ext_callback(netif, LWIP_NSC_IPV6_ADDR_STATE_CHANGED, &args);
    }
#endif
  }
  LWIP_DEBUGF(NETIF_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("netif: IPv6 address %d of interface %c%c set to %s/0x%"X8_F"\n",
              addr_idx, netif->name[0], netif->name[1], ip6addr_ntoa(netif_ip6_addr(netif, addr_idx)),
              netif_ip6_addr_state(netif, addr_idx)));
}

/**
 * Checks if a specific local address is present on the netif and returns its
 * index. Depending on its state, it may or may not be assigned to the
 * interface (as per RFC terminology).
 *
 * The given address may or may not be zoned (i.e., have a zone index other
 * than IP6_NO_ZONE). If the address is zoned, it must have the correct zone
 * for the given netif, or no match will be found.
 *
 * @param netif the netif to check
 * @param ip6addr the IPv6 address to find
 * @return >= 0: address found, this is its index
 *         -1: address not found on this netif
 */
s8_t
netif_get_ip6_addr_match(struct netif *netif, const ip6_addr_t *ip6addr)
{
  s8_t i;

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ASSERT("netif_get_ip6_addr_match: invalid netif", netif != NULL);
  LWIP_ASSERT("netif_get_ip6_addr_match: invalid ip6addr", ip6addr != NULL);

#if LWIP_IPV6_SCOPES
  if (ip6_addr_has_zone(ip6addr) && !ip6_addr_test_zone(ip6addr, netif)) {
    return -1; /* wrong zone, no match */
  }
#endif /* LWIP_IPV6_SCOPES */

  for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
    if (!ip6_addr_isinvalid(netif_ip6_addr_state(netif, i)) &&
        ip6_addr_cmp_zoneless(netif_ip6_addr(netif, i), ip6addr)) {
      return i;
    }
  }
  return -1;
}

/**
 * @ingroup netif_ip6
 * Create a link-local IPv6 address on a netif (stored in slot 0)
 *
 * @param netif the netif to create the address on
 * @param from_mac_48bit if != 0, assume hwadr is a 48-bit MAC address (std conversion)
 *                       if == 0, use hwaddr directly as interface ID
 */
void
netif_create_ip6_linklocal_address(struct netif *netif, u8_t from_mac_48bit)
{
  u8_t i, addr_index;

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ASSERT("netif_create_ip6_linklocal_address: invalid netif", netif != NULL);

  /* Link-local prefix. */
  ip_2_ip6(&netif->ip6_addr[0])->addr[0] = PP_HTONL(0xfe800000ul);
  ip_2_ip6(&netif->ip6_addr[0])->addr[1] = 0;

  /* Generate interface ID. */
  if (from_mac_48bit) {
    /* Assume hwaddr is a 48-bit IEEE 802 MAC. Convert to EUI-64 address. Complement Group bit. */
    ip_2_ip6(&netif->ip6_addr[0])->addr[2] = lwip_htonl((((u32_t)(netif->hwaddr[0] ^ 0x02)) << 24) |
        ((u32_t)(netif->hwaddr[1]) << 16) |
        ((u32_t)(netif->hwaddr[2]) << 8) |
        (0xff));
    ip_2_ip6(&netif->ip6_addr[0])->addr[3] = lwip_htonl((u32_t)(0xfeul << 24) |
        ((u32_t)(netif->hwaddr[3]) << 16) |
        ((u32_t)(netif->hwaddr[4]) << 8) |
        (netif->hwaddr[5]));
  } else {
    /* Use hwaddr directly as interface ID. */
    ip_2_ip6(&netif->ip6_addr[0])->addr[2] = 0;
    ip_2_ip6(&netif->ip6_addr[0])->addr[3] = 0;

    addr_index = 3;
    for (i = 0; (i < 8) && (i < netif->hwaddr_len); i++) {
      if (i == 4) {
        addr_index--;
      }
      ip_2_ip6(&netif->ip6_addr[0])->addr[addr_index] |= lwip_htonl(((u32_t)(netif->hwaddr[netif->hwaddr_len - i - 1])) << (8 * (i & 0x03)));
    }
  }

  /* Set a link-local zone. Even though the zone is implied by the owning
   * netif, setting the zone anyway has two important conceptual advantages:
   * 1) it avoids the need for a ton of exceptions in internal code, allowing
   *    e.g. ip6_addr_cmp() to be used on local addresses;
   * 2) the properly zoned address is visible externally, e.g. when any outside
   *    code enumerates available addresses or uses one to bind a socket.
   * Any external code unaware of address scoping is likely to just ignore the
   * zone field, so this should not create any compatibility problems. */
  ip6_addr_assign_zone(ip_2_ip6(&netif->ip6_addr[0]), IP6_UNICAST, netif);

  /* Set address state. */
#if LWIP_IPV6_DUP_DETECT_ATTEMPTS
  /* Will perform duplicate address detection (DAD). */
  netif_ip6_addr_set_state(netif, 0, IP6_ADDR_TENTATIVE);
#else
  /* Consider address valid. */
  netif_ip6_addr_set_state(netif, 0, IP6_ADDR_PREFERRED);
#endif /* LWIP_IPV6_AUTOCONFIG */
}

/**
 * @ingroup netif_ip6
 * This function allows for the easy addition of a new IPv6 address to an interface.
 * It takes care of finding an empty slot and then sets the address tentative
 * (to make sure that all the subsequent processing happens).
 *
 * @param netif netif to add the address on
 * @param ip6addr address to add
 * @param chosen_idx if != NULL, the chosen IPv6 address index will be stored here
 */
err_t
netif_add_ip6_address(struct netif *netif, const ip6_addr_t *ip6addr, s8_t *chosen_idx)
{
  s8_t i;

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ASSERT("netif_add_ip6_address: invalid netif", netif != NULL);
  LWIP_ASSERT("netif_add_ip6_address: invalid ip6addr", ip6addr != NULL);

  i = netif_get_ip6_addr_match(netif, ip6addr);
  if (i >= 0) {
    /* Address already added */
    if (chosen_idx != NULL) {
      *chosen_idx = i;
    }
    return ERR_OK;
  }

  /* Find a free slot. The first one is reserved for link-local addresses. */
  for (i = ip6_addr_islinklocal(ip6addr) ? 0 : 1; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
    if (ip6_addr_isinvalid(netif_ip6_addr_state(netif, i))) {
      ip_addr_copy_from_ip6(netif->ip6_addr[i], *ip6addr);
      ip6_addr_assign_zone(ip_2_ip6(&netif->ip6_addr[i]), IP6_UNICAST, netif);
      netif_ip6_addr_set_state(netif, i, IP6_ADDR_TENTATIVE);
      if (chosen_idx != NULL) {
        *chosen_idx = i;
      }
      return ERR_OK;
    }
  }

  if (chosen_idx != NULL) {
    *chosen_idx = -1;
  }
  return ERR_VAL;
}

/** Dummy IPv6 output function for netifs not supporting IPv6
 */
static err_t
netif_null_output_ip6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr)
{
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(p);
  LWIP_UNUSED_ARG(ipaddr);

  return ERR_IF;
}
#endif /* LWIP_IPV6 */

#if LWIP_IPV4
/** Dummy IPv4 output function for netifs not supporting IPv4
 */
/*********************************************************************************************************
** 函数名称: netif_null_output_ip4
** 功能描述: 在不支持 IPv4 协议时，发送数据使用这个“假的”函数指针
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
netif_null_output_ip4(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
  LWIP_UNUSED_ARG(netif);
  LWIP_UNUSED_ARG(p);
  LWIP_UNUSED_ARG(ipaddr);

  return ERR_IF;
}
#endif /* LWIP_IPV4 */

/**
* @ingroup netif
* Return the interface index for the netif with name
* or NETIF_NO_INDEX if not found/on error
*
* @param name the name of the netif
*/
/*********************************************************************************************************
** 函数名称: netif_name_to_index
** 功能描述: 通过指定的网络接口名获取与其对应的网络接口号
** 输	 入: name - 网络接口名
** 输	 出: u8_t - 网络接口号
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
netif_name_to_index(const char *name)
{
  struct netif *netif = netif_find(name);
  if (netif != NULL) {
    return netif_get_index(netif);
  }
  /* No name found, return invalid index */
  return NETIF_NO_INDEX;
}

/**
* @ingroup netif
* Return the interface name for the netif matching index
* or NULL if not found/on error
*
* @param idx the interface index of the netif
* @param name char buffer of at least NETIF_NAMESIZE bytes
*/
/*********************************************************************************************************
** 函数名称: netif_index_to_name
** 功能描述: 通过指定的网络接口号获取与其对应的网络接口名
** 输	 入: idx - 网络接口号
**         : name - 存储网络接口名的缓冲区
** 输	 出: name - 网络接口名
**         : NULL - 获取失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
char *
netif_index_to_name(u8_t idx, char *name)
{
  struct netif *netif = netif_get_by_index(idx);

  if (netif != NULL) {
    name[0] = netif->name[0];
    name[1] = netif->name[1];
    lwip_itoa(&name[2], NETIF_NAMESIZE - 2, netif_index_to_num(idx));
    return name;
  }
  return NULL;
}

/**
* @ingroup netif
* Return the interface for the netif index
*
* @param idx index of netif to find
*/
/*********************************************************************************************************
** 函数名称: netif_get_by_index
** 功能描述: 通过指定的网络接口号获取与其对应的网络接口结构体
** 输	 入: idx - 网络接口号
** 输	 出: netif - 网络接口结构体
**		   : NULL - 获取失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct netif *
netif_get_by_index(u8_t idx)
{
  struct netif *netif;

  LWIP_ASSERT_CORE_LOCKED();

  if (idx != NETIF_NO_INDEX) {
    NETIF_FOREACH(netif) {
      if (idx == netif_get_index(netif)) {
        return netif; /* found! */
      }
    }
  }

  return NULL;
}

/**
 * @ingroup netif
 * Find a network interface by searching for its name
 *
 * @param name the name of the netif (like netif->name) plus concatenated number
 * in ascii representation (e.g. 'en0')
 */
/*********************************************************************************************************
** 函数名称: netif_find
** 功能描述: 通过指定的字符串格式名字找到与其对应的网络接口指针
** 输	 入: name - 要查找的网络接口名，字符串格式，例如：name = "en1"
** 输	 出: netif - 查找到的网络接口指针
**         : NULL - 当前系统内没有这个名字的网络接口
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct netif *
netif_find(const char *name)
{
  struct netif *netif;
  u8_t num;

  LWIP_ASSERT_CORE_LOCKED();

  if (name == NULL) {
    return NULL;
  }

  /* 把网络接口名中的数组部分从字符串格式转换成与其对应的数值格式 */
  num = (u8_t)atoi(&name[2]);

  NETIF_FOREACH(netif) {
    if (num == netif->num &&
        name[0] == netif->name[0] &&
        name[1] == netif->name[1]) {
      LWIP_DEBUGF(NETIF_DEBUG, ("netif_find: found %c%c\n", name[0], name[1]));
      return netif;
    }
  }
  LWIP_DEBUGF(NETIF_DEBUG, ("netif_find: didn't find %c%c\n", name[0], name[1]));
  return NULL;
}

#if LWIP_NETIF_EXT_STATUS_CALLBACK
/**
 * @ingroup netif
 * Add extended netif events listener
 * @param callback pointer to listener structure
 * @param fn callback function
 */
/*********************************************************************************************************
** 函数名称: netif_add_ext_callback
** 功能描述: 向当前系统 ext_callback 链表中添加一个指定的回调函数指针（插在链表头）
** 输	 入: callback - 要移除的回调函数指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_add_ext_callback(netif_ext_callback_t *callback, netif_ext_callback_fn fn)
{
  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ASSERT("callback must be != NULL", callback != NULL);
  LWIP_ASSERT("fn must be != NULL", fn != NULL);

  callback->callback_fn = fn;
  callback->next        = ext_callback;
  ext_callback          = callback;
}

/**
 * @ingroup netif
 * Remove extended netif events listener
 * @param callback pointer to listener structure
 */
/*********************************************************************************************************
** 函数名称: netif_remove_ext_callback
** 功能描述: 从当前系统 ext_callback 链表中移除指定的回调函数指针
** 输	 入: callback - 要移除的回调函数指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_remove_ext_callback(netif_ext_callback_t* callback)
{
  netif_ext_callback_t *last, *iter;

  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ASSERT("callback must be != NULL", callback != NULL);

  if (ext_callback == NULL) {
    return;
  }

  if (callback == ext_callback) {
    ext_callback = ext_callback->next;
  } else {
    last = ext_callback;
    for (iter = ext_callback->next; iter != NULL; last = iter, iter = iter->next) {
      if (iter == callback) {
        LWIP_ASSERT("last != NULL", last != NULL);
        last->next = callback->next;
        callback->next = NULL;
        return;
      }
    }
  }
}

/**
 * Invoke extended netif status event
 * @param netif netif that is affected by change
 * @param reason change reason
 * @param args depends on reason, see reason description
 */
/*********************************************************************************************************
** 函数名称: netif_invoke_ext_callback
** 功能描述: 分别向当前系统 ext_callback 中的每个回调函数发送一个指定的事件
** 输	 入: netif - 产生事件的网络接口指针
**		   : reason - 产生事件的原因
**		   : args - 和事件相关参数
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
netif_invoke_ext_callback(struct netif *netif, netif_nsc_reason_t reason, const netif_ext_callback_args_t *args)
{
  netif_ext_callback_t *callback = ext_callback;

  LWIP_ASSERT("netif must be != NULL", netif != NULL);

  while (callback != NULL) {
    callback->callback_fn(netif, reason, args);
    callback = callback->next;
  }
}
#endif /* LWIP_NETIF_EXT_STATUS_CALLBACK */
