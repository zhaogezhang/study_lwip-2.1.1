/**
 * @file
 * SNMP netconn frontend.
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
 * Author: Dirk Ziegelmeier <dziegel@gmx.de>
 */

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP && SNMP_USE_NETCONN

#include <string.h>
#include "lwip/api.h"
#include "lwip/ip.h"
#include "lwip/udp.h"
#include "snmp_msg.h"
#include "lwip/sys.h"
#include "lwip/prot/iana.h"

/** SNMP netconn API worker thread */
/*********************************************************************************************************
** 函数名称: snmp_netconn_thread
** 功能描述: 表示当前 snmp 协议栈工作在 NETCONN 模式时的工作线程函数
** 输	 入: arg - 未使用
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
snmp_netconn_thread(void *arg)
{
  struct netconn *conn;
  struct netbuf *buf;
  err_t err;
  LWIP_UNUSED_ARG(arg);

  /* Bind to SNMP port with default IP address */
#if LWIP_IPV6
  conn = netconn_new(NETCONN_UDP_IPV6);
  netconn_bind(conn, IP6_ADDR_ANY, LWIP_IANA_PORT_SNMP);
#else /* LWIP_IPV6 */
  conn = netconn_new(NETCONN_UDP);
  netconn_bind(conn, IP4_ADDR_ANY, LWIP_IANA_PORT_SNMP);
#endif /* LWIP_IPV6 */
  LWIP_ERROR("snmp_netconn: invalid conn", (conn != NULL), return;);

  /* 记录当前 snmp 协议模块使用的 udp 协议控制块指针 */
  snmp_traps_handle = conn;

  do {
    err = netconn_recv(conn, &buf);

    if (err == ERR_OK) {
      snmp_receive(conn, buf->p, &buf->addr, buf->port);
    }

    if (buf != NULL) {
      netbuf_delete(buf);
    }
  } while (1);
}

/*********************************************************************************************************
** 函数名称: snmp_sendto
** 功能描述: 表示当前 snmp 协议栈工作在 NETCONN 模式时的 snmp 数据包发送函数
** 输	 入: handle - 用来发送 snmp 数据包的 udp 协议控制块指针
**         : p - 表示需要发送的 snmp 数据包
**         : dst - 表示目的地 IP 地址
**         : port - 表示目的地端口号
** 输	 出: ERR_OK - 发送成功
**         : others - 发送失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_sendto(void *handle, struct pbuf *p, const ip_addr_t *dst, u16_t port)
{
  err_t result;
  struct netbuf buf;

  memset(&buf, 0, sizeof(buf));
  buf.p = p;
  result = netconn_sendto((struct netconn *)handle, &buf, dst, port);

  return result;
}

/*********************************************************************************************************
** 函数名称: snmp_get_local_ip_for_dst
** 功能描述: 为指定的目的地 IP 地址在当前协议栈中查找一个用于发送这个数据包的网路接口的 IP 地址
** 输	 入: handle - 指定的 udp 协议控制块
**         : dst - 指定的目的地 IP 地址
** 输	 出: 1 - 获取成功
**         : 0 - 获取失败
**         : result - 获取到的本地 IP 地址
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_get_local_ip_for_dst(void *handle, const ip_addr_t *dst, ip_addr_t *result)
{
  struct netconn *conn = (struct netconn *)handle;
  struct netif *dst_if;
  const ip_addr_t *dst_ip;

  LWIP_UNUSED_ARG(conn); /* unused in case of IPV4 only configuration */

  ip_route_get_local_ip(&conn->pcb.udp->local_ip, dst, dst_if, dst_ip);

  if ((dst_if != NULL) && (dst_ip != NULL)) {
    ip_addr_copy(*result, *dst_ip);
    return 1;
  } else {
    return 0;
  }
}

/**
 * Starts SNMP Agent.
 */
/*********************************************************************************************************
** 函数名称: snmp_init
** 功能描述: 初始化 snmp 协议模块，启动 snmp 工作线程
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_init(void)
{
  LWIP_ASSERT_CORE_LOCKED();
  sys_thread_new("snmp_netconn", snmp_netconn_thread, NULL, SNMP_STACK_SIZE, SNMP_THREAD_PRIO);
}

#endif /* LWIP_SNMP && SNMP_USE_NETCONN */
