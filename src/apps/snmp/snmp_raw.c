/**
 * @file
 * SNMP RAW API frontend.
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
#include "lwip/ip_addr.h"

#if LWIP_SNMP && SNMP_USE_RAW

#include "lwip/udp.h"
#include "lwip/ip.h"
#include "lwip/prot/iana.h"
#include "snmp_msg.h"

/* lwIP UDP receive callback function */
/*********************************************************************************************************
** 函数名称: snmp_recv
** 功能描述: 当前协议栈 snmp 协议用来处理接收数据包的回调函数
** 输	 入: arg - 未使用
**         : pcb - 接收到数据包的 udp 协议控制块
**         : p - 接收到的 snmp 数据包
**         : addr - 接收数据包的源 IP 地址
**         : port - 接收数据包的源端口号
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
snmp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
  LWIP_UNUSED_ARG(arg);

  /* 接收并处理接收到的 snmp 数据包 */
  snmp_receive(pcb, p, addr, port);

  pbuf_free(p);
}

/*********************************************************************************************************
** 函数名称: snmp_sendto
** 功能描述: 把指定的 snmp 发送数据包通过 udp 协议发送到指定的目的地处
** 输	 入: handle - 用来发送数据包的 udp 协议控制块
**         : p - 需要发送的 snmp 数据包
**         : dst - 需要发送到的目的地 IP 地址
**         : port - 需要发送到的目的地端口号
** 输	 出: err_t - 发送状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_sendto(void *handle, struct pbuf *p, const ip_addr_t *dst, u16_t port)
{
  return udp_sendto((struct udp_pcb *)handle, p, dst, port);
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
  struct udp_pcb *udp_pcb = (struct udp_pcb *)handle;
  struct netif *dst_if;
  const ip_addr_t *dst_ip;

  LWIP_UNUSED_ARG(udp_pcb); /* unused in case of IPV4 only configuration */

  /* 1. 尝试使用我们自己实现的基于“源” IP 地址的路由策略找到一个发送指定数据包的网络接口，如果
		基于“源” IP 地址的路由策略没找到有效的网络接口，则使用默认基于“目的” IP 地址的路由策略
	 2. 获取指定网口的 IPv4 地址 */
  ip_route_get_local_ip(&udp_pcb->local_ip, dst, dst_if, dst_ip);

  if ((dst_if != NULL) && (dst_ip != NULL)) {
    ip_addr_copy(*result, *dst_ip);
    return 1;
  } else {
    return 0;
  }
}

/**
 * @ingroup snmp_core
 * Starts SNMP Agent.
 * Allocates UDP pcb and binds it to IP_ANY_TYPE port 161.
 */
/*********************************************************************************************************
** 函数名称: snmp_init
** 功能描述: 初始化 snmp 协议模块，操作如下：
**         : 1. 创建一个 udp 连接
**         : 2. 设置新创建的 udp 连接的数据接收处理函数为 snmp_recv
**         : 3. 把新创建的 udp 连接绑定到 IP_ANY_TYPE 地址的 LWIP_IANA_PORT_SNMP 端口上
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_init(void)
{
  err_t err;

  /* 创建一个指定 IP 类型的 udp 协议控制块结构，用来和其他设备建立通信 */
  struct udp_pcb *snmp_pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
  LWIP_ERROR("snmp_raw: no PCB", (snmp_pcb != NULL), return;);

  LWIP_ASSERT_CORE_LOCKED();

  /* 记录当前 snmp 协议模块使用的 udp 协议控制块指针 */
  snmp_traps_handle = snmp_pcb;

  /* 设置新创建的 udp 连接的数据接收处理函数为 snmp_recv */
  udp_recv(snmp_pcb, snmp_recv, NULL);

  /* 把指定的 udp 协议控制块绑定到指定的“本地”网络接口和“本地”端口号上 */
  err = udp_bind(snmp_pcb, IP_ANY_TYPE, LWIP_IANA_PORT_SNMP);
  LWIP_ERROR("snmp_raw: Unable to bind PCB", (err == ERR_OK), return;);
}

#endif /* LWIP_SNMP && SNMP_USE_RAW */
