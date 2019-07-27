/**
 * @file
 * IP fragmentation/reassembly
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
 * Author: Jani Monoses <jani@iv.ro>
 *
 */

#ifndef LWIP_HDR_IP4_FRAG_H
#define LWIP_HDR_IP4_FRAG_H

#include "lwip/opt.h"
#include "lwip/err.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/ip.h"

#if LWIP_IPV4

#ifdef __cplusplus
extern "C" {
#endif

#if IP_REASSEMBLY
/* The IP reassembly timer interval in milliseconds. */
/* IPv4 分片数据包重组超时定时器超时周期，单位是毫秒 */
#define IP_TMR_INTERVAL 1000

/** IP reassembly helper struct.
 * This is exported because memp needs to know the size.
 */
/* 定义当前协议栈用来缓存正在重组的“完整”数据包的缓存队列项结构，每个队列项
 * 表示一个正在缓存的“完整”数据包 */
struct ip_reassdata {
  /* 通过单向链表把系统内正在进行重组的“完整”数据包链接起来，形成一个队列 */
  struct ip_reassdata *next;

  /* 表示属于当前“完整”数据包的所有“分片”数据包，具体的组织方式见 ip4_frag.c
   * 文件开始位置定义的 struct ip_reass_helper 结构体 */
  struct pbuf *p;

  /* 存储了当前“完整”数据包的 IP 协议头结构信息 */
  struct ip_hdr iphdr;
  
  u16_t datagram_len;

  /* 表示当前正在重组的“完整”数据包相关标志变量，比如 IP_REASS_FLAG_LASTFRAG */
  u8_t flags;

  /* 记录当前正在缓存的、需要重组的“完整”数据包剩余重组时间，单位是分片数据包
   * 重组定时器周期，默认为            1 秒，如果这个变量值达到 0，则放弃重组并清空当前已
   * 经缓存的分片数据包 */
  u8_t timer;
};

void ip_reass_init(void);
void ip_reass_tmr(void);
struct pbuf * ip4_reass(struct pbuf *p);
#endif /* IP_REASSEMBLY */

#if IP_FRAG
#if !LWIP_NETIF_TX_SINGLE_PBUF
#ifndef LWIP_PBUF_CUSTOM_REF_DEFINED
#define LWIP_PBUF_CUSTOM_REF_DEFINED
/** A custom pbuf that holds a reference to another pbuf, which is freed
 * when this custom pbuf is freed. This is used to create a custom PBUF_REF
 * that points into the original pbuf. */
/* 这个结构体用在网络数据包分片函数（ip4_frag）中，通过这个结构体可以创建
 * 一个到原始数据包的映射 pbuf 结构，这样在分片的过程中就不需要执行数据拷
 * 贝操作了 */
struct pbuf_custom_ref {
  /** 'base class' */
  struct pbuf_custom pc;
  /** pointer to the original pbuf that is referenced */
  struct pbuf *original;
};
#endif /* LWIP_PBUF_CUSTOM_REF_DEFINED */
#endif /* !LWIP_NETIF_TX_SINGLE_PBUF */

err_t ip4_frag(struct pbuf *p, struct netif *netif, const ip4_addr_t *dest);
#endif /* IP_FRAG */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_IPV4 */

#endif /* LWIP_HDR_IP4_FRAG_H */
