/**
 * @file
 * TCP internal implementations (do not use in application code)
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
 *
 */
#ifndef LWIP_HDR_TCP_PRIV_H
#define LWIP_HDR_TCP_PRIV_H

#include "lwip/opt.h"

#if LWIP_TCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/tcp.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/icmp.h"
#include "lwip/err.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/prot/tcp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Functions for interfacing with TCP: */

/* Lower layer interface to TCP: */
void             tcp_init    (void);  /* Initialize this module. */
void             tcp_tmr     (void);  /* Must be called every
                                         TCP_TMR_INTERVAL
                                         ms. (Typically 250 ms). */
/* It is also possible to call these two functions at the right
   intervals (instead of calling tcp_tmr()). */
void             tcp_slowtmr (void);
void             tcp_fasttmr (void);

/* Call this from a netif driver (watch out for threading issues!) that has
   returned a memory error on transmit and now has free buffers to send more.
   This iterates all active pcbs that had an error and tries to call
   tcp_output, so use this with care as it might slow down the system. */
void             tcp_txnow   (void);

/* Only used by IP to pass a TCP segment to TCP: */
void             tcp_input   (struct pbuf *p, struct netif *inp);
/* Used within the TCP code only: */
struct tcp_pcb * tcp_alloc   (u8_t prio);
void             tcp_free    (struct tcp_pcb *pcb);
void             tcp_abandon (struct tcp_pcb *pcb, int reset);
err_t            tcp_send_empty_ack(struct tcp_pcb *pcb);
err_t            tcp_rexmit  (struct tcp_pcb *pcb);
err_t            tcp_rexmit_rto_prepare(struct tcp_pcb *pcb);
void             tcp_rexmit_rto_commit(struct tcp_pcb *pcb);
void             tcp_rexmit_rto  (struct tcp_pcb *pcb);
void             tcp_rexmit_fast (struct tcp_pcb *pcb);
u32_t            tcp_update_rcv_ann_wnd(struct tcp_pcb *pcb);
err_t            tcp_process_refused_data(struct tcp_pcb *pcb);

/**
 * This is the Nagle algorithm: try to combine user data to send as few TCP
 * segments as possible. Only send if
 * - no previously transmitted data on the connection remains unacknowledged or
 * - the TF_NODELAY flag is set (nagle algorithm turned off for this pcb) or
 * - the only unsent segment is at least pcb->mss bytes long (or there is more
 *   than one unsent segment - with lwIP, this can happen although unsent->len < mss)
 * - or if we are in fast-retransmit (TF_INFR)
 */
/* 根据 Nagle 算法判断指定的 tcp 协议控制块是否可以发送数据 */
#define tcp_do_output_nagle(tpcb) ((((tpcb)->unacked == NULL) || \
                            ((tpcb)->flags & (TF_NODELAY | TF_INFR)) || \
                            (((tpcb)->unsent != NULL) && (((tpcb)->unsent->next != NULL) || \
                              ((tpcb)->unsent->len >= (tpcb)->mss))) || \
                            ((tcp_sndbuf(tpcb) == 0) || (tcp_sndqueuelen(tpcb) >= TCP_SND_QUEUELEN)) \
                            ) ? 1 : 0)
                            
#define tcp_output_nagle(tpcb) (tcp_do_output_nagle(tpcb) ? tcp_output(tpcb) : ERR_OK)

/* 当前协议栈 tcp 数据包字序号比较操作宏定义接口 */
#define TCP_SEQ_LT(a,b)     ((s32_t)((u32_t)(a) - (u32_t)(b)) < 0)
#define TCP_SEQ_LEQ(a,b)    ((s32_t)((u32_t)(a) - (u32_t)(b)) <= 0)
#define TCP_SEQ_GT(a,b)     ((s32_t)((u32_t)(a) - (u32_t)(b)) > 0)
#define TCP_SEQ_GEQ(a,b)    ((s32_t)((u32_t)(a) - (u32_t)(b)) >= 0)

/* is b<=a<=c? */
#if 0 /* see bug #10548 */
#define TCP_SEQ_BETWEEN(a,b,c) ((c)-(b) >= (a)-(b))
#endif

/* 判断指定的字序号 a 是否处于指定的字序号 b 和 c 之间 */
#define TCP_SEQ_BETWEEN(a,b,c) (TCP_SEQ_GEQ(a,b) && TCP_SEQ_LEQ(a,c))

#ifndef TCP_TMR_INTERVAL
#define TCP_TMR_INTERVAL       250  /* The TCP timer interval in milliseconds. */
#endif /* TCP_TMR_INTERVAL */

#ifndef TCP_FAST_INTERVAL
#define TCP_FAST_INTERVAL      TCP_TMR_INTERVAL /* the fine grained timeout in milliseconds */
#endif /* TCP_FAST_INTERVAL */

#ifndef TCP_SLOW_INTERVAL
#define TCP_SLOW_INTERVAL      (2*TCP_TMR_INTERVAL)  /* the coarse grained timeout in milliseconds */
#endif /* TCP_SLOW_INTERVAL */

#define TCP_FIN_WAIT_TIMEOUT 20000 /* milliseconds */
#define TCP_SYN_RCVD_TIMEOUT 20000 /* milliseconds */

#define TCP_OOSEQ_TIMEOUT        6U /* x RTO */

#ifndef TCP_MSL
#define TCP_MSL 60000UL /* The maximum segment lifetime in milliseconds */
#endif

/* Keepalive values, compliant with RFC 1122. Don't change this unless you know what you're doing */
#ifndef  TCP_KEEPIDLE_DEFAULT
#define  TCP_KEEPIDLE_DEFAULT     7200000UL /* Default KEEPALIVE timer in milliseconds */
#endif

#ifndef  TCP_KEEPINTVL_DEFAULT
#define  TCP_KEEPINTVL_DEFAULT    75000UL   /* Default Time between KEEPALIVE probes in milliseconds */
#endif

#ifndef  TCP_KEEPCNT_DEFAULT
#define  TCP_KEEPCNT_DEFAULT      9U        /* Default Counter for KEEPALIVE probes */
#endif

#define  TCP_MAXIDLE              TCP_KEEPCNT_DEFAULT * TCP_KEEPINTVL_DEFAULT  /* Maximum KEEPALIVE probe time */

/* 获取指定的 tcp 分片数据包的包长度 */
#define TCP_TCPLEN(seg) ((seg)->len + (((TCPH_FLAGS((seg)->tcphdr) & (TCP_FIN | TCP_SYN)) != 0) ? 1U : 0U))

/** Flags used on input processing, not on pcb->flags
*/
/* 表示指定的 tcp 协议控制块接收到了一个 RST（reset）数据包 */
#define TF_RESET     (u8_t)0x08U   /* Connection was reset. */

#define TF_CLOSED    (u8_t)0x10U   /* Connection was successfully closed. */

/* 表示指定的 tcp 协议控制块的 tcp 连接已经接收到了 FIN 数据包 */
#define TF_GOT_FIN   (u8_t)0x20U   /* Connection was closed by the remote end. */


#if LWIP_EVENT_API

#define TCP_EVENT_ACCEPT(lpcb,pcb,arg,err,ret) ret = lwip_tcp_event(arg, (pcb),\
                LWIP_EVENT_ACCEPT, NULL, 0, err)
#define TCP_EVENT_SENT(pcb,space,ret) ret = lwip_tcp_event((pcb)->callback_arg, (pcb),\
                   LWIP_EVENT_SENT, NULL, space, ERR_OK)
#define TCP_EVENT_RECV(pcb,p,err,ret) ret = lwip_tcp_event((pcb)->callback_arg, (pcb),\
                LWIP_EVENT_RECV, (p), 0, (err))          
#define TCP_EVENT_CLOSED(pcb,ret) ret = lwip_tcp_event((pcb)->callback_arg, (pcb),\
                LWIP_EVENT_RECV, NULL, 0, ERR_OK)
#define TCP_EVENT_CONNECTED(pcb,err,ret) ret = lwip_tcp_event((pcb)->callback_arg, (pcb),\
                LWIP_EVENT_CONNECTED, NULL, 0, (err))
#define TCP_EVENT_POLL(pcb,ret)       do { if ((pcb)->state != SYN_RCVD) {                          \
                ret = lwip_tcp_event((pcb)->callback_arg, (pcb), LWIP_EVENT_POLL, NULL, 0, ERR_OK); \
                } else {                                                                            \
                ret = ERR_ARG; } } while(0)
/* For event API, last state SYN_RCVD must be excluded here: the application
   has not seen this pcb, yet! */
#define TCP_EVENT_ERR(last_state,errf,arg,err)  do { if (last_state != SYN_RCVD) {                \
                lwip_tcp_event((arg), NULL, LWIP_EVENT_ERR, NULL, 0, (err)); } } while(0)

#else /* LWIP_EVENT_API */

/* 通过用户注册在指定的 tcp 协议控制块中的回调函数通知应用层成功建立了 tcp 连接 */
#define TCP_EVENT_ACCEPT(lpcb,pcb,arg,err,ret)                 \
  do {                                                         \
    if((lpcb)->accept != NULL)                                 \
      (ret) = (lpcb)->accept((arg),(pcb),(err));               \
    else (ret) = ERR_ARG;                                      \
  } while (0)

/* 通过用户注册在指定的 tcp 协议控制块中的回调函数发送指定 tcp 协议控制块中待发送的数据包 */
#define TCP_EVENT_SENT(pcb,space,ret)                          \
  do {                                                         \
    if((pcb)->sent != NULL)                                    \
      (ret) = (pcb)->sent((pcb)->callback_arg,(pcb),(space));  \
    else (ret) = ERR_OK;                                       \
  } while (0)

/* 通过用户注册在指定的 tcp 协议控制块中的回调函数分发指定的 tcp 协议控制块的指定数据包到应用层协议中 */
#define TCP_EVENT_RECV(pcb,p,err,ret)                          \
  do {                                                         \
    if((pcb)->recv != NULL) {                                  \
      (ret) = (pcb)->recv((pcb)->callback_arg,(pcb),(p),(err));\
    } else {                                                   \
      (ret) = tcp_recv_null(NULL, (pcb), (p), (err));          \
    }                                                          \
  } while (0)

/* 通过用户注册在指定的 tcp 协议控制块中的回调函数通知应用层关闭了 tcp 连接 */
#define TCP_EVENT_CLOSED(pcb,ret)                                \
  do {                                                           \
    if(((pcb)->recv != NULL)) {                                  \
      (ret) = (pcb)->recv((pcb)->callback_arg,(pcb),NULL,ERR_OK);\
    } else {                                                     \
      (ret) = ERR_OK;                                            \
    }                                                            \
  } while (0)

/* 通过用户注册在指定的 tcp 协议控制块中的回调函数通知应用层成功建立了 tcp 连接 */
#define TCP_EVENT_CONNECTED(pcb,err,ret)                         \
  do {                                                           \
    if((pcb)->connected != NULL)                                 \
      (ret) = (pcb)->connected((pcb)->callback_arg,(pcb),(err)); \
    else (ret) = ERR_OK;                                         \
  } while (0)

#define TCP_EVENT_POLL(pcb,ret)                                \
  do {                                                         \
    if((pcb)->poll != NULL)                                    \
      (ret) = (pcb)->poll((pcb)->callback_arg,(pcb));          \
    else (ret) = ERR_OK;                                       \
  } while (0)

#define TCP_EVENT_ERR(last_state,errf,arg,err)                 \
  do {                                                         \
    LWIP_UNUSED_ARG(last_state);                               \
    if((errf) != NULL)                                         \
      (errf)((arg),(err));                                     \
  } while (0)

#endif /* LWIP_EVENT_API */

/** Enabled extra-check for TCP_OVERSIZE if LWIP_DEBUG is enabled */
#if TCP_OVERSIZE && defined(LWIP_DEBUG)
#define TCP_OVERSIZE_DBGCHECK 1
#else
#define TCP_OVERSIZE_DBGCHECK 0
#endif

/** Don't generate checksum on copy if CHECKSUM_GEN_TCP is disabled */
#define TCP_CHECKSUM_ON_COPY  (LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_TCP)

/* This structure represents a TCP segment on the unsent, unacked and ooseq queues */
/* tcp 分片数据包管理结构，表示一个 TCP 分片数据包 */
struct tcp_seg {
  /* 在把 tcp 分片数据包放入一个队列中的时候，通过这个指针把 tcp 分片数据包链接在一起 */
  struct tcp_seg *next;    /* used when putting segments on a queue */

  /* 表示 tcp 分片数据包的负载数据起始地址且这个指针不可移动（包含 tcp 数据包协议头和 tcp 数据包负载数据），具体见 tcp_create_segment 函数 */
  struct pbuf *p;          /* buffer containing data + TCP header */

  /* 表示 tcp 分片数据包的数据长度，包括 tcp 协议头和 tcp 负载数据，但是不包括协议头中的“选项”数据 */
  u16_t len;               /* the TCP length of this segment */
  
#if TCP_OVERSIZE_DBGCHECK
  /* 表示在未发送数据包队列最后一个 tcp 分片数据包成员中空闲的、可存储新数据的内存空间大小 */
  u16_t oversize_left;     /* Extra bytes available at the end of the last
                              pbuf in unsent (used for asserting vs.
                              tcp_pcb.unsent_oversize only) */
#endif /* TCP_OVERSIZE_DBGCHECK */

#if TCP_CHECKSUM_ON_COPY
  u16_t chksum;
  u8_t  chksum_swapped;
#endif /* TCP_CHECKSUM_ON_COPY */

  /* 表示当前 tcp 分片数据包的选项位标志变量 */
  u8_t  flags;

/* 表示 tcp 协议头中的最大报文长度选项标志 */
#define TF_SEG_OPTS_MSS         (u8_t)0x01U /* Include MSS option (only used in SYN segments) */

/* 表示 tcp 协议头中的时间戳选项标志 */
#define TF_SEG_OPTS_TS          (u8_t)0x02U /* Include timestamp option. */

/* 表示当前 tcp 分片数据包中的负载数据的校验和（所有应用层数据的校验和）存储在 chksum 字段中 */
#define TF_SEG_DATA_CHECKSUMMED (u8_t)0x04U /* ALL data (not the header) is
                                               checksummed into 'chksum' */

/* 表示当前 tcp 协议头中包含窗口扩大因子选项数据 */
#define TF_SEG_OPTS_WND_SCALE   (u8_t)0x08U /* Include WND SCALE option (only used in SYN segments) */

/* SACK - select acknowledge */
/* 表示 tcp 协议头中的选择确认选项标志 */
#define TF_SEG_OPTS_SACK_PERM   (u8_t)0x10U /* Include SACK Permitted option (only used in SYN segments) */

  /* 表示当前 tcp 分片数据包的协议头指针 */
  struct tcp_hdr *tcphdr;  /* the TCP header */
};

/* 当前协议栈支持的 tcp 协议头中的选项数据类型 */
#define LWIP_TCP_OPT_EOL        0
#define LWIP_TCP_OPT_NOP        1
#define LWIP_TCP_OPT_MSS        2
#define LWIP_TCP_OPT_WS         3
#define LWIP_TCP_OPT_SACK_PERM  4
#define LWIP_TCP_OPT_TS         8

#define LWIP_TCP_OPT_LEN_MSS    4

#if LWIP_TCP_TIMESTAMPS
#define LWIP_TCP_OPT_LEN_TS     10
#define LWIP_TCP_OPT_LEN_TS_OUT 12 /* aligned for output (includes NOP padding) */
#else
#define LWIP_TCP_OPT_LEN_TS_OUT 0
#endif

#if LWIP_WND_SCALE
#define LWIP_TCP_OPT_LEN_WS     3
#define LWIP_TCP_OPT_LEN_WS_OUT 4 /* aligned for output (includes NOP padding) */
#else
#define LWIP_TCP_OPT_LEN_WS_OUT 0
#endif

#if LWIP_TCP_SACK_OUT
#define LWIP_TCP_OPT_LEN_SACK_PERM     2
#define LWIP_TCP_OPT_LEN_SACK_PERM_OUT 4 /* aligned for output (includes NOP padding) */
#else
#define LWIP_TCP_OPT_LEN_SACK_PERM_OUT 0
#endif

/* 计算指定的协“议头选项标志”所代表的“选项字段”数据长度 */
#define LWIP_TCP_OPT_LENGTH(flags) \
  ((flags) & TF_SEG_OPTS_MSS       ? LWIP_TCP_OPT_LEN_MSS           : 0) + \
  ((flags) & TF_SEG_OPTS_TS        ? LWIP_TCP_OPT_LEN_TS_OUT        : 0) + \
  ((flags) & TF_SEG_OPTS_WND_SCALE ? LWIP_TCP_OPT_LEN_WS_OUT        : 0) + \
  ((flags) & TF_SEG_OPTS_SACK_PERM ? LWIP_TCP_OPT_LEN_SACK_PERM_OUT : 0)

/** This returns a TCP header option for MSS in an u32_t */
#define TCP_BUILD_MSS_OPTION(mss) lwip_htonl(0x02040000 | ((mss) & 0xFFFF))

#if LWIP_WND_SCALE
#define TCPWNDSIZE_F       U32_F
#define TCPWND_MAX         0xFFFFFFFFU
#define TCPWND_CHECK16(x)  LWIP_ASSERT("window size > 0xFFFF", (x) <= 0xFFFF)
#define TCPWND_MIN16(x)    ((u16_t)LWIP_MIN((x), 0xFFFF))
#else /* LWIP_WND_SCALE */
#define TCPWNDSIZE_F       U16_F
#define TCPWND_MAX         0xFFFFU
#define TCPWND_CHECK16(x)
#define TCPWND_MIN16(x)    x
#endif /* LWIP_WND_SCALE */

/* Global variables: */
extern struct tcp_pcb *tcp_input_pcb;
extern u32_t tcp_ticks;
extern u8_t tcp_active_pcbs_changed;

/* The TCP PCB lists. */
union tcp_listen_pcbs_t { /* List of all TCP PCBs in LISTEN state. */
  struct tcp_pcb_listen *listen_pcbs;
  struct tcp_pcb *pcbs;
};
extern struct tcp_pcb *tcp_bound_pcbs;
extern union tcp_listen_pcbs_t tcp_listen_pcbs;
extern struct tcp_pcb *tcp_active_pcbs;  /* List of all TCP PCBs that are in a
              state in which they accept or send
              data. */
extern struct tcp_pcb *tcp_tw_pcbs;      /* List of all TCP PCBs in TIME-WAIT. */

#define NUM_TCP_PCB_LISTS_NO_TIME_WAIT  3
#define NUM_TCP_PCB_LISTS               4
extern struct tcp_pcb ** const tcp_pcb_lists[NUM_TCP_PCB_LISTS];

/* Axioms about the above lists:
   1) Every TCP PCB that is not CLOSED is in one of the lists.
   2) A PCB is only in one of the lists.
   3) All PCBs in the tcp_listen_pcbs list is in LISTEN state.
   4) All PCBs in the tcp_tw_pcbs list is in TIME-WAIT state.
*/
/* Define two macros, TCP_REG and TCP_RMV that registers a TCP PCB
   with a PCB list or removes a PCB from a list, respectively. */
#ifndef TCP_DEBUG_PCB_LISTS
#define TCP_DEBUG_PCB_LISTS 0
#endif
#if TCP_DEBUG_PCB_LISTS
#define TCP_REG(pcbs, npcb) do {\
                            struct tcp_pcb *tcp_tmp_pcb; \
                            LWIP_DEBUGF(TCP_DEBUG, ("TCP_REG %p local port %"U16_F"\n", (void *)(npcb), (npcb)->local_port)); \
                            for (tcp_tmp_pcb = *(pcbs); \
          tcp_tmp_pcb != NULL; \
        tcp_tmp_pcb = tcp_tmp_pcb->next) { \
                                LWIP_ASSERT("TCP_REG: already registered\n", tcp_tmp_pcb != (npcb)); \
                            } \
                            LWIP_ASSERT("TCP_REG: pcb->state != CLOSED", ((pcbs) == &tcp_bound_pcbs) || ((npcb)->state != CLOSED)); \
                            (npcb)->next = *(pcbs); \
                            LWIP_ASSERT("TCP_REG: npcb->next != npcb", (npcb)->next != (npcb)); \
                            *(pcbs) = (npcb); \
                            LWIP_ASSERT("TCP_REG: tcp_pcbs sane", tcp_pcbs_sane()); \
              tcp_timer_needed(); \
                            } while(0)
#define TCP_RMV(pcbs, npcb) do { \
                            struct tcp_pcb *tcp_tmp_pcb; \
                            LWIP_ASSERT("TCP_RMV: pcbs != NULL", *(pcbs) != NULL); \
                            LWIP_DEBUGF(TCP_DEBUG, ("TCP_RMV: removing %p from %p\n", (void *)(npcb), (void *)(*(pcbs)))); \
                            if(*(pcbs) == (npcb)) { \
                               *(pcbs) = (*pcbs)->next; \
                            } else for (tcp_tmp_pcb = *(pcbs); tcp_tmp_pcb != NULL; tcp_tmp_pcb = tcp_tmp_pcb->next) { \
                               if(tcp_tmp_pcb->next == (npcb)) { \
                                  tcp_tmp_pcb->next = (npcb)->next; \
                                  break; \
                               } \
                            } \
                            (npcb)->next = NULL; \
                            LWIP_ASSERT("TCP_RMV: tcp_pcbs sane", tcp_pcbs_sane()); \
                            LWIP_DEBUGF(TCP_DEBUG, ("TCP_RMV: removed %p from %p\n", (void *)(npcb), (void *)(*(pcbs)))); \
                            } while(0)

#else /* LWIP_DEBUG */

/* 把指定的 tcp 协议控制块注册到指定的 tcp 协议控制块链表中 */
#define TCP_REG(pcbs, npcb)                        \
  do {                                             \
    (npcb)->next = *pcbs;                          \
    *(pcbs) = (npcb);                              \
    tcp_timer_needed();                            \
  } while (0)

/* 把指定的 tcp 协议控制块从指定的 tcp 协议控制块链表上移除 */
#define TCP_RMV(pcbs, npcb)                        \
  do {                                             \
    if(*(pcbs) == (npcb)) {                        \
      (*(pcbs)) = (*pcbs)->next;                   \
    }                                              \
    else {                                         \
      struct tcp_pcb *tcp_tmp_pcb;                 \
      for (tcp_tmp_pcb = *pcbs;                    \
          tcp_tmp_pcb != NULL;                     \
          tcp_tmp_pcb = tcp_tmp_pcb->next) {       \
        if(tcp_tmp_pcb->next == (npcb)) {          \
          tcp_tmp_pcb->next = (npcb)->next;        \
          break;                                   \
        }                                          \
      }                                            \
    }                                              \
    (npcb)->next = NULL;                           \
  } while(0)

#endif /* LWIP_DEBUG */

/* 把指定的 tcp 协议控制块插入到当前协议栈的 tcp_active_pcbs 链表中 */
#define TCP_REG_ACTIVE(npcb)                       \
  do {                                             \
    TCP_REG(&tcp_active_pcbs, npcb);               \
    tcp_active_pcbs_changed = 1;                   \
  } while (0)

/* 把指定的 tcp 协议控制块从当前协议栈的 tcp_active_pcbs 链表中移除 */
#define TCP_RMV_ACTIVE(npcb)                       \
  do {                                             \
    TCP_RMV(&tcp_active_pcbs, npcb);               \
    tcp_active_pcbs_changed = 1;                   \
  } while (0)

/* 把指定的 tcp 协议控制块从当前协议栈的 tcp_active_pcbs 链表中移除并释放这个 tcp 协议控制块
 * 的所有缓存数据、把这个 tcp 协议控制块的延迟发送应答数据包立即发送出去，然后设置这个 tcp 协
 * 议控制块的状态和本地端口号分别为 CLOSED 和 0  */
#define TCP_PCB_REMOVE_ACTIVE(pcb)                 \
  do {                                             \
    tcp_pcb_remove(&tcp_active_pcbs, pcb);         \
    tcp_active_pcbs_changed = 1;                   \
  } while (0)


/* Internal functions: */
struct tcp_pcb *tcp_pcb_copy(struct tcp_pcb *pcb);
void tcp_pcb_purge(struct tcp_pcb *pcb);
void tcp_pcb_remove(struct tcp_pcb **pcblist, struct tcp_pcb *pcb);

void tcp_segs_free(struct tcp_seg *seg);
void tcp_seg_free(struct tcp_seg *seg);
struct tcp_seg *tcp_seg_copy(struct tcp_seg *seg);

/* 设置指定的 tcp 协议控制块的 ACK 标志位，表示需要发送应答数据包 */
#define tcp_ack(pcb)                               \
  do {                                             \
    if((pcb)->flags & TF_ACK_DELAY) {              \
      tcp_clear_flags(pcb, TF_ACK_DELAY);          \
      tcp_ack_now(pcb);                            \
    }                                              \
    else {                                         \
      tcp_set_flags(pcb, TF_ACK_DELAY);            \
    }                                              \
  } while (0)

/* 设置指定 tcp 协议控制块的 TF_ACK_NOW 标志位 */
#define tcp_ack_now(pcb)                           \
  tcp_set_flags(pcb, TF_ACK_NOW)

err_t tcp_send_fin(struct tcp_pcb *pcb);
err_t tcp_enqueue_flags(struct tcp_pcb *pcb, u8_t flags);

void tcp_rexmit_seg(struct tcp_pcb *pcb, struct tcp_seg *seg);

void tcp_rst(const struct tcp_pcb* pcb, u32_t seqno, u32_t ackno,
       const ip_addr_t *local_ip, const ip_addr_t *remote_ip,
       u16_t local_port, u16_t remote_port);

u32_t tcp_next_iss(struct tcp_pcb *pcb);

err_t tcp_keepalive(struct tcp_pcb *pcb);
err_t tcp_split_unsent_seg(struct tcp_pcb *pcb, u16_t split);
err_t tcp_zero_window_probe(struct tcp_pcb *pcb);
void  tcp_trigger_input_pcb_close(void);

#if TCP_CALCULATE_EFF_SEND_MSS
u16_t tcp_eff_send_mss_netif(u16_t sendmss, struct netif *outif,
                             const ip_addr_t *dest);

/* 通过当前 tcp mss 和指定网络接口的 mtu 计算到指定目的 IP 地址处的有效 mss */
#define tcp_eff_send_mss(sendmss, src, dest) \
    tcp_eff_send_mss_netif(sendmss, ip_route(src, dest), dest)
#endif /* TCP_CALCULATE_EFF_SEND_MSS */

#if LWIP_CALLBACK_API
err_t tcp_recv_null(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
#endif /* LWIP_CALLBACK_API */

#if TCP_DEBUG || TCP_INPUT_DEBUG || TCP_OUTPUT_DEBUG
void tcp_debug_print(struct tcp_hdr *tcphdr);
void tcp_debug_print_flags(u8_t flags);
void tcp_debug_print_state(enum tcp_state s);
void tcp_debug_print_pcbs(void);
s16_t tcp_pcbs_sane(void);
#else
#  define tcp_debug_print(tcphdr)
#  define tcp_debug_print_flags(flags)
#  define tcp_debug_print_state(s)
#  define tcp_debug_print_pcbs()
#  define tcp_pcbs_sane() 1
#endif /* TCP_DEBUG */

/** External function (implemented in timers.c), called when TCP detects
 * that a timer is needed (i.e. active- or time-wait-pcb found). */
void tcp_timer_needed(void);

void tcp_netif_ip_addr_changed(const ip_addr_t* old_addr, const ip_addr_t* new_addr);

#if TCP_QUEUE_OOSEQ
void tcp_free_ooseq(struct tcp_pcb *pcb);
#endif

#if LWIP_TCP_PCB_NUM_EXT_ARGS
err_t tcp_ext_arg_invoke_callbacks_passive_open(struct tcp_pcb_listen *lpcb, struct tcp_pcb *cpcb);
#endif

#ifdef __cplusplus
}
#endif

#endif /* LWIP_TCP */

#endif /* LWIP_HDR_TCP_PRIV_H */
