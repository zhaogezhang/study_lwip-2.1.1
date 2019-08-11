/**
 * @file
 * Transmission Control Protocol for IP
 * See also @ref tcp_raw
 *
 * @defgroup tcp_raw TCP
 * @ingroup callbackstyle_api
 * Transmission Control Protocol for IP\n
 * @see @ref api
 *
 * Common functions for the TCP implementation, such as functions
 * for manipulating the data structures and the TCP timer functions. TCP functions
 * related to input and output is found in tcp_in.c and tcp_out.c respectively.\n
 * 
 * TCP connection setup
 * --------------------
 * The functions used for setting up connections is similar to that of
 * the sequential API and of the BSD socket API. A new TCP connection
 * identifier (i.e., a protocol control block - PCB) is created with the
 * tcp_new() function. This PCB can then be either set to listen for new
 * incoming connections or be explicitly connected to another host.
 * - tcp_new()
 * - tcp_bind()
 * - tcp_listen() and tcp_listen_with_backlog()
 * - tcp_accept()
 * - tcp_connect()
 * 
 * Sending TCP data
 * ----------------
 * TCP data is sent by enqueueing the data with a call to tcp_write() and
 * triggering to send by calling tcp_output(). When the data is successfully
 * transmitted to the remote host, the application will be notified with a
 * call to a specified callback function.
 * - tcp_write()
 * - tcp_output()
 * - tcp_sent()
 * 
 * Receiving TCP data
 * ------------------
 * TCP data reception is callback based - an application specified
 * callback function is called when new data arrives. When the
 * application has taken the data, it has to call the tcp_recved()
 * function to indicate that TCP can advertise increase the receive
 * window.
 * - tcp_recv()
 * - tcp_recved()
 * 
 * Application polling
 * -------------------
 * When a connection is idle (i.e., no data is either transmitted or
 * received), lwIP will repeatedly poll the application by calling a
 * specified callback function. This can be used either as a watchdog
 * timer for killing connections that have stayed idle for too long, or
 * as a method of waiting for memory to become available. For instance,
 * if a call to tcp_write() has failed because memory wasn't available,
 * the application may use the polling functionality to call tcp_write()
 * again when the connection has been idle for a while.
 * - tcp_poll()
 *
 * Closing and aborting connections
 * --------------------------------
 * - tcp_close()
 * - tcp_abort()
 * - tcp_err()
 * 
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
/* TCP 数据包协议格式，详细内容见链接：https://tools.ietf.org/html/rfc793
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          Source Port          |       Destination Port        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                        Sequence Number                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Acknowledgment Number                      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  Data |           |U|A|P|R|S|F|                               |
 *   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 *   |       |           |G|K|H|T|N|N|                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           Checksum            |         Urgent Pointer        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Options                    |    Padding    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                           Payload                             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *   源端口（Source Port）：发送这个数据包进程的端口号
 *   目的端口（Destination Port）：接收这个数据包进程的端口号
 *   字节号（Sequence Number）：当前数据包的第一个负载字节数据的字节号（除了在 SYN 数据包中），在 SYN 数据包中
 *                              当前数据包的第一个负载字节数据表示的是初始字节号
 *   应答字节号（Acknowledgment Number）：在 ACK 控制位被置位的时候有效，表示接收端下一次希望接收的数据包的字节号
 *                                        在建立连接之后，这个位一直有效
 *   负载数据偏移量（Data Offset）：表示当前数据包负载数据从包头开始的偏移量（即常规协议头和选项数据长度），单位是 4 个 8 位字节
 *   保留位（Reserved）：必须设置为 0
 *   紧急数据控制位（URG）：表示紧急指针字段（Urgent Pointer）数据有效且当前数据包负载数据起始位置处携带的是“紧急”数据
 *   应答字节号控制位（ACK）：表示应答字节号字段（Acknowledgment Number）数据有效
 *   推送控制位（PSH）：在发送端表示当前数据包需要尽快发送出去，在接收端表示当前数据包需要尽快推送给应用层处理
 *   复位连接控制位（RST）：复位当前的 tcp 连接（拒绝 tcp 连接请求、断开已经连接成功的 tcp 连接），无需执行复杂的四次挥手
 *   同步字节号控制位（SYN）：表示当前数据包是 SYN 数据包，数据包的第一个负载字节数据表示的是初始字节号
 *   结束控制位（FIN）：表示要断开当前已经建立的 tcp 连接（双向连接中的一个方向）
 *   窗口大小（Window）：表示在发送这个数据包的时候，发送这个数据包的设备当前窗口可以接收的数据字节数
 *   校验和（Checksum）：表示当前数据包的校验和（tcp 协议头和 tcp 负载数据以及 tcp 伪协议头的校验和）
 *   紧急数据指针（Urgent Pointer）：在紧急数据控制位被置位的时候有效，表示当前数据包负载数据中跟在“紧急”数据后的“非紧急”
 *                                   数据的第一个字节数据和当前数据包协议头中的“字节号”之间的偏移量
 *   选项字段（Options）：在 tcp 协议头中可附加的“选项”数据，数据格式为：1 字节选项类型 + 1 字节选项总长度 + 选项数据
 *   对齐填充（Padding）：因为 tcp 协议头中的选项数据需要 4 字节对齐，在数据不对齐时，通过追加填充 0 使其对齐
 *   负载数据（Payload）：当前数据包的负载数据
 *
 *
 * TCP 协议中的伪协议头：详细描述见：https://blog.csdn.net/liuxingen/article/details/45459313#pseudo-header%E7%9A%84%E5%AE%9A%E4%B9%89
 *                                   https://stackoverflow.com/questions/359045/what-is-the-significance-of-pseudo-header-used-in-udp-tcp
 *   +—————–+—————–+—————–+—————–+ 
 *   |      Source Address       | 
 *   +—————–+—————–+—————–+—————–+ 
 *   |    Destination Address    | 
 *   +—————–+—————–+—————–+———–——+ 
 *   | zero | Type | TCP Length  | 
 *   +—————–+—————–+—————–+—————–+ 
 *
 *   当前 tcp 分片数据包所属数据包的“源”地址（Source Address）：IPv4 源地址
 *   当前 tcp 分片数据包所属数据包的“目的”地址（Destination Address）：IPv4 目的地址
 *   当前 tcp 分片数据包所属数据包的协议类型（Type）：IP_PROTO_TCP
 *   当前 tcp 分片数据包所属数据包长度（TCP Length）：TCP Header + TCP Payload
 *
 *
 * 常用的 tcp 协议头选项数据：
 *   
 *   选项列表结束标志：在 tcp 协议头所有选项后使用，表示选项列表结束边界（这个选项不是强制要求设置的），格式如下：
 *                     详情见链接：https://tools.ietf.org/html/rfc793
 *   +--------+
 *   | Kind=0 |
 *   +--------+
 *
 *   NOP 选项：表示没有实际意义的选项数据，用来在不同选项之间填充空间使每个选项起始地址能够按照“字”对齐，格式如下：
 *                     详情见链接：https://tools.ietf.org/html/rfc793
 *   +--------+
 *   | Kind=1 |
 *   +--------+
 *
 *   最大报文长度选项：只可以在 SYN 数据包中使用，表示发送这个数据包的设备支持的最大接收数据包长度，格式如下：
 *                     详情见链接：https://tools.ietf.org/html/rfc793
 *   +--------+--------+---------+--------+
 *   | Kind=2 |Length=4|   max seg size   |
 *   +--------+--------+---------+--------+
 *
 *   时间戳选项：可以用来计算数据包往返时延，格式如下：
 *               详情见链接：https://tools.ietf.org/html/rfc1323
 *   +--------+---------+---------------------+---------------------+
 *   | Kind=8 |Length=10|   TS Value (TSval)  |TS Echo Reply (TSecr)|
 *   +--------+---------+---------------------+---------------------+
 *  	 1		   1			  4					     4
 *
 *   选择确认允许选项：表示当前设备支持 sack 功能，仅在 SYN 数据包中使用，格式如下：
 *                     详情见链接：https://tools.ietf.org/html/draft-sabatini-tcp-sack-01
 *   +--------+--------+
 *   | Kind=4 |Length=2|
 *   +--------+--------+
 *
 *   选择确认选项：表示当前接收端已经接收到了哪些字节号不连续的数据包，格式如下：
 *                 详情见链接：https://tools.ietf.org/html/draft-floyd-sack-00
 *  				   +--------+--------+
 *  				   | Kind=5 | Length |
 *   +--------+--------+--------+--------+
 *   |		Left Edge of 1st Block		 |
 *   +--------+--------+--------+--------+
 *   |		Right Edge of 1st Block 	 |
 *   +--------+--------+--------+--------+
 *   |									 |
 *   /			  . . . 				 /
 *   |									 |
 *   +--------+--------+--------+--------+
 *   |		Left Edge of nth Block		 |
 *   +--------+--------+--------+--------+
 *   |		Right Edge of nth Block 	 |
 *   +--------+--------+--------+--------+
 *
 *   窗口扩大因子选项：因为 tcp 协议头中的窗口大小只有 16 位，所以如果想要设置超过 65535 的窗口，就需要用的
 *                     窗口扩大因子选项，此时的窗口大小 = Window * (2 ^ shift.cnt)
 *                     详情见链接：https://tools.ietf.org/html/rfc1323
 *   +---------+---------+---------+
 *   | Kind=3  |Length=3 |shift.cnt|
 *   +---------+---------+---------+
 *
 *
 * TCP 连接状态变化图：
 *
 *                                +---------+ ---------\      active OPEN
 *                                |  CLOSED |            \    -----------
 *                                +---------+<---------\   \   create TCB
 *                                  |     ^              \   \  snd SYN
 *                     passive OPEN |     |   CLOSE        \   \
 *                     ------------ |     | ----------       \   \
 *                      create TCB  |     | delete TCB         \   \
 *                                  V     |                      \   \
 *                                +---------+            CLOSE    |    \
 *                                |  LISTEN |          ---------- |     |
 *                                +---------+          delete TCB |     |
 *                     rcv SYN      |     |     SEND              |     |
 *                    -----------   |     |    -------            |     V
 *   +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
 *   |         |<-----------------           ------------------>|         |
 *   |   SYN   |                    rcv SYN                     |   SYN   |
 *   |   RCVD  |<-----------------------------------------------|   SENT  |
 *   |         |                    snd ACK                     |         |
 *   |         |------------------           -------------------|         |
 *   +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
 *     |           --------------   |     |   -----------
 *     |                  x         |     |     snd ACK
 *     |                            V     V
 *     |  CLOSE                   +---------+
 *     | -------                  |  ESTAB  |
 *     | snd FIN                  +---------+
 *     |                   CLOSE    |     |    rcv FIN
 *     V                  -------   |     |    -------
 *   +---------+          snd FIN  /       \   snd ACK          +---------+
 *   |  FIN    |<-----------------           ------------------>|  CLOSE  |
 *   | WAIT-1  |------------------                              |   WAIT  |
 *   +---------+          rcv FIN  \                            +---------+
 *     | rcv ACK of FIN   -------   |                            CLOSE  |
 *     | --------------   snd ACK   |                           ------- |
 *     V        x                   V                           snd FIN V
 *   +---------+                  +---------+                   +---------+
 *   |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
 *   +---------+                  +---------+                   +---------+
 *     |                rcv ACK of FIN |                 rcv ACK of FIN |
 *     |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
 *     |  -------              x       V    ------------        x       V
 *      \ snd ACK                 +---------+delete TCB         +---------+
 *       ------------------------>|TIME WAIT|------------------>| CLOSED  |
 *                                +---------+                   +---------+
 *
 *   LISTEN - 表示服务端正在等待其他客户端设备发送连接请求
 *   
 *   SYN-SENT - 表示客户端发送一个连接请求后，正在等待服务端发送与其匹配的连接请求
 *   
 *   SYN-RECEIVED - 表示服务端在接收到客户端发送的连接请求并发送了一个与其匹配的连接请求后
 *                  正在等待客户端的连接请求确认消息
 *
 *   ESTABLISHED - 表示服务端和客户端在经过三次握手后，成功建立了 tcp 连接，可以收发数据了
 *   
 *   FIN-WAIT-1 - 表示“本地”客户端/服务端“先”发送一个连接终止请求后，正在等待对端设备发送连接终止请求
 *                应答消息，或者是对端设备发送的连接终止请求
 *   
 *   FIN-WAIT-2 - 表示“本地”客户端/服务端“先”发送的连接终止请求已经接收到对应的连接终止请求应答消息
 *                正在等待“对端”设备发送接终止请求
 *   
 *   CLOSE-WAIT - 表示“对端”客户端/服务端“先”发送的连接终止请求已经接收到对应的连接终止请求应答消息
 *                正在等待“本地”设备发送接终止请求
 *   
 *   CLOSING - 表示“对端”客户端/服务端发送的连接终止请求已经接收到对应的连接终止请求应答消息，但是
 *             “本地”客户端/服务端发送的连接终止请求还没接收到对应的连接终止请求应答消息，现在正在
 *             等待“对端”客户端/服务端发送对应的连接终止请求应答消息（第一个连接终止请求由“本地”设备发起）
 *   
 *   LAST-ACK - 表示“对端”客户端/服务端发送的连接终止请求已经接收到对应的连接终止请求应答消息，但是
 *             “本地”客户端/服务端发送的连接终止请求还没接收到对应的连接终止请求应答消息，现在正在
 *             等待“对端”客户端/服务端发送对应的连接终止请求应答消息（第一个连接终止请求由“对端”设备发起）
 *
 *   TIME-WAIT - 表示“本地”客户端/服务端发送完四次挥手中的最后一个连接终止请求应答消息后，延时期间状态
 *               延时的目的主要是为了保证对端设备可以接收到自己发送的连接终止请求应答消息
 *   
 *   CLOSED - 表示服务端和客户端在经过四次挥手后，成功关闭了 tcp 连接
 *
 */
#include "lwip/opt.h"

#if LWIP_TCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/nd6.h"

#include <string.h>

/* 添加用户自定义的钩子函数头文件 */
#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif

/* 定义当前系统 tcp 模块使用的端口号范围 */
#ifndef TCP_LOCAL_PORT_RANGE_START
/* From http://www.iana.org/assignments/port-numbers:
   "The Dynamic and/or Private Ports are those from 49152 through 65535" */
#define TCP_LOCAL_PORT_RANGE_START        0xc000
#define TCP_LOCAL_PORT_RANGE_END          0xffff
/* 确保指定的端口号在合法范围内 */
#define TCP_ENSURE_LOCAL_PORT_RANGE(port) ((u16_t)(((port) & (u16_t)~TCP_LOCAL_PORT_RANGE_START) + TCP_LOCAL_PORT_RANGE_START))
#endif

#if LWIP_TCP_KEEPALIVE
#define TCP_KEEP_DUR(pcb)   ((pcb)->keep_cnt * (pcb)->keep_intvl)
#define TCP_KEEP_INTVL(pcb) ((pcb)->keep_intvl)
#else /* LWIP_TCP_KEEPALIVE */
#define TCP_KEEP_DUR(pcb)   TCP_MAXIDLE
#define TCP_KEEP_INTVL(pcb) TCP_KEEPINTVL_DEFAULT
#endif /* LWIP_TCP_KEEPALIVE */

/* As initial send MSS, we use TCP_MSS but limit it to 536. */
/* 当前协议栈的 tcp 连接默认使用的 MSS（Maximum segment size）*/
#if TCP_MSS > 536
#define INITIAL_MSS 536
#else
#define INITIAL_MSS TCP_MSS
#endif

/* 当前协议栈的 tcp 连接状态的字符串描述 */
static const char *const tcp_state_str[] = {
  "CLOSED",
  "LISTEN",
  "SYN_SENT",
  "SYN_RCVD",
  "ESTABLISHED",
  "FIN_WAIT_1",
  "FIN_WAIT_2",
  "CLOSE_WAIT",
  "CLOSING",
  "LAST_ACK",
  "TIME_WAIT"
};

/* last local TCP port */
static u16_t tcp_port = TCP_LOCAL_PORT_RANGE_START;

/* Incremented every coarse grained timer shot (typically every 500 ms). */
/* 表示当前协议栈 tcp 模块使用的基准定时器的计数值，默认基准定时器超时周期是 ms */
u32_t tcp_ticks;

static const u8_t tcp_backoff[13] =
{ 1, 2, 3, 4, 5, 6, 7, 7, 7, 7, 7, 7, 7};

/* Times per slowtmr hits */
/* 表示当前协议栈的 tcp 模块的坚持定时器退避时间选择数组，在使用的时候通过数组索引
 * 选择退避时间，坚持定时器在连续发生退避时会使对应的数组索引值加 1 */
static const u8_t tcp_persist_backoff[7] = { 3, 6, 12, 24, 48, 96, 120 };

/* The TCP PCB lists. */

/** List of all TCP PCBs bound but not yet (connected || listening) */
/* 用来链接当前系统内所有已经绑定“本地”设备、但还没建立连接或者还没进入监听状态的 tcp 协议控制块 */
struct tcp_pcb *tcp_bound_pcbs;

/** List of all TCP PCBs in LISTEN state */
/* 用来链接当前系统内所有正处于监听状态的 tcp 协议控制块 */
union tcp_listen_pcbs_t tcp_listen_pcbs;

/** List of all TCP PCBs that are in a state in which
 * they accept or send data. */ 
/* 用来链接当前系统内所有正处于发送数据或者接收数据状态的 tcp 协议控制块 */
struct tcp_pcb *tcp_active_pcbs;

/** List of all TCP PCBs in TIME-WAIT state */
/* 用来链接当前系统内所有正处于 TIME-WAIT 状态的 tcp 协议控制块 */
struct tcp_pcb *tcp_tw_pcbs;

/** An array with all (non-temporary) PCB lists, mainly used for smaller code size */
/* 表示当前系统内处于不同状态的 tcp 协议控制块链表的链表头指针 */
struct tcp_pcb **const tcp_pcb_lists[] = {&tcp_listen_pcbs.pcbs, &tcp_bound_pcbs,
         &tcp_active_pcbs, &tcp_tw_pcbs
};

/* 表示当前系统的 tcp_active_pcbs 链表的成员结构是否发生了变化（添加或者移除）*/
u8_t tcp_active_pcbs_changed;

/** Timer counter to handle calling slow-timer from tcp_tmr() */
static u8_t tcp_timer;

static u8_t tcp_timer_ctr;
static u16_t tcp_new_port(void);

static err_t tcp_close_shutdown_fin(struct tcp_pcb *pcb);
#if LWIP_TCP_PCB_NUM_EXT_ARGS
static void tcp_ext_arg_invoke_callbacks_destroyed(struct tcp_pcb_ext_args *ext_args);
#endif

/**
 * Initialize this module.
 */
/*********************************************************************************************************
** 函数名称: tcp_init
** 功能描述: 初始化当前协议栈的 tcp 功能模块（初始化起始端口号的值）
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_init(void)
{
#ifdef LWIP_RAND
  tcp_port = TCP_ENSURE_LOCAL_PORT_RANGE(LWIP_RAND());
#endif /* LWIP_RAND */
}

/** Free a tcp pcb */
/*********************************************************************************************************
** 函数名称: tcp_free
** 功能描述: 释放指定的 MEMP_TCP_PCB 类型的 tcp 协议控制块结构
** 输	 入: pcb - 需要释放的 tcp 协议控制块
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_free(struct tcp_pcb *pcb)
{
  LWIP_ASSERT("tcp_free: LISTEN", pcb->state != LISTEN);
  
#if LWIP_TCP_PCB_NUM_EXT_ARGS
  tcp_ext_arg_invoke_callbacks_destroyed(pcb->ext_args);
#endif

  memp_free(MEMP_TCP_PCB, pcb);
}

/** Free a tcp listen pcb */
/*********************************************************************************************************
** 函数名称: tcp_free_listen
** 功能描述: 释放指定的 MEMP_TCP_PCB_LISTEN 类型的 tcp 协议控制块结构
** 输	 入: pcb - 需要释放的 tcp 协议控制块
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
tcp_free_listen(struct tcp_pcb *pcb)
{
  LWIP_ASSERT("tcp_free_listen: !LISTEN", pcb->state != LISTEN);
  
#if LWIP_TCP_PCB_NUM_EXT_ARGS
  tcp_ext_arg_invoke_callbacks_destroyed(pcb->ext_args);
#endif

  memp_free(MEMP_TCP_PCB_LISTEN, pcb);
}

/**
 * Called periodically to dispatch TCP timers.
 */ 
/*********************************************************************************************************
** 函数名称: tcp_tmr
** 功能描述: 当前协议栈的基准软件定时器超时函数
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_tmr(void)
{
  /* Call tcp_fasttmr() every 250 ms */
  /* 调用 tcp 模块的快速软件定时器 */
  tcp_fasttmr();

  /* 调用 tcp 模块的慢速软件定时器，慢速软件定时器调用周期是快速软件定时器的二倍 */
  if (++tcp_timer & 1) {
    /* Call tcp_slowtmr() every 500 ms, i.e., every other timer
       tcp_tmr() is called. */
    tcp_slowtmr();
  }
}

#if LWIP_CALLBACK_API || TCP_LISTEN_BACKLOG
/** Called when a listen pcb is closed. Iterates one pcb list and removes the
 * closed listener pcb from pcb->listener if matching.
 */ 
/*********************************************************************************************************
** 函数名称: tcp_remove_listener
** 功能描述: 遍历指定的 tcp 协议控制块链表并从中清除所有和指定的、已关闭的 tcp “监听”协议控制块的信息
** 输	 入: list - 要遍历的 tcp 协议控制块链
**         : lpcb - 要清除的处于“监听”状态的 tcp 协议控制块
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
tcp_remove_listener(struct tcp_pcb *list, struct tcp_pcb_listen *lpcb)
{
  struct tcp_pcb *pcb;

  LWIP_ASSERT("tcp_remove_listener: invalid listener", lpcb != NULL);

  for (pcb = list; pcb != NULL; pcb = pcb->next) {
    if (pcb->listener == lpcb) {
      pcb->listener = NULL;
    }
  }
}
#endif

/** Called when a listen pcb is closed. Iterates all pcb lists and removes the
 * closed listener pcb from pcb->listener if matching.
 */
/*********************************************************************************************************
** 函数名称: tcp_remove_listener
** 功能描述: 关闭指定的处于“监听”状态的 tcp 协议控制块，清除系统内所有和这个 tcp 协议控制块相关的信息
** 输	 入: pcb - 需要关闭的处于“监听”状态的 tcp 协议控制块
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
tcp_listen_closed(struct tcp_pcb *pcb)
{
#if LWIP_CALLBACK_API || TCP_LISTEN_BACKLOG
  size_t i;
  LWIP_ASSERT("pcb != NULL", pcb != NULL);
  LWIP_ASSERT("pcb->state == LISTEN", pcb->state == LISTEN);

  /* 清除系统内所有和这个 tcp 协议控制块相关的信息 */
  for (i = 1; i < LWIP_ARRAYSIZE(tcp_pcb_lists); i++) {
    tcp_remove_listener(*tcp_pcb_lists[i], (struct tcp_pcb_listen *)pcb);
  }
#endif

  LWIP_UNUSED_ARG(pcb);
}

#if TCP_LISTEN_BACKLOG
/** @ingroup tcp_raw
 * Delay accepting a connection in respect to the listen backlog:
 * the number of outstanding connections is increased until
 * tcp_backlog_accepted() is called.
 *
 * ATTENTION: the caller is responsible for calling tcp_backlog_accepted()
 * or else the backlog feature will get out of sync!
 *
 * @param pcb the connection pcb which is not fully accepted yet
 */
/*********************************************************************************************************
** 函数名称: tcp_backlog_delayed
** 功能描述: 增加指定的 tcp 协议控制块所属监听者的 backlog 计数值，执行逻辑如下：
**         : 判断指定的 tcp 协议控制块是否设置了 TF_BACKLOGPEND 标志，如果没设置，表示这个 tcp 协议
**         : 控制块代表的 tcp 连接还没统计到其所属监听者的 backlog 计数值中，所以将其统计进去
** 注     释: 如果开启了 tcp 模块的 TCP_LISTEN_BACKLOG 选项，表示会通过追踪 tcp 监听者的 backlog 计数值
**         : 来限制 tcp 模块同时建立的连接请求数
** 输	 入: pcb - 建立连接的 tcp 协议控制块
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_backlog_delayed(struct tcp_pcb *pcb)
{
  LWIP_ASSERT("pcb != NULL", pcb != NULL);
  LWIP_ASSERT_CORE_LOCKED();

  /* 如果指定的 tcp 协议控制块还没统计到其所属监听者的 backlog 计数值中，则统计进去 */
  if ((pcb->flags & TF_BACKLOGPEND) == 0) {
    if (pcb->listener != NULL) {
      pcb->listener->accepts_pending++;
      LWIP_ASSERT("accepts_pending != 0", pcb->listener->accepts_pending != 0);
      tcp_set_flags(pcb, TF_BACKLOGPEND);
    }
  }
}

/** @ingroup tcp_raw
 * A delayed-accept a connection is accepted (or closed/aborted): decreases
 * the number of outstanding connections after calling tcp_backlog_delayed().
 *
 * ATTENTION: the caller is responsible for calling tcp_backlog_accepted()
 * or else the backlog feature will get out of sync!
 *
 * @param pcb the connection pcb which is now fully accepted (or closed/aborted)
 */ 
/*********************************************************************************************************
** 函数名称: tcp_backlog_accepted
** 功能描述: 尝试减小指定的 tcp 协议控制块所属监听者的 backlog 计数值，执行逻辑如下：
**         : 判断指定的 tcp 协议控制块是否设置了 TF_BACKLOGPEND 标志，如果设置了，表示这个 tcp 协议
**         : 控制块代表的 tcp 连接已经统计到其所属监听者的 backlog 计数值中，所以将其移除
** 注     释: 如果开启了 tcp 模块的 TCP_LISTEN_BACKLOG 选项，表示会通过追踪 tcp 监听者的 backlog 计数值
**         : 来限制 tcp 模块同时建立的连接请求数
** 输	 入: pcb - 建立连接的 tcp 协议控制块
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_backlog_accepted(struct tcp_pcb *pcb)
{
  LWIP_ASSERT("pcb != NULL", pcb != NULL);
  LWIP_ASSERT_CORE_LOCKED();
  
  if ((pcb->flags & TF_BACKLOGPEND) != 0) {
    if (pcb->listener != NULL) {
      LWIP_ASSERT("accepts_pending != 0", pcb->listener->accepts_pending != 0);
	  
      pcb->listener->accepts_pending--;
      tcp_clear_flags(pcb, TF_BACKLOGPEND);
    }
  }
}
#endif /* TCP_LISTEN_BACKLOG */

/**
 * Closes the TX side of a connection held by the PCB.
 * For tcp_close(), a RST is sent if the application didn't receive all data
 * (tcp_recved() not called for all data passed to recv callback).
 *
 * Listening pcbs are freed and may not be referenced any more.
 * Connection pcbs are freed if not yet connected and may not be referenced
 * any more. If a connection is established (at least SYN received or in
 * a closing state), the connection is closed, and put in a closing state.
 * The pcb is then automatically freed in tcp_slowtmr(). It is therefore
 * unsafe to reference it.
 *
 * @param pcb the tcp_pcb to close
 * @return ERR_OK if connection has been closed
 *         another err_t if closing failed and pcb is not freed
 */ 
/*********************************************************************************************************
** 函数名称: tcp_close_shutdown
** 功能描述: 关闭指定的 tcp 协议控制块的发送数据端连接
** 输	 入: pcb - 需要关闭发送端连接的 tcp 协议控制块
**         : rst_on_unacked_data - 表示是否需要发送 reset 数据包到对端设备
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
tcp_close_shutdown(struct tcp_pcb *pcb, u8_t rst_on_unacked_data)
{
  LWIP_ASSERT("tcp_close_shutdown: invalid pcb", pcb != NULL);

  if (rst_on_unacked_data && ((pcb->state == ESTABLISHED) || (pcb->state == CLOSE_WAIT))) {
    if ((pcb->refused_data != NULL) || (pcb->rcv_wnd != TCP_WND_MAX(pcb))) {
      /* Not all data received by application, send RST to tell the remote
         side about this. */
      LWIP_ASSERT("pcb->flags & TF_RXCLOSED", pcb->flags & TF_RXCLOSED);

      /* don't call tcp_abort here: we must not deallocate the pcb since
         that might not be expected when calling tcp_close */
      /* 根据函数参数构建一个 tcp reset 控制数据包并发送到对端设备处，复位指定的 tpc 连接 */
      tcp_rst(pcb, pcb->snd_nxt, pcb->rcv_nxt, &pcb->local_ip, &pcb->remote_ip,
              pcb->local_port, pcb->remote_port);

      /* 清空指定的、不是处于完全关闭状态的 tcp 协议控制块的所有缓存数据 */
      tcp_pcb_purge(pcb);
	  
	  /* 把当前 tcp 协议控制块从当前协议栈的 tcp_active_pcbs 链表中移除 */
      TCP_RMV_ACTIVE(pcb);
	  
      /* Deallocate the pcb since we already sent a RST for it */
      if (tcp_input_pcb == pcb) {
        /* prevent using a deallocated pcb: free it from tcp_input later */
	    /* 设置全局变量 recv_flags 的 TF_CLOSED 标志位 */
        tcp_trigger_input_pcb_close();
      } else {
		/* 释放指定的 MEMP_TCP_PCB 类型的 tcp 协议控制块结构 */
        tcp_free(pcb);
      }
      return ERR_OK;
    }
  }

  /* - states which free the pcb are handled here,
     - states which send FIN and change state are handled in tcp_close_shutdown_fin() */
  /* 根据当前 tcp 协议控制块的状态执行相应的关闭 tcp 连接的操作 */
  switch (pcb->state) {
    case CLOSED:
      /* Closing a pcb in the CLOSED state might seem erroneous,
       * however, it is in this state once allocated and as yet unused
       * and the user needs some way to free it should the need arise.
       * Calling tcp_close() with a pcb that has already been closed, (i.e. twice)
       * or for a pcb that has been used and then entered the CLOSED state
       * is erroneous, but this should never happen as the pcb has in those cases
       * been freed, and so any remaining handles are bogus. */
      if (pcb->local_port != 0) {	  	
	    /* 把指定的 tcp 协议控制块从 tcp_bound_pcbs 协议控制块链表上移除 */
        TCP_RMV(&tcp_bound_pcbs, pcb);
      }
      /* 释放指定的 MEMP_TCP_PCB 类型的 tcp 协议控制块结构 */
      tcp_free(pcb);
      break;
    case LISTEN:
	  /* 关闭指定的处于“监听”状态的 tcp 协议控制块，清除系统内所有和这个 tcp 协议控制块相关的信息 */
      tcp_listen_closed(pcb);

	  /* 把指定的 tcp 协议控制块从 tcp_listen_pcbs tcp 协议控制块链表上移除，并释放这个 tcp 协议
       * 控制块的所有缓存数据、把这个 tcp 协议控制块的延迟发送应答数据包立即发送出去，然后设置这
       * 个 tcp 协议控制块的状态和本地端口号分别为 CLOSED 和 0 */
      tcp_pcb_remove(&tcp_listen_pcbs.pcbs, pcb);

	  /* 释放指定的 MEMP_TCP_PCB_LISTEN 类型的 tcp 协议控制块结构 */
      tcp_free_listen(pcb);
      break;
    case SYN_SENT:		
	  /* 把指定的 tcp 协议控制块从当前协议栈的 tcp_active_pcbs 链表中移除并释放这个 tcp 协议控制块
	   * 的所有缓存数据、把这个 tcp 协议控制块的延迟发送应答数据包立即发送出去，然后设置这个 tcp 协
	   * 议控制块的状态和本地端口号分别为 CLOSED 和 0 */
      TCP_PCB_REMOVE_ACTIVE(pcb);

      /* 释放指定的 MEMP_TCP_PCB 类型的 tcp 协议控制块结构 */
	  tcp_free(pcb);
	
      MIB2_STATS_INC(mib2.tcpattemptfails);
      break;
    default:
	  /* 根据指定 tcp 协议控制块状态向这个协议控制块的未发送数据队列中添加一个 FIN 数据包，并更新
       * 这个协议控制块到下一个状态（tcp 状态机的下一个状态），同时尝试把这个协议控制块的未发送数
       * 据队列中的所有分片数据包发送出去 */
      return tcp_close_shutdown_fin(pcb);
  }
  return ERR_OK;
}

/*********************************************************************************************************
** 函数名称: tcp_close_shutdown_fin
** 功能描述: 根据指定 tcp 协议控制块状态向这个协议控制块的未发送数据队列中添加一个 FIN 数据包，并更新
**         : 这个协议控制块到下一个状态（tcp 状态机的下一个状态），同时尝试把这个协议控制块的未发送数
**         : 据队列中的所有分片数据包发送出去
** 输	 入: pcb - 需要发送 FIN 数据包的 tcp 协议控制块
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
tcp_close_shutdown_fin(struct tcp_pcb *pcb)
{
  err_t err;
  LWIP_ASSERT("pcb != NULL", pcb != NULL);

  switch (pcb->state) {
    case SYN_RCVD:
	  /* 向当前的 tcp 协议控制块的未发送数据队列中添加一个 FIN 数据包 */
      err = tcp_send_fin(pcb);
      if (err == ERR_OK) {
	  	/* 尝试减小指定的 tcp 协议控制块所属监听者的 backlog 计数值 */
        tcp_backlog_accepted(pcb);
        MIB2_STATS_INC(mib2.tcpattemptfails);
        pcb->state = FIN_WAIT_1;
      }
      break;
    case ESTABLISHED:
	  /* 向当前的 tcp 协议控制块的未发送数据队列中添加一个 FIN 数据包 */
      err = tcp_send_fin(pcb);
      if (err == ERR_OK) {
        MIB2_STATS_INC(mib2.tcpestabresets);
        pcb->state = FIN_WAIT_1;
      }
      break;
    case CLOSE_WAIT:		
	  /* 向当前的 tcp 协议控制块的未发送数据队列中添加一个 FIN 数据包 */
      err = tcp_send_fin(pcb);
      if (err == ERR_OK) {
        MIB2_STATS_INC(mib2.tcpestabresets);
        pcb->state = LAST_ACK;
      }
      break;
    default:
      /* Has already been closed, do nothing. */
      return ERR_OK;
  }

  if (err == ERR_OK) {
    /* To ensure all data has been sent when tcp_close returns, we have
       to make sure tcp_output doesn't fail.
       Since we don't really have to ensure all data has been sent when tcp_close
       returns (unsent data is sent from tcp timer functions, also), we don't care
       for the return value of tcp_output for now. */
    /* 尝试发送当前 tcp 协议控制块的未发送数据队列中的分片数据包数据，因为在这个函数返回时
     * 并不保证把指定的 tcp 协议控制块未发送数据队列中的所有数据包全部发送出去，可能会延迟
     * 发送，所以如果我们需要在 tcp_close 函数返回前确保当前 tcp 协议控制块的所有未发送数据
     * 包能够全部发送出去，则需要判断 tcp_output 函数的返回值，根据返回值状态执行对应操作 */
    tcp_output(pcb);
  } else if (err == ERR_MEM) {
    /* Mark this pcb for closing. Closing is retried from tcp_tmr. */  
	/* 表示当前 tcp 协议控制块发送的 FIN 数据包发送失败，需要在 tcp_tmr 定时器中通过检查这个标志重新发送 */
    tcp_set_flags(pcb, TF_CLOSEPEND);
    /* We have to return ERR_OK from here to indicate to the callers that this
       pcb should not be used any more as it will be freed soon via tcp_tmr.
       This is OK here since sending FIN does not guarantee a time frime for
       actually freeing the pcb, either (it is left in closure states for
       remote ACK or timeout) */
    return ERR_OK;
  }
  return err;
}

/**
 * @ingroup tcp_raw
 * Closes the connection held by the PCB.
 *
 * Listening pcbs are freed and may not be referenced any more.
 * Connection pcbs are freed if not yet connected and may not be referenced
 * any more. If a connection is established (at least SYN received or in
 * a closing state), the connection is closed, and put in a closing state.
 * The pcb is then automatically freed in tcp_slowtmr(). It is therefore
 * unsafe to reference it (unless an error is returned).
 * 
 * The function may return ERR_MEM if no memory
 * was available for closing the connection. If so, the application
 * should wait and try again either by using the acknowledgment
 * callback or the polling functionality. If the close succeeds, the
 * function returns ERR_OK.
 *
 * @param pcb the tcp_pcb to close
 * @return ERR_OK if connection has been closed
 *         another err_t if closing failed and pcb is not freed
 */ 
/*********************************************************************************************************
** 函数名称: tcp_close
** 功能描述: 关闭指定的 tcp 协议控制块的发送数据方向的 tcp 连接，如果当前 tcp 状态不是 LISTEN，同时把
**         : 接收数据方向的 tcp 连接也关闭
** 输	 入: pcb - 需要关闭 tcp 连接的 tcp 协议控制块
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
tcp_close(struct tcp_pcb *pcb)
{
  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("tcp_close: invalid pcb", pcb != NULL, return ERR_ARG);
  LWIP_DEBUGF(TCP_DEBUG, ("tcp_close: closing in "));

  tcp_debug_print_state(pcb->state);

  if (pcb->state != LISTEN) {
    /* Set a flag not to receive any more data... */
    tcp_set_flags(pcb, TF_RXCLOSED);
  }
  /* ... and close */
  return tcp_close_shutdown(pcb, 1);
}

/**
 * @ingroup tcp_raw
 * Causes all or part of a full-duplex connection of this PCB to be shut down.
 * This doesn't deallocate the PCB unless shutting down both sides!
 * Shutting down both sides is the same as calling tcp_close, so if it succeds
 * (i.e. returns ER_OK), the PCB must not be referenced any more!
 *
 * @param pcb PCB to shutdown
 * @param shut_rx shut down receive side if this is != 0
 * @param shut_tx shut down send side if this is != 0
 * @return ERR_OK if shutdown succeeded (or the PCB has already been shut down)
 *         another err_t on error.
 */ 
/*********************************************************************************************************
** 函数名称: tcp_shutdown
** 功能描述: 关闭指定的 tcp 协议控制块的指定方向（因为 tcp 连接是全双工模式，所以它的 tcp 连接包括收发
**         : 数据两个方向）的 tcp 连接
** 输	 入: pcb - 需要关闭连接的 tcp 协议控制块
**         : shut_rx - 表示是否关闭当前 tcp 协议控制块的“接收”端连接
**         : shut_tx - 表示是否关闭当前 tcp 协议控制块的“发送”端连接
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
tcp_shutdown(struct tcp_pcb *pcb, int shut_rx, int shut_tx)
{
  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("tcp_shutdown: invalid pcb", pcb != NULL, return ERR_ARG);

  /* 判断指定的 tcp 协议控制块状态是否适合执行关闭连接操作 */
  if (pcb->state == LISTEN) {
    return ERR_CONN;
  }

  /* 关闭当前 tcp 协议控制块的“接收”数据端连接 */
  if (shut_rx) {
    /* shut down the receive side: set a flag not to receive any more data... */
    tcp_set_flags(pcb, TF_RXCLOSED);
    if (shut_tx) {
      /* shutting down the tx AND rx side is the same as closing for the raw API */
	  /* 关闭指定的 tcp 协议控制块的发送数据端连接 */
      return tcp_close_shutdown(pcb, 1);
    }
	
    /* ... and free buffered data */
	/* 在我们关闭 tcp 协议控制块的接收数据端连接的时候，如果在协议栈中还有已经接收但是
	 * 应用层还未处理的数据包，则直接丢弃这些数据包 */
    if (pcb->refused_data != NULL) {
      pbuf_free(pcb->refused_data);
      pcb->refused_data = NULL;
    }
  }
  
  /* 关闭当前 tcp 协议控制块的“发送”数据端连接 */
  if (shut_tx) {
    /* This can't happen twice since if it succeeds, the pcb's state is changed.
       Only close in these states as the others directly deallocate the PCB */
    switch (pcb->state) {
      case SYN_RCVD:
      case ESTABLISHED:
      case CLOSE_WAIT:
        return tcp_close_shutdown(pcb, (u8_t)shut_rx);
      default:
        /* Not (yet?) connected, cannot shutdown the TX side as that would bring us
          into CLOSED state, where the PCB is deallocated. */
        return ERR_CONN;
    }
  }
  return ERR_OK;
}

/**
 * Abandons a connection and optionally sends a RST to the remote
 * host.  Deletes the local protocol control block. This is done when
 * a connection is killed because of shortage of memory.
 *
 * @param pcb the tcp_pcb to abort
 * @param reset boolean to indicate whether a reset should be sent
 */ 
/*********************************************************************************************************
** 函数名称: tcp_abandon
** 功能描述: 释放指定 tcp 协议控制块数据队列中的数据包并关闭这个 tcp 协议控制块的连接，并根据指定的
**         : 参数决定是否发送 reset 数据包到对端设备
** 输	 入: pcb - 需要关闭的 tcp 协议控制块
**         : reset - 表示是否需要向对端设备发送 reset 数据包
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_abandon(struct tcp_pcb *pcb, int reset)
{
  u32_t seqno, ackno;
  
#if LWIP_CALLBACK_API
  tcp_err_fn errf;
#endif /* LWIP_CALLBACK_API */

  void *errf_arg;

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("tcp_abandon: invalid pcb", pcb != NULL, return);

  /* pcb->state LISTEN not allowed here */
  LWIP_ASSERT("don't call tcp_abort/tcp_abandon for listen-pcbs",
              pcb->state != LISTEN);
  
  /* Figure out on which TCP PCB list we are, and remove us. If we
     are in an active state, call the receive function associated with
     the PCB with a NULL argument, and send an RST to the remote end. */
  if (pcb->state == TIME_WAIT) {
  	/* 把指定的 tcp 协议控制块从 tcp_tw_pcbs 协议控制块链表上移除，并释放这个 tcp 协议控制
     * 块的所有缓存数据、把这个 tcp 协议控制块的延迟发送应答数据包立即发送出去，然后设置这
     * 个 tcp 协议控制块的状态和本地端口号分别为 CLOSED 和 0 */
    tcp_pcb_remove(&tcp_tw_pcbs, pcb);
    tcp_free(pcb);
  } else {
    int send_rst = 0;
    u16_t local_port = 0;
    enum tcp_state last_state;
    seqno = pcb->snd_nxt;
    ackno = pcb->rcv_nxt;
	
#if LWIP_CALLBACK_API
    errf = pcb->errf;
#endif /* LWIP_CALLBACK_API */

    errf_arg = pcb->callback_arg;

    if (pcb->state == CLOSED) {
      if (pcb->local_port != 0) {
        /* bound, not yet opened */
		/* 把指定的 tcp 协议控制块从 tcp_bound_pcbs 协议控制块链表上移除 */
        TCP_RMV(&tcp_bound_pcbs, pcb);
      }
    } else {
      send_rst = reset;
      local_port = pcb->local_port;
	  /* 把指定的 tcp 协议控制块从当前协议栈的 tcp_active_pcbs 链表中移除并释放这个 tcp 协议控制块
	   * 的所有缓存数据、把这个 tcp 协议控制块的延迟发送应答数据包立即发送出去，然后设置这个 tcp 协
	   * 议控制块的状态和本地端口号分别为 CLOSED 和 0	*/
      TCP_PCB_REMOVE_ACTIVE(pcb);
    }
	
	/* 释放 pcb->unacked tcp 分片数据包链表所占用的内存资源 */
    if (pcb->unacked != NULL) {
      tcp_segs_free(pcb->unacked);
    }
	
	/* 释放 pcb->unsent tcp 分片数据包链表所占用的内存资源 */
    if (pcb->unsent != NULL) {
      tcp_segs_free(pcb->unsent);
    }
	
/* 释放 pcb->ooseq tcp 分片数据包链表所占用的内存资源 */
#if TCP_QUEUE_OOSEQ
    if (pcb->ooseq != NULL) {
      tcp_segs_free(pcb->ooseq);
    }
#endif /* TCP_QUEUE_OOSEQ */

    /* 尝试减小指定的 tcp 协议控制块所属监听者的 backlog 计数值 */
    tcp_backlog_accepted(pcb);
    if (send_rst) {
      LWIP_DEBUGF(TCP_RST_DEBUG, ("tcp_abandon: sending RST\n"));
      tcp_rst(pcb, seqno, ackno, &pcb->local_ip, &pcb->remote_ip, local_port, pcb->remote_port);
    }
	
    last_state = pcb->state;
    tcp_free(pcb);
    TCP_EVENT_ERR(last_state, errf, errf_arg, ERR_ABRT);
  }
}

/**
 * @ingroup tcp_raw
 * Aborts the connection by sending a RST (reset) segment to the remote
 * host. The pcb is deallocated. This function never fails.
 *
 * ATTENTION: When calling this from one of the TCP callbacks, make
 * sure you always return ERR_ABRT (and never return ERR_ABRT otherwise
 * or you will risk accessing deallocated memory or memory leaks!
 *
 * @param pcb the tcp pcb to abort
 */ 
/*********************************************************************************************************
** 函数名称: tcp_abort
** 功能描述: 通过发送 reset 数据包来终止指定的 tcp 协议控制块的 tcp 连接，并释放指定的 tcp 协议
**         : 控制块结构占用的内存空间
** 输	 入: pcb - 需要被终止的 tcp 协议控制块
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_abort(struct tcp_pcb *pcb)
{
  /* 释放指定 tcp 协议控制块数据队列中的数据包并关闭这个 tcp 协议控制块的连接，并根据指定的
   * 参数决定是否发送 reset 数据包到对端设备 */
  tcp_abandon(pcb, 1);
}

/**
 * @ingroup tcp_raw
 * Binds the connection to a local port number and IP address. If the
 * IP address is not given (i.e., ipaddr == IP_ANY_TYPE), the connection is
 * bound to all local IP addresses.
 * If another connection is bound to the same port, the function will
 * return ERR_USE, otherwise ERR_OK is returned.
 *
 * @param pcb the tcp_pcb to bind (no check is done whether this pcb is
 *        already bound!)
 * @param ipaddr the local ip address to bind to (use IPx_ADDR_ANY to bind
 *        to any local address
 * @param port the local port to bind to
 * @return ERR_USE if the port is already in use
 *         ERR_VAL if bind failed because the PCB is not in a valid state
 *         ERR_OK if bound
 */
/*********************************************************************************************************
** 函数名称: tcp_bind
** 功能描述: 把指定的 tcp 协议控制块绑定到指定的本地 IPv4 地址和指定的本地端口号，如果没指定 IPv4 地址
**         : 则将其设置为 ANY，如果没指定本地端口号，则从系统中申请一个空闲的
** 注     释: 当前协议栈的 tcp 模块支持 SOF_REUSEADDR 选项
** 输	 入: pcb - 需要绑定本地 IPv4 地址和本地端口号的 tcp 协议控制块
**		   : ipaddr - 需要绑定的本地 IPv4 地址
**		   : port - 需要绑定的本地端口号
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{
  int i;
  int max_pcb_list = NUM_TCP_PCB_LISTS;
  struct tcp_pcb *cpcb;
  
#if LWIP_IPV6 && LWIP_IPV6_SCOPES
  ip_addr_t zoned_ipaddr;
#endif /* LWIP_IPV6 && LWIP_IPV6_SCOPES */

  LWIP_ASSERT_CORE_LOCKED();

/* 如果没指定 IPv4 地址，则将其设置为 ANY */
#if LWIP_IPV4
  /* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
  if (ipaddr == NULL) {
    ipaddr = IP4_ADDR_ANY;
  }
#else /* LWIP_IPV4 */
  LWIP_ERROR("tcp_bind: invalid ipaddr", ipaddr != NULL, return ERR_ARG);
#endif /* LWIP_IPV4 */

  LWIP_ERROR("tcp_bind: invalid pcb", pcb != NULL, return ERR_ARG);

  LWIP_ERROR("tcp_bind: can only bind in state CLOSED", pcb->state == CLOSED, return ERR_VAL);

#if SO_REUSE
  /* Unless the REUSEADDR flag is set,
     we have to check the pcbs in TIME-WAIT state, also.
     We do not dump TIME_WAIT pcb's; they can still be matched by incoming
     packets using both local and remote IP addresses and ports to distinguish.
   */
  if (ip_get_option(pcb, SOF_REUSEADDR)) {
    max_pcb_list = NUM_TCP_PCB_LISTS_NO_TIME_WAIT;
  }
#endif /* SO_REUSE */

#if LWIP_IPV6 && LWIP_IPV6_SCOPES
  /* If the given IP address should have a zone but doesn't, assign one now.
   * This is legacy support: scope-aware callers should always provide properly
   * zoned source addresses. Do the zone selection before the address-in-use
   * check below; as such we have to make a temporary copy of the address. */
  if (IP_IS_V6(ipaddr) && ip6_addr_lacks_zone(ip_2_ip6(ipaddr), IP6_UNICAST)) {
    ip_addr_copy(zoned_ipaddr, *ipaddr);
    ip6_addr_select_zone(ip_2_ip6(&zoned_ipaddr), ip_2_ip6(&zoned_ipaddr));
    ipaddr = &zoned_ipaddr;
  }
#endif /* LWIP_IPV6 && LWIP_IPV6_SCOPES */

  /* 如果没指定端口号，则从当前系统内申请一个空闲端口号 */
  if (port == 0) {
    port = tcp_new_port();
    if (port == 0) {
      return ERR_BUF;
    }
  } else {
    /* Check if the address already is in use (on all lists) */
    /* 遍历当前系统内所有 tcp 协议控制块链表中的每一个 tcp 协议控制块，判断当前绑定的
	 * 本地端口号和系统内已经存在的本地端口号是否有冲突，如果有冲突则返回 ERR_USE */
    for (i = 0; i < max_pcb_list; i++) {
      for (cpcb = *tcp_pcb_lists[i]; cpcb != NULL; cpcb = cpcb->next) {
        if (cpcb->local_port == port) {
#if SO_REUSE
          /* Omit checking for the same port if both pcbs have REUSEADDR set.
             For SO_REUSEADDR, the duplicate-check for a 5-tuple is done in
             tcp_connect. */
          /* 如果当前遍历的 tcp 协议控制块和我们绑定的 tcp 协议控制块二者其中有任何一个
           * 没设置 SOF_REUSEADDR 选项，则需要校验地址使用是否冲突 */
          if (!ip_get_option(pcb, SOF_REUSEADDR) ||
              !ip_get_option(cpcb, SOF_REUSEADDR))
#endif /* SO_REUSE */
          {
            /* @todo: check accept_any_ip_version */
            if ((IP_IS_V6(ipaddr) == IP_IS_V6_VAL(cpcb->local_ip)) &&
                (ip_addr_isany(&cpcb->local_ip) ||
                 ip_addr_isany(ipaddr) ||
                 ip_addr_cmp(&cpcb->local_ip, ipaddr))) {
              return ERR_USE;
            }
          }
        }
      }
    }
  }

  if (!ip_addr_isany(ipaddr)
#if LWIP_IPV4 && LWIP_IPV6
      || (IP_GET_TYPE(ipaddr) != IP_GET_TYPE(&pcb->local_ip))
#endif /* LWIP_IPV4 && LWIP_IPV6 */
     ) {
    ip_addr_set(&pcb->local_ip, ipaddr);
  }

  pcb->local_port = port;
  
  /* 把指定的 tcp 协议控制块注册到 tcp_bound_pcbs 协议控制块链表中 */
  TCP_REG(&tcp_bound_pcbs, pcb);
  
  LWIP_DEBUGF(TCP_DEBUG, ("tcp_bind: bind to port %"U16_F"\n", port));
  return ERR_OK;
}

/**
 * @ingroup tcp_raw
 * Binds the connection to a netif and IP address.
 * After calling this function, all packets received via this PCB
 * are guaranteed to have come in via the specified netif, and all
 * outgoing packets will go out via the specified netif.
 *
 * @param pcb the tcp_pcb to bind.
 * @param netif the netif to bind to. Can be NULL.
 */
/*********************************************************************************************************
** 函数名称: tcp_bind_netif
** 功能描述: 把指定的 tcp 协议控制块和指定的网络接口绑定到一起
** 注     释: 当前协议栈的 tcp 模块支持 SOF_REUSEADDR 选项
** 输	 入: pcb - 需要绑定网络接口的 tcp 协议控制块
**		   : netif - 需要绑定的网络接口指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_bind_netif(struct tcp_pcb *pcb, const struct netif *netif)
{
  LWIP_ASSERT_CORE_LOCKED();
  if (netif != NULL) {
    pcb->netif_idx = netif_get_index(netif);
  } else {
    pcb->netif_idx = NETIF_NO_INDEX;
  }
}

#if LWIP_CALLBACK_API
/**
 * Default accept callback if no accept callback is specified by the user.
 */
/*********************************************************************************************************
** 函数名称: tcp_accept_null
** 功能描述: 如果当前系统没指定 accept 回调函数，则使用这个默认的函数
** 注     释: 当前协议栈的 tcp 模块支持 SOF_REUSEADDR 选项
** 输	 入: arg - 
**         : pcb - 收到链接请求的 tcp 协议控制块
**		   : err - 
** 输	 出: ERR_ABRT - 表示不接受当前的 tcp 连接请求
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
tcp_accept_null(void *arg, struct tcp_pcb *pcb, err_t err)
{
  LWIP_UNUSED_ARG(arg);
  LWIP_UNUSED_ARG(err);

  LWIP_ASSERT("tcp_accept_null: invalid pcb", pcb != NULL);

  /* 通过发送 reset 数据包来终止指定的 tcp 协议控制块的 tcp 连接，并释放指定的 tcp 协议
   * 控制块结构占用的内存空间 */
  tcp_abort(pcb);

  return ERR_ABRT;
}
#endif /* LWIP_CALLBACK_API */

/**
 * @ingroup tcp_raw
 * Set the state of the connection to be LISTEN, which means that it
 * is able to accept incoming connections. The protocol control block
 * is reallocated in order to consume less memory. Setting the
 * connection to LISTEN is an irreversible process.
 * When an incoming connection is accepted, the function specified with
 * the tcp_accept() function will be called. The pcb has to be bound
 * to a local port with the tcp_bind() function.
 * 
 * The tcp_listen() function returns a new connection identifier, and
 * the one passed as an argument to the function will be
 * deallocated. The reason for this behavior is that less memory is
 * needed for a connection that is listening, so tcp_listen() will
 * reclaim the memory needed for the original connection and allocate a
 * new smaller memory block for the listening connection.
 *
 * tcp_listen() may return NULL if no memory was available for the
 * listening connection. If so, the memory associated with the pcb
 * passed as an argument to tcp_listen() will not be deallocated.
 *
 * The backlog limits the number of outstanding connections
 * in the listen queue to the value specified by the backlog argument.
 * To use it, your need to set TCP_LISTEN_BACKLOG=1 in your lwipopts.h.
 * 
 * @param pcb the original tcp_pcb
 * @param backlog the incoming connections queue limit
 * @return tcp_pcb used for listening, consumes less memory.
 *
 * @note The original tcp_pcb is freed. This function therefore has to be
 *       called like this:
 *             tpcb = tcp_listen_with_backlog(tpcb, backlog);
 */
/*********************************************************************************************************
** 函数名称: tcp_listen_with_backlog
** 功能描述: 把指定的 tcp 协议控制块转换成与其对应的  listen tcp 协议控制块并设置其 backlog 阈值
** 输	 入: pcb - 需要转换为 listen tcp 协议控制块的 tcp 协议控制块指针
**         : backlog - 新的 listen tcp 协议控制块的 backlog 阈值
** 输	 出: lpcb - 转换后的 listen tcp 协议控制块
**         : NULL - 执行失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct tcp_pcb *
tcp_listen_with_backlog(struct tcp_pcb *pcb, u8_t backlog)
{
  LWIP_ASSERT_CORE_LOCKED();

  /* 把指定的 tcp 协议控制块转换成与其对应的  listen tcp 协议控制块并设置其 backlog 阈值 */
  return tcp_listen_with_backlog_and_err(pcb, backlog, NULL);
}

/**
 * @ingroup tcp_raw
 * Set the state of the connection to be LISTEN, which means that it
 * is able to accept incoming connections. The protocol control block
 * is reallocated in order to consume less memory. Setting the
 * connection to LISTEN is an irreversible process.
 *
 * @param pcb the original tcp_pcb
 * @param backlog the incoming connections queue limit
 * @param err when NULL is returned, this contains the error reason
 * @return tcp_pcb used for listening, consumes less memory.
 *
 * @note The original tcp_pcb is freed. This function therefore has to be
 *       called like this:
 *             tpcb = tcp_listen_with_backlog_and_err(tpcb, backlog, &err);
 */
/*********************************************************************************************************
** 函数名称: tcp_listen_with_backlog_and_err
** 功能描述: 把指定的 tcp 协议控制块转换成与其对应的  listen tcp 协议控制块并设置其 backlog 阈值
** 输	 入: pcb - 需要转换为 listen tcp 协议控制块的 tcp 协议控制块指针
**         : backlog - 新的 listen tcp 协议控制块的 backlog 阈值
** 输	 出: lpcb - 转换后的 listen tcp 协议控制块
**         : NULL - 执行失败
**         : err - 执行失败错误码
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct tcp_pcb *
tcp_listen_with_backlog_and_err(struct tcp_pcb *pcb, u8_t backlog, err_t *err)
{
  struct tcp_pcb_listen *lpcb = NULL;
  err_t res;

  LWIP_UNUSED_ARG(backlog);

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("tcp_listen_with_backlog_and_err: invalid pcb", pcb != NULL, res = ERR_ARG; goto done);
  LWIP_ERROR("tcp_listen_with_backlog_and_err: pcb already connected", pcb->state == CLOSED, res = ERR_CLSD; goto done);

  /* already listening? */
  /* 判断指定的 tcp 协议控制块是否已经处于 listen 装套，如果是则直接返回 ERR_ALREADY 成功 */
  if (pcb->state == LISTEN) {
    lpcb = (struct tcp_pcb_listen *)pcb;
    res = ERR_ALREADY;
    goto done;
  }

/* 因为处于 listen 状态的 tcp 协议控制块不可以复用地址信息，所以校验当前系统内
 * tcp_listen_pcbs.listen_pcbs 链表上的成员和当前指定的 tcp 协议控制块地址是否
 * 存在复用关系，如果有则直接返回 ERR_USE 失败 */
#if SO_REUSE
  if (ip_get_option(pcb, SOF_REUSEADDR)) {
    /* Since SOF_REUSEADDR allows reusing a local address before the pcb's usage
       is declared (listen-/connection-pcb), we have to make sure now that
       this port is only used once for every local IP. */
    for (lpcb = tcp_listen_pcbs.listen_pcbs; lpcb != NULL; lpcb = lpcb->next) {
      if ((lpcb->local_port == pcb->local_port) &&
          ip_addr_cmp(&lpcb->local_ip, &pcb->local_ip)) {
        /* this address/port is already used */
        lpcb = NULL;
        res = ERR_USE;
        goto done;
      }
    }
  }
#endif /* SO_REUSE */

  /* 申请一个 listen tcp 结构，用来管理系统内所有处于 listen 状态的 tcp 协议控制块 */
  lpcb = (struct tcp_pcb_listen *)memp_malloc(MEMP_TCP_PCB_LISTEN);
  if (lpcb == NULL) {
    res = ERR_MEM;
    goto done;
  }

  /* 初始化当前 listen tcp 协议控制块 */
  lpcb->callback_arg = pcb->callback_arg;
  lpcb->local_port = pcb->local_port;
  lpcb->state = LISTEN;
  lpcb->prio = pcb->prio;
  lpcb->so_options = pcb->so_options;
  lpcb->netif_idx = NETIF_NO_INDEX;
  lpcb->ttl = pcb->ttl;
  lpcb->tos = pcb->tos;
  
#if LWIP_IPV4 && LWIP_IPV6
  IP_SET_TYPE_VAL(lpcb->remote_ip, pcb->local_ip.type);
#endif /* LWIP_IPV4 && LWIP_IPV6 */

  ip_addr_copy(lpcb->local_ip, pcb->local_ip);

  /* 如果当前 tcp 协议控制块之前在 tcp_bound_pcbs 链表中，则将其从中移除 */
  if (pcb->local_port != 0) {
    TCP_RMV(&tcp_bound_pcbs, pcb);
  }
  
#if LWIP_TCP_PCB_NUM_EXT_ARGS
  /* copy over ext_args to listening pcb  */
  memcpy(&lpcb->ext_args, &pcb->ext_args, sizeof(pcb->ext_args));
#endif

  /* 释放之前的 tcp 协议控制块，因为我们现在使用刚申请的 listen tcp 结构，所以
   * 之前的就可以被释放了 */
  tcp_free(pcb);

#if LWIP_CALLBACK_API
  lpcb->accept = tcp_accept_null;
#endif /* LWIP_CALLBACK_API */

/* 设置当前 listen tcp 的 backlog 阈值 */
#if TCP_LISTEN_BACKLOG
  lpcb->accepts_pending = 0;
  tcp_backlog_set(lpcb, backlog);
#endif /* TCP_LISTEN_BACKLOG */

  /* 把当前的 listen tcp 协议控制块注册到 tcp_listen_pcbs.pcbs tcp 协议控制块链表中 */
  TCP_REG(&tcp_listen_pcbs.pcbs, (struct tcp_pcb *)lpcb);
  res = ERR_OK;
  
done:
  if (err != NULL) {
    *err = res;
  }
  return (struct tcp_pcb *)lpcb;
}

/**
 * Update the state that tracks the available window space to advertise.
 *
 * Returns how much extra window would be advertised if we sent an
 * update now.
 */ 
/*********************************************************************************************************
** 函数名称: tcp_update_rcv_ann_wnd
** 功能描述: 计算并更新指定的 tcp 协议控制块的接收窗口大小，并返回接收窗口右边界可以增加的字节数
** 输	 入: pcb - 需要更新接收窗口的 tcp 协议控制块
** 输	 出: u32_t - 表示指定的 tcp 协议控制块的接收窗口右边界可以增加的字节数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u32_t
tcp_update_rcv_ann_wnd(struct tcp_pcb *pcb)
{
  u32_t new_right_edge;

  LWIP_ASSERT("tcp_update_rcv_ann_wnd: invalid pcb", pcb != NULL);

  /* 计算当前 tcp 协议控制块的接收窗口的右边界值 */
  new_right_edge = pcb->rcv_nxt + pcb->rcv_wnd;

  /* 计算并更新指定的 tcp 协议控制块的接收窗口大小，并返回接收窗口右边界可以增加的字节数 */
  if (TCP_SEQ_GEQ(new_right_edge, pcb->rcv_ann_right_edge + LWIP_MIN((TCP_WND / 2), pcb->mss))) {
    /* we can advertise more window */
    pcb->rcv_ann_wnd = pcb->rcv_wnd;
    return new_right_edge - pcb->rcv_ann_right_edge;
  } else {
    if (TCP_SEQ_GT(pcb->rcv_nxt, pcb->rcv_ann_right_edge)) {
      /* Can happen due to other end sending out of advertised window,
       * but within actual available (but not yet advertised) window */
      pcb->rcv_ann_wnd = 0;
    } else {
      /* keep the right edge of window constant */
      u32_t new_rcv_ann_wnd = pcb->rcv_ann_right_edge - pcb->rcv_nxt;
	  
#if !LWIP_WND_SCALE
      LWIP_ASSERT("new_rcv_ann_wnd <= 0xffff", new_rcv_ann_wnd <= 0xffff);
#endif

      pcb->rcv_ann_wnd = (tcpwnd_size_t)new_rcv_ann_wnd;
    }
    return 0;
  }
}

/**
 * @ingroup tcp_raw
 * This function should be called by the application when it has
 * processed the data. The purpose is to advertise a larger window
 * when the data has been processed.
 *
 * @param pcb the tcp_pcb for which data is read
 * @param len the amount of bytes that have been read by the application
 */
/*********************************************************************************************************
** 函数名称: tcp_recved
** 功能描述: 在应用层处理完接收到的数据时调用，用来增加本地设备的数据接收窗口并通知对端设备
** 输	 入: pcb - 表示应用层处理的数据所属的 tcp 协议控制块
**         : len - 表示应用层已经处理的数据字节数
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_recved(struct tcp_pcb *pcb, u16_t len)
{
  u32_t wnd_inflation;
  tcpwnd_size_t rcv_wnd;

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("tcp_recved: invalid pcb", pcb != NULL, return);

  /* pcb->state LISTEN not allowed here */
  LWIP_ASSERT("don't call tcp_recved for listen-pcbs",
              pcb->state != LISTEN);

  /* 调整当前 tcp 协议控制块的接收数据窗口大小 */
  rcv_wnd = pcb->rcv_wnd + len;
  if (rcv_wnd < pcb->rcv_wnd || (len != 0 && rcv_wnd == pcb->rcv_wnd)) {
    /* rcv_wnd overflowed */
    if (TCP_STATE_IS_CLOSING(pcb->state)) {
      /* In passive close, we allow this, since the FIN bit is added to rcv_wnd
         by the stack itself, since it is not mandatory for an application
         to call tcp_recved() for the FIN bit, but e.g. the netconn API does so. */
      pcb->rcv_wnd = TCP_WND_MAX(pcb);
    } else {
      LWIP_ASSERT("tcp_recved: len wrapped rcv_wnd\n", 0);
    }
  } else if (rcv_wnd <= TCP_WND_MAX(pcb)) {
    pcb->rcv_wnd = rcv_wnd;
  } else {
    LWIP_ASSERT("tcp_recved: len overflowed TCP_WND_MAX",
		rcv_wnd <= TCP_WND_MAX(pcb));
    pcb->rcv_wnd = TCP_WND_MAX(pcb);
  }

  /* 计算并更新指定的 tcp 协议控制块的接收窗口大小，并返回接收窗口右边界可以增加的字节数 */
  wnd_inflation = tcp_update_rcv_ann_wnd(pcb);

  /* If the change in the right edge of window is significant (default
   * watermark is TCP_WND/4), then send an explicit update now.
   * Otherwise wait for a packet to be sent in the normal course of
   * events (or more window to be available later) */
  /* 如果当前接收数据窗口调整值超过了预先设定的阈值，则立即发送一个窗口更新数据包，否则延迟
   * 发送接收数据窗口更新信息（由之后发送的数据包携带）*/
  if (wnd_inflation >= TCP_WND_UPDATE_THRESHOLD) {
    tcp_ack_now(pcb);
    tcp_output(pcb);
  }

  LWIP_DEBUGF(TCP_DEBUG, ("tcp_recved: received %"U16_F" bytes, wnd %"TCPWNDSIZE_F" (%"TCPWNDSIZE_F").\n",
                          len, pcb->rcv_wnd, (u16_t)(TCP_WND_MAX(pcb) - pcb->rcv_wnd)));
}

/**
 * Allocate a new local TCP port.
 *
 * @return a new (free) local TCP port number
 */
/*********************************************************************************************************
** 函数名称: tcp_new_port
** 功能描述: 从当前系统内申请一个空闲未使用的 tcp 端口号
** 输	 入: 
** 输	 出: tcp_port - 成功申请到的空闲 tcp 端口号
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static u16_t
tcp_new_port(void)
{
  u8_t i;
  u16_t n = 0;
  struct tcp_pcb *pcb;

again:
  tcp_port++;
  if (tcp_port == TCP_LOCAL_PORT_RANGE_END) {
    tcp_port = TCP_LOCAL_PORT_RANGE_START;
  }
  /* Check all PCB lists. */
  for (i = 0; i < NUM_TCP_PCB_LISTS; i++) {
    for (pcb = *tcp_pcb_lists[i]; pcb != NULL; pcb = pcb->next) {
      if (pcb->local_port == tcp_port) {
        n++;
        if (n > (TCP_LOCAL_PORT_RANGE_END - TCP_LOCAL_PORT_RANGE_START)) {
          return 0;
        }
        goto again;
      }
    }
  }
  return tcp_port;
}

/**
 * @ingroup tcp_raw
 * Connects to another host. The function given as the "connected"
 * argument will be called when the connection has been established.
 * Sets up the pcb to connect to the remote host and sends the
 * initial SYN segment which opens the connection. 
 *
 * The tcp_connect() function returns immediately; it does not wait for
 * the connection to be properly setup. Instead, it will call the
 * function specified as the fourth argument (the "connected" argument)
 * when the connection is established. If the connection could not be
 * properly established, either because the other host refused the
 * connection or because the other host didn't answer, the "err"
 * callback function of this pcb (registered with tcp_err, see below)
 * will be called.
 *
 * The tcp_connect() function can return ERR_MEM if no memory is
 * available for enqueueing the SYN segment. If the SYN indeed was
 * enqueued successfully, the tcp_connect() function returns ERR_OK.
 *
 * @param pcb the tcp_pcb used to establish the connection
 * @param ipaddr the remote ip address to connect to
 * @param port the remote tcp port to connect to
 * @param connected callback function to call when connected (on error,
                    the err calback will be called)
 * @return ERR_VAL if invalid arguments are given
 *         ERR_OK if connect request has been sent
 *         other err_t values if connect request couldn't be sent
 */
/*********************************************************************************************************
** 函数名称: tcp_connect
** 功能描述: 根据函数参数初始化指定的 tcp 协议控制块并发送一个 SYN 建立连接请求数据包到指定的对端设备
** 输	 入: pcb - 需要和对端设备建立连接的 tcp 协议控制块
**         : ipaddr - 对端设备的 IP 地址
**         : port - 对端设备的端口号
**         : connected - 表示当前 tcp 协议控制块成功建立连接时需要调用的回调函数指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
tcp_connect(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port,
            tcp_connected_fn connected)
{
  struct netif *netif = NULL;
  err_t ret;
  u32_t iss;
  u16_t old_local_port;

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("tcp_connect: invalid pcb", pcb != NULL, return ERR_ARG);
  LWIP_ERROR("tcp_connect: invalid ipaddr", ipaddr != NULL, return ERR_ARG);

  LWIP_ERROR("tcp_connect: can only connect from state CLOSED", pcb->state == CLOSED, return ERR_ISCONN);

  LWIP_DEBUGF(TCP_DEBUG, ("tcp_connect to port %"U16_F"\n", port));
  
  ip_addr_set(&pcb->remote_ip, ipaddr);
  pcb->remote_port = port;

  /* 选择发送 SYN 连接请求数据包的网络接口设备 */
  if (pcb->netif_idx != NETIF_NO_INDEX) {
    netif = netif_get_by_index(pcb->netif_idx);
  } else {
    /* check if we have a route to the remote host */
    netif = ip_route(&pcb->local_ip, &pcb->remote_ip);
  }
  
  if (netif == NULL) {
    /* Don't even try to send a SYN packet if we have no route since that will fail. */
    return ERR_RTE;
  }

  /* check if local IP has been assigned to pcb, if not, get one */
  /* 如果当前 tcp 协议控制块没有绑定本地 IP 地址，则使用当前选择的网络接口的 IP 地址作为这个
   * tcp 协议控制块的绑定本地 IP 地址 */
  if (ip_addr_isany(&pcb->local_ip)) {
    const ip_addr_t *local_ip = ip_netif_get_local_ip(netif, ipaddr);
    if (local_ip == NULL) {
      return ERR_RTE;
    }
    ip_addr_copy(pcb->local_ip, *local_ip);
  }

#if LWIP_IPV6 && LWIP_IPV6_SCOPES
  /* If the given IP address should have a zone but doesn't, assign one now.
   * Given that we already have the target netif, this is easy and cheap. */
  if (IP_IS_V6(&pcb->remote_ip) &&
      ip6_addr_lacks_zone(ip_2_ip6(&pcb->remote_ip), IP6_UNICAST)) {
    ip6_addr_assign_zone(ip_2_ip6(&pcb->remote_ip), IP6_UNICAST, netif);
  }
#endif /* LWIP_IPV6 && LWIP_IPV6_SCOPES */

  old_local_port = pcb->local_port;

  /* 如果当前 tcp 协议控制块没有绑定本地端口号，则从系统内申请一个空闲未使用的 tcp 端口号
   * 作为这个tcp 协议控制块的绑定本地端口号 */
  if (pcb->local_port == 0) {
    pcb->local_port = tcp_new_port();
    if (pcb->local_port == 0) {
      return ERR_BUF;
    }
  } else {

/* 如果当前 tcp 协议控制块启用了 SOF_REUSEADDR 选项，则判断当前 tcp 协议控制块和系统内的
 * active- and TIME-WAIT 协议控制块的五元组是否有冲突，如果有冲突则返回 ERR_USE 错误 */
#if SO_REUSE
    if (ip_get_option(pcb, SOF_REUSEADDR)) {
      /* Since SOF_REUSEADDR allows reusing a local address, we have to make sure
         now that the 5-tuple is unique. */
      struct tcp_pcb *cpcb;
      int i;
	
      /* Don't check listen- and bound-PCBs, check active- and TIME-WAIT PCBs. */
      for (i = 2; i < NUM_TCP_PCB_LISTS; i++) {
        for (cpcb = *tcp_pcb_lists[i]; cpcb != NULL; cpcb = cpcb->next) {
          if ((cpcb->local_port == pcb->local_port) &&
              (cpcb->remote_port == port) &&
              ip_addr_cmp(&cpcb->local_ip, &pcb->local_ip) &&
              ip_addr_cmp(&cpcb->remote_ip, ipaddr)) {
            /* linux returns EISCONN here, but ERR_USE should be OK for us */
            return ERR_USE;
          }
        }
      }
    }
#endif /* SO_REUSE */

  }

  /* 为新建立的、指定的 tcp 协议控制块分配一个 ISN（Initial Sequence Number）*/
  iss = tcp_next_iss(pcb);

  /* 初始化当前需要建立 tcp 连接的 tcp 协议控制块 */
  pcb->rcv_nxt = 0;
  pcb->snd_nxt = iss;
  pcb->lastack = iss - 1;
  pcb->snd_wl2 = iss - 1;
  pcb->snd_lbb = iss - 1;
  /* Start with a window that does not need scaling. When window scaling is
     enabled and used, the window is enlarged when both sides agree on scaling. */
  pcb->rcv_wnd = pcb->rcv_ann_wnd = TCPWND_MIN16(TCP_WND);
  pcb->rcv_ann_right_edge = pcb->rcv_nxt;
  pcb->snd_wnd = TCP_WND;
  /* As initial send MSS, we use TCP_MSS but limit it to 536.
     The send MSS is updated when an MSS option is received. */
  pcb->mss = INITIAL_MSS;
  
#if TCP_CALCULATE_EFF_SEND_MSS
  /* 通过当前 tcp mss 和指定网络接口的 mtu 计算到指定目的 IP 地址处的有效 mss */
  pcb->mss = tcp_eff_send_mss_netif(pcb->mss, netif, &pcb->remote_ip);
#endif /* TCP_CALCULATE_EFF_SEND_MSS */

  pcb->cwnd = 1;

#if LWIP_CALLBACK_API
  pcb->connected = connected;
#else /* LWIP_CALLBACK_API */
  LWIP_UNUSED_ARG(connected);
#endif /* LWIP_CALLBACK_API */

  /* Send a SYN together with the MSS option. */
  /* 为当前的 tcp 协议控制块发送一个 SYN 建立连接请求的数据包，此函数只是把要发送的 
   * tcp 分片数据包添加到指定的 tcp 协议控制块的未发送数据队列中 */
  ret = tcp_enqueue_flags(pcb, TCP_SYN);
  if (ret == ERR_OK) {
    /* SYN segment was enqueued, changed the pcbs state now */
    pcb->state = SYN_SENT;
    if (old_local_port != 0) {
      TCP_RMV(&tcp_bound_pcbs, pcb);
    }

	/* 把当前 tcp 协议控制块添插入到当前协议栈的 tcp_active_pcbs 链表中 */
    TCP_REG_ACTIVE(pcb);
    MIB2_STATS_INC(mib2.tcpactiveopens);

    /* 开始发送在当前 tcp 协议控制块的未发送数据队列中 SYN 数据包 */
    tcp_output(pcb);
  }
  return ret;
}

/**
 * Called every 500 ms and implements the retransmission timer and the timer that
 * removes PCBs that have been in TIME-WAIT for enough time. It also increments
 * various timers such as the inactivity timer in each PCB.
 *
 * Automatically called from tcp_tmr().
 */
/*********************************************************************************************************
** 函数名称: tcp_slowtmr
** 功能描述: tcp 协议模块的慢速定时器超时函数，超时周期默认为 500ms，具体指定操作如下：
**         : 1. 递增 tcp 协议模块基准定时器计数值 tcp_ticks
**         : 2. 递增 tcp 协议模块 x 定时器计数值 tcp_timer_ctr
**         : 3. 分别遍历当前系统 tcp_active_pcbs 链表中的每一个 tcp 协议控制块，并对其做如下处理：
**         :    a. 如果重复发送 SYN 请求数据包次数超过预先设定的阈值，则释放这个 tcp 协议控制块
**         :    b. 如果“连续”启动重传数据包的次数超过预先设定的阈值，则释放这个 tcp 协议控制块
**         :    c. 如果上面两条都没执行，则执行如下操作：
**         :       I.  如果 tcp 协议控制块"启动"了坚持定时器，则执行如下操作：
**         :           1. 如果当前 tcp 协议控制块发送窗口探测数据包的次数超过预先设定的阈值，则释放这个 
**         :              tcp 协议控制块
**         :           2. 如果坚持定时器已经超时且当前 tcp 协议控制块发送窗口“为 0”，则发送一个“窗口探测”
**         :              数据包如果坚持定时器已经超时但是当前 tcp 协议控制块发送窗口“不为 0”，则把当前 tcp
**         :              协议控制块的未发送数据队列的第一个分片数据包按照当前 tcp 协议控制块发送窗口大小进
**         :              行分割，把分割后的数据包封装成 tcp 分片数据包，并通过链表按照原来顺序链接起来，然
**         :              后执行数据包发送操作发送数据包的时候会关闭当前 tcp 协议控制块的坚持定时器
**         :       II. 如果 tcp 协议控制块“没启动"坚持定时器，则执行如下操作：
**         :           1. 如果当前 tcp 协议控制块启动了超时重传定时器，则递增超时重传定时器计数值
**         :           2. 如果当前 tcp 协议控制块已经是发送超时状态，则尝试重新发送那些发送失败的数据包，同
**         :              时把当前 tcp 协议控制块的慢启动阈值设置为 LWIP_MIN(pcb->cwnd, pcb->snd_wnd) 的一半
**         :              大小（但是慢启动阈值不能低于 2 个 pcb->mss 大小），并把当前 tcp 协议控制块的拥塞窗
**         :              口设置为 pcb->mss 大小
**         :    d. 如果当前 tcp 协议控制块处于 FIN_WAIT_2 状态的时间太长且已经关闭接收数据端连接，则释放这个 
**         :       tcp 协议控制块
**         :    e. 如果当前 tcp 协议控制块开启了长连接功能，则处理和长连接相关事件，相关事件如下：
**         :       I.  如果当前 tcp 协议控制块处于长连接且空闲时间超过了预先设定的阈值，则释放这个 tcp 协议
**         :           控制块
**         :       II. 如果当前 tcp 协议控制块处于长连接时间达到了发送长连接数据包的时间周期，则发送长连接
**         :           “保活探测”数据包
**         :    f. 如果当前 tcp 协议控制块的乱序数据包队列中是数据包存在时间超过了预先设定的阈值，则释放这
**         :       些数据包
**         :    g. 如果当前 tcp 协议控制块处于 SYN_RCVD 状态的时间太长，则释放这个 tcp 协议控制块
**         :    h. 如果当前 tcp 协议控制块处于 LAST_ACK 状态的时间太长，则释放这个 tcp 协议控制块
**         : 4. 遍历当前系统 tcp_tw_pcbs 链表中的 tcp 协议控制块，分别判断每一个 tcp 协议控制块处于 TIME_WAIT
**         :    状态时间是否已经超过 2 * TCP_MSL，如果超过了 2 * TCP_MSL，则释放对应的 tcp 协议控制块结构
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_slowtmr(void)
{
  struct tcp_pcb *pcb, *prev;
  tcpwnd_size_t eff_wnd;
  u8_t pcb_remove;      /* flag if a PCB should be removed */
  u8_t pcb_reset;       /* flag if a RST should be sent when removing */
  err_t err;

  err = ERR_OK;

  ++tcp_ticks;
  ++tcp_timer_ctr;

tcp_slowtmr_start:
  /* Steps through all of the active PCBs. */
  prev = NULL;
  pcb = tcp_active_pcbs;
  if (pcb == NULL) {
    LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: no active pcbs\n"));
  }

  /* 分别遍历当前系统 tcp_active_pcbs 链表中的每一个 tcp 协议控制块，并对其做相应处理 */
  while (pcb != NULL) {
  	
    LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: processing active pcb\n"));
    LWIP_ASSERT("tcp_slowtmr: active pcb->state != CLOSED\n", pcb->state != CLOSED);
    LWIP_ASSERT("tcp_slowtmr: active pcb->state != LISTEN\n", pcb->state != LISTEN);
    LWIP_ASSERT("tcp_slowtmr: active pcb->state != TIME-WAIT\n", pcb->state != TIME_WAIT);
	
    if (pcb->last_timer == tcp_timer_ctr) {
      /* skip this pcb, we have already processed it */
      prev = pcb;
      pcb = pcb->next;
      continue;
    }
	
    pcb->last_timer = tcp_timer_ctr;

    pcb_remove = 0;
    pcb_reset = 0;

    /* 如果重复发送 SYN 请求数据包次数超过预先设定的阈值，则释放这个 tcp 协议控制块 */
    if (pcb->state == SYN_SENT && pcb->nrtx >= TCP_SYNMAXRTX) {
      ++pcb_remove;
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: max SYN retries reached\n"));

	/* 如果“连续”启动重传数据包的次数超过预先设定的阈值，则释放这个 tcp 协议控制块 */
    } else if (pcb->nrtx >= TCP_MAXRTX) {
      ++pcb_remove;
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: max DATA retries reached\n"));

    } else {

	  /* 如果 tcp 协议控制块"启动"了坚持定时器，则执行如下括号内操作 */
      if (pcb->persist_backoff > 0) {
        LWIP_ASSERT("tcp_slowtimr: persist ticking with in-flight data", pcb->unacked == NULL);
        LWIP_ASSERT("tcp_slowtimr: persist ticking with empty send buffer", pcb->unsent != NULL);

		/* 如果当前 tcp 协议控制块发送窗口探测数据包的次数超过预先设定的阈值，则释放这个 tcp 协议控制块 */
        if (pcb->persist_probe >= TCP_MAXRTX) {
          ++pcb_remove; /* max probes reached */
        } else {
          u8_t backoff_cnt = tcp_persist_backoff[pcb->persist_backoff - 1];
          if (pcb->persist_cnt < backoff_cnt) {
            pcb->persist_cnt++;
          }

		  /* 如果坚持定时器已经超时且当前 tcp 协议控制块发送窗口“为 0”，则发送一个“窗口探测”数据包
		   * 如果坚持定时器已经超时但是当前 tcp 协议控制块发送窗口“不为 0”，则把当前 tcp 协议控制块
		   * 的未发送数据队列的第一个分片数据包按照当前 tcp 协议控制块发送窗口大小进行分割，把分割后
		   * 的数据包封装成 tcp 分片数据包，并通过链表按照原来顺序链接起来，然后执行数据包发送操作
		   * 发送数据包的时候会关闭当前 tcp 协议控制块的坚持定时器 */
          if (pcb->persist_cnt >= backoff_cnt) {
            int next_slot = 1; /* increment timer to next slot */
            /* If snd_wnd is zero, send 1 byte probes */
            if (pcb->snd_wnd == 0) {
			  /* 为指定的 tcp 协议控制块发送一个“窗口探测”数据包 */
              if (tcp_zero_window_probe(pcb) != ERR_OK) {
                next_slot = 0; /* try probe again with current slot */
              }
              /* snd_wnd not fully closed, split unsent head and fill window */
            } else {
              if (tcp_split_unsent_seg(pcb, (u16_t)pcb->snd_wnd) == ERR_OK) {
			  	/* 发送数据包的时候会关闭当前 tcp 协议控制块的坚持定时器 */
                if (tcp_output(pcb) == ERR_OK) {
                  /* sending will cancel persist timer, else retry with current slot */
                  next_slot = 0;
                }
              }
            }

			/* 尝试把当前 tcp 协议控制块的退避时间更新到下一个位置（退避时间更大的位置）*/
            if (next_slot) {
              pcb->persist_cnt = 0;
              if (pcb->persist_backoff < sizeof(tcp_persist_backoff)) {
                pcb->persist_backoff++;
              }
            }
          }
        }

      /* 如果 tcp 协议控制块“没启动"坚持定时器，则执行如下括号内操作 */
      } else {
        
        /* Increase the retransmission timer if it is running */
	    /* 如果当前 tcp 协议控制块启动了超时重传定时器，则递增超时重传定时器计数值 */
        if ((pcb->rtime >= 0) && (pcb->rtime < 0x7FFF)) {
          ++pcb->rtime;
        }

        /* 如果当前 tcp 协议控制块已经是发送超时状态，则尝试重新发送那些发送失败的数据包 */
        if (pcb->rtime >= pcb->rto) {
          /* Time for a retransmission. */
          LWIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_slowtmr: rtime %"S16_F
                                      " pcb->rto %"S16_F"\n",
                                      pcb->rtime, pcb->rto));
		  
          /* If prepare phase fails but we have unsent data but no unacked data,
             still execute the backoff calculations below, as this means we somehow
             failed to send segment. */
          if ((tcp_rexmit_rto_prepare(pcb) == ERR_OK) || ((pcb->unacked == NULL) && (pcb->unsent != NULL))) {
		  	
            /* Double retransmission time-out unless we are trying to
             * connect to somebody (i.e., we are in SYN_SENT). */
            /* 如果当前 tcp 协议控制块状态不是 SYN_SENT，则更新当前 tcp 协议控制块的超时重传定时器的超时时间 */
            if (pcb->state != SYN_SENT) {
              u8_t backoff_idx = LWIP_MIN(pcb->nrtx, sizeof(tcp_backoff) - 1);
              int calc_rto = ((pcb->sa >> 3) + pcb->sv) << tcp_backoff[backoff_idx];
              pcb->rto = (s16_t)LWIP_MIN(calc_rto, 0x7FFF);
            }

            /* Reset the retransmission timer. */
            pcb->rtime = 0;

            /* Reduce congestion window and ssthresh. */
			/* 把当前 tcp 协议控制块的慢启动阈值设置为 LWIP_MIN(pcb->cwnd, pcb->snd_wnd) 的一半大小
			 * 但是慢启动阈值不能低于 2 个 pcb->mss 大小 */
            eff_wnd = LWIP_MIN(pcb->cwnd, pcb->snd_wnd);
            pcb->ssthresh = eff_wnd >> 1;
            if (pcb->ssthresh < (tcpwnd_size_t)(pcb->mss << 1)) {
              pcb->ssthresh = (tcpwnd_size_t)(pcb->mss << 1);
            }

			/* 把当前 tcp 协议控制块的拥塞窗口设置为 pcb->mss 大小 */
            pcb->cwnd = pcb->mss;
			
            LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_slowtmr: cwnd %"TCPWNDSIZE_F
                                         " ssthresh %"TCPWNDSIZE_F"\n",
                                         pcb->cwnd, pcb->ssthresh));
			
            pcb->bytes_acked = 0;

            /* The following needs to be called AFTER cwnd is set to one
               mss - STJ */
            /* 尝试把从指定 tcp 协议控制块的发送但未应答数据包链表上移动到 tcp 协议控制块的未发送数据队列
             * 中的每一个分片数据包数据发送出去，即启动数据包重传功能 */
            tcp_rexmit_rto_commit(pcb);
          }
        }
      }
    }
	
    /* Check if this PCB has stayed too long in FIN-WAIT-2 */
    /* 如果当前 tcp 协议控制块处于 FIN_WAIT_2 状态的时间太长且已经关闭接收数据端连接，则释放这个 tcp 协议控制块 */
    if (pcb->state == FIN_WAIT_2) {
      /* If this PCB is in FIN_WAIT_2 because of SHUT_WR don't let it time out. */
      if (pcb->flags & TF_RXCLOSED) {
        /* PCB was fully closed (either through close() or SHUT_RDWR):
           normal FIN-WAIT timeout handling. */
        if ((u32_t)(tcp_ticks - pcb->tmr) >
            TCP_FIN_WAIT_TIMEOUT / TCP_SLOW_INTERVAL) {
          ++pcb_remove;
          LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: removing pcb stuck in FIN-WAIT-2\n"));
        }
      }
    }

    /* Check if KEEPALIVE should be sent */
	/* 如果当前 tcp 协议控制块开启了长连接功能，则处理和长连接相关事件 */
    if (ip_get_option(pcb, SOF_KEEPALIVE) &&
        ((pcb->state == ESTABLISHED) ||
         (pcb->state == CLOSE_WAIT))) {

	  /* 如果当前 tcp 协议控制块处于长连接且空闲时间超过了预先设定的阈值，则释放这个 tcp 协议控制块 */
      if ((u32_t)(tcp_ticks - pcb->tmr) >
          (pcb->keep_idle + TCP_KEEP_DUR(pcb)) / TCP_SLOW_INTERVAL) {
          
        LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: KEEPALIVE timeout. Aborting connection to "));
        ip_addr_debug_print_val(TCP_DEBUG, pcb->remote_ip);
        LWIP_DEBUGF(TCP_DEBUG, ("\n"));

        ++pcb_remove;
        ++pcb_reset;

	  /* 如果当前 tcp 协议控制块处于长连接时间达到了发送长连接数据包的时间周期，则发送长连接“保活探测”数据包 */
      } else if ((u32_t)(tcp_ticks - pcb->tmr) >
                 (pcb->keep_idle + pcb->keep_cnt_sent * TCP_KEEP_INTVL(pcb))
                 / TCP_SLOW_INTERVAL) {
                 
        /* 为指定的 tcp 协议控制块发送一个“保活探测”数据包，应用于 tcp 长连接 */
        err = tcp_keepalive(pcb);
        if (err == ERR_OK) {
          pcb->keep_cnt_sent++;
        }
      }
    }

    /* If this PCB has queued out of sequence data, but has been
       inactive for too long, will drop the data (it will eventually
       be retransmitted). */
/* 如果当前 tcp 协议控制块的乱序数据包队列中是数据包存在时间超过了预先设定的阈值，则释放这些数据包 */
#if TCP_QUEUE_OOSEQ
    if (pcb->ooseq != NULL &&
        (tcp_ticks - pcb->tmr >= (u32_t)pcb->rto * TCP_OOSEQ_TIMEOUT)) {
        
      LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_slowtmr: dropping OOSEQ queued data\n"));
	  
      tcp_free_ooseq(pcb);
    }
#endif /* TCP_QUEUE_OOSEQ */

    /* Check if this PCB has stayed too long in SYN-RCVD */
    /* 如果当前 tcp 协议控制块处于 SYN_RCVD 状态的时间太长，则释放这个 tcp 协议控制块 */
    if (pcb->state == SYN_RCVD) {
      if ((u32_t)(tcp_ticks - pcb->tmr) >
          TCP_SYN_RCVD_TIMEOUT / TCP_SLOW_INTERVAL) {
        ++pcb_remove;
        LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: removing pcb stuck in SYN-RCVD\n"));
      }
    }

    /* Check if this PCB has stayed too long in LAST-ACK */
    /* 如果当前 tcp 协议控制块处于 LAST_ACK 状态的时间太长，则释放这个 tcp 协议控制块 */
    if (pcb->state == LAST_ACK) {
      if ((u32_t)(tcp_ticks - pcb->tmr) > 2 * TCP_MSL / TCP_SLOW_INTERVAL) {
        ++pcb_remove;
        LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: removing pcb stuck in LAST-ACK\n"));
      }
    }

    /* If the PCB should be removed, do it. */
    if (pcb_remove) {
      struct tcp_pcb *pcb2;
	  
#if LWIP_CALLBACK_API
      tcp_err_fn err_fn = pcb->errf;
#endif /* LWIP_CALLBACK_API */

      void *err_arg;
      enum tcp_state last_state;

	  /* 清空指定的、不是处于完全关闭状态的 tcp 协议控制块的所有缓存数据 */
      tcp_pcb_purge(pcb);
	  
      /* Remove PCB from tcp_active_pcbs list. */
      if (prev != NULL) {
        LWIP_ASSERT("tcp_slowtmr: middle tcp != tcp_active_pcbs", pcb != tcp_active_pcbs);
        prev->next = pcb->next;
      } else {
        /* This PCB was the first. */
        LWIP_ASSERT("tcp_slowtmr: first pcb == tcp_active_pcbs", tcp_active_pcbs == pcb);
        tcp_active_pcbs = pcb->next;
      }

      /* 根据函数参数构建一个 tcp reset 控制数据包并发送到指定的目的地址处，复位指定的 tpc 连接 */
      if (pcb_reset) {
        tcp_rst(pcb, pcb->snd_nxt, pcb->rcv_nxt, &pcb->local_ip, &pcb->remote_ip,
                pcb->local_port, pcb->remote_port);
      }

      err_arg = pcb->callback_arg;
      last_state = pcb->state;
      pcb2 = pcb;
      pcb = pcb->next;
      tcp_free(pcb2);

      tcp_active_pcbs_changed = 0;
	  
      TCP_EVENT_ERR(last_state, err_fn, err_arg, ERR_ABRT);
	  
      if (tcp_active_pcbs_changed) {
        goto tcp_slowtmr_start;
      }
    } else {
      /* get the 'next' element now and work with 'prev' below (in case of abort) */
	  /* 开始处理 tcp_active_pcbs 链表上的下一个成员 */
      prev = pcb;
      pcb = pcb->next;

      /* We check if we should poll the connection. */
      ++prev->polltmr;
      if (prev->polltmr >= prev->pollinterval) {
        prev->polltmr = 0;
		
        LWIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: polling application\n"));
	  
        tcp_active_pcbs_changed = 0;
        TCP_EVENT_POLL(prev, err);
        if (tcp_active_pcbs_changed) {
          goto tcp_slowtmr_start;
        }
		
        /* if err == ERR_ABRT, 'prev' is already deallocated */
        if (err == ERR_OK) {
          tcp_output(prev);
        }
      }
    }
  }


  /* Steps through all of the TIME-WAIT PCBs. */
  prev = NULL;
  pcb = tcp_tw_pcbs;

  /* 遍历当前系统 tcp_tw_pcbs 链表中的 tcp 协议控制块，分别判断每一个 tcp 协议控制块处于 TIME_WAIT 状态
   * 时间是否已经超过 2 * TCP_MSL，如果超过了 2 * TCP_MSL，则释放对应的 tcp 协议控制块结构 */
  while (pcb != NULL) {
    LWIP_ASSERT("tcp_slowtmr: TIME-WAIT pcb->state == TIME-WAIT", pcb->state == TIME_WAIT);
	
    pcb_remove = 0;

    /* Check if this PCB has stayed long enough in TIME-WAIT */
    if ((u32_t)(tcp_ticks - pcb->tmr) > 2 * TCP_MSL / TCP_SLOW_INTERVAL) {
      ++pcb_remove;
    }

    /* If the PCB should be removed, do it. */
    if (pcb_remove) {
      struct tcp_pcb *pcb2;
      tcp_pcb_purge(pcb);
      /* Remove PCB from tcp_tw_pcbs list. */
      if (prev != NULL) {
        LWIP_ASSERT("tcp_slowtmr: middle tcp != tcp_tw_pcbs", pcb != tcp_tw_pcbs);
        prev->next = pcb->next;
      } else {
        /* This PCB was the first. */
        LWIP_ASSERT("tcp_slowtmr: first pcb == tcp_tw_pcbs", tcp_tw_pcbs == pcb);
        tcp_tw_pcbs = pcb->next;
      }
      pcb2 = pcb;
      pcb = pcb->next;
      tcp_free(pcb2);
    } else {
      prev = pcb;
      pcb = pcb->next;
    }
  }
}

/**
 * Is called every TCP_FAST_INTERVAL (250 ms) and process data previously
 * "refused" by upper layer (application) and sends delayed ACKs or pending FINs.
 *
 * Automatically called from tcp_tmr().
 */
void
tcp_fasttmr(void)
{
  struct tcp_pcb *pcb;

  ++tcp_timer_ctr;

tcp_fasttmr_start:
  pcb = tcp_active_pcbs;

  while (pcb != NULL) {
    if (pcb->last_timer != tcp_timer_ctr) {
      struct tcp_pcb *next;
      pcb->last_timer = tcp_timer_ctr;
      /* send delayed ACKs */
      if (pcb->flags & TF_ACK_DELAY) {
        LWIP_DEBUGF(TCP_DEBUG, ("tcp_fasttmr: delayed ACK\n"));
        tcp_ack_now(pcb);
        tcp_output(pcb);
        tcp_clear_flags(pcb, TF_ACK_DELAY | TF_ACK_NOW);
      }
      /* send pending FIN */
      if (pcb->flags & TF_CLOSEPEND) {
        LWIP_DEBUGF(TCP_DEBUG, ("tcp_fasttmr: pending FIN\n"));
        tcp_clear_flags(pcb, TF_CLOSEPEND);
        tcp_close_shutdown_fin(pcb);
      }

      next = pcb->next;

      /* If there is data which was previously "refused" by upper layer */
      if (pcb->refused_data != NULL) {
        tcp_active_pcbs_changed = 0;
        tcp_process_refused_data(pcb);
        if (tcp_active_pcbs_changed) {
          /* application callback has changed the pcb list: restart the loop */
          goto tcp_fasttmr_start;
        }
      }
      pcb = next;
    } else {
      pcb = pcb->next;
    }
  }
}

/** Call tcp_output for all active pcbs that have TF_NAGLEMEMERR set */
void
tcp_txnow(void)
{
  struct tcp_pcb *pcb;

  for (pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
    if (pcb->flags & TF_NAGLEMEMERR) {
      tcp_output(pcb);
    }
  }
}

/** Pass pcb->refused_data to the recv callback */
/*********************************************************************************************************
** 函数名称: tcp_process_refused_data
** 功能描述: 处理指定 tcp 协议控制块未处理的 refused 数据，尝试把数据分发到应用层协议中
** 输	 入: pcb - 需要处理 refused 数据的 tcp 协议控制块
** 输	 出: err_t - 执行状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
tcp_process_refused_data(struct tcp_pcb *pcb)
{
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
  struct pbuf *rest;
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */

  LWIP_ERROR("tcp_process_refused_data: invalid pcb", pcb != NULL, return ERR_ARG);

#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
  while (pcb->refused_data != NULL)
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */

  {
    err_t err;
    u8_t refused_flags = pcb->refused_data->flags;
    /* set pcb->refused_data to NULL in case the callback frees it and then
       closes the pcb */
    struct pbuf *refused_data = pcb->refused_data;

/* 如果当前协议栈“支持” tcp 缓存乱序分片数据包到缓存队列，则从当前 tcp 协议控制块的
 * refused_data 缓冲区中截取前 64KB 数据块，如果当前协议栈“不支持” tcp 缓存乱序分片
 * 数据包到缓存队列，则拿出 refused_data 缓冲区中所有数据 */
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
    pbuf_split_64k(refused_data, &rest);
    pcb->refused_data = rest;
#else /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */
    pcb->refused_data = NULL;
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */

    /* Notify again application with data previously received. */
    LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: notify kept packet\n"));

	/* 通过用户注册在指定的 tcp 协议控制块中的回调函数分发指定的 tcp 协议控制块的指定数据包到应用层协议中 */
    TCP_EVENT_RECV(pcb, refused_data, ERR_OK, err);

	/* 如果应用层接收了我们分发的数据包，并且分发的数据包是 FIN 数据包，并且
	 * 当前 tcp 协议控制块中已经没有未处理的 refused 数据，则关闭当前 tcp 协
	 * 议控制块的连接 */
    if (err == ERR_OK) {
      /* did refused_data include a FIN? */
      if ((refused_flags & PBUF_FLAG_TCP_FIN)
	  	
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
          && (rest == NULL)
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */

         ) {
        /* correct rcv_wnd as the application won't call tcp_recved()
           for the FIN's seqno */
        if (pcb->rcv_wnd != TCP_WND_MAX(pcb)) {
          pcb->rcv_wnd++;
        }
		
		/* 通过用户注册在指定的 tcp 协议控制块中的回调函数通知应用层关闭了 tcp 连接 */
        TCP_EVENT_CLOSED(pcb, err);
		
        if (err == ERR_ABRT) {
          return ERR_ABRT;
        }
      }
    } else if (err == ERR_ABRT) {
      /* if err == ERR_ABRT, 'pcb' is already deallocated */
      /* Drop incoming packets because pcb is "full" (only if the incoming
         segment contains data). */
      LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: drop incoming packets, because pcb is \"full\"\n"));
      return ERR_ABRT;
    } else {
      /* data is still refused, pbuf is still valid (go on for ACK-only packets) */

/* 如果应用层协议仍然不处理 refused 数据，则把分割下来的 64KB 数据块链接到原来的数据链表上 */
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
      if (rest != NULL) {
        pbuf_cat(refused_data, rest);
      }
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */

      pcb->refused_data = refused_data;
      return ERR_INPROGRESS;
    }
	
  }
  return ERR_OK;
}

/**
 * Deallocates a list of TCP segments (tcp_seg structures).
 *
 * @param seg tcp_seg list of TCP segments to free
 */
/*********************************************************************************************************
** 函数名称: tcp_segs_free
** 功能描述: 释放指定的 tcp 分片数据包链表所占用的内存资源
** 输	 入: seg - 要释放的 tcp 分片数据包链表头指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_segs_free(struct tcp_seg *seg)
{
  while (seg != NULL) {
    struct tcp_seg *next = seg->next;
    tcp_seg_free(seg);
    seg = next;
  }
}

/**
 * Frees a TCP segment (tcp_seg structure).
 *
 * @param seg single tcp_seg to free
 */
/*********************************************************************************************************
** 函数名称: tcp_seg_free
** 功能描述: 释放一个 tcp 分片数据包
** 输	 入: seg - 要释放的 tcp 分段数据指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_seg_free(struct tcp_seg *seg)
{
  if (seg != NULL) {
    if (seg->p != NULL) {
      pbuf_free(seg->p);
#if TCP_DEBUG
      seg->p = NULL;
#endif /* TCP_DEBUG */
    }
    memp_free(MEMP_TCP_SEG, seg);
  }
}

/**
 * @ingroup tcp
 * Sets the priority of a connection.
 *
 * @param pcb the tcp_pcb to manipulate
 * @param prio new priority
 */
void
tcp_setprio(struct tcp_pcb *pcb, u8_t prio)
{
  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("tcp_setprio: invalid pcb", pcb != NULL, return);

  pcb->prio = prio;
}

#if TCP_QUEUE_OOSEQ
/**
 * Returns a copy of the given TCP segment.
 * The pbuf and data are not copied, only the pointers
 *
 * @param seg the old tcp_seg
 * @return a copy of seg
 */ 
/*********************************************************************************************************
** 函数名称: tcp_seg_copy
** 功能描述: 申请一个新的 tcp 分片数据包管理结构并把指定的 tcp 分片数据包管理数据复制到这个结构中
** 输	 入: seg - 需要复制的 tcp 分片数据包管理数据
** 输	 出: cseg - 新申请的，复制了数据的 tcp 分片数据包管理结构
**         : NULL - 复制失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct tcp_seg *
tcp_seg_copy(struct tcp_seg *seg)
{
  struct tcp_seg *cseg;

  LWIP_ASSERT("tcp_seg_copy: invalid seg", seg != NULL);

  cseg = (struct tcp_seg *)memp_malloc(MEMP_TCP_SEG);
  if (cseg == NULL) {
    return NULL;
  }
  SMEMCPY((u8_t *)cseg, (const u8_t *)seg, sizeof(struct tcp_seg));
  pbuf_ref(cseg->p);
  return cseg;
}
#endif /* TCP_QUEUE_OOSEQ */

#if LWIP_CALLBACK_API
/**
 * Default receive callback that is called if the user didn't register
 * a recv callback for the pcb.
 */ 
/*********************************************************************************************************
** 函数名称: tcp_recv_null
** 功能描述: 当前协议栈默认的、用于向应用层协议分发数据的回调函数
** 输	 入: arg - 当前回调函数的自定义参数
**         : pcb - 接收到数据包的 tcp 协议控制块
**         : p - 需要分发到应用层协议的数据包
**         : err - 操作错误码
** 输	 出: err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
tcp_recv_null(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
  LWIP_UNUSED_ARG(arg);

  LWIP_ERROR("tcp_recv_null: invalid pcb", pcb != NULL, return ERR_ARG);

  if (p != NULL) {
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
  } else if (err == ERR_OK) {
    return tcp_close(pcb);
  }
  return ERR_OK;
}
#endif /* LWIP_CALLBACK_API */

/**
 * Kills the oldest active connection that has a lower priority than 'prio'.
 *
 * @param prio minimum priority
 */
static void
tcp_kill_prio(u8_t prio)
{
  struct tcp_pcb *pcb, *inactive;
  u32_t inactivity;
  u8_t mprio;

  mprio = LWIP_MIN(TCP_PRIO_MAX, prio);

  /* We want to kill connections with a lower prio, so bail out if 
   * supplied prio is 0 - there can never be a lower prio
   */
  if (mprio == 0) {
    return;
  }

  /* We only want kill connections with a lower prio, so decrement prio by one 
   * and start searching for oldest connection with same or lower priority than mprio.
   * We want to find the connections with the lowest possible prio, and among
   * these the one with the longest inactivity time.
   */
  mprio--;

  inactivity = 0;
  inactive = NULL;
  for (pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
        /* lower prio is always a kill candidate */
    if ((pcb->prio < mprio) ||
        /* longer inactivity is also a kill candidate */
        ((pcb->prio == mprio) && ((u32_t)(tcp_ticks - pcb->tmr) >= inactivity))) {
      inactivity = tcp_ticks - pcb->tmr;
      inactive   = pcb;
      mprio      = pcb->prio;
    }
  }
  if (inactive != NULL) {
    LWIP_DEBUGF(TCP_DEBUG, ("tcp_kill_prio: killing oldest PCB %p (%"S32_F")\n",
                            (void *)inactive, inactivity));
    tcp_abort(inactive);
  }
}

/**
 * Kills the oldest connection that is in specific state.
 * Called from tcp_alloc() for LAST_ACK and CLOSING if no more connections are available.
 */
static void
tcp_kill_state(enum tcp_state state)
{
  struct tcp_pcb *pcb, *inactive;
  u32_t inactivity;

  LWIP_ASSERT("invalid state", (state == CLOSING) || (state == LAST_ACK));

  inactivity = 0;
  inactive = NULL;
  /* Go through the list of active pcbs and get the oldest pcb that is in state
     CLOSING/LAST_ACK. */
  for (pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
    if (pcb->state == state) {
      if ((u32_t)(tcp_ticks - pcb->tmr) >= inactivity) {
        inactivity = tcp_ticks - pcb->tmr;
        inactive = pcb;
      }
    }
  }
  if (inactive != NULL) {
    LWIP_DEBUGF(TCP_DEBUG, ("tcp_kill_closing: killing oldest %s PCB %p (%"S32_F")\n",
                            tcp_state_str[state], (void *)inactive, inactivity));
    /* Don't send a RST, since no data is lost. */
    tcp_abandon(inactive, 0);
  }
}

/**
 * Kills the oldest connection that is in TIME_WAIT state.
 * Called from tcp_alloc() if no more connections are available.
 */
static void
tcp_kill_timewait(void)
{
  struct tcp_pcb *pcb, *inactive;
  u32_t inactivity;

  inactivity = 0;
  inactive = NULL;
  /* Go through the list of TIME_WAIT pcbs and get the oldest pcb. */
  for (pcb = tcp_tw_pcbs; pcb != NULL; pcb = pcb->next) {
    if ((u32_t)(tcp_ticks - pcb->tmr) >= inactivity) {
      inactivity = tcp_ticks - pcb->tmr;
      inactive = pcb;
    }
  }
  if (inactive != NULL) {
    LWIP_DEBUGF(TCP_DEBUG, ("tcp_kill_timewait: killing oldest TIME-WAIT PCB %p (%"S32_F")\n",
                            (void *)inactive, inactivity));
    tcp_abort(inactive);
  }
}

/* Called when allocating a pcb fails.
 * In this case, we want to handle all pcbs that want to close first: if we can
 * now send the FIN (which failed before), the pcb might be in a state that is
 * OK for us to now free it.
 */
static void
tcp_handle_closepend(void)
{
  struct tcp_pcb *pcb = tcp_active_pcbs;

  while (pcb != NULL) {
    struct tcp_pcb *next = pcb->next;
    /* send pending FIN */
    if (pcb->flags & TF_CLOSEPEND) {
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_handle_closepend: pending FIN\n"));
      tcp_clear_flags(pcb, TF_CLOSEPEND);
      tcp_close_shutdown_fin(pcb);
    }
    pcb = next;
  }
}

/**
 * Allocate a new tcp_pcb structure.
 *
 * @param prio priority for the new pcb
 * @return a new tcp_pcb that initially is in state CLOSED
 */ 
/*********************************************************************************************************
** 函数名称: tcp_alloc
** 功能描述: 从当前系统的 MEMP_TCP_PCB 内存池中申请一个指定优先级的 tcp 协议控制块结构
** 输	 入: prio - 需要申请的 tcp 协议控制块的优先级
** 输	 出: pcb - 成功申请的 tcp 协议控制块结构
**         : NULL - 申请失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct tcp_pcb *
tcp_alloc(u8_t prio)
{
  struct tcp_pcb *pcb;

  LWIP_ASSERT_CORE_LOCKED();

  /* 从当前协议栈的内存池中申请一个 tcp 协议控制块结构 */
  pcb = (struct tcp_pcb *)memp_malloc(MEMP_TCP_PCB);
  if (pcb == NULL) {
    /* Try to send FIN for all pcbs stuck in TF_CLOSEPEND first */
    tcp_handle_closepend();

    /* Try killing oldest connection in TIME-WAIT. */
    LWIP_DEBUGF(TCP_DEBUG, ("tcp_alloc: killing off oldest TIME-WAIT connection\n"));
    tcp_kill_timewait();
    /* Try to allocate a tcp_pcb again. */
    pcb = (struct tcp_pcb *)memp_malloc(MEMP_TCP_PCB);
    if (pcb == NULL) {
      /* Try killing oldest connection in LAST-ACK (these wouldn't go to TIME-WAIT). */
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_alloc: killing off oldest LAST-ACK connection\n"));
      tcp_kill_state(LAST_ACK);
      /* Try to allocate a tcp_pcb again. */
      pcb = (struct tcp_pcb *)memp_malloc(MEMP_TCP_PCB);
      if (pcb == NULL) {
        /* Try killing oldest connection in CLOSING. */
        LWIP_DEBUGF(TCP_DEBUG, ("tcp_alloc: killing off oldest CLOSING connection\n"));
        tcp_kill_state(CLOSING);
        /* Try to allocate a tcp_pcb again. */
        pcb = (struct tcp_pcb *)memp_malloc(MEMP_TCP_PCB);
        if (pcb == NULL) {
          /* Try killing oldest active connection with lower priority than the new one. */
          LWIP_DEBUGF(TCP_DEBUG, ("tcp_alloc: killing oldest connection with prio lower than %d\n", prio));
          tcp_kill_prio(prio);
          /* Try to allocate a tcp_pcb again. */
          pcb = (struct tcp_pcb *)memp_malloc(MEMP_TCP_PCB);
          if (pcb != NULL) {
            /* adjust err stats: memp_malloc failed multiple times before */
            MEMP_STATS_DEC(err, MEMP_TCP_PCB);
          }
        }
        if (pcb != NULL) {
          /* adjust err stats: memp_malloc failed multiple times before */
          MEMP_STATS_DEC(err, MEMP_TCP_PCB);
        }
      }
      if (pcb != NULL) {
        /* adjust err stats: memp_malloc failed multiple times before */
        MEMP_STATS_DEC(err, MEMP_TCP_PCB);
      }
    }
    if (pcb != NULL) {
      /* adjust err stats: memp_malloc failed above */
      MEMP_STATS_DEC(err, MEMP_TCP_PCB);
    }
  }
  
  if (pcb != NULL) {
    /* zero out the whole pcb, so there is no need to initialize members to zero */
    memset(pcb, 0, sizeof(struct tcp_pcb));
    pcb->prio = prio;
    pcb->snd_buf = TCP_SND_BUF;
    /* Start with a window that does not need scaling. When window scaling is
       enabled and used, the window is enlarged when both sides agree on scaling. */
    pcb->rcv_wnd = pcb->rcv_ann_wnd = TCPWND_MIN16(TCP_WND);
    pcb->ttl = TCP_TTL;
    /* As initial send MSS, we use TCP_MSS but limit it to 536.
       The send MSS is updated when an MSS option is received. */
    pcb->mss = INITIAL_MSS;
    pcb->rto = 3000 / TCP_SLOW_INTERVAL;
    pcb->sv = 3000 / TCP_SLOW_INTERVAL;
    pcb->rtime = -1;
    pcb->cwnd = 1;
    pcb->tmr = tcp_ticks;
    pcb->last_timer = tcp_timer_ctr;

    /* RFC 5681 recommends setting ssthresh abritrarily high and gives an example
    of using the largest advertised receive window.  We've seen complications with
    receiving TCPs that use window scaling and/or window auto-tuning where the
    initial advertised window is very small and then grows rapidly once the
    connection is established. To avoid these complications, we set ssthresh to the
    largest effective cwnd (amount of in-flight data) that the sender can have. */
    pcb->ssthresh = TCP_SND_BUF;

#if LWIP_CALLBACK_API
    pcb->recv = tcp_recv_null;
#endif /* LWIP_CALLBACK_API */

    /* Init KEEPALIVE timer */
    pcb->keep_idle  = TCP_KEEPIDLE_DEFAULT;

#if LWIP_TCP_KEEPALIVE
    pcb->keep_intvl = TCP_KEEPINTVL_DEFAULT;
    pcb->keep_cnt   = TCP_KEEPCNT_DEFAULT;
#endif /* LWIP_TCP_KEEPALIVE */
  }
  return pcb;
}

/**
 * @ingroup tcp_raw
 * Creates a new TCP protocol control block but doesn't place it on
 * any of the TCP PCB lists.
 * The pcb is not put on any list until binding using tcp_bind().
 * If memory is not available for creating the new pcb, NULL is returned.
 *
 * @internal: Maybe there should be a idle TCP PCB list where these
 * PCBs are put on. Port reservation using tcp_bind() is implemented but
 * allocated pcbs that are not bound can't be killed automatically if wanting
 * to allocate a pcb with higher prio (@see tcp_kill_prio())
 *
 * @return a new tcp_pcb that initially is in state CLOSED
 */
struct tcp_pcb *
tcp_new(void)
{
  return tcp_alloc(TCP_PRIO_NORMAL);
}

/**
 * @ingroup tcp_raw
 * Creates a new TCP protocol control block but doesn't
 * place it on any of the TCP PCB lists.
 * The pcb is not put on any list until binding using tcp_bind().
 *
 * @param type IP address type, see @ref lwip_ip_addr_type definitions.
 * If you want to listen to IPv4 and IPv6 (dual-stack) connections,
 * supply @ref IPADDR_TYPE_ANY as argument and bind to @ref IP_ANY_TYPE.
 * @return a new tcp_pcb that initially is in state CLOSED
 */
struct tcp_pcb *
tcp_new_ip_type(u8_t type)
{
  struct tcp_pcb *pcb;
  pcb = tcp_alloc(TCP_PRIO_NORMAL);
#if LWIP_IPV4 && LWIP_IPV6
  if (pcb != NULL) {
    IP_SET_TYPE_VAL(pcb->local_ip, type);
    IP_SET_TYPE_VAL(pcb->remote_ip, type);
  }
#else
  LWIP_UNUSED_ARG(type);
#endif /* LWIP_IPV4 && LWIP_IPV6 */
  return pcb;
}

/**
 * @ingroup tcp_raw
 * Specifies the program specific state that should be passed to all
 * other callback functions. The "pcb" argument is the current TCP
 * connection control block, and the "arg" argument is the argument
 * that will be passed to the callbacks.
 *
 * @param pcb tcp_pcb to set the callback argument
 * @param arg void pointer argument to pass to callback functions
 */
void
tcp_arg(struct tcp_pcb *pcb, void *arg)
{
  LWIP_ASSERT_CORE_LOCKED();
  /* This function is allowed to be called for both listen pcbs and
     connection pcbs. */
  if (pcb != NULL) {
    pcb->callback_arg = arg;
  }
}
#if LWIP_CALLBACK_API

/**
 * @ingroup tcp_raw
 * Sets the callback function that will be called when new data
 * arrives. The callback function will be passed a NULL pbuf to
 * indicate that the remote host has closed the connection. If the
 * callback function returns ERR_OK or ERR_ABRT it must have
 * freed the pbuf, otherwise it must not have freed it.
 *
 * @param pcb tcp_pcb to set the recv callback
 * @param recv callback function to call for this pcb when data is received
 */
void
tcp_recv(struct tcp_pcb *pcb, tcp_recv_fn recv)
{
  LWIP_ASSERT_CORE_LOCKED();
  if (pcb != NULL) {
    LWIP_ASSERT("invalid socket state for recv callback", pcb->state != LISTEN);
    pcb->recv = recv;
  }
}

/**
 * @ingroup tcp_raw
 * Specifies the callback function that should be called when data has
 * successfully been received (i.e., acknowledged) by the remote
 * host. The len argument passed to the callback function gives the
 * amount bytes that was acknowledged by the last acknowledgment.
 *
 * @param pcb tcp_pcb to set the sent callback
 * @param sent callback function to call for this pcb when data is successfully sent
 */
void
tcp_sent(struct tcp_pcb *pcb, tcp_sent_fn sent)
{
  LWIP_ASSERT_CORE_LOCKED();
  if (pcb != NULL) {
    LWIP_ASSERT("invalid socket state for sent callback", pcb->state != LISTEN);
    pcb->sent = sent;
  }
}

/**
 * @ingroup tcp_raw
 * Used to specify the function that should be called when a fatal error
 * has occurred on the connection.
 * 
 * If a connection is aborted because of an error, the application is
 * alerted of this event by the err callback. Errors that might abort a
 * connection are when there is a shortage of memory. The callback
 * function to be called is set using the tcp_err() function.
 *
 * @note The corresponding pcb is already freed when this callback is called!
 *
 * @param pcb tcp_pcb to set the err callback
 * @param err callback function to call for this pcb when a fatal error
 *        has occurred on the connection
 */
void
tcp_err(struct tcp_pcb *pcb, tcp_err_fn err)
{
  LWIP_ASSERT_CORE_LOCKED();
  if (pcb != NULL) {
    LWIP_ASSERT("invalid socket state for err callback", pcb->state != LISTEN);
    pcb->errf = err;
  }
}

/**
 * @ingroup tcp_raw
 * Used for specifying the function that should be called when a
 * LISTENing connection has been connected to another host.
 *
 * @param pcb tcp_pcb to set the accept callback
 * @param accept callback function to call for this pcb when LISTENing
 *        connection has been connected to another host
 */
void
tcp_accept(struct tcp_pcb *pcb, tcp_accept_fn accept)
{
  LWIP_ASSERT_CORE_LOCKED();
  if ((pcb != NULL) && (pcb->state == LISTEN)) {
    struct tcp_pcb_listen *lpcb = (struct tcp_pcb_listen *)pcb;
    lpcb->accept = accept;
  }
}
#endif /* LWIP_CALLBACK_API */


/**
 * @ingroup tcp_raw
 * Specifies the polling interval and the callback function that should
 * be called to poll the application. The interval is specified in
 * number of TCP coarse grained timer shots, which typically occurs
 * twice a second. An interval of 10 means that the application would
 * be polled every 5 seconds.
 * 
 * When a connection is idle (i.e., no data is either transmitted or
 * received), lwIP will repeatedly poll the application by calling a
 * specified callback function. This can be used either as a watchdog
 * timer for killing connections that have stayed idle for too long, or
 * as a method of waiting for memory to become available. For instance,
 * if a call to tcp_write() has failed because memory wasn't available,
 * the application may use the polling functionality to call tcp_write()
 * again when the connection has been idle for a while.
 */
void
tcp_poll(struct tcp_pcb *pcb, tcp_poll_fn poll, u8_t interval)
{
  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ERROR("tcp_poll: invalid pcb", pcb != NULL, return);
  LWIP_ASSERT("invalid socket state for poll", pcb->state != LISTEN);

#if LWIP_CALLBACK_API
  pcb->poll = poll;
#else /* LWIP_CALLBACK_API */
  LWIP_UNUSED_ARG(poll);
#endif /* LWIP_CALLBACK_API */
  pcb->pollinterval = interval;
}

/**
 * Purges a TCP PCB. Removes any buffered data and frees the buffer memory
 * (pcb->ooseq, pcb->unsent and pcb->unacked are freed).
 *
 * @param pcb tcp_pcb to purge. The pcb itself is not deallocated!
 */ 
/*********************************************************************************************************
** 函数名称: tcp_pcb_purge
** 功能描述: 清空指定的、不是处于完全关闭状态的 tcp 协议控制块的所有缓存数据
** 输	 入: pcb - 需要释放缓存数据的 tcp 协议控制块
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_pcb_purge(struct tcp_pcb *pcb)
{
  LWIP_ERROR("tcp_pcb_purge: invalid pcb", pcb != NULL, return);

  /* 判断当前 tcp 协议控制块是否处于完全关闭状态，如果不是完全关闭状态，则执行缓存数据清理操作 */
  if (pcb->state != CLOSED &&
      pcb->state != TIME_WAIT &&
      pcb->state != LISTEN) {

    LWIP_DEBUGF(TCP_DEBUG, ("tcp_pcb_purge\n"));

    /* 尝试减小指定的 tcp 协议控制块所属监听者的 backlog 计数值 */
    tcp_backlog_accepted(pcb);

    /* 清空当前 tcp 协议控制块之前已经接收到的、但是还没被上层（应用层）协议处理的数据包*/
    if (pcb->refused_data != NULL) {
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_pcb_purge: data left on ->refused_data\n"));
      pbuf_free(pcb->refused_data);
      pcb->refused_data = NULL;
    }
	
    if (pcb->unsent != NULL) {
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_pcb_purge: not all data sent\n"));
    }
	
    if (pcb->unacked != NULL) {
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_pcb_purge: data left on ->unacked\n"));
    }

/* 释放指定 tcp 连接中所有 out of sequence 数据包 */
#if TCP_QUEUE_OOSEQ
    if (pcb->ooseq != NULL) {
      LWIP_DEBUGF(TCP_DEBUG, ("tcp_pcb_purge: data left on ->ooseq\n"));
      tcp_free_ooseq(pcb);
    }
#endif /* TCP_QUEUE_OOSEQ */

    /* Stop the retransmission timer as it will expect data on unacked
       queue if it fires */
    /* 关闭当前 tcp 协议控制块的数据包重传定时器 */
    pcb->rtime = -1;

    /* 清空当前 tcp 协议控制块未发送数据队列上的所有数据包 */
    tcp_segs_free(pcb->unsent);
	
    /* 清空当前 tcp 协议控制块发送但是还未应答队列上的所有数据包 */
    tcp_segs_free(pcb->unacked);
	
    pcb->unacked = pcb->unsent = NULL;
	
#if TCP_OVERSIZE
    pcb->unsent_oversize = 0;
#endif /* TCP_OVERSIZE */
  }
}

/**
 * Purges the PCB and removes it from a PCB list. Any delayed ACKs are sent first.
 *
 * @param pcblist PCB list to purge.
 * @param pcb tcp_pcb to purge. The pcb itself is NOT deallocated!
 */ 
/*********************************************************************************************************
** 函数名称: tcp_pcb_remove
** 功能描述: 把指定的 tcp 协议控制块从指定的 tcp 协议控制块链表上移除，并释放这个 tcp 协议控制块
**         : 的所有缓存数据、把这个 tcp 协议控制块的延迟发送应答数据包立即发送出去，然后设置这个
**         : tcp 协议控制块的状态和本地端口号分别为 CLOSED 和 0 
** 输	 入: pcblist - 需要清理的 tcp 协议控制块所属链表
**         : pcb - 需要清理的 tcp 协议控制块
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_pcb_remove(struct tcp_pcb **pcblist, struct tcp_pcb *pcb)
{
  LWIP_ASSERT("tcp_pcb_remove: invalid pcb", pcb != NULL);
  LWIP_ASSERT("tcp_pcb_remove: invalid pcblist", pcblist != NULL);

  /* 把指定的 tcp 协议控制块从指定的 tcp 协议控制块链表上移除 */
  TCP_RMV(pcblist, pcb);

  /* 清空指定的、不是处于完全关闭状态的 tcp 协议控制块的所有缓存数据 */
  tcp_pcb_purge(pcb);

  /* if there is an outstanding delayed ACKs, send it */
  if ((pcb->state != TIME_WAIT) &&
      (pcb->state != LISTEN) &&
      (pcb->flags & TF_ACK_DELAY)) {
	/* 设置当前 tcp 协议控制块的 TF_ACK_NOW 标志位 */
    tcp_ack_now(pcb);
	/* 执行当前 tcp 协议控制块要向对端设备发送的应答数据包操作 */
    tcp_output(pcb);
  }

  if (pcb->state != LISTEN) {
    LWIP_ASSERT("unsent segments leaking", pcb->unsent == NULL);
    LWIP_ASSERT("unacked segments leaking", pcb->unacked == NULL);
#if TCP_QUEUE_OOSEQ
    LWIP_ASSERT("ooseq segments leaking", pcb->ooseq == NULL);
#endif /* TCP_QUEUE_OOSEQ */
  }

  pcb->state = CLOSED;
  /* reset the local port to prevent the pcb from being 'bound' */
  pcb->local_port = 0;

  LWIP_ASSERT("tcp_pcb_remove: tcp_pcbs_sane()", tcp_pcbs_sane());
}

/**
 * Calculates a new initial sequence number for new connections.
 *
 * @return u32_t pseudo random sequence number
 */
/*********************************************************************************************************
** 函数名称: tcp_next_iss
** 功能描述: 为新建立的、指定的 tcp 协议控制块分配一个 ISN（Initial Sequence Number）
** 输	 入: pcb - 需要分配 ISN 的 tcp 协议控制块
** 输	 出: iss - 分配到的 ISN
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u32_t
tcp_next_iss(struct tcp_pcb *pcb)
{

/* 优先使用用户实现的自定义接口函数，为新建立的 tcp 连接分配 ISN（Initial Sequence Number）*/
#ifdef LWIP_HOOK_TCP_ISN
  LWIP_ASSERT("tcp_next_iss: invalid pcb", pcb != NULL);
  return LWIP_HOOK_TCP_ISN(&pcb->local_ip, pcb->local_port, &pcb->remote_ip, pcb->remote_port);
#else /* LWIP_HOOK_TCP_ISN */

  static u32_t iss = 6510;

  LWIP_ASSERT("tcp_next_iss: invalid pcb", pcb != NULL);
  LWIP_UNUSED_ARG(pcb);

  iss += tcp_ticks;       /* XXX */
  return iss;
#endif /* LWIP_HOOK_TCP_ISN */
}

#if TCP_CALCULATE_EFF_SEND_MSS
/**
 * Calculates the effective send mss that can be used for a specific IP address
 * by calculating the minimum of TCP_MSS and the mtu (if set) of the target
 * netif (if not NULL).
 */
/*********************************************************************************************************
** 函数名称: tcp_eff_send_mss_netif
** 功能描述: 通过当前 tcp mss 和指定网络接口的 mtu 计算到指定目的 IP 地址处的有效 mss
** 输	 入: sendmss - 当前系统 tcp mss 大小
**         : outif - 用来发送数据包的网路接口指针
**         : dest - 需要发送的数据包的目的 IP 地址
** 输	 出: err_t - 发送状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u16_t
tcp_eff_send_mss_netif(u16_t sendmss, struct netif *outif, const ip_addr_t *dest)
{
  u16_t mss_s;
  u16_t mtu;

  LWIP_UNUSED_ARG(dest); /* in case IPv6 is disabled */

  LWIP_ASSERT("tcp_eff_send_mss_netif: invalid dst_ip", dest != NULL);


#if LWIP_IPV6

#if LWIP_IPV4
  if (IP_IS_V6(dest))
#endif /* LWIP_IPV4 */
  {
    /* First look in destination cache, to see if there is a Path MTU. */
    mtu = nd6_get_destination_mtu(ip_2_ip6(dest), outif);
  }

#if LWIP_IPV4
  else
#endif /* LWIP_IPV4 */

#endif /* LWIP_IPV6 */


#if LWIP_IPV4
  {
    if (outif == NULL) {
      return sendmss;
    }
    mtu = outif->mtu;
  }
#endif /* LWIP_IPV4 */

  if (mtu != 0) {
    u16_t offset;

  
#if LWIP_IPV6

#if LWIP_IPV4
    if (IP_IS_V6(dest))
#endif /* LWIP_IPV4 */

    {
      offset = IP6_HLEN + TCP_HLEN;
    }

#if LWIP_IPV4
    else
#endif /* LWIP_IPV4 */

#endif /* LWIP_IPV6 */


#if LWIP_IPV4
    {
      offset = IP_HLEN + TCP_HLEN;
    }
#endif /* LWIP_IPV4 */

    mss_s = (mtu > offset) ? (u16_t)(mtu - offset) : 0;
    /* RFC 1122, chap 4.2.2.6:
     * Eff.snd.MSS = min(SendMSS+20, MMS_S) - TCPhdrsize - IPoptionsize
     * We correct for TCP options in tcp_write(), and don't support IP options.
     */
    sendmss = LWIP_MIN(sendmss, mss_s);
  }
  
  return sendmss;
}
#endif /* TCP_CALCULATE_EFF_SEND_MSS */

/** Helper function for tcp_netif_ip_addr_changed() that iterates a pcb list */
static void
tcp_netif_ip_addr_changed_pcblist(const ip_addr_t *old_addr, struct tcp_pcb *pcb_list)
{
  struct tcp_pcb *pcb;
  pcb = pcb_list;

  LWIP_ASSERT("tcp_netif_ip_addr_changed_pcblist: invalid old_addr", old_addr != NULL);

  while (pcb != NULL) {
    /* PCB bound to current local interface address? */
    if (ip_addr_cmp(&pcb->local_ip, old_addr)
#if LWIP_AUTOIP
        /* connections to link-local addresses must persist (RFC3927 ch. 1.9) */
        && (!IP_IS_V4_VAL(pcb->local_ip) || !ip4_addr_islinklocal(ip_2_ip4(&pcb->local_ip)))
#endif /* LWIP_AUTOIP */
       ) {
      /* this connection must be aborted */
      struct tcp_pcb *next = pcb->next;
      LWIP_DEBUGF(NETIF_DEBUG | LWIP_DBG_STATE, ("netif_set_ipaddr: aborting TCP pcb %p\n", (void *)pcb));
      tcp_abort(pcb);
      pcb = next;
    } else {
      pcb = pcb->next;
    }
  }
}

/** This function is called from netif.c when address is changed or netif is removed
 *
 * @param old_addr IP address of the netif before change
 * @param new_addr IP address of the netif after change or NULL if netif has been removed
 */
void
tcp_netif_ip_addr_changed(const ip_addr_t *old_addr, const ip_addr_t *new_addr)
{
  struct tcp_pcb_listen *lpcb;

  if (!ip_addr_isany(old_addr)) {
    tcp_netif_ip_addr_changed_pcblist(old_addr, tcp_active_pcbs);
    tcp_netif_ip_addr_changed_pcblist(old_addr, tcp_bound_pcbs);

    if (!ip_addr_isany(new_addr)) {
      /* PCB bound to current local interface address? */
      for (lpcb = tcp_listen_pcbs.listen_pcbs; lpcb != NULL; lpcb = lpcb->next) {
        /* PCB bound to current local interface address? */
        if (ip_addr_cmp(&lpcb->local_ip, old_addr)) {
          /* The PCB is listening to the old ipaddr and
            * is set to listen to the new one instead */
          ip_addr_copy(lpcb->local_ip, *new_addr);
        }
      }
    }
  }
}

const char *
tcp_debug_state_str(enum tcp_state s)
{
  return tcp_state_str[s];
}

err_t
tcp_tcp_get_tcp_addrinfo(struct tcp_pcb *pcb, int local, ip_addr_t *addr, u16_t *port)
{
  if (pcb) {
    if (local) {
      if (addr) {
        *addr = pcb->local_ip;
      }
      if (port) {
        *port = pcb->local_port;
      }
    } else {
      if (addr) {
        *addr = pcb->remote_ip;
      }
      if (port) {
        *port = pcb->remote_port;
      }
    }
    return ERR_OK;
  }
  return ERR_VAL;
}

#if TCP_QUEUE_OOSEQ
/* Free all ooseq pbufs (and possibly reset SACK state) */
/*********************************************************************************************************
** 函数名称: tcp_free_ooseq
** 功能描述: 释放指定 tcp 连接中所有 out of sequence 数据包
** 输	 入: pcb - 要释放 out of sequence 数据包的 tcp 连接指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_free_ooseq(struct tcp_pcb *pcb)
{
  if (pcb->ooseq) {
    tcp_segs_free(pcb->ooseq);
    pcb->ooseq = NULL;
  
#if LWIP_TCP_SACK_OUT
    memset(pcb->rcv_sacks, 0, sizeof(pcb->rcv_sacks));
#endif /* LWIP_TCP_SACK_OUT */

  }
}
#endif /* TCP_QUEUE_OOSEQ */

#if TCP_DEBUG || TCP_INPUT_DEBUG || TCP_OUTPUT_DEBUG
/**
 * Print a tcp header for debugging purposes.
 *
 * @param tcphdr pointer to a struct tcp_hdr
 */
void
tcp_debug_print(struct tcp_hdr *tcphdr)
{
  LWIP_DEBUGF(TCP_DEBUG, ("TCP header:\n"));
  LWIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(TCP_DEBUG, ("|    %5"U16_F"      |    %5"U16_F"      | (src port, dest port)\n",
                          lwip_ntohs(tcphdr->src), lwip_ntohs(tcphdr->dest)));
  LWIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(TCP_DEBUG, ("|           %010"U32_F"          | (seq no)\n",
                          lwip_ntohl(tcphdr->seqno)));
  LWIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(TCP_DEBUG, ("|           %010"U32_F"          | (ack no)\n",
                          lwip_ntohl(tcphdr->ackno)));
  LWIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(TCP_DEBUG, ("| %2"U16_F" |   |%"U16_F"%"U16_F"%"U16_F"%"U16_F"%"U16_F"%"U16_F"|     %5"U16_F"     | (hdrlen, flags (",
                          TCPH_HDRLEN(tcphdr),
                          (u16_t)(TCPH_FLAGS(tcphdr) >> 5 & 1),
                          (u16_t)(TCPH_FLAGS(tcphdr) >> 4 & 1),
                          (u16_t)(TCPH_FLAGS(tcphdr) >> 3 & 1),
                          (u16_t)(TCPH_FLAGS(tcphdr) >> 2 & 1),
                          (u16_t)(TCPH_FLAGS(tcphdr) >> 1 & 1),
                          (u16_t)(TCPH_FLAGS(tcphdr)      & 1),
                          lwip_ntohs(tcphdr->wnd)));
  tcp_debug_print_flags(TCPH_FLAGS(tcphdr));
  LWIP_DEBUGF(TCP_DEBUG, ("), win)\n"));
  LWIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
  LWIP_DEBUGF(TCP_DEBUG, ("|    0x%04"X16_F"     |     %5"U16_F"     | (chksum, urgp)\n",
                          lwip_ntohs(tcphdr->chksum), lwip_ntohs(tcphdr->urgp)));
  LWIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
}

/**
 * Print a tcp state for debugging purposes.
 *
 * @param s enum tcp_state to print
 */
void
tcp_debug_print_state(enum tcp_state s)
{
  LWIP_DEBUGF(TCP_DEBUG, ("State: %s\n", tcp_state_str[s]));
}

/**
 * Print tcp flags for debugging purposes.
 *
 * @param flags tcp flags, all active flags are printed
 */
void
tcp_debug_print_flags(u8_t flags)
{
  if (flags & TCP_FIN) {
    LWIP_DEBUGF(TCP_DEBUG, ("FIN "));
  }
  if (flags & TCP_SYN) {
    LWIP_DEBUGF(TCP_DEBUG, ("SYN "));
  }
  if (flags & TCP_RST) {
    LWIP_DEBUGF(TCP_DEBUG, ("RST "));
  }
  if (flags & TCP_PSH) {
    LWIP_DEBUGF(TCP_DEBUG, ("PSH "));
  }
  if (flags & TCP_ACK) {
    LWIP_DEBUGF(TCP_DEBUG, ("ACK "));
  }
  if (flags & TCP_URG) {
    LWIP_DEBUGF(TCP_DEBUG, ("URG "));
  }
  if (flags & TCP_ECE) {
    LWIP_DEBUGF(TCP_DEBUG, ("ECE "));
  }
  if (flags & TCP_CWR) {
    LWIP_DEBUGF(TCP_DEBUG, ("CWR "));
  }
  LWIP_DEBUGF(TCP_DEBUG, ("\n"));
}

/**
 * Print all tcp_pcbs in every list for debugging purposes.
 */
void
tcp_debug_print_pcbs(void)
{
  struct tcp_pcb *pcb;
  struct tcp_pcb_listen *pcbl;

  LWIP_DEBUGF(TCP_DEBUG, ("Active PCB states:\n"));
  for (pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
    LWIP_DEBUGF(TCP_DEBUG, ("Local port %"U16_F", foreign port %"U16_F" snd_nxt %"U32_F" rcv_nxt %"U32_F" ",
                            pcb->local_port, pcb->remote_port,
                            pcb->snd_nxt, pcb->rcv_nxt));
    tcp_debug_print_state(pcb->state);
  }

  LWIP_DEBUGF(TCP_DEBUG, ("Listen PCB states:\n"));
  for (pcbl = tcp_listen_pcbs.listen_pcbs; pcbl != NULL; pcbl = pcbl->next) {
    LWIP_DEBUGF(TCP_DEBUG, ("Local port %"U16_F" ", pcbl->local_port));
    tcp_debug_print_state(pcbl->state);
  }

  LWIP_DEBUGF(TCP_DEBUG, ("TIME-WAIT PCB states:\n"));
  for (pcb = tcp_tw_pcbs; pcb != NULL; pcb = pcb->next) {
    LWIP_DEBUGF(TCP_DEBUG, ("Local port %"U16_F", foreign port %"U16_F" snd_nxt %"U32_F" rcv_nxt %"U32_F" ",
                            pcb->local_port, pcb->remote_port,
                            pcb->snd_nxt, pcb->rcv_nxt));
    tcp_debug_print_state(pcb->state);
  }
}

/**
 * Check state consistency of the tcp_pcb lists.
 */
s16_t
tcp_pcbs_sane(void)
{
  struct tcp_pcb *pcb;
  for (pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
    LWIP_ASSERT("tcp_pcbs_sane: active pcb->state != CLOSED", pcb->state != CLOSED);
    LWIP_ASSERT("tcp_pcbs_sane: active pcb->state != LISTEN", pcb->state != LISTEN);
    LWIP_ASSERT("tcp_pcbs_sane: active pcb->state != TIME-WAIT", pcb->state != TIME_WAIT);
  }
  for (pcb = tcp_tw_pcbs; pcb != NULL; pcb = pcb->next) {
    LWIP_ASSERT("tcp_pcbs_sane: tw pcb->state == TIME-WAIT", pcb->state == TIME_WAIT);
  }
  return 1;
}
#endif /* TCP_DEBUG */

#if LWIP_TCP_PCB_NUM_EXT_ARGS
/**
 * @defgroup tcp_raw_extargs ext arguments
 * @ingroup tcp_raw
 * Additional data storage per tcp pcb\n
 * @see @ref tcp_raw
 *
 * When LWIP_TCP_PCB_NUM_EXT_ARGS is > 0, every tcp pcb (including listen pcb)
 * includes a number of additional argument entries in an array.
 *
 * To support memory management, in addition to a 'void *', callbacks can be
 * provided to manage transition from listening pcbs to connections and to
 * deallocate memory when a pcb is deallocated (see struct @ref tcp_ext_arg_callbacks).
 *
 * After allocating this index, use @ref tcp_ext_arg_set and @ref tcp_ext_arg_get
 * to store and load arguments from this index for a given pcb.
 */

static u8_t tcp_ext_arg_id;

/**
 * @ingroup tcp_raw_extargs
 * Allocate an index to store data in ext_args member of struct tcp_pcb.
 * Returned value is an index in mentioned array.
 * The index is *global* over all pcbs!
 *
 * When @ref LWIP_TCP_PCB_NUM_EXT_ARGS is > 0, every tcp pcb (including listen pcb)
 * includes a number of additional argument entries in an array.
 *
 * To support memory management, in addition to a 'void *', callbacks can be
 * provided to manage transition from listening pcbs to connections and to
 * deallocate memory when a pcb is deallocated (see struct @ref tcp_ext_arg_callbacks).
 *
 * After allocating this index, use @ref tcp_ext_arg_set and @ref tcp_ext_arg_get
 * to store and load arguments from this index for a given pcb.
 *
 * @return a unique index into struct tcp_pcb.ext_args
 */
u8_t
tcp_ext_arg_alloc_id(void)
{
  u8_t result = tcp_ext_arg_id;
  tcp_ext_arg_id++;

  LWIP_ASSERT_CORE_LOCKED();

#if LWIP_TCP_PCB_NUM_EXT_ARGS >= 255
#error LWIP_TCP_PCB_NUM_EXT_ARGS
#endif
  LWIP_ASSERT("Increase LWIP_TCP_PCB_NUM_EXT_ARGS in lwipopts.h", result < LWIP_TCP_PCB_NUM_EXT_ARGS);
  return result;
}

/**
 * @ingroup tcp_raw_extargs
 * Set callbacks for a given index of ext_args on the specified pcb.
 *
 * @param pcb tcp_pcb for which to set the callback
 * @param id ext_args index to set (allocated via @ref tcp_ext_arg_alloc_id)
 * @param callbacks callback table (const since it is referenced, not copied!)
 */
void
tcp_ext_arg_set_callbacks(struct tcp_pcb *pcb, uint8_t id, const struct tcp_ext_arg_callbacks * const callbacks)
{
  LWIP_ASSERT("pcb != NULL", pcb != NULL);
  LWIP_ASSERT("id < LWIP_TCP_PCB_NUM_EXT_ARGS", id < LWIP_TCP_PCB_NUM_EXT_ARGS);
  LWIP_ASSERT("callbacks != NULL", callbacks != NULL);

  LWIP_ASSERT_CORE_LOCKED();

  pcb->ext_args[id].callbacks = callbacks;
}

/**
 * @ingroup tcp_raw_extargs
 * Set data for a given index of ext_args on the specified pcb.
 *
 * @param pcb tcp_pcb for which to set the data
 * @param id ext_args index to set (allocated via @ref tcp_ext_arg_alloc_id)
 * @param arg data pointer to set
 */
void tcp_ext_arg_set(struct tcp_pcb *pcb, uint8_t id, void *arg)
{
  LWIP_ASSERT("pcb != NULL", pcb != NULL);
  LWIP_ASSERT("id < LWIP_TCP_PCB_NUM_EXT_ARGS", id < LWIP_TCP_PCB_NUM_EXT_ARGS);

  LWIP_ASSERT_CORE_LOCKED();

  pcb->ext_args[id].data = arg;
}

/**
 * @ingroup tcp_raw_extargs
 * Set data for a given index of ext_args on the specified pcb.
 *
 * @param pcb tcp_pcb for which to set the data
 * @param id ext_args index to set (allocated via @ref tcp_ext_arg_alloc_id)
 * @return data pointer at the given index
 */
void *tcp_ext_arg_get(const struct tcp_pcb *pcb, uint8_t id)
{
  LWIP_ASSERT("pcb != NULL", pcb != NULL);
  LWIP_ASSERT("id < LWIP_TCP_PCB_NUM_EXT_ARGS", id < LWIP_TCP_PCB_NUM_EXT_ARGS);

  LWIP_ASSERT_CORE_LOCKED();

  return pcb->ext_args[id].data;
}

/** This function calls the "destroy" callback for all ext_args once a pcb is
 * freed.
 */
static void
tcp_ext_arg_invoke_callbacks_destroyed(struct tcp_pcb_ext_args *ext_args)
{
  int i;
  LWIP_ASSERT("ext_args != NULL", ext_args != NULL);

  for (i = 0; i < LWIP_TCP_PCB_NUM_EXT_ARGS; i++) {
    if (ext_args[i].callbacks != NULL) {
      if (ext_args[i].callbacks->destroy != NULL) {
        ext_args[i].callbacks->destroy((u8_t)i, ext_args[i].data);
      }
    }
  }
}

/** This function calls the "passive_open" callback for all ext_args if a connection
 * is in the process of being accepted. This is called just after the SYN is
 * received and before a SYN/ACK is sent, to allow to modify the very first
 * segment sent even on passive open. Naturally, the "accepted" callback of the
 * pcb has not been called yet!
 */
err_t
tcp_ext_arg_invoke_callbacks_passive_open(struct tcp_pcb_listen *lpcb, struct tcp_pcb *cpcb)
{
  int i;
  LWIP_ASSERT("lpcb != NULL", lpcb != NULL);
  LWIP_ASSERT("cpcb != NULL", cpcb != NULL);

  for (i = 0; i < LWIP_TCP_PCB_NUM_EXT_ARGS; i++) {
    if (lpcb->ext_args[i].callbacks != NULL) {
      if (lpcb->ext_args[i].callbacks->passive_open != NULL) {
        err_t err = lpcb->ext_args[i].callbacks->passive_open((u8_t)i, lpcb, cpcb);
        if (err != ERR_OK) {
          return err;
        }
      }
    }
  }
  return ERR_OK;
}
#endif /* LWIP_TCP_PCB_NUM_EXT_ARGS */

#endif /* LWIP_TCP */
