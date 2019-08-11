/**
 * @file
 * TCP API (to be used from TCPIP thread)\n
 * See also @ref tcp_raw
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
#ifndef LWIP_HDR_TCP_H
#define LWIP_HDR_TCP_H

#include "lwip/opt.h"

#if LWIP_TCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/tcpbase.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/icmp.h"
#include "lwip/err.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tcp_pcb;
struct tcp_pcb_listen;

/** Function prototype for tcp accept callback functions. Called when a new
 * connection can be accepted on a listening pcb.
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param newpcb The new connection pcb
 * @param err An error code if there has been an error accepting.
 *            Only return ERR_ABRT if you have called tcp_abort from within the
 *            callback function!
 */
typedef err_t (*tcp_accept_fn)(void *arg, struct tcp_pcb *newpcb, err_t err);

/** Function prototype for tcp receive callback functions. Called when data has
 * been received.
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param tpcb The connection pcb which received data
 * @param p The received data (or NULL when the connection has been closed!)
 * @param err An error code if there has been an error receiving
 *            Only return ERR_ABRT if you have called tcp_abort from within the
 *            callback function!
 */
typedef err_t (*tcp_recv_fn)(void *arg, struct tcp_pcb *tpcb,
                             struct pbuf *p, err_t err);

/** Function prototype for tcp sent callback functions. Called when sent data has
 * been acknowledged by the remote side. Use it to free corresponding resources.
 * This also means that the pcb has now space available to send new data.
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param tpcb The connection pcb for which data has been acknowledged
 * @param len The amount of bytes acknowledged
 * @return ERR_OK: try to send some data by calling tcp_output
 *            Only return ERR_ABRT if you have called tcp_abort from within the
 *            callback function!
 */
typedef err_t (*tcp_sent_fn)(void *arg, struct tcp_pcb *tpcb,
                              u16_t len);

/** Function prototype for tcp poll callback functions. Called periodically as
 * specified by @see tcp_poll.
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param tpcb tcp pcb
 * @return ERR_OK: try to send some data by calling tcp_output
 *            Only return ERR_ABRT if you have called tcp_abort from within the
 *            callback function!
 */
typedef err_t (*tcp_poll_fn)(void *arg, struct tcp_pcb *tpcb);

/** Function prototype for tcp error callback functions. Called when the pcb
 * receives a RST or is unexpectedly closed for any other reason.
 *
 * @note The corresponding pcb is already freed when this callback is called!
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param err Error code to indicate why the pcb has been closed
 *            ERR_ABRT: aborted through tcp_abort or by a TCP timer
 *            ERR_RST: the connection was reset by the remote host
 */
typedef void  (*tcp_err_fn)(void *arg, err_t err);

/** Function prototype for tcp connected callback functions. Called when a pcb
 * is connected to the remote side after initiating a connection attempt by
 * calling tcp_connect().
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param tpcb The connection pcb which is connected
 * @param err An unused error code, always ERR_OK currently ;-) @todo!
 *            Only return ERR_ABRT if you have called tcp_abort from within the
 *            callback function!
 *
 * @note When a connection attempt fails, the error callback is currently called!
 */
typedef err_t (*tcp_connected_fn)(void *arg, struct tcp_pcb *tpcb, err_t err);

#if LWIP_WND_SCALE
#define RCV_WND_SCALE(pcb, wnd) (((wnd) >> (pcb)->rcv_scale))
#define SND_WND_SCALE(pcb, wnd) (((wnd) << (pcb)->snd_scale))
#define TCPWND16(x)             ((u16_t)LWIP_MIN((x), 0xFFFF))
#define TCP_WND_MAX(pcb)        ((tcpwnd_size_t)(((pcb)->flags & TF_WND_SCALE) ? TCP_WND : TCPWND16(TCP_WND)))
#else
#define RCV_WND_SCALE(pcb, wnd) (wnd)
#define SND_WND_SCALE(pcb, wnd) (wnd)
#define TCPWND16(x)             (x)
#define TCP_WND_MAX(pcb)        TCP_WND
#endif

/* Increments a tcpwnd_size_t and holds at max value rather than rollover */
/* 把指定的 tcp 窗口变量增加指定的步长，如果增加到最大值则保持为最大值，不会出现溢出翻转 */
#define TCP_WND_INC(wnd, inc)   do { \
                                  if ((tcpwnd_size_t)(wnd + inc) >= wnd) { \
                                    wnd = (tcpwnd_size_t)(wnd + inc); \
                                  } else { \
                                    wnd = (tcpwnd_size_t)-1; \
                                  } \
                                } while(0)

#if LWIP_TCP_SACK_OUT
/** SACK ranges to include in ACK packets.
 * SACK entry is invalid if left==right. */
/* 定义了 tcp 数据包协议头中的 sack 选项对数据结构 */
struct tcp_sack_range {
  /** Left edge of the SACK: the first acknowledged sequence number. */
  u32_t left;
  /** Right edge of the SACK: the last acknowledged sequence number +1 (so first NOT acknowledged). */
  u32_t right;
};
#endif /* LWIP_TCP_SACK_OUT */

/** Function prototype for deallocation of arguments. Called *just before* the
 * pcb is freed, so don't expect to be able to do anything with this pcb!
 *
 * @param id ext arg id (allocated via @ref tcp_ext_arg_alloc_id)
 * @param data pointer to the data (set via @ref tcp_ext_arg_set before)
 */
typedef void (*tcp_extarg_callback_pcb_destroyed_fn)(u8_t id, void *data);

/** Function prototype to transition arguments from a listening pcb to an accepted pcb
 *
 * @param id ext arg id (allocated via @ref tcp_ext_arg_alloc_id)
 * @param lpcb the listening pcb accepting a connection
 * @param cpcb the newly allocated connection pcb
 * @return ERR_OK if OK, any error if connection should be dropped
 */
typedef err_t (*tcp_extarg_callback_passive_open_fn)(u8_t id, struct tcp_pcb_listen *lpcb, struct tcp_pcb *cpcb);

/** A table of callback functions that is invoked for ext arguments */
struct tcp_ext_arg_callbacks {
  /** @ref tcp_extarg_callback_pcb_destroyed_fn */
  tcp_extarg_callback_pcb_destroyed_fn destroy;
  /** @ref tcp_extarg_callback_passive_open_fn */
  tcp_extarg_callback_passive_open_fn passive_open;
};

#define LWIP_TCP_PCB_NUM_EXT_ARG_ID_INVALID 0xFF

#if LWIP_TCP_PCB_NUM_EXT_ARGS
/* This is the structure for ext args in tcp pcbs (used as array) */
struct tcp_pcb_ext_args {
  const struct tcp_ext_arg_callbacks *callbacks;
  void *data;
};
/* This is a helper define to prevent zero size arrays if disabled */
#define TCP_PCB_EXTARGS struct tcp_pcb_ext_args ext_args[LWIP_TCP_PCB_NUM_EXT_ARGS];
#else
#define TCP_PCB_EXTARGS
#endif

typedef u16_t tcpflags_t;
#define TCP_ALLFLAGS 0xffffU

/**
 * members common to struct tcp_pcb and struct tcp_listen_pcb
 */
#define TCP_PCB_COMMON(type) \
  type *next; /* for the linked list */ \
  void *callback_arg; \
  TCP_PCB_EXTARGS \
  enum tcp_state state; /* TCP state */ \
  u8_t prio; \
  /* ports are in host byte order */ \
  u16_t local_port


/** the TCP protocol control block for listening pcbs */
struct tcp_pcb_listen {
/** Common members of all PCB types */
  IP_PCB;
/** Protocol specific PCB members */
  TCP_PCB_COMMON(struct tcp_pcb_listen);

#if LWIP_CALLBACK_API
  /* Function to call when a listener has been connected. */
  tcp_accept_fn accept;
#endif /* LWIP_CALLBACK_API */

#if TCP_LISTEN_BACKLOG
  /* 表示当前协议栈的 tcp 模块支持的同时建立的连接请求数的最大值 */
  u8_t backlog;

  /* 表示当前 tcp 模块已经建立的连接请求数，在发送接受其他设备的连接请求时加一，在成功建立连接的时候减一 */
  u8_t accepts_pending;
#endif /* TCP_LISTEN_BACKLOG */
};


/** the TCP protocol control block */
/* 定义当前协议栈的 tcp 协议控制块结构 */
struct tcp_pcb {
  /** common PCB members */
  IP_PCB;

  /** protocol specific PCB members */
  TCP_PCB_COMMON(struct tcp_pcb);

  /* ports are in host byte order */  
  /* 表示当前 tcp 协议控制块的对端设备端口号 */
  u16_t remote_port;

  /* 表示当前 tcp 协议控制块的标志变量，例如 TF_NODELAY */
  tcpflags_t flags;

/* 表示当前 tcp 协议控制块正处于延迟应答状态 */
#define TF_ACK_DELAY   0x01U   /* Delayed ACK. */

/* 表示当前 tcp 协议控制块需要立即发送应答数据包 */
#define TF_ACK_NOW     0x02U   /* Immediate ACK. */

/* 表示当前 tcp 协议控制块正处于数据包快速重传状态 */
#define TF_INFR        0x04U   /* In fast recovery. */

/* 表示当前 tcp 协议控制块发送的 FIN 数据包发送失败，需要在 tcp_tmr 定时器中通过检查这个标志重新发送 */
#define TF_CLOSEPEND   0x08U   /* If this is set, tcp_close failed to enqueue the FIN (retried in tcp_tmr) */

/* 表示当前 tcp 协议控制块的接收数据端连接已经被关闭，即不能再接收对端设备发送的数据包了 */
#define TF_RXCLOSED    0x10U   /* rx closed by tcp_shutdown */

/* 表示当前 tcp 协议控制块已经发送了 FIN 数据包，即发起了关闭 tcp 连接请求 */
#define TF_FIN         0x20U   /* Connection was closed locally (FIN segment enqueued). */

/* 表示关闭 Nagle 算法逻辑
 * Nagle algorithm 的基本功能是为了减少大量小包的发送，实际上就是基于小包的停-等协议
 * 在等待已经发出的包被确认之前，发送端利用这段时间可以积累应用下来的数据，使其大小趋向于增加 */
#define TF_NODELAY     0x40U   /* Disable Nagle algorithm */

/* 表示在启用 Nagle 算法的时候，发生了缓冲区相关错误，需要把当前缓存的待发送数据尽快发送出去 */
#define TF_NAGLEMEMERR 0x80U   /* nagle enabled, memerr, try to output to prevent delayed ACK to happen */

/* 表示当前 tcp 协议控制块启用了窗口扩大因子选项功能 */
#if LWIP_WND_SCALE
#define TF_WND_SCALE   0x0100U /* Window Scale option enabled */
#endif

#if TCP_LISTEN_BACKLOG
/* 如果当前协议栈为 tcp 监听函数启用 backlog 选项，那么会通过统计 tcp 监听者的 backlog 计数值限制
 * tcp 模块同时建立的连接请求数，如果指定的 tcp 协议控制块已经设置了 TF_BACKLOGPEND 标志，表示这
 * 个协议控制块的 tcp 连接已经统计进了 tcp 监听者的 backlog 计数值中 */
#define TF_BACKLOGPEND 0x0200U /* If this is set, a connection pcb has increased the backlog on its listener */
#endif

/* 表示当前 tcp 协议控制块启用了时间戳选项功能 */
#if LWIP_TCP_TIMESTAMPS
#define TF_TIMESTAMP   0x0400U   /* Timestamp option enabled */
#endif

/* 表示当前 tcp 协议控制块的发送超时重传定时器已经启动 */
#define TF_RTO         0x0800U /* RTO timer has fired, in-flight data moved to unsent and being retransmitted */

/* 表示当前 tcp 协议控制块启用了 sack 选项功能 */
#if LWIP_TCP_SACK_OUT
#define TF_SACK        0x1000U /* Selective ACKs enabled */
#endif

  /* the rest of the fields are in host byte order
     as we have to do some math with them */

  /* Timers */
  u8_t polltmr, pollinterval;
  u8_t last_timer;

  /* 表示当前 tcp 协议控制块处于某种状态下的起始时间点，用来计算在这种状态持续的时间 */
  u32_t tmr;

  /* receiver variables */
  /* 表示当前 tcp 协议控制块下一次想要接收的 tcp 分片数据包的字序号 */
  u32_t rcv_nxt;   /* next seqno expected */

  /* 表示当前 tcp 协议控制块有效的接收数据窗口大小 */
  tcpwnd_size_t rcv_wnd;   /* receiver window available */

  /* 表示当前 tcp 协议控制块需要发送给其它对端设备的本地设备接收窗口大小 */
  tcpwnd_size_t rcv_ann_wnd; /* receiver window to announce */

  /* 表示当前 tcp 协议控制块接收窗口的右边沿位置 */
  u32_t rcv_ann_right_edge; /* announced right edge of window */

#if LWIP_TCP_SACK_OUT
  /* SACK ranges to include in ACK packets (entry is invalid if left==right) */
  /* 记录当前 tcp 协议控制块需要发送的 sack 数据对，这个选项只有在接收的数据块不连续的情景下使用
   * 用来通知数据发送端，已经接收到了哪些数据块，这样发送端就不必重新发送这些数据块了 */
  struct tcp_sack_range rcv_sacks[LWIP_TCP_MAX_SACK_NUM];

/* 判断指定的 tcp 协议控制块的指定索引位置处的 sack 选项数据是否有效 */
#define LWIP_TCP_SACK_VALID(pcb, idx) ((pcb)->rcv_sacks[idx].left != (pcb)->rcv_sacks[idx].right)
#endif /* LWIP_TCP_SACK_OUT */

  /* Retransmission timer. */
  /* 表示当前 tcp 协议控制块的超时重传定时器计数值，在我们发送完一个数据包之后，会启动超时重传
   * 定时器，表示如果在指定的时间内没有收到应答数据包（不一定是我们刚刚发送的数据包的应答数据包
   * 也可以是之前发送的数据包的应答数据包），则表示我们的数据包发送失败需要重新传输，-1 表示定
   * 时器没启动，其他值表示从发送数据包后已经消耗的时间周期数 */
  s16_t rtime;

  /* 通过 tcp mss 和网络接口的 mtu 计算得到的有效 mss，详细见 tcp_eff_send_mss_netif */
  u16_t mss;   /* maximum segment size */

  /* RTT (round trip time) estimation variables */
  /* 表示在计算当前 tcp 协议控制块的数据包收发时间（RTT）时，发送数据包时刻的系统时间 */
  u32_t rttest; /* RTT estimate in 500ms ticks */

  /* 表示当前 tcp 协议控制块正在计时的 tcp 分片数据包的字序号 */
  u32_t rtseq;  /* sequence number being timed */
  
  s16_t sa, sv; /* @see "Congestion Avoidance and Control" by Van Jacobson and Karels */

  /* 表示当前 tcp 协议控制块的数据包超时重传定时器的超时时间，单位是 TCP_SLOW_INTERVAL */
  s16_t rto;    /* retransmission time-out (in ticks of TCP_SLOW_INTERVAL) */

  /* 表示当前 tcp 协议控制块“连续”启动重传数据包的次数 */
  u8_t nrtx;    /* number of retransmissions */

  /* fast retransmit/recovery */
  /* 表示当前 tcp 协议控制块连续接收到的重复应答数据包次数，有关这个计数值的处理，分别有如下几条：
   * a) dupacks < 3: do nothing
   * b) dupacks == 3: fast retransmit
   * c) dupacks > 3: increase cwnd 
   */
  u8_t dupacks;

  /* 表示当前 tcp 协议控制块已经应答的最大字序号的值 */
  u32_t lastack; /* Highest acknowledged seqno. */

  /* congestion avoidance/control variables */
  /* 拥塞窗口的作用：流量控制可以很好地解决发送端与接收端之间的端-端报文发送和
   * 处理速度的协调，但是无法控制进入网络的总体流量。如果每个发送端与接收端的
   * 端-端之间流量是合适的，但是对于网络整体来说，随着网络的流量增加，也会使网
   * 络通信负荷过重由此引起报文传输延迟增大或丢弃。报文的差错确认和重传又会进
   * 一步加剧网络的拥塞，所以引入了拥塞窗口大小这个参数 */
  /* 表示当前 tcp 协议控制块的拥塞窗口大小，在发送数据包的时候选择发送窗口和拥塞窗口二者中的小值作为有效发送窗口 */
  tcpwnd_size_t cwnd;

  /* 慢启动描述（因为新设备不清楚当前网络拥塞状态，需要一个探测过程，即慢启动）：
   * 1. 在刚刚开始发送报文段时，先把拥塞窗口 cwnd 设置为一个最大报文段 MSS 的数
   *    值。而在每收到一个对新的报文段的确认后，把拥塞窗口以 2 的指数增长。用这
   *    样的方法逐步增大发送方的拥塞窗口 cwnd，可以使分组注入到网络的速率更加合理
   * 2. 每经过一个传输轮次，拥塞窗口 cwnd 就加倍。一个传输轮次所经历的时间其实就
   *    是往返时间 RTT。不过“传输轮次”更加强调：把拥塞窗口 cwnd 所允许发送的报文
   *    段都连续发送出去，并收到了对已发送所有数据包的确认信息
   * 3. 慢开始的“慢”并不是指 cwnd 的增长速率慢，而是指在 TCP 开始发送报文段时先
   *    设置 cwnd=1，使得发送方在开始时只发送一个报文段（目的是试探一下网络的拥
   *    塞情况），然后再逐渐增大 cwnd
   * 为了防止拥塞窗口 cwnd 增长过大引起网络拥塞，还需要设置一个慢启动阈值 ssthresh
   * 状态变量（如何设置 ssthresh）。慢启动阈值 ssthresh 的用法如下： 
   * 1. 当 cwnd < ssthresh 时，使用上述的慢启动算法 
   * 2. 当 cwnd > ssthresh 时，停止使用慢启动算法而改用拥塞避免算法
   * 3. 当 cwnd = ssthresh 时，既可使用慢启动算法，也可使用拥塞控制避免算法 */
  
  /* 拥塞避免算法：
   * 1. 让拥塞窗口 cwnd 缓慢地增大，即每经过一个轮次就把发送方的拥塞窗口 cwnd 
   *	加 1，而不是加倍。这样拥塞窗口 cwnd 按线性规律缓慢增长，比慢启动算法的
   *	指数拥塞窗口增长速率缓慢得多
   * 2. “拥塞避免”并非指完全能够避免了拥塞。利用以上的措施要完全避免网络拥塞还
   *	是不可能的。“拥塞避免”是说在拥塞避免阶段将拥塞窗口控制为按线性规律增长
   *	使网络比较不容易出现拥塞
   * 3. 无论在慢动阶段还是在拥塞避免阶段，只要发送方判断网络出现拥塞（其根据就
   *	是没有收到确认），就要把慢启动阈值 ssthresh 设置为出现拥塞时的发送方窗
   *	口或者拥塞窗口值（取二者中小的）的一半（但不能小于2）。然后把拥塞窗口 
   *	cwnd 重新设置为 1，执行慢启动算法。这样做的目的就是要迅速减少主机发送到
   *	网络中的分片数据包，使得发生拥塞的路由器有足够时间把队列中积压的分片数
   *    据包处理完毕 */

  /* 表示当前 tcp 协议控制块的慢启动阈值 */
  tcpwnd_size_t ssthresh;

  /* first byte following last rto byte */
  /* 表示重传分片数据包链表表示的字序号范围的下一个字序号的值，详情见 tcp_rexmit_rto_prepare */
  u32_t rto_end;

  /* sender variables */
  /* 表示当前 tcp 协议控制块下一次发送的 tcp 分片数据包的字序号 */
  u32_t snd_nxt;   /* next new seqno to be sent */

  /* 表示当前 tcp 协议控制块上一次更新发送窗口大小时接收到的数据包的字序号和应答字序号 */
  u32_t snd_wl1, snd_wl2; /* Sequence and acknowledgement numbers of last
                             window update. */

  /* 追踪记录当前 tcp 协议控制块下一次构建发送分片数据包时使用的字节号 */							 
  u32_t snd_lbb;       /* Sequence number of next byte to be buffered. */

  /* 表示当前 tcp 协议控制块的发送窗口大小，在发送数据包的时候选择发送窗口和拥塞窗口二者中的小值作为有效发送窗口 */				 
  tcpwnd_size_t snd_wnd;   /* sender window */

  /* 表示由对端设备宣称的最大发送窗口，在我们发送数据的时候使用 */
  tcpwnd_size_t snd_wnd_max; /* the maximum sender window announced by the remote host */

  /* 表示当前 tcp 协议控制块的发送数据缓冲区大小，单位是八位字节，随着收发数据动态变化 */
  tcpwnd_size_t snd_buf;   /* Available buffer space for sending (in bytes). */
  
#define TCP_SNDQUEUELEN_OVERFLOW (0xffffU-3)

  /* 表示当前 tcp 协议控制块发送队列中包含的 pbuf 个数，包含了未发送的数据包和发送但是未应答的数据包之和 */
  u16_t snd_queuelen; /* Number of pbufs currently in the send buffer. */

#if TCP_OVERSIZE
  /* Extra bytes available at the end of the last pbuf in unsent. */
  /* 表示在未发送数据包队列最后一个 tcp 分片数据包成员中空闲的、可存储新数据的内存空间大小 */
  u16_t unsent_oversize;
#endif /* TCP_OVERSIZE */

  /* 表示当前 tcp 协议控制块在拥塞窗口范围内，已经应答的数据包字节数？？？ */
  tcpwnd_size_t bytes_acked;

  /* These are ordered by sequence number: */
  /* 通过单向链表把所有未发送的数据包按照队列的方式组织起来，在队列中的数据包，是按照字节号升序方式排列的 */
  struct tcp_seg *unsent;   /* Unsent (queued) segments. */
  
  /* 通过单向链表把所有已经发送但是还未应答的数据包按照队列的方式组织起来，在队列中的数据包是按照字节号升序方式排列的
   * 我们在发送完 tcp 分片数据包之后，会把的发送的分片数据包结构添加到对应的 tcp 协议控制块中，然后为这些数据包启动一
   * 个重传定时器，表示如果在指定的时间内，这些数据包还没有接收到应答信息，表示发送失败，则需要启动重传逻辑，所以为了
   * 实现发送失败重传功能，我们在发送完数据包之后不能直接释放对应 tcp 分片数据包的内存空间，需要在接收到应答信息的时候
   * 才能释放这个 tcp 分片数据包占用的内存空间 */
  struct tcp_seg *unacked;  /* Sent but unacknowledged segments. */

/* 表示当前 tcp 协议控制块接收到的乱序 tcp 分片数据包队列 */
#if TCP_QUEUE_OOSEQ
  struct tcp_seg *ooseq;    /* Received out of sequence segments. */
#endif /* TCP_QUEUE_OOSEQ */

  /* 表示当前 tcp 协议控制块之前已经接收到的、但是还没被上层（应用层）协议处理的数据包 */
  struct pbuf *refused_data; /* Data previously received but not yet taken by upper layer */

#if LWIP_CALLBACK_API || TCP_LISTEN_BACKLOG
  /* 表示当前 tcp 协议控制块所属 tcp 监听者（在服务端监听并处理其他设备的连接请求）*/
  struct tcp_pcb_listen* listener;
#endif /* LWIP_CALLBACK_API || TCP_LISTEN_BACKLOG */

#if LWIP_CALLBACK_API
  /* Function to be called when more send buffer space is available. */
  tcp_sent_fn sent;
  /* Function to be called when (in-sequence) data has arrived. */
  tcp_recv_fn recv;
  /* Function to be called when a connection has been set up. */
  tcp_connected_fn connected;
  /* Function which is called periodically. */
  tcp_poll_fn poll;
  /* Function to be called whenever a fatal error occurs. */
  tcp_err_fn errf;
#endif /* LWIP_CALLBACK_API */

#if LWIP_TCP_TIMESTAMPS
  /* 表示当前 tcp 协议控制块最后一次发送的应答字序号值 */
  u32_t ts_lastacksent;

  /* 表示当前 tcp 协议控制块接收到的最近一次对端设备在 tcp 协议头中发送的时间戳选项值 */
  u32_t ts_recent;
#endif /* LWIP_TCP_TIMESTAMPS */

  /* idle time before KEEPALIVE is sent */
  u32_t keep_idle;

#if LWIP_TCP_KEEPALIVE
  u32_t keep_intvl;
  u32_t keep_cnt;
#endif /* LWIP_TCP_KEEPALIVE */

  /* 坚持定时器（Persist timer）：当接收方建议的窗口大小为 0 时，发送方就会停止发送
   * 直到接收方有缓存空间时再用一个窗口值非零的 ACK 提示发送方可以继续发送。但是这个
   * 称为 Window update 的 ACK 报文段很可能会发生丢失，这个时候就不可避免地发送了死锁
   * 因此，发送方需要设置一个坚持定时器，每隔一段时间就向接收方发送一个窗口探测报文
   * 当接收方可以接收数据时就重新开始发送 */
   
  /* Persist timer counter */
  /* 表示当前 tcp 协议控制块的坚持定时器计数，当计数值超过当前退避时间，则发送一个窗口探查数据包 */
  u8_t persist_cnt;

  /* Persist timer back-off */
  /* 表示当前 tcp 协议控制块的坚持定时器的退避时间索引值（这个值是退避时间数组的索引值加 1）
   * 如果是 0，则表示没有启动坚持定时器功能 */
  u8_t persist_backoff;
  
  /* Number of persist probes */
  /* 表示当前 tcp 协议控制块发送窗口探测数据包的个数 */
  u8_t persist_probe;

  /* KEEPALIVE counter */
  /* 表示当前 tcp 协议可控制块发送的“保活探测”数据包次数 */
  u8_t keep_cnt_sent;

#if LWIP_WND_SCALE
  /* 表示当前 tcp 协议控制块的“发送”窗口扩大因子数值 */
  u8_t snd_scale;

  /* 表示当前 tcp 协议控制块的“接收”窗口扩大因子数值 */
  u8_t rcv_scale;
#endif
};

#if LWIP_EVENT_API

enum lwip_event {
  LWIP_EVENT_ACCEPT,
  LWIP_EVENT_SENT,
  LWIP_EVENT_RECV,
  LWIP_EVENT_CONNECTED,
  LWIP_EVENT_POLL,
  LWIP_EVENT_ERR
};

err_t lwip_tcp_event(void *arg, struct tcp_pcb *pcb,
         enum lwip_event,
         struct pbuf *p,
         u16_t size,
         err_t err);

#endif /* LWIP_EVENT_API */

/* Application program's interface: */
struct tcp_pcb * tcp_new     (void);
struct tcp_pcb * tcp_new_ip_type (u8_t type);

void             tcp_arg     (struct tcp_pcb *pcb, void *arg);
#if LWIP_CALLBACK_API
void             tcp_recv    (struct tcp_pcb *pcb, tcp_recv_fn recv);
void             tcp_sent    (struct tcp_pcb *pcb, tcp_sent_fn sent);
void             tcp_err     (struct tcp_pcb *pcb, tcp_err_fn err);
void             tcp_accept  (struct tcp_pcb *pcb, tcp_accept_fn accept);
#endif /* LWIP_CALLBACK_API */
void             tcp_poll    (struct tcp_pcb *pcb, tcp_poll_fn poll, u8_t interval);

/* 设置指定 tcp 协议控制块的指定 tcp flags 标志位 */
#define          tcp_set_flags(pcb, set_flags)     do { (pcb)->flags = (tcpflags_t)((pcb)->flags |  (set_flags)); } while(0)

/* 清除指定 tcp 协议控制块的指定 tcp flags 标志位 */
#define          tcp_clear_flags(pcb, clr_flags)   do { (pcb)->flags = (tcpflags_t)((pcb)->flags & (tcpflags_t)(~(clr_flags) & TCP_ALLFLAGS)); } while(0)

/* 判断指定 tcp 协议控制块的指定 tcp flags 标志位是否置位 */
#define          tcp_is_flag_set(pcb, flag)        (((pcb)->flags & (flag)) != 0)

#if LWIP_TCP_TIMESTAMPS
#define          tcp_mss(pcb)             (((pcb)->flags & TF_TIMESTAMP) ? ((pcb)->mss - 12)  : (pcb)->mss)
#else /* LWIP_TCP_TIMESTAMPS */
/** @ingroup tcp_raw */
#define          tcp_mss(pcb)             ((pcb)->mss)
#endif /* LWIP_TCP_TIMESTAMPS */

/** @ingroup tcp_raw */
/* 获取指定的 tcp 协议控制块的发送缓冲区大小 */
#define          tcp_sndbuf(pcb)          (TCPWND16((pcb)->snd_buf))

/** @ingroup tcp_raw */
/* 获取指定的 tcp 协议控制块的发送队列大小 */
#define          tcp_sndqueuelen(pcb)     ((pcb)->snd_queuelen)

/** @ingroup tcp_raw */
#define          tcp_nagle_disable(pcb)   tcp_set_flags(pcb, TF_NODELAY)
/** @ingroup tcp_raw */
#define          tcp_nagle_enable(pcb)    tcp_clear_flags(pcb, TF_NODELAY)
/** @ingroup tcp_raw */
#define          tcp_nagle_disabled(pcb)  tcp_is_flag_set(pcb, TF_NODELAY)

/* 操作处于 listen 状态的 tcp 协议控制块的 backlog 接口 */
#if TCP_LISTEN_BACKLOG
#define          tcp_backlog_set(pcb, new_backlog) do { \
  LWIP_ASSERT("pcb->state == LISTEN (called for wrong pcb?)", (pcb)->state == LISTEN); \
  ((struct tcp_pcb_listen *)(pcb))->backlog = ((new_backlog) ? (new_backlog) : 1); } while(0)
void             tcp_backlog_delayed(struct tcp_pcb* pcb);
void             tcp_backlog_accepted(struct tcp_pcb* pcb);
#else  /* TCP_LISTEN_BACKLOG */
#define          tcp_backlog_set(pcb, new_backlog)
#define          tcp_backlog_delayed(pcb)
#define          tcp_backlog_accepted(pcb)
#endif /* TCP_LISTEN_BACKLOG */


#define          tcp_accepted(pcb) do { LWIP_UNUSED_ARG(pcb); } while(0) /* compatibility define, not needed any more */

void             tcp_recved  (struct tcp_pcb *pcb, u16_t len);
err_t            tcp_bind    (struct tcp_pcb *pcb, const ip_addr_t *ipaddr,
                              u16_t port);
void             tcp_bind_netif(struct tcp_pcb *pcb, const struct netif *netif);
err_t            tcp_connect (struct tcp_pcb *pcb, const ip_addr_t *ipaddr,
                              u16_t port, tcp_connected_fn connected);

struct tcp_pcb * tcp_listen_with_backlog_and_err(struct tcp_pcb *pcb, u8_t backlog, err_t *err);
struct tcp_pcb * tcp_listen_with_backlog(struct tcp_pcb *pcb, u8_t backlog);
/** @ingroup tcp_raw */
#define          tcp_listen(pcb) tcp_listen_with_backlog(pcb, TCP_DEFAULT_LISTEN_BACKLOG)

void             tcp_abort (struct tcp_pcb *pcb);
err_t            tcp_close   (struct tcp_pcb *pcb);
err_t            tcp_shutdown(struct tcp_pcb *pcb, int shut_rx, int shut_tx);

err_t            tcp_write   (struct tcp_pcb *pcb, const void *dataptr, u16_t len,
                              u8_t apiflags);

void             tcp_setprio (struct tcp_pcb *pcb, u8_t prio);

err_t            tcp_output  (struct tcp_pcb *pcb);

err_t            tcp_tcp_get_tcp_addrinfo(struct tcp_pcb *pcb, int local, ip_addr_t *addr, u16_t *port);

#define tcp_dbg_get_tcp_state(pcb) ((pcb)->state)

/* for compatibility with older implementation */
#define tcp_new_ip6() tcp_new_ip_type(IPADDR_TYPE_V6)

#if LWIP_TCP_PCB_NUM_EXT_ARGS
u8_t tcp_ext_arg_alloc_id(void);
void tcp_ext_arg_set_callbacks(struct tcp_pcb *pcb, uint8_t id, const struct tcp_ext_arg_callbacks * const callbacks);
void tcp_ext_arg_set(struct tcp_pcb *pcb, uint8_t id, void *arg);
void *tcp_ext_arg_get(const struct tcp_pcb *pcb, uint8_t id);
#endif

#ifdef __cplusplus
}
#endif

#endif /* LWIP_TCP */

#endif /* LWIP_HDR_TCP_H */
