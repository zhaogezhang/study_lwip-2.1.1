/**
 * @file
 * pbuf API
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

#ifndef LWIP_HDR_PBUF_H
#define LWIP_HDR_PBUF_H

#include "lwip/opt.h"
#include "lwip/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** LWIP_SUPPORT_CUSTOM_PBUF==1: Custom pbufs behave much like their pbuf type
 * but they are allocated by external code (initialised by calling
 * pbuf_alloced_custom()) and when pbuf_free gives up their last reference, they
 * are freed by calling pbuf_custom->custom_free_function().
 * Currently, the pbuf_custom code is only needed for one specific configuration
 * of IP_FRAG, unless required by external driver/application code. */
#ifndef LWIP_SUPPORT_CUSTOM_PBUF
#define LWIP_SUPPORT_CUSTOM_PBUF ((IP_FRAG && !LWIP_NETIF_TX_SINGLE_PBUF) || (LWIP_IPV6 && LWIP_IPV6_FRAG))
#endif

/** @ingroup pbuf 
 * PBUF_NEEDS_COPY(p): return a boolean value indicating whether the given
 * pbuf needs to be copied in order to be kept around beyond the current call
 * stack without risking being corrupted. The default setting provides safety:
 * it will make a copy iof any pbuf chain that does not consist entirely of
 * PBUF_ROM type pbufs. For setups with zero-copy support, it may be redefined
 * to evaluate to true in all cases, for example. However, doing so also has an
 * effect on the application side: any buffers that are *not* copied must also
 * *not* be reused by the application after passing them to lwIP. For example,
 * when setting PBUF_NEEDS_COPY to (0), after using udp_send() with a PBUF_RAM
 * pbuf, the application must free the pbuf immediately, rather than reusing it
 * for other purposes. For more background information on this, see tasks #6735
 * and #7896, and bugs #11400 and #49914. */
#ifndef PBUF_NEEDS_COPY
#define PBUF_NEEDS_COPY(p)  ((p)->type_internal & PBUF_TYPE_FLAG_DATA_VOLATILE)
#endif /* PBUF_NEEDS_COPY */

/* @todo: We need a mechanism to prevent wasting memory in every pbuf
   (TCP vs. UDP, IPv4 vs. IPv6: UDP/IPv4 packets may waste up to 28 bytes) */
/* 传输层协议头字节数 */
#define PBUF_TRANSPORT_HLEN 20

/* IP 层协议头字节数(IPv6 协议报头长度固定为 40 字节，而 IPv4 协议报头长度在 20 字节
 * 到 60 字节之间，其中前面 20 字节数据为固定必须字段，后面的 40 字节是可选 IP Options
 * 字段，因为在实际使用中 IP Options 字段应用场景很少，所以 LWIP 在实现 IPv4 时默认不
 * 支持 IP Options 选项字段，所以 IPv4 报头长度默认为 20 字节 */
#if LWIP_IPV6
#define PBUF_IP_HLEN        40
#else
#define PBUF_IP_HLEN        20
#endif

/**
 * @ingroup pbuf
 * Enumeration of pbuf layers
 */
/* 这个枚举变量定义了 TCP/IP 协议栈不同层需要的报头长度，因为 LWIP 协议栈在不同层
 * 之间使用 pbuf 传输数据，所以为了能够在指定的 pbuf 中找到当前协议层有效负载数据
 * 的起始地址，只需要以 pbuf 缓冲区起始地址为起点，加上当前协议层报头长度即可 */
typedef enum {
  /** Includes spare room for transport layer header, e.g. UDP header.
   * Use this if you intend to pass the pbuf to functions like udp_send().
   */
  PBUF_TRANSPORT = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + PBUF_IP_HLEN + PBUF_TRANSPORT_HLEN,
  /** Includes spare room for IP header.
   * Use this if you intend to pass the pbuf to functions like raw_send().
   */
  PBUF_IP = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + PBUF_IP_HLEN,
  /** Includes spare room for link layer header (ethernet header).
   * Use this if you intend to pass the pbuf to functions like ethernet_output().
   * @see PBUF_LINK_HLEN
   */
  PBUF_LINK = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN,
  /** Includes spare room for additional encapsulation header before ethernet
   * headers (e.g. 802.11).
   * Use this if you intend to pass the pbuf to functions like netif->linkoutput().
   * @see PBUF_LINK_ENCAPSULATION_HLEN
   */
  PBUF_RAW_TX = PBUF_LINK_ENCAPSULATION_HLEN,
  /** Use this for input packets in a netif driver when calling netif->input()
   * in the most common case - ethernet-layer netif driver. */
  PBUF_RAW = 0
} pbuf_layer;


/* Base flags for pbuf_type definitions: */

/** Indicates that the payload directly follows the struct pbuf.
 *  This makes @ref pbuf_header work in both directions. */
/* 表示 struct pbuf 结构和负载数据是连续且处于同一个内存块中，所以我们可以
 * 通过 struct pbuf 计算出负载数据的起始地址 */
#define PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS       0x80

/** Indicates the data stored in this pbuf can change. If this pbuf needs
 * to be queued, it must be copied/duplicated. */
#define PBUF_TYPE_FLAG_DATA_VOLATILE                0x40

/** 4 bits are reserved for 16 allocation sources (e.g. heap, pool1, pool2, etc)
 * Internally, we use: 0=heap, 1=MEMP_PBUF, 2=MEMP_PBUF_POOL -> 13 types free*/
/* 在 pbuf->type_internal 变量中使用 4 bit 表示当前 pbuf 是从哪里分配的，基本的
 * 来源包括：内存堆（mem_malloc）、MEMP_PBUF（PBUF_REF/ROM）和 MEMP_PBUF_POOL（PBUF_POOL）*/
#define PBUF_TYPE_ALLOC_SRC_MASK                    0x0F

/** Indicates this pbuf is used for RX (if not set, indicates use for TX).
 * This information can be used to keep some spare RX buffers e.g. for
 * receiving TCP ACKs to unblock a connection) */
/* 表示当前 pbuf 是用于网卡的接收数据缓冲区，如果没设置这个标志，就表示当前
 * pbuf 是用于网卡的发送数据缓冲区 */
#define PBUF_ALLOC_FLAG_RX                          0x0100

/** Indicates the application needs the pbuf payload to be in one piece */
/* 表示当前 pbuf 的 struct pbuf 结构和负载数据是连续且处于同一个内存块中 */
#define PBUF_ALLOC_FLAG_DATA_CONTIGUOUS             0x0200

/* 表示当前 pbuf 内存是从系统内存堆（mem_malloc）中申请的，即当前 pbuf 类型为 PBUF_RAM */
#define PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP           0x00

/* 表示当前 pbuf 内存是从 MEMP_PBUF 中申请的，即当前 pbuf 类型为 PBUF_REF/ROM */
#define PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF      0x01

/* 表示当前 pbuf 内存是从 MEMP_PBUF_POOL 中申请的，即当前 pbuf 类型为 PBUF_POOL */
#define PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF_POOL 0x02

/** First pbuf allocation type for applications */
#define PBUF_TYPE_ALLOC_SRC_MASK_APP_MIN            0x03
/** Last pbuf allocation type for applications */
#define PBUF_TYPE_ALLOC_SRC_MASK_APP_MAX            PBUF_TYPE_ALLOC_SRC_MASK

/**
 * @ingroup pbuf
 * Enumeration of pbuf types
 */
/* 定义了当前 LWIP 一共支持的几种 pbuf 数据缓冲区类型 */
typedef enum {
  /** pbuf data is stored in RAM, used for TX mostly, struct pbuf and its payload
      are allocated in one piece of contiguous memory (so the first payload byte
      can be calculated from struct pbuf).
      pbuf_alloc() allocates PBUF_RAM pbufs as unchained pbufs (although that might
      change in future versions).
      This should be used for all OUTGOING packets (TX).*/
  /* 这种类型的 pbuf 常用于发送数据，这种类型缓冲区的 struct pbuf 结构和负载数据是连续且处于
   * 同一个内存块中，所以我们可以通过 struct pbuf 计算出负载数据的起始地址 */
  PBUF_RAM = (PBUF_ALLOC_FLAG_DATA_CONTIGUOUS | PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS | PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP),
  /** pbuf data is stored in ROM, i.e. struct pbuf and its payload are located in
      totally different memory areas. Since it points to ROM, payload does not
      have to be copied when queued for transmission. */
  PBUF_ROM = PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF,
  /** pbuf comes from the pbuf pool. Much like PBUF_ROM but payload might change
      so it has to be duplicated when queued before transmitting, depending on
      who has a 'ref' to it. */
  PBUF_REF = (PBUF_TYPE_FLAG_DATA_VOLATILE | PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF),
  /** pbuf payload refers to RAM. This one comes from a pool and should be used
      for RX. Payload can be chained (scatter-gather RX) but like PBUF_RAM, struct
      pbuf and its payload are allocated in one piece of contiguous memory (so
      the first payload byte can be calculated from struct pbuf).
      Don't use this for TX, if the pool becomes empty e.g. because of TCP queuing,
      you are unable to receive TCP acks! */
  /* 这种类型的 pbuf 常用于接收数据，这种类型缓冲区的 struct pbuf 结构和第一个负载数据块是连续
   * 且处于同一个内存块中，所以我们可以通过 struct pbuf 计算出负载数据的起始地址。又因为网卡驱动
   * 在接收数据的时候，大部分 DMA 都工作于 scatter-gather 模式且接收数据帧长度不定，所以接收缓冲
   * 区是通过链表把每个接收 pbuf 数据链接在一起、形成一个 pbuf chain，直到接收到一个完成数据帧时
   * 才把这个 pbuf chain 提交到协议栈上层进行处理 */
  PBUF_POOL = (PBUF_ALLOC_FLAG_RX | PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS | PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF_POOL)
} pbuf_type;


/** indicates this packet's data should be immediately passed to the application */
#define PBUF_FLAG_PUSH      0x01U

/** indicates this is a custom pbuf: pbuf_free calls pbuf_custom->custom_free_function()
    when the last reference is released (plus custom PBUF_RAM cannot be trimmed) */
/* 表示当前的 pbuf 类型是用户自定义的 pbuf_custom */
#define PBUF_FLAG_IS_CUSTOM 0x02U

/** indicates this pbuf is UDP multicast to be looped back */
/* 表示当前通过 udp 多播协议发送的数据包需要回环发送到当前网络接口上 */
#define PBUF_FLAG_MCASTLOOP 0x04U

/** indicates this pbuf was received as link-level broadcast */
/* 表示链路层接收到的是一个广播包，在 ip4_canforward 函数中使用 */
#define PBUF_FLAG_LLBCAST   0x08U

/** indicates this pbuf was received as link-level multicast */
/* 表示链路层接收到的是一个多播包，在 ip4_canforward 函数中使用 */
#define PBUF_FLAG_LLMCAST   0x10U

/** indicates this pbuf includes a TCP FIN flag */
#define PBUF_FLAG_TCP_FIN   0x20U

/** Main packet buffer struct */
struct pbuf {
  /** next pbuf in singly linked pbuf chain */
  struct pbuf *next;

  /** pointer to the actual data in the buffer */
  void *payload;

  /**
   * total length of this buffer and all next buffers in chain
   * belonging to the same packet.
   *
   * For non-queue packet chains this is the invariant:
   * p->tot_len == p->len + (p->next? p->next->tot_len: 0)
   */
  u16_t tot_len;

  /** length of this buffer */
  /* 表示当前 pbuf 结构有效负载空间字节数，不包含被隐藏的协议头数据 */
  u16_t len;

  /** a bit field indicating pbuf type and allocation sources
      (see PBUF_TYPE_FLAG_*, PBUF_ALLOC_FLAG_* and PBUF_TYPE_ALLOC_SRC_MASK)
    */
  u8_t type_internal;

  /** misc flags，for example PBUF_FLAG_IS_CUSTOM */
  u8_t flags;

  /**
   * the reference count always equals the number of pointers
   * that refer to this pbuf. This can be pointers from an application,
   * the stack itself, or pbuf->next pointers from a chain.
   */
  /* 表示当前 pbuf 结构的引用计数（刚申请的 pbuf 默认引用计数为 1）*/
  LWIP_PBUF_REF_T ref;

  /** For incoming packets, this contains the input netif's index */
  u8_t if_idx;
};


/** Helper struct for const-correctness only.
 * The only meaning of this one is to provide a const payload pointer
 * for PBUF_ROM type.
 */
struct pbuf_rom {
  /** next pbuf in singly linked pbuf chain */
  struct pbuf *next;

  /** pointer to the actual data in the buffer */
  const void *payload;
};

#if LWIP_SUPPORT_CUSTOM_PBUF
/** Prototype for a function to free a custom pbuf */
typedef void (*pbuf_free_custom_fn)(struct pbuf *p);

/** A custom pbuf: like a pbuf, but following a function pointer to free it. */
struct pbuf_custom {
  /** The actual pbuf */
  struct pbuf pbuf;
  /** This function is called when pbuf_free deallocates this pbuf(_custom) */
  pbuf_free_custom_fn custom_free_function;
};
#endif /* LWIP_SUPPORT_CUSTOM_PBUF */

/** Define this to 0 to prevent freeing ooseq pbufs when the PBUF_POOL is empty */
#ifndef PBUF_POOL_FREE_OOSEQ
#define PBUF_POOL_FREE_OOSEQ 1
#endif /* PBUF_POOL_FREE_OOSEQ */
#if LWIP_TCP && TCP_QUEUE_OOSEQ && NO_SYS && PBUF_POOL_FREE_OOSEQ
extern volatile u8_t pbuf_free_ooseq_pending;
void pbuf_free_ooseq(void);
/** When not using sys_check_timeouts(), call PBUF_CHECK_FREE_OOSEQ()
    at regular intervals from main level to check if ooseq pbufs need to be
    freed! */
#define PBUF_CHECK_FREE_OOSEQ() do { if(pbuf_free_ooseq_pending) { \
  /* pbuf_alloc() reported PBUF_POOL to be empty -> try to free some \
     ooseq queued pbufs now */ \
  pbuf_free_ooseq(); }}while(0)
#else /* LWIP_TCP && TCP_QUEUE_OOSEQ && NO_SYS && PBUF_POOL_FREE_OOSEQ */
  /* Otherwise declare an empty PBUF_CHECK_FREE_OOSEQ */
  #define PBUF_CHECK_FREE_OOSEQ()
#endif /* LWIP_TCP && TCP_QUEUE_OOSEQ && NO_SYS && PBUF_POOL_FREE_OOSEQ*/

/* Initializes the pbuf module. This call is empty for now, but may not be in future. */
#define pbuf_init()

struct pbuf *pbuf_alloc(pbuf_layer l, u16_t length, pbuf_type type);
struct pbuf *pbuf_alloc_reference(void *payload, u16_t length, pbuf_type type);
#if LWIP_SUPPORT_CUSTOM_PBUF
struct pbuf *pbuf_alloced_custom(pbuf_layer l, u16_t length, pbuf_type type,
                                 struct pbuf_custom *p, void *payload_mem,
                                 u16_t payload_mem_len);
#endif /* LWIP_SUPPORT_CUSTOM_PBUF */
void pbuf_realloc(struct pbuf *p, u16_t size);

/* 获取指定的 pbuf 类型标志信息 */
#define pbuf_get_allocsrc(p)          ((p)->type_internal & PBUF_TYPE_ALLOC_SRC_MASK)

/* 判断指定的 pbuf 是否是指定的类型 */
#define pbuf_match_allocsrc(p, type)  (pbuf_get_allocsrc(p) == ((type) & PBUF_TYPE_ALLOC_SRC_MASK))

#define pbuf_match_type(p, type)      pbuf_match_allocsrc(p, type)
u8_t pbuf_header(struct pbuf *p, s16_t header_size);
u8_t pbuf_header_force(struct pbuf *p, s16_t header_size);
u8_t pbuf_add_header(struct pbuf *p, size_t header_size_increment);
u8_t pbuf_add_header_force(struct pbuf *p, size_t header_size_increment);
u8_t pbuf_remove_header(struct pbuf *p, size_t header_size);
struct pbuf *pbuf_free_header(struct pbuf *q, u16_t size);
void pbuf_ref(struct pbuf *p);
u8_t pbuf_free(struct pbuf *p);
u16_t pbuf_clen(const struct pbuf *p);
void pbuf_cat(struct pbuf *head, struct pbuf *tail);
void pbuf_chain(struct pbuf *head, struct pbuf *tail);
struct pbuf *pbuf_dechain(struct pbuf *p);
err_t pbuf_copy(struct pbuf *p_to, const struct pbuf *p_from);
u16_t pbuf_copy_partial(const struct pbuf *p, void *dataptr, u16_t len, u16_t offset);
void *pbuf_get_contiguous(const struct pbuf *p, void *buffer, size_t bufsize, u16_t len, u16_t offset);
err_t pbuf_take(struct pbuf *buf, const void *dataptr, u16_t len);
err_t pbuf_take_at(struct pbuf *buf, const void *dataptr, u16_t len, u16_t offset);
struct pbuf *pbuf_skip(struct pbuf* in, u16_t in_offset, u16_t* out_offset);
struct pbuf *pbuf_coalesce(struct pbuf *p, pbuf_layer layer);
struct pbuf *pbuf_clone(pbuf_layer l, pbuf_type type, struct pbuf *p);
#if LWIP_CHECKSUM_ON_COPY
err_t pbuf_fill_chksum(struct pbuf *p, u16_t start_offset, const void *dataptr,
                       u16_t len, u16_t *chksum);
#endif /* LWIP_CHECKSUM_ON_COPY */
#if LWIP_TCP && TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
void pbuf_split_64k(struct pbuf *p, struct pbuf **rest);
#endif /* LWIP_TCP && TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */

u8_t pbuf_get_at(const struct pbuf* p, u16_t offset);
int pbuf_try_get_at(const struct pbuf* p, u16_t offset);
void pbuf_put_at(struct pbuf* p, u16_t offset, u8_t data);
u16_t pbuf_memcmp(const struct pbuf* p, u16_t offset, const void* s2, u16_t n);
u16_t pbuf_memfind(const struct pbuf* p, const void* mem, u16_t mem_len, u16_t start_offset);
u16_t pbuf_strstr(const struct pbuf* p, const char* substr);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_PBUF_H */
