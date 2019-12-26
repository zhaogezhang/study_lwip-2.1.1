/**
 * @file
 * SNMP Agent message handling structures (internal API, do not use in client code).
 */

/*
 * Copyright (c) 2006 Axon Digital Design B.V., The Netherlands.
 * Copyright (c) 2016 Elias Oenal.
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
 * Author: Christiaan Simons <christiaan.simons@axon.tv>
 *         Martin Hentschel <info@cl-soft.de>
 *         Elias Oenal <lwip@eliasoenal.com>
 */

#ifndef LWIP_HDR_APPS_SNMP_MSG_H
#define LWIP_HDR_APPS_SNMP_MSG_H

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP

#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_core.h"
#include "snmp_pbuf_stream.h"
#include "lwip/ip_addr.h"
#include "lwip/err.h"

#if LWIP_SNMP_V3
#include "snmpv3_priv.h"
#endif


#ifdef __cplusplus
extern "C" {
#endif

/* version defines used in PDU */
#define SNMP_VERSION_1  0
#define SNMP_VERSION_2c 1
#define SNMP_VERSION_3  3

/* 表示当前系统内的 snmp variable bind 数据结构，表示的是 snmp 数据包中指定的
   snmp 对象列表信息，即当前 snmp 数据包都需要操作哪些对象 */
struct snmp_varbind_enumerator {
  struct snmp_pbuf_stream pbuf_stream;
  u16_t varbind_count;
};

/* 当前系统对 snmp variable bind 操作错误码定义 */
typedef enum {
  SNMP_VB_ENUMERATOR_ERR_OK            = 0,
  SNMP_VB_ENUMERATOR_ERR_EOVB          = 1,  /* 表示读取到 vb_enumerator 缓存数据流的末尾 */
  SNMP_VB_ENUMERATOR_ERR_ASN1ERROR     = 2,
  SNMP_VB_ENUMERATOR_ERR_INVALIDLENGTH = 3
} snmp_vb_enumerator_err_t;

void snmp_vb_enumerator_init(struct snmp_varbind_enumerator *enumerator, struct pbuf *p, u16_t offset, u16_t length);
snmp_vb_enumerator_err_t snmp_vb_enumerator_get_next(struct snmp_varbind_enumerator *enumerator, struct snmp_varbind *varbind);

/* 当我们接收到一个 snmp 请求数据包的时候会对其解析，然后把解析到的数据存储到这个数据结构中 */
struct snmp_request {
  /* Communication handle */
  void *handle;
  /* source IP address */
  const ip_addr_t *source_ip;
  /* source UDP port */
  u16_t source_port;
  
  /* incoming snmp version */
  u8_t version;
  
  /* community name (zero terminated) */
  u8_t community[SNMP_MAX_COMMUNITY_STR_LEN + 1];
  /* community string length (exclusive zero term) */
  u16_t community_strlen;
  
  /* request type */
  u8_t request_type;
  /* request ID */
  s32_t request_id;

  /* error status */  
  s32_t error_status;
  /* error index */
  s32_t error_index;
  
  /* non-repeaters (getBulkRequest (SNMPv2c)) */
  /* Nonrepeaters tells the get-bulk command that the first N objects 
     can be retrieved with a simple get-next operation. */
  s32_t non_repeaters;
  
  /* max-repetitions (getBulkRequest (SNMPv2c)) */
  /* Max-repetitions tells the get-bulk command to attempt up to Mget-next operations 
     to retrieve the remaining objects. */
  s32_t max_repetitions;

  /* Usually response-pdu (2). When snmpv3 errors are detected report-pdu(8) */
  u8_t request_out_type;

#if LWIP_SNMP_V3
  s32_t msg_id;
  s32_t msg_max_size;
  u8_t  msg_flags;
  s32_t msg_security_model;
  u8_t  msg_authoritative_engine_id[SNMP_V3_MAX_ENGINE_ID_LENGTH];
  u8_t  msg_authoritative_engine_id_len;
  s32_t msg_authoritative_engine_boots;
  s32_t msg_authoritative_engine_time;
  u8_t  msg_user_name[SNMP_V3_MAX_USER_LENGTH];
  u8_t  msg_user_name_len;
  u8_t  msg_authentication_parameters[SNMP_V3_MAX_AUTH_PARAM_LENGTH];
  u8_t  msg_authentication_parameters_len;
  u8_t  msg_privacy_parameters[SNMP_V3_MAX_PRIV_PARAM_LENGTH];
  u8_t  msg_privacy_parameters_len;
  u8_t  context_engine_id[SNMP_V3_MAX_ENGINE_ID_LENGTH];
  u8_t  context_engine_id_len;
  u8_t  context_name[SNMP_V3_MAX_ENGINE_ID_LENGTH];
  u8_t  context_name_len;
#endif

  /* 指向当前接收到的 snmp 请求数据包的 pbuf 结构指针 */
  struct pbuf *inbound_pbuf;

  /* 表示的是 snmp 数据包中指定的 snmp 对象列表信息，即当前 snmp 数据包都需要操作哪些对象 */
  struct snmp_varbind_enumerator inbound_varbind_enumerator;

  /* 表示当前接收到的 snmp 请求数据包中存储的 varbind 数据在 inbound_pbuf 缓冲区中的偏移量 */
  u16_t inbound_varbind_offset;
  
  /* 表示当前接收到的 snmp 请求数据包的有效数据在 inbound_pbuf 缓冲区中的长度 */
  u16_t inbound_varbind_len;
  
  /* 表示当前接收到的 snmp 请求数据包在 inbound_pbuf 缓冲区后添加的 pad 数据的长度 */
  u16_t inbound_padding_len;

  /* 指向当前需要发送的 snmp 数据包的 pbuf 结构指针 */
  struct pbuf *outbound_pbuf;

  /* 表示当前 snmp 请求数据包的发送数据缓冲流数据结构 */
  struct snmp_pbuf_stream outbound_pbuf_stream;

  /* 表示需要发送的 snmp 数据包的 PDU 数据在 outbound_pbuf 缓冲区中的偏移量
     注释：因为在 snmp_prepare_outbound_frame 数据封装函数中对某些数据封装时只写入 tlv 结构
           中的 tl 字段，但是还没有写入 v 字段值，所以需要记录下 v 字段在 snmp 数据包缓存流
           中的偏移量，这样后面需要写入 v 字段值的时候就可以直接写入到目的地址处了 */
  u16_t outbound_pdu_offset;
  
  /* 表示需要发送的 snmp 数据包的 error status 数据在 outbound_pbuf 缓冲区中的偏移量
     注释：因为在 snmp_prepare_outbound_frame 数据封装函数中对某些数据封装时只写入 tlv 结构
           中的 tl 字段，但是还没有写入 v 字段值，所以需要记录下 v 字段在 snmp 数据包缓存流
           中的偏移量，这样后面需要写入 v 字段值的时候就可以直接写入到目的地址处了 */
  u16_t outbound_error_status_offset;

  /* 表示需要发送的 snmp 数据包的 error index 数据在 outbound_pbuf 缓冲区中的偏移量
     注释：因为在 snmp_prepare_outbound_frame 数据封装函数中对某些数据封装时只写入 tlv 结构
           中的 tl 字段，但是还没有写入 v 字段值，所以需要记录下 v 字段在 snmp 数据包缓存流
           中的偏移量，这样后面需要写入 v 字段值的时候就可以直接写入到目的地址处了 */
  u16_t outbound_error_index_offset;
  
  /* 表示需要发送的 snmp 数据包的 varbind 数据在 outbound_pbuf 缓冲区中的偏移量
     注释：因为在 snmp_prepare_outbound_frame 数据封装函数中对某些数据封装时只写入 tlv 结构
           中的 tl 字段，但是还没有写入 v 字段值，所以需要记录下 v 字段在 snmp 数据包缓存流
           中的偏移量，这样后面需要写入 v 字段值的时候就可以直接写入到目的地址处了 */
  u16_t outbound_varbind_offset;
  
#if LWIP_SNMP_V3
  u16_t outbound_msg_global_data_offset;
  u16_t outbound_msg_global_data_end;
  u16_t outbound_msg_security_parameters_str_offset;
  u16_t outbound_msg_security_parameters_seq_offset;
  u16_t outbound_msg_security_parameters_end;
  u16_t outbound_msg_authentication_parameters_offset;
  u16_t outbound_scoped_pdu_seq_offset;
  u16_t outbound_scoped_pdu_string_offset;
#endif

  u8_t value_buffer[SNMP_MAX_VALUE_SIZE];
};

/** A helper struct keeping length information about varbinds */
struct snmp_varbind_len {
  u8_t  vb_len_len;      /* 表示当前 varbind 结构的 vb_value_len 字段需要占用的字节数 */
  u16_t vb_value_len;    /* 表示当前 varbind 结构需要占用的字节数 */
  u8_t  oid_len_len;     /* 表示指定 varbind 结构的 oid.len 字段占用的字节数 */
  u16_t oid_value_len;   /* 表示指定 varbind 结构的 oid.id 字段占用的字节数 */
  u8_t  value_len_len;   /* 表示指定 varbind 结构的 value_len 字段占用的字节数 */
  u16_t value_value_len; /* 表示指定 varbind 结构的 value 字段占用的字节数 */
};

/** Agent community string */
extern const char *snmp_community;
/** Agent community string for write access */
extern const char *snmp_community_write;
/** handle for sending traps */
extern void *snmp_traps_handle;

void snmp_receive(void *handle, struct pbuf *p, const ip_addr_t *source_ip, u16_t port);
err_t snmp_sendto(void *handle, struct pbuf *p, const ip_addr_t *dst, u16_t port);
u8_t snmp_get_local_ip_for_dst(void *handle, const ip_addr_t *dst, ip_addr_t *result);
err_t snmp_varbind_length(struct snmp_varbind *varbind, struct snmp_varbind_len *len);
err_t snmp_append_outbound_varbind(struct snmp_pbuf_stream *pbuf_stream, struct snmp_varbind *varbind);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_SNMP */

#endif /* LWIP_HDR_APPS_SNMP_MSG_H */
