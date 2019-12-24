/**
 * @file
 * SNMP pbuf stream wrapper (internal API, do not use in client code).
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
 * Author: Martin Hentschel <info@cl-soft.de>
 *
 */

#ifndef LWIP_HDR_APPS_SNMP_PBUF_STREAM_H
#define LWIP_HDR_APPS_SNMP_PBUF_STREAM_H

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP

#include "lwip/err.h"
#include "lwip/pbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 表示 snmp 协议使用的数据缓冲流数据结构 */
struct snmp_pbuf_stream {
  struct pbuf *pbuf; /* 用来存储当前 snmp 数据的 pbuf 结构指针 */
  u16_t offset;      /* 表示当前 snmp 数据缓冲流中有效数据在 pbuf 缓冲结构中的起始索引值 */
  u16_t length;      /* 表示当前 snmp 数据缓冲流中有效数据字节数 */
};

err_t snmp_pbuf_stream_init(struct snmp_pbuf_stream *pbuf_stream, struct pbuf *p, u16_t offset, u16_t length);
err_t snmp_pbuf_stream_read(struct snmp_pbuf_stream *pbuf_stream, u8_t *data);
err_t snmp_pbuf_stream_write(struct snmp_pbuf_stream *pbuf_stream, u8_t data);
err_t snmp_pbuf_stream_writebuf(struct snmp_pbuf_stream *pbuf_stream, const void *buf, u16_t buf_len);
err_t snmp_pbuf_stream_writeto(struct snmp_pbuf_stream *pbuf_stream, struct snmp_pbuf_stream *target_pbuf_stream, u16_t len);
err_t snmp_pbuf_stream_seek(struct snmp_pbuf_stream *pbuf_stream, s32_t offset);
err_t snmp_pbuf_stream_seek_abs(struct snmp_pbuf_stream *pbuf_stream, u32_t offset);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_SNMP */

#endif /* LWIP_HDR_APPS_SNMP_PBUF_STREAM_H */
