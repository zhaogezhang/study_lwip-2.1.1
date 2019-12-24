/**
 * @file
 * SNMP pbuf stream wrapper implementation (internal API, do not use in client code).
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

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include "snmp_pbuf_stream.h"
#include "lwip/def.h"
#include <string.h>

/*********************************************************************************************************
** 函数名称: snmp_pbuf_stream_init
** 功能描述: 根据函数指定参数初始化指定的 snmp 数据缓冲流结构
** 输	 入: pbuf_stream - 需要初始化的 snmp 数据缓冲流指针
**         : p - 用来存储 snmp 缓冲流数据的 pbuf 结构指针
**         : offset - 当前 snmp 数据缓冲流中起始有效数据字节在 pbuf 结构中的偏移量
**         : length - 当前 snmp 数据缓冲流中有效数据字节数
** 输	 出: ERR_OK - 成功初始化
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_pbuf_stream_init(struct snmp_pbuf_stream *pbuf_stream, struct pbuf *p, u16_t offset, u16_t length)
{
  pbuf_stream->offset = offset;
  pbuf_stream->length = length;
  pbuf_stream->pbuf   = p;

  return ERR_OK;
}

/*********************************************************************************************************
** 函数名称: snmp_pbuf_stream_read
** 功能描述: 从指定的 snmp 数据缓冲流中读取一个字节数据并更新相关变量值
** 输	 入: pbuf_stream - 想要读取的 snmp 数据缓冲流指针
** 输	 出: data - 用来存储读取到的字节数据
**         : ERR_OK - 读取成功
**         : ERR_BUF - 读取失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_pbuf_stream_read(struct snmp_pbuf_stream *pbuf_stream, u8_t *data)
{
  if (pbuf_stream->length == 0) {
    return ERR_BUF;
  }

  if (pbuf_copy_partial(pbuf_stream->pbuf, data, 1, pbuf_stream->offset) == 0) {
    return ERR_BUF;
  }

  pbuf_stream->offset++;
  pbuf_stream->length--;

  return ERR_OK;
}

/*********************************************************************************************************
** 函数名称: snmp_pbuf_stream_write
** 功能描述: 向指定的 snmp 数据缓冲流中写入一个字节数据并更新相关变量值
** 输	 入: pbuf_stream - 想要写入数据的 snmp 数据缓冲流指针
**         : data - 想要写入的字节数据
** 输	 出: ERR_OK - 写入成功
**         : ERR_BUF - 写入失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_pbuf_stream_write(struct snmp_pbuf_stream *pbuf_stream, u8_t data)
{
  return snmp_pbuf_stream_writebuf(pbuf_stream, &data, 1);
}

/*********************************************************************************************************
** 函数名称: snmp_pbuf_stream_writebuf
** 功能描述: 向指定的 snmp 数据缓冲流中写入指定长度的数据并更新相关变量值
** 输	 入: pbuf_stream - 想要写入数据的 snmp 数据缓冲流指针
**         : buf - 想要写入的数据缓冲区地址
**         : buf_len - 想要写入的数据字节数
** 输	 出: ERR_OK - 写入成功
**         : ERR_BUF - 缓冲区错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_pbuf_stream_writebuf(struct snmp_pbuf_stream *pbuf_stream, const void *buf, u16_t buf_len)
{
  if (pbuf_stream->length < buf_len) {
    return ERR_BUF;
  }

  if (pbuf_take_at(pbuf_stream->pbuf, buf, buf_len, pbuf_stream->offset) != ERR_OK) {
    return ERR_BUF;
  }

  pbuf_stream->offset += buf_len;
  pbuf_stream->length -= buf_len;

  return ERR_OK;
}

/*********************************************************************************************************
** 函数名称: snmp_pbuf_stream_writeto
** 功能描述: 从指定的源 snmp 数据缓冲流中拷贝指定长度的数据到指定的目的 snmp 数据缓冲流中
** 输	 入: pbuf_stream - 指定的源 snmp 数据缓冲流指针
**         : target_pbuf_stream - 指定的目的 snmp 数据缓冲流指针
**         : len - 想要拷贝的数据字节数
** 输	 出: ERR_OK - 拷贝成功
**         : ERR_ARG - 参数错误
**         : ERR_BUF - 缓冲区错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_pbuf_stream_writeto(struct snmp_pbuf_stream *pbuf_stream, struct snmp_pbuf_stream *target_pbuf_stream, u16_t len)
{

  if ((pbuf_stream == NULL) || (target_pbuf_stream == NULL)) {
    return ERR_ARG;
  }
  
  if ((len > pbuf_stream->length) || (len > target_pbuf_stream->length)) {
    return ERR_ARG;
  }

  if (len == 0) {
    len = LWIP_MIN(pbuf_stream->length, target_pbuf_stream->length);
  }

  /* 从指定的源 snmp 数据缓冲流中拷贝指定长度的数据到指定的目的 snmp 数据缓冲流中 */
  while (len > 0) {
    u16_t chunk_len;
    err_t err;
    u16_t target_offset;

	/* 从指定的 pbuf/pbuf chain 中的负载空间中，找到包含指定偏移量的 pbuf 以及偏移量的余数部分
     * 所谓的偏移量余数部分指的是通过我们指定的偏移量找到 pbuf 之后，剩余的在 pbuf 内的偏移量 */
    struct pbuf *pbuf = pbuf_skip(pbuf_stream->pbuf, pbuf_stream->offset, &target_offset);

    if ((pbuf == NULL) || (pbuf->len == 0)) {
      return ERR_BUF;
    }

    chunk_len = LWIP_MIN(len, pbuf->len);
    err = snmp_pbuf_stream_writebuf(target_pbuf_stream, &((u8_t *)pbuf->payload)[target_offset], chunk_len);
    if (err != ERR_OK) {
      return err;
    }

    pbuf_stream->offset   += chunk_len;
    pbuf_stream->length   -= chunk_len;
    len -= chunk_len;
  }

  return ERR_OK;
}

/*********************************************************************************************************
** 函数名称: snmp_pbuf_stream_seek
** 功能描述: 调整指定的 snmp 数据缓冲流的有效数据索引值
** 输	 入: pbuf_stream - 想要调整有效数据索引值的 snmp 数据缓冲流指针
**         : offset - 在原有基础上想要调整的偏移量（大于零表示向后平移，小于零表示向前平移）
** 输	 出: ERR_OK - 操作成功
**         : ERR_ARG - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_pbuf_stream_seek(struct snmp_pbuf_stream *pbuf_stream, s32_t offset)
{
  if ((offset < 0) || (offset > pbuf_stream->length)) {
    /* we cannot seek backwards or forward behind stream end */
    return ERR_ARG;
  }

  pbuf_stream->offset += (u16_t)offset;
  pbuf_stream->length -= (u16_t)offset;

  return ERR_OK;
}

/*********************************************************************************************************
** 函数名称: snmp_pbuf_stream_seek_abs
** 功能描述: 调整指定的 snmp 数据缓冲流的有效数据索引值到指定的位置
** 输	 入: pbuf_stream - 想要调整有效数据索引值的 snmp 数据缓冲流指针
**         : offset - 想要调整到的有效数据索引值
** 输	 出: ERR_OK - 操作成功
**         : ERR_ARG - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_pbuf_stream_seek_abs(struct snmp_pbuf_stream *pbuf_stream, u32_t offset)
{
  s32_t rel_offset = offset - pbuf_stream->offset;
  return snmp_pbuf_stream_seek(pbuf_stream, rel_offset);
}

#endif /* LWIP_SNMP */
