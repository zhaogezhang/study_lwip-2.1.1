/**
 * @file
 * Abstract Syntax Notation One (ISO 8824, 8825) encoding
 *
 * @todo not optimised (yet), favor correctness over speed, favor speed over size
 */

/*
 * Copyright (c) 2006 Axon Digital Design B.V., The Netherlands.
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
 */

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include "snmp_asn1.h"

/* 如果指定的 code != ERR_OK 则返回 ERR_BUF */
#define PBUF_OP_EXEC(code) \
  if ((code) != ERR_OK) { \
    return ERR_BUF; \
  }

/**
 * Encodes a TLV into a pbuf stream.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param tlv TLV to encode
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) encode
 */
/*********************************************************************************************************
** 函数名称: snmp_ans1_enc_tlv
** 功能描述: 把指定的 asn1_tlv 结构参数按照 tlv 结构编码到指定的 snmp 数据缓冲流中
** 注     释: 当前函数只把 tlv 结构中的 type 和 length 字段编码到了指定的 snmp 数据缓冲流中，而 value
**         : 字段没有编码到指定的 snmp 数据缓冲流中
** 输	 入: pbuf_stream - 用来存储编码结果的 snmp 数据缓冲流指针
**         : tlv - 表示需要被编码的 tlv 信息数据
** 输	 出: ERR_OK - 操作成功
**         : ERR_ARG - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_ans1_enc_tlv(struct snmp_pbuf_stream *pbuf_stream, struct snmp_asn1_tlv *tlv)
{
  u8_t data;

  /* 表示 tlv 结构中 length 字段需要占用的字节数 */
  u8_t length_bytes_required;

  /* write type */
  /* 如果当前指定的 tlv 数据没有使用扩展格式，则不做任何处理直接返回 */
  if ((tlv->type & SNMP_ASN1_DATATYPE_MASK) == SNMP_ASN1_DATATYPE_EXTENDED) {
    /* extended format is not used by SNMP so we do not accept those values */
    return ERR_ARG;
  }
  
  if (tlv->type_len != 0) {
    /* any other value as auto is not accepted for type (we always use one byte because extended syntax is prohibited) */
    return ERR_ARG;
  }

  /* 向指定的 snmp 数据缓冲流中写入 tlv 中的 type 数据值并更新相关变量值 */
  PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, tlv->type));
  tlv->type_len = 1;

  /* write length */
  /* 根据当前 tlv 需要存储的数据字节数计算 tlv 结构中 length 字段需要占用的字节数 */
  if (tlv->value_len <= 127) {
    length_bytes_required = 1;
  } else if (tlv->value_len <= 255) {
    length_bytes_required = 2;
  } else  {
    length_bytes_required = 3;
  }

  /* check for forced min length */
  if (tlv->length_len > 0) {
    if (tlv->length_len < length_bytes_required) {
      /* unable to code requested length in requested number of bytes */
      return ERR_ARG;
    }

    length_bytes_required = tlv->length_len;
  } else {
    tlv->length_len = length_bytes_required;
  }

  /* 向指定的 snmp 数据缓冲流中写入 tlv 中的 length 数据值并更新相关变量值 */
  if (length_bytes_required > 1) {
    /* multi byte representation required */
    length_bytes_required--;
    data = 0x80 | length_bytes_required; /* extended length definition, 1 length byte follows */

    PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, data));

    while (length_bytes_required > 1) {
      if (length_bytes_required == 2) {
        /* append high byte */
        data = (u8_t)(tlv->value_len >> 8);
      } else {
        /* append leading 0x00 */
        data = 0x00;
      }

      PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, data));
      length_bytes_required--;
    }
  }

  /* append low byte */  
  data = (u8_t)(tlv->value_len & 0xFF);
  PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, data));

  return ERR_OK;
}

/**
 * Encodes raw data (octet string, opaque) into a pbuf chained ASN1 msg.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param raw_len raw data length
 * @param raw points raw data
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) encode
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_enc_raw
** 功能描述: 把指定的缓存数据流编码到到指定的 snmp 数据缓冲流中
** 输	 入: pbuf_stream - 用来存储数据的 snmp 数据缓冲流指针
**         : raw - 表示指定的缓存数据地址
**         : raw_len - 表示指定的缓存数据长度
** 输	 出: ERR_OK - 操作成功
**         : ERR_BUF - 缓冲区错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_asn1_enc_raw(struct snmp_pbuf_stream *pbuf_stream, const u8_t *raw, u16_t raw_len)
{
  PBUF_OP_EXEC(snmp_pbuf_stream_writebuf(pbuf_stream, raw, raw_len));

  return ERR_OK;
}

/**
 * Encodes u32_t (counter, gauge, timeticks) into a pbuf chained ASN1 msg.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param octets_needed encoding length (from snmp_asn1_enc_u32t_cnt())
 * @param value is the host order u32_t value to be encoded
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) encode
 *
 * @see snmp_asn1_enc_u32t_cnt()
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_enc_u32t
** 功能描述: 把指定的 unsigned 32 bit 数据编码到到指定的 snmp 数据缓冲流中
** 输	 入: pbuf_stream - 用来存储数据的 snmp 数据缓冲流指针
**         : octets_needed - 需要编码的字节数
**         : value - 需要编码的数据值
** 输	 出: ERR_OK - 操作成功
**         : ERR_ARG - 参数错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_asn1_enc_u32t(struct snmp_pbuf_stream *pbuf_stream, u16_t octets_needed, u32_t value)
{
  if (octets_needed > 5) {
    return ERR_ARG;
  }
  
  if (octets_needed == 5) {
    /* not enough bits in 'value' add leading 0x00 */
    PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, 0x00));
    octets_needed--;
  }

  while (octets_needed > 1) {
    octets_needed--;
    PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, (u8_t)(value >> (octets_needed << 3))));
  }

  /* (only) one least significant octet */
  PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, (u8_t)value));

  return ERR_OK;
}
/**
 * Encodes s32_t integer into a pbuf chained ASN1 msg.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param octets_needed encoding length (from snmp_asn1_enc_s32t_cnt())
 * @param value is the host order s32_t value to be encoded
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) encode
 *
 * @see snmp_asn1_enc_s32t_cnt()
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_enc_s32t
** 功能描述: 把指定的 signed 32 bit 数据编码到到指定的 snmp 数据缓冲流中
** 输	 入: pbuf_stream - 用来存储数据的 snmp 数据缓冲流指针
**         : octets_needed - 需要编码的字节数
**         : value - 需要编码的数据值
** 输	 出: ERR_OK - 操作成功
**         : ERR_ARG - 参数错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_asn1_enc_s32t(struct snmp_pbuf_stream *pbuf_stream, u16_t octets_needed, s32_t value)
{
  while (octets_needed > 1) {
    octets_needed--;

    PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, (u8_t)(value >> (octets_needed << 3))));
  }

  /* (only) one least significant octet */
  PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, (u8_t)value));

  return ERR_OK;
}

/**
 * Encodes object identifier into a pbuf chained ASN1 msg.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param oid points to object identifier array
 * @param oid_len object identifier array length
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) encode
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_enc_oid
** 功能描述: 把指定的 signed 32 bit 数据编码到到指定的 snmp 数据缓冲流中
** 输	 入: pbuf_stream - 用来存储数据的 snmp 数据缓冲流指针
**         : oid - 需要编码的 oid 数据指针
**         : oid_len - 需要编码的 oid 数据字数
** 输	 出: ERR_OK - 操作成功
**         : ERR_ARG - 参数错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_asn1_enc_oid(struct snmp_pbuf_stream *pbuf_stream, const u32_t *oid, u16_t oid_len)
{
  /* 如果 oid 数据长度达到了 2 个字，则把第一个字和第二个字压缩成一个字存储到指定的 snmp 数据缓冲中 */
  if (oid_len > 1) {
    /* write compressed first two sub id's */
    u32_t compressed_byte = ((oid[0] * 40) + oid[1]);
    PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, (u8_t)compressed_byte));
    oid_len -= 2;
    oid += 2;
  } else {
    /* @bug:  allow empty varbinds for symmetry (we must decode them for getnext), allow partial compression?? */
    /* ident_len <= 1, at least we need zeroDotZero (0.0) (ident_len == 2) */
    return ERR_ARG;
  }

  /* 把其余的 oid 数据按照顺序编码到指定的 snmp 数据缓冲中 */
  while (oid_len > 0) {
    u32_t sub_id;
    u8_t shift, tail;

    oid_len--;
    sub_id = *oid;
    tail = 0;
    shift = 28;
	
    while (shift > 0) {
      u8_t code;

      code = (u8_t)(sub_id >> shift);
      if ((code != 0) || (tail != 0)) {
        tail = 1;
        PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, code | 0x80));
      }
      shift -= 7;
    }
	
    PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, (u8_t)sub_id & 0x7F));

    /* proceed to next sub-identifier */
    oid++;
  }
  
  return ERR_OK;
}

/**
 * Returns octet count for length.
 *
 * @param length parameter length
 * @param octets_needed points to the return value
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_enc_length_cnt
** 功能描述: 计算指定 unsigned 16 bit 变量值转换成 tlv 结构时 length 字段占用几个字节
** 输	 入: length - 指定的 unsigned 16 bit 变量
** 输	 出: octets_needed - 表示需要占用的字节数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_asn1_enc_length_cnt(u16_t length, u8_t *octets_needed)
{
  if (length < 0x80U) {
    *octets_needed = 1;
  } else if (length < 0x100U) {
    *octets_needed = 2;
  } else {
    *octets_needed = 3;
  }
}

/**
 * Returns octet count for an u32_t.
 *
 * @param value value to be encoded
 * @param octets_needed points to the return value
 *
 * @note ASN coded integers are _always_ signed. E.g. +0xFFFF is coded
 * as 0x00,0xFF,0xFF. Note the leading sign octet. A positive value
 * of 0xFFFFFFFF is preceded with 0x00 and the length is 5 octets!!
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_enc_u32t_cnt
** 功能描述: 计算指定 unsigned 32 bit 变量值转换成 tlv 结构时 length 字段占用几个字节
** 输	 入: value - 指定的 unsigned 32 bit 变量
** 输	 出: octets_needed - 表示需要占用的字节数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/ 
void
snmp_asn1_enc_u32t_cnt(u32_t value, u16_t *octets_needed)
{
  if (value < 0x80UL) {
    *octets_needed = 1;
  } else if (value < 0x8000UL) {
    *octets_needed = 2;
  } else if (value < 0x800000UL) {
    *octets_needed = 3;
  } else if (value < 0x80000000UL) {
    *octets_needed = 4;
  } else {
    *octets_needed = 5;
  }
}

/**
 * Returns octet count for an s32_t.
 *
 * @param value value to be encoded
 * @param octets_needed points to the return value
 *
 * @note ASN coded integers are _always_ signed.
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_enc_s32t_cnt
** 功能描述: 计算指定 signed 32 bit 变量值转换成 tlv 结构时 length 字段占用几个字节
** 输	 入: value - 指定的 signed 32 bit 变量
** 输	 出: octets_needed - 表示需要占用的字节数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_asn1_enc_s32t_cnt(s32_t value, u16_t *octets_needed)
{
  if (value < 0) {
    value = ~value;
  }
  if (value < 0x80L) {
    *octets_needed = 1;
  } else if (value < 0x8000L) {
    *octets_needed = 2;
  } else if (value < 0x800000L) {
    *octets_needed = 3;
  } else {
    *octets_needed = 4;
  }
}

/**
 * Returns octet count for an object identifier.
 *
 * @param oid points to object identifier array
 * @param oid_len object identifier array length
 * @param octets_needed points to the return value
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_enc_oid_cnt
** 功能描述: 计算指定长度的 oid 数据转换成 tlv 结构时 length 字段占用的字节数
** 输	 入: oid - 指定的 oid 数据地址
**         : oid_len - 指定的 oid 数据字数
** 输	 出: octets_needed - 表示需要占用的字节数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_asn1_enc_oid_cnt(const u32_t *oid, u16_t oid_len, u16_t *octets_needed)
{
  u32_t sub_id;

  *octets_needed = 0;
  if (oid_len > 1) {
    /* compressed prefix in one octet */
    (*octets_needed)++;
    oid_len -= 2;
    oid += 2;
  }
  
  while (oid_len > 0) {
    oid_len--;
    sub_id = *oid;

    sub_id >>= 7;
    (*octets_needed)++;
    while (sub_id > 0) {
      sub_id >>= 7;
      (*octets_needed)++;
    }
    oid++;
  }
}

/**
 * Decodes a TLV from a pbuf stream.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param tlv returns decoded TLV
 * @return ERR_OK if successful, ERR_VAL if we can't decode
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_dec_tlv
** 功能描述: 从指定的 snmp 数据缓冲流中解析出 tlv 信息数据
** 注     释: 当前函数只把 tlv 结构中的 type 和 length 字段从指定的 snmp 数据缓冲流中解析出来，而 value
**         : 字段没有从指定的 snmp 数据缓冲流中解析出来
** 输	 入: pbuf_stream - 存储着 tlv 结构数据的 snmp 数据缓冲流指针
** 输	 出: tlv - 存储解码后的 tlv 信息数据
**         : ERR_OK - 解析成功
**         : ERR_VAL - 解析失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_asn1_dec_tlv(struct snmp_pbuf_stream *pbuf_stream, struct snmp_asn1_tlv *tlv)
{
  u8_t data;

  /* decode type first */
  /* 从指定的 snmp 数据缓冲流中解析出 tlv 结构中的 type 字段数据 */
  PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
  tlv->type = data;

  if ((tlv->type & SNMP_ASN1_DATATYPE_MASK) == SNMP_ASN1_DATATYPE_EXTENDED) {
    /* extended format is not used by SNMP so we do not accept those values */
    return ERR_VAL;
  }
  tlv->type_len = 1;

  /* now, decode length */  
  /* 从指定的 snmp 数据缓冲流中解析出 tlv 结构中的 length 字段数据 */
  PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));

  if (data < 0x80) { /* short form */  	
    tlv->length_len = 1;
    tlv->value_len  = data;
  } else if (data > 0x80) { /* long form */
  	
    u8_t length_bytes = data - 0x80;
	
    if (length_bytes > pbuf_stream->length) {
      return ERR_VAL;
    }
	
    tlv->length_len = length_bytes + 1; /* this byte + defined number of length bytes following */
    tlv->value_len = 0;

    while (length_bytes > 0) {
		
      /* we only support up to u16.maxvalue-1 (2 bytes) but have to accept leading zero bytes */
      if (tlv->value_len > 0xFF) {
        return ERR_VAL;
      }
	  
      PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
      tlv->value_len <<= 8;
      tlv->value_len |= data;

      /* take care for special value used for indefinite length */
      if (tlv->value_len == 0xFFFF) {
        return ERR_VAL;
      }

      length_bytes--;
    }
  } else { /* data == 0x80 indefinite length form */
    /* (not allowed for SNMP; RFC 1157, 3.2.2) */
    return ERR_VAL;
  }

  return ERR_OK;
}

/**
 * Decodes positive integer (counter, gauge, timeticks) into u32_t.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param len length of the coded integer field
 * @param value return host order integer
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) decode
 *
 * @note ASN coded integers are _always_ signed. E.g. +0xFFFF is coded
 * as 0x00,0xFF,0xFF. Note the leading sign octet. A positive value
 * of 0xFFFFFFFF is preceded with 0x00 and the length is 5 octets!!
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_dec_u32t
** 功能描述: 从指定的 snmp 数据缓冲流中解析出 unsigned 32 bit 类型数据
** 输	 入: pbuf_stream - 存储着 unsigned 32 bit 数据的 snmp 数据缓冲流指针
**         : len - 在 snmp 数据缓冲流中存储的 unsigned 32 bit 数据字节长度
** 输	 出: value - 存储解码后的 unsigned 32 bit 数据
**         : ERR_OK - 解析成功
**         : ERR_VAL - 解析失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_asn1_dec_u32t(struct snmp_pbuf_stream *pbuf_stream, u16_t len, u32_t *value)
{
  u8_t data;

  if ((len > 0) && (len <= 5)) {
    PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));

    /* expecting sign bit to be zero, only unsigned please! */
    if (((len == 5) && (data == 0x00)) || ((len < 5) && ((data & 0x80) == 0))) {
      *value = data;
      len--;

      while (len > 0) {
        PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
        len--;

        *value <<= 8;
        *value |= data;
      }

      return ERR_OK;
    }
  }

  return ERR_VAL;
}

/**
 * Decodes integer into s32_t.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param len length of the coded integer field
 * @param value return host order integer
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) decode
 *
 * @note ASN coded integers are _always_ signed!
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_dec_s32t
** 功能描述: 从指定的 snmp 数据缓冲流中解析出 signed 32 bit 类型数据
** 输	 入: pbuf_stream - 存储着 signed 32 bit 数据的 snmp 数据缓冲流指针
**         : len - 在 snmp 数据缓冲流中存储的 signed 32 bit 数据字节长度
** 输	 出: value - 存储解码后的 signed 32 bit 数据
**         : ERR_OK - 解析成功
**         : ERR_VAL - 解析失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_asn1_dec_s32t(struct snmp_pbuf_stream *pbuf_stream, u16_t len, s32_t *value)
{
  u8_t data;

  if ((len > 0) && (len < 5)) {
    PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));

    if (data & 0x80) {
      /* negative, start from -1 */
      *value = -1;
      *value = (*value << 8) | data;
    } else {
      /* positive, start from 0 */
      *value = data;
    }
    len--;
    /* shift in the remaining value */
    while (len > 0) {
      PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
      *value = (*value << 8) | data;
      len--;
    }
    return ERR_OK;
  }

  return ERR_VAL;
}

/**
 * Decodes object identifier from incoming message into array of u32_t.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param len length of the coded object identifier
 * @param oid return decoded object identifier
 * @param oid_len return decoded object identifier length
 * @param oid_max_len size of oid buffer
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) decode
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_dec_oid
** 功能描述: 从指定的 snmp 数据缓冲流中解析出 oid 数据
** 输	 入: pbuf_stream - 存储着 signed 32 bit 数据的 snmp 数据缓冲流指针
**         : len - 在 snmp 数据缓冲流中存储的 oid 数据字长度
**         : oid_max_len - 表示存储 oid 数据的缓冲区字个数
** 输	 出: oid - 存储解码后的 oid 数据
**         : oid_len - 存储解码后的 oid 字长度
**         : ERR_OK - 解析成功
**         : ERR_VAL - 解析失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_asn1_dec_oid(struct snmp_pbuf_stream *pbuf_stream, u16_t len, u32_t *oid, u8_t *oid_len, u8_t oid_max_len)
{
  u32_t *oid_ptr;
  u8_t data;

  *oid_len = 0;
  oid_ptr = oid;
  if (len > 0) {
    if (oid_max_len < 2) {
      return ERR_MEM;
    }

    PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
    len--;

    /* first compressed octet */
    if (data == 0x2B) {
      /* (most) common case 1.3 (iso.org) */
      *oid_ptr = 1;
      oid_ptr++;
      *oid_ptr = 3;
      oid_ptr++;
    } else if (data < 40) {
      *oid_ptr = 0;
      oid_ptr++;
      *oid_ptr = data;
      oid_ptr++;
    } else if (data < 80) {
      *oid_ptr = 1;
      oid_ptr++;
      *oid_ptr = data - 40;
      oid_ptr++;
    } else {
      *oid_ptr = 2;
      oid_ptr++;
      *oid_ptr = data - 80;
      oid_ptr++;
    }
    *oid_len = 2;
  } else {
    /* accepting zero length identifiers e.g. for getnext operation. uncommon but valid */
    return ERR_OK;
  }

  while ((len > 0) && (*oid_len < oid_max_len)) {
    PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
    len--;

    if ((data & 0x80) == 0x00) {
      /* sub-identifier uses single octet */
      *oid_ptr = data;
    } else {
      /* sub-identifier uses multiple octets */
      u32_t sub_id = (data & ~0x80);
      while ((len > 0) && ((data & 0x80) != 0)) {
        PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
        len--;

        sub_id = (sub_id << 7) + (data & ~0x80);
      }

      if ((data & 0x80) != 0) {
        /* "more bytes following" bit still set at end of len */
        return ERR_VAL;
      }
      *oid_ptr = sub_id;
    }
    oid_ptr++;
    (*oid_len)++;
  }

  if (len > 0) {
    /* OID to long to fit in our buffer */
    return ERR_MEM;
  }

  return ERR_OK;
}

/**
 * Decodes (copies) raw data (ip-addresses, octet strings, opaque encoding)
 * from incoming message into array.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param len length of the coded raw data (zero is valid, e.g. empty string!)
 * @param buf return raw bytes
 * @param buf_len returns length of the raw return value
 * @param buf_max_len buffer size
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) decode
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_dec_raw
** 功能描述: 把指定的缓存数据流编码到到指定的 snmp 数据缓冲流中
** 输	 入: pbuf_stream - 存储着数据的 snmp 数据缓冲流指针
**		   : len - 在 snmp 数据缓冲流存储的数据字节数
**		   : buf_max_len - 表示用来存储解码后的数据缓冲区长度
** 输	 出: buf - 表示用来存储解码后的数据缓冲区地址
**		   : buf_len - 表示解码后的数据字节数
**		   : ERR_OK - 操作成功
**		   : ERR_MEM - 缓冲区不足
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_asn1_dec_raw(struct snmp_pbuf_stream *pbuf_stream, u16_t len, u8_t *buf, u16_t *buf_len, u16_t buf_max_len)
{
  if (len > buf_max_len) {
    /* not enough dst space */
    return ERR_MEM;
  }
  *buf_len = len;

  while (len > 0) {
    PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, buf));
    buf++;
    len--;
  }

  return ERR_OK;
}

#if LWIP_HAVE_INT64
/**
 * Returns octet count for an u64_t.
 *
 * @param value value to be encoded
 * @param octets_needed points to the return value
 *
 * @note ASN coded integers are _always_ signed. E.g. +0xFFFF is coded
 * as 0x00,0xFF,0xFF. Note the leading sign octet. A positive value
 * of 0xFFFFFFFFFFFFFFFF is preceded with 0x00 and the length is 9 octets!!
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_enc_u64t_cnt
** 功能描述: 计算指定 unsigned 64 bit 变量值转换成 tlv 结构时 length 字段占用几个字节
** 输	 入: value - 指定的 unsigned 64 bit 变量
** 输	 出: octets_needed - 表示需要占用的字节数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_asn1_enc_u64t_cnt(u64_t value, u16_t *octets_needed)
{
  /* check if high u32 is 0 */
  if ((value >> 32) == 0) {
    /* only low u32 is important */
    /* 计算指定 unsigned 32 bit 变量值转换成 tlv 结构时 length 字段占用几个字节 */
    snmp_asn1_enc_u32t_cnt((u32_t)value, octets_needed);
  } else {
    /* low u32 does not matter for length determination */
    /* 计算指定 unsigned 32 bit 变量值转换成 tlv 结构时 length 字段占用几个字节 */
    snmp_asn1_enc_u32t_cnt((u32_t)(value >> 32), octets_needed);
    *octets_needed = *octets_needed + 4; /* add the 4 bytes of low u32 */
  }
}

/**
 * Decodes large positive integer (counter64) into 2x u32_t.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param len length of the coded integer field
 * @param value return 64 bit integer
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) decode
 *
 * @note ASN coded integers are _always_ signed. E.g. +0xFFFF is coded
 * as 0x00,0xFF,0xFF. Note the leading sign octet. A positive value
 * of 0xFFFFFFFFFFFFFFFF is preceded with 0x00 and the length is 9 octets!!
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_dec_u64t
** 功能描述: 从指定的 snmp 数据缓冲流中解析出 unsigned 64 bit 类型数据
** 输	 入: pbuf_stream - 存储着 unsigned 64 bit 数据的 snmp 数据缓冲流指针
**         : len - 在 snmp 数据缓冲流中存储的 unsigned 64 bit 数据字节长度
** 输	 出: value - 存储解码后的 unsigned 64 bit 数据
**         : ERR_OK - 解析成功
**         : ERR_VAL - 解析失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_asn1_dec_u64t(struct snmp_pbuf_stream *pbuf_stream, u16_t len, u64_t *value)
{
  u8_t data;

  if ((len > 0) && (len <= 9)) {
    PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));

    /* expecting sign bit to be zero, only unsigned please! */
    if (((len == 9) && (data == 0x00)) || ((len < 9) && ((data & 0x80) == 0))) {
      *value = data;
      len--;

      while (len > 0) {
        PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
        *value <<= 8;
        *value |= data;
        len--;
      }

      return ERR_OK;
    }
  }

  return ERR_VAL;
}

/**
 * Encodes u64_t (counter64) into a pbuf chained ASN1 msg.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param octets_needed encoding length (from snmp_asn1_enc_u32t_cnt())
 * @param value is the value to be encoded
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) encode
 *
 * @see snmp_asn1_enc_u64t_cnt()
 */
/*********************************************************************************************************
** 函数名称: snmp_asn1_enc_u64t
** 功能描述: 把指定的 unsigned 64 bit 数据编码到到指定的 snmp 数据缓冲流中
** 输	 入: pbuf_stream - 用来存储数据的 snmp 数据缓冲流指针
**         : octets_needed - 需要编码的字节数
**         : value - 需要编码的数据值
** 输	 出: ERR_OK - 操作成功
**         : ERR_ARG - 参数错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_asn1_enc_u64t(struct snmp_pbuf_stream *pbuf_stream, u16_t octets_needed, u64_t value)
{
  if (octets_needed > 9) {
    return ERR_ARG;
  }
  if (octets_needed == 9) {
    /* not enough bits in 'value' add leading 0x00 */
    PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, 0x00));
    octets_needed--;
  }

  while (octets_needed > 1) {
    octets_needed--;
    PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, (u8_t)(value >> (octets_needed << 3))));
  }

  /* always write at least one octet (also in case of value == 0) */
  PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, (u8_t)(value)));

  return ERR_OK;
}
#endif

#endif /* LWIP_SNMP */
