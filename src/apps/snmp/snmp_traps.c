/**
 * @file
 * SNMPv1 traps implementation.
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
 * Author: Martin Hentschel
 *         Christiaan Simons <christiaan.simons@axon.tv>
 *
 */

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include <string.h>

#include "lwip/snmp.h"
#include "lwip/sys.h"
#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_core.h"
#include "lwip/prot/iana.h"
#include "snmp_msg.h"
#include "snmp_asn1.h"
#include "snmp_core_priv.h"

/* 保存了系统需要发送的 trap 数据包数据 */
struct snmp_msg_trap {
  /* source enterprise ID (sysObjectID) */
  const struct snmp_obj_id *enterprise;
  /* source IP address, raw network order format */
  ip_addr_t sip;
  /* generic trap code */
  u32_t gen_trap;
  /* specific trap code */
  u32_t spc_trap;
  /* timestamp */
  u32_t ts;
  /* snmp_version */
  u32_t snmp_version;

  /* output trap lengths used in ASN encoding */
  /* encoding pdu length */
  u16_t pdulen;
  /* encoding community length */
  u16_t comlen;
  /* encoding sequence length */
  u16_t seqlen;
  /* encoding varbinds sequence length */
  u16_t vbseqlen;
};

static u16_t snmp_trap_varbind_sum(struct snmp_msg_trap *trap, struct snmp_varbind *varbinds);
static u16_t snmp_trap_header_sum(struct snmp_msg_trap *trap, u16_t vb_len);
static err_t snmp_trap_header_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream);
static err_t snmp_trap_varbind_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream, struct snmp_varbind *varbinds);

/* 如果指定的状态码 code != ERR_OK 则打印 log 信息并返回 ERR_ARG 值 */
#define BUILD_EXEC(code) \
  if ((code) != ERR_OK) { \
    LWIP_DEBUGF(SNMP_DEBUG, ("SNMP error during creation of outbound trap frame!")); \
    return ERR_ARG; \
  }

/** Agent community string for sending traps */
extern const char *snmp_community_trap;

/* 记录当前 snmp 协议模块使用的 udp 协议控制块指针 */
void *snmp_traps_handle;

struct snmp_trap_dst {
  /* destination IP address in network order */
  ip_addr_t dip;
  /* set to 0 when disabled, >0 when enabled */
  u8_t enable;
};
static struct snmp_trap_dst trap_dst[SNMP_TRAP_DESTINATIONS];

static u8_t snmp_auth_traps_enabled = 0;

/**
 * @ingroup snmp_traps
 * Sets enable switch for this trap destination.
 * @param dst_idx index in 0 .. SNMP_TRAP_DESTINATIONS-1
 * @param enable switch if 0 destination is disabled >0 enabled.
 */
/*********************************************************************************************************
** 函数名称: snmp_trap_dst_enable
** 功能描述: 设置 trap_dst 数组指定索引位置处的地址使能情况
** 输	 入: dst_idx - 指定的 trap_dst 数组的索引值
**         : enable - 设置使能情况，0 表示失能，>0 表示使能
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_trap_dst_enable(u8_t dst_idx, u8_t enable)
{
  LWIP_ASSERT_CORE_LOCKED();
  if (dst_idx < SNMP_TRAP_DESTINATIONS) {
    trap_dst[dst_idx].enable = enable;
  }
}

/**
 * @ingroup snmp_traps
 * Sets IPv4 address for this trap destination.
 * @param dst_idx index in 0 .. SNMP_TRAP_DESTINATIONS-1
 * @param dst IPv4 address in host order.
 */
/*********************************************************************************************************
** 函数名称: snmp_trap_dst_ip_set
** 功能描述: 设置 trap_dst 数组指定索引位置处的目的 IP 地址信息
** 输	 入: dst_idx - 指定的 trap_dst 数组的索引值
**         : dst - 指定的目的 IP 地址信息
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_trap_dst_ip_set(u8_t dst_idx, const ip_addr_t *dst)
{
  LWIP_ASSERT_CORE_LOCKED();
  if (dst_idx < SNMP_TRAP_DESTINATIONS) {
    ip_addr_set(&trap_dst[dst_idx].dip, dst);
  }
}

/**
 * @ingroup snmp_traps
 * Enable/disable authentication traps
 */
/*********************************************************************************************************
** 函数名称: snmp_set_auth_traps_enabled
** 功能描述: 设置 trap_dst 数组指定索引位置处的目的 IP 地址信息
** 输	 入: dst_idx - 指定的 trap_dst 数组的索引值
**         : dst - 指定的目的 IP 地址信息
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_set_auth_traps_enabled(u8_t enable)
{
  snmp_auth_traps_enabled = enable;
}

/**
 * @ingroup snmp_traps
 * Get authentication traps enabled state
 */
/*********************************************************************************************************
** 函数名称: snmp_get_auth_traps_enabled
** 功能描述: 获取当前系统有关 auth traps 的使能情况
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_get_auth_traps_enabled(void)
{
  return snmp_auth_traps_enabled;
}


/**
 * @ingroup snmp_traps
 * Sends a generic or enterprise specific trap message.
 *
 * @param eoid points to enterprise object identifier
 * @param generic_trap is the trap code
 * @param specific_trap used for enterprise traps when generic_trap == 6
 * @param varbinds linked list of varbinds to be sent
 * @return ERR_OK when success, ERR_MEM if we're out of memory
 *
 * @note the use of the enterprise identifier field
 * is per RFC1215.
 * Use .iso.org.dod.internet.mgmt.mib-2.snmp for generic traps
 * and .iso.org.dod.internet.private.enterprises.yourenterprise
 * (sysObjectID) for specific traps.
 */
/*********************************************************************************************************
** 函数名称: snmp_send_trap
** 功能描述: 根据函数指定的参数创建一个 trap 数据包并发送到 trap_dst 数组中的每一个有效地址处
** 输	 入: eoid - 指定的企业 oid 数据
**         : generic_trap - 指定的 trap 码
**         : specific_trap - 当 generic_trap == 6 时用于企业级 trap
**         : varbinds - 需要发送的 variable bind 列表
** 输	 出: ERR_OK - 发送成功
**         : ERR_MEM - 内存错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_send_trap(const struct snmp_obj_id *eoid, s32_t generic_trap, s32_t specific_trap, struct snmp_varbind *varbinds)
{
  struct snmp_msg_trap trap_msg;
  struct snmp_trap_dst *td;
  struct pbuf *p;
  u16_t i, tot_len;
  err_t err = ERR_OK;

  LWIP_ASSERT_CORE_LOCKED();

  trap_msg.snmp_version = 0;

  /* 遍历当前 trap_dst 数组中的每一个数组成员结构 */
  for (i = 0, td = &trap_dst[0]; i < SNMP_TRAP_DESTINATIONS; i++, td++) {

    /* 判断当前遍历的地址信息是否使能并有效 */
    if ((td->enable != 0) && !ip_addr_isany(&td->dip)) {
		
      /* lookup current source address for this dst */
	  /* 为指定的目的地 IP 地址在当前协议栈中查找一个用于发送这个数据包的网路接口的 IP 地址 */
      if (snmp_get_local_ip_for_dst(snmp_traps_handle, &td->dip, &trap_msg.sip)) {

	    /* 如果当前函数没有指定企业 oid 数据则使用当前系统默认的企业 oid */
        if (eoid == NULL) {
          trap_msg.enterprise = snmp_get_device_enterprise_oid();
        } else {
          trap_msg.enterprise = eoid;
        }

        /* 设置当前 trap 数据包的 trap 码信息 */
        trap_msg.gen_trap = generic_trap;
        if (generic_trap == SNMP_GENTRAP_ENTERPRISE_SPECIFIC) {
          trap_msg.spc_trap = specific_trap;
        } else {
          trap_msg.spc_trap = 0;
        }

        /* 设置当前 trap 数据包的时间戳信息 */
        MIB2_COPY_SYSUPTIME_TO(&trap_msg.ts);

        /* pass 0, calculate length fields */
		/* 计算指定的 variable bind 数据列表转换成 tlv 结构时 length 字段占用几个字节 */
        tot_len = snmp_trap_varbind_sum(&trap_msg, varbinds);

		/* 计算指定的 trap 数据结构转换成 tlv 结构时 length 字段占用几个字节 */
        tot_len = snmp_trap_header_sum(&trap_msg, tot_len);

        /* allocate pbuf(s) */
		/* 为当前待发送的数据包申请一个 pbuf 数据结构 */
        p = pbuf_alloc(PBUF_TRANSPORT, tot_len, PBUF_RAM);
        if (p != NULL) {
			
          struct snmp_pbuf_stream pbuf_stream;

		  /* 根据函数指定参数初始化指定的 snmp 数据缓冲流结构 */
          snmp_pbuf_stream_init(&pbuf_stream, p, 0, tot_len);

          /* pass 1, encode packet into the pbuf(s) */
		  /* 把指定的 trap header 的 asn1_tlv 结构参数按照 tlv 结构编码到指定的 snmp 数据缓冲流中 */
          snmp_trap_header_enc(&trap_msg, &pbuf_stream);

		  /* 把指定的 trap varbind 的 asn1_tlv 结构参数按照 tlv 结构编码到指定的 snmp 数据缓冲流中 */
          snmp_trap_varbind_enc(&trap_msg, &pbuf_stream, varbinds);

          snmp_stats.outtraps++;
          snmp_stats.outpkts++;

          /** send to the TRAP destination */
		  /* 把打包好的 trap 数据包发送到指定的 trap_dst 目的地址处 */
          snmp_sendto(snmp_traps_handle, p, &td->dip, LWIP_IANA_PORT_SNMP_TRAP);

		  /* 数据包发送完成之后释放之前申请的 pbuf 缓冲区结构 */
          pbuf_free(p);
		  
        } else {
          err = ERR_MEM;
        }
      } else {
        /* routing error */
        err = ERR_RTE;
      }
    }
  }
  return err;
}

/**
 * @ingroup snmp_traps
 * Send generic SNMP trap
 */
/*********************************************************************************************************
** 函数名称: snmp_send_trap_generic
** 功能描述: 根据函数指定的参数创建一个 generic trap 数据包并发送到 trap_dst 数组中的每一个有效地址处
** 输	 入: generic_trap - 指定的 trap 码
** 输	 出: ERR_OK - 发送成功
**         : ERR_MEM - 内存错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_send_trap_generic(s32_t generic_trap)
{
  static const struct snmp_obj_id oid = { 7, { 1, 3, 6, 1, 2, 1, 11 } };
  return snmp_send_trap(&oid, generic_trap, 0, NULL);
}

/**
 * @ingroup snmp_traps
 * Send specific SNMP trap with variable bindings
 */
/*********************************************************************************************************
** 函数名称: snmp_send_trap_specific
** 功能描述: 根据函数指定的参数创建一个 specific trap 数据包并发送到 trap_dst 数组中的每一个有效地址处
** 输	 入: specific_trap - 指定的 specific trap 码
**         : varbinds - 需要发送的 variable bind 列表
** 输	 出: ERR_OK - 发送成功
**         : ERR_MEM - 内存错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_send_trap_specific(s32_t specific_trap, struct snmp_varbind *varbinds)
{
  return snmp_send_trap(NULL, SNMP_GENTRAP_ENTERPRISE_SPECIFIC, specific_trap, varbinds);
}

/**
 * @ingroup snmp_traps
 * Send coldstart trap
 */
/*********************************************************************************************************
** 函数名称: snmp_coldstart_trap
** 功能描述: 创建一个 cold start trap 数据包并发送到 trap_dst 数组中的每一个有效地址处
** 输	 入: 
** 输	 出: ERR_OK - 发送成功
**         : ERR_MEM - 内存错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_coldstart_trap(void)
{
  snmp_send_trap_generic(SNMP_GENTRAP_COLDSTART);
}

/**
 * @ingroup snmp_traps
 * Send authentication failure trap (used internally by agent)
 */
/*********************************************************************************************************
** 函数名称: snmp_authfail_trap
** 功能描述: 创建一个 authentication failure trap 数据包并发送到 trap_dst 数组中的每一个有效地址处
** 输	 入: 
** 输	 出: ERR_OK - 发送成功
**         : ERR_MEM - 内存错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_authfail_trap(void)
{
  if (snmp_auth_traps_enabled != 0) {
    snmp_send_trap_generic(SNMP_GENTRAP_AUTH_FAILURE);
  }
}

/*********************************************************************************************************
** 函数名称: snmp_trap_varbind_sum
** 功能描述: 计算指定的 variable bind 数据列表转换成 tlv 结构时 length 字段占用几个字节
** 输	 入: trap - 指定的 trap 数据包指针
**         : varbinds - 指定的 variable bind 数据列表指针
** 输	 出: tot_len - 表示指定的 trap 数据包转换成 tlv 结构时 length 字段占用几个字节
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static u16_t
snmp_trap_varbind_sum(struct snmp_msg_trap *trap, struct snmp_varbind *varbinds)
{
  struct snmp_varbind *varbind;
  u16_t tot_len;
  u8_t tot_len_len;

  tot_len = 0;
  varbind = varbinds;

  /* 分别遍历 varbinds 列表中的每一个 variable bind 并统计把他们转换成 tlv 结构时 length 字段占用几个字节 */
  while (varbind != NULL) {
    struct snmp_varbind_len len;

    /* 计算指定的 snmp variable bind 结构相关的长度信息 */
    if (snmp_varbind_length(varbind, &len) == ERR_OK) {
      tot_len += 1 + len.vb_len_len + len.vb_value_len;
    }

    varbind = varbind->next;
  }

  trap->vbseqlen = tot_len;

  /* 计算指定 unsigned 16 bit 变量值转换成 tlv 结构时 length 字段占用几个字节 */
  snmp_asn1_enc_length_cnt(trap->vbseqlen, &tot_len_len);
  tot_len += 1 + tot_len_len;

  return tot_len;
}

/**
 * Sums trap header field lengths from tail to head and
 * returns trap_header_lengths for second encoding pass.
 *
 * @param trap Trap message
 * @param vb_len varbind-list length
 * @return the required length for encoding the trap header
 */
/*********************************************************************************************************
** 函数名称: snmp_trap_header_sum
** 功能描述: 计算指定的 trap 数据结构转换成 tlv 结构时 length 字段占用几个字节
** 输	 入: trap - 指定的 trap 数据包指针
**         : vb_len - 指定的 variable bind 数据转换成 tlv 结构时 length 字段占用字节数
** 输	 出: tot_len - 表示指定的 trap header 数据结构转换成 tlv 结构时 length 字段占用几个字节
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static u16_t
snmp_trap_header_sum(struct snmp_msg_trap *trap, u16_t vb_len)
{
  u16_t tot_len;
  u16_t len;
  u8_t lenlen;

  tot_len = vb_len;

  snmp_asn1_enc_u32t_cnt(trap->ts, &len);
  snmp_asn1_enc_length_cnt(len, &lenlen);
  tot_len += 1 + len + lenlen;

  snmp_asn1_enc_s32t_cnt(trap->spc_trap, &len);
  snmp_asn1_enc_length_cnt(len, &lenlen);
  tot_len += 1 + len + lenlen;

  snmp_asn1_enc_s32t_cnt(trap->gen_trap, &len);
  snmp_asn1_enc_length_cnt(len, &lenlen);
  tot_len += 1 + len + lenlen;

  if (IP_IS_V6_VAL(trap->sip)) {
#if LWIP_IPV6
    len = sizeof(ip_2_ip6(&trap->sip)->addr);
#endif
  } else {
#if LWIP_IPV4
    len = sizeof(ip_2_ip4(&trap->sip)->addr);
#endif
  }
  snmp_asn1_enc_length_cnt(len, &lenlen);
  tot_len += 1 + len + lenlen;

  snmp_asn1_enc_oid_cnt(trap->enterprise->id, trap->enterprise->len, &len);
  snmp_asn1_enc_length_cnt(len, &lenlen);
  tot_len += 1 + len + lenlen;

  trap->pdulen = tot_len;
  snmp_asn1_enc_length_cnt(trap->pdulen, &lenlen);
  tot_len += 1 + lenlen;

  trap->comlen = (u16_t)LWIP_MIN(strlen(snmp_community_trap), 0xFFFF);
  snmp_asn1_enc_length_cnt(trap->comlen, &lenlen);
  tot_len += 1 + lenlen + trap->comlen;

  snmp_asn1_enc_s32t_cnt(trap->snmp_version, &len);
  snmp_asn1_enc_length_cnt(len, &lenlen);
  tot_len += 1 + len + lenlen;

  trap->seqlen = tot_len;
  snmp_asn1_enc_length_cnt(trap->seqlen, &lenlen);
  tot_len += 1 + lenlen;

  return tot_len;
}

/*********************************************************************************************************
** 函数名称: snmp_trap_varbind_enc
** 功能描述: 把指定的 trap varbind 的 asn1_tlv 结构参数按照 tlv 结构编码到指定的 snmp 数据缓冲流中
** 输	 入: trap - 指定的 trap 数据包指针
**         : varbinds - 指定的 varbind 的 asn1_tlv 结构参数
** 输	 出: pbuf_stream - 用来存储编码后数据的 snmp 数据缓冲流指针
**         : ERR_OK - 编码成功
**         : ERR_ARG - 编码错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
snmp_trap_varbind_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream, struct snmp_varbind *varbinds)
{
  struct snmp_asn1_tlv tlv;
  struct snmp_varbind *varbind;

  varbind = varbinds;
  
  /* 根据指定参数初始化指定的 tlv 数据结构 */
  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 0, trap->vbseqlen);

  BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );

  while (varbind != NULL) {

    /* 把指定的 varbind 结构中的有用数据（oid、type、value_len、value）按照 ans1 格式编码
       到指定的 snmp 数据缓冲流数据结构中 */
    BUILD_EXEC( snmp_append_outbound_varbind(pbuf_stream, varbind) );

    varbind = varbind->next;
  }

  return ERR_OK;
}

/**
 * Encodes trap header from head to tail.
 */
/*********************************************************************************************************
** 函数名称: snmp_trap_header_enc
** 功能描述: 把指定的 trap header 的 asn1_tlv 结构参数按照 tlv 结构编码到指定的 snmp 数据缓冲流中
** 输	 入: trap - 指定的 trap 数据包指针
** 输	 出: pbuf_stream - 用来存储编码后数据的 snmp 数据缓冲流指针
**         : ERR_OK - 编码成功
**         : ERR_ARG - 编码错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static err_t
snmp_trap_header_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream)
{
  struct snmp_asn1_tlv tlv;

  /* 'Message' sequence */
  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 0, trap->seqlen);
  BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );

  /* version */
  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
  snmp_asn1_enc_s32t_cnt(trap->snmp_version, &tlv.value_len);
  BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
  BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->snmp_version) );

  /* community */
  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, trap->comlen);
  BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
  BUILD_EXEC( snmp_asn1_enc_raw(pbuf_stream,  (const u8_t *)snmp_community_trap, trap->comlen) );

  /* 'PDU' sequence */
  SNMP_ASN1_SET_TLV_PARAMS(tlv, (SNMP_ASN1_CLASS_CONTEXT | SNMP_ASN1_CONTENTTYPE_CONSTRUCTED | SNMP_ASN1_CONTEXT_PDU_TRAP), 0, trap->pdulen);
  BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );

  /* object ID */
  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OBJECT_ID, 0, 0);
  snmp_asn1_enc_oid_cnt(trap->enterprise->id, trap->enterprise->len, &tlv.value_len);
  BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
  BUILD_EXEC( snmp_asn1_enc_oid(pbuf_stream, trap->enterprise->id, trap->enterprise->len) );

  /* IP addr */
  if (IP_IS_V6_VAL(trap->sip)) {
#if LWIP_IPV6
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_IPADDR, 0, sizeof(ip_2_ip6(&trap->sip)->addr));
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    BUILD_EXEC( snmp_asn1_enc_raw(pbuf_stream, (const u8_t *)&ip_2_ip6(&trap->sip)->addr, sizeof(ip_2_ip6(&trap->sip)->addr)) );
#endif
  } else {
#if LWIP_IPV4
    SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_IPADDR, 0, sizeof(ip_2_ip4(&trap->sip)->addr));
    BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
    BUILD_EXEC( snmp_asn1_enc_raw(pbuf_stream, (const u8_t *)&ip_2_ip4(&trap->sip)->addr, sizeof(ip_2_ip4(&trap->sip)->addr)) );
#endif
  }

  /* trap length */
  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
  snmp_asn1_enc_s32t_cnt(trap->gen_trap, &tlv.value_len);
  BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
  BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->gen_trap) );

  /* specific trap */
  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
  snmp_asn1_enc_s32t_cnt(trap->spc_trap, &tlv.value_len);
  BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
  BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->spc_trap) );

  /* timestamp */
  SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_TIMETICKS, 0, 0);
  snmp_asn1_enc_s32t_cnt(trap->ts, &tlv.value_len);
  BUILD_EXEC( snmp_ans1_enc_tlv(pbuf_stream, &tlv) );
  BUILD_EXEC( snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->ts) );

  return ERR_OK;
}

#endif /* LWIP_SNMP */
