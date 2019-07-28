/**
 * @file
 * IGMP protocol definitions
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
#ifndef LWIP_HDR_PROT_IGMP_H
#define LWIP_HDR_PROT_IGMP_H

#include "lwip/arch.h"
#include "lwip/prot/ip4.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * IGMP constants
 */
/* 表示 igmp 数据包的 IP 协议头中的 ttl（Time To Live）字段值 */
#define IGMP_TTL                       1

/* 表示 igmp 数据包的最小长度 */
#define IGMP_MINLEN                    8

/* 表示 igmp 数据包的 IP 协议头中的路由告警选项头内容（Type + Leng）*/
#define ROUTER_ALERT                   0x9404U

/* 表示 igmp 数据包的 IP 协议头中的路由告警选项数据长度字节数 */
#define ROUTER_ALERTLEN                4

/*
 * IGMP message types, including version number.
 */
/* 定义当前协议栈支持的 igmp 数据包类型 */
#define IGMP_MEMB_QUERY                0x11 /* Membership query         */
#define IGMP_V1_MEMB_REPORT            0x12 /* Ver. 1 membership report */
#define IGMP_V2_MEMB_REPORT            0x16 /* Ver. 2 membership report */
#define IGMP_LEAVE_GROUP               0x17 /* Leave-group message      */

/* Group  membership states */
/* 表示当前多播组中没有任何主机设备成员 */
#define IGMP_GROUP_NON_MEMBER          0

/* 表示当前多播组正处于延迟发送组成员报告信息状态，在这个状态的组，会启动一个
 * 软件定时器，在定时器超时函数中，发送一个多播组成员报告信息 */
#define IGMP_GROUP_DELAYING_MEMBER     1

/* 表示当前多播组正处于空闲状态，在这个状态的多播组表示刚刚发送完  多播组成员报告信息 */
#define IGMP_GROUP_IDLE_MEMBER         2

/**
 * IGMP packet format.
 */
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/bpstruct.h"
#endif

/* 定义 igmp 数据包协议头结构 */
PACK_STRUCT_BEGIN
struct igmp_msg {
  PACK_STRUCT_FLD_8(u8_t         igmp_msgtype);
  PACK_STRUCT_FLD_8(u8_t         igmp_maxresp);
  PACK_STRUCT_FIELD(u16_t        igmp_checksum);
  PACK_STRUCT_FLD_S(ip4_addr_p_t igmp_group_address);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
	
#ifdef PACK_STRUCT_USE_INCLUDES
#  include "arch/epstruct.h"
#endif

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_PROT_IGMP_H */
