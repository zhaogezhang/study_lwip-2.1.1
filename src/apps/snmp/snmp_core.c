/**
 * @file
 * MIB tree access/construction functions.
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

/**
 * @defgroup snmp SNMPv2c/v3 agent
 * @ingroup apps
 * SNMPv2c and SNMPv3 compatible agent\n
 * There is also a MIB compiler and a MIB viewer in lwIP contrib repository
 * (lwip-contrib/apps/LwipMibCompiler).\n
 * The agent implements the most important MIB2 MIBs including IPv6 support
 * (interfaces, UDP, TCP, SNMP, ICMP, SYSTEM). IP MIB is an older version
 * without IPv6 statistics (TODO).\n
 * Rewritten by Martin Hentschel <info@cl-soft.de> and
 * Dirk Ziegelmeier <dziegel@gmx.de>\n
 *
 * 0 Agent Capabilities
 * ====================
 *
 * Features:
 * ---------
 * - SNMPv2c support.
 * - SNMPv3 support (a port to ARM mbedtls is provided, LWIP_SNMP_V3_MBEDTLS option).
 * - Low RAM usage - no memory pools, stack only.
 * - MIB2 implementation is separated from SNMP stack.
 * - Support for multiple MIBs (snmp_set_mibs() call) - e.g. for private MIB.
 * - Simple and generic API for MIB implementation.
 * - Comfortable node types and helper functions for scalar arrays and tables.
 * - Counter64, bit and truthvalue datatype support.
 * - Callbacks for SNMP writes e.g. to implement persistency.
 * - Runs on two APIs: RAW and netconn.
 * - Async API is gone - the stack now supports netconn API instead,
 *   so blocking operations can be done in MIB calls.
 *   SNMP runs in a worker thread when netconn API is used.
 * - Simplified thread sync support for MIBs - useful when MIBs
 *   need to access variables shared with other threads where no locking is
 *   possible. Used in MIB2 to access lwIP stats from lwIP thread.
 *
 * MIB compiler (code generator):
 * ------------------------------
 * - Provided in lwIP contrib repository.
 * - Written in C#. MIB viewer used Windows Forms.
 * - Developed on Windows with Visual Studio 2010.
 * - Can be compiled and used on all platforms with http://www.monodevelop.com/.
 * - Based on a heavily modified version of of SharpSnmpLib (a4bd05c6afb4)
 *   (https://sharpsnmplib.codeplex.com/SourceControl/network/forks/Nemo157/MIBParserUpdate).
 * - MIB parser, C file generation framework and LWIP code generation are cleanly
 *   separated, which means the code may be useful as a base for code generation
 *   of other SNMP agents.
 *
 * Notes:
 * ------
 * - Stack and MIB compiler were used to implement a Profinet device.
 *   Compiled/implemented MIBs: LLDP-MIB, LLDP-EXT-DOT3-MIB, LLDP-EXT-PNO-MIB.
 *
 * SNMPv1 per RFC1157 and SNMPv2c per RFC 3416
 * -------------------------------------------
 *   Note the S in SNMP stands for "Simple". Note that "Simple" is
 *   relative. SNMP is simple compared to the complex ISO network
 *   management protocols CMIP (Common Management Information Protocol)
 *   and CMOT (CMip Over Tcp).
 *
 * SNMPv3
 * ------
 * When SNMPv3 is used, several functions from snmpv3.h must be implemented
 * by the user. This is mainly user management and persistence handling.
 * The sample provided in lwip-contrib is insecure, don't use it in production
 * systems, especially the missing persistence for engine boots variable
 * simplifies replay attacks.
 *
 * MIB II
 * ------
 *   The standard lwIP stack management information base.
 *   This is a required MIB, so this is always enabled.
 *   The groups EGP, CMOT and transmission are disabled by default.
 *
 *   Most mib-2 objects are not writable except:
 *   sysName, sysLocation, sysContact, snmpEnableAuthenTraps.
 *   Writing to or changing the ARP and IP address and route
 *   tables is not possible.
 *
 *   Note lwIP has a very limited notion of IP routing. It currently
 *   doen't have a route table and doesn't have a notion of the U,G,H flags.
 *   Instead lwIP uses the interface list with only one default interface
 *   acting as a single gateway interface (G) for the default route.
 *
 *   The agent returns a "virtual table" with the default route 0.0.0.0
 *   for the default interface and network routes (no H) for each
 *   network interface in the netif_list.
 *   All routes are considered to be up (U).
 *
 * Loading additional MIBs
 * -----------------------
 *   MIBs can only be added in compile-time, not in run-time.
 *
 *
 * 1 Building the Agent
 * ====================
 * First of all you'll need to add the following define
 * to your local lwipopts.h:
 * \#define LWIP_SNMP               1
 *
 * and add the source files your makefile.
 *
 * Note you'll might need to adapt you network driver to update
 * the mib2 variables for your interface.
 *
 * 2 Running the Agent
 * ===================
 * The following function calls must be made in your program to
 * actually get the SNMP agent running.
 *
 * Before starting the agent you should supply pointers
 * for sysContact, sysLocation, and snmpEnableAuthenTraps.
 * You can do this by calling
 *
 * - snmp_mib2_set_syscontact()
 * - snmp_mib2_set_syslocation()
 * - snmp_set_auth_traps_enabled()
 *
 * You can register a callback which is called on successful write access:
 * snmp_set_write_callback().
 *
 * Additionally you may want to set
 *
 * - snmp_mib2_set_sysdescr()
 * - snmp_set_device_enterprise_oid()
 * - snmp_mib2_set_sysname()
 *
 * Also before starting the agent you need to setup
 * one or more trap destinations using these calls:
 *
 * - snmp_trap_dst_enable()
 * - snmp_trap_dst_ip_set()
 *
 * If you need more than MIB2, set the MIBs you want to use
 * by snmp_set_mibs().
 *
 * Finally, enable the agent by calling snmp_init()
 *
 * @defgroup snmp_core Core
 * @ingroup snmp
 *
 * @defgroup snmp_traps Traps
 * @ingroup snmp
 */

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_core.h"
#include "snmp_core_priv.h"
#include "lwip/netif.h"
#include <string.h>


#if (LWIP_SNMP && (SNMP_TRAP_DESTINATIONS<=0))
#error "If you want to use SNMP, you have to define SNMP_TRAP_DESTINATIONS>=1 in your lwipopts.h"
#endif
#if (!LWIP_UDP && LWIP_SNMP)
#error "If you want to use SNMP, you have to define LWIP_UDP=1 in your lwipopts.h"
#endif
#if SNMP_MAX_OBJ_ID_LEN > 255
#error "SNMP_MAX_OBJ_ID_LEN must fit into an u8_t"
#endif

/* 表示当前 snmp 系统需要统计的数据 */
struct snmp_statistics snmp_stats;

/* 当前系统默认使用的企业 OID，默认为 LWIP 的企业 OID */
static const struct snmp_obj_id  snmp_device_enterprise_oid_default = {SNMP_DEVICE_ENTERPRISE_OID_LEN, SNMP_DEVICE_ENTERPRISE_OID};
static const struct snmp_obj_id *snmp_device_enterprise_oid         = &snmp_device_enterprise_oid_default;

/* 当前系统默认使用的常量引用 OID {0, 0} */
const u32_t snmp_zero_dot_zero_values[] = { 0, 0 };
const struct snmp_obj_id_const_ref snmp_zero_dot_zero = { LWIP_ARRAYSIZE(snmp_zero_dot_zero_values), snmp_zero_dot_zero_values };

/* 初始化并创建一个 snmp 树形结构中的默认 mib2 节点，这个节点被挂在了 snmp 树上 */
#if SNMP_LWIP_MIB2 && LWIP_SNMP_V3
#include "lwip/apps/snmp_mib2.h"
#include "lwip/apps/snmp_snmpv2_framework.h"
#include "lwip/apps/snmp_snmpv2_usm.h"
static const struct snmp_mib *const default_mibs[] = { &mib2, &snmpframeworkmib, &snmpusmmib };
static u8_t snmp_num_mibs                          = LWIP_ARRAYSIZE(default_mibs);
#elif SNMP_LWIP_MIB2
#include "lwip/apps/snmp_mib2.h"
static const struct snmp_mib *const default_mibs[] = { &mib2 };
static u8_t snmp_num_mibs                          = LWIP_ARRAYSIZE(default_mibs);
#else
static const struct snmp_mib *const default_mibs[] = { NULL };
static u8_t snmp_num_mibs                          = 0;
#endif

/* List of known mibs */
/* 表示当前系统运行时使用的 mib 树形结构节点，这个指针是个二维数组，所以可以包含多个 mib 节点指针 */
static struct snmp_mib const *const *snmp_mibs = default_mibs;

/**
 * @ingroup snmp_core
 * Sets the MIBs to use.
 * Example: call snmp_set_mibs() as follows:
 * static const struct snmp_mib *my_snmp_mibs[] = {
 *   &mib2,
 *   &private_mib
 * };
 * snmp_set_mibs(my_snmp_mibs, LWIP_ARRAYSIZE(my_snmp_mibs));
 */
/*********************************************************************************************************
** 函数名称: snmp_set_mibs
** 功能描述: 设置系统运行时使用的 mib 树形节点信息
** 输	 入: mibs - 想要设置的 mib 树形节点指针数组的首地址
**         : num_mibs - 表示当前设置的 mib 树形节点指针数组中包含的节点指针数
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_set_mibs(const struct snmp_mib **mibs, u8_t num_mibs)
{
  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ASSERT("mibs pointer must be != NULL", (mibs != NULL));
  LWIP_ASSERT("num_mibs pointer must be != 0", (num_mibs != 0));
  snmp_mibs     = mibs;
  snmp_num_mibs = num_mibs;
}

/**
 * @ingroup snmp_core
 * 'device enterprise oid' is used for 'device OID' field in trap PDU's (for identification of generating device)
 * as well as for value returned by MIB-2 'sysObjectID' field (if internal MIB2 implementation is used).
 * The 'device enterprise oid' shall point to an OID located under 'private-enterprises' branch (1.3.6.1.4.1.XXX). If a vendor
 * wants to provide a custom object there, he has to get its own enterprise oid from IANA (http://www.iana.org). It
 * is not allowed to use LWIP enterprise ID!
 * In order to identify a specific device it is recommended to create a dedicated OID for each device type under its own
 * enterprise oid.
 * e.g.
 * device a > 1.3.6.1.4.1.XXX(ent-oid).1(devices).1(device a)
 * device b > 1.3.6.1.4.1.XXX(ent-oid).1(devices).2(device b)
 * for more details see description of 'sysObjectID' field in RFC1213-MIB
 */
/*********************************************************************************************************
** 函数名称: snmp_set_device_enterprise_oid
** 功能描述: 设置当前系统默认使用的企业 OID
** 输	 入: device_enterprise_oid - 需要设置的企业 OID
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void snmp_set_device_enterprise_oid(const struct snmp_obj_id *device_enterprise_oid)
{
  LWIP_ASSERT_CORE_LOCKED();
  if (device_enterprise_oid == NULL) {
    snmp_device_enterprise_oid = &snmp_device_enterprise_oid_default;
  } else {
    snmp_device_enterprise_oid = device_enterprise_oid;
  }
}

/**
 * @ingroup snmp_core
 * Get 'device enterprise oid'
 */
/*********************************************************************************************************
** 函数名称: snmp_get_device_enterprise_oid
** 功能描述: 获取当前系统默认使用的企业 OID
** 输	 入: 
** 输	 出: device_enterprise_oid - 获取到的企业 OID
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
const struct snmp_obj_id *snmp_get_device_enterprise_oid(void)
{
  LWIP_ASSERT_CORE_LOCKED();
  return snmp_device_enterprise_oid;
}

#if LWIP_IPV4
/**
 * Conversion from InetAddressIPv4 oid to lwIP ip4_addr
 * @param oid points to u32_t ident[4] input
 * @param ip points to output struct
 */
/*********************************************************************************************************
** 函数名称: snmp_oid_to_ip4
** 功能描述: 把指定的 snmp oid 转换成与其对应的 IPv4 地址
** 输	 入: oid - 需要转换的 snmp oid 指针
** 输	 出: ip - 转换后得到的 IPv4 地址
**         : 0 - 转换失败，使用默认的 any IPv4 地址
**         : 1 - 转换成功
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_oid_to_ip4(const u32_t *oid, ip4_addr_t *ip)
{
  if ((oid[0] > 0xFF) ||
      (oid[1] > 0xFF) ||
      (oid[2] > 0xFF) ||
      (oid[3] > 0xFF)) {
    ip4_addr_copy(*ip, *IP4_ADDR_ANY4);
    return 0;
  }

  /* 通过“点”表示法设置 IPv4 地址值，最后的地址值表现为网络字节序 */
  IP4_ADDR(ip, oid[0], oid[1], oid[2], oid[3]);
  return 1;
}

/**
 * Convert ip4_addr to InetAddressIPv4 (no InetAddressType)
 * @param ip points to input struct
 * @param oid points to u32_t ident[4] output
 */
/*********************************************************************************************************
** 函数名称: snmp_ip4_to_oid
** 功能描述: 把指定的 IPv4 地址转换成与其对应的 snmp oid
** 输	 入: ip - 需要转换的 IPv4 地址
** 输	 出: oid - 转换后得到的 snmp oid
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_ip4_to_oid(const ip4_addr_t *ip, u32_t *oid)
{
  oid[0] = ip4_addr1(ip);
  oid[1] = ip4_addr2(ip);
  oid[2] = ip4_addr3(ip);
  oid[3] = ip4_addr4(ip);
}
#endif /* LWIP_IPV4 */

#if LWIP_IPV6
/**
 * Conversion from InetAddressIPv6 oid to lwIP ip6_addr
 * @param oid points to u32_t oid[16] input
 * @param ip points to output struct
 */
/*********************************************************************************************************
** 函数名称: snmp_oid_to_ip6
** 功能描述: 把指定的 snmp oid 转换成与其对应的 IPv6 地址
** 输	 入: oid - 需要转换的 snmp oid 指针
** 输	 出: ip - 转换后得到的 IPv6 地址
**		   : 0 - 转换失败，使用默认的 any IPv6 地址
**		   : 1 - 转换成功
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_oid_to_ip6(const u32_t *oid, ip6_addr_t *ip)
{
  if ((oid[0]  > 0xFF) ||
      (oid[1]  > 0xFF) ||
      (oid[2]  > 0xFF) ||
      (oid[3]  > 0xFF) ||
      (oid[4]  > 0xFF) ||
      (oid[5]  > 0xFF) ||
      (oid[6]  > 0xFF) ||
      (oid[7]  > 0xFF) ||
      (oid[8]  > 0xFF) ||
      (oid[9]  > 0xFF) ||
      (oid[10] > 0xFF) ||
      (oid[11] > 0xFF) ||
      (oid[12] > 0xFF) ||
      (oid[13] > 0xFF) ||
      (oid[14] > 0xFF) ||
      (oid[15] > 0xFF)) {
    ip6_addr_set_any(ip);
    return 0;
  }

  ip->addr[0] = (oid[0]  << 24) | (oid[1]  << 16) | (oid[2]  << 8) | (oid[3]  << 0);
  ip->addr[1] = (oid[4]  << 24) | (oid[5]  << 16) | (oid[6]  << 8) | (oid[7]  << 0);
  ip->addr[2] = (oid[8]  << 24) | (oid[9]  << 16) | (oid[10] << 8) | (oid[11] << 0);
  ip->addr[3] = (oid[12] << 24) | (oid[13] << 16) | (oid[14] << 8) | (oid[15] << 0);
  return 1;
}

/**
 * Convert ip6_addr to InetAddressIPv6 (no InetAddressType)
 * @param ip points to input struct
 * @param oid points to u32_t ident[16] output
 */
/*********************************************************************************************************
** 函数名称: snmp_ip6_to_oid
** 功能描述: 把指定的 IPv6 地址转换成与其对应的 snmp oid
** 输	 入: ip - 需要转换的 IPv6 地址
** 输	 出: oid - 转换后得到的 snmp oid
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_ip6_to_oid(const ip6_addr_t *ip, u32_t *oid)
{
  oid[0]  = (ip->addr[0] & 0xFF000000) >> 24;
  oid[1]  = (ip->addr[0] & 0x00FF0000) >> 16;
  oid[2]  = (ip->addr[0] & 0x0000FF00) >>  8;
  oid[3]  = (ip->addr[0] & 0x000000FF) >>  0;
  oid[4]  = (ip->addr[1] & 0xFF000000) >> 24;
  oid[5]  = (ip->addr[1] & 0x00FF0000) >> 16;
  oid[6]  = (ip->addr[1] & 0x0000FF00) >>  8;
  oid[7]  = (ip->addr[1] & 0x000000FF) >>  0;
  oid[8]  = (ip->addr[2] & 0xFF000000) >> 24;
  oid[9]  = (ip->addr[2] & 0x00FF0000) >> 16;
  oid[10] = (ip->addr[2] & 0x0000FF00) >>  8;
  oid[11] = (ip->addr[2] & 0x000000FF) >>  0;
  oid[12] = (ip->addr[3] & 0xFF000000) >> 24;
  oid[13] = (ip->addr[3] & 0x00FF0000) >> 16;
  oid[14] = (ip->addr[3] & 0x0000FF00) >>  8;
  oid[15] = (ip->addr[3] & 0x000000FF) >>  0;
}
#endif /* LWIP_IPV6 */

#if LWIP_IPV4 || LWIP_IPV6
/**
 * Convert to InetAddressType+InetAddress+InetPortNumber
 * @param ip IP address
 * @param port Port
 * @param oid OID
 * @return OID length
 */
/*********************************************************************************************************
** 函数名称: snmp_ip_port_to_oid
** 功能描述: 把指定的 IPv4/IPv6 地址转换成与其对应的 snmp oid
** 注     释: 转换后的数据格式为 InetAddressType + InetAddress + InetPortNumber
** 输	 入: ip - 需要转换的 IPv4/IPv6 地址
**         : port - 需要转换的端口号
** 输	 出: oid - 转换后得到的 snmp oid
**         : idx - 转换后得到的 snmp oid 数据字节长度
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_ip_port_to_oid(const ip_addr_t *ip, u16_t port, u32_t *oid)
{
  u8_t idx;

  idx = snmp_ip_to_oid(ip, oid);
  oid[idx] = port;
  idx++;

  return idx;
}

/**
 * Convert to InetAddressType+InetAddress
 * @param ip IP address
 * @param oid OID
 * @return OID length
 */
/*********************************************************************************************************
** 函数名称: snmp_ip_to_oid
** 功能描述: 把指定的 IPv4/IPv6 地址转换成与其对应的 snmp oid
** 注     释: 转换后的数据格式为 InetAddressType + InetAddress
** 输	 入: ip - 需要转换的 IPv4/IPv6 地址
** 输	 出: oid - 转换后得到的 snmp oid
**         : u8_t - 转换后得到的 snmp oid 数据字节长度
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_ip_to_oid(const ip_addr_t *ip, u32_t *oid)
{
  if (IP_IS_ANY_TYPE_VAL(*ip)) {
    oid[0] = 0; /* any */
    oid[1] = 0; /* no IP OIDs follow */
    return 2;
  } else if (IP_IS_V6(ip)) {
#if LWIP_IPV6
    oid[0] = 2; /* ipv6 */
    oid[1] = 16; /* 16 InetAddressIPv6 OIDs follow */
    snmp_ip6_to_oid(ip_2_ip6(ip), &oid[2]);
    return 18;
#else /* LWIP_IPV6 */
    return 0;
#endif /* LWIP_IPV6 */
  } else {
#if LWIP_IPV4
    oid[0] = 1; /* ipv4 */
    oid[1] = 4; /* 4 InetAddressIPv4 OIDs follow */
    snmp_ip4_to_oid(ip_2_ip4(ip), &oid[2]);
    return 6;
#else /* LWIP_IPV4 */
    return 0;
#endif /* LWIP_IPV4 */
  }
}

/**
 * Convert from InetAddressType+InetAddress to ip_addr_t
 * @param oid OID
 * @param oid_len OID length
 * @param ip IP address
 * @return Parsed OID length
 */
/*********************************************************************************************************
** 函数名称: snmp_oid_to_ip
** 功能描述: 把指定的 snmp oid 地址转换成与其对应的 IPv4/IPv6 
** 注     释: 需要转换的 snmp oid 数据格式为 InetAddressType + InetAddress
** 输	 入: oid - 需要转换的 snmp oid
**         : oid_len - 需要转换的 snmp oid 字节长度
** 输	 出: ip - 转换后得到的 IPv4/IPv6 地址
**         : u8_t - 成功转换的 snmp oid 数据字节长度
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_oid_to_ip(const u32_t *oid, u8_t oid_len, ip_addr_t *ip)
{
  /* InetAddressType */
  if (oid_len < 1) {
    return 0;
  }

  if (oid[0] == 0) { /* any */
    /* 1x InetAddressType, 1x OID len */
    if (oid_len < 2) {
      return 0;
    }
    if (oid[1] != 0) {
      return 0;
    }

    memset(ip, 0, sizeof(*ip));
    IP_SET_TYPE(ip, IPADDR_TYPE_ANY);

    return 2;
  } else if (oid[0] == 1) { /* ipv4 */
#if LWIP_IPV4
    /* 1x InetAddressType, 1x OID len, 4x InetAddressIPv4 */
    if (oid_len < 6) {
      return 0;
    }

    /* 4x ipv4 OID */
    if (oid[1] != 4) {
      return 0;
    }

    IP_SET_TYPE(ip, IPADDR_TYPE_V4);
    if (!snmp_oid_to_ip4(&oid[2], ip_2_ip4(ip))) {
      return 0;
    }

    return 6;
#else /* LWIP_IPV4 */
    return 0;
#endif /* LWIP_IPV4 */
  } else if (oid[0] == 2) { /* ipv6 */
#if LWIP_IPV6
    /* 1x InetAddressType, 1x OID len, 16x InetAddressIPv6 */
    if (oid_len < 18) {
      return 0;
    }

    /* 16x ipv6 OID */
    if (oid[1] != 16) {
      return 0;
    }

    IP_SET_TYPE(ip, IPADDR_TYPE_V6);
    if (!snmp_oid_to_ip6(&oid[2], ip_2_ip6(ip))) {
      return 0;
    }

    return 18;
#else /* LWIP_IPV6 */
    return 0;
#endif /* LWIP_IPV6 */
  } else { /* unsupported InetAddressType */
    return 0;
  }
}

/**
 * Convert from InetAddressType+InetAddress+InetPortNumber to ip_addr_t and u16_t
 * @param oid OID
 * @param oid_len OID length
 * @param ip IP address
 * @param port Port
 * @return Parsed OID length
 */
/*********************************************************************************************************
** 函数名称: snmp_oid_to_ip_port
** 功能描述: 把指定的 snmp oid 地址转换成与其对应的 IPv4/IPv6 
** 注     释: 需要转换的 snmp oid 数据格式为 InetAddressType + InetAddress + InetPortNumber
** 输	 入: oid - 需要转换的 snmp oid
**         : oid_len - 需要转换的 snmp oid 字节长度
** 输	 出: ip - 转换后得到的 IPv4/IPv6 地址
**         : port - 转换后得到的端口号
**         : u8_t - 成功转换的 snmp oid 数据字节长度
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_oid_to_ip_port(const u32_t *oid, u8_t oid_len, ip_addr_t *ip, u16_t *port)
{
  u8_t idx;

  /* InetAddressType + InetAddress */
  idx = snmp_oid_to_ip(&oid[0], oid_len, ip);
  if (idx == 0) {
    return 0;
  }

  /* InetPortNumber */
  if (oid_len < (idx + 1)) {
    return 0;
  }
  if (oid[idx] > 0xffff) {
    return 0;
  }
  *port = (u16_t)oid[idx];
  idx++;

  return idx;
}

#endif /* LWIP_IPV4 || LWIP_IPV6 */

/**
 * Assign an OID to struct snmp_obj_id
 * @param target Assignment target
 * @param oid OID
 * @param oid_len OID length
 */
/*********************************************************************************************************
** 函数名称: snmp_oid_assign
** 功能描述: 根据函数指定参数初始化指定的 snmp oid 对象 
** 输	 入: target - 需要初始化的 snmp oid 对象指针
**         : oid - 想要设置的 snmp oid
**         : oid_len - 想要设置的 snmp oid 字长度
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_oid_assign(struct snmp_obj_id *target, const u32_t *oid, u8_t oid_len)
{
  LWIP_ASSERT("oid_len <= SNMP_MAX_OBJ_ID_LEN", oid_len <= SNMP_MAX_OBJ_ID_LEN);

  target->len = oid_len;

  if (oid_len > 0) {
    MEMCPY(target->id, oid, oid_len * sizeof(u32_t));
  }
}

/**
 * Prefix an OID to OID in struct snmp_obj_id
 * @param target Assignment target to prefix
 * @param oid OID
 * @param oid_len OID length
 */
/*********************************************************************************************************
** 函数名称: snmp_oid_prefix
** 功能描述: 把指定的 snmp oid 数据添加到指定的 snmp oid 对象数据的前端位置
** 输	 入: target - 想要添加前缀数据的 snmp oid 对象指针
**         : oid - 想要添加的 snmp oid 前缀数据
**         : oid_len - 想要添加的 snmp oid 前缀数据字节长度
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_oid_prefix(struct snmp_obj_id *target, const u32_t *oid, u8_t oid_len)
{
  LWIP_ASSERT("target->len + oid_len <= SNMP_MAX_OBJ_ID_LEN", (target->len + oid_len) <= SNMP_MAX_OBJ_ID_LEN);

  if (oid_len > 0) {
    /* move existing OID to make room at the beginning for OID to insert */
    int i;

    /* 把原来的、已经存在的 snmp oid 数据向后平移 oid_len 字节数，给需要添加的前缀预留出空间 */
    for (i = target->len - 1; i >= 0; i--) {
      target->id[i + oid_len] = target->id[i];
    }

    /* paste oid at the beginning */
	/* 把指定的 snmp oid 前缀数据复制到指定的 snmp oid 数据对象前端位置 */
    MEMCPY(target->id, oid, oid_len * sizeof(u32_t));
  }
}

/**
 * Combine two OIDs into struct snmp_obj_id
 * @param target Assignmet target
 * @param oid1 OID 1
 * @param oid1_len OID 1 length
 * @param oid2 OID 2
 * @param oid2_len OID 2 length
 */
/*********************************************************************************************************
** 函数名称: snmp_oid_combine
** 功能描述: 把指定的两个 snmp oid 数据按照顺序组合成一个 snmp oid 对象并放到指定的目标 snmp oid 对象中
** 输	 入: target - 指定的目标 snmp oid 对象指针
**         : oid1 - 需要结合的第一个 snmp oid 数据
**         : oid1_len - 需要结合的第一个 snmp oid 数据字节长度
**         : oid2 - 需要结合的第二个 snmp oid 数据
**         : oid2_len - 需要结合的第二个 snmp oid 数据字节长度
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_oid_combine(struct snmp_obj_id *target, const u32_t *oid1, u8_t oid1_len, const u32_t *oid2, u8_t oid2_len)
{
  snmp_oid_assign(target, oid1, oid1_len);
  snmp_oid_append(target, oid2, oid2_len);
}

/**
 * Append OIDs to struct snmp_obj_id
 * @param target Assignment target to append to
 * @param oid OID
 * @param oid_len OID length
 */
/*********************************************************************************************************
** 函数名称: snmp_oid_append
** 功能描述: 把指定的 snmp oid 数据追加到指定的 snmp oid 对象数据的后端位置
** 输	 入: target - 想要追加后缀数据的 snmp oid 对象指针
**         : oid - 想要追加的 snmp oid 后缀数据
**         : oid_len - 想要追加的 snmp oid 后缀数据字节长度
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_oid_append(struct snmp_obj_id *target, const u32_t *oid, u8_t oid_len)
{
  LWIP_ASSERT("offset + oid_len <= SNMP_MAX_OBJ_ID_LEN", (target->len + oid_len) <= SNMP_MAX_OBJ_ID_LEN);

  if (oid_len > 0) {
    MEMCPY(&target->id[target->len], oid, oid_len * sizeof(u32_t));
    target->len = (u8_t)(target->len + oid_len);
  }
}

/**
 * Compare two OIDs
 * @param oid1 OID 1
 * @param oid1_len OID 1 length
 * @param oid2 OID 2
 * @param oid2_len OID 2 length
 * @return -1: OID1&lt;OID2  1: OID1 &gt;OID2 0: equal
 */
/*********************************************************************************************************
** 函数名称: snmp_oid_compare
** 功能描述: 比较两个指定的 snmp oid 对象数据内容
** 输	 入: oid1 - 需要比较的第一个 snmp oid 数据
**         : oid1_len - 需要比较的第一个 snmp oid 数据字节长度
**         : oid2 - 需要比较的第二个 snmp oid 数据
**         : oid2_len - 需要比较的第二个 snmp oid 数据字节长度
** 输	 出: 0 - 两个 snmp oid 数据对象相等
**         : -1 - oid1 < oid2
**         :  1 - oid1 > oid2
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
s8_t
snmp_oid_compare(const u32_t *oid1, u8_t oid1_len, const u32_t *oid2, u8_t oid2_len)
{
  u8_t level = 0;
  LWIP_ASSERT("'oid1' param must not be NULL or 'oid1_len' param be 0!", (oid1 != NULL) || (oid1_len == 0));
  LWIP_ASSERT("'oid2' param must not be NULL or 'oid2_len' param be 0!", (oid2 != NULL) || (oid2_len == 0));

  while ((level < oid1_len) && (level < oid2_len)) {
    if (*oid1 < *oid2) {
      return -1;
    }
    if (*oid1 > *oid2) {
      return 1;
    }

    level++;
    oid1++;
    oid2++;
  }

  /* common part of both OID's is equal, compare length */
  if (oid1_len < oid2_len) {
    return -1;
  }
  if (oid1_len > oid2_len) {
    return 1;
  }

  /* they are equal */
  return 0;
}


/**
 * Check of two OIDs are equal
 * @param oid1 OID 1
 * @param oid1_len OID 1 length
 * @param oid2 OID 2
 * @param oid2_len OID 2 length
 * @return 1: equal 0: non-equal
 */
/*********************************************************************************************************
** 函数名称: snmp_oid_compare
** 功能描述: 比较两个指定的 snmp oid 对象数据是否相同
** 输	 入: oid1 - 需要比较的第一个 snmp oid 数据
**         : oid1_len - 需要比较的第一个 snmp oid 数据字节长度
**         : oid2 - 需要比较的第二个 snmp oid 数据
**         : oid2_len - 需要比较的第二个 snmp oid 数据字节长度
** 输	 出: 1 - 相等
**         : 0 - 不相等
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_oid_equal(const u32_t *oid1, u8_t oid1_len, const u32_t *oid2, u8_t oid2_len)
{
  return (snmp_oid_compare(oid1, oid1_len, oid2, oid2_len) == 0) ? 1 : 0;
}

/**
 * Convert netif to interface index
 * @param netif netif
 * @return index
 */
/*********************************************************************************************************
** 函数名称: netif_to_num
** 功能描述: 指定网络接口的网络接口号，这个网络接口号从 1 开始计算，0 表示的是无效的网络接口号
** 输	 入: netif - 需要获取索引号的网络接口指针
** 输	 出: u8_t - 获取到的网路接口索引号
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
netif_to_num(const struct netif *netif)
{
  return netif_get_index(netif);
}

/*********************************************************************************************************
** 函数名称: snmp_get_mib_from_oid
** 功能描述: 遍历当前系统内所有有效的 mib 列表成员查找和指定的 snmp oid 匹配的 mib 对象
** 注     释: 这个函数是通过 mib 的 base oid 数据内容来匹配的，并没有比较指定 snmp oid 的所有 oid 数据
** 输	 入: oid - 需要匹配的  snmp oid 数据内容
**         : oid_len - 需要匹配的 snmp oid 数据内容字节长度
** 输	 出: matched_mib - 查找到的匹配的 mib 对象指针
**         : NULL - 没找到和指定 snmp oid 匹配的 mib 对象
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static const struct snmp_mib *
snmp_get_mib_from_oid(const u32_t *oid, u8_t oid_len)
{
  const u32_t *list_oid;
  const u32_t *searched_oid;
  u8_t i, l;

  u8_t max_match_len = 0;
  const struct snmp_mib *matched_mib = NULL;

  LWIP_ASSERT("'oid' param must not be NULL!", (oid != NULL));

  if (oid_len == 0) {
    return NULL;
  }

  /* 遍历当前系统所有有效的 mib 列表成员 */
  for (i = 0; i < snmp_num_mibs; i++) {
    LWIP_ASSERT("MIB array not initialized correctly", (snmp_mibs[i] != NULL));
    LWIP_ASSERT("MIB array not initialized correctly - base OID is NULL", (snmp_mibs[i]->base_oid != NULL));

    if (oid_len >= snmp_mibs[i]->base_oid_len) {
      l            = snmp_mibs[i]->base_oid_len;
      list_oid     = snmp_mibs[i]->base_oid;
      searched_oid = oid;

      /* 比较需要查找的 snmp base oid 和当前遍历的 mib base oid 内容是否相同 */
      while (l > 0) {
        if (*list_oid != *searched_oid) {
          break;
        }

        l--;
        list_oid++;
        searched_oid++;
      }

      /* 如果找到了和指定 snmp oid 匹配的 mib，则记录找到的 mib 信息 */
      if ((l == 0) && (snmp_mibs[i]->base_oid_len > max_match_len)) {
        max_match_len = snmp_mibs[i]->base_oid_len;
        matched_mib = snmp_mibs[i];
      }
    }
  }

  return matched_mib;
}

/*********************************************************************************************************
** 函数名称: snmp_get_next_mib
** 功能描述: 遍历当前系统所有有效的 mib 列表成员，以 snmp oid 为关键字按照升序的方式在 snmp_mibs 
**         : 数组中找到和指定的 snmp oid 最接近的下一个 mib 成员指针
** 输	 入: oid - 需要查找的  snmp oid 数据内容
**         : oid_len - 需要查找的 snmp oid 数据内容字节长度
** 输	 出: next_mib - 查找到的和指定 snmp oid 最接近的下一个 mib 成员指针
**         : NULL - 没找到匹配的 mib 对象
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static const struct snmp_mib *
snmp_get_next_mib(const u32_t *oid, u8_t oid_len)
{
  u8_t i;
  const struct snmp_mib *next_mib = NULL;

  LWIP_ASSERT("'oid' param must not be NULL!", (oid != NULL));

  if (oid_len == 0) {
    return NULL;
  }

  /* 遍历当前系统所有有效的 mib 列表成员，以 snmp oid 为关键字按照升序的方式在 snmp_mibs 数组中找到
   * 和指定的 snmp oid 最接近的下一个 mib 成员指针 */
  for (i = 0; i < snmp_num_mibs; i++) {
    if (snmp_mibs[i]->base_oid != NULL) {
      /* check if mib is located behind starting point */
      if (snmp_oid_compare(snmp_mibs[i]->base_oid, snmp_mibs[i]->base_oid_len, oid, oid_len) > 0) {
        if ((next_mib == NULL) ||
            (snmp_oid_compare(snmp_mibs[i]->base_oid, snmp_mibs[i]->base_oid_len,
                              next_mib->base_oid, next_mib->base_oid_len) < 0)) {
          next_mib = snmp_mibs[i];
        }
      }
    }
  }

  return next_mib;
}

/*********************************************************************************************************
** 函数名称: snmp_get_mib_between
** 功能描述: 遍历当前系统所有有效的 mib 列表成员，以 snmp oid 为关键字查找位于指定的两个 snmp oid 之间
**         : 的 mib 成员并返回满足条件的成员指针
** 输	 入: oid1 - 指定的下边界 snmp oid 数据
**         : oid1_len - 指定的下边界 snmp oid 数据字节长度
**         : oid2 - 指定的上边界 snmp oid 数据
**         : oid2_len - 指定的上边界 snmp oid 数据字节长度
** 输	 出: next_mib - 查找到的满足条件的 mib 成员指针
**         : NULL - 没找到满足条件的 mib 对象
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static const struct snmp_mib *
snmp_get_mib_between(const u32_t *oid1, u8_t oid1_len, const u32_t *oid2, u8_t oid2_len)
{
  const struct snmp_mib *next_mib = snmp_get_next_mib(oid1, oid1_len);

  LWIP_ASSERT("'oid2' param must not be NULL!", (oid2 != NULL));
  LWIP_ASSERT("'oid2_len' param must be greater than 0!", (oid2_len > 0));

  if (next_mib != NULL) {
    if (snmp_oid_compare(next_mib->base_oid, next_mib->base_oid_len, oid2, oid2_len) < 0) {
      return next_mib;
    }
  }

  return NULL;
}

/*********************************************************************************************************
** 函数名称: snmp_get_node_instance_from_oid
** 功能描述: 遍历当前系统内所有有效的 mib 列表成员查找和指定的 snmp oid 匹配的叶子节点并
**         : 返回这个叶子节点的实例信息
** 输	 入: oid - 指定的 snmp oid 数据内容
**         : oid_len - 指定的 snmp oid 数据内容字节长度
** 输	 出: node_instance - 查找到的匹配的叶子节点的实例信息
**         : result - 查找结果
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_get_node_instance_from_oid(const u32_t *oid, u8_t oid_len, struct snmp_node_instance *node_instance)
{
  u8_t result = SNMP_ERR_NOSUCHOBJECT;
  const struct snmp_mib *mib;
  const struct snmp_node *mn = NULL;

  /* 遍历当前系统内所有有效的 mib 列表成员查找和指定的 snmp oid 匹配的 mib 对象 */
  mib = snmp_get_mib_from_oid(oid, oid_len);
  if (mib != NULL) {
    u8_t oid_instance_len;

    /* 以指定的 mib 根节点为起点依次向下遍历查找和指定的 snmp oid 匹配的树节点并返回这个节点指针
       以及这个节点的 snmp oid 数据的字节长度 */
    mn = snmp_mib_tree_resolve_exact(mib, oid, oid_len, &oid_instance_len);
  
    if ((mn != NULL) && (mn->node_type != SNMP_NODE_TREE)) {
      /* get instance */
	  /* 如果不是树节点，则认为是树的叶子节点 */
      const struct snmp_leaf_node *leaf_node = (const struct snmp_leaf_node *)(const void *)mn;

      /* 根据查找到的、和指定 snmp oid 匹配的叶子节点信息初始化指定的节点实例 node_instance */
      node_instance->node = mn;
      snmp_oid_assign(&node_instance->instance_oid, oid + (oid_len - oid_instance_len), oid_instance_len);

      /* 调用指定的叶子节点的 get_instance 接口获取这个叶子节点的实例信息并返回操作结果 */
      result = leaf_node->get_instance(
                 oid,
                 oid_len - oid_instance_len,
                 node_instance);

#ifdef LWIP_DEBUG
      if (result == SNMP_ERR_NOERROR) {
        if (((node_instance->access & SNMP_NODE_INSTANCE_ACCESS_READ) != 0) && (node_instance->get_value == NULL)) {
          LWIP_DEBUGF(SNMP_DEBUG, ("SNMP inconsistent access: node is readable but no get_value function is specified\n"));
        }
        if (((node_instance->access & SNMP_NODE_INSTANCE_ACCESS_WRITE) != 0) && (node_instance->set_value == NULL)) {
          LWIP_DEBUGF(SNMP_DEBUG, ("SNMP inconsistent access: node is writable but no set_value and/or set_test function is specified\n"));
        }
      }
#endif
    }
  }

  return result;
}

/*********************************************************************************************************
** 函数名称: snmp_get_next_node_instance_from_oid
** 功能描述: 在当前系统内遍历所有的 mib 树形结构并以 oid 为关键字按照升序方式查找和指定的 snmp oid 
**         : 最接近的下一个叶子节点，如果找到满足条件的叶子节点则执行如下操作：
**         : 1. 调用查找到的叶子节点的 get_next_instance 接口获取这个叶子节点的下一个实例信息
**         : 2. 如果函数参数指定了节点的有效性验证函数指针，则执行有效性验证操作并返回这个节点
**         :    实例的完整 snmp oid
** 输	 入: oid - 指定的 snmp oid 数据内容
**         : oid_len - 指定的 snmp oid 数据内容字节长度
**         : validate_node_instance_method - 用于验证找到到的节点的有效性的函数指针
**         : validate_node_instance_arg - 用于验证找到到的节点的有效性的函数参数
** 输	 出: node_oid - 查找到的满足条件的节点 snmp oid 信息指针
**         : node_instance - 查找到的满足条件的节点实例指针
**         : SNMP_ERR_NOERROR - 获取成功
**         : SNMP_ERR_ENDOFMIBVIEW - 获取失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_get_next_node_instance_from_oid(const u32_t *oid, u8_t oid_len, snmp_validate_node_instance_method validate_node_instance_method, void *validate_node_instance_arg, struct snmp_obj_id *node_oid, struct snmp_node_instance *node_instance)
{
  const struct snmp_mib      *mib;
  const struct snmp_node *mn = NULL;
  const u32_t *start_oid     = NULL;
  u8_t         start_oid_len = 0;

  /* resolve target MIB from passed OID */
  /* 遍历当前系统内所有有效的 mib 列表成员查找和指定的 snmp oid 匹配的 mib 对象 */
  mib = snmp_get_mib_from_oid(oid, oid_len);
  if (mib == NULL) {
    /* passed OID does not reference any known MIB, start at the next closest MIB */
    /* 遍历当前系统所有有效的 mib 列表成员，以 snmp oid 为关键字按照升序的方式在 snmp_mibs 
     * 数组中找到和指定的 snmp oid 最接近的下一个 mib 成员指针 */
    mib = snmp_get_next_mib(oid, oid_len);

    if (mib != NULL) {
      start_oid     = mib->base_oid;
      start_oid_len = mib->base_oid_len;
    }
  } else {
    start_oid     = oid;
    start_oid_len = oid_len;
  }

  /* resolve target node from MIB, skip to next MIB if no suitable node is found in current MIB */
  while ((mib != NULL) && (mn == NULL)) {
    u8_t oid_instance_len;

    /* check if OID directly references a node inside current MIB, in this case we have to ask this node for the next instance */
    /* 以指定的 mib 根节点为起点依次向下遍历查找和指定的 snmp oid 匹配的树节点并返回这个节点指针
       以及这个节点的 snmp oid 数据的字节长度 */
    mn = snmp_mib_tree_resolve_exact(mib, start_oid, start_oid_len, &oid_instance_len);
    if (mn != NULL) {
	  /* 如果找到了和指定的 snmp oid 匹配的树形节点，则保存这个树形节点信息到指定变量中（node_oid/node_instance）*/
      snmp_oid_assign(node_oid, start_oid, start_oid_len - oid_instance_len); /* set oid to node */
      snmp_oid_assign(&node_instance->instance_oid, start_oid + (start_oid_len - oid_instance_len), oid_instance_len); /* set (relative) instance oid */
    } else {
      /* OID does not reference a node, search for the next closest node inside MIB; set instance_oid.len to zero because we want the first instance of this node */
      /* 以指定的 mib 根节点为起点开始遍历 snmp 树形结构并以 oid 为关键字按照升序方式查找和指定的
       * snmp oid 最接近的下一个叶子节点，并返回满足条件的叶子节点指针以及叶子节点的 snmp oid 信息 */
	  mn = snmp_mib_tree_resolve_next(mib, start_oid, start_oid_len, node_oid);
      node_instance->instance_oid.len = 0;
    }

    /* validate the node; if the node has no further instance or the returned instance is invalid, search for the next in MIB and validate again */
    node_instance->node = mn;

	/* 通过指定的叶子节点的 get_next_instance 接口获取这个叶子节点的下一个实例信息并验证这个节点实例的有效性
	 * 如果验证通过，则返回这个节点的实例信息以及完整 snmp oid 数据，否则继续查找 */
    while (mn != NULL) {
      u8_t result;

      /* clear fields which may have values from previous loops */
      node_instance->asn1_type        = 0;
      node_instance->access           = SNMP_NODE_INSTANCE_NOT_ACCESSIBLE;
      node_instance->get_value        = NULL;
      node_instance->set_test         = NULL;
      node_instance->set_value        = NULL;
      node_instance->release_instance = NULL;
      node_instance->reference.ptr    = NULL;
      node_instance->reference_len    = 0;

      /* 调用指定的叶子节点的 get_next_instance 接口获取这个叶子节点的下一个实例信息并返回操作结果 */
      result = ((const struct snmp_leaf_node *)(const void *)mn)->get_next_instance(
                 node_oid->id,
                 node_oid->len,
                 node_instance);

      if (result == SNMP_ERR_NOERROR) {
	  	
#ifdef LWIP_DEBUG
        if (((node_instance->access & SNMP_NODE_INSTANCE_ACCESS_READ) != 0) && (node_instance->get_value == NULL)) {
          LWIP_DEBUGF(SNMP_DEBUG, ("SNMP inconsistent access: node is readable but no get_value function is specified\n"));
        }
        if (((node_instance->access & SNMP_NODE_INSTANCE_ACCESS_WRITE) != 0) && (node_instance->set_value == NULL)) {
          LWIP_DEBUGF(SNMP_DEBUG, ("SNMP inconsistent access: node is writable but no set_value function is specified\n"));
        }
#endif

        /* validate node because the node may be not accessible for example (but let the caller decide what is valid */
        /* 如果函数参数指定了节点的有效性验证函数指针，则执行有效性验证操作并返回这个节点实例的完整 snmp oid
         * 并退出当前循环继续执行后续操作 */
		if ((validate_node_instance_method == NULL) ||
            (validate_node_instance_method(node_instance, validate_node_instance_arg) == SNMP_ERR_NOERROR)) {
          /* node_oid "returns" the full result OID (including the instance part) */
          snmp_oid_append(node_oid, node_instance->instance_oid.id, node_instance->instance_oid.len);
          break;
        }

        if (node_instance->release_instance != NULL) {
          node_instance->release_instance(node_instance);
        }
        /*
        the instance itself is not valid, ask for next instance from same node.
        we don't have to change any variables because node_instance->instance_oid is used as input (starting point)
        as well as output (resulting next OID), so we have to simply call get_next_instance method again
        */
      } else {
      
        if (node_instance->release_instance != NULL) {
          node_instance->release_instance(node_instance);
        }

        /* the node has no further instance, skip to next node */
		/* 以指定的 mib 根节点为起点开始遍历 snmp 树形结构并以 oid 为关键字按照升序方式查找和指定的
         * snmp oid 最接近的下一个叶子节点，并返回满足条件的叶子节点指针以及叶子节点的 snmp oid 信息 */
        mn = snmp_mib_tree_resolve_next(mib, node_oid->id, node_oid->len, &node_instance->instance_oid); /* misuse node_instance->instance_oid as tmp buffer */
        if (mn != NULL) {
          /* prepare for next loop */
          snmp_oid_assign(node_oid, node_instance->instance_oid.id, node_instance->instance_oid.len);
          node_instance->instance_oid.len = 0;
          node_instance->node = mn;
        }
      }
    }

    if (mn != NULL) {
      /*
      we found a suitable next node,
      now we have to check if a inner MIB is located between the searched OID and the resulting OID.
      this is possible because MIB's may be located anywhere in the global tree, that means also in
      the subtree of another MIB (e.g. if searched OID is .2 and resulting OID is .4, then another
      MIB having .3 as root node may exist)
      */

	  /* 如果在我们查找到的 snmp oid 和当前查找时使用的起始 snmp oid 之间存在其他的inter mib
	   * 则继续尝试在这个 inter mib 上遍历并查找更加符合的树形叶子节点 */
      const struct snmp_mib *intermediate_mib;
      intermediate_mib = snmp_get_mib_between(start_oid, start_oid_len, node_oid->id, node_oid->len);

      if (intermediate_mib != NULL) {
        /* search for first node inside intermediate mib in next loop */
        if (node_instance->release_instance != NULL) {
          node_instance->release_instance(node_instance);
        }

        mn            = NULL;
        mib           = intermediate_mib;
        start_oid     = mib->base_oid;
        start_oid_len = mib->base_oid_len;
      }
      /* else { we found out target node } */
    } else {

      /*
      there is no further (suitable) node inside this MIB, search for the next MIB with following priority
      1. search for inner MIB's (whose root is located inside tree of current MIB)
      2. search for surrouding MIB's (where the current MIB is the inner MIB) and continue there if any
      3. take the next closest MIB (not being related to the current MIB)
      */
      /* 执行到这表示在当前的 mib 中没有找到和指定的 snmp oid 匹配的树形节点，所以需要遍历当前系统内其他的
	   * mib 树形结构来继续尝试查找和指定的 snmp oid 匹配的树形节点 */
      const struct snmp_mib *next_mib;

	  /* 遍历当前系统所有有效的 mib 列表成员，以 snmp oid 为关键字按照升序的方式在 snmp_mibs 
       * 数组中找到和指定的 snmp oid 最接近的下一个 mib 成员指针 */
      next_mib = snmp_get_next_mib(start_oid, start_oid_len); /* returns MIB's related to point 1 and 3 */

      /* is the found MIB an inner MIB? (point 1) */
      if ((next_mib != NULL) && (next_mib->base_oid_len > mib->base_oid_len) &&
          (snmp_oid_compare(next_mib->base_oid, mib->base_oid_len, mib->base_oid, mib->base_oid_len) == 0)) {
        /* yes it is -> continue at inner MIB */
		/* 表示当前遍历的 mib 上有一个 inner mib，所以我们继续遍历这个挂载在当前 mib 上的 inner mib 树形结构 */
        mib = next_mib;
        start_oid     = mib->base_oid;
        start_oid_len = mib->base_oid_len;
      } else {
        /* check if there is a surrounding mib where to continue (point 2) (only possible if OID length > 1) */
        if (mib->base_oid_len > 1) {

		  /* 遍历当前系统内所有有效的 mib 列表成员查找和指定的 snmp oid 匹配的 mib 对象 */
          mib = snmp_get_mib_from_oid(mib->base_oid, mib->base_oid_len - 1);

          /* 如果当前遍历的 mib 不是 inner mib，则直接遍历找到的和指定的 snmp oid 最接近的下一个 mib */
          if (mib == NULL) {
            /* no surrounding mib, use next mib encountered above (point 3) */
            mib = next_mib;

            if (mib != NULL) {
              start_oid     = mib->base_oid;
              start_oid_len = mib->base_oid_len;
            }
          }
          /* else { start_oid stays the same because we want to continue from current offset in surrounding mib (point 2) } */
        }
      }
    }
  }

  if (mib == NULL) {
    /* loop is only left when mib == null (error) or mib_node != NULL (success) */
    return SNMP_ERR_ENDOFMIBVIEW;
  }

  return SNMP_ERR_NOERROR;
}

/**
 * Searches tree for the supplied object identifier.
 *
 */
/*********************************************************************************************************
** 函数名称: snmp_mib_tree_resolve_exact
** 功能描述: 以指定的 mib 根节点为起点依次向下遍历查找和指定的 snmp oid 匹配的树节点并返回这个节点指针
**         : 以及这个节点的 snmp oid 数据的字节长度
** 输	 入: mib - 需要遍历的 snmp 树形结构中的 mib 节点指针
**         : oid - 需要匹配的 snmp oid 数据内容
**         : oid_len - 需要匹配的 snmp oid 数据内容字节长度
** 输	 出: node - 查找到的满足条件的树节点成员指针
**         : oid_instance_len - 查找到的满足条件的树节点成员的 snmp oid 数据字节长度
**         : NULL - 没找到满足条件的 mib 对象
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
const struct snmp_node *
snmp_mib_tree_resolve_exact(const struct snmp_mib *mib, const u32_t *oid, u8_t oid_len, u8_t *oid_instance_len)
{
  const struct snmp_node *const *node = &mib->root_node;
  u8_t oid_offset = mib->base_oid_len;

  /* 从指定的 mib 根节点依次向下遍历，直到遍历到指定的叶子节点 */
  while ((oid_offset < oid_len) && ((*node)->node_type == SNMP_NODE_TREE)) {
    /* search for matching sub node */
    u32_t subnode_oid = *(oid + oid_offset);

    u32_t i = (*(const struct snmp_tree_node * const *)node)->subnode_count;
    node    = (*(const struct snmp_tree_node * const *)node)->subnodes;

	/* 遍历当前节点的所有子节点来查找和指定的 snmp oid “相应字段”匹配的子节点 */
    while ((i > 0) && ((*node)->oid != subnode_oid)) {
      node++;
      i--;
    }

    if (i == 0) {
      /* no matching subnode found */
      return NULL;
    }

    /* 更新到指定 snmp oid 的下一个字段位置并继续比较 */
    oid_offset++;
  }

  if ((*node)->node_type != SNMP_NODE_TREE) {
    /* we found a leaf node */
    *oid_instance_len = oid_len - oid_offset;
    return (*node);
  }

  return NULL;
}

/*********************************************************************************************************
** 函数名称: snmp_mib_tree_resolve_next
** 功能描述: 以指定的 mib 根节点为起点开始遍历 snmp 树形结构并以 oid 为关键字按照升序方式查找和指定的
**         : snmp oid 最接近的下一个叶子节点，并返回满足条件的叶子节点指针以及叶子节点的 snmp oid 信息
** 输	 入: mib - 需要遍历的 snmp 树形结构中的 mib 节点指针
**         : oid - 需要匹配的 snmp oid 数据内容
**         : oid_len - 需要匹配的 snmp oid 数据内容字节长度
** 输	 出: node - 查找到的满足条件的叶子节点指针
**         : oidret - 查找到的满足条件的叶子节点 snmp oid 信息
**         : NULL - 没找到满足条件的叶子节点
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
const struct snmp_node *
snmp_mib_tree_resolve_next(const struct snmp_mib *mib, const u32_t *oid, u8_t oid_len, struct snmp_obj_id *oidret)
{
  u8_t  oid_offset = mib->base_oid_len;
  const struct snmp_node *const *node;
  const struct snmp_tree_node *node_stack[SNMP_MAX_OBJ_ID_LEN];
  s32_t nsi = 0; /* NodeStackIndex */
  u32_t subnode_oid;

  if (mib->root_node->node_type != SNMP_NODE_TREE) {
    /* a next operation on a mib with only a leaf node will always return NULL because there is no other node */
    return NULL;
  }

  /* first build node stack related to passed oid (as far as possible), then go backwards to determine the next node */
  node_stack[nsi] = (const struct snmp_tree_node *)(const void *)mib->root_node;

  /* 根据指定的 mib 节点和指定的 snmp oid 信息开始遍历 mib 树并把遍历路径所经过的节点信息保存在 node_stack 中 */
  while (oid_offset < oid_len) {
  	
    /* search for matching sub node */
    /* 获取当前节点的子节点信息 */
    u32_t i = node_stack[nsi]->subnode_count;
    node    = node_stack[nsi]->subnodes;

    /* 获取指定的 snmp oid 数据中需要匹配的子节点的 oid 字段数据 */
    subnode_oid = *(oid + oid_offset);

    while ((i > 0) && ((*node)->oid != subnode_oid)) {
      node++;
      i--;
    }

    /* 如果遍历到了叶子节点，则直接退出 */
    if ((i == 0) || ((*node)->node_type != SNMP_NODE_TREE)) {
      /* no (matching) tree-subnode found */
      break;
    }

	/* 在 node_stack 中记录遍历指定的 mib 树时所经过的所有路径节点信息 */
    nsi++;
    node_stack[nsi] = (const struct snmp_tree_node *)(const void *)(*node);

    oid_offset++;
  }


  if (oid_offset >= oid_len) {
    /* passed oid references a tree node -> return first useable sub node of it */
    subnode_oid = 0;
  } else {
    subnode_oid = *(oid + oid_offset) + 1;
  }

  /* 根据上面构建的 node_stack 以 oid 为关键字按照升序方式查找和指定的 snmp oid 
   * 最接近的下一个 node 节点 */
  while (nsi >= 0) {
    const struct snmp_node *subnode = NULL;

    /* find next node on current level */
    s32_t i        = node_stack[nsi]->subnode_count;
    node           = node_stack[nsi]->subnodes;

    /* 遍历当前节点的所有子节点以 oid 为关键字按照升序方式查找和指定的 snmp oid
     * 最接近的下一个 node 节点 */
    while (i > 0) {
      if ((*node)->oid == subnode_oid) {
        subnode = *node;
        break;
      } else if (((*node)->oid > subnode_oid) && ((subnode == NULL) || ((*node)->oid < subnode->oid))) {
        subnode = *node;
      }

      node++;
      i--;
    }

    if (subnode == NULL) {
      /* no further node found on this level, go one level up and start searching with index of current node */
	  /* 如果在当前树形结构中没有找到满足条件的节点，则回退到遍历路径的上一级继续遍历 */
      subnode_oid = node_stack[nsi]->node.oid + 1;
      nsi--;
    } else {
		
      if (subnode->node_type == SNMP_NODE_TREE) {
        /* next is a tree node, go into it and start searching */
	    /* 如果查找到的满足条件的节点是一个树形节点，则继续向下遍历 */
        nsi++;
        node_stack[nsi] = (const struct snmp_tree_node *)(const void *)subnode;
        subnode_oid = 0;
      } else {
        /* we found a leaf node -> fill oidret and return it */
        /* 如果找到了满足条件的叶子节点，则把相关的 snmp oid 信息复制到指定的 snmp oid 返回值 oidret 中 */

		
	    /* 复制满足条件的叶子节点的 mib base oid 信息到指定的 snmp oid 返回值 oidret 中 */
        snmp_oid_assign(oidret, mib->base_oid, mib->base_oid_len);
        i = 1;

		/* 从 mib base 为起点，以 node_stack 为路径开始复制剩余的 snmp oid 信息到指定的 snmp oid 返回值 oidret 中 */
        while (i <= nsi) {
          oidret->id[oidret->len] = node_stack[i]->node.oid;
          oidret->len++;
          i++;
        }

        /* 设置获取到的叶子节点的 snmp oid 数据到指定的 snmp oid 返回值 oidret 中 */
        oidret->id[oidret->len] = subnode->oid;
        oidret->len++;

        /* 返回查找到的满足条件的叶子节点指针 */
        return subnode;
      }
    }
  }

  return NULL;
}

/** initialize struct next_oid_state using this function before passing it to next_oid_check */
/*********************************************************************************************************
** 函数名称: snmp_next_oid_init
** 功能描述: 根据函数指定参数初始化指定的 snmp next oid state 结构体
** 输	 入: start_oid - 起始 snmp oid 数据内容
**         : start_oid_len - 起始 snmp oid 数据内容字节数
**         : next_oid_buf - 下一个 snmp oid 数据内容
**         : next_oid_max_len - 下一个 snmp oid 数据内容字节数
** 输	 出: state - 需要初始化的结构体指针
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
snmp_next_oid_init(struct snmp_next_oid_state *state,
                   const u32_t *start_oid, u8_t start_oid_len,
                   u32_t *next_oid_buf, u8_t next_oid_max_len)
{
  state->start_oid        = start_oid;
  state->start_oid_len    = start_oid_len;
  state->next_oid         = next_oid_buf;
  state->next_oid_len     = 0;
  state->next_oid_max_len = next_oid_max_len;
  state->status           = SNMP_NEXT_OID_STATUS_NO_MATCH;
}

/** checks if the passed incomplete OID may be a possible candidate for snmp_next_oid_check();
this method is intended if the complete OID is not yet known but it is very expensive to build it up,
so it is possible to test the starting part before building up the complete oid and pass it to snmp_next_oid_check()*/
/*********************************************************************************************************
** 函数名称: snmp_next_oid_precheck
** 功能描述: 校验指定的 snmp oid 是否在指定的 next oid state 结构表示的范围之内
**         : 这个函数参数指定的 snmp oid 可能只是完整 snmp oid 的一部分
** 输	 入: state - 指定的 next oid state 结构指针
**         : oid - 需要检验的 snmp oid 数据内容
**         : oid_len - 需要检验的 snmp oid 数据内容字节数
** 输	 出: 1 - 指定的 snmp oid “在”指定的 next oid state 结构表示的范围之内
**         : 0 - 指定的 snmp oid “不在”指定的 next oid state 结构表示的范围之内
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_next_oid_precheck(struct snmp_next_oid_state *state, const u32_t *oid, u8_t oid_len)
{
  if (state->status != SNMP_NEXT_OID_STATUS_BUF_TO_SMALL) {
    u8_t start_oid_len = (oid_len < state->start_oid_len) ? oid_len : state->start_oid_len;

    /* check passed OID is located behind start offset */
    if (snmp_oid_compare(oid, oid_len, state->start_oid, start_oid_len) >= 0) {
      /* check if new oid is located closer to start oid than current closest oid */
      if ((state->status == SNMP_NEXT_OID_STATUS_NO_MATCH) ||
          (snmp_oid_compare(oid, oid_len, state->next_oid, state->next_oid_len) < 0)) {
        return 1;
      }
    }
  }

  return 0;
}

/** checks the passed OID if it is a candidate to be the next one (get_next); returns !=0 if passed oid is currently closest, otherwise 0 */
/*********************************************************************************************************
** 函数名称: snmp_next_oid_check
** 功能描述: 校验指定的 snmp oid 是否在指定的 next oid state 结构表示的范围之内，如果在则更新这个
**         : next oid state 结构的 next_oid 字段为指定的 snmp oid 来实现缩小 next oid state 范围的功能
** 输	 入: state - 指定的 next oid state 结构指针
**         : oid - 需要检验的 snmp oid 数据内容
**         : oid_len - 需要检验的 snmp oid 数据内容字节数
** 输	 出: 1 - 指定的 snmp oid “在”指定的 next oid state 结构表示的范围之内
**         : 0 - 指定的 snmp oid “不在”指定的 next oid state 结构表示的范围之内
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_next_oid_check(struct snmp_next_oid_state *state, const u32_t *oid, u8_t oid_len, void *reference)
{
  /* do not overwrite a fail result */
  if (state->status != SNMP_NEXT_OID_STATUS_BUF_TO_SMALL) {
  	
    /* check passed OID is located behind start offset */
    if (snmp_oid_compare(oid, oid_len, state->start_oid, state->start_oid_len) > 0) {
		
      /* check if new oid is located closer to start oid than current closest oid */
      if ((state->status == SNMP_NEXT_OID_STATUS_NO_MATCH) ||
          (snmp_oid_compare(oid, oid_len, state->next_oid, state->next_oid_len) < 0)) {
          
        if (oid_len <= state->next_oid_max_len) {
          MEMCPY(state->next_oid, oid, oid_len * sizeof(u32_t));
          state->next_oid_len = oid_len;
          state->status       = SNMP_NEXT_OID_STATUS_SUCCESS;
          state->reference    = reference;
          return 1;
        } else {
		  /* 表示指定的 snmp oid 数据长度超过了指定的 next oid state 的 next_oid_max_len 字段值 */
          state->status = SNMP_NEXT_OID_STATUS_BUF_TO_SMALL;
        }
      }
    }
  }

  return 0;
}

/*********************************************************************************************************
** 函数名称: snmp_oid_in_range
** 功能描述: 校验指定的 snmp oid 是否在指定的 oid_ranges 表示的范围之内
** 输	 入: oid_in - 需要检验的 snmp oid 数据内容
**         : oid_len - 需要检验的 snmp oid 数据内容字节数
**         : oid_ranges - 指定的 oid_ranges 设定的范围数据，这是一个数组结构
**         : oid_ranges_len - 表示指定的 oid_ranges 设定的范围的数组数据长度
** 输	 出: 1 - 指定的 snmp oid “在”指定的范围之内
**         : 0 - 指定的 snmp oid “不在”指定的范围之内
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_oid_in_range(const u32_t *oid_in, u8_t oid_len, const struct snmp_oid_range *oid_ranges, u8_t oid_ranges_len)
{
  u8_t i;

  if (oid_len != oid_ranges_len) {
    return 0;
  }

  for (i = 0; i < oid_ranges_len; i++) {
    if ((oid_in[i] < oid_ranges[i].min) || (oid_in[i] > oid_ranges[i].max)) {
      return 0;
    }
  }

  return 1;
}

/*********************************************************************************************************
** 函数名称: snmp_set_test_ok
** 功能描述: 当前系统默认使用的数值设置测试方法函数指针，可在设置指定的 oid 对象数据之前调用，判断想要
**         : 执行的数值设置操作是否合法
** 输	 入: instance - 需要测试的实例指针
**         : value_len - 需要设置的数值数据长度
**         : value - 需要设置的数值数据内容
** 输	 出: SNMP_ERR_NOERROR - 表示可以执行数值设置操作
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
snmp_err_t
snmp_set_test_ok(struct snmp_node_instance *instance, u16_t value_len, void *value)
{
  LWIP_UNUSED_ARG(instance);
  LWIP_UNUSED_ARG(value_len);
  LWIP_UNUSED_ARG(value);

  return SNMP_ERR_NOERROR;
}

/**
 * Decodes BITS pseudotype value from ASN.1 OctetString.
 *
 * @note Because BITS pseudo type is encoded as OCTET STRING, it cannot directly
 * be encoded/decoded by the agent. Instead call this function as required from
 * get/test/set methods.
 *
 * @param buf points to a buffer holding the ASN1 octet string
 * @param buf_len length of octet string
 * @param bit_value decoded Bit value with Bit0 == LSB
 * @return ERR_OK if successful, ERR_ARG if bit value contains more than 32 bit
 */
/*********************************************************************************************************
** 函数名称: snmp_decode_bits
** 功能描述: 把存储在指定缓冲区中的 ASN1 格式数据转换成与其对应的 32 bit LSB 格式数据
**         : 比如 buf 数据为 - 00001111 01010101 10101010 11110000
**         : 则转换后的数据为 - 11110000 10101010 01010101 00001111
** 输	 入: buf - ASN1 格式的数据缓冲区地址
**         : buf_len - ASN1 格式的数据缓冲区长度
** 输	 出: bit_value - 转换后的结果数据
**         : ERR_OK - 转换成功
**         : ERR_VAL - ASN1 格式的数据缓冲区长度太长
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_decode_bits(const u8_t *buf, u32_t buf_len, u32_t *bit_value)
{
  u8_t b;
  u8_t bits_processed = 0;
  *bit_value = 0;

  while (buf_len > 0) {
  	
    /* any bit set in this byte? */
    if (*buf != 0x00) {
		
      if (bits_processed >= 32) {
        /* accept more than 4 bytes, but only when no bits are set */
        return ERR_VAL;
      }

      b = *buf;

	  /* 每次只处理 8 bits 数据，单字节的高位放到 bit_value 的低位 */
      do {
        if (b & 0x80) {
          *bit_value |= (1 << bits_processed);
        }
        bits_processed++;
        b <<= 1;
      } while ((bits_processed & 0x07) != 0); /* &0x07 -> % 8 */
	  
    } else {
      bits_processed += 8;
    }

    buf_len--;
    buf++;
  }

  return ERR_OK;
}

/*********************************************************************************************************
** 函数名称: snmp_decode_truthvalue
** 功能描述: 把指定的 32 bit ASN1 数据转换成与其对应的 bool 类型值
** 输	 入: asn1_value - 32 bit ASN1 格式的数据指针
** 输	 出: bool_value - 转换后的 bool 类型值
**         : ERR_OK - 转换成功
**         : ERR_VAL - ASN1 格式数据错误
**         : ERR_ARG - 参数错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
err_t
snmp_decode_truthvalue(const s32_t *asn1_value, u8_t *bool_value)
{
  /* defined by RFC1443:
   TruthValue ::= TEXTUAL-CONVENTION
    STATUS       current
    DESCRIPTION
     "Represents a boolean value."
    SYNTAX       INTEGER { true(1), false(2) }
  */

  if ((asn1_value == NULL) || (bool_value == NULL)) {
    return ERR_ARG;
  }

  if (*asn1_value == 1) {
    *bool_value = 1;
  } else if (*asn1_value == 2) {
    *bool_value = 0;
  } else {
    return ERR_VAL;
  }

  return ERR_OK;
}

/**
 * Encodes BITS pseudotype value into ASN.1 OctetString.
 *
 * @note Because BITS pseudo type is encoded as OCTET STRING, it cannot directly
 * be encoded/decoded by the agent. Instead call this function as required from
 * get/test/set methods.
 *
 * @param buf points to a buffer where the resulting ASN1 octet string is stored to
 * @param buf_len max length of the bufffer
 * @param bit_value Bit value to encode with Bit0 == LSB
 * @param bit_count Number of possible bits for the bit value (according to rfc we have to send all bits independant from their truth value)
 * @return number of bytes used from buffer to store the resulting OctetString
 */
/*********************************************************************************************************
** 函数名称: snmp_encode_bits
** 功能描述: 把指定位数的 bit 数据转换成与其对应的 ASN1 格式数据存储到指定的缓冲区中，并返回转换后的
**         : ASN1 格式数据字节数
** 输	 入: buf_len - 用来存储转换结果的缓冲区长度
**         : bit_value - 需要转换的 bit 数据
**         : bit_count - 需要转换的 bit 位数
** 输	 出: buf - 转换后的 ASN1 格式数据
**         : len - 转换后的 ASN1 格式数据字节数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_encode_bits(u8_t *buf, u32_t buf_len, u32_t bit_value, u8_t bit_count)
{
  u8_t len = 0;
  u8_t min_bytes = (bit_count + 7) >> 3; /* >>3 -> / 8 */

  while ((buf_len > 0) && (bit_value != 0x00)) {

    /* 每次转换一个字节数据并存储到指定的缓冲区中 */
    s8_t i = 7;
    *buf = 0x00;
    while (i >= 0) {
      if (bit_value & 0x01) {
        *buf |= 0x01;
      }

      if (i > 0) {
        *buf <<= 1;
      }

      bit_value >>= 1;
      i--;
    }

    buf++;
    buf_len--;
    len++;
  }

  if (len < min_bytes) {
    buf     += len;
    buf_len -= len;

    while ((len < min_bytes) && (buf_len > 0)) {
      *buf = 0x00;
      buf++;
      buf_len--;
      len++;
    }
  }

  return len;
}

/*********************************************************************************************************
** 函数名称: snmp_encode_truthvalue
** 功能描述: 把指定的 bool 类型数据转换成与其对应的 ASN1 格式数据
** 输	 入: bool_value - 需要转换的 bool 类型数据
** 输	 出: asn1_value - 转换后的 ASN1 格式数据
**         : u8_t - 转换后的 ASN1 格式数据字节数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u8_t
snmp_encode_truthvalue(s32_t *asn1_value, u32_t bool_value)
{
  /* defined by RFC1443:
   TruthValue ::= TEXTUAL-CONVENTION
    STATUS       current
    DESCRIPTION
     "Represents a boolean value."
    SYNTAX       INTEGER { true(1), false(2) }
  */

  if (asn1_value == NULL) {
    return 0;
  }

  if (bool_value) {
    *asn1_value = 1; /* defined by RFC1443 */
  } else {
    *asn1_value = 2; /* defined by RFC1443 */
  }

  return sizeof(s32_t);
}

#endif /* LWIP_SNMP */
