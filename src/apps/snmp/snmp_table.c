/**
 * @file
 * SNMP table support implementation.
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
/* SNMP Table Basics:
 * An SNMP table can be defined as an ordered collection of objects consisting of zero or more rows. 
 * Each row may contain one or more objects. Each object in a table is identified using the table index. 
 * A table can have a single index or multiple indices.
 *
 * A scalar variable has a single instance and is identified by its ".0". On the other hand, a table 
 * object or the columnar variable can have one or more instances and is identified by its index value. 
 * To identify a specific columnar variable, the index of the row has to be appended to its OID.
 * 
 * For example for a table with OID .1.3.6.1.2.1.x.x.xTable, with the column name yy and the index value 
 * ind1, the value of the column yy can be got by appending the instance ind1 to the columnar OID 
 * .1.3.6.1.2.1.x.x.xTable.xEntry.yy. If the table has multiple indices namely ind1 and ind2 then the 
 * value of the column yy can be got by using the OID .1.3.6.1.2.1.x.x.xTable.xEntry.yy.ind1.ind2.
 *
 * For example, consider tcpConnTable. It has four indices namely tcpConnLocalAddress, tcpConnLocalPort, 
 * tcpConnRemAddress, and tcpConnRemPort where the values of the table are as follows.
 * 
 * +---------------------------------------------------------------------------------------------+
 * |  tcpConnState  | tcpConnLocalAddress | tcpConnLocaPort | tcpConnRemAddress | tcpConnRemPort |
 * +----------------+---------------------+-----------------+-------------------+----------------+
 * |    listen(2)   |       0.0.0.0       |       21        |     0.0.0.0       |       0        |
 * +----------------+---------------------+-----------------+-------------------+----------------+
 * |    listen(2)   |       0.0.0.0       |       23        |     0.0.0.0       |       0        |
 * +----------------+---------------------+-----------------+-------------------+----------------+
 * |    listen(2)   |       0.0.0.0       |      3306       |     0.0.0.0       |       0        |
 * +----------------+---------------------+-----------------+-------------------+----------------+
 * |    listen(2)   |       0.0.0.0       |      6000       |     0.0.0.0       |       0        |
 * +----------------+---------------------+-----------------+-------------------+----------------+
 * | established(5) |      127.0.0.1      |      1042       |    127.0.0.1      |      6000      |
 * +----------------+---------------------+-----------------+-------------------+----------------+
 * | established(5) |      127.0.0.1      |      6000       |    127.0.0.1      |      1042      |
 * +----------------+---------------------+-----------------+-------------------+----------------+
 * |  closeWait(8)  |     192.168.1.78    |      1156       |   192.168.4.144   |       80       |
 * +----------------+---------------------+-----------------+-------------------+----------------+
 * 
 * To get the value of the column tcpConnState for the last row, you have to query with the OID 
 * tcpConnState.192.168.1.78.1156.192.168.4.144.80 where 192.168.1.78 is the value of tcpConnLocalAddress 
 * for the last row, 1156 is the value of tcpConnLocalPort for the last row 192.168.4.144 is the value of 
 * tcpConnRemAddress for the last row 80 is the value of tcpConnRemPort for the last row.
 *
 * Also if the index is of integer type, it can be in any order. For example in a table, if the values of 
 * the index column are {1,2,3,4}, it can have values in any order say {2,4,3,1}.
 */
 
#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include "lwip/apps/snmp_core.h"
#include "lwip/apps/snmp_table.h"
#include <string.h>

/*********************************************************************************************************
** 函数名称: snmp_table_get_instance
** 功能描述: 根据函数指定列索引值获取匹配的表格实例数据结构
** 注     释: 在对 snmp 表格实例对象操作时，实例 oid 分配规则如下：
**         : instance_oid.id[0] == 1
**         : instance_oid.id[1] 表示要操作的表格实例列索引值
**         : instance_oid.id[2] --- instance_oid.id[n] 表示要操作的表格实例行 oid
** 输	 入: root_oid - 未使用
**         : root_oid_len - 未使用
**         : instance - 指定的表格信息
** 输	 出: instance - 需要实例化的表格实例指针
**         : SNMP_ERR_NOERROR - 初始化成功
**         : SNMP_ERR_NOSUCHINSTANCE - 操作失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
snmp_err_t snmp_table_get_instance(const u32_t *root_oid, u8_t root_oid_len, struct snmp_node_instance *instance)
{
  snmp_err_t ret = SNMP_ERR_NOSUCHINSTANCE;
  const struct snmp_table_node *table_node = (const struct snmp_table_node *)(const void *)instance->node;

  LWIP_UNUSED_ARG(root_oid);
  LWIP_UNUSED_ARG(root_oid_len);

  /* check min. length (fixed row entry definition, column, row instance oid with at least one entry */
  /* fixed row entry always has oid 1 */
  /* 检验函数指定的表格实例 oid 是否合法（oid 长度大于等于 3，oid 数组索引为 0 的数值为 1）*/
  if ((instance->instance_oid.len >= 3) && (instance->instance_oid.id[0] == 1)) {
  	
    /* search column */
    const struct snmp_table_col_def *col_def = table_node->columns;
    u16_t i = table_node->column_count;

	/* 遍历当前表格实例所有列信息，找到索引值和我们指定的索引值相同的列指针 */
    while (i > 0) {
      if (col_def->index == instance->instance_oid.id[1]) {
        break;
      }

      col_def++;
      i--;
    }

    /* 根据获取到的数据初始化指定的表格实例数据结构 */
    if (i > 0) {
      /* everything may be overwritten by get_cell_instance_method() in order to implement special handling for single columns/cells */
      instance->asn1_type = col_def->asn1_type;
      instance->access    = col_def->access;
      instance->get_value = table_node->get_value;
      instance->set_test  = table_node->set_test;
      instance->set_value = table_node->set_value;

      ret = table_node->get_cell_instance(
              &(instance->instance_oid.id[1]),
              &(instance->instance_oid.id[2]),
              instance->instance_oid.len - 2,
              instance);
    }
  }

  return ret;
}

/*********************************************************************************************************
** 函数名称: snmp_table_get_next_instance
** 功能描述: 根据函数指定参数获取和当前指定表格实例索引值相邻的下一个表格实例数据结构
** 注     释: 如果表格列索引值等于我们指定的列索引值则直接返回这个列数据，否则以列索引值为键值
**         : 按照升序方式查找并返回和指定列索引值最接近的列数据
**         : 在对 snmp 表格实例对象操作时，实例 oid 分配规则如下：
**         : instance_oid.id[0] == 1
**         : instance_oid.id[1] 表示要操作的表格实例列索引值
**         : instance_oid.id[2] --- instance_oid.id[n] 表示要操作的表格实例行 oid
** 输	 入: root_oid - 未使用
**         : root_oid_len - 未使用
**         : instance - 指定的表格信息
** 输	 出: instance - 需要实例化的表格实例指针
**         : SNMP_ERR_NOERROR - 初始化成功
**         : SNMP_ERR_NOSUCHINSTANCE - 变量实例的 oid 参数错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
snmp_err_t snmp_table_get_next_instance(const u32_t *root_oid, u8_t root_oid_len, struct snmp_node_instance *instance)
{
  const struct snmp_table_node *table_node = (const struct snmp_table_node *)(const void *)instance->node;
  const struct snmp_table_col_def *col_def;
  struct snmp_obj_id row_oid;
  u32_t column = 0;
  snmp_err_t result;

  LWIP_UNUSED_ARG(root_oid);
  LWIP_UNUSED_ARG(root_oid_len);

  /* check that first part of id is 0 or 1, referencing fixed row entry */
  /* 校验指定的表格实例 oid 是否合法（长度大于 0 且 oid 数组索引为 0 位置处的值大于 1 表示非法）*/
  if ((instance->instance_oid.len > 0) && (instance->instance_oid.id[0] > 1)) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  /* 如果指定的表格实例 oid 长度大于 1 则 oid 数组索引值为 1 位置处的值表示表格实例的列索引值 */
  if (instance->instance_oid.len > 1) {
    column = instance->instance_oid.id[1];
  }

  /* 如果指定的表格实例 oid 长度大于 2 则从 oid 数组索引值为 2 位置处开始的 oid 数据是表格实例的行 oid 数值 */
  if (instance->instance_oid.len > 2) {
    snmp_oid_assign(&row_oid, &(instance->instance_oid.id[2]), instance->instance_oid.len - 2);
  } else {
    row_oid.len = 0;
  }

  /* 根据函数参数指定的函数指针初始化当前表格实例的对象操作函数指针 */
  instance->get_value    = table_node->get_value;
  instance->set_test     = table_node->set_test;
  instance->set_value    = table_node->set_value;

  /* resolve column and value */
  do {
    u16_t i;
    const struct snmp_table_col_def *next_col_def = NULL;
    col_def = table_node->columns;

    /* 遍历函数参数指定的表格实例的每一列数据，如果遍历的表格列索引值等于我们指定的列索引值则直接
	   返回这个列数据，否则以列索引值为键值按照升序方式查找并返回和指定列索引值最接近的列数据 */
    for (i = 0; i < table_node->column_count; i++) {
      if (col_def->index == column) {
        next_col_def = col_def;
        break;
      } else if ((col_def->index > column) && ((next_col_def == NULL) || (col_def->index < next_col_def->index))) {
        next_col_def = col_def;
      }
      col_def++;
    }

    if (next_col_def == NULL) {
      /* no further column found */
      return SNMP_ERR_NOSUCHINSTANCE;
    }

    instance->asn1_type          = next_col_def->asn1_type;
    instance->access             = next_col_def->access;

    result = table_node->get_next_cell_instance(
               &next_col_def->index,
               &row_oid,
               instance);

    if (result == SNMP_ERR_NOERROR) {
      col_def = next_col_def;
      break;
    }

    row_oid.len = 0; /* reset row_oid because we switch to next column and start with the first entry there */
    column = next_col_def->index + 1;
  } while (1);

  /* build resulting oid */
  /* 根据查找到的列信息初始化指定的表格实例数据结构 */
  instance->instance_oid.len   = 2;
  instance->instance_oid.id[0] = 1;
  instance->instance_oid.id[1] = col_def->index;
  snmp_oid_append(&instance->instance_oid, row_oid.id, row_oid.len);

  return SNMP_ERR_NOERROR;
}

/*********************************************************************************************************
** 函数名称: snmp_table_simple_get_instance
** 功能描述: 根据函数指定列索引值获取匹配的简单表格实例数据结构
** 注     释: 在对 snmp 表格实例对象操作时，实例 oid 分配规则如下：
**         : instance_oid.id[0] == 1
**         : instance_oid.id[1] 表示要操作的表格实例列索引值
**         : instance_oid.id[2] --- instance_oid.id[n] 表示要操作的表格实例行 oid
** 输	 入: root_oid - 未使用
**         : root_oid_len - 未使用
**         : instance - 指定的表格信息
** 输	 出: instance - 需要实例化的简单表格实例指针
**         : SNMP_ERR_NOERROR - 初始化成功
**         : SNMP_ERR_NOSUCHINSTANCE - 获取失败
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
snmp_err_t snmp_table_simple_get_instance(const u32_t *root_oid, u8_t root_oid_len, struct snmp_node_instance *instance)
{
  snmp_err_t ret = SNMP_ERR_NOSUCHINSTANCE;
  const struct snmp_table_simple_node *table_node = (const struct snmp_table_simple_node *)(const void *)instance->node;

  LWIP_UNUSED_ARG(root_oid);
  LWIP_UNUSED_ARG(root_oid_len);

  /* check min. length (fixed row entry definition, column, row instance oid with at least one entry */
  /* fixed row entry always has oid 1 */  
  /* 检验函数指定的表格实例 oid 是否合法（oid 长度大于等于 3，oid 数组索引为 0 的数值为 1）*/
  if ((instance->instance_oid.len >= 3) && (instance->instance_oid.id[0] == 1)) {
  	
    ret = table_node->get_cell_value(
            &(instance->instance_oid.id[1]),
            &(instance->instance_oid.id[2]),
            instance->instance_oid.len - 2,
            &instance->reference,
            &instance->reference_len);

    if (ret == SNMP_ERR_NOERROR) {
		
      /* search column */
      const struct snmp_table_simple_col_def *col_def = table_node->columns;
      u32_t i = table_node->column_count;

      /* 遍历指定的表格实例列信息查找并返回列索引值和我们指定的列索引值匹配的列信息 */	
      while (i > 0) {
        if (col_def->index == instance->instance_oid.id[1]) {
          break;
        }

        col_def++;
        i--;
      }

      /* 如果在指定的表格实例中找到了索引值匹配的列信息，则根据找到的列信息初始化我们指定的表格实例数据结构 */
      if (i > 0) {
        instance->asn1_type = col_def->asn1_type;
        instance->access    = SNMP_NODE_INSTANCE_READ_ONLY;
        instance->set_test  = NULL;
        instance->set_value = NULL;

        switch (col_def->data_type) {
          case SNMP_VARIANT_VALUE_TYPE_U32:
            instance->get_value = snmp_table_extract_value_from_u32ref;
            break;
          case SNMP_VARIANT_VALUE_TYPE_S32:
            instance->get_value = snmp_table_extract_value_from_s32ref;
            break;
          case SNMP_VARIANT_VALUE_TYPE_PTR: /* fall through */
          case SNMP_VARIANT_VALUE_TYPE_CONST_PTR:
            instance->get_value = snmp_table_extract_value_from_refconstptr;
            break;
          default:
            LWIP_DEBUGF(SNMP_DEBUG, ("snmp_table_simple_get_instance(): unknown column data_type: %d\n", col_def->data_type));
            return SNMP_ERR_GENERROR;
        }

        ret = SNMP_ERR_NOERROR;
      } else {
        ret = SNMP_ERR_NOSUCHINSTANCE;
      }
    }
  }

  return ret;
}

/*********************************************************************************************************
** 函数名称: snmp_table_simple_get_next_instance
** 功能描述: 根据函数指定参数获取和当前指定简答表格实例索引值相邻的下一个简答表格实例数据结构
** 注     释: 如果简答表格列索引值等于我们指定的简答列索引值则直接返回这个列数据，否则以列索引值为键值
**         : 按照升序方式查找并返回和指定列索引值最接近的列数据
**         : 在对 snmp 表格实例对象操作时，实例 oid 分配规则如下：
**         : instance_oid.id[0] == 1
**         : instance_oid.id[1] 表示要操作的表格实例列索引值
**         : instance_oid.id[2] --- instance_oid.id[n] 表示要操作的表格实例行 oid
** 输	 入: root_oid - 未使用
**         : root_oid_len - 未使用
**         : instance - 指定的简答表格信息
** 输	 出: instance - 需要实例化的简单表格实例指针
**         : SNMP_ERR_NOERROR - 初始化成功
**         : SNMP_ERR_NOSUCHINSTANCE - 变量实例的 oid 参数错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
snmp_err_t snmp_table_simple_get_next_instance(const u32_t *root_oid, u8_t root_oid_len, struct snmp_node_instance *instance)
{
  const struct snmp_table_simple_node *table_node = (const struct snmp_table_simple_node *)(const void *)instance->node;
  const struct snmp_table_simple_col_def *col_def;
  struct snmp_obj_id row_oid;
  u32_t column = 0;
  snmp_err_t result;

  LWIP_UNUSED_ARG(root_oid);
  LWIP_UNUSED_ARG(root_oid_len);

  /* check that first part of id is 0 or 1, referencing fixed row entry */  
  /* 校验指定的表格实例 oid 是否合法（长度大于 0 且 oid 数组索引为 0 位置处的值大于 1 表示非法）*/
  if ((instance->instance_oid.len > 0) && (instance->instance_oid.id[0] > 1)) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }
  
  /* 如果指定的表格实例 oid 长度大于 1 则 oid 数组索引值为 1 位置处的值表示表格实例的列索引值 */
  if (instance->instance_oid.len > 1) {
    column = instance->instance_oid.id[1];
  }
  
  /* 如果指定的表格实例 oid 长度大于 2 则从 oid 数组索引值为 2 位置处开始的 oid 数据是表格实例的行 oid 数值 */
  if (instance->instance_oid.len > 2) {
    snmp_oid_assign(&row_oid, &(instance->instance_oid.id[2]), instance->instance_oid.len - 2);
  } else {
    row_oid.len = 0;
  }

  /* resolve column and value */
  do {
    u32_t i;
    const struct snmp_table_simple_col_def *next_col_def = NULL;
    col_def = table_node->columns;

    /* 遍历函数参数指定的表格实例的每一列数据，如果遍历的表格列索引值等于我们指定的列索引值则直接
	   返回这个列数据，否则以列索引值为键值按照升序方式查找并返回和指定列索引值最接近的列数据 */
    for (i = 0; i < table_node->column_count; i++) {
      if (col_def->index == column) {
        next_col_def = col_def;
        break;
      } else if ((col_def->index > column) && ((next_col_def == NULL) ||
                 (col_def->index < next_col_def->index))) {
        next_col_def = col_def;
      }
      col_def++;
    }

    if (next_col_def == NULL) {
      /* no further column found */
      return SNMP_ERR_NOSUCHINSTANCE;
    }

    result = table_node->get_next_cell_instance_and_value(
               &next_col_def->index,
               &row_oid,
               &instance->reference,
               &instance->reference_len);

    if (result == SNMP_ERR_NOERROR) {
      col_def = next_col_def;
      break;
    }

    row_oid.len = 0; /* reset row_oid because we switch to next column and start with the first entry there */
    column = next_col_def->index + 1;
  } while (1);

  /* 根据查找到的列信息初始化指定的简单表格实例数据结构 */
  instance->asn1_type = col_def->asn1_type;
  instance->access    = SNMP_NODE_INSTANCE_READ_ONLY;
  instance->set_test  = NULL;
  instance->set_value = NULL;

  switch (col_def->data_type) {
    case SNMP_VARIANT_VALUE_TYPE_U32:
      instance->get_value = snmp_table_extract_value_from_u32ref;
      break;
    case SNMP_VARIANT_VALUE_TYPE_S32:
      instance->get_value = snmp_table_extract_value_from_s32ref;
      break;
    case SNMP_VARIANT_VALUE_TYPE_PTR: /* fall through */
    case SNMP_VARIANT_VALUE_TYPE_CONST_PTR:
      instance->get_value = snmp_table_extract_value_from_refconstptr;
      break;
    default:
      LWIP_DEBUGF(SNMP_DEBUG, ("snmp_table_simple_get_instance(): unknown column data_type: %d\n", col_def->data_type));
      return SNMP_ERR_GENERROR;
  }

  /* build resulting oid */
  instance->instance_oid.len   = 2;
  instance->instance_oid.id[0] = 1;
  instance->instance_oid.id[1] = col_def->index;
  snmp_oid_append(&instance->instance_oid, row_oid.id, row_oid.len);

  return SNMP_ERR_NOERROR;
}

/*********************************************************************************************************
** 函数名称: snmp_table_extract_value_from_s32ref
** 功能描述: 当前系统在获取指定简单表格实例成员值（signed 32 bit）时使用的默认操作函数实现
** 输	 入: instance - 指定的简单表格实例指针
** 输	 出: value - 存储获取到的简单表格实例成员值（signed 32 bit）
**         : s16_t - 表示获取到的数据长度字节数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
s16_t
snmp_table_extract_value_from_s32ref(struct snmp_node_instance *instance, void *value)
{
  s32_t *dst = (s32_t *)value;
  *dst = instance->reference.s32;
  return sizeof(*dst);
}

/*********************************************************************************************************
** 函数名称: snmp_table_extract_value_from_u32ref
** 功能描述: 当前系统在获取指定简单表格实例成员值（unsigned 32 bit）时使用的默认操作函数实现
** 输	 入: instance - 指定的简单表格实例指针
** 输	 出: value - 存储获取到的简单表格实例成员值（unsigned 32 bit）
**         : s16_t - 表示获取到的数据长度字节数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
s16_t
snmp_table_extract_value_from_u32ref(struct snmp_node_instance *instance, void *value)
{
  u32_t *dst = (u32_t *)value;
  *dst = instance->reference.u32;
  return sizeof(*dst);
}

/*********************************************************************************************************
** 函数名称: snmp_table_extract_value_from_refconstptr
** 功能描述: 当前系统在获取指定简单表格实例成员值（point buf）时使用的默认操作函数实现
** 输	 入: instance - 指定的简单表格实例指针
** 输	 出: value - 存储获取到的简单表格实例成员值（point buf）
**         : s16_t - 表示获取到的数据长度字节数
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
s16_t
snmp_table_extract_value_from_refconstptr(struct snmp_node_instance *instance, void *value)
{
  MEMCPY(value, instance->reference.const_ptr, instance->reference_len);
  return (u16_t)instance->reference_len;
}

#endif /* LWIP_SNMP */
