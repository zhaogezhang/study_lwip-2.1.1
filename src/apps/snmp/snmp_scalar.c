/**
 * @file
 * SNMP scalar node support implementation.
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

#include "lwip/apps/snmp_scalar.h"
#include "lwip/apps/snmp_core.h"

static s16_t snmp_scalar_array_get_value(struct snmp_node_instance *instance, void *value);
static snmp_err_t  snmp_scalar_array_set_test(struct snmp_node_instance *instance, u16_t value_len, void *value);
static snmp_err_t  snmp_scalar_array_set_value(struct snmp_node_instance *instance, u16_t value_len, void *value);

/*********************************************************************************************************
** 函数名称: snmp_scalar_get_instance
** 功能描述: 根据函数指定参数获取指定的标量实例数据结构
** 输	 入: root_oid - 未使用
**         : root_oid_len - 未使用
**         : instance - 指定的标量信息
** 输	 出: instance - 需要实例化的标量实例指针
**         : SNMP_ERR_NOERROR - 初始化成功
**         : SNMP_ERR_NOSUCHINSTANCE - 变量实例的 oid 参数错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
snmp_err_t
snmp_scalar_get_instance(const u32_t *root_oid, u8_t root_oid_len, struct snmp_node_instance *instance)
{
  const struct snmp_scalar_node *scalar_node = (const struct snmp_scalar_node *)(const void *)instance->node;

  LWIP_UNUSED_ARG(root_oid);
  LWIP_UNUSED_ARG(root_oid_len);

  /* scalar only has one dedicated instance: .0 */
  /* 判断当前指定的标量实例 oid 数据是否合法（是否为 .0）*/
  if ((instance->instance_oid.len != 1) || (instance->instance_oid.id[0] != 0)) {
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  /* 根据当前指定的标量实例预填充的节点数据初始化当前标量实例的相关字段 */
  instance->access    = scalar_node->access;
  instance->asn1_type = scalar_node->asn1_type;
  instance->get_value = scalar_node->get_value;
  instance->set_test  = scalar_node->set_test;
  instance->set_value = scalar_node->set_value;
  return SNMP_ERR_NOERROR;
}

/*********************************************************************************************************
** 函数名称: snmp_scalar_get_next_instance
** 功能描述: 根据函数指定参数获取和当前指定标量实例相邻的下一个标量实例数据结构
** 输	 入: root_oid - 未使用
**         : root_oid_len - 未使用
**         : instance - 指定的标量信息
** 输	 出: instance - 需要实例化的标量实例指针
**         : SNMP_ERR_NOERROR - 初始化成功
**         : SNMP_ERR_NOSUCHINSTANCE - 变量实例的 oid 参数错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
snmp_err_t
snmp_scalar_get_next_instance(const u32_t *root_oid, u8_t root_oid_len, struct snmp_node_instance *instance)
{
  /* because our only instance is .0 we can only return a next instance if no instance oid is passed */
  /* 因为标量实例只有一个成员且实例 oid 为 .0，所以只有在函数参数未指定实例 oid 的时候，我们才返回这个标量实例 */
  if (instance->instance_oid.len == 0) {
    instance->instance_oid.len   = 1;
    instance->instance_oid.id[0] = 0;

    return snmp_scalar_get_instance(root_oid, root_oid_len, instance);
  }

  return SNMP_ERR_NOSUCHINSTANCE;
}

/*********************************************************************************************************
** 函数名称: snmp_scalar_array_get_instance
** 功能描述: 根据函数指定参数从指定的标量数组中获取指定的标量实例数据结构
** 输	 入: root_oid - 未使用
**         : root_id_len - 未使用
**         : instance - 指定的标量信息
** 输	 出: instance - 需要实例化的标量实例指针
**         : SNMP_ERR_NOERROR - 初始化成功
**         : SNMP_ERR_NOSUCHINSTANCE - 变量实例的 oid 参数错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
snmp_err_t
snmp_scalar_array_get_instance(const u32_t *root_oid, u8_t root_oid_len, struct snmp_node_instance *instance)
{
  LWIP_UNUSED_ARG(root_oid);
  LWIP_UNUSED_ARG(root_oid_len);

  /* 检查当前指定的标量数组节点的 oid 是否合法（长度是否为 2，且索引为 1 的 oid 数组成员值为 0）*/
  if ((instance->instance_oid.len == 2) && (instance->instance_oid.id[1] == 0)) {
  	
    const struct snmp_scalar_array_node *array_node = (const struct snmp_scalar_array_node *)(const void *)instance->node;
    const struct snmp_scalar_array_node_def *array_node_def = array_node->array_nodes;
    u32_t i = 0;

    /* 遍历当前指定的标量数组节点所有子节点，找到我们指定的 oid 的标量实例 */
    while (i < array_node->array_node_count) {

	  /* 如果当前遍历到的标量实例的 oid 和我们指定的 oid 相同，则表示找到了我们想要的标量实例 */
      if (array_node_def->oid == instance->instance_oid.id[0]) {
        break;
      }

      array_node_def++;
      i++;
    }

    /* 如果当前指定的标量数组中有我们指定的标量实例，则根据找到的标量实例初始化指定的目标实例数据结构 */
    if (i < array_node->array_node_count) {
      instance->access              = array_node_def->access;
      instance->asn1_type           = array_node_def->asn1_type;
      instance->get_value           = snmp_scalar_array_get_value;
      instance->set_test            = snmp_scalar_array_set_test;
      instance->set_value           = snmp_scalar_array_set_value;
      instance->reference.const_ptr = array_node_def;

      return SNMP_ERR_NOERROR;
    }
  }

  return SNMP_ERR_NOSUCHINSTANCE;
}

/*********************************************************************************************************
** 函数名称: snmp_scalar_array_get_next_instance
** 功能描述: 根据函数指定参数从指定的标量数组中获取和指定的 oid 最接近的标量实例数据结构
** 注     释: 1. 如果没有指定 oid 则返回指定的标量数组中 oid 最小的标量实例指针
**         : 2. 如果指定的 oid 长度为 1 则返回标量数组中 oid 等于我们指定的 oid 值的标量实例指针
**         : 3. 如果指定的 oid 长度大于 1 则返回标量数组中 oid 和我们指定的 oid 最接近的标量实例指针
** 输	 入: root_oid - 未使用
**         : root_id_len - 未使用
**         : instance - 指定的标量信息
** 输	 出: instance - 需要实例化的标量实例指针
**         : SNMP_ERR_NOERROR - 初始化成功
**         : SNMP_ERR_NOSUCHINSTANCE - 变量实例的 oid 参数错误
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
snmp_err_t
snmp_scalar_array_get_next_instance(const u32_t *root_oid, u8_t root_oid_len, struct snmp_node_instance *instance)
{
  const struct snmp_scalar_array_node *array_node = (const struct snmp_scalar_array_node *)(const void *)instance->node;
  const struct snmp_scalar_array_node_def *array_node_def = array_node->array_nodes;
  const struct snmp_scalar_array_node_def *result = NULL;

  LWIP_UNUSED_ARG(root_oid);
  LWIP_UNUSED_ARG(root_oid_len);

  /* 如果函数参数没有指定标量实例 oid，则返回当前标量数组中 oid 最小的标量实例指针 */
  if ((instance->instance_oid.len == 0) && (array_node->array_node_count > 0)) {
    /* return node with lowest OID */
    u16_t i = 0;

    result = array_node_def;
    array_node_def++;

    /* 遍历当前指定的标量数组下的每一个标量实例成员并记录 oid 值最小的标量实例指针 */
    for (i = 1; i < array_node->array_node_count; i++) {
      if (array_node_def->oid < result->oid) {
        result = array_node_def;
      }
      array_node_def++;
    }
	
  } else if (instance->instance_oid.len >= 1) {
  
    if (instance->instance_oid.len == 1) {
      /* if we have the requested OID we return its instance, otherwise we search for the next available */
      u16_t i = 0;

	  /* 如果指定的 oid 长度为 1, 则遍历当前指定的标量数组下的每一个标量实例成员
	     查找并记录 oid 等于我们指定的 oid 的标量实例指针 */
      while (i < array_node->array_node_count) {
        if (array_node_def->oid == instance->instance_oid.id[0]) {
          result = array_node_def;
          break;
        }

        array_node_def++;
        i++;
      }
    }

	/* 如果指定的 oid 长度大于 1, 则遍历当前指定的标量数组下的每一个标量实例成员
	   查找并记录 oid 和我们指定的 oid 最接近的标量实例指针 */
    if (result == NULL) {
      u32_t oid_dist = 0xFFFFFFFFUL;
      u16_t i        = 0;
      array_node_def = array_node->array_nodes; /* may be already at the end when if case before was executed without result -> reinitialize to start */

	  while (i < array_node->array_node_count) {
        if ((array_node_def->oid > instance->instance_oid.id[0]) &&
            ((u32_t)(array_node_def->oid - instance->instance_oid.id[0]) < oid_dist)) {
          result   = array_node_def;
          oid_dist = array_node_def->oid - instance->instance_oid.id[0];
        }

        array_node_def++;
        i++;
      }
    }
  }

  if (result == NULL) {
    /* nothing to return */
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  /* 根据查找到的标量实例信息实例化我们指定的标量实例数据结构 */
  instance->instance_oid.len   = 2;
  instance->instance_oid.id[0] = result->oid;
  instance->instance_oid.id[1] = 0;

  instance->access              = result->access;
  instance->asn1_type           = result->asn1_type;
  instance->get_value           = snmp_scalar_array_get_value;
  instance->set_test            = snmp_scalar_array_set_test;
  instance->set_value           = snmp_scalar_array_set_value;
  instance->reference.const_ptr = result;

  return SNMP_ERR_NOERROR;
}

/*********************************************************************************************************
** 函数名称: snmp_scalar_array_get_value
** 功能描述: 当前系统在获取标量数组成员值时使用的默认操作函数实现
** 输	 入: instance - 需要获取值的标量实例指针
** 输	 出: value - 成功获取的标量实例值
**         : result - 操作结果
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static s16_t
snmp_scalar_array_get_value(struct snmp_node_instance *instance, void *value)
{
  s16_t result = -1;
  const struct snmp_scalar_array_node *array_node = (const struct snmp_scalar_array_node *)(const void *)instance->node;
  const struct snmp_scalar_array_node_def *array_node_def = (const struct snmp_scalar_array_node_def *)instance->reference.const_ptr;

  if (array_node->get_value != NULL) {
    result = array_node->get_value(array_node_def, value);
  }
  return result;
}

/*********************************************************************************************************
** 函数名称: snmp_scalar_array_set_test
** 功能描述: 当前系统在测试设置标量数组成员值时使用的默认操作函数实现
** 输	 入: instance - 需要测试设置值的标量实例指针
**         : value_len - 需要设置值的长度
**         : value - 需要设置的值
** 输	 出: result - 操作结果
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static snmp_err_t
snmp_scalar_array_set_test(struct snmp_node_instance *instance, u16_t value_len, void *value)
{
  snmp_err_t result = SNMP_ERR_NOTWRITABLE;
  const struct snmp_scalar_array_node *array_node = (const struct snmp_scalar_array_node *)(const void *)instance->node;
  const struct snmp_scalar_array_node_def *array_node_def = (const struct snmp_scalar_array_node_def *)instance->reference.const_ptr;

  if (array_node->set_test != NULL) {
    result = array_node->set_test(array_node_def, value_len, value);
  }
  return result;
}

/*********************************************************************************************************
** 函数名称: snmp_scalar_array_set_value
** 功能描述: 当前系统在设置标量数组成员值时使用的默认操作函数实现
** 输	 入: instance - 需要设置值的标量实例指针
**         : value_len - 需要设置值的长度
**         : value - 需要设置的值
** 输	 出: result - 操作结果
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static snmp_err_t
snmp_scalar_array_set_value(struct snmp_node_instance *instance, u16_t value_len, void *value)
{
  snmp_err_t result = SNMP_ERR_NOTWRITABLE;
  const struct snmp_scalar_array_node *array_node = (const struct snmp_scalar_array_node *)(const void *)instance->node;
  const struct snmp_scalar_array_node_def *array_node_def = (const struct snmp_scalar_array_node_def *)instance->reference.const_ptr;

  if (array_node->set_value != NULL) {
    result = array_node->set_value(array_node_def, value_len, value);
  }
  return result;
}

#endif /* LWIP_SNMP */
