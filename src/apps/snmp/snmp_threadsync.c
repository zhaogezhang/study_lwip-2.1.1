/**
 * @file
 * SNMP thread synchronization implementation.
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
 * Author: Dirk Ziegelmeier <dziegel@gmx.de>
 */

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP && (NO_SYS == 0) /* don't build if not configured for use in lwipopts.h */

#include "lwip/apps/snmp_threadsync.h"
#include "lwip/apps/snmp_core.h"
#include "lwip/sys.h"
#include <string.h>

/*********************************************************************************************************
** 函数名称: call_synced_function
** 功能描述: 同步的执行指定的函数指针
** 注     释: 在调用这个函数之前，线程同步代理的运行时数据需要初始化完成
** 输	 入: call_data - 表示线程同步代理的运行时数据指针
**         : fn - 需要同步执行的函数指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
call_synced_function(struct threadsync_data *call_data, snmp_threadsync_called_fn fn)
{
  sys_mutex_lock(&call_data->threadsync_node->instance->sem_usage_mutex);

  /* 同步执行指定的函数指针并在执行完成后发送 call_data->threadsync_node->instance->sem 信号量 */
  call_data->threadsync_node->instance->sync_fn(fn, call_data);

  /* 等待指定的函数执行完成同步信号量 */
  sys_sem_wait(&call_data->threadsync_node->instance->sem);
  
  sys_mutex_unlock(&call_data->threadsync_node->instance->sem_usage_mutex);
}

/*********************************************************************************************************
** 函数名称: threadsync_get_value_synced
** 功能描述: 尝试在线程同步代理环境下同步的执行指定的代理实例的 proxy_instance.get_value 函数
**         : 读取这个实例对象的值
** 注     释: 在调用这个函数之前，线程同步代理的运行时数据需要初始化完成
** 输	 入: ctx - 表示线程同步代理的运行时数据指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
threadsync_get_value_synced(void *ctx)
{
  struct threadsync_data *call_data = (struct threadsync_data *)ctx;

  if (call_data->proxy_instance.get_value != NULL) {
    call_data->retval.s16 = call_data->proxy_instance.get_value(&call_data->proxy_instance, call_data->arg1.value);
  } else {
    call_data->retval.s16 = -1;
  }

  /* 通过信号量通知同步等待线程获取指定代理实例对象值的操作已经执行完成 */
  sys_sem_signal(&call_data->threadsync_node->instance->sem);
}

/*********************************************************************************************************
** 函数名称: threadsync_get_value
** 功能描述: 尝试通过线程同步代理实例的 proxy_instance.get_value 函数同步的读取这个代理实例对象的值
** 注     释: 在调用这个函数之前，线程同步代理的运行时数据需要初始化完成
** 输	 入: instance - 需要被代理的实例指针
**         : value - 用来存储成功获取到的值
** 输	 出: call_data->retval.s16 - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static s16_t
threadsync_get_value(struct snmp_node_instance *instance, void *value)
{
  struct threadsync_data *call_data = (struct threadsync_data *)instance->reference.ptr;

  call_data->arg1.value = value;
  call_synced_function(call_data, threadsync_get_value_synced);

  return call_data->retval.s16;
}

/*********************************************************************************************************
** 函数名称: threadsync_set_test_synced
** 功能描述: 尝试在线程同步代理环境下同步的执行指定的代理实例的 proxy_instance.set_test 函数
**         : 测试设置代理实例对象值操作是否合法
** 注     释: 在调用这个函数之前，线程同步代理的运行时数据需要初始化完成
** 输	 入: ctx - 表示线程同步代理的运行时数据指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
threadsync_set_test_synced(void *ctx)
{
  struct threadsync_data *call_data = (struct threadsync_data *)ctx;

  if (call_data->proxy_instance.set_test != NULL) {
    call_data->retval.err = call_data->proxy_instance.set_test(&call_data->proxy_instance, call_data->arg2.len, call_data->arg1.value);
  } else {
    call_data->retval.err = SNMP_ERR_NOTWRITABLE;
  }

  /* 通过信号量通知同步等待线程获取指定代理实例对象值的操作已经执行完成 */
  sys_sem_signal(&call_data->threadsync_node->instance->sem);
}

/*********************************************************************************************************
** 函数名称: threadsync_set_test
** 功能描述: 尝试通过线程同步代理实例的 proxy_instance.set_test 函数同步的测试设置代理实例对象值
**         : 操作是否合法
** 注     释: 在调用这个函数之前，线程同步代理的运行时数据需要初始化完成
** 输	 入: instance - 需要被代理的实例指针
**         : len - 需要设置的值长度
**         : value - 需要设置的值
** 输	 出: snmp_err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static snmp_err_t
threadsync_set_test(struct snmp_node_instance *instance, u16_t len, void *value)
{
  struct threadsync_data *call_data = (struct threadsync_data *)instance->reference.ptr;

  call_data->arg1.value = value;
  call_data->arg2.len = len;
  call_synced_function(call_data, threadsync_set_test_synced);

  return call_data->retval.err;
}

/*********************************************************************************************************
** 函数名称: threadsync_set_value_synced
** 功能描述: 尝试在线程同步代理环境下同步的执行指定的代理实例的 proxy_instance.set_value 函数
**         : 设置代理实例对象值
** 注     释: 在调用这个函数之前，线程同步代理的运行时数据需要初始化完成
** 输	 入: ctx - 表示线程同步代理的运行时数据指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
threadsync_set_value_synced(void *ctx)
{
  struct threadsync_data *call_data = (struct threadsync_data *)ctx;

  if (call_data->proxy_instance.set_value != NULL) {
    call_data->retval.err = call_data->proxy_instance.set_value(&call_data->proxy_instance, call_data->arg2.len, call_data->arg1.value);
  } else {
    call_data->retval.err = SNMP_ERR_NOTWRITABLE;
  }
  
  /* 通过信号量通知同步等待线程获取指定代理实例对象值的操作已经执行完成 */
  sys_sem_signal(&call_data->threadsync_node->instance->sem);
}

/*********************************************************************************************************
** 函数名称: threadsync_set_value
** 功能描述: 尝试通过线程同步代理实例的 proxy_instance.set_value 函数同步的设置代理实例对象值
** 注     释: 在调用这个函数之前，线程同步代理的运行时数据需要初始化完成
** 输	 入: instance - 需要被代理的实例指针
**         : len - 需要设置的值长度
**         : value - 需要设置的值
** 输	 出: snmp_err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static snmp_err_t
threadsync_set_value(struct snmp_node_instance *instance, u16_t len, void *value)
{
  struct threadsync_data *call_data = (struct threadsync_data *)instance->reference.ptr;

  call_data->arg1.value = value;
  call_data->arg2.len = len;
  call_synced_function(call_data, threadsync_set_value_synced);

  return call_data->retval.err;
}

/*********************************************************************************************************
** 函数名称: threadsync_release_instance_synced
** 功能描述: 尝试在线程同步代理环境下同步的执行指定的代理实例的 proxy_instance.release_instance 函数
**         : 释放指定的代理实例对象
** 注     释: 在调用这个函数之前，线程同步代理的运行时数据需要初始化完成
** 输	 入: ctx - 表示线程同步代理的运行时数据指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
threadsync_release_instance_synced(void *ctx)
{
  struct threadsync_data *call_data = (struct threadsync_data *)ctx;

  call_data->proxy_instance.release_instance(&call_data->proxy_instance);

  /* 通过信号量通知同步等待线程获取指定代理实例对象值的操作已经执行完成 */
  sys_sem_signal(&call_data->threadsync_node->instance->sem);
}

/*********************************************************************************************************
** 函数名称: threadsync_release_instance
** 功能描述: 尝试通过线程同步代理实例的 proxy_instance.release_instance 函数同步的释放代理实例对象
** 注     释: 在调用这个函数之前，线程同步代理的运行时数据需要初始化完成
** 输	 入: instance - 需要释放的代理实例指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
threadsync_release_instance(struct snmp_node_instance *instance)
{
  struct threadsync_data *call_data = (struct threadsync_data *)instance->reference.ptr;

  if (call_data->proxy_instance.release_instance != NULL) {
    call_synced_function(call_data, threadsync_release_instance_synced);
  }
}

/*********************************************************************************************************
** 函数名称: get_instance_synced
** 功能描述: 尝试在线程同步代理环境下同步的执行指定的代理实例的 proxy_instance.node.get_instance 函数
**         : 获取指定的代理实例对象并把实例对象数据存储到 call_data->proxy_instance 中
** 注     释: 在调用这个函数之前，线程同步代理的运行时数据需要初始化完成
** 输	 入: instance - 需要释放的代理实例指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
get_instance_synced(void *ctx)
{
  struct threadsync_data *call_data   = (struct threadsync_data *)ctx;
  const struct snmp_leaf_node *leaf   = (const struct snmp_leaf_node *)(const void *)call_data->proxy_instance.node;

  call_data->retval.err = leaf->get_instance(call_data->arg1.root_oid, call_data->arg2.root_oid_len, &call_data->proxy_instance);

  /* 通过信号量通知同步等待线程获取指定代理实例对象值的操作已经执行完成 */
  sys_sem_signal(&call_data->threadsync_node->instance->sem);
}

/*********************************************************************************************************
** 函数名称: get_instance_synced
** 功能描述: 尝试在线程同步代理环境下同步的执行指定的代理实例的 proxy_instance.node.get_next_instance
**         : 函数获取指定的代理实例对象并把实例对象数据存储到 call_data->proxy_instance 中
** 注     释: 在调用这个函数之前，线程同步代理的运行时数据需要初始化完成
** 输	 入: ctx - 表示线程同步代理的运行时数据指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
get_next_instance_synced(void *ctx)
{
  struct threadsync_data *call_data   = (struct threadsync_data *)ctx;
  const struct snmp_leaf_node *leaf   = (const struct snmp_leaf_node *)(const void *)call_data->proxy_instance.node;

  call_data->retval.err = leaf->get_next_instance(call_data->arg1.root_oid, call_data->arg2.root_oid_len, &call_data->proxy_instance);

  /* 通过信号量通知同步等待线程获取指定代理实例对象值的操作已经执行完成 */
  sys_sem_signal(&call_data->threadsync_node->instance->sem);
}

/*********************************************************************************************************
** 函数名称: do_sync
** 功能描述: 根据指定的运行时数据同步的执行指定的函数指针，然后根据执行结果初始化指定的叶子节点实例
** 输	 入: root_oid - 需要代理的实例的根 oid 数据指针
**         : root_oid_len - 需要代理的实例的根 oid 数据长度
**         : instance - 需要初始化的叶子节点实例指针
**         : fn - 需要同步执行的函数指针
** 输	 出: snmp_err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static snmp_err_t
do_sync(const u32_t *root_oid, u8_t root_oid_len, struct snmp_node_instance *instance, snmp_threadsync_called_fn fn)
{
  /* 表示需要被代理的叶子节点实例指针 */
  const struct snmp_threadsync_node *threadsync_node = (const struct snmp_threadsync_node *)(const void *)instance->node;

  /* 表示当前同步代理实例使用的运行时数据 */
  struct threadsync_data *call_data = &threadsync_node->instance->data;

  if (threadsync_node->node.node.oid != threadsync_node->target->node.oid) {
    LWIP_DEBUGF(SNMP_DEBUG, ("Sync node OID does not match target node OID"));
    return SNMP_ERR_NOSUCHINSTANCE;
  }

  /* 初始化当前线程同步代理实例的运行时数据结构 */
  memset(&call_data->proxy_instance, 0, sizeof(call_data->proxy_instance));

  instance->reference.ptr = call_data;
  snmp_oid_assign(&call_data->proxy_instance.instance_oid, instance->instance_oid.id, instance->instance_oid.len);

  call_data->proxy_instance.node = &threadsync_node->target->node;
  call_data->threadsync_node     = threadsync_node;

  call_data->arg1.root_oid       = root_oid;
  call_data->arg2.root_oid_len   = root_oid_len;

  /* 同步的执行指定的函数获取指定的代理实例对象并把实例对象数据存储到 call_data->proxy_instance 中 */
  call_synced_function(call_data, fn);

  /* 根据同步获取到的代理实例对象数据初始化指定的叶子节点实例数据结构 */
  if (call_data->retval.err == SNMP_ERR_NOERROR) {
    instance->access           = call_data->proxy_instance.access;
    instance->asn1_type        = call_data->proxy_instance.asn1_type;
    instance->release_instance = threadsync_release_instance;
    instance->get_value        = (call_data->proxy_instance.get_value != NULL) ? threadsync_get_value : NULL;
    instance->set_value        = (call_data->proxy_instance.set_value != NULL) ? threadsync_set_value : NULL;
    instance->set_test         = (call_data->proxy_instance.set_test != NULL) ?  threadsync_set_test  : NULL;
    snmp_oid_assign(&instance->instance_oid, call_data->proxy_instance.instance_oid.id, call_data->proxy_instance.instance_oid.len);
  }

  return call_data->retval.err;
}

/*********************************************************************************************************
** 函数名称: snmp_threadsync_get_instance
** 功能描述: 根据指定的函数参数同步的执行 get_instance_synced 函数并把获取到的同步代理实例对象
**         : 数据设置到指定的叶子节点实例
** 输	 入: root_oid - 需要代理的实例的根 oid 数据指针
**         : root_oid_len - 需要代理的实例的根 oid 数据长度
**         : instance - 需要初始化的叶子节点实例指针
** 输	 出: snmp_err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
snmp_err_t
snmp_threadsync_get_instance(const u32_t *root_oid, u8_t root_oid_len, struct snmp_node_instance *instance)
{
  return do_sync(root_oid, root_oid_len, instance, get_instance_synced);
}

/*********************************************************************************************************
** 函数名称: snmp_threadsync_get_instance
** 功能描述: 根据指定的函数参数同步的执行 get_next_instance_synced 函数并把获取到的同步代理实例对象
**         : 数据设置到指定的叶子节点实例
** 输	 入: root_oid - 需要代理的实例的根 oid 数据指针
**         : root_oid_len - 需要代理的实例的根 oid 数据长度
**         : instance - 需要初始化的叶子节点实例指针
** 输	 出: snmp_err_t - 操作状态
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
snmp_err_t
snmp_threadsync_get_next_instance(const u32_t *root_oid, u8_t root_oid_len, struct snmp_node_instance *instance)
{
  return do_sync(root_oid, root_oid_len, instance, get_next_instance_synced);
}

/** Initializes thread synchronization instance */
/*********************************************************************************************************
** 函数名称: snmp_threadsync_init
** 功能描述: 初始化指定的同步代理实例
** 注     释: static void  sync_fn (snmp_threadsync_called_fn  pfunc, void*  pvArg)
**         : {
**         :     if (pfunc) {
**         :         pfunc(pvArg);
**         :     }
**         : }
** 输	 入: instance - 需要初始化的同步代理实例指针
**         : sync_fn - 指定的同步代理实例的同步函数
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void snmp_threadsync_init(struct snmp_threadsync_instance *instance, snmp_threadsync_synchronizer_fn sync_fn)
{
  err_t err = sys_mutex_new(&instance->sem_usage_mutex);
  LWIP_ASSERT("Failed to set up mutex", err == ERR_OK);
  err = sys_sem_new(&instance->sem, 0);
  LWIP_UNUSED_ARG(err); /* in case of LWIP_NOASSERT */
  LWIP_ASSERT("Failed to set up semaphore", err == ERR_OK);
  instance->sync_fn = sync_fn;
}

#endif /* LWIP_SNMP */
