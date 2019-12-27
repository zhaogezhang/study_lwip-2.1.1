/**
 * @file
 * SNMP server MIB API to implement thread synchronization
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
 * Author: Dirk Ziegelmeier <dziegel@gmx.de>
 *
 */

#ifndef LWIP_HDR_APPS_SNMP_THREADSYNC_H
#define LWIP_HDR_APPS_SNMP_THREADSYNC_H

#include "lwip/apps/snmp_opts.h"

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include "lwip/apps/snmp_core.h"
#include "lwip/sys.h"

typedef void (*snmp_threadsync_called_fn)(void* arg);
typedef void (*snmp_threadsync_synchronizer_fn)(snmp_threadsync_called_fn fn, void* arg);

/** Thread sync runtime data. For internal usage only. */
/* 表示 snmp 线程同步代理运行时数据 */
struct threadsync_data
{
  union {
    snmp_err_t err;
    s16_t s16;
  } retval;
  union {
    const u32_t *root_oid;
    void *value;
  } arg1;
  union {
    u8_t root_oid_len;
    u16_t len;
  } arg2;
  const struct snmp_threadsync_node *threadsync_node; /* 表示线程同步实例中的叶子节点数据 */
  struct snmp_node_instance proxy_instance;           /* 表示当前线程同步实例指向的被代理叶子节点实例 */
};

/** Thread sync instance. Needed EXCATLY once for every thread to be synced into. */
/* 表示 snmp 线程同步代理实例数据结构 */
struct snmp_threadsync_instance
{
  sys_sem_t                       sem;             /* 表示当前同步代理实例使用的同步信号量句柄 */
  sys_mutex_t                     sem_usage_mutex; /* 用来保护当前结构体的 sem 字段数据的互斥锁 */
  snmp_threadsync_synchronizer_fn sync_fn;         /* 表示当前同步代理实例使用的同步执行函数 */
  struct threadsync_data          data;            /* 表示当前同步代理实例使用的运行时数据 */
};

/** SNMP thread sync proxy leaf node */
/* 表示 snmp 线程同步代理叶子节点数据结构 */
struct snmp_threadsync_node
{
  /* inherited "base class" members */
  /* 为了实现基类继承功能，这个表示叶子节点的数据结构必须放在当前结构体的开始位置 */
  struct snmp_leaf_node           node;

  const struct snmp_leaf_node     *target;
  struct snmp_threadsync_instance *instance;
};

snmp_err_t snmp_threadsync_get_instance(const u32_t *root_oid, u8_t root_oid_len, struct snmp_node_instance* instance);
snmp_err_t snmp_threadsync_get_next_instance(const u32_t *root_oid, u8_t root_oid_len, struct snmp_node_instance* instance);

/** Create thread sync proxy node */
/* 通过指定的参数创建一个 snmp 线程同步代理实例叶子节点数据结构 */
#define SNMP_CREATE_THREAD_SYNC_NODE(oid, target_leaf_node, threadsync_instance) \
  {{{ SNMP_NODE_THREADSYNC, (oid) }, \
    snmp_threadsync_get_instance, \
    snmp_threadsync_get_next_instance }, \
    (target_leaf_node), \
    (threadsync_instance) }

/** Create thread sync instance data */
void snmp_threadsync_init(struct snmp_threadsync_instance *instance, snmp_threadsync_synchronizer_fn sync_fn);

#endif /* LWIP_SNMP */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_APPS_SNMP_THREADSYNC_H */
