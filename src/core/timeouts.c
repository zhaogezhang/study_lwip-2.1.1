/**
 * @file
 * Stack-internal timers implementation.
 * This file includes timer callbacks for stack-internal timers as well as
 * functions to set up or stop timers and check for expired timers.
 *
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
 *         Simon Goldschmidt
 *
 */

#include "lwip/opt.h"

#include "lwip/timeouts.h"
#include "lwip/priv/tcp_priv.h"

#include "lwip/def.h"
#include "lwip/memp.h"
#include "lwip/priv/tcpip_priv.h"

#include "lwip/ip4_frag.h"
#include "lwip/etharp.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"
#include "lwip/igmp.h"
#include "lwip/dns.h"
#include "lwip/nd6.h"
#include "lwip/ip6_frag.h"
#include "lwip/mld6.h"
#include "lwip/dhcp6.h"
#include "lwip/sys.h"
#include "lwip/pbuf.h"

#if LWIP_DEBUG_TIMERNAMES
#define HANDLER(x) x, #x
#else /* LWIP_DEBUG_TIMERNAMES */
#define HANDLER(x) x
#endif /* LWIP_DEBUG_TIMERNAMES */

#define LWIP_MAX_TIMEOUT  0x7fffffff

/* Check if timer's expiry time is greater than time and care about u32_t wraparounds */
/* 比较指定的时间 t 是否小于指定的时间 compare_to，返回 1 表示时间 t 小于 compare_to，返回 0 表示时间 t 不小于 compare_to */
#define TIME_LESS_THAN(t, compare_to) ( (((u32_t)((t)-(compare_to))) > LWIP_MAX_TIMEOUT) ? 1 : 0 )

/** This array contains all stack-internal cyclic timers. To get the number of
 * timers, use LWIP_ARRAYSIZE() */
/* 定义当前协议栈中使用的所有软件周期循环定时器 */
const struct lwip_cyclic_timer lwip_cyclic_timers[] = {
#if LWIP_TCP
  /* The TCP timer is a special case: it does not have to run always and
     is triggered to start from TCP using tcp_timer_needed() */
  {TCP_TMR_INTERVAL, HANDLER(tcp_tmr)},
#endif /* LWIP_TCP */
#if LWIP_IPV4
#if IP_REASSEMBLY
  {IP_TMR_INTERVAL, HANDLER(ip_reass_tmr)},
#endif /* IP_REASSEMBLY */
#if LWIP_ARP
  {ARP_TMR_INTERVAL, HANDLER(etharp_tmr)},
#endif /* LWIP_ARP */
#if LWIP_DHCP
  {DHCP_COARSE_TIMER_MSECS, HANDLER(dhcp_coarse_tmr)},
  {DHCP_FINE_TIMER_MSECS, HANDLER(dhcp_fine_tmr)},
#endif /* LWIP_DHCP */
#if LWIP_AUTOIP
  {AUTOIP_TMR_INTERVAL, HANDLER(autoip_tmr)},
#endif /* LWIP_AUTOIP */
#if LWIP_IGMP
  {IGMP_TMR_INTERVAL, HANDLER(igmp_tmr)},
#endif /* LWIP_IGMP */
#endif /* LWIP_IPV4 */
#if LWIP_DNS
  {DNS_TMR_INTERVAL, HANDLER(dns_tmr)},
#endif /* LWIP_DNS */
#if LWIP_IPV6
  {ND6_TMR_INTERVAL, HANDLER(nd6_tmr)},
#if LWIP_IPV6_REASS
  {IP6_REASS_TMR_INTERVAL, HANDLER(ip6_reass_tmr)},
#endif /* LWIP_IPV6_REASS */
#if LWIP_IPV6_MLD
  {MLD6_TMR_INTERVAL, HANDLER(mld6_tmr)},
#endif /* LWIP_IPV6_MLD */
#if LWIP_IPV6_DHCP6
  {DHCP6_TIMER_MSECS, HANDLER(dhcp6_tmr)},
#endif /* LWIP_IPV6_DHCP6 */
#endif /* LWIP_IPV6 */
};

/* 表示当前协议栈中使用的软件循环定时器个数 */
const int lwip_num_cyclic_timers = LWIP_ARRAYSIZE(lwip_cyclic_timers);

#if LWIP_TIMERS && !LWIP_TIMERS_CUSTOM

/** The one and only timeout list */
/* 系统内所有的超时事件都以超时时间按照升序的方式链接成一个链表，next_timeout 指向这个链表
 * 的链表头，所以 next_timeout 指向的成员就是和当前系统时间最接近的下一个超时事件 */
static struct sys_timeo *next_timeout;

static u32_t current_timeout_due_time;

#if LWIP_TESTMODE
/*********************************************************************************************************
** 函数名称: sys_timeouts_get_next_timeout
** 功能描述: 获取当前系统内距离当前时间最接近的下一个超时事件的结构体指针
** 输	 入: 
** 输	 出: sys_timeo - 获取到的下一个超时事假结构体指针
**         : NULL - 当前系统不存在超时事件
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
struct sys_timeo**
sys_timeouts_get_next_timeout(void)
{
  return &next_timeout;
}
#endif

#if LWIP_TCP
/** global variable that shows if the tcp timer is currently scheduled or not */
/* 全局变量，表示当前 tcp 模块定时器是否正在被调度 */
static int tcpip_tcp_timer_active;

/**
 * Timer callback function that calls tcp_tmr() and reschedules itself.
 *
 * @param arg unused argument
 */
/*********************************************************************************************************
** 函数名称: tcpip_tcp_timer
** 功能描述: 调用 tcp 模块的软件定时器处理函数并重新启动 tcp 模块软件定时器，实现周期循环处理的功能逻辑
** 输	 入: arg - 超时处理函数参数
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
tcpip_tcp_timer(void *arg)
{
  LWIP_UNUSED_ARG(arg);

  /* call TCP timer handler */
  tcp_tmr();
  /* timer still needed? */
  if (tcp_active_pcbs || tcp_tw_pcbs) {
    /* restart timer */
    sys_timeout(TCP_TMR_INTERVAL, tcpip_tcp_timer, NULL);
  } else {
    /* disable timer */
    tcpip_tcp_timer_active = 0;
  }
}

/**
 * Called from TCP_REG when registering a new PCB:
 * the reason is to have the TCP timer only running when
 * there are active (or time-wait) PCBs.
 */
/*********************************************************************************************************
** 函数名称: tcp_timer_needed
** 功能描述: 根据当前系统内 tcp 模块定时器状态判断是否需要启动 tcp 模块定时器，如果需要启动，则启动
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
tcp_timer_needed(void)
{
  LWIP_ASSERT_CORE_LOCKED();

  /* timer is off but needed again? */
  /* 如果当前 tcp 模块定时器没有被调度且 tcp_active_pcbs 或者 tcp_tw_pcbs 链表不为空
   * 则启动 tcp 模块定时器 */
  if (!tcpip_tcp_timer_active && (tcp_active_pcbs || tcp_tw_pcbs)) {
    /* enable and start timer */
    tcpip_tcp_timer_active = 1;
    sys_timeout(TCP_TMR_INTERVAL, tcpip_tcp_timer, NULL);
  }
}
#endif /* LWIP_TCP */

/*********************************************************************************************************
** 函数名称: sys_timeout_abs
** 功能描述: 根据函数参数动态生成一个 sys_timeo 成员并以超时时间按照升序的方式链接到 next_timeout 链表中
** 输	 入: abs_time - 超时时间点的绝对时间
**         : handler - 超时处理函数
**         : arg - 超时处理函数的参数
**         : handler_name - 超时处理函数名
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static void
#if LWIP_DEBUG_TIMERNAMES
sys_timeout_abs(u32_t abs_time, sys_timeout_handler handler, void *arg, const char *handler_name)
#else /* LWIP_DEBUG_TIMERNAMES */
sys_timeout_abs(u32_t abs_time, sys_timeout_handler handler, void *arg)
#endif
{
  struct sys_timeo *timeout, *t;

  /* 从当前系统内存池中申请一个 sys_timeo 结构体占用的内存空间 */
  timeout = (struct sys_timeo *)memp_malloc(MEMP_SYS_TIMEOUT);
  if (timeout == NULL) {
    LWIP_ASSERT("sys_timeout: timeout != NULL, pool MEMP_SYS_TIMEOUT is empty", timeout != NULL);
    return;
  }

  /* 初始化 sys_timeo 结构的成员字段 */
  timeout->next = NULL;
  timeout->h = handler;
  timeout->arg = arg;
  timeout->time = abs_time;

#if LWIP_DEBUG_TIMERNAMES
  timeout->handler_name = handler_name;
  LWIP_DEBUGF(TIMERS_DEBUG, ("sys_timeout: %p abs_time=%"U32_F" handler=%s arg=%p\n",
                             (void *)timeout, abs_time, handler_name, (void *)arg));
#endif /* LWIP_DEBUG_TIMERNAMES */

  /* 把刚刚创建的 timeout 成员以超时时间按照升序的方式链接到 next_timeout 链表中 */
  if (next_timeout == NULL) {
    next_timeout = timeout;
    return;
  }
  
  if (TIME_LESS_THAN(timeout->time, next_timeout->time)) {
    timeout->next = next_timeout;
    next_timeout = timeout;
  } else {
    for (t = next_timeout; t != NULL; t = t->next) {
      if ((t->next == NULL) || TIME_LESS_THAN(timeout->time, t->next->time)) {
        timeout->next = t->next;
        t->next = timeout;
        break;
      }
    }
  }
}

/**
 * Timer callback function that calls cyclic->handler() and reschedules itself.
 *
 * @param arg unused argument
 */
#if !LWIP_TESTMODE
/*********************************************************************************************************
** 函数名称: lwip_cyclic_timer
** 功能描述: 调用参数指定的循环超时事件处理函数并根据循环周期重新启动这个循环超时事件
** 输	 入: arg - 循环处理超时事件指针
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
static
#endif
void
lwip_cyclic_timer(void *arg)
{
  u32_t now;
  u32_t next_timeout_time;
  const struct lwip_cyclic_timer *cyclic = (const struct lwip_cyclic_timer *)arg;

#if LWIP_DEBUG_TIMERNAMES
  LWIP_DEBUGF(TIMERS_DEBUG, ("tcpip: %s()\n", cyclic->handler_name));
#endif

  /* 调用当前 cyclic 超时事件的超时处理函数 */
  cyclic->handler();

  /* 根据当前系统时间和当前循环超时事件循环周期计算下一个超时时间点 */
  now = sys_now();
  next_timeout_time = (u32_t)(current_timeout_due_time + cyclic->interval_ms);  /* overflow handled by TIME_LESS_THAN macro */ 

  /* 重新启动当前循环超时事件软件定时器 */
  if (TIME_LESS_THAN(next_timeout_time, now)) {
    /* timer would immediately expire again -> "overload" -> restart without any correction */
#if LWIP_DEBUG_TIMERNAMES
    sys_timeout_abs((u32_t)(now + cyclic->interval_ms), lwip_cyclic_timer, arg, cyclic->handler_name);
#else
    sys_timeout_abs((u32_t)(now + cyclic->interval_ms), lwip_cyclic_timer, arg);
#endif

  } else {
    /* correct cyclic interval with handler execution delay and sys_check_timeouts jitter */
#if LWIP_DEBUG_TIMERNAMES
    sys_timeout_abs(next_timeout_time, lwip_cyclic_timer, arg, cyclic->handler_name);
#else
    sys_timeout_abs(next_timeout_time, lwip_cyclic_timer, arg);
#endif
  }
}

/** Initialize this module */
/*********************************************************************************************************
** 函数名称: sys_timeouts_init
** 功能描述: 初始化当前系统的循环超时事件功能模块，遍历当前系统在 lwip_cyclic_timers 循环超时事件
**         : 数组中定义的每一个循环超时事件并启动
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void sys_timeouts_init(void)
{
  size_t i;
  
  /* tcp_tmr() at index 0 is started on demand */
  /* 遍历当前系统在 lwip_cyclic_timers 循环超时事件数组中定义的每一个循环超时事件并启动 */
  for (i = (LWIP_TCP ? 1 : 0); i < LWIP_ARRAYSIZE(lwip_cyclic_timers); i++) {
    /* we have to cast via size_t to get rid of const warning
      (this is OK as cyclic_timer() casts back to const* */
    sys_timeout(lwip_cyclic_timers[i].interval_ms, lwip_cyclic_timer, LWIP_CONST_CAST(void *, &lwip_cyclic_timers[i]));
  }
}

/**
 * Create a one-shot timer (aka timeout). Timeouts are processed in the
 * following cases:
 * - while waiting for a message using sys_timeouts_mbox_fetch()
 * - by calling sys_check_timeouts() (NO_SYS==1 only)
 *
 * @param msecs time in milliseconds after that the timer should expire
 * @param handler callback function to call when msecs have elapsed
 * @param arg argument to pass to the callback function
 */
#if LWIP_DEBUG_TIMERNAMES
void
sys_timeout_debug(u32_t msecs, sys_timeout_handler handler, void *arg, const char *handler_name)
#else /* LWIP_DEBUG_TIMERNAMES */
void
sys_timeout(u32_t msecs, sys_timeout_handler handler, void *arg)
#endif /* LWIP_DEBUG_TIMERNAMES */
{
  u32_t next_timeout_time;

  LWIP_ASSERT_CORE_LOCKED();

  LWIP_ASSERT("Timeout time too long, max is LWIP_UINT32_MAX/4 msecs", msecs <= (LWIP_UINT32_MAX / 4));

  next_timeout_time = (u32_t)(sys_now() + msecs); /* overflow handled by TIME_LESS_THAN macro */ 

#if LWIP_DEBUG_TIMERNAMES
  sys_timeout_abs(next_timeout_time, handler, arg, handler_name);
#else
  sys_timeout_abs(next_timeout_time, handler, arg);
#endif
}

/**
 * Go through timeout list (for this task only) and remove the first matching
 * entry (subsequent entries remain untouched), even though the timeout has not
 * triggered yet.
 *
 * @param handler callback function that would be called by the timeout
 * @param arg callback argument that would be passed to handler
*/
/*********************************************************************************************************
** 函数名称: sys_untimeout
** 功能描述: 从当前系统的 next_timeout 链表中移出指定的超时事件成员
** 输	 入: handler - 需要移除的超时事件成员超时处理函数
**         : arg - 需要移除的超时事件成员超时处理函数参数
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
sys_untimeout(sys_timeout_handler handler, void *arg)
{
  struct sys_timeo *prev_t, *t;

  LWIP_ASSERT_CORE_LOCKED();

  if (next_timeout == NULL) {
    return;
  }

  /* 遍历当前系统 next_timeout 链表上的超时事件成员并查找函数参数指定的超时成员
   * 如果找到则将其从中移除，并释放其占用的内存资源 */
  for (t = next_timeout, prev_t = NULL; t != NULL; prev_t = t, t = t->next) {
    if ((t->h == handler) && (t->arg == arg)) {
      /* We have a match */
      /* Unlink from previous in list */
      if (prev_t == NULL) {
        next_timeout = t->next;
      } else {
        prev_t->next = t->next;
      }
      memp_free(MEMP_SYS_TIMEOUT, t);
      return;
    }
  }
  return;
}

/**
 * @ingroup lwip_nosys
 * Handle timeouts for NO_SYS==1 (i.e. without using
 * tcpip_thread/sys_timeouts_mbox_fetch(). Uses sys_now() to call timeout
 * handler functions when timeouts expire.
 *
 * Must be called periodically from your main loop.
 */
/*********************************************************************************************************
** 函数名称: sys_check_timeouts
** 功能描述: 从当前系统 next_timeout 的链表头位置开始遍历其成员，通过当前系统时间判断遍历的成员是否
**         : 到达超时时间，如果达到超时时间则调用相应的超时处理函数并释放其资源，如果没到达超时时间
**         : 则不做任何处理直接退出返回
** 注     释: 这个函数“必须”在主循环函数中周期性的调用，来推动系统软件定时器的正常运行
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
sys_check_timeouts(void)
{
  u32_t now;

  LWIP_ASSERT_CORE_LOCKED();

  /* Process only timers expired at the start of the function. */
  now = sys_now();

  do {
    struct sys_timeo *tmptimeout;
    sys_timeout_handler handler;
    void *arg;

    PBUF_CHECK_FREE_OOSEQ();

    /* 如果当前系统不存在超时事件，则不做任何处理直接返回 */
    tmptimeout = next_timeout;
    if (tmptimeout == NULL) {
      return;
    }

    /* 如果当前系统时间还没到当前系统内最接近的超时事件，则不做任何处理直接返回*/
    if (TIME_LESS_THAN(now, tmptimeout->time)) {
      return;
    }

    /* Timeout has expired */
    next_timeout = tmptimeout->next;
    handler = tmptimeout->h;
    arg = tmptimeout->arg;
    current_timeout_due_time = tmptimeout->time;
#if LWIP_DEBUG_TIMERNAMES
    if (handler != NULL) {
      LWIP_DEBUGF(TIMERS_DEBUG, ("sct calling h=%s t=%"U32_F" arg=%p\n",
                                 tmptimeout->handler_name, sys_now() - tmptimeout->time, arg));
    }
#endif /* LWIP_DEBUG_TIMERNAMES */

    /* 释放已经超时的超时事件占用的内存资源并调用超时事件的超时处理函数 */
    memp_free(MEMP_SYS_TIMEOUT, tmptimeout);
    if (handler != NULL) {
      handler(arg);
    }

    LWIP_TCPIP_THREAD_ALIVE();

    /* Repeat until all expired timers have been called */
  } while (1);
}

/** Rebase the timeout times to the current time.
 * This is necessary if sys_check_timeouts() hasn't been called for a long
 * time (e.g. while saving energy) to prevent all timer functions of that
 * period being called.
 */
/*********************************************************************************************************
** 函数名称: sys_restart_timeouts
** 功能描述: 把当前系统的 next_timeout 链表上的所有超时成员的超时时间都调整成以当前系统时间为基准
**         : 的超时值，经过调整后，next_timeout 链表上的第一个超时成员超时时间等于当前系统时间，而
**         : 其他超时成员则按照原来的超时间隔重新排列在 next_timeout 链表后
** 输	 入: 
** 输	 出: 
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
void
sys_restart_timeouts(void)
{
  u32_t now;
  u32_t base;
  struct sys_timeo *t;

  if (next_timeout == NULL) {
    return;
  }

  now = sys_now();
  base = next_timeout->time;

  for (t = next_timeout; t != NULL; t = t->next) {
    t->time = (t->time - base) + now;
  }
}

/** Return the time left before the next timeout is due. If no timeouts are
 * enqueued, returns 0xffffffff
 */
/*********************************************************************************************************
** 函数名称: sys_timeouts_sleeptime
** 功能描述: 计算从当前系统时间点到系统内下一个超时事件需要流逝的时间
** 输	 入: 
** 输	 出: 0 - 表示已经超时
**         : ret - 表示还需等待 ret 时间
**         : SYS_TIMEOUTS_SLEEPTIME_INFINITE - 表示当前系统不存在超时事件
** 全局变量: 
** 调用模块: 
*********************************************************************************************************/
u32_t
sys_timeouts_sleeptime(void)
{
  u32_t now;

  LWIP_ASSERT_CORE_LOCKED();

  if (next_timeout == NULL) {
    return SYS_TIMEOUTS_SLEEPTIME_INFINITE;
  }
  now = sys_now();
  if (TIME_LESS_THAN(next_timeout->time, now)) {
    return 0;
  } else {
    u32_t ret = (u32_t)(next_timeout->time - now);
    LWIP_ASSERT("invalid sleeptime", ret <= LWIP_MAX_TIMEOUT);
    return ret;
  }
}

#else /* LWIP_TIMERS && !LWIP_TIMERS_CUSTOM */
/* Satisfy the TCP code which calls this function */
void
tcp_timer_needed(void)
{
}
#endif /* LWIP_TIMERS && !LWIP_TIMERS_CUSTOM */
