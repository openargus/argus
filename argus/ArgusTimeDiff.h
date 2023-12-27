/*
 * Gargoyle Software. Argus files - Time include files
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 *
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */

#ifndef __ARGUS_TIME_DIFF_H
# define __ARGUS_TIME_DIFF_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# include <sys/time.h>

static inline
long long
ArgusTimeDiff(const struct timeval * const start,
              const struct timeval * const stop)
{
   long long retn, t1, t2;

#if defined(ARGUS_NANOSECONDS)
   t1 = (start->tv_sec * 1000000000LL) + (start->tv_usec * 1LL);
   t2 = (stop->tv_sec  * 1000000000LL) + ( stop->tv_usec * 1LL);
#else
   t1 = (start->tv_sec * 1000000LL) + (start->tv_usec * 1LL);
   t2 = (stop->tv_sec  * 1000000LL) + ( stop->tv_usec * 1LL);
#endif

   retn = t2 - t1;
   return (retn);
}

static inline
unsigned long long
ArgusAbsTimeDiff(const struct timeval * const start,
                 const struct timeval * const stop)
{
   unsigned long long retn = 0;
   const struct timeval *t1 = start, *t2 = stop;

   if ((stop->tv_sec < start->tv_sec) || ((stop->tv_sec == start->tv_sec) &&
                                          (stop->tv_usec < start->tv_usec))) {
      t2 = start;
      t1 = stop;
   }

#if defined(ARGUS_NANOSECONDS)
   retn = ((t2->tv_sec * 1000000000LL) + t2->tv_usec) - 
          ((t1->tv_sec * 1000000000LL) + t1->tv_usec);
#else
   retn = ((t2->tv_sec * 1000000LL) + t2->tv_usec) -
          ((t1->tv_sec * 1000000LL) + t1->tv_usec);
#endif

   return (retn);
}

#endif
