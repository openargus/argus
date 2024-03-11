/*
 * Argus-5.0 Software. Argus files - Time include files
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software, released under the GNU General
 * Public License; you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software
 * Foundation; either version 3, or any later version.
 *
 * Other licenses are available through QoSient, LLC.
 * Inquire at info@qosient.com.
 *
 * This program is distributed WITHOUT ANY WARRANTY; without even the
 * implied warranty of * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
