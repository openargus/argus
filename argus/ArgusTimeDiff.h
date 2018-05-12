#ifndef __ARGUS_TIME_DIFF_H
# define __ARGUS_TIME_DIFF_H

#include <sys/time.h>

static inline
long long
ArgusTimeDiff(const struct timeval * const start,
              const struct timeval * const stop)
{
   long long retn, t1, t2;

   stime = (start->tv_sec * 1000000LL) + start->tv_usec;
   etime = (stop->tv_sec  * 1000000LL) +  stop->tv_usec;

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

   retn = ((t2->tv_sec * 1000000LL) + t2->tv_usec) -
          ((t1->tv_sec * 1000000LL) + t1->tv_usec);

   return (retn);
}

#endif
