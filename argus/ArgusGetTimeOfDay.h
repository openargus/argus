#ifndef __ARGUSGETTIMEOFDAY_H
# define __ARGUSGETTIMEOFDAY_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif
# include <sys/time.h>
# include <ArgusSource.h>
# include "argus_def.h"

/* call gettimeofday and convert to nanoseconds if required */

# ifdef __GNUC__
__attribute__((always_inline))
# endif
inline
static int
ArgusGetTimeOfDay(const struct ArgusSourceStruct * const src,
                  struct timeval *tv)
{
   int rv;

   rv = gettimeofday(tv, 0);
   if (rv == 0) {
      if (src->timeStampType == ARGUS_TYPE_UTC_NANOSECONDS)
         tv->tv_usec *= 1000;
   }
   return rv;
}

#endif
