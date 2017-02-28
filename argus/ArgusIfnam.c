#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <pthread.h>
#include "argus_compat.h"
#include "ArgusModeler.h"
#include "ArgusSource.h"

#define __NAMELENGTH 4

static inline int
__rot26(int c)
{
   if (!isalpha(c))
      return -1;

   if (c == 'z')
      c = 'a';
   else if (c == 'Z')
      c = 'A';
   else
      c++;

   return c;
}

static inline void
__shortname_next(char *ifnam)
{
   *ifnam = __rot26(*ifnam);
}

/* out := first letter of *in followed by the last 3 chars of *in */
static int
shortname_ethdev(char *in, char *out, size_t outlen)
{
   int nullterm;
   size_t inlen;

   if (outlen < __NAMELENGTH)
      return -ENOSPC;

   if (outlen == __NAMELENGTH)
      nullterm = 0;
   else
      nullterm = 1;

   while (outlen > 0)
      out[--outlen] = '\0';

   inlen = strlen(in);
   if (inlen <= __NAMELENGTH) {
      while (inlen > 0) {
         inlen--;
         out[inlen] = in[inlen];
      }
   } else {
      out[0] = *in;
      out[1] = in[inlen-3];
      out[2] = in[inlen-2];
      out[3] = in[inlen-1];
   }

   if (nullterm)
      out[4] = '\0';

   return 0;
}

static int
shortname_ethdev_check(char *ifnam, struct ArgusListStruct *ArgusDeviceList)
{
   struct ArgusDeviceStruct *dev;
   int ret = 0;

   pthread_mutex_lock(&ArgusDeviceList->lock);
   dev = (struct ArgusDeviceStruct *)ArgusDeviceList->start;
   if (dev) {
      for (; dev; dev = (struct ArgusDeviceStruct *)dev->nxt) {
         size_t ifnamlen = strlen(ifnam);

         if (!memcmp(ifnam, dev->trans.srcid.inf,
                     ifnamlen < __NAMELENGTH ? ifnamlen : __NAMELENGTH)) {
            /* oops, this name is already on the list */
            ret = -1;
            break;
         }
      }
    }
   pthread_mutex_unlock(&ArgusDeviceList->lock);
   return ret;
}

/* out := first letter of *in followed by the last 3 alnum chars of *in */
int
shortname_ethdev_unique(char *in, char *out, size_t outlen,
                        struct ArgusListStruct *ArgusDeviceList)
{
   unsigned count = 0;
   int done = 0;
   int ret = 0;
   char *incopy;
   size_t inlen;

   /* Really only needed for Windows Transport Names */
   while (*in && !isalpha(*in))
      in++;

   incopy = strdup(in);
   if (incopy == NULL)
      return -1;

   inlen = strlen(incopy);
   while (inlen > 0 && !isalnum(incopy[inlen-1]))
      incopy[--inlen] = '\0';

   ret = shortname_ethdev(incopy, out, outlen);
   free(incopy);

   if (ret < 0)
      return ret;

   do {
      ret = shortname_ethdev_check(out, ArgusDeviceList);
      if (++count < 25 && ret < 0)
         __shortname_next(out);
      else
         done = 1;
   } while (!done);

   return ret;
}
