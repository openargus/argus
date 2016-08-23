/*
 * Gargoyle Software.  Argus files - UDP Protocol processing
 * Copyright (c) 2000-2015 QoSient, LLC
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

/* 
 * $Id$
 * $DateTime: 2014/05/14 12:53:31 $
 * $Change: 2827 $
 */

#if !defined(ArgusL2TP)
#define ArgusL2TP

#include <ArgusL2TP.h>

unsigned short ArgusParseL2TP (struct ArgusModelerStruct *, void *);

unsigned short
ArgusParseL2TP (struct ArgusModelerStruct *model, void *vptr)
{
   unsigned short retn = 0;
   u_int16_t *ptr = vptr;
   int len = 0;
   struct l2tphdr *l2tp = (struct l2tphdr *) vptr;
   struct l2tphdr l2tpbuf, *ltptr = &l2tpbuf;

   if (STRUCTCAPTURED(model, *l2tp)) {
      ltptr->opts = EXTRACT_16BITS(ptr++);
      len += 2;

      if (((ltptr->opts & L2TP_VERSION_MASK) == L2TP_VERSION_L2F) ||
          ((ltptr->opts & L2TP_VERSION_MASK) != L2TP_VERSION_L2TP))
         return (retn);

      if (ltptr->opts & L2TP_FLAG_LENGTH) {
         ltptr->len  = EXTRACT_16BITS(ptr++);
         len += 2;
      }

      ltptr->tunid   = EXTRACT_16BITS(ptr++); len += 2;
      ltptr->sessid  = EXTRACT_16BITS(ptr++); len += 2;
      
      if (ltptr->opts & L2TP_FLAG_SEQUENCE) {
         ltptr->ns   = EXTRACT_16BITS(ptr++); len += 2;
         ltptr->nr   = EXTRACT_16BITS(ptr++); len += 2;
      }
      if (ltptr->opts & L2TP_FLAG_OFFSET) {
         ltptr->offP = EXTRACT_16BITS(ptr++); len += 2;
         ptr += ltptr->offP / sizeof(*ptr);
         len += ltptr->offP;
      }

      if (!(ltptr->opts & L2TP_FLAG_TYPE)) {
         retn = ETHERTYPE_PPP;

         model->ArgusThisEncaps |= ARGUS_ENCAPS_L2TP;
         model->ArgusThisUpHdr  = (unsigned char *)ptr;
         model->ArgusThisLength -= len;
         model->ArgusSnapLength -= len;
      }
   }
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusParseL2TP(%p, %p) returning %d\n", model, ptr, retn);
#endif
   return (retn);
}


#endif
