/*
 * Argus-5.0 Software.  Argus files - UDP Protocol processing
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
      ltptr->opts = EXTRACT_16BITS(ptr); ptr++; len += 2;

      if (((ltptr->opts & L2TP_VERSION_MASK) == L2TP_VERSION_L2F) ||
          ((ltptr->opts & L2TP_VERSION_MASK) != L2TP_VERSION_L2TP))
         return (retn);

      if (ltptr->opts & L2TP_FLAG_LENGTH) {
         ltptr->len  = EXTRACT_16BITS(ptr); ptr++; len += 2;
      }

      ltptr->tunid   = EXTRACT_16BITS(ptr); ptr++; len += 2;
      ltptr->sessid  = EXTRACT_16BITS(ptr); ptr++; len += 2;
      
      if (ltptr->opts & L2TP_FLAG_SEQUENCE) {
         ltptr->ns   = EXTRACT_16BITS(ptr); ptr++; len += 2;
         ltptr->nr   = EXTRACT_16BITS(ptr); ptr++; len += 2;
      }
      if (ltptr->opts & L2TP_FLAG_OFFSET) {
         ltptr->offP = EXTRACT_16BITS(ptr); ptr++; len += 2;
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
