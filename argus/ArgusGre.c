/*
 * Argus-5.0 Software.  Argus files - GRE Tunnel processing
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

#if !defined(ArgusGre)
#define ArgusGre

#include <ArgusGre.h>

unsigned short ArgusParseGre (struct ArgusModelerStruct *, struct ip *, int);

unsigned short
ArgusParseGre (struct ArgusModelerStruct *model, struct ip *ip, int length)
{
   struct argus_gre *gre = model->ArgusThisGre;
   int retn = 0, grelen = 4, hlen = 0, pass = 0;

   if (ip->ip_v == 4) {
      model->ArgusThisNetworkFlowType = ETHERTYPE_IP;
      pass = STRUCTCAPTURED(model,*ip);
      hlen = ip->ip_hl << 2;
   } else {
      struct ip6_hdr *ipv6 = (struct ip6_hdr *) ip;
      model->ArgusThisNetworkFlowType = ETHERTYPE_IPV6;
      pass = STRUCTCAPTURED(model,*ipv6);
      hlen += sizeof(*ipv6);
   } 

   if (!pass || !BYTESCAPTURED(model, *ip, hlen))
      return (0);

   {
      char *bp = ((char *)ip + hlen);
      unsigned short flags;

/*
   model->ArgusThisLength -= hlen;
   model->ArgusSnapLength -= hlen;
*/
      length -= hlen;

      /* flags + protocol-type fields are 4 bytes total; confirm they are captured
       * before reading, rather than trusting the caller's length accounting alone. */
      if (!BYTESCAPTURED(model, *bp, 4))
         return (0);

      flags = EXTRACT_16BITS(bp);
      bp += sizeof(unsigned short);

      retn = EXTRACT_16BITS(bp);
      bp += sizeof(unsigned short);

      switch(flags & GRE_VERS_MASK) {
         case 0: {
            if (flags & (GRE_CP | GRE_RP)) {
               if (!BYTESCAPTURED(model, *bp, 4))
                  return (0);
               grelen += 4;
               bp += 4;
            }

            if (flags & GRE_KP) {
               if (!BYTESCAPTURED(model, *bp, 4))
                  return (0);
               bp += 4;
               grelen -= 4;
            }

            if (flags & GRE_SP) {
               if (!BYTESCAPTURED(model, *bp, 4))
                  return (0);
               bp += 4;
               grelen += 4;
            }

            if (flags & GRE_RP) {
               for (;;) {
                  u_int16_t af;
                  u_int8_t srelen;

                  if (BYTESCAPTURED(model, *bp, 4)) {
                     af = EXTRACT_16BITS(bp);
                     srelen = *(bp + 3);
                     bp += 4;
                     grelen -= 4;

                     if (af == 0 && srelen == 0)
                        break;

                     if (!BYTESCAPTURED(model, *bp, srelen))
                        return (0);
                     bp += srelen;
                     grelen += srelen;

                  } else
                     return (0);
               }
            }
            break;
         }

         case 1: {
            if (flags & GRE_KP) {
               if (!BYTESCAPTURED(model, *bp, 4))
                  return (0);
               bp += 4;
               grelen -= 4;
            }

            if (flags & GRE_SP) {
               if (!BYTESCAPTURED(model, *bp, 4))
                  return (0);
               bp += 4;
               grelen += 4;
            }

            if (flags & GRE_AP) {
               if (!BYTESCAPTURED(model, *bp, 4))
                  return (0);
               bp += 4;
               grelen += 4;
            }
            break;
         }
      }
      gre->flags = flags;
      gre->proto = retn;

      model->ArgusThisEncaps |= ARGUS_ENCAPS_GRE;
      model->ArgusThisUpHdr  = (unsigned char *) bp;
      model->ArgusThisLength -= grelen;
      model->ArgusSnapLength -= grelen;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusParseGre(%p, %p, %d) returning 0x%x\n", model, ip, length, retn);
#endif 

   return (retn);
}

#endif
