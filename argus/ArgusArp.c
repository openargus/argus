/*
 * Argus Software.  Argus files - Arp Procession
 * Copyright (c) 2000-2015 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/* 
 * $Id: //depot/argus/argus/argus/ArgusArp.c#32 $
 * $DateTime: 2015/04/17 08:10:46 $
 * $Change: 3011 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusArp)
#define ArgusArp
#endif

#include <stdio.h>
#include <argus_compat.h>
#include <ArgusModeler.h>

#if !defined(__OpenBSD__)
#include <net/if_arp.h>
#endif

#include <string.h>
#include <errno.h>

#define argus_ar_sha(ap)   (((const u_char *)((ap)+1))+0)
#define argus_ar_spa(ap)   (((const u_char *)((ap)+1))+  (ap)->ar_hln)
#define argus_ar_tha(ap)   (((const u_char *)((ap)+1))+  (ap)->ar_hln+(ap)->ar_pln)
#define argus_ar_tpa(ap)   (((const u_char *)((ap)+1))+2*(ap)->ar_hln+(ap)->ar_pln)

#define ARP_HDRLEN      8

#define HRD(ap) EXTRACT_16BITS(&(ap)->ar_hrd)
#define HLN(ap) ((ap)->ar_hln)
#define PLN(ap) ((ap)->ar_pln)
#define OP(ap)  EXTRACT_16BITS(&(ap)->ar_op)
#define PRO(ap) EXTRACT_16BITS(&(ap)->ar_pro)

#if defined(SHA)
#undef SHA
#endif
#define SHA(ap) (argus_ar_sha(ap))

#if defined(SPA)
#undef SPA
#endif
#define SPA(ap) (argus_ar_spa(ap))

#if defined(THA)
#undef THA
#endif
#define THA(ap) (argus_ar_tha(ap))

#if defined(TPA)
#undef TPA
#endif
#define TPA(ap) (argus_ar_tpa(ap))

#if !defined(REVARP_REQUEST)
#define REVARP_REQUEST          3
#endif
#if !defined(REVARP_REPLY)
#define REVARP_REPLY            4
#endif

void ArgusUpdateArpState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);

/*
struct ArgusHAddr {
   union {
      unsigned char ethernet[6];
      unsigned char ib[32];
      unsigned char ieee1394[16];
      unsigned char framerelay[4];
      unsigned char tokenring[6];
      unsigned char arcnet[1];
      unsigned char fiberchannel[12];
      unsigned char atm[20];
   } haddr_un;
};

struct ArgusArpFlow {
   unsigned short    hrd;
   unsigned short    pro;
   unsigned char     hln; 
   unsigned char     pln;
   unsigned short    op;
   unsigned int      arp_spa;
   unsigned int      arp_tpa;
   struct ArgusHAddr haddr;
};
 
struct ArgusRarpFlow {
   unsigned short    hrd;
   unsigned short    pro;
   unsigned char     hln;
   unsigned char     pln;
   unsigned short    op;
   unsigned int      arp_tpa;
   struct ArgusHAddr shaddr;
   struct ArgusHAddr dhaddr;
};
*/

#define ARP_ETHERNET	1
#define ARP_IEEE802	6
#define ARP_ARCNET  	7
#define ARP_FRELAY	15
#define ARP_ATM 	19
#define ARP_STRIP	23
#define ARP_IEEE1394	24
#define ARP_INFINIBAND	32

struct ArgusSystemFlow *
ArgusCreateArpFlow (struct ArgusModelerStruct *model, struct ether_header *ep) 
{
   struct arphdr *ahdr = (struct arphdr *)model->ArgusThisUpHdr;
   struct ArgusSystemFlow *retn = NULL;
   unsigned int arp_tpa, arp_spa;

   if (STRUCTCAPTURED(model, *ahdr)) {
      retn = model->ArgusThisFlow;

      retn->hdr.type              = ARGUS_FLOW_DSR;
      retn->hdr.subtype           = ARGUS_FLOW_ARP;

      switch (OP(ahdr)) {
         case ARPOP_REQUEST: {
            retn->hdr.argus_dsrvl8.len  = sizeof(struct ArgusArpFlow)/4 + 1;
            retn->hdr.argus_dsrvl8.qual = ARGUS_TYPE_ARP;

            if (PLN(ahdr) == sizeof(arp_spa)) {
               bcopy (SPA(ahdr), &arp_spa, sizeof(arp_spa));
               bcopy (TPA(ahdr), &arp_tpa, sizeof(arp_tpa));

#ifdef _LITTLE_ENDIAN
               arp_spa = ntohl(arp_spa);
               arp_tpa = ntohl(arp_tpa);
#endif
//             if (arp_spa > arp_tpa)
//                model->state |= ARGUS_DIRECTION;

               retn->arp_flow.hrd = HRD(ahdr);
               retn->arp_flow.pro = PRO(ahdr);
               retn->arp_flow.hln = HLN(ahdr);
               retn->arp_flow.pln = PLN(ahdr);
               retn->arp_flow.op  =  OP(ahdr);

               retn->arp_flow.arp_tpa = arp_tpa;
               retn->arp_flow.arp_spa = arp_spa;

               bcopy (SHA(ahdr), (char *)&retn->arp_flow.haddr, HLN(ahdr));
            }
            break;
         }
   
         case ARPOP_REPLY: {
            retn->hdr.argus_dsrvl8.len  = sizeof(struct ArgusArpFlow)/4 + 1;
            retn->hdr.argus_dsrvl8.qual = ARGUS_TYPE_ARP;

            if (PLN(ahdr) == sizeof(arp_spa)) {
               bcopy (SPA(ahdr), &arp_spa, sizeof(arp_spa));
               bcopy (TPA(ahdr), &arp_tpa, sizeof(arp_tpa));

#ifdef _LITTLE_ENDIAN
               arp_spa = ntohl(arp_spa);
               arp_tpa = ntohl(arp_tpa);
#endif
//             if (arp_spa > arp_tpa)
                  model->state |= ARGUS_DIRECTION;

               retn->arp_flow.hrd     = HRD(ahdr);
               retn->arp_flow.pro     = PRO(ahdr);
               retn->arp_flow.hln     = HLN(ahdr);
               retn->arp_flow.pln     = PLN(ahdr);
               retn->arp_flow.op      = ARPOP_REQUEST;

               retn->arp_flow.arp_tpa = arp_spa;
               retn->arp_flow.arp_spa = arp_tpa;
   
               bcopy (THA(ahdr), (char *)&retn->arp_flow.haddr, HLN(ahdr));
            }
            break;
         }

         case REVARP_REQUEST: {
            retn->hdr.argus_dsrvl8.len  = sizeof(struct ArgusRarpFlow)/4 + 1;
            retn->hdr.argus_dsrvl8.qual = ARGUS_TYPE_RARP;

#ifdef _LITTLE_ENDIAN
            arp_tpa = ntohl(arp_tpa);
#endif
            retn->rarp_flow.hrd     = HRD(ahdr);
            retn->rarp_flow.pro     = PRO(ahdr);
            retn->rarp_flow.hln     = HLN(ahdr);
            retn->rarp_flow.pln     = PLN(ahdr);
            retn->rarp_flow.op      =  OP(ahdr);

            bcopy (THA(ahdr), &retn->rarp_flow.shaddr, HLN(ahdr));
            bcopy (SHA(ahdr), &retn->rarp_flow.dhaddr, HLN(ahdr));
            break;
         }

         case REVARP_REPLY: {
            retn->hdr.argus_dsrvl8.len  = sizeof(struct ArgusRarpFlow)/4 + 1;
            retn->hdr.argus_dsrvl8.qual = ARGUS_TYPE_RARP;
            bcopy (TPA(ahdr), &arp_tpa, sizeof(arp_tpa));

#ifdef _LITTLE_ENDIAN
            arp_tpa = ntohl(arp_tpa);
#endif
            retn->rarp_flow.hrd     = HRD(ahdr);
            retn->rarp_flow.pro     = PRO(ahdr);
            retn->rarp_flow.hln     = HLN(ahdr);
            retn->rarp_flow.pln     = PLN(ahdr);
            retn->rarp_flow.op      = REVARP_REQUEST;

            bcopy ((char *)&arp_tpa, &retn->rarp_flow.arp_tpa, sizeof(arp_tpa));
            bcopy (SHA(ahdr), &retn->rarp_flow.shaddr, HLN(ahdr));
            bcopy (THA(ahdr), &retn->rarp_flow.dhaddr, HLN(ahdr));
            break;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusCreateArpFlow (%p) returning %p\n", ep, retn);
#endif

   return (retn);
}

/*
struct  arphdr {
        u_short ar_hrd;
#define ARPHRD_ETHER    1
#define ARPHRD_IEEE802  6
#define ARPHRD_FRELAY   15
#define ARPHRD_IEEE1394 24
#define ARPHRD_IEEE1394_EUI64 27
        u_short ar_pro;
        u_char  ar_hln;
        u_char  ar_pln;
        u_short ar_op;
#define ARPOP_REQUEST   1
#define ARPOP_REPLY     2
#define ARPOP_REVREQUEST 3
#define ARPOP_REVREPLY  4
#define ARPOP_INVREQUEST 8
#define ARPOP_INVREPLY  9
#ifdef COMMENT_ONLY
        u_char  ar_sha[];
        u_char  ar_spa[];
        u_char  ar_tha[];
        u_char  ar_tpa[];
#endif
};
*/

void
ArgusUpdateArpState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char *state)
{
   struct ArgusARPObject *arpobj = NULL;
   struct ether_arp *arp = NULL;
   struct arphdr *ahdr = NULL;

   if (model->ArgusThisEpHdr == NULL)
      return;

   arp = (struct ether_arp *)(model->ArgusThisEpHdr + 1);
   ahdr = &arp->ea_hdr;

   if (STRUCTCAPTURED(model, *arp)) {
      model->ArgusThisLength -= sizeof(*arp);
      model->ArgusSnapLength -= sizeof(*arp);
      model->ArgusThisUpHdr = (unsigned char *)(arp + 1);

      switch (OP(ahdr)) {
         case ARPOP_REQUEST:
            break;

         case ARPOP_REPLY: {
            struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) flowstr->dsrs[ARGUS_NETWORK_INDEX];

            if (net == NULL) {
               net = (struct ArgusNetworkStruct *) &flowstr->canon.net;
               flowstr->dsrs[ARGUS_NETWORK_INDEX] = (struct ArgusDSRHeader *) net;
            }

            net->hdr.type              = ARGUS_NETWORK_DSR;
            net->hdr.subtype           = ARGUS_NETWORK_SUBTYPE_ARP;
            net->hdr.argus_dsrvl8.qual = 0;
            net->hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusUDTObject) + 3)/4) + 1;

            arpobj = &net->net_union.arp;

            bcopy ((unsigned char *)SHA(ahdr), arpobj->respaddr, 6);
            break;
         }
      }
   }
}
