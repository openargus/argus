/*
 * Gargoyle Software.  Argus files - IGMP protocol processing
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

/* 
 * $Id: //depot/gargoyle/argus/argus/ArgusIgmp.c#4 $
 * $DateTime: 2015/04/13 00:39:28 $
 * $Change: 2980 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusIgmp)
#define ArgusIgmp
#endif

#include <argus_compat.h>
#include <ArgusModeler.h>
#include <ArgusOutput.h>
#include <ArgusSource.h>
#include <ArgusUtil.h>

#if !defined(IGMP_MEMBERSHIP_QUERY)
#define IGMP_MEMBERSHIP_QUERY		0x11
#endif
#if !defined(IGMP_V1_MEMBERSHIP_REPORT)
#define IGMP_V1_MEMBERSHIP_REPORT	0x12
#endif
#if !defined(IGMP_V2_MEMBERSHIP_REPORT)
#define IGMP_V2_MEMBERSHIP_REPORT	0x16
#endif
#if !defined(IGMP_V2_LEAVE_GROUP)
#define IGMP_V2_LEAVE_GROUP		0x17
#endif

struct ArgusFlow *ArgusCreateIGMPv6Flow (struct ArgusModelerStruct *, struct igmp *);
struct ArgusFlow *ArgusCreateIGMPFlow (struct ArgusModelerStruct *, struct ip *);

struct ArgusFlow *
ArgusCreateIGMPv6Flow (struct ArgusModelerStruct *model, struct igmp *igmp)
{
   struct ArgusFlow *retn = NULL;
   struct ArgusIGMPFlow *igmpFlow = &model->ArgusThisFlow->igmp_flow;

   if (STRUCTCAPTURED(model, *igmp)) {
      igmpFlow->type   = igmp->igmp_type;
      igmpFlow->code   = igmp->igmp_code;
      igmpFlow->pad    = 0;
 
      switch (igmp->igmp_type) {
         case IGMP_HOST_MEMBERSHIP_QUERY:
            if (igmp->igmp_group.s_addr != 0)
               igmpFlow->ip_dst = ntohl(igmp->igmp_group.s_addr);
 
            break;
 
         case IGMP_V1_MEMBERSHIP_REPORT:
         case IGMP_V2_MEMBERSHIP_REPORT:
         case IGMP_V2_LEAVE_GROUP:
         default:
            igmpFlow->ip_dst = ntohl(igmp->igmp_group.s_addr);
            break;
      }
 
      retn = (struct ArgusFlow *) model->ArgusThisFlow;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusCreateIGMPFlow(0x%x) returning %d\n", igmp, retn);
#endif 

   return (retn);
}


struct ArgusFlow *
ArgusCreateIGMPFlow (struct ArgusModelerStruct *model, struct ip *ip)
{
   struct ArgusFlow *retn = NULL;
   unsigned int *igmphdr = (unsigned int *) model->ArgusThisUpHdr;
   struct igmp *igmp = (struct igmp *) igmphdr;
   struct ArgusIGMPFlow *igmpFlow = &model->ArgusThisFlow->igmp_flow;

   model->state &= ~ARGUS_DIRECTION;

   if (STRUCTCAPTURED(model, *igmphdr)) {
      model->ArgusThisFlow->hdr.type             = ARGUS_FLOW_DSR;
      model->ArgusThisFlow->hdr.subtype          = ARGUS_FLOW_CLASSIC5TUPLE;
      model->ArgusThisFlow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
      model->ArgusThisFlow->hdr.argus_dsrvl8.len  = 5;

      igmpFlow->ip_src = ntohl(ip->ip_src.s_addr);
      igmpFlow->ip_dst = ntohl(ip->ip_dst.s_addr);
      igmpFlow->ip_p   = ip->ip_p;
      igmpFlow->type   = igmp->igmp_type;
      igmpFlow->code   = igmp->igmp_code;
      igmpFlow->ip_id  = ntohs(ip->ip_id);
      igmpFlow->pad    = 0;

      switch (igmp->igmp_type) {
         case IGMP_HOST_MEMBERSHIP_QUERY:
            if (igmp->igmp_group.s_addr != 0)
               igmpFlow->ip_dst = ntohl(igmp->igmp_group.s_addr);

            break;

         case IGMP_V1_MEMBERSHIP_REPORT:
         case IGMP_V2_MEMBERSHIP_REPORT:
         case IGMP_V2_LEAVE_GROUP:
         default:
            igmpFlow->ip_dst = ntohl(igmp->igmp_group.s_addr);
            break;
      }

      retn = (struct ArgusFlow *) model->ArgusThisFlow;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusCreateIGMPFlow(0x%x) returning %d\n", ip, retn);
#endif 

   return (retn);
}
