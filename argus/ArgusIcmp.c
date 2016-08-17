/*
 * Argus Software.  Argus files - ICMP protocol processing
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
 * $Id: //depot/argus/argus/argus/ArgusIcmp.c#23 $
 * $DateTime: 2015/08/05 22:33:18 $
 * $Change: 3042 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusIcmp)
#define ArgusIcmp
#endif

#include <argus_compat.h>
#include <ArgusModeler.h>
#include <ArgusOutput.h>
#include <ArgusSource.h>
#include <ArgusUtil.h>


struct ArgusSystemFlow *
ArgusCreateICMPv6Flow (struct ArgusModelerStruct *model, struct icmp6_hdr *icmp)
{
   struct ArgusSystemFlow *retn = NULL;

   if (STRUCTCAPTURED(model, *icmp)) {
      struct ArgusICMPv6Flow *icmpv6Flow = &model->ArgusThisFlow->icmpv6_flow;

      icmpv6Flow->type = icmp->icmp6_type;

      switch (icmp->icmp6_type & ICMP6_INFOMSG_MASK) {
         case ICMP6_INFOMSG_MASK: 
            switch (icmp->icmp6_type) {
               case ICMP6_ECHO_REPLY:
                  if (model->ArgusFlowType == ARGUS_BIDIRECTIONAL)
                     icmpv6Flow->type = ICMP6_ECHO_REQUEST;
                  break;

               case ICMP6_MEMBERSHIP_REPORT:
               case ICMP6_MEMBERSHIP_REDUCTION:
                  if (model->ArgusFlowType == ARGUS_BIDIRECTIONAL)
                     icmpv6Flow->type = ICMP6_MEMBERSHIP_QUERY;
                  break;

               case ND_ROUTER_ADVERT:
                  if (model->ArgusFlowType == ARGUS_BIDIRECTIONAL)
                     icmpv6Flow->type = ND_ROUTER_SOLICIT;
                  break;

               case ND_NEIGHBOR_ADVERT:
                  if (model->ArgusFlowType == ARGUS_BIDIRECTIONAL)
                     icmpv6Flow->type = ND_NEIGHBOR_SOLICIT;
                  break;

               case ICMP6_HADISCOV_REPLY:
                  if (model->ArgusFlowType == ARGUS_BIDIRECTIONAL)
                     icmpv6Flow->type = ICMP6_HADISCOV_REQUEST;
                  break;
            }
            icmpv6Flow->code = icmp->icmp6_code;
            break;

         default: {
            switch (icmp->icmp6_type) {
               case ICMP6_DST_UNREACH:
               case ICMP6_PACKET_TOO_BIG:
               case ICMP6_TIME_EXCEEDED:
               case ICMP6_PARAM_PROB:
                  break;
            }

            icmpv6Flow->type = icmp->icmp6_type;
            icmpv6Flow->code = icmp->icmp6_code;
            break;
         }
      }

      if (model->state & ARGUS_DIRECTION) {
      }

      retn = (struct ArgusSystemFlow *) model->ArgusThisFlow;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusCreateICMPFlow(0x%x) returning %d\n", icmp, retn);
#endif 
   return (retn);
}

struct ArgusSystemFlow *
ArgusCreateICMPFlow (struct ArgusModelerStruct *model, struct ip *ip)
{
   struct ArgusSystemFlow *retn = NULL;
   struct icmp *icmp = (struct icmp *) model->ArgusThisUpHdr;

   if (STRUCTCAPTURED(model, icmp->icmp_type)) {
      struct ArgusICMPFlow *icmpFlow = &model->ArgusThisFlow->icmp_flow;

      retn = model->ArgusThisFlow;
      model->state &= ~ARGUS_DIRECTION;

      retn->hdr.type              = ARGUS_FLOW_DSR;
      retn->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
      retn->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
      retn->hdr.argus_dsrvl8.len  = 5;

      icmpFlow->ip_src = ntohl(ip->ip_src.s_addr);
      icmpFlow->ip_dst = ntohl(ip->ip_dst.s_addr);

      icmpFlow->type   = icmp->icmp_type;
      icmpFlow->ip_p   = ip->ip_p;
      icmpFlow->tp_p   = 0;
      icmpFlow->id     = 0;
      icmpFlow->ip_id  = 0;

      if (ICMP_INFOTYPE(icmp->icmp_type)) {
         switch (icmp->icmp_type) {
            case ICMP_ECHOREPLY:
               model->state |= ARGUS_DIRECTION;
            case ICMP_ECHO:
               icmpFlow->type = ICMP_ECHO;
               if (STRUCTCAPTURED(model, icmp->icmp_id))
                  icmpFlow->id = ntohs(icmp->icmp_id);
               if (STRUCTCAPTURED(model, icmp->icmp_seq))
                  icmpFlow->ip_id = ntohs(icmp->icmp_seq);
               break;
            case ICMP_TSTAMPREPLY:
               model->state |= ARGUS_DIRECTION;
            case ICMP_TSTAMP:
               icmpFlow->type = ICMP_TSTAMP;
               break;
            case ICMP_IREQREPLY:
               model->state |= ARGUS_DIRECTION;
            case ICMP_IREQ:
               icmpFlow->type = ICMP_IREQ;
               break;
            case ICMP_MASKREPLY:
               model->state |= ARGUS_DIRECTION;
            case ICMP_MASKREQ:
               icmpFlow->type = ICMP_MASKREQ;
               break;
         }

      } else {
         if (STRUCTCAPTURED(model, icmp->icmp_code)) {
            icmpFlow->code   = icmp->icmp_code;
            if (STRUCTCAPTURED(model, icmp->icmp_ip)) {
               struct ip *oip = &icmp->icmp_ip;
               switch (icmp->icmp_type) {
                  case ICMP_UNREACH: 
                     switch (icmp->icmp_code) {
                        case ICMP_UNREACH_PROTOCOL:
                           icmpFlow->id = (unsigned short) icmp->icmp_ip.ip_p;
                           break;

                        case ICMP_UNREACH_PORT: {
                           struct ip *oip = &icmp->icmp_ip;
                           struct udphdr *ouh;
                           int hlen = oip->ip_hl << 2;

                           ouh = (struct udphdr *) (((u_char *) oip) + hlen);
                           icmpFlow->tp_p = oip->ip_p;
                           icmpFlow->id = ntohs((unsigned short) ouh->uh_dport);
                           break;
                        }

                        case ICMP_UNREACH_NET:
                        case ICMP_UNREACH_HOST:
                           bcopy ((char *) &icmp->icmp_ip.ip_dst.s_addr,
                                           (char *)&icmpFlow->id, sizeof (int));
                           break;
                     }
                     break;

                  case ICMP_REDIRECT:
                     switch (icmp->icmp_code) {
                        case ICMP_REDIRECT_TOSNET:
                        case ICMP_REDIRECT_TOSHOST:
                           icmpFlow->tp_p = oip->ip_tos;
                           break;

                        case ICMP_REDIRECT_NET:
                        case ICMP_REDIRECT_HOST:
                           bcopy ((char *) &icmp->icmp_ip.ip_dst.s_addr, (char *)&icmpFlow->id, sizeof (int));
                           break;
                     }
                     break;

                  default:
                     break;
               }
            }
         }
      }

      if (model->state & ARGUS_DIRECTION) {
         unsigned int addr = icmpFlow->ip_src;
         icmpFlow->ip_src = icmpFlow->ip_dst;
         icmpFlow->ip_dst = addr;
         model->ArgusThisFlow->hdr.argus_dsrvl8.qual |= ARGUS_DIRECTION;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusCreateICMPFlow(0x%x) returning %d\n", ip, retn);
#endif 
   return (retn);
}


#include <string.h>
#include <errno.h>

void ArgusUpdateICMPState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);
void ArgusUpdateICMPv6State (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);


void
ArgusUpdateICMPState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char *state)
{
   struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) &flowstr->canon.net;
   struct ArgusICMPObject *icmpObj = &net->net_union.icmp;
   struct icmp *icmp = (struct icmp *) model->ArgusThisUpHdr; 

   if (STRUCTCAPTURED(model, *icmp)) {
      if (*state == ARGUS_START) {
         net->hdr.type             = ARGUS_NETWORK_DSR;
         net->hdr.subtype          = ARGUS_ICMP_DSR;
         net->hdr.argus_dsrvl8.qual = 0;
         net->hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusICMPObject)+3))/4 + 1;
         bzero ((char *)icmpObj, sizeof(*icmpObj));

         icmpObj->icmp_type = icmp->icmp_type;
         icmpObj->icmp_code = icmp->icmp_code;
         icmpObj->iseq      = ntohs(icmp->icmp_seq);

         icmpObj->osrcaddr  = ntohl(((struct ip *)model->ArgusThisIpHdr)->ip_src.s_addr);
         icmpObj->odstaddr  = ntohl(((struct ip *)model->ArgusThisIpHdr)->ip_dst.s_addr);

         if (ICMP_INFOTYPE(icmp->icmp_type)) {
            switch (icmp->icmp_type) {
               case ICMP_ECHO:
               case ICMP_IREQ:
               case ICMP_MASKREQ:
               case ICMP_TSTAMP:
                  break;

               case ICMP_MASKREPLY:
                  icmp->icmp_mask = ntohl(icmp->icmp_mask);
                  icmpObj->isrcaddr = icmp->icmp_mask;

               case ICMP_ECHOREPLY:
               case ICMP_IREQREPLY:
               case ICMP_TSTAMPREPLY:
                     break;
            }

         } else {
            struct ip *oip = &icmp->icmp_ip;

            if (STRUCTCAPTURED(model, *oip)) {
               icmpObj->isrcaddr  = ntohl(oip->ip_src.s_addr);
               icmpObj->idstaddr  = ntohl(oip->ip_dst.s_addr);
               icmpObj->igwaddr   = ntohl(icmp->icmp_gwaddr.s_addr);
            }
         }

      } else {
         if (ICMP_INFOTYPE(icmp->icmp_type)) {
            if ((flowstr->canon.metric.src.pkts == 0) && (flowstr->canon.metric.dst.pkts == 0))
               icmpObj->icmp_type = icmp->icmp_type;

            switch (icmp->icmp_type) {
               case ICMP_ECHO:
               case ICMP_IREQ:
               case ICMP_TSTAMP:
               case ICMP_MASKREQ:
                  *state = ARGUS_START;
                  icmpObj->icmp_type = icmp->icmp_type;
                  break;

               case ICMP_ECHOREPLY:
               case ICMP_IREQREPLY:
               case ICMP_TSTAMPREPLY:
               case ICMP_MASKREPLY:
                  model->ArgusInProtocol = 1;
                  break;

               default:
                  break;
            }
         }
      }

      if (!(ICMP_INFOTYPE(icmp->icmp_type))) {
         struct ArgusSystemFlow *tflow = NULL;
         struct ArgusFlowStruct *flow;
         struct ArgusHashStruct hstruct;

         struct ip *oip = &icmp->icmp_ip;

         if (STRUCTCAPTURED(model, *oip)) {
            model->ArgusThisIpHdr = oip;
            model->ArgusThisUpHdr = (unsigned char *) oip;

            if ((tflow = ArgusCreateFlow(model, oip, model->ArgusThisLength)) != NULL) {
               ArgusCreateFlowKey (model, tflow, &hstruct);
               if ((flow = ArgusFindFlow (model, &hstruct)) != NULL) {
                  struct ArgusDSRHeader *dsr = &flow->canon.icmp.hdr;
                  struct ArgusTimeObject *time = &flow->canon.time;

                  dsr->type            = ARGUS_ICMP_DSR;
                  dsr->subtype         = 0;
                  switch (icmp->icmp_type) {
                     
                     case ICMP_UNREACH:  dsr->argus_dsrvl8.qual = ARGUS_ICMPUNREACH_MAPPED; break;
                     case ICMP_REDIRECT: dsr->argus_dsrvl8.qual = ARGUS_ICMPREDIREC_MAPPED; break;
                     case ICMP_TIMXCEED: dsr->argus_dsrvl8.qual = ARGUS_ICMPTIMXCED_MAPPED; break;

                  }

                  dsr->argus_dsrvl8.len  = (sizeof (struct ArgusIcmpStruct) + 3)/4 + 1;
                  bcopy ((char *) icmpObj, (char *) (dsr + 1), sizeof (*icmpObj));
                  flow->dsrs[ARGUS_ICMP_INDEX] = dsr;
                  flow->dsrindex |= 1 << ARGUS_ICMP_INDEX;

                  if (time->src.start.tv_sec == 0) {
                     time->hdr.subtype          = ARGUS_TIME_ABSOLUTE_TIMESTAMP;
                     time->hdr.argus_dsrvl8.qual = ARGUS_TYPE_UTC_MICROSECONDS;
                     time->hdr.argus_dsrvl8.len  = 3;

                     time->src.start.tv_sec  = model->ArgusGlobalTime.tv_sec;
                     time->src.start.tv_usec = model->ArgusGlobalTime.tv_usec;

                  } else {
                     if (time->hdr.argus_dsrvl8.len != 5) {
                        time->hdr.subtype          = ARGUS_TIME_ABSOLUTE_RANGE;
                        time->hdr.argus_dsrvl8.qual = ARGUS_TYPE_UTC_MICROSECONDS;
                        time->hdr.argus_dsrvl8.len  = 5;
                     }

                     time->src.end.tv_sec  = model->ArgusGlobalTime.tv_sec;
                     time->src.end.tv_usec = model->ArgusGlobalTime.tv_usec;
                  }
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusUpdateICMPState(0x%x, %d) returning\n", flowstr, state);
#endif 
}


void
ArgusUpdateICMPv6State (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char *state)
{
   struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) &flowstr->canon.net;
   struct ArgusICMPv6Object *icmpObj = &net->net_union.icmpv6;
   struct icmp6_hdr *icmpv6 = (struct icmp6_hdr *) model->ArgusThisUpHdr;

   if (STRUCTCAPTURED(model, *icmpv6)) {
      if (*state == ARGUS_START) {
         net->hdr.type             = ARGUS_NETWORK_DSR;
         net->hdr.subtype          = ARGUS_ICMP_DSR;
         net->hdr.argus_dsrvl8.qual = 0;
         net->hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusICMPObject)+3))/4 + 1;
         bzero ((char *)icmpObj, sizeof(*icmpObj));

         icmpObj->icmp_type = icmpv6->icmp6_type;
         icmpObj->icmp_code = icmpv6->icmp6_code;
         icmpObj->cksum     = ntohs(icmpv6->icmp6_cksum);

         if (icmpv6->icmp6_type & ICMP6_INFOMSG_MASK) {
         } else {
            switch (icmpv6->icmp6_type) {
               case ICMP6_DST_UNREACH:
               case ICMP6_PACKET_TOO_BIG:
               case ICMP6_TIME_EXCEEDED:
               case ICMP6_PARAM_PROB:
                  break;
            }
         }

      } else {
         if (icmpv6->icmp6_type & ICMP6_INFOMSG_MASK) {
            if ((flowstr->canon.metric.src.pkts == 0) && (flowstr->canon.metric.dst.pkts == 0))
               icmpObj->icmp_type = icmpv6->icmp6_type;

            switch (icmpv6->icmp6_type) {
               default:
                  break;
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusUpdateICMPState(0x%x, %d) returning\n", flowstr, state);
#endif 
}
