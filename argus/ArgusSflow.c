/*
 * Argus Software.  Argus files - Fragment processing
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
 * $Id: //depot/argus/argus/argus/ArgusSflow.c#6 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusSflow)
#define ArgusSflow

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <argus_compat.h>
#include <ArgusModeler.h>
#include <ArgusUtil.h>
#include <ArgusSflow.h>

void
ArgusParseSflowRecord (struct ArgusModelerStruct *model, void *ptr)
{
/*
   int ArgusReadSocketState = ARGUS_READINGPREHDR;
   int ArgusReadSocketSize = 0;
   unsigned int ArgusFlowSeq = 0, ArgusCounter, ArgusSourceId;
   unsigned int ArgusSysUptime = 0;

   unsigned short ArgusReadCiscoVersion, ArgusReadSocketNum;

   struct timeval tvpbuf, *tvp = &tvpbuf;
   void **templates = NULL;

   while ((char *)ptr < (char *)model->ArgusThisSnapEnd) {
      switch (ArgusReadSocketState) {
         case ARGUS_READINGPREHDR: {
            unsigned short *sptr = (unsigned short *) ptr;
            ArgusReadCiscoVersion = ntohs(*sptr++);
            ArgusReadSocketNum  = ntohs(*sptr);
            ArgusReadSocketState = ARGUS_READINGHDR;
            break;
         }

         case ARGUS_READINGHDR: {
#ifdef ARGUSDEBUG
            ArgusDebug (7, "ArgusReadCiscoStreamSocket (%p, %p) read record header\n", model, ptr);
#endif
            switch (ArgusReadCiscoVersion) {
               case CISCO_VERSION_1: {
                  CiscoFlowHeaderV1_t *ArgusNetFlow = (CiscoFlowHeaderV1_t *) ptr;
                  ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                  ArgusSysUptime  = ntohl(ArgusNetFlow->sysUptime);
                  ArgusCounter  =  ntohs(ArgusNetFlow->count);
                  tvp->tv_sec  = ntohl(ArgusNetFlow->unix_secs);
                  tvp->tv_usec = ntohl(ArgusNetFlow->unix_nsecs)/1000;
                  break;
               }

               case CISCO_VERSION_5: {
                  CiscoFlowHeaderV5_t *ArgusNetFlow = (CiscoFlowHeaderV5_t *) ptr;
                  ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                  ArgusSysUptime  = ntohl(ArgusNetFlow->sysUptime);
                  ArgusFlowSeq  = ntohl(ArgusNetFlow->flow_sequence);
                  ArgusCounter  =  ntohs(ArgusNetFlow->count);
                  tvp->tv_sec  = ntohl(ArgusNetFlow->unix_secs);
                  tvp->tv_usec = ntohl(ArgusNetFlow->unix_nsecs)/1000;
                  break;
               }

               case CISCO_VERSION_6: {
                  CiscoFlowHeaderV6_t *ArgusNetFlow = (CiscoFlowHeaderV6_t *) ptr;
                  ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                  ArgusSysUptime  = ntohl(ArgusNetFlow->sysUptime);
                  ArgusFlowSeq  = ntohl(ArgusNetFlow->flow_sequence);
                  ArgusCounter  =  0;
                  tvp->tv_sec  = ntohl(ArgusNetFlow->unix_secs);
                  tvp->tv_usec = ntohl(ArgusNetFlow->unix_nsecs)/1000;
                  break;
               }

               case CISCO_VERSION_7: {
                  CiscoFlowHeaderV7_t *ArgusNetFlow = (CiscoFlowHeaderV7_t *) ptr;
                  ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                  ArgusSysUptime  = ntohl(ArgusNetFlow->sysUptime);
                  ArgusFlowSeq    = ntohl(ArgusNetFlow->flow_sequence);
                  ArgusCounter    =  0;
                  tvp->tv_sec     = ntohl(ArgusNetFlow->unix_secs);
                  tvp->tv_usec    = ntohl(ArgusNetFlow->unix_nsecs)/1000;
                  break;
               }

               case CISCO_VERSION_8: {
                  CiscoFlowHeaderV8_t *ArgusNetFlow = (CiscoFlowHeaderV8_t *) ptr;
                  ArgusReadSocketSize  = sizeof(*ArgusNetFlow);
                  break;
               }

               case CISCO_VERSION_9: {
                  CiscoFlowHeaderV9_t *ArgusNetFlow = (CiscoFlowHeaderV9_t *) ptr;
                  ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                  ArgusCounter      = ntohs(ArgusNetFlow->count);
                  ArgusSysUptime    = ntohl(ArgusNetFlow->sysUptime);
                  tvp->tv_sec       = ntohl(ArgusNetFlow->unix_secs);
                  tvp->tv_usec      = 0;
                  ArgusFlowSeq      = ntohl(ArgusNetFlow->package_sequence);
                  ArgusSourceId     = ntohl(ArgusNetFlow->source_id);
                  break;
               }

               default: {
#ifdef ARGUSDEBUG
                  ArgusDebug (7, "ArgusReadCiscoStreamSocket (%p) read header\n", ptr);
#endif
               }
            }
            ptr += ArgusReadSocketSize;
            ArgusReadSocketState = ARGUS_READINGBLOCK;
            break;
         }

         case ARGUS_READINGBLOCK: {
            struct ArgusSystemFlow flowbuf, *sflow = &flowbuf;
            struct ArgusHashStruct hbuf, *hstruct = &hbuf;
            struct ArgusFlowStruct *flow = NULL;

#ifdef ARGUSDEBUG
            ArgusDebug (7, "ArgusReadCiscoStreamSocket (%p, %p) read record complete\n", model, ptr);
#endif
            switch (ArgusReadCiscoVersion) {
               case CISCO_VERSION_1: {
                  CiscoFlowEntryV1_t *ArgusNetFlow = (CiscoFlowEntryV1_t *) ptr;
                  bzero(sflow, sizeof(*sflow));
                  bzero(hstruct, sizeof(*hstruct));

                  sflow->hdr.type              = ARGUS_FLOW_DSR;
                  sflow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
                  sflow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                  sflow->hdr.argus_dsrvl8.len  = 5;
                  sflow->ip_flow.ip_src = ntohl(ArgusNetFlow->srcaddr);
                  sflow->ip_flow.ip_dst = ntohl(ArgusNetFlow->dstaddr);
 
                  switch (sflow->ip_flow.ip_p = ArgusNetFlow->prot) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP:
                        sflow->ip_flow.sport  = ntohs(ArgusNetFlow->srcport);
                        sflow->ip_flow.dport  = ntohs(ArgusNetFlow->dstport);
                     break;
 
                     case IPPROTO_ICMP:
                        sflow->icmp_flow.type  = ((char *)&ArgusNetFlow->dstport)[0];
                        sflow->icmp_flow.code  = ((char *)&ArgusNetFlow->dstport)[1];
                     break;
                  }

                  ArgusCreateFlowKey(model, sflow, hstruct);
                  if ((flow = ArgusNewFlow(model, sflow, NULL, NULL)) != NULL) {
                     struct ArgusTimeObject *time = &flow->canon.time;
                     long timeval;

                     flow->canon.hdr.type         = ARGUS_FAR | ARGUS_NETFLOW | ARGUS_VERSION;

                     time->hdr.type               = ARGUS_TIME_DSR;
                     time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
                     time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
                     time->hdr.argus_dsrvl8.len   = 5;               

                     timeval = ntohl(ArgusNetFlow->first);
                     time->src.start.tv_sec   = (timeval - (long)ArgusSysUptime)/1000; 
                     time->src.start.tv_sec  += tvp->tv_sec;

                     time->src.start.tv_usec  = ((timeval - (long)ArgusSysUptime)%1000) * 1000; 
                     time->src.start.tv_usec += tvp->tv_usec;

                     if (time->src.start.tv_usec >= 1000000) {
                        time->src.start.tv_sec++;
                        time->src.start.tv_usec -= 1000000;
                     }
                     if (time->src.start.tv_usec < 0) {
                        time->src.start.tv_sec--;
                        time->src.start.tv_usec += 1000000;
                     }

                     timeval = ntohl(ArgusNetFlow->last);
                     time->src.end.tv_sec   = (timeval - (long)ArgusSysUptime)/1000;
                     time->src.end.tv_sec  += tvp->tv_sec;

                     time->src.end.tv_usec  = ((timeval - (long)ArgusSysUptime)%1000) * 1000;
                     time->src.end.tv_usec += tvp->tv_usec;

                     if (time->src.end.tv_usec >= 1000000) {
                        time->src.end.tv_sec++;
                        time->src.end.tv_usec -= 1000000;
                     }
                     if (time->src.end.tv_usec < 0) {
                        time->src.end.tv_sec--;
                        time->src.end.tv_usec += 1000000;
                     }

                     time->src.start.tv_usec = (time->src.start.tv_usec / 1000) * 1000;
                     time->src.end.tv_usec  = (time->src.end.tv_usec / 1000) * 1000;
                     flow->dsrindex |= 1 << ARGUS_TIME_INDEX;
                     flow->dsrs[ARGUS_TIME_INDEX] = (void *)time;

                     {
                        struct ArgusMetricStruct *metric = &flow->canon.metric;
                        metric->hdr.type              = ARGUS_METER_DSR;
                        metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
                        metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_INT;
                        metric->hdr.argus_dsrvl8.len  = 3;

                        metric->src.pkts  = ntohl(ArgusNetFlow->pkts);
                        metric->src.bytes = ntohl(ArgusNetFlow->bytes);
                        flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                        flow->dsrs[ARGUS_METRIC_INDEX] = (void *)metric;
                     }

                     {
                        struct ArgusMacStruct *mac = &flow->canon.mac;
                        mac->hdr.type              = ARGUS_MAC_DSR;
                        mac->hdr.subtype           = 0;
                        mac->hdr.argus_dsrvl8.len  = 5;
                        ArgusNetFlow->input = ntohs(ArgusNetFlow->input);
                        ArgusNetFlow->output = ntohs(ArgusNetFlow->output);
#if defined(HAVE_SOLARIS)
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost.ether_addr_octet[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost.ether_addr_octet[4], 2);
#else
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost[4], 2);
#endif
                        flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                        flow->dsrs[ARGUS_MAC_INDEX] = (void *)mac;
                     }

                     {
                        if (ArgusNetFlow->prot == IPPROTO_TCP) {
                           struct ArgusNetworkStruct *net = &flow->canon.net;
                           struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;

                           net->hdr.type              = ARGUS_NETWORK_DSR;
                           net->hdr.subtype           = ARGUS_TCP_STATUS;
                           net->hdr.argus_dsrvl8.len  = 3;
                           net->net_union.tcpstatus.src = ArgusNetFlow->flags;

                           if (ArgusNetFlow->flags & TH_RST) 
                              tcp->status |= ARGUS_RESET;
          
                           if (ArgusNetFlow->flags & TH_FIN)
                              tcp->status |= ARGUS_FIN;
          
                           if ((ArgusNetFlow->flags & TH_ACK) || (ArgusNetFlow->flags & TH_PUSH) || (ArgusNetFlow->flags & TH_URG))
                              tcp->status |= ARGUS_CON_ESTABLISHED;
          
                           switch (ArgusNetFlow->flags & (TH_SYN|TH_ACK)) {
                              case (TH_SYN):  
                                 tcp->status |= ARGUS_SAW_SYN;
                                 break;
             
                              case (TH_SYN|TH_ACK): 
                                 tcp->status |= ARGUS_SAW_SYN_SENT;  
                                 if (ntohl(ArgusNetFlow->pkts) > 1)
                                    tcp->status &= ~(ARGUS_CON_ESTABLISHED);
                                 break;
                           }
                           flow->dsrindex |= 1 << ARGUS_NETWORK_INDEX;
                           flow->dsrs[ARGUS_NETWORK_INDEX] = (void *)net;
                        }
                     }
                     if (model->ArgusThisFlow && (model->ArgusThisFlow->ip_flow.ip_src != 0)) {
                        struct ArgusTransportStruct *trans = &flow->canon.trans;
                        trans->hdr.type               = ARGUS_TRANSPORT_DSR;
                        trans->hdr.subtype            = ARGUS_SRCID | ARGUS_SEQ;
                        trans->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV4;
                        trans->hdr.argus_dsrvl8.len   = 3;
                        trans->srcid.a_un.ipv4        = (model->ArgusThisFlow->hdr.subtype & ARGUS_REVERSE) ?
                                                        model->ArgusThisFlow->ip_flow.ip_dst :
                                                        model->ArgusThisFlow->ip_flow.ip_src ;

                        trans->seqnum                 = ArgusFlowSeq + ArgusCounter++;
                        flow->dsrindex |= 1 << ARGUS_TRANSPORT_INDEX;
                        flow->dsrs[ARGUS_TRANSPORT_INDEX] = (void *)trans;
                     }
                     {
                        struct ArgusIPAttrStruct *attr = &flow->canon.attr;
                        attr->hdr.type               = ARGUS_IPATTR_DSR;
                        attr->hdr.subtype            = 0;
                        attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
                        attr->hdr.argus_dsrvl8.len   = 2;
                        attr->src.tos                = ArgusNetFlow->tos;
                        attr->src.ttl                = 0;
                        attr->src.ip_id              = 0;
                        flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                        flow->dsrs[ARGUS_IPATTR_INDEX] = (void *)attr;
                     }
                     ArgusSendFlowRecord (model, flow, ARGUS_STATUS);
                  }

                  ptr += sizeof(*ArgusNetFlow);
                  break;
               }

               case CISCO_VERSION_5: {
                  CiscoFlowEntryV5_t *ArgusNetFlow = (CiscoFlowEntryV5_t *) ptr;
                  bzero(sflow, sizeof(*sflow));
                  bzero(hstruct, sizeof(*hstruct));

                  sflow->hdr.type              = ARGUS_FLOW_DSR;
                  sflow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
                  sflow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                  sflow->hdr.argus_dsrvl8.len  = 5;
                  sflow->ip_flow.ip_src = ntohl(ArgusNetFlow->srcaddr);
                  sflow->ip_flow.ip_dst = ntohl(ArgusNetFlow->dstaddr);
 
                  sflow->ip_flow.smask = ArgusNetFlow->src_mask;
                  sflow->ip_flow.dmask = ArgusNetFlow->dst_mask;
 
                  switch (sflow->ip_flow.ip_p = ArgusNetFlow->prot) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP:
                        sflow->ip_flow.sport  = ntohs(ArgusNetFlow->srcport);
                        sflow->ip_flow.dport  = ntohs(ArgusNetFlow->dstport);
                     break;
 
                     case IPPROTO_ICMP:
                        sflow->icmp_flow.type  = ((char *)&ArgusNetFlow->dstport)[0];
                        sflow->icmp_flow.code  = ((char *)&ArgusNetFlow->dstport)[1];
                     break;
                  }

                  ArgusCreateFlowKey(model, sflow, hstruct);
                  if ((flow = ArgusNewFlow(model, sflow, NULL, NULL)) != NULL) {
                     struct ArgusTimeObject *time = &flow->canon.time;
                     long timeval;

                     flow->canon.hdr.type         = ARGUS_FAR | ARGUS_NETFLOW | ARGUS_VERSION;

                     time->hdr.type               = ARGUS_TIME_DSR;
                     time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
                     time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
                     time->hdr.argus_dsrvl8.len   = 5;               

                     timeval = ntohl(ArgusNetFlow->first);
                     time->src.start.tv_sec   = (timeval - (long)ArgusSysUptime)/1000; 
                     time->src.start.tv_sec  += tvp->tv_sec;

                     time->src.start.tv_usec  = ((timeval - (long)ArgusSysUptime)%1000) * 1000; 
                     time->src.start.tv_usec += tvp->tv_usec;

                     if (time->src.start.tv_usec >= 1000000) {
                        time->src.start.tv_sec++;
                        time->src.start.tv_usec -= 1000000;
                     }
                     if (time->src.start.tv_usec < 0) {
                        time->src.start.tv_sec--;
                        time->src.start.tv_usec += 1000000;
                     }

                     timeval = ntohl(ArgusNetFlow->last);
                     time->src.end.tv_sec   = (timeval - (long)ArgusSysUptime)/1000;
                     time->src.end.tv_sec  += tvp->tv_sec;

                     time->src.end.tv_usec  = ((timeval - (long)ArgusSysUptime)%1000) * 1000;
                     time->src.end.tv_usec += tvp->tv_usec;

                     if (time->src.end.tv_usec >= 1000000) {
                        time->src.end.tv_sec++;
                        time->src.end.tv_usec -= 1000000;
                     }
                     if (time->src.end.tv_usec < 0) {
                        time->src.end.tv_sec--;
                        time->src.end.tv_usec += 1000000;
                     }

                     time->src.start.tv_usec = (time->src.start.tv_usec / 1000) * 1000;
                     time->src.end.tv_usec  = (time->src.end.tv_usec / 1000) * 1000;
                     flow->dsrindex |= 1 << ARGUS_TIME_INDEX;
                     flow->dsrs[ARGUS_TIME_INDEX] = (void *)time;

                     {
                        struct ArgusAsnStruct *asn  = &flow->canon.asn;
                        asn->hdr.type               = ARGUS_ASN_DSR;
                        asn->hdr.subtype            = 0;
                        asn->hdr.argus_dsrvl8.qual  = 0;
                        asn->hdr.argus_dsrvl8.len   = 3;
                        asn->src_as                 = ArgusNetFlow->src_as;
                        asn->dst_as                 = ArgusNetFlow->dst_as;
                        flow->dsrindex |= 1 << ARGUS_ASN_INDEX;
                        flow->dsrs[ARGUS_ASN_INDEX] = (void *)asn;
                     }

                     {
                        struct ArgusMetricStruct *metric = &flow->canon.metric;
                        metric->hdr.type              = ARGUS_METER_DSR;
                        metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
                        metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_INT;
                        metric->hdr.argus_dsrvl8.len  = 3;

                        metric->src.pkts  = ntohl(ArgusNetFlow->pkts);
                        metric->src.bytes = ntohl(ArgusNetFlow->bytes);
                        flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                        flow->dsrs[ARGUS_METRIC_INDEX] = (void *)metric;
                     }

                     {
                        struct ArgusMacStruct *mac = &flow->canon.mac;
                        mac->hdr.type              = ARGUS_MAC_DSR;
                        mac->hdr.subtype           = 0;
                        mac->hdr.argus_dsrvl8.len  = 5;
                        ArgusNetFlow->input = ntohs(ArgusNetFlow->input);
                        ArgusNetFlow->output = ntohs(ArgusNetFlow->output);
#if defined(HAVE_SOLARIS)
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost.ether_addr_octet[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost.ether_addr_octet[4], 2);
#else
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost[4], 2);
#endif
                        flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                        flow->dsrs[ARGUS_MAC_INDEX] = (void *)mac;
                     }

                     {
                        if (ArgusNetFlow->prot == IPPROTO_TCP) {
                           struct ArgusNetworkStruct *net = &flow->canon.net;
                           struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;

                           net->hdr.type              = ARGUS_NETWORK_DSR;
                           net->hdr.subtype           = ARGUS_TCP_STATUS;
                           net->hdr.argus_dsrvl8.len  = 3;
                           net->net_union.tcpstatus.src = ArgusNetFlow->tcp_flags;

                           if (ArgusNetFlow->tcp_flags & TH_RST) 
                              tcp->status |= ARGUS_RESET;
          
                           if (ArgusNetFlow->tcp_flags & TH_FIN)
                              tcp->status |= ARGUS_FIN;
          
                           if ((ArgusNetFlow->tcp_flags & TH_ACK) || (ArgusNetFlow->tcp_flags & TH_PUSH) || (ArgusNetFlow->tcp_flags & TH_URG))
                              tcp->status |= ARGUS_CON_ESTABLISHED;
          
                           switch (ArgusNetFlow->tcp_flags & (TH_SYN|TH_ACK)) {
                              case (TH_SYN):  
                                 tcp->status |= ARGUS_SAW_SYN;
                                 break;
             
                              case (TH_SYN|TH_ACK): 
                                 tcp->status |= ARGUS_SAW_SYN_SENT;  
                                 if (ntohl(ArgusNetFlow->pkts) > 1)
                                    tcp->status &= ~(ARGUS_CON_ESTABLISHED);
                                 break;
                           }
                           flow->dsrindex |= 1 << ARGUS_NETWORK_INDEX;
                           flow->dsrs[ARGUS_NETWORK_INDEX] = (void *)net;
                        }
                     }
                     if (model->ArgusThisFlow && (model->ArgusThisFlow->ip_flow.ip_src != 0)) {
                        struct ArgusTransportStruct *trans = &flow->canon.trans;
                        trans->hdr.type               = ARGUS_TRANSPORT_DSR;
                        trans->hdr.subtype            = ARGUS_SRCID | ARGUS_SEQ;
                        trans->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV4;
                        trans->hdr.argus_dsrvl8.len   = 3;
                        trans->srcid.a_un.ipv4        = (model->ArgusThisFlow->hdr.subtype & ARGUS_REVERSE) ?
                                                        model->ArgusThisFlow->ip_flow.ip_dst :
                                                        model->ArgusThisFlow->ip_flow.ip_src ;

                        trans->seqnum                 = ArgusFlowSeq + ArgusCounter++;
                        flow->dsrindex |= 1 << ARGUS_TRANSPORT_INDEX;
                        flow->dsrs[ARGUS_TRANSPORT_INDEX] = (void *)trans;
                     }
                     {
                        struct ArgusIPAttrStruct *attr = &flow->canon.attr;
                        attr->hdr.type               = ARGUS_IPATTR_DSR;
                        attr->hdr.subtype            = 0;
                        attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
                        attr->hdr.argus_dsrvl8.len   = 2;
                        attr->src.tos                = ArgusNetFlow->tos;
                        attr->src.ttl                = 0;
                        attr->src.ip_id              = 0;
                        flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                        flow->dsrs[ARGUS_IPATTR_INDEX] = (void *)attr;
                     }
                     ArgusSendFlowRecord (model, flow, ARGUS_STATUS);
                  }

                  ptr += sizeof(*ArgusNetFlow);
                  break;
               }

               case CISCO_VERSION_6: {
                  CiscoFlowEntryV6_t *ArgusNetFlow = (CiscoFlowEntryV6_t *) ptr;
                  bzero(sflow, sizeof(*sflow));
                  bzero(hstruct, sizeof(*hstruct));

                  sflow->hdr.type              = ARGUS_FLOW_DSR;
                  sflow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
                  sflow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                  sflow->hdr.argus_dsrvl8.len  = 5;
                  sflow->ip_flow.ip_src = ntohl(ArgusNetFlow->srcaddr);
                  sflow->ip_flow.ip_dst = ntohl(ArgusNetFlow->dstaddr);
 
                  sflow->ip_flow.smask = ArgusNetFlow->src_mask;
                  sflow->ip_flow.dmask = ArgusNetFlow->dst_mask;
 
                  switch (sflow->ip_flow.ip_p = ArgusNetFlow->prot) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP:
                        sflow->ip_flow.sport  = ntohs(ArgusNetFlow->srcport);
                        sflow->ip_flow.dport  = ntohs(ArgusNetFlow->dstport);
                     break;
 
                     case IPPROTO_ICMP:
                        sflow->icmp_flow.type  = ((char *)&ArgusNetFlow->dstport)[0];
                        sflow->icmp_flow.code  = ((char *)&ArgusNetFlow->dstport)[1];
                     break;
                  }

                  ArgusCreateFlowKey(model, sflow, hstruct);
                  if ((flow = ArgusNewFlow(model, sflow, NULL, NULL)) != NULL) {
                     struct ArgusTimeObject *time = &flow->canon.time;
                     long timeval;

                     flow->canon.hdr.type         = ARGUS_FAR | ARGUS_NETFLOW | ARGUS_VERSION;

                     time->hdr.type               = ARGUS_TIME_DSR;
                     time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
                     time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
                     time->hdr.argus_dsrvl8.len   = 5;               

                     timeval = ntohl(ArgusNetFlow->first);
                     time->src.start.tv_sec   = (timeval - (long)ArgusSysUptime)/1000; 
                     time->src.start.tv_sec  += tvp->tv_sec;

                     time->src.start.tv_usec  = ((timeval - (long)ArgusSysUptime)%1000) * 1000; 
                     time->src.start.tv_usec += tvp->tv_usec;

                     if (time->src.start.tv_usec >= 1000000) {
                        time->src.start.tv_sec++;
                        time->src.start.tv_usec -= 1000000;
                     }
                     if (time->src.start.tv_usec < 0) {
                        time->src.start.tv_sec--;
                        time->src.start.tv_usec += 1000000;
                     }

                     timeval = ntohl(ArgusNetFlow->last);
                     time->src.end.tv_sec   = (timeval - (long)ArgusSysUptime)/1000;
                     time->src.end.tv_sec  += tvp->tv_sec;

                     time->src.end.tv_usec  = ((timeval - (long)ArgusSysUptime)%1000) * 1000;
                     time->src.end.tv_usec += tvp->tv_usec;

                     if (time->src.end.tv_usec >= 1000000) {
                        time->src.end.tv_sec++;
                        time->src.end.tv_usec -= 1000000;
                     }
                     if (time->src.end.tv_usec < 0) {
                        time->src.end.tv_sec--;
                        time->src.end.tv_usec += 1000000;
                     }

                     time->src.start.tv_usec = (time->src.start.tv_usec / 1000) * 1000;
                     time->src.end.tv_usec  = (time->src.end.tv_usec / 1000) * 1000;
                     flow->dsrindex |= 1 << ARGUS_TIME_INDEX;
                     flow->dsrs[ARGUS_TIME_INDEX] = (void *)time;

                     {
                        struct ArgusAsnStruct *asn  = &flow->canon.asn;
                        asn->hdr.type               = ARGUS_ASN_DSR;
                        asn->hdr.subtype            = 0;
                        asn->hdr.argus_dsrvl8.qual  = 0;
                        asn->hdr.argus_dsrvl8.len   = 3;
                        asn->src_as                 = ArgusNetFlow->src_as;
                        asn->dst_as                 = ArgusNetFlow->dst_as;
                        flow->dsrindex |= 1 << ARGUS_ASN_INDEX;
                        flow->dsrs[ARGUS_ASN_INDEX] = (void *)asn;
                     }

                     {
                        struct ArgusMetricStruct *metric = &flow->canon.metric;
                        metric->hdr.type              = ARGUS_METER_DSR;
                        metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
                        metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_INT;
                        metric->hdr.argus_dsrvl8.len  = 3;

                        metric->src.pkts  = ntohl(ArgusNetFlow->pkts);
                        metric->src.bytes = ntohl(ArgusNetFlow->bytes);
                        flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                        flow->dsrs[ARGUS_METRIC_INDEX] = (void *)metric;
                     }

                     {
                        struct ArgusMacStruct *mac = &flow->canon.mac;
                        mac->hdr.type              = ARGUS_MAC_DSR;
                        mac->hdr.subtype           = 0;
                        mac->hdr.argus_dsrvl8.len  = 5;
                        ArgusNetFlow->input = ntohs(ArgusNetFlow->input);
                        ArgusNetFlow->output = ntohs(ArgusNetFlow->output);
#if defined(HAVE_SOLARIS)
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost.ether_addr_octet[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost.ether_addr_octet[4], 2);
#else
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost[4], 2);
#endif
                        flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                        flow->dsrs[ARGUS_MAC_INDEX] = (void *)mac;
                     }

                     {
                        if (ArgusNetFlow->prot == IPPROTO_TCP) {
                           struct ArgusNetworkStruct *net = &flow->canon.net;
                           struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;

                           net->hdr.type              = ARGUS_NETWORK_DSR;
                           net->hdr.subtype           = ARGUS_TCP_STATUS;
                           net->hdr.argus_dsrvl8.len  = 3;
                           net->net_union.tcpstatus.src = ArgusNetFlow->tcp_flags;

                           if (ArgusNetFlow->tcp_flags & TH_RST) 
                              tcp->status |= ARGUS_RESET;
          
                           if (ArgusNetFlow->tcp_flags & TH_FIN)
                              tcp->status |= ARGUS_FIN;
          
                           if ((ArgusNetFlow->tcp_flags & TH_ACK) || (ArgusNetFlow->tcp_flags & TH_PUSH) || (ArgusNetFlow->tcp_flags & TH_URG))
                              tcp->status |= ARGUS_CON_ESTABLISHED;
          
                           switch (ArgusNetFlow->tcp_flags & (TH_SYN|TH_ACK)) {
                              case (TH_SYN):  
                                 tcp->status |= ARGUS_SAW_SYN;
                                 break;
             
                              case (TH_SYN|TH_ACK): 
                                 tcp->status |= ARGUS_SAW_SYN_SENT;  
                                 if (ntohl(ArgusNetFlow->pkts) > 1)
                                    tcp->status &= ~(ARGUS_CON_ESTABLISHED);
                                 break;
                           }
                           flow->dsrindex |= 1 << ARGUS_NETWORK_INDEX;
                           flow->dsrs[ARGUS_NETWORK_INDEX] = (void *)net;
                        }
                     }
                     if (model->ArgusThisFlow && (model->ArgusThisFlow->ip_flow.ip_src != 0)) {
                        struct ArgusTransportStruct *trans = &flow->canon.trans;
                        trans->hdr.type               = ARGUS_TRANSPORT_DSR;
                        trans->hdr.subtype            = ARGUS_SRCID | ARGUS_SEQ;
                        trans->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV4;
                        trans->hdr.argus_dsrvl8.len   = 3;
                        trans->srcid.a_un.ipv4        = (model->ArgusThisFlow->hdr.subtype & ARGUS_REVERSE) ?
                                                        model->ArgusThisFlow->ip_flow.ip_dst :
                                                        model->ArgusThisFlow->ip_flow.ip_src ;

                        trans->seqnum                 = ArgusFlowSeq + ArgusCounter++;
                        flow->dsrindex |= 1 << ARGUS_TRANSPORT_INDEX;
                        flow->dsrs[ARGUS_TRANSPORT_INDEX] = (void *)trans;
                     }
                     {
                        struct ArgusIPAttrStruct *attr = &flow->canon.attr;
                        attr->hdr.type               = ARGUS_IPATTR_DSR;
                        attr->hdr.subtype            = 0;
                        attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
                        attr->hdr.argus_dsrvl8.len   = 2;
                        attr->src.tos                = ArgusNetFlow->tos;
                        attr->src.ttl                = 0;
                        attr->src.ip_id              = 0;
                        flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                        flow->dsrs[ARGUS_IPATTR_INDEX] = (void *)attr;
                     }
                     ArgusSendFlowRecord (model, flow, ARGUS_STATUS);
                  }

                  ptr += sizeof(*ArgusNetFlow);
                  break;
               }

               case CISCO_VERSION_7: {
                  CiscoFlowEntryV7_t *ArgusNetFlow = (CiscoFlowEntryV7_t *) ptr;
                  bzero(sflow, sizeof(*sflow));
                  bzero(hstruct, sizeof(*hstruct));

                  sflow->hdr.type              = ARGUS_FLOW_DSR;
                  sflow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
                  sflow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                  sflow->hdr.argus_dsrvl8.len  = 5;
                  sflow->ip_flow.ip_src = ntohl(ArgusNetFlow->srcaddr);
                  sflow->ip_flow.ip_dst = ntohl(ArgusNetFlow->dstaddr);
 
                  sflow->ip_flow.smask = ArgusNetFlow->src_mask;
                  sflow->ip_flow.dmask = ArgusNetFlow->dst_mask;
 
                  switch (sflow->ip_flow.ip_p = ArgusNetFlow->prot) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP:
                        sflow->ip_flow.sport  = ntohs(ArgusNetFlow->srcport);
                        sflow->ip_flow.dport  = ntohs(ArgusNetFlow->dstport);
                     break;
 
                     case IPPROTO_ICMP:
                        sflow->icmp_flow.type  = ((char *)&ArgusNetFlow->dstport)[0];
                        sflow->icmp_flow.code  = ((char *)&ArgusNetFlow->dstport)[1];
                     break;
                  }

                  ArgusCreateFlowKey(model, sflow, hstruct);
                  if ((flow = ArgusNewFlow(model, sflow, NULL, NULL)) != NULL) {
                     struct ArgusTimeObject *time = &flow->canon.time;
                     long timeval;

                     flow->canon.hdr.type         = ARGUS_FAR | ARGUS_NETFLOW | ARGUS_VERSION;

                     time->hdr.type               = ARGUS_TIME_DSR;
                     time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
                     time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
                     time->hdr.argus_dsrvl8.len   = 5;               

                     timeval = ntohl(ArgusNetFlow->first);
                     time->src.start.tv_sec   = (timeval - (long)ArgusSysUptime)/1000; 
                     time->src.start.tv_sec  += tvp->tv_sec;

                     time->src.start.tv_usec  = ((timeval - (long)ArgusSysUptime)%1000) * 1000; 
                     time->src.start.tv_usec += tvp->tv_usec;

                     if (time->src.start.tv_usec >= 1000000) {
                        time->src.start.tv_sec++;
                        time->src.start.tv_usec -= 1000000;
                     }
                     if (time->src.start.tv_usec < 0) {
                        time->src.start.tv_sec--;
                        time->src.start.tv_usec += 1000000;
                     }

                     timeval = ntohl(ArgusNetFlow->last);
                     time->src.end.tv_sec   = (timeval - (long)ArgusSysUptime)/1000;
                     time->src.end.tv_sec  += tvp->tv_sec;

                     time->src.end.tv_usec  = ((timeval - (long)ArgusSysUptime)%1000) * 1000;
                     time->src.end.tv_usec += tvp->tv_usec;

                     if (time->src.end.tv_usec >= 1000000) {
                        time->src.end.tv_sec++;
                        time->src.end.tv_usec -= 1000000;
                     }
                     if (time->src.end.tv_usec < 0) {
                        time->src.end.tv_sec--;
                        time->src.end.tv_usec += 1000000;
                     }

                     time->src.start.tv_usec = (time->src.start.tv_usec / 1000) * 1000;
                     time->src.end.tv_usec  = (time->src.end.tv_usec / 1000) * 1000;
                     flow->dsrindex |= 1 << ARGUS_TIME_INDEX;
                     flow->dsrs[ARGUS_TIME_INDEX] = (void *)time;

                     {
                        struct ArgusAsnStruct *asn  = &flow->canon.asn;
                        asn->hdr.type               = ARGUS_ASN_DSR;
                        asn->hdr.subtype            = 0;
                        asn->hdr.argus_dsrvl8.qual  = 0;
                        asn->hdr.argus_dsrvl8.len   = 3;
                        asn->src_as                 = ArgusNetFlow->src_as;
                        asn->dst_as                 = ArgusNetFlow->dst_as;
                        flow->dsrindex |= 1 << ARGUS_ASN_INDEX;
                        flow->dsrs[ARGUS_ASN_INDEX] = (void *)asn;
                     }

                     {
                        struct ArgusMetricStruct *metric = &flow->canon.metric;
                        metric->hdr.type              = ARGUS_METER_DSR;
                        metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
                        metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_INT;
                        metric->hdr.argus_dsrvl8.len  = 3;

                        metric->src.pkts  = ntohl(ArgusNetFlow->pkts);
                        metric->src.bytes = ntohl(ArgusNetFlow->bytes);
                        flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                        flow->dsrs[ARGUS_METRIC_INDEX] = (void *)metric;
                     }

                     {
                        struct ArgusMacStruct *mac = &flow->canon.mac;
                        mac->hdr.type              = ARGUS_MAC_DSR;
                        mac->hdr.subtype           = 0;
                        mac->hdr.argus_dsrvl8.len  = 5;
                        ArgusNetFlow->input = ntohs(ArgusNetFlow->input);
                        ArgusNetFlow->output = ntohs(ArgusNetFlow->output);
#if defined(HAVE_SOLARIS)
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost.ether_addr_octet[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost.ether_addr_octet[4], 2);
#else
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost[4], 2);
#endif
                        flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                        flow->dsrs[ARGUS_MAC_INDEX] = (void *)mac;
                     }

                     {
                        if (ArgusNetFlow->prot == IPPROTO_TCP) {
                           struct ArgusNetworkStruct *net = &flow->canon.net;
                           struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;

                           net->hdr.type              = ARGUS_NETWORK_DSR;
                           net->hdr.subtype           = ARGUS_TCP_STATUS;
                           net->hdr.argus_dsrvl8.len  = 3;
                           net->net_union.tcpstatus.src = ArgusNetFlow->tcp_flags;

                           if (ArgusNetFlow->tcp_flags & TH_RST) 
                              tcp->status |= ARGUS_RESET;
          
                           if (ArgusNetFlow->tcp_flags & TH_FIN)
                              tcp->status |= ARGUS_FIN;
          
                           if ((ArgusNetFlow->tcp_flags & TH_ACK) || (ArgusNetFlow->tcp_flags & TH_PUSH) || (ArgusNetFlow->tcp_flags & TH_URG))
                              tcp->status |= ARGUS_CON_ESTABLISHED;
          
                           switch (ArgusNetFlow->tcp_flags & (TH_SYN|TH_ACK)) {
                              case (TH_SYN):  
                                 tcp->status |= ARGUS_SAW_SYN;
                                 break;
             
                              case (TH_SYN|TH_ACK): 
                                 tcp->status |= ARGUS_SAW_SYN_SENT;  
                                 if (ntohl(ArgusNetFlow->pkts) > 1)
                                    tcp->status &= ~(ARGUS_CON_ESTABLISHED);
                                 break;
                           }
                           flow->dsrindex |= 1 << ARGUS_NETWORK_INDEX;
                           flow->dsrs[ARGUS_NETWORK_INDEX] = (void *)net;
                        }
                     }
                     if (model->ArgusThisFlow && (model->ArgusThisFlow->ip_flow.ip_src != 0)) {
                        struct ArgusTransportStruct *trans = &flow->canon.trans;
                        trans->hdr.type               = ARGUS_TRANSPORT_DSR;
                        trans->hdr.subtype            = ARGUS_SRCID | ARGUS_SEQ;
                        trans->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_IPV4;
                        trans->hdr.argus_dsrvl8.len   = 3;
                        trans->srcid.a_un.ipv4        = (model->ArgusThisFlow->hdr.subtype & ARGUS_REVERSE) ?
                                                        model->ArgusThisFlow->ip_flow.ip_dst :
                                                        model->ArgusThisFlow->ip_flow.ip_src ;

                        trans->seqnum                 = ArgusFlowSeq + ArgusCounter++;
                        flow->dsrindex |= 1 << ARGUS_TRANSPORT_INDEX;
                        flow->dsrs[ARGUS_TRANSPORT_INDEX] = (void *)trans;
                     }
                     {
                        struct ArgusIPAttrStruct *attr = &flow->canon.attr;
                        attr->hdr.type               = ARGUS_IPATTR_DSR;
                        attr->hdr.subtype            = 0;
                        attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
                        attr->hdr.argus_dsrvl8.len   = 2;
                        attr->src.tos                = ArgusNetFlow->tos;
                        attr->src.ttl                = 0;
                        attr->src.ip_id              = 0;
                        flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                        flow->dsrs[ARGUS_IPATTR_INDEX] = (void *)attr;
                     }
                     ArgusSendFlowRecord (model, flow, ARGUS_STATUS);
                  }

                  ptr += sizeof(*ArgusNetFlow);
                  break;
               }

               case CISCO_VERSION_8: {
//                ptr += sizeof(CiscoFlowEntryV8_t);
                  break;
               }

               case CISCO_VERSION_9: {
                  CiscoFlowEntryV9_t *ArgusNetFlow = (CiscoFlowEntryV9_t *) ptr;
                  int done = 0, flowset_id, flowset_len;

                  flowset_id  = ntohs(ArgusNetFlow->flowset_id);
                  flowset_len = ntohs(ArgusNetFlow->length);

                  switch (flowset_id) {
                     case k_CiscoV9TemplateFlowsetId: {
                        if (ArgusParseCiscoRecordV9Template(model, templates, (u_char *)(ArgusNetFlow + 1), (flowset_len - sizeof(*ArgusNetFlow))) == NULL) {
                        }
                        break;
                     }

                     case k_CiscoV9OptionsFlowsetId: {
                        done++;
                        break;
                     }

                     default: {
                        if (flowset_id >= k_CiscoV9MinRecordFlowsetId) {
                           if (ArgusParseCiscoRecordV9Data(model, templates, (u_char *)ArgusNetFlow, flowset_len) == NULL) {
                           }
                        }
                        done++;
                        break;
                     }
                  }
                  ptr += flowset_len;
                  break;
               }
            }
            break;
         }
      }
   }
*/

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusParseSflowRecord(%p, %p)", model, ptr);
#endif 
}

#endif
