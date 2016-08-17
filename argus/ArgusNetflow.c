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
 * $Id: //depot/argus/argus/argus/ArgusNetflow.c#23 $
 * $DateTime: 2011/01/26 17:21:20 $
 * $Change: 2089 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusNetflow)
#define ArgusNetflow

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#include <argus_compat.h>
#include <ArgusModeler.h>
#include <ArgusUtil.h>
#include <ArgusNetflow.h>

#include <arpa/inet.h>

struct ArgusRecord *ArgusParseCiscoRecordV9Data (struct ArgusParserStruct *, struct ArgusModelerStruct *, struct ArgusQueueStruct *, u_char *, int *);
struct ArgusRecord *ArgusParseCiscoRecordV9Template (struct ArgusModelerStruct *, struct ArgusQueueStruct *, u_char *, int);
struct ArgusRecord *ArgusParseCiscoRecordV9OptionTemplate (struct ArgusModelerStruct *, struct ArgusQueueStruct *, u_char *, int);


unsigned char *ArgusNetFlowRecordHeader = NULL;

unsigned char ArgusNetFlowArgusRecordBuf[4098];
struct ArgusRecord *ArgusNetFlowArgusRecord = (struct ArgusRecord *) ArgusNetFlowArgusRecordBuf;


struct ArgusCiscoTemplateStruct {
   int length, count;
   struct timeval lasttime;
   CiscoFlowTemplateFlowEntryV9_t **tHdr;
};

struct ArgusCiscoSourceStruct {
   struct ArgusQueueHeader qhdr;
   struct ArgusHashTableHeader htblbuf, *htblhdr;
   unsigned int srcid, saddr;
   struct timeval startime, lasttime;
   struct ArgusCiscoTemplateStruct templates[0x10000];
};

int ArgusCounter;
unsigned int ArgusFlowSeq = 0;
unsigned int ArgusCiscoSrcId = 0;
unsigned int ArgusCiscoSrcAddr = 0;
unsigned int ArgusSysUptime = 0;
struct timeval ArgusCiscoTvpBuf, *ArgusCiscoTvp = &ArgusCiscoTvpBuf;
struct ArgusQueueStruct *ArgusTemplateQueue = NULL;

void
ArgusParseCiscoRecord (struct ArgusModelerStruct *model, void *ptr)
{
   int ArgusReadSocketState = ARGUS_READINGPREHDR;
   int ArgusReadSocketSize = 0;

   unsigned short ArgusReadCiscoVersion;
// unsigned short ArgusReadSocketNum;

   if (ArgusTemplateQueue == NULL) 
      if ((ArgusTemplateQueue = ArgusNewQueue()) == NULL)
         ArgusLog (LOG_ERR, "ArgusParseCiscoRecord () ArgusNewQueue error %s\n", strerror(errno));

   while ((char *)ptr < (char *)model->ArgusThisSnapEnd) {
      switch (ArgusReadSocketState) {
         case ARGUS_READINGPREHDR: {
            unsigned short *sptr = (unsigned short *) ptr;
            ArgusReadCiscoVersion = ntohs(*sptr++);
//          ArgusReadSocketNum  = ntohs(*sptr);
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
                  ArgusCiscoTvp->tv_sec  = ntohl(ArgusNetFlow->unix_secs);
                  ArgusCiscoTvp->tv_usec = ntohl(ArgusNetFlow->unix_nsecs)/1000;
                  break;
               }

               case CISCO_VERSION_5: {
                  CiscoFlowHeaderV5_t *ArgusNetFlow = (CiscoFlowHeaderV5_t *) ptr;
                  ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                  ArgusSysUptime  = ntohl(ArgusNetFlow->sysUptime);
                  ArgusFlowSeq  = ntohl(ArgusNetFlow->flow_sequence);
                  ArgusCounter  =  ntohs(ArgusNetFlow->count);
                  ArgusCiscoTvp->tv_sec  = ntohl(ArgusNetFlow->unix_secs);
                  ArgusCiscoTvp->tv_usec = ntohl(ArgusNetFlow->unix_nsecs)/1000;
                  break;
               }

               case CISCO_VERSION_6: {
                  CiscoFlowHeaderV6_t *ArgusNetFlow = (CiscoFlowHeaderV6_t *) ptr;
                  ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                  ArgusSysUptime  = ntohl(ArgusNetFlow->sysUptime);
                  ArgusFlowSeq  = ntohl(ArgusNetFlow->flow_sequence);
                  ArgusCounter  =  0;
                  ArgusCiscoTvp->tv_sec  = ntohl(ArgusNetFlow->unix_secs);
                  ArgusCiscoTvp->tv_usec = ntohl(ArgusNetFlow->unix_nsecs)/1000;
                  break;
               }

               case CISCO_VERSION_7: {
                  CiscoFlowHeaderV7_t *ArgusNetFlow = (CiscoFlowHeaderV7_t *) ptr;
                  ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                  ArgusSysUptime  = ntohl(ArgusNetFlow->sysUptime);
                  ArgusFlowSeq    = ntohl(ArgusNetFlow->flow_sequence);
                  ArgusCounter    =  0;
                  ArgusCiscoTvp->tv_sec     = ntohl(ArgusNetFlow->unix_secs);
                  ArgusCiscoTvp->tv_usec    = ntohl(ArgusNetFlow->unix_nsecs)/1000;
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

                  ArgusSysUptime         = ntohl(ArgusNetFlow->sysUptime);
                  ArgusCiscoTvp->tv_sec  = ntohl(ArgusNetFlow->unix_secs);
                  ArgusCiscoTvp->tv_usec = 0;
                  ArgusFlowSeq           = ntohl(ArgusNetFlow->package_sequence);
                  ArgusCounter           = ntohs(ArgusNetFlow->count);
                  ArgusCiscoSrcId        = ntohl(ArgusNetFlow->source_id);

                  if (model->state & ARGUS_REVERSE)
                     ArgusCiscoSrcAddr   = model->ArgusThisFlow->flow_un.ip.ip_src;
                  else
                     ArgusCiscoSrcAddr   = model->ArgusThisFlow->flow_un.ip.ip_dst;

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
                     time->src.start.tv_sec  += ArgusCiscoTvp->tv_sec;

                     time->src.start.tv_usec  = ((timeval - (long)ArgusSysUptime)%1000) * 1000; 
                     time->src.start.tv_usec += ArgusCiscoTvp->tv_usec;

                     if (time->src.start.tv_usec >= 1000000) {
                        time->src.start.tv_sec++;
                        time->src.start.tv_usec -= 1000000;
                     }

                     timeval = ntohl(ArgusNetFlow->last);
                     time->src.end.tv_sec   = (timeval - (long)ArgusSysUptime)/1000;
                     time->src.end.tv_sec  += ArgusCiscoTvp->tv_sec;

                     time->src.end.tv_usec  = ((timeval - (long)ArgusSysUptime)%1000) * 1000;
                     time->src.end.tv_usec += ArgusCiscoTvp->tv_usec;

                     if (time->src.end.tv_usec >= 1000000) {
                        time->src.end.tv_sec++;
                        time->src.end.tv_usec -= 1000000;
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
                     int timeval, secs, usecs;

                     flow->canon.hdr.type         = ARGUS_FAR | ARGUS_NETFLOW | ARGUS_VERSION;

                     time->hdr.type               = ARGUS_TIME_DSR;
                     time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
                     time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
                     time->hdr.argus_dsrvl8.len   = 5;               

                     timeval = ntohl(ArgusNetFlow->first);
                     secs  = ArgusCiscoTvp->tv_sec  + ((timeval - (int)ArgusSysUptime) / 1000);
                     usecs = ArgusCiscoTvp->tv_usec + ((timeval - (int)ArgusSysUptime) % 1000) * 1000;

                     time->src.start.tv_sec  = secs;

                     if (usecs < 0) {
                        time->src.start.tv_sec--;
                        usecs += 1000000;
                     } else 
                     if (usecs > 1000000) {
                        time->src.start.tv_sec++;
                        usecs -= 1000000;
                     }
                     time->src.start.tv_usec = usecs;

                     timeval = ntohl(ArgusNetFlow->last);
                     secs  = ArgusCiscoTvp->tv_sec  + ((timeval - (int)ArgusSysUptime) / 1000);
                     usecs = ArgusCiscoTvp->tv_usec + ((timeval - (int)ArgusSysUptime) % 1000) * 1000;

                     time->src.end.tv_sec  = secs;

                     if (usecs < 0) {
                        time->src.end.tv_sec--;
                        usecs += 1000000;
                     } else 
                     if (usecs > 1000000) {
                        time->src.end.tv_sec++;
                        usecs -= 1000000;
                     } 
                     time->src.end.tv_usec = usecs;

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
                     time->src.start.tv_sec  += ArgusCiscoTvp->tv_sec;

                     time->src.start.tv_usec  = ((timeval - (long)ArgusSysUptime)%1000) * 1000; 
                     time->src.start.tv_usec += ArgusCiscoTvp->tv_usec;

                     if (time->src.start.tv_usec >= 1000000) {
                        time->src.start.tv_sec++;
                        time->src.start.tv_usec -= 1000000;
                     }

                     timeval = ntohl(ArgusNetFlow->last);
                     time->src.end.tv_sec   = (timeval - (long)ArgusSysUptime)/1000;
                     time->src.end.tv_sec  += ArgusCiscoTvp->tv_sec;

                     time->src.end.tv_usec  = ((timeval - (long)ArgusSysUptime)%1000) * 1000;
                     time->src.end.tv_usec += ArgusCiscoTvp->tv_usec;

                     if (time->src.end.tv_usec >= 1000000) {
                        time->src.end.tv_sec++;
                        time->src.end.tv_usec -= 1000000;
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
                     time->src.start.tv_sec  += ArgusCiscoTvp->tv_sec;

                     time->src.start.tv_usec  = ((timeval - (long)ArgusSysUptime)%1000) * 1000; 
                     time->src.start.tv_usec += ArgusCiscoTvp->tv_usec;

                     if (time->src.start.tv_usec >= 1000000) {
                        time->src.start.tv_sec++;
                        time->src.start.tv_usec -= 1000000;
                     }

                     timeval = ntohl(ArgusNetFlow->last);
                     time->src.end.tv_sec   = (timeval - (long)ArgusSysUptime)/1000;
                     time->src.end.tv_sec  += ArgusCiscoTvp->tv_sec;

                     time->src.end.tv_usec  = ((timeval - (long)ArgusSysUptime)%1000) * 1000;
                     time->src.end.tv_usec += ArgusCiscoTvp->tv_usec;

                     if (time->src.end.tv_usec >= 1000000) {
                        time->src.end.tv_sec++;
                        time->src.end.tv_usec -= 1000000;
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
                  if ((flowset_len = ntohs(ArgusNetFlow->length)) > 0) {
                     switch (flowset_id) {
                        case k_CiscoV9TemplateFlowsetId: {
                           if (ArgusParseCiscoRecordV9Template(model, ArgusTemplateQueue, (u_char *)(ArgusNetFlow + 1), (flowset_len - sizeof(*ArgusNetFlow))) == NULL) {
                           }
                           break;
                        }

                        case k_CiscoV9OptionsFlowsetId: {
                           if (ArgusParseCiscoRecordV9OptionTemplate(model, ArgusTemplateQueue, (u_char *)(ArgusNetFlow + 1), (flowset_len - sizeof(*ArgusNetFlow))) == NULL) {
                           }
                           break;
                        }

                        default: {
                           if (flowset_id >= k_CiscoV9MinRecordFlowsetId) {
                              ArgusParseCiscoRecordV9Data(ArgusParser, model, ArgusTemplateQueue, (u_char *) ptr, &ArgusCounter);
                           }
                           break;
                        }
                     }
                     ptr += flowset_len;
                     break;

                  } else
                     done++;
               }
            }
            break;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusParseCiscoRecord(%p, %p)", model, ptr);
#endif 
}

void
ArgusParseCiscoRecordV5 (struct ArgusModelerStruct *model, void *ptr)
{
#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV5 (%p, %p)\n", model, ptr);
#endif
}

void
ArgusParseCiscoRecordV6 (struct ArgusModelerStruct *model, void *ptr)
{
#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV6 (%p, %p)\n", model, ptr);
#endif
}


extern long long ArgusDiffTime (struct ArgusTime *, struct ArgusTime *, struct timeval *);

typedef struct value {
   union {
      uint8_t   val8[16];
      uint16_t  val16[8];
      uint32_t  val32[4];
      uint64_t  val64[2];
      uint64_t val128[2];
   };
} value_t;


struct ArgusRecord *
ArgusParseCiscoRecordV9Data (struct ArgusParserStruct *parser, struct ArgusModelerStruct *model, struct ArgusQueueStruct *tqueue, u_char *ptr, int *cnt)
{
   struct ArgusRecord *retn = NULL;
   struct ArgusCiscoTemplateStruct *templates = NULL;
   struct ArgusCiscoSourceStruct *src;
   int ArgusParsingIPv6 = 0;
   u_char *tptr = ptr;

   if (tqueue != NULL) {
      int i, count = tqueue->count;
      for (i = 0; (i < count) && (templates == NULL); i++) {
         src = (struct ArgusCiscoSourceStruct *)ArgusPopQueue (tqueue, ARGUS_LOCK);
         if ((src->srcid == ArgusCiscoSrcId) && (src->saddr == ArgusCiscoSrcAddr))
            templates = src->templates;
         ArgusAddToQueue(tqueue, &src->qhdr, ARGUS_LOCK);
      }
   }

   if (templates == NULL) 
      return(retn);

//  using the matching template, parse out a single record.  we need to update ptr and
//  len so that they represent marching through the buffer, parsing out the records.
//  

   {
      CiscoFlowEntryV9_t *cflow = (CiscoFlowEntryV9_t *) tptr;
      CiscoFlowTemplateHeaderV9_t *tHdr = NULL;
      CiscoFlowTemplateFlowEntryV9_t *tData;

      int flowset_id = ntohs(cflow->flowset_id);
      int length = ntohs(cflow->length);

      if (length) {
#define ARGUS_TEMPLATE_TIMEOUT	1800

         if ((tHdr = (CiscoFlowTemplateHeaderV9_t *) templates[flowset_id].tHdr) != NULL) {
            if ((templates[flowset_id].lasttime.tv_sec + ARGUS_TEMPLATE_TIMEOUT) > model->ArgusGlobalTime.tv_sec) {
               int i, count = tHdr->count, nflowPad = 3;
               struct ArgusFlowStruct flowbuf, *flow = &flowbuf;
               u_char *sptr = (u_char *)(cflow + 1);
               u_char *eptr = sptr + (length - sizeof(*cflow));

// process an entire flow set

               while (sptr < (eptr - nflowPad)) {
                  struct ArgusDSRHeader *dsr = (struct ArgusDSRHeader *) &ArgusNetFlowArgusRecordBuf[4];
                  bzero(flow, sizeof(*flow));

                  tData = (CiscoFlowTemplateFlowEntryV9_t *)(tHdr + 1);
                  retn = NULL;

                  for (i = 0; i < count; i++) {
                     value_t value;

                     bzero(&value, sizeof(value));
                     
                     switch (tData->length) {
                        case  1: value.val8[0] = *sptr; break;
                        case  2: value.val16[0] = EXTRACT_16BITS(sptr); break;
                        case  4: value.val32[0] = EXTRACT_32BITS(sptr); break;
                        case  8: value.val64[0] = EXTRACT_64BITS(sptr); break;
                        case 16: bcopy(sptr, &value.val128, 16); break;
                     }
                     sptr += tData->length;

                     switch (tData->type) {
                        case k_CiscoV9InBytes: {
                           flow->canon.metric.src.bytes = value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           flow->dsrs[ARGUS_METRIC_INDEX] = &flow->canon.metric.hdr;
                           break;
                        }
                        case k_CiscoV9InPackets: {
                           flow->canon.metric.src.pkts = value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           flow->dsrs[ARGUS_METRIC_INDEX] = &flow->canon.metric.hdr;
                           break;
                        }
                        case k_CiscoV9Flows: {
                           break;
                        }
                        case k_CiscoV9InProtocol: {
                           flow->canon.flow.flow_un.ipv6.ip_p = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9SrcTos: {
                           flow->canon.attr.src.tos = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           flow->dsrs[ARGUS_IPATTR_INDEX] = &flow->canon.attr.hdr;
                           break;
                        }
                        case k_CiscoV9TcpFlags: {
                           struct ArgusNetworkStruct *net = &flow->canon.net;
                           struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;
                           unsigned char flags =  value.val8[0];

                           net->hdr.type                = ARGUS_NETWORK_DSR;
                           net->hdr.subtype             = ARGUS_TCP_STATUS;
                           net->hdr.argus_dsrvl8.len    = 3;
                           net->net_union.tcpstatus.src = flags;

                           if (flags & TH_RST)
                              tcp->status |= ARGUS_RESET;

                           if (flags & TH_FIN)
                              tcp->status |= ARGUS_FIN;

                           if ((flags & TH_ACK) || (flags & TH_PUSH) || (flags & TH_URG))
                              tcp->status |= ARGUS_CON_ESTABLISHED;

                           switch (flags & (TH_SYN|TH_ACK)) {
                              case (TH_SYN):
                                 tcp->status |= ARGUS_SAW_SYN;
                                 break;

                              case (TH_SYN|TH_ACK):
                                 break;
                           }
                           flow->dsrindex |= 1 << ARGUS_NETWORK_INDEX;
                           flow->dsrs[ARGUS_NETWORK_INDEX] = (void *)net;
                           break;
                        }
                        case k_CiscoV9L4SrcPort: {
                           flow->canon.flow.flow_un.ipv6.sport = value.val16[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9IpV4SrcAddr: {
                           flow->canon.flow.flow_un.ipv6.ip_src[0] = value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9SrcMask: {
                           uint32_t mask = 0xffffffff << (32 - value.val8[0]);
                           flow->canon.flow.flow_un.ipv6.ip_src[3] = mask;
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9InputSnmp: {
                           break;
                        }
                        case k_CiscoV9L4DstPort: {
                           flow->canon.flow.flow_un.ipv6.dport = value.val16[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9IpV4DstAddr: {
                           flow->canon.flow.flow_un.ipv6.ip_dst[0] = value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9DstMask: {
                           uint32_t mask = 0xffffffff << (32 - value.val8[0]);
                           flow->canon.flow.flow_un.ipv6.ip_dst[3] = mask;
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9OutputSnmp: {
                           break;
                        }
                        case k_CiscoV9IpV4NextHop: {
                           break;
                        }
                        case k_CiscoV9SrcAS: {
                           flow->canon.asn.src_as = (tData->length == 2) ? value.val16[0] : value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_ASN_INDEX;
                           flow->dsrs[ARGUS_ASN_INDEX] = &flow->canon.asn.hdr;
                           break;
                        }
                        case k_CiscoV9DstAS: {
                           flow->canon.asn.dst_as = (tData->length == 2) ? value.val16[0] : value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_ASN_INDEX;
                           flow->dsrs[ARGUS_ASN_INDEX] = &flow->canon.asn.hdr;
                           break;
                        }
                        case k_CiscoV9BgpIpV4NextHop: {
                           break;
                        }
                        case k_CiscoV9MulDstPkts: {
                           break;
                        }
                        case k_CiscoV9MulDstBytes: {
                           break;
                        }
                        case k_CiscoV9LastSwitched: {
                           long timeval = (tData->length == 2) ? value.val16[0] : value.val32[0];
                           int secs, usecs;

                           secs  = ((timeval - ArgusSysUptime) / 1000);
                           usecs = ((timeval - ArgusSysUptime) % 1000) * 1000;

                           flow->canon.time.src.end.tv_sec   = ArgusCiscoTvp->tv_sec  + secs;
                           if (usecs < 0) {
                              flow->canon.time.src.end.tv_sec--;
                              usecs += 1000000;
                           }
                           flow->canon.time.src.end.tv_usec  = ArgusCiscoTvp->tv_usec + usecs;

                           flow->dsrindex |= 1 << ARGUS_TIME_INDEX;
                           flow->dsrs[ARGUS_TIME_INDEX] = &flow->canon.time.hdr;
                           break;
                        }
                        case k_CiscoV9FirstSwitched: {
                           long timeval = (tData->length == 2) ? value.val16[0] : value.val32[0];
                           int secs, usecs;

                           secs  = ((timeval - ArgusSysUptime) / 1000);
                           usecs = ((timeval - ArgusSysUptime) % 1000) * 1000;

                           flow->canon.time.src.start.tv_sec   = ArgusCiscoTvp->tv_sec  + secs;
                           if (usecs < 0) {
                              flow->canon.time.src.start.tv_sec--;
                              usecs += 1000000;
                           }
                           flow->canon.time.src.start.tv_usec  = ArgusCiscoTvp->tv_usec + usecs;

                           flow->dsrindex |= 1 << ARGUS_TIME_INDEX;
                           flow->dsrs[ARGUS_TIME_INDEX] = &flow->canon.time.hdr;
                           break;
                        }
                        case k_CiscoV9OutBytes: {
/*
                           flow->canon.metric.dst.bytes = value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           flow->dsrs[ARGUS_METRIC_INDEX] = &flow->canon.metric.hdr;
*/
                           break;
                        }
                        case k_CiscoV9OutPkts: {
/*
                           flow->canon.metric.dst.pkts = value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           flow->dsrs[ARGUS_METRIC_INDEX] = &flow->canon.metric.hdr;
*/
                           break;
                        }
                        case k_CiscoV9MinPktLen: {
                           flow->canon.psize.src.psizemin = value.val16[0];
                           flow->dsrindex |= 1 << ARGUS_PSIZE_INDEX;
                           flow->dsrs[ARGUS_PSIZE_INDEX] = &flow->canon.psize.hdr;
                           break;
                        }
                        case k_CiscoV9MaxPktLen: {
                           flow->canon.psize.src.psizemax = value.val16[0];
                           flow->dsrindex |= 1 << ARGUS_PSIZE_INDEX;
                           flow->dsrs[ARGUS_PSIZE_INDEX] = &flow->canon.psize.hdr;
                           break;
                        }
                        case k_CiscoV9IpV6SrcAddr: {
                           bcopy (&value, &flow->canon.flow.flow_un.ipv6.ip_src, 16);
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           ArgusParsingIPv6 = 1;
                           break;
                        }
                        case k_CiscoV9IpV6DstAddr: {
                           bcopy (&value, &flow->canon.flow.flow_un.ipv6.ip_dst, 16);
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           ArgusParsingIPv6 = 1;
                           break;
                        }
                        case k_CiscoV9IPV6SrcMask: {
                           break;
                        }
                        case k_CiscoV9IpV6DstMask: {
                           break;
                        }
                        case k_CiscoV9IpV6FlowLabel: {
                           break;
                        }
                        case k_CiscoV9IpV6IcmpType: {
                           struct ArgusICMPv6Flow *icmpv6Flow = &flow->canon.flow.icmpv6_flow;
                           icmpv6Flow->type = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9IpV6MulIgmpType: {
                           break;
                        }
                        case k_CiscoV9IpV6SamplingInterval: {
                           break;
                        }
                        case k_CiscoV9IpV6SamplingAlgorithm: {
                           break;
                        }
                        case k_CiscoV9FlowActiveTimeout: {
                           break;
                        }
                        case k_CiscoV9FlowInactiveTimeout: {
                           break;
                        }
                        case k_CiscoV9EngineType: {
                           break;
                        }
                        case k_CiscoV9EngineID: {
                           break;
                        }
                        case k_CiscoV9TotalBytesExp: {
                           break;
                        }
                        case k_CiscoV9TotalPktsExp: {
                           break;
                        }
                        case k_CiscoV9TotalFlowsExp: {
                           break;
                        }
                        case k_CiscoV9MplsTopLabelType: {
                           break;
                        }
                        case k_CiscoV9MplsTopLabelIPAddr: {
                           break;
                        }
                        case k_CiscoV9FlowSamplerID: {
                           break;
                        }
                        case k_CiscoV9FlowSamplerMode: {
                           break;
                        }
                        case k_CiscoV9FlowSamplerRandomInt: {
                           break;
                        }

                        case k_CiscoV9MinTtl: {
                           flow->canon.attr.src.ttl = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           flow->dsrs[ARGUS_IPATTR_INDEX] = &flow->canon.attr.hdr;
                           break;
                        }
                        case k_CiscoV9MaxTtl: {
                           flow->canon.attr.src.ttl = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           flow->dsrs[ARGUS_IPATTR_INDEX] = &flow->canon.attr.hdr;
                           break;
                        }
                        case k_CiscoV9IPv4IpId: {
                           flow->canon.attr.src.ip_id = value.val16[0];
                           flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           flow->dsrs[ARGUS_IPATTR_INDEX] = &flow->canon.attr.hdr;
                           break;
                        }
                        case k_CiscoV9DstTos: {
                           flow->canon.attr.dst.tos = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           flow->dsrs[ARGUS_IPATTR_INDEX] = &flow->canon.attr.hdr;
                           break;
                        }
                        case k_CiscoV9SrcMac: {
                           flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                           flow->dsrs[ARGUS_MAC_INDEX] = &flow->canon.mac.hdr;
                           break;
                        }
                        case k_CiscoV9DstMac: {
                           flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                           flow->dsrs[ARGUS_MAC_INDEX] = &flow->canon.mac.hdr;
                           break;
                        }
                        case k_CiscoV9SrcVlan: {
                           flow->canon.vlan.sid = value.val16[0];
                           flow->dsrindex |= 1 << ARGUS_VLAN_INDEX;
                           flow->dsrs[ARGUS_VLAN_INDEX] = &flow->canon.vlan.hdr;
                           break;
                        }
                        case k_CiscoV9DstVlan: {
                           flow->canon.vlan.did = value.val16[0];
                           flow->dsrindex |= 1 << ARGUS_VLAN_INDEX;
                           flow->dsrs[ARGUS_VLAN_INDEX] = &flow->canon.vlan.hdr;
                           break;
                        }
                        case k_CiscoV9IpProtocolVersion: {
                           break;
                        }
                        case k_CiscoV9Direction: {
                           break;
                        }
                        case k_CiscoV9IpV6NextHop: {
                           break;
                        }
                        case k_CiscoV9BgpIpV6NextHop: {
                           break;
                        }
                        case k_CiscoV9IpV6OptionHeaders: {
                           break;
                        }
                        case k_CiscoV9MplsLabel1: {
                           break;
                        }
                        case k_CiscoV9MplsLabel2: {
                           break;
                        }
                        case k_CiscoV9MplsLabel3: {
                           break;
                        }
                        case k_CiscoV9MplsLabel4: {
                           break;
                        }
                        case k_CiscoV9MplsLabel5: {
                           break;
                        }
                        case k_CiscoV9MplsLabel6: {
                           break;
                        }
                        case k_CiscoV9MplsLabel7: {
                           break;
                        }
                        case k_CiscoV9MplsLabel8: {
                           break;
                        }
                        case k_CiscoV9MplsLabel9: {
                           break;
                        }
                        case k_CiscoV9MplsLabel10: {
                           break;
                        }
                        case k_CiscoV9InDstMac: {
                           flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                           flow->dsrs[ARGUS_MAC_INDEX] = &flow->canon.mac.hdr;
                           break;
                        }
                        case k_CiscoV9OutSrcMac: {
                           flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                           flow->dsrs[ARGUS_MAC_INDEX] = &flow->canon.mac.hdr;
                           break;
                        }
                        case k_CiscoV9IfName: {
                           break;
                        }
                        case k_CiscoV9IfDesc: {
                           break;
                        }
                        case k_CiscoV9SampleName: {
                           break;
                        }
                        case k_CiscoV9InPermanentBytes: {
                           flow->canon.metric.src.bytes = value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           flow->dsrs[ARGUS_METRIC_INDEX] = &flow->canon.metric.hdr;
                           break;
                        }
                        case k_CiscoV9InPermanentPkts: {
                           break;
                        }
                        case k_CiscoV9FragmentOffset: {
                           break;
                        }
                        case k_CiscoV9ForwardingStatus: {
                           break;
                        }
                        case k_CiscoV9PostDSCP: {
                           break;
                        }
                        case k_CiscoV9NatInsideGlobalAddr: {
                           break;
                        }
                        case k_CiscoV9NatOutsideGlobalAddr: {
                           break;
                        }
                        case k_CiscoV9postNatL4SrcPort: {
                           break;
                        }
                        case k_CiscoV9postNatL4DstPort: {
                           break;
                        }
                        case k_CiscoV9postNatEvent: {
                           break;
                        }
                        case k_CiscoV9IngressVRFID: {
                           break;
                        }
                        case k_CiscoV9ConnId: {
                           break;
                        }
                        case k_CiscoV9IcmpType: {
                           break;
                        }
                        case k_CiscoV9IcmpCode: {
                           break;
                        }
                        case k_CiscoV9IcmpTypeV6: {
                           struct ArgusICMPv6Flow *icmpv6Flow = &flow->canon.flow.icmpv6_flow;
                           icmpv6Flow->type = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9IcmpCodeV6: {
                           struct ArgusICMPv6Flow *icmpv6Flow = &flow->canon.flow.icmpv6_flow;
                           icmpv6Flow->code = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoEventTimeMilliSec: {
                           break;
                        }
                        case k_CiscoEventTimeMicroSec: {
                           break;
                        }
                        case k_CiscoEventTimeNanoSec:  {
                           break;
                        }
                     }
                     tData++;
                  }

                  {
                     struct timeval tdiffbuf, *tdiff = &tdiffbuf;
                     flow->canon.hdr.type    = ARGUS_FAR | ARGUS_NETFLOW | ARGUS_VERSION;
                     flow->canon.hdr.cause   = ARGUS_STATUS;
                     flow->canon.hdr.len     = 1;

                     if (!(flow->dsrindex & (1 << ARGUS_TIME_INDEX))) {
                        struct ArgusTimeObject *ato = &flow->canon.time;
                        ato->src.start.tv_sec   = ArgusCiscoTvp->tv_sec;
                        ato->src.start.tv_usec  = ((long)(ArgusSysUptime)%1000) * 1000;
 
                        if (ato->src.start.tv_usec >= 1000000) {
                           ato->src.start.tv_sec++;
                           ato->src.start.tv_usec -= 1000000;
                        }
                        ato->src.end = ato->src.start;
                        flow->dsrindex |= 1 << ARGUS_TIME_INDEX;
                        flow->dsrs[ARGUS_TIME_INDEX] = (void *)ato;
                     }

                     if (ArgusDiffTime(&flow->canon.time.src.end, &flow->canon.time.src.start, tdiff) == 0) {
                        struct ArgusMetricStruct *metric = &flow->canon.metric;

#define ARGUS_DEFAULT_RATE	1000000.0f
                        if (metric->src.pkts > 1) {
                           double dtime = (metric->src.pkts * 1.0) / ARGUS_DEFAULT_RATE;
                           double itime;
                           double ftime = modf(dtime, &itime);
                           flow->canon.time.src.end.tv_sec  = flow->canon.time.src.start.tv_sec  + (itime);
                           flow->canon.time.src.end.tv_usec = flow->canon.time.src.start.tv_usec + (ftime * 1000000);
                           if (flow->canon.time.src.end.tv_usec >= 1000000) {
                              flow->canon.time.src.end.tv_usec  -= 1000000;
                              flow->canon.time.src.end.tv_sec++;
                           }
                        }
                     }

                     for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
                        if (flow->dsrindex & (1 << i)) {
                           switch(i) {
                              case ARGUS_FLOW_INDEX: {
                                 flow->canon.flow.hdr.type              = ARGUS_FLOW_DSR;
                                 flow->canon.flow.hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;

                                 if (ArgusParsingIPv6) {
                                    flow->canon.flow.hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV6;
                                    flow->canon.flow.hdr.argus_dsrvl8.len  = 11;

                                 } else {
                                    struct ArgusFlow tflow;
                                    bzero(&tflow, sizeof(tflow));
                                    tflow.flow_un.ip.ip_src = flow->canon.flow.flow_un.ipv6.ip_src[0];
                                    tflow.flow_un.ip.ip_dst = flow->canon.flow.flow_un.ipv6.ip_dst[0];
                                    tflow.flow_un.ip.ip_p   = flow->canon.flow.flow_un.ipv6.ip_p;
                                    tflow.flow_un.ip.sport  = flow->canon.flow.flow_un.ipv6.sport;
                                    tflow.flow_un.ip.dport  = flow->canon.flow.flow_un.ipv6.dport;
                                    tflow.flow_un.ip.smask  = flow->canon.flow.flow_un.ipv6.ip_src[3];
                                    tflow.flow_un.ip.dmask  = flow->canon.flow.flow_un.ipv6.ip_dst[3];

                                    flow->canon.flow.hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                                    flow->canon.flow.hdr.argus_dsrvl8.len  = 5;
                                    bcopy(&tflow.flow_un.ip, &flow->canon.flow.flow_un.ip, sizeof(tflow.flow_un.ip));
                                 }  

                                 bcopy(&flow->canon.flow, dsr, flow->canon.flow.hdr.argus_dsrvl8.len * 4);
                                 dsr += flow->canon.flow.hdr.argus_dsrvl8.len;
                                 flow->canon.hdr.len += flow->canon.flow.hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_TIME_INDEX: {
                                 struct ArgusTimeObject *time = &flow->canon.time;
                                 time->hdr.type               = ARGUS_TIME_DSR;
                                 time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
                                 time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
                                 time->hdr.argus_dsrvl8.len   = 5;
                                 bcopy(time, dsr, time->hdr.argus_dsrvl8.len * 4);
                                 dsr += time->hdr.argus_dsrvl8.len;
                                 flow->canon.hdr.len += time->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_ASN_INDEX: {
                                 struct ArgusAsnStruct *asn  = &flow->canon.asn;
                                 asn->hdr.type               = ARGUS_ASN_DSR;
                                 asn->hdr.subtype            = 0;
                                 asn->hdr.argus_dsrvl8.qual  = 0;
                                 asn->hdr.argus_dsrvl8.len   = 3;
                                 bcopy(asn, dsr, asn->hdr.argus_dsrvl8.len * 4);
                                 dsr += asn->hdr.argus_dsrvl8.len;
                                 flow->canon.hdr.len += asn->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_METRIC_INDEX: {
                                 struct ArgusMetricStruct *metric = &flow->canon.metric;
                                 int pkts, bytes;

                                 metric->hdr.type              = ARGUS_METER_DSR;
                                 metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
                                 metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_INT;
                                 metric->hdr.argus_dsrvl8.len  = 3;

                                 pkts  = metric->src.pkts;
                                 bytes = metric->src.bytes;

                                 bcopy(&metric->hdr, dsr, 4);
                                 bcopy(&pkts,  dsr+1, 4);
                                 bcopy(&bytes, dsr+2, 4);

                                 dsr += metric->hdr.argus_dsrvl8.len;
                                 flow->canon.hdr.len += metric->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_NETWORK_INDEX: {
                                 struct ArgusNetworkStruct *net = &flow->canon.net;
                                 bcopy(net, dsr, net->hdr.argus_dsrvl8.len * 4);
                                 dsr += net->hdr.argus_dsrvl8.len;
                                 flow->canon.hdr.len += net->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_MAC_INDEX: {
                                 struct ArgusMacStruct *mac = &flow->canon.mac;
                                 mac->hdr.type              = ARGUS_MAC_DSR;
                                 mac->hdr.subtype           = 0;
                                 mac->hdr.argus_dsrvl8.len  = 5;
                                 bcopy(mac, dsr, mac->hdr.argus_dsrvl8.len * 4);
                                 dsr += mac->hdr.argus_dsrvl8.len;
                                 flow->canon.hdr.len += mac->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_IPATTR_INDEX: {
                                 struct ArgusIPAttrStruct *attr = &flow->canon.attr;
                                 attr->hdr.type               = ARGUS_IPATTR_DSR;
                                 attr->hdr.subtype            = 0;
                                 attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
                                 attr->hdr.argus_dsrvl8.len   = 2;
                                 bcopy(attr, dsr, attr->hdr.argus_dsrvl8.len * 4);
                                 dsr += attr->hdr.argus_dsrvl8.len;
                                 flow->canon.hdr.len += attr->hdr.argus_dsrvl8.len;
                              }
                           }
                        }
                     }

                     ArgusSendFlowRecord (model, flow, ARGUS_STATUS);
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusParseCiscoRecordV9Data (%p, %p, %p, %p, %d) new flow %p\n", parser, model, tqueue, ptr, *cnt, retn);
#endif
                  }
                  ArgusParsingIPv6 = 0;
                  *cnt = *cnt - 1;
               }
               src->lasttime = model->ArgusGlobalTime;

            } else {
               if (templates[flowset_id].tHdr != NULL) {
                  ArgusFree(templates[flowset_id].tHdr);
                  bzero(&templates[flowset_id], sizeof(struct ArgusCiscoTemplateStruct));
                  templates[flowset_id].tHdr = NULL;
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV9Data (%p, %p, %p, %p, %d) returning %p\n", parser, model, tqueue, ptr, *cnt, retn);
#endif
   return(retn);
}

struct ArgusRecord *
ArgusParseCiscoRecordV9Template (struct ArgusModelerStruct *model, struct ArgusQueueStruct *tqueue, u_char *ptr, int len)
{
   struct ArgusCiscoTemplateStruct *templates = NULL;
   struct ArgusRecord *retn = NULL;
   struct ArgusCiscoSourceStruct *src;
   int i, done = 0;

   if (tqueue != NULL) {
      int cnt = tqueue->count;
      for (i = 0; (i < cnt) && (templates == NULL); i++) {
         src = (struct ArgusCiscoSourceStruct *)ArgusPopQueue (tqueue, ARGUS_LOCK);
         if ((src->srcid == ArgusCiscoSrcId) && (src->saddr == ArgusCiscoSrcAddr))
            templates = src->templates;
         ArgusAddToQueue(tqueue, &src->qhdr, ARGUS_LOCK);
      }
   }

   if (templates == NULL) {
      if ((src = (struct ArgusCiscoSourceStruct *)ArgusCalloc (1, sizeof(*src))) == NULL)
         ArgusLog(LOG_ERR, "ArgusParseCiscoRecordV9Template: ArgusCalloc(%d, %d) error %s\n", 1, sizeof(*src), strerror(errno));

      src->srcid = ArgusCiscoSrcId;
      src->saddr = ArgusCiscoSrcAddr;
      src->startime = model->ArgusGlobalTime;
      src->lasttime = model->ArgusGlobalTime;
      templates = src->templates;
      ArgusAddToQueue (tqueue, &src->qhdr, ARGUS_LOCK);
   }

   if (templates) {
      while (!done) {
         CiscoFlowTemplateHeaderV9_t *tHdr = (CiscoFlowTemplateHeaderV9_t *) ptr;
         CiscoFlowTemplateFlowEntryV9_t *tData = (CiscoFlowTemplateFlowEntryV9_t *)(tHdr + 1);
         CiscoFlowTemplateFlowEntryV9_t **dArray = NULL;
         int slen = 0;

         tHdr->template_id = ntohs(tHdr->template_id);
         tHdr->count = ntohs(tHdr->count);

         slen = (sizeof(*tData) * tHdr->count) + sizeof(*tHdr);
         
         if (templates[tHdr->template_id].tHdr != NULL) {

#ifdef ARGUSDEBUG
            unsigned long addr = htonl(ArgusCiscoSrcAddr);
            char *srcAddr = (inet_ntoa(*(struct in_addr *)&addr));

            ArgusDebug (3, "ArgusParseCiscoRecordV9Template: pkt %d changing template src %s srcid %d tid %d \n", 
               model->ArgusTotalPacket, srcAddr, ArgusCiscoSrcId, tHdr->template_id);
#endif
            ArgusFree(templates[tHdr->template_id].tHdr);
            templates[tHdr->template_id].tHdr =  NULL;

            templates[tHdr->template_id].length = slen + 4;
            templates[tHdr->template_id].count = tHdr->count;

         }  else {
#ifdef ARGUSDEBUG
            unsigned long addr = htonl(ArgusCiscoSrcAddr);
            char *srcAddr = (inet_ntoa(*(struct in_addr *)&addr));

            ArgusDebug (3, "ArgusParseCiscoRecordV9Template: pkt %d new template src %s srcid %d tid %d \n",
               model->ArgusTotalPacket, srcAddr, ArgusCiscoSrcId, tHdr->template_id);
#endif
         }

         if ((dArray = ArgusCalloc(1, slen + 4)) == NULL)
            ArgusLog(LOG_ERR, "ArgusCalloc(%d, %d) error %s\n", tHdr->count, sizeof(*tData), strerror(errno));

         for (i = 0; i < tHdr->count; i++) {
            tData->type   = ntohs(tData->type);
            tData->length = ntohs(tData->length);
            tData++;
         }

         bcopy(tHdr, dArray, slen);
         templates[tHdr->template_id].tHdr = dArray;
         templates[tHdr->template_id].lasttime = model->ArgusGlobalTime;

         if ((len - slen) > 0) {
            ptr += slen;
            len -= slen;
         } else
            done = 1;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV9Template (%p, %p, %d, %p) returning %p\n", model, templates, ptr, len);
#endif
   return(retn);
}

struct ArgusRecord *
ArgusParseCiscoRecordV9OptionTemplate (struct ArgusModelerStruct *model, struct ArgusQueueStruct *tqueue, u_char *ptr, int len)
{
   struct ArgusCiscoTemplateStruct *templates = NULL;
   struct ArgusRecord *retn = NULL;
   struct ArgusCiscoSourceStruct *src;
   int i;

   if (tqueue != NULL) {
      int cnt = tqueue->count;
      for (i = 0; (i < cnt) && (templates == NULL); i++) {
         src = (struct ArgusCiscoSourceStruct *)ArgusPopQueue (tqueue, ARGUS_LOCK);
         if ((src->srcid == ArgusCiscoSrcId) && (src->saddr == ArgusCiscoSrcAddr))
            templates = src->templates;
         ArgusAddToQueue(tqueue, &src->qhdr, ARGUS_LOCK);
      }
   }

   if (templates) {
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV9OptionTemplate (%p, %p) returning %p\n", model, ptr, retn);
#endif
   return(retn);
}

#endif
