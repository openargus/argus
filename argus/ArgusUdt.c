/*
 * Argus Software.  Argus files - Udt protocol processing
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
 * $Id: //depot/argus/argus/argus/ArgusUdt.c#10 $
 * $DateTime: 2015/06/29 16:17:25 $
 * $Change: 3027 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusUdt)
#define ArgusUdt
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <argus_compat.h>
#include <ArgusModeler.h>

#include <argus/bootp.h>
struct bootp *bp;

struct ArgusSystemFlow *
ArgusCreateUDTFlow (struct ArgusModelerStruct *model, struct udt_header *udt)
{
   struct ArgusSystemFlow *retn = NULL;
   struct ArgusSystemFlow *tflow = model->ArgusThisFlow;

   if (STRUCTCAPTURED(model, *udt)) {
      struct ether_header *ep = model->ArgusThisMacHdr;
      if (ep != NULL) {
         if (model->ArgusFlowType == ARGUS_BIDIRECTIONAL) {
            int dstgteq = 1, i;
            tflow->hdr.type              = ARGUS_FLOW_DSR;
            tflow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
            tflow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_UDT;
            tflow->hdr.argus_dsrvl8.len  = 6;
#ifndef ETH_ALEN
#define ETH_ALEN   6
#endif
            for (i = 0; i < ETH_ALEN; i++) {
               if (((unsigned char *)&ep->ether_shost)[i] != ((unsigned char *)&ep->ether_dhost)[i]) {
                  if (((unsigned char *)&ep->ether_shost)[i] > ((unsigned char *)&ep->ether_dhost)[i])
                     dstgteq = 0;
                  break;
               }
            }

            if (dstgteq) {
               bcopy ((char *) ep, (char *)&tflow->udt_flow.mac.mac_union.ether.ehdr, sizeof (struct ether_header));
            } else {
               model->state |= ARGUS_DIRECTION;
               bcopy ((char *)&ep->ether_shost, (char *)&tflow->udt_flow.mac.mac_union.ether.ehdr.ether_dhost, ETH_ALEN);
               bcopy ((char *)&ep->ether_dhost, (char *)&tflow->udt_flow.mac.mac_union.ether.ehdr.ether_shost, ETH_ALEN);
               tflow->udt_flow.mac.mac_union.ether.ehdr.ether_type = ep->ether_type;
            }

            if (model->ArgusThisEncaps & ARGUS_ENCAPS_LLC) {
               tflow->udt_flow.mac.mac_union.ether.ehdr.ether_type = 0;
               switch (model->ArgusThisNetworkFlowType & 0xFFFF) {
                  case ARGUS_ISIS:
                     tflow->udt_flow.mac.mac_union.ether.ehdr.ether_type = ARGUS_ISIS;
                     break;

                  default:
                     model->ArgusThisNetworkFlowType &= ~(0xFFFF);
                     break;
               }
               if (dstgteq) {
                  tflow->udt_flow.mac.mac_union.ether.ssap = model->ArgusThisLLC->ssap;
                  tflow->udt_flow.mac.mac_union.ether.dsap = model->ArgusThisLLC->dsap;
               } else {
                  tflow->udt_flow.mac.mac_union.ether.ssap = model->ArgusThisLLC->dsap;
                  tflow->udt_flow.mac.mac_union.ether.dsap = model->ArgusThisLLC->ssap;
               }
            } else {
               tflow->udt_flow.mac.mac_union.ether.ssap = 0;
               tflow->udt_flow.mac.mac_union.ether.dsap = 0;
            }

            switch (ntohs(udt->un_udt.cntl.type) & UDT_PACKET_MASK) {
               case UDT_CONTROL_PACKET: {
                  struct udtoe_control_hdr *udtc = (void *) ((char *)udt + UDTOECONTROLPAD);
                  tflow->udt_flow.sockid = EXTRACT_32BITS(&udtc->sockid);
                  break;
               }
               case UDT_DATA_PACKET: {
                  struct udt_data_hdr *udtd = (void *) udt;
                  tflow->udt_flow.sockid = EXTRACT_32BITS(&udtd->sockid);
                  break;
               }
            }

            if (model->state & ARGUS_DIRECTION) {
               tflow->hdr.argus_dsrvl8.qual |= ARGUS_DIRECTION;
               tflow->hdr.subtype           |= ARGUS_REVERSE;
            }

            retn = tflow;
         }
      }
   }
   return (retn);
}


void ArgusUpdateUDToEState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);
void ArgusUpdateUDTState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);

void
ArgusUpdateUDToEState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char *state)
{
   struct udtoe_header *udt = (struct udtoe_header *) model->ArgusThisUpHdr;
   u_char *nxtHdr = (u_char *)(udt + 1);

   if (STRUCTCAPTURED(model, *udt)) {
      model->ArgusThisLength -= sizeof(*udt);
      model->ArgusSnapLength -= sizeof(*udt);
      model->ArgusThisUpHdr = nxtHdr;

      if (*state == ARGUS_START) {

      } else {
         struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) flowstr->dsrs[ARGUS_NETWORK_INDEX];

         struct ArgusUDTObjectMetrics *ArgusThisUdtMetric;

         if (model->ArgusThisDir) {
            ArgusThisUdtMetric = &net->net_union.udt.src;
         } else {
            ArgusThisUdtMetric = &net->net_union.udt.dst;
         }

         if ((flowstr->canon.metric.src.pkts + flowstr->canon.metric.dst.pkts) > 2)
            flowstr->timeout = ARGUS_IPTIMEOUT;

         switch (udt->un_udt.cntl.type & UDTOE_PACKET_MASK) {
            case UDTOE_CONTROL_PACKET: {
               struct udtoe_control_hdr *udtc = (void *) ((char *)udt + UDTOECONTROLPAD);
               unsigned char type = ((udtc->type & 0x7F) >> 3);

               model->ArgusThisLength -= 48;

               switch (type & UDTOE_CONTROL_TYPE_MASK) {
                  case UDTOE_CONTROL_HANDSHAKE: {
                     struct udt_control_handshake *hshake = (void *) (udtc + 1);
                     if (ntohl(hshake->version) == 4) {
                        ArgusThisUdtHshake = hshake;
                        hshake->version = ntohl(hshake->version);
                        hshake->socktype = ntohl(hshake->socktype);
                        hshake->initseq = ntohl(hshake->initseq);
                        hshake->psize = ntohl(hshake->psize);
                        hshake->wsize = ntohl(hshake->wsize);
                        hshake->conntype = ntohl(hshake->conntype);
                        hshake->sockid = ntohl(hshake->sockid);
                     }
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDToEState(%p, %d) UDT_CONTROL_HANDSHAKE type %d seqNum %d size %d maxWin %d conn %d sockid 0x%x\n", 
                                flowstr, *state, hshake->socktype, hshake->initseq, hshake->psize, hshake->wsize, hshake->conntype, hshake->sockid);
#endif
                     break;
                  }

                  case UDTOE_CONTROL_KEEPALIVE: {
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDToEState(%p, %d) UDT_CONTROL_KEEPALIVE\n", flowstr, *state);
#endif
                     break;
                  }

                  case UDTOE_CONTROL_ACK: {
                     struct udt_control_ack *ack = (void *) (udtc + 1);
                     int len = model->ArgusThisLength/4;

                     if (len--) { ArgusThisUdtMetric->ack   = ntohl(ack->ackseqnum);
                     if (len--) { ArgusThisUdtMetric->rtt   = ntohl(ack->rtt);
                     if (len--) { ArgusThisUdtMetric->var   = ntohl(ack->var);
                     if (len--) { ArgusThisUdtMetric->bsize = ntohl(ack->bsize);
                                  if (ack->bsize == 0) {
                                     net->net_union.udt.status |= ARGUS_WINDOW_SHUT;
                                  }
                     if (len--) { ArgusThisUdtMetric->rate  = ntohl(ack->rate);
                     if (len--) { ArgusThisUdtMetric->lcap  = ntohl(ack->lcap); }}}}}}
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDToEState(%p, %d) UDT_CONTROL_ACK, sockid 0x%x ack = 0x%x\n", 
                         flowstr, *state, ntohl(udtc->sockid), net->net_union.udt.src.ack);
#endif
                     break;
                  }

                  case UDTOE_CONTROL_NAK: {
                     struct udt_control_nak *nak = (void *) (udtc + 1);
                     int num = 0, len = model->ArgusThisLength/4;
                     unsigned int *sptr = &nak->seqnum;
                     int i, fitem, sseq, eseq, range;
#ifdef ARGUSDEBUG
                     char buf[256];
                     *buf = '\0';
#endif
                     for (i = 0, fitem = 0; i < len; i++, sptr++) {
                        *sptr = ntohl(*sptr);
                        if (*sptr & 0x80000000) {
                           sseq = *sptr & 0x7FFFFFFF;
                           range = 1;
                        } else {
                           eseq = *sptr;
                           if (range) {
#ifdef ARGUSDEBUG
                              if (fitem++)
                                 sprintf(&buf[strlen(buf)], ",0x%x-0x%x", sseq, eseq);
                              else
                                 sprintf(&buf[strlen(buf)], "0x%x-0x%x", sseq, eseq);
#endif
                              num += (eseq - sseq) + 1;
                              range = 0;
                           } else {
#ifdef ARGUSDEBUG
                              if (fitem++)
                                 sprintf(&buf[strlen(buf)], ",0x%x", eseq);
                              else
                                 sprintf(&buf[strlen(buf)], "0x%x", eseq);
#endif
                              fitem++;
                              num++;
                           }
                        }
                     }
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDToEState(%p, %d) UDT_CONTROL_NAK, sockid 0x%x nak.comp[%d] num %d %s", 
                           flowstr, *state, ntohl(udtc->sockid), len, num, buf);
#endif
                     if (num)
                        ArgusThisUdtMetric->nacked += num;
                     break;
                  }

                  case UDTOE_CONTROL_CONGEST: {
                     net->net_union.udt.status |= ARGUS_ECN_CONGESTED;
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDToEState(%p, %d) UDT_CONTROL_CONGEST, sockid 0x%x", 
                           flowstr, *state, ntohl(udtc->sockid));
#endif
                     break;
                  }

                  case UDTOE_CONTROL_SHUTDOWN: {
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDToEState(%p, %d) UDT_CONTROL_SHUTDOWN\n", flowstr, *state);
#endif
                     break;
                  }
                  case UDTOE_CONTROL_ACKACK: {
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDToEState(%p, %d) UDT_CONTROL_ACKACK\n", flowstr, *state);
#endif
                     break;
                  }

                  case UDTOE_CONTROL_DROPREQ: {
                     struct udt_control_dropreq *drop = (void *)(udtc + 1);
                     if (drop->firstseqnum == 0)
                        if (net != NULL)
                           net->net_union.udt.status |= ARGUS_UDT_FIRSTDROPZERO;
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDToEState(%p, %d) UDT_CONTROL_DROPREQ\n", flowstr, *state);
#endif
                     break;
                  }

                  default: {
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDToEState(%p, %d) UDT_CONTROL_UNKNOWN\n", flowstr, *state);
#endif
                     break;
                  }
               }
               break;
            }
/*
struct ArgusUDTObjectMetrics {
   struct ArgusTime lasttime;
   unsigned int seq, tstamp, ack, rtt, var, bsize, rate, lcap;
   int solo, first, middle, last, drops, retrans, nacked;
};

struct ArgusUDTObject {
   unsigned int state, status;
   struct udt_control_handshake hshake;
   struct ArgusUDTObjectMetrics src;
};
*/
            case UDT_DATA_PACKET: {
               struct udt_data_hdr *udtd = (void *) udt;
               unsigned int seqnum = ntohl(udtd->seqnum);
               unsigned int msgnum = ntohl(udtd->msgnum);
               unsigned int tstamp = ntohl(udtd->tstamp);
#ifdef ARGUSDEBUG
               unsigned int sockid = ntohl(udtd->sockid);
#endif
               int seq = ArgusThisUdtMetric->seq;
               int loss = 0;;

#define ARGUS_UDT_MSGTYPE	0xC0000000
#define ARGUS_UDT_SOLO_MSG	0xC0000000
#define ARGUS_UDT_FIRST_MSG	0x80000000
#define ARGUS_UDT_MIDDLE_MSG	0x00000000
#define ARGUS_UDT_LAST_MSG	0x40000000

               switch (msgnum & ARGUS_UDT_MSGTYPE) {
                  case ARGUS_UDT_SOLO_MSG:
                     ArgusThisUdtMetric->solo++;
                     break;
                  case ARGUS_UDT_FIRST_MSG:
                     ArgusThisUdtMetric->first++;
                     break;
                  case ARGUS_UDT_MIDDLE_MSG:
                     ArgusThisUdtMetric->middle++;
                     break;
                  case ARGUS_UDT_LAST_MSG:
                     ArgusThisUdtMetric->last++;
                     break;
               }
/*
               msgnum &= 0x1FFFFFFF;
*/
               if (seqnum == (seq + 1)) {
                  ArgusThisUdtMetric->lasttime.tv_sec  = model->ArgusGlobalTime.tv_sec;
                  ArgusThisUdtMetric->lasttime.tv_usec = model->ArgusGlobalTime.tv_usec;
                  ArgusThisUdtMetric->tstamp = tstamp;
                  ArgusThisUdtMetric->seq = seqnum;

               } else {
                  if (seq > 0) {
                     if (seqnum > (seq + 2)) {
                        loss = seqnum - (seq + 1);
                        ArgusThisUdtMetric->drops += loss;
                        net->net_union.udt.status |= ARGUS_PKTS_DROP;
                        ArgusThisUdtMetric->seq = seqnum;
                     } else {
                        if (seqnum != (seq + 1)) {
                           ArgusThisUdtMetric->retrans++;
                           net->net_union.udt.status |= ARGUS_PKTS_RETRANS;
                        } else {
                           ArgusThisUdtMetric->lasttime.tv_sec  = model->ArgusGlobalTime.tv_sec;
                           ArgusThisUdtMetric->lasttime.tv_usec = model->ArgusGlobalTime.tv_usec;
                           ArgusThisUdtMetric->tstamp = tstamp;
                           ArgusThisUdtMetric->seq = seqnum;
                        }
                     }

                  } else {
                     ArgusThisUdtMetric->lasttime.tv_sec  = model->ArgusGlobalTime.tv_sec;
                     ArgusThisUdtMetric->lasttime.tv_usec = model->ArgusGlobalTime.tv_usec;
                     ArgusThisUdtMetric->tstamp = tstamp;
                     ArgusThisUdtMetric->seq = seqnum;
                  }
               }

#ifdef ARGUSDEBUG
               ArgusDebug (4, "ArgusUpdateUDToEState(%p, %d) UDT_DATA_PACKET seq 0x%x msgnum 0x%x tstmp 0x%x sockid 0x%x loss %d\n", 
                                 flowstr, *state, seqnum, msgnum, tstamp, sockid, loss);
#endif
               break;
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusUpdateUDToEState(%p, %d) returning\n", flowstr, *state);
#endif
}


void
ArgusUpdateUDTState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char *state)
{
   struct udt_header *udt = (struct udt_header *) model->ArgusThisUpHdr;
   u_char *nxtHdr = (u_char *)(udt + 1);

   if (STRUCTCAPTURED(model, *udt)) {
      model->ArgusThisLength -= sizeof(*udt);
      model->ArgusSnapLength -= sizeof(*udt);
      model->ArgusThisUpHdr = nxtHdr;

      if (*state == ARGUS_START) {

      } else {
         struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) flowstr->dsrs[ARGUS_NETWORK_INDEX];

         if ((flowstr->canon.metric.src.pkts + flowstr->canon.metric.dst.pkts) > 2)
            flowstr->timeout = ARGUS_IPTIMEOUT;

         switch (ntohs(udt->un_udt.cntl.type) & UDT_PACKET_MASK) {
            case UDT_CONTROL_PACKET: {
               struct udt_control_hdr *udtc = (void *) udt;
               unsigned short type = EXTRACT_16BITS(&udtc->type);

               switch (type & UDT_CONTROL_TYPE_MASK) {
                  case UDT_CONTROL_HANDSHAKE: {
                     struct udt_control_handshake *hshake = (void *) (udtc + 1);
                     if (ntohl(hshake->version) == 4) {
                        ArgusThisUdtHshake = hshake;
                     } else {
                     }
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDTState(%p, %d) UDT_CONTROL_HANDSHAKE\n", flowstr, *state);
#endif
                     break;
                  }

                  case UDT_CONTROL_KEEPALIVE: {
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDTState(%p, %d) UDT_CONTROL_KEEPALIVE\n", flowstr, *state);
#endif
                     break;
                  }

                  case UDT_CONTROL_ACK: {
                     struct udt_control_ack *ack = (void *) (udtc + 1);
                     int len = model->ArgusThisLength/4;

                     if (len--) { net->net_union.udt.src.ack   = ntohl(ack->ackseqnum);
                     if (len--) { net->net_union.udt.src.rtt   = ntohl(ack->rtt);
                     if (len--) { net->net_union.udt.src.var   = ntohl(ack->var);
                     if (len--) { net->net_union.udt.src.bsize = ntohl(ack->bsize);
                                  if (ack->bsize == 0) {
                                     net->net_union.udt.status |= ARGUS_WINDOW_SHUT;
                                  }
                     if (len--) { net->net_union.udt.src.rate  = ntohl(ack->rate);
                     if (len--) { net->net_union.udt.src.lcap  = ntohl(ack->lcap); }}}}}}
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDTState(%p, %d) UDT_CONTROL_ACK, sockid 0x%x ack = 0x%x\n", 
                         flowstr, *state, udtc->sockid, net->net_union.udt.src.ack);
#endif
                     break;
                  }

                  case UDT_CONTROL_NAK: {
                     struct udt_control_nak *nak = (void *) (udtc + 1);
                     int num = 0, len = model->ArgusThisLength/4;
                     unsigned int *sptr = &nak->seqnum, value;
                     int i, fitem, sseq, eseq, range;
#ifdef ARGUSDEBUG
                     char buf[256];
                     *buf = '\0';
#endif
                     for (i = 0, fitem = 0; i < len; i++, sptr++) {
                        if (BYTESCAPTURED(ArgusModel, sptr, 4)) {
                           value = ntohl(*sptr);
                           if (value & 0x80000000) {
                              sseq = value & 0x7FFFFFFF;
                              range = 1;
                           } else {
#ifdef ARGUSDEBUG
                              int slen = sizeof(buf) - strlen(buf);
#endif
                              eseq = value;
                              if (range) {
#ifdef ARGUSDEBUG
                                 if (fitem++)
                                    snprintf(&buf[strlen(buf)], slen, ",0x%x-0x%x", sseq, eseq);
                                 else
                                    snprintf(&buf[strlen(buf)], slen, "0x%x-0x%x", sseq, eseq);
#endif
                                 num += (eseq - sseq) + 1;
                                 range = 0;
                              } else {
#ifdef ARGUSDEBUG
                                 if (fitem++)
                                    snprintf(&buf[strlen(buf)], slen, ",0x%x", eseq);
                                 else
                                    snprintf(&buf[strlen(buf)], slen, "0x%x", eseq);
#endif
                                 fitem++;
                                 num++;
                              }
                           }
                        } else
                           break;
                     }
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDTState(%p, %d) UDT_CONTROL_NAK, sockid 0x%x nak.comp[%d] num %d %s", 
                           flowstr, *state, udtc->sockid, len, num, buf);
#endif
                     if (num)
                        net->net_union.udt.src.nacked += num;
                     break;
                  }

                  case UDT_CONTROL_CONGEST: {
                     net->net_union.udt.status |= ARGUS_ECN_CONGESTED;
                     break;
                  }

                  case UDT_CONTROL_SHUTDOWN: {
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDTState(%p, %d) UDT_CONTROL_SHUTDOWN\n", flowstr, *state);
#endif
                     break;
                  }
                  case UDT_CONTROL_ACKACK: {
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDTState(%p, %d) UDT_CONTROL_ACKACK\n", flowstr, *state);
#endif
                     break;
                  }

                  case UDT_CONTROL_DROPREQ: {
                     struct udt_control_dropreq *drop = (void *)(udtc + 1);
                     if (drop->firstseqnum == 0)
                        if (net != NULL)
                           net->net_union.udt.status |= ARGUS_UDT_FIRSTDROPZERO;
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDTState(%p, %d) UDT_CONTROL_DROPREQ\n", flowstr, *state);
#endif
                     break;
                  }

                  default: {
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusUpdateUDTState(%p, %d) UDT_CONTROL_UNKNOWN\n", flowstr, *state);
#endif
                     break;
                  }
               }
               break;
            }
/*
struct ArgusUDTObjectMetrics {
   struct ArgusTime lasttime;
   unsigned int seq, tstamp, ack, rtt, var, bsize, rate, lcap;
   int solo, first, middle, last, drops, retrans, nacked;
};

struct ArgusUDTObject {
   unsigned int state, status;
   struct udt_control_handshake hshake;
   struct ArgusUDTObjectMetrics src;
};
*/
            case UDT_DATA_PACKET: {
               struct udt_data_hdr *udtd = (void *) udt;
               unsigned int seqnum = ntohl(udtd->seqnum);
               unsigned int msgnum = ntohl(udtd->msgnum);
               unsigned int tstamp = ntohl(udtd->tstamp);
#ifdef ARGUSDEBUG
               unsigned int sockid = ntohl(udtd->sockid);
#endif
               int loss = 0;

#define ARGUS_UDT_MSGTYPE	0xC0000000
#define ARGUS_UDT_SOLO_MSG	0xC0000000
#define ARGUS_UDT_FIRST_MSG	0x80000000
#define ARGUS_UDT_MIDDLE_MSG	0x00000000
#define ARGUS_UDT_LAST_MSG	0x40000000

               switch (msgnum & ARGUS_UDT_MSGTYPE) {
                  case ARGUS_UDT_SOLO_MSG:
                     net->net_union.udt.src.solo++;
                     break;
                  case ARGUS_UDT_FIRST_MSG:
                     net->net_union.udt.src.first++;
                     break;
                  case ARGUS_UDT_MIDDLE_MSG:
                     net->net_union.udt.src.middle++;
                     break;
                  case ARGUS_UDT_LAST_MSG:
                     net->net_union.udt.src.last++;
                     break;
               }
/*
               msgnum &= 0x1FFFFFFF;
*/
               if (net->net_union.udt.src.seq > 0) {
                  if (seqnum > (net->net_union.udt.src.seq + 2)) {
                     loss = seqnum - (net->net_union.udt.src.seq + 1);
                     net->net_union.udt.src.drops += loss;
                     net->net_union.udt.status |= ARGUS_PKTS_DROP;
                     net->net_union.udt.src.seq = seqnum;
                  } else {
                     if (seqnum != (net->net_union.udt.src.seq + 1)) {
                        net->net_union.udt.src.retrans++;
                        net->net_union.udt.status |= ARGUS_PKTS_RETRANS;
                     } else {
                        net->net_union.udt.src.lasttime.tv_sec  = model->ArgusGlobalTime.tv_sec;
                        net->net_union.udt.src.lasttime.tv_usec = model->ArgusGlobalTime.tv_usec;
                        net->net_union.udt.src.tstamp = tstamp;
                        net->net_union.udt.src.seq = seqnum;
                     }
                  }

               } else {
                  net->net_union.udt.src.lasttime.tv_sec  = model->ArgusGlobalTime.tv_sec;
                  net->net_union.udt.src.lasttime.tv_usec = model->ArgusGlobalTime.tv_usec;
                  net->net_union.udt.src.tstamp = tstamp;
                  net->net_union.udt.src.seq = seqnum;
               }

#ifdef ARGUSDEBUG
               ArgusDebug (4, "ArgusUpdateUDTState(%p, %d) UDT_DATA_PACKET seq 0x%x msgnum 0x%x tstmp 0x%x sockid 0x%x loss %d\n", 
                                 flowstr, *state, seqnum, msgnum, tstamp, sockid, loss);
#endif
               break;
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusUpdateUDTState(%p, %d) returning\n", flowstr, *state);
#endif
}


#include <argus_out.h>

void ArgusUDTFlowRecord (struct ArgusFlowStruct *, struct ArgusRecord *, unsigned char);

void
ArgusUDTFlowRecord (struct ArgusFlowStruct *flow, struct ArgusRecord *argus, unsigned char state)
{
}


struct udt_control_handshake *ArgusThisUdtHshake = NULL;
int ArgusParseUDToEHeader (struct ArgusModelerStruct *, struct udt_header *, unsigned int *);

int
ArgusParseUDToEHeader (struct ArgusModelerStruct *model, struct udt_header *udt, unsigned int *status)
{
   int retn = 0;

   ArgusThisUdtHshake = NULL;

   if (STRUCTCAPTURED(model, *udt)) {
      switch (udt->un_udt.cntl.type & UDTOE_PACKET_MASK) {
         case UDTOE_CONTROL_PACKET: {
            struct udtoe_control_hdr *udtc = (void *) ((char *)udt + UDTOECONTROLPAD);
            switch ((udtc->type & 0x7F) >> 3) {
               case UDTOE_CONTROL_HANDSHAKE: {
                  struct udt_control_handshake *hshake = (void *) (udtc + 1);
                  if (ntohl(hshake->version) == 4) {
                     ArgusThisUdtHshake = hshake;
                     retn = 1;
                  } else
                     *status |= ARGUS_UDT_BADVERSION;
                  break;
               }
               case UDTOE_CONTROL_KEEPALIVE:
                  retn = 1;
                  break;

               case UDTOE_CONTROL_ACK: {
                  retn = 1;
                  break;
               }
               case UDTOE_CONTROL_NAK:
                  retn = 1;
                  break;
               case UDTOE_CONTROL_SHUTDOWN:
                  retn = 1;
                  break;
               case UDTOE_CONTROL_ACKACK:
                  retn = 1;
                  break;

               case UDTOE_CONTROL_DROPREQ: {
                  struct udt_control_dropreq *drop = (void *)(udtc + 1);
                  if (drop->firstseqnum == 0)
                     *status |= ARGUS_UDT_FIRSTDROPZERO;
                  retn = 1;
                  break;
               }
            }
            break;
         }
         case UDT_DATA_PACKET: 
            retn = 1;
            break;
      }
   }

   return (retn);
}


int
ArgusParseUDTHeader (struct ArgusModelerStruct *model, struct udt_header *udt, unsigned int *status)
{
   int retn = 0;

   ArgusThisUdtHshake = NULL;

   if (STRUCTCAPTURED(model, *udt)) {
      switch (ntohs(udt->un_udt.cntl.type) & UDT_PACKET_MASK) {
         case UDT_CONTROL_PACKET: {
            struct udt_control_hdr *udtc = (void *) udt;
            switch ((ntohs(udtc->type) & 0x78) >> 3) {
               case UDT_CONTROL_HANDSHAKE: {
                  struct udt_control_handshake *hshake = (void *) (udt + 1);
                  if (ntohl(hshake->version) == 4) {
                     ArgusThisUdtHshake = hshake;
                     retn = 1;
                  } else 
                     *status |= ARGUS_UDT_BADVERSION;
                  break;
               }
               case UDT_CONTROL_KEEPALIVE:
                  retn = 1;
                  break;

               case UDT_CONTROL_ACK: {
/*
                  struct udt_control_ack *ack = (void *) (udt + 1);
*/
                  retn = 1;
                  break;
               }
               case UDT_CONTROL_NAK:
                  retn = 1;
                  break;
               case UDT_CONTROL_SHUTDOWN:
                  retn = 1;
                  break;
               case UDT_CONTROL_ACKACK:
                  retn = 1;
                  break;

               case UDT_CONTROL_DROPREQ: {
                  struct udt_control_dropreq *drop = (void *)(udt + 1);
                  if (drop->firstseqnum == 0)
                     *status |= ARGUS_UDT_FIRSTDROPZERO;
                  retn = 1;
                  break;
               }
            }
            break;
         }
         case UDT_DATA_PACKET: 
            retn = 1;
            break;
      }
   }

   return (retn);
}
