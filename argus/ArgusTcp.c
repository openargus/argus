/*
 * Argus Software.  Argus files - TCP protocol
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
 * $Id: //depot/argus/argus/argus/ArgusTcp.c#51 $
 * $DateTime: 2015/07/02 10:42:46 $
 * $Change: 3030 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusTcp)
#define ArgusTcp
#endif


#include <argus_compat.h>
#include <ArgusModeler.h>

#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>

extern void ArgusZeroRecord(struct ArgusFlowStruct *);


/* These tcp optinos do not have the size octet */
#define ZEROLENOPT(o) ((o) == TCPOPT_EOL || (o) == TCPOPT_NOP)

#if !defined(TH_ECE)
#define TH_ECE  0x40
#endif
#if !defined(TH_CWR)
#define TH_CWR  0x80
#endif

void ArgusParseTCPOptions(struct ArgusModelerStruct *, struct tcphdr *, int, u_int *, struct ArgusTCPObjectMetrics *);
void ArgusInitializeTCP (struct ArgusModelerStruct *, struct ArgusFlowStruct *);
void ArgusUpdateTCPState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);
int ArgusUpdateTCPSequence (struct ArgusModelerStruct *, struct ArgusFlowStruct *, struct tcphdr *);
void ArgusTCPKeystroke (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);
int ArgusUpdateTCPStateMachine (struct ArgusModelerStruct *, struct ArgusFlowStruct *, struct tcphdr *);
void ArgusTCPFlowRecord (struct ArgusNetworkStruct *, unsigned char);
long long ArgusDiffTime (struct ArgusTime *, struct ArgusTime *, struct timeval *);



#include <errno.h>
#include <string.h>

void
ArgusUpdateTCPState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char *state)
{
   struct ArgusTCPObjectMetrics *ArgusThisTCPsrc, *ArgusThisTCPdst;
   struct tcphdr *thdr = (struct tcphdr *) model->ArgusThisUpHdr;
   struct tcphdr tcpbuf, *tcp = &tcpbuf;
   struct ArgusTCPObject *tcpExt = NULL;

   if (thdr && STRUCTCAPTURED(model, *thdr)) {
      int tcplen = model->ArgusThisLength;
      int tcphlen = thdr->th_off * 4;
      int tcpdatalen = tcplen - tcphlen;
      unsigned char flags = thdr->th_flags;

#ifdef _LITTLE_ENDIAN
      bzero ((char *)tcp, sizeof(tcpbuf));
      tcp->th_dport = ntohs(thdr->th_dport);
      tcp->th_sport = ntohs(thdr->th_sport);
      tcp->th_seq   = ntohl(thdr->th_seq);
      tcp->th_ack   = ntohl(thdr->th_ack);
      tcp->th_win   = ntohs(thdr->th_win);
      tcp->th_flags = thdr->th_flags;
#else
      bcopy ((char *) thdr, (char *)tcp, sizeof(tcpbuf));
#endif
      if (*state == ARGUS_START) {
         struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) &flowstr->canon.net;
         net->hdr.type             = ARGUS_NETWORK_DSR;
         net->hdr.subtype          = ARGUS_TCP_INIT;
         net->hdr.argus_dsrvl8.len = ((sizeof(struct ArgusTCPInitStatus)+3))/4 + 1;
         net->hdr.argus_dsrvl8.qual = 0;
         flowstr->dsrs[ARGUS_NETWORK_INDEX] = (struct ArgusDSRHeader *) net;
         tcpExt                    = &net->net_union.tcp;
         bzero ((char *)tcpExt, sizeof(*tcpExt));

         model->ArgusSnapLength -= tcphlen;
         model->ArgusThisLength  = tcpdatalen;
         model->ArgusThisUpHdr  += tcphlen;

         if (model->ArgusThisDir) {
            ArgusThisTCPsrc = &tcpExt->src;
            ArgusThisTCPdst = &tcpExt->dst;
         } else {
            ArgusThisTCPsrc = &tcpExt->dst;
            ArgusThisTCPdst = &tcpExt->src;
         }

         if ((tcphlen -= sizeof(*tcp)) > 0)
            ArgusParseTCPOptions (model, thdr, tcphlen, &tcpExt->options, ArgusThisTCPsrc);

         if (flags & TH_RST) {
            tcpExt->status |= ARGUS_RESET;
            ArgusThisTCPsrc->status  |= ARGUS_RESET;
            tcpExt->state             = TCPS_LISTEN;
            ArgusThisTCPsrc->bytes   += model->ArgusThisLength;
            ArgusThisTCPsrc->flags   |= flags;

            if (tcp->th_seq) {
               ArgusThisTCPsrc->seqbase  = tcp->th_seq - 1;
               ArgusThisTCPsrc->seq      = tcp->th_seq + model->ArgusThisLength;
            } else {
               ArgusThisTCPsrc->seqbase  = tcp->th_ack - 1;
               ArgusThisTCPsrc->seq      = tcp->th_ack - 1;
            }

            ArgusThisTCPdst->ack      = tcp->th_ack - 1;

            ArgusThisTCPsrc->lasttime.tv_sec  = model->ArgusGlobalTime.tv_sec;
            ArgusThisTCPsrc->lasttime.tv_usec = model->ArgusGlobalTime.tv_usec;

         } else {
            switch (flags & (TH_SYN|TH_ACK|TH_FIN|TH_PUSH|TH_URG)) {
               case (TH_SYN):
                  tcpExt->status      |= ARGUS_SAW_SYN;
                  tcpExt->state        = TCPS_SYN_SENT;
                  ArgusThisTCPsrc->bytes   += model->ArgusThisLength;
                  ArgusThisTCPsrc->seqbase  = tcp->th_seq; 
                  ArgusThisTCPsrc->seq      = tcp->th_seq; 
                  ArgusThisTCPsrc->win      = tcp->th_win;
                  ArgusThisTCPsrc->flags   |= flags; 
      
                  if ((flags & (TH_ECE|TH_CWR)) == (TH_ECE|TH_CWR))
                     tcpExt->options |= ARGUS_TCP_SRC_ECN;
                  break;
         
               case (TH_SYN|TH_ACK): {
                  tcpExt->status      |= ARGUS_SAW_SYN_SENT;
                  tcpExt->state        = TCPS_SYN_RECEIVED;
                  ArgusThisTCPsrc->bytes   += model->ArgusThisLength;
                  ArgusThisTCPsrc->seqbase  = tcp->th_seq;
                  ArgusThisTCPsrc->seq      = tcp->th_seq;
                  ArgusThisTCPsrc->win      = tcp->th_win;
                  ArgusThisTCPsrc->flags   |= flags; 

                  ArgusThisTCPdst->ack      = tcp->th_ack - 1;

                  if ((tcp->th_flags & (TH_ECE|TH_CWR)) == TH_ECE)
                     tcpExt->options |= ARGUS_TCP_DST_ECN;
                  break;
               }
      
               case (TH_ACK):
               case (TH_PUSH|TH_ACK):
               case (TH_URG|TH_ACK):
               case (TH_PUSH|TH_URG|TH_ACK):
                  ArgusThisTCPdst->ack      = tcp->th_ack - 1;

               case (TH_PUSH):
               case (TH_URG):
               case (TH_PUSH|TH_URG):
                  tcpExt->status      |= ARGUS_CON_ESTABLISHED;
                  tcpExt->state        = TCPS_ESTABLISHED;
                  ArgusThisTCPsrc->bytes   += model->ArgusThisLength;
                  ArgusThisTCPsrc->flags   |= flags; 
                  ArgusThisTCPsrc->seqbase  = tcp->th_seq - 1;

                  ArgusThisTCPsrc->seq      = tcp->th_seq + model->ArgusThisLength;
                  ArgusThisTCPsrc->win      = tcp->th_win;
                  break;
      
               case (TH_FIN):
               case (TH_FIN|TH_ACK):
                  tcpExt->status      |= ARGUS_FIN;
                  tcpExt->state        = TCPS_FIN_WAIT_1;
                  ArgusThisTCPsrc->bytes   += model->ArgusThisLength;
                  ArgusThisTCPsrc->flags   |= flags; 
                  ArgusThisTCPsrc->seqbase  = tcp->th_seq - 1;

                  ArgusThisTCPsrc->seq      = tcp->th_seq + model->ArgusThisLength;
                  ArgusThisTCPsrc->win      = tcp->th_win;
                  break;
      
               default:
                  tcpExt->status      |= ARGUS_CON_ESTABLISHED;
                  tcpExt->state        = TCPS_CLOSING;
                  ArgusThisTCPsrc->bytes   += model->ArgusThisLength;
                  ArgusThisTCPsrc->flags   |= flags; 
                  ArgusThisTCPsrc->seqbase  = tcp->th_seq - 1;

                  ArgusThisTCPsrc->seq      = tcp->th_seq + model->ArgusThisLength;
                  
                  if (!(flags & TH_RST))
                     ArgusThisTCPsrc->win      = tcp->th_win;
                  break;
            }

            ArgusThisTCPsrc->lasttime.tv_sec  = model->ArgusGlobalTime.tv_sec;
            ArgusThisTCPsrc->lasttime.tv_usec = model->ArgusGlobalTime.tv_usec;
         }

      } else {

#define ARGUS_ECN_FLAGS         (ARGUS_TCP_SRC_ECN | ARGUS_TCP_DST_ECN)
  
         tcpExt = (struct ArgusTCPObject *)&flowstr->canon.net.net_union.tcp;

         if (model->ArgusThisDir) {
            ArgusThisTCPsrc = &tcpExt->src;
            ArgusThisTCPdst = &tcpExt->dst;
         } else {
            ArgusThisTCPsrc = &tcpExt->dst;
            ArgusThisTCPdst = &tcpExt->src;
         }

         switch (tcpExt->state) {
            case TCPS_LISTEN: {
               if (flags & TH_SYN) {
                  ArgusSendFlowRecord (model, flowstr, ARGUS_STOP);
                  ArgusInitializeTCP (model, flowstr);
                  ArgusRemoveFromQueue(flowstr->qhdr.queue, &flowstr->qhdr, ARGUS_LOCK);
                  ArgusPushQueue(model->ArgusStatusQueue, &flowstr->qhdr, ARGUS_LOCK);

                  *state = ARGUS_START;
//                ArgusUpdateBasicFlow (model, flowstr, ARGUS_START);
//                ArgusUpdateTCPState (model, flowstr, state);
               }
               ArgusThisTCPsrc->flags   |= flags;
               break;
            }

            default: {
               if (getArgusTCPflag(model)) {
                  flowstr->canon.net.hdr.subtype          = ARGUS_TCP_PERF;
                  flowstr->canon.net.hdr.argus_dsrvl8.len = ((sizeof(struct ArgusTCPObject)+3))/4 + 1;
               } else {
                  flowstr->canon.net.hdr.subtype          = ARGUS_TCP_STATUS;
               }

               model->ArgusSnapLength -= tcphlen;
               model->ArgusThisLength  = tcpdatalen;
               model->ArgusThisUpHdr  += tcphlen;

               if ((tcphlen - sizeof(*tcp)) > 0)
                  ArgusParseTCPOptions (model, thdr, (tcphlen - sizeof(*tcp)), &tcpExt->options, ArgusThisTCPsrc);
   
               ArgusThisTCPsrc->flags |= flags;

               if ((tcpExt->options & ARGUS_ECN_FLAGS) && (flags & TH_ECE)) {
                  if (flags & TH_ACK) {
                     if (model->ArgusThisDir) {
                        tcpExt->status |= ARGUS_SRC_CONGESTED;
                     } else {
                        tcpExt->status |= ARGUS_DST_CONGESTED;
                     }
                  }
               }

               if (ArgusUpdateTCPSequence(model, flowstr, tcp)) {
                  switch (ArgusUpdateTCPStateMachine(model, flowstr, tcp)) {
                     case TCPS_LISTEN:
                        if (flags == TH_SYN) {
                           ArgusThisTCPsrc->bytes -= model->ArgusThisLength;
                           model->ArgusThisUpHdr  -= tcphlen;
                           model->ArgusThisLength = tcplen;
                           model->ArgusSnapLength += tcphlen;

                           ArgusRemoveFromQueue (flowstr->qhdr.queue, &flowstr->qhdr, ARGUS_LOCK);
                           ArgusSendFlowRecord (model, flowstr, ARGUS_STOP);
                           ArgusInitializeTCP (model, flowstr);
                           ArgusPushQueue(model->ArgusStatusQueue, &flowstr->qhdr, ARGUS_LOCK);
                           return;
                        }
                        break;
   
                     case TCPS_CLOSED:
                     case TCPS_TIME_WAIT:
                        if (!(tcpExt->status & ARGUS_RESET))
                           tcpExt->status |= ARGUS_NORMAL_CLOSE;
                        flowstr->timeout = 10;
                        break;
                  }
               }
            }
            ArgusThisTCPsrc->lasttime.tv_sec  = model->ArgusGlobalTime.tv_sec;
            ArgusThisTCPsrc->lasttime.tv_usec = model->ArgusGlobalTime.tv_usec;
         }
      }
   }
}

void
ArgusInitializeTCP (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flow)
{
   struct ArgusSystemFlow *fdsr = (struct ArgusSystemFlow *)flow->dsrs[ARGUS_FLOW_INDEX];
   struct ArgusTCPObject *tcpExt = (struct ArgusTCPObject *)&flow->canon.net.net_union.tcp;
   bzero ((char *)tcpExt, sizeof(*tcpExt));

   if (fdsr) {
      if (!(model->ArgusThisDir)) {
         fdsr->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
         fdsr->hdr.subtype           &= ~ARGUS_REVERSE;
      }
   }

   flow->state         = model->state & ARGUS_DIRECTION;
   model->ArgusThisDir = 1;

   flow->qhdr.lasttime = model->ArgusGlobalTime;

   ArgusUpdateFlow (model, flow, ARGUS_START, 0);
}


int
ArgusUpdateTCPStateMachine (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, struct tcphdr *tcp)
{
   struct ArgusTCPObjectMetrics *ArgusThisTCPsrc, *ArgusThisTCPdst;
   unsigned char flags = tcp->th_flags;
   struct ArgusTCPObject *tcpExt = (struct ArgusTCPObject *)&flowstr->canon.net.net_union.tcp;
   unsigned int state = tcpExt->state;
   int len = model->ArgusThisLength;

   if (model->ArgusThisDir) {
      ArgusThisTCPsrc = &tcpExt->src;
      ArgusThisTCPdst = &tcpExt->dst;
   } else {
      ArgusThisTCPsrc = &tcpExt->dst;
      ArgusThisTCPdst = &tcpExt->src;
   }

   if (flags & TH_RST) {
      tcpExt->status |= ARGUS_RESET;
      ArgusThisTCPsrc->status |= ARGUS_RESET;

      if (state == TCPS_SYN_SENT) {
         if (ArgusThisTCPdst->seq == ArgusThisTCPsrc->ack)
             state = TCPS_LISTEN;
         else
             state = TCPS_CLOSING;
      } else { 
         if ((tcp->th_seq >= ArgusThisTCPsrc->ack) &&
                    (tcp->th_seq < (ArgusThisTCPsrc->ack + (ArgusThisTCPsrc->win >> ArgusThisTCPsrc->winshift))))
            state = TCPS_CLOSED;
         else
             state = TCPS_CLOSING;
      }

   } else {
      switch (state) {
         case TCPS_LISTEN:
         case TCPS_SYN_SENT:
            if (flags == TH_SYN) {
               ArgusThisTCPsrc->status |= ARGUS_PKTS_RETRANS;
               ArgusThisTCPsrc->retrans++;
            } else
            if (flags == (TH_SYN|TH_ACK)) {
               if (ArgusThisTCPsrc->status & ARGUS_SAW_SYN) {
                  state = TCPS_LISTEN;
                  tcpExt->status |= ARGUS_SAW_SYN_SENT;
                  ArgusThisTCPsrc->status |= ARGUS_SAW_SYN_SENT;

               } else {
                  state = TCPS_SYN_RECEIVED;
                  tcpExt->status |= ARGUS_SAW_SYN_SENT;
                  ArgusThisTCPsrc->status |= ARGUS_SAW_SYN_SENT;

                  if (ArgusThisTCPdst->seq == ArgusThisTCPsrc->ack) {
                     struct timeval lasttime;
                     lasttime.tv_sec  = ArgusThisTCPdst->lasttime.tv_sec;
                     lasttime.tv_usec = ArgusThisTCPdst->lasttime.tv_usec;

                     tcpExt->synAckuSecs = ArgusAbsTimeDiff (&model->ArgusGlobalTime, &lasttime);
                  }
               }

            } else
            if (flags & TH_FIN) {
               state = TCPS_FIN_WAIT_1;
               tcpExt->status |= ARGUS_FIN;
               ArgusThisTCPsrc->status |= ARGUS_FIN;
            } else 
            if (flags & TH_ACK) {
               state = TCPS_ESTABLISHED;
               tcpExt->status |= ARGUS_CON_ESTABLISHED;
               ArgusThisTCPsrc->status |= ARGUS_CON_ESTABLISHED;
/*
               flowstr->ArgusTimeout = ARGUS_IPTIMEOUT;
*/
            }
            break;
    
         case TCPS_SYN_RECEIVED:
            if (flags & TH_FIN) {
               state = TCPS_FIN_WAIT_1;
               tcpExt->status |= ARGUS_FIN;
               ArgusThisTCPsrc->status |= ARGUS_FIN;

            } else
            if (!(flags & TH_SYN)) {
               if (flags & TH_ACK) {
                  state = TCPS_ESTABLISHED;
                  tcpExt->status |= ARGUS_CON_ESTABLISHED;
/*
                  flowstr->ArgusTimeout = ARGUS_IPTIMEOUT;
*/
                  ArgusThisTCPsrc->status |= ARGUS_CON_ESTABLISHED;
                  if (ArgusThisTCPsrc->seq == ArgusThisTCPdst->ack) {
                     struct timeval lasttime;
                     lasttime.tv_sec  = ArgusThisTCPdst->lasttime.tv_sec;
                     lasttime.tv_usec = ArgusThisTCPdst->lasttime.tv_usec;

                     tcpExt->ackDatauSecs = ArgusAbsTimeDiff (&model->ArgusGlobalTime, &lasttime);
                  }
               }

            } else {
               ArgusThisTCPsrc->status |= ARGUS_PKTS_RETRANS;
               ArgusThisTCPsrc->retrans++;
            }

            break;
    
         case TCPS_ESTABLISHED:
            if (flags & TH_FIN) {
               state = TCPS_FIN_WAIT_1;
               tcpExt->status |= ARGUS_FIN;
               ArgusThisTCPsrc->status |= ARGUS_FIN;

            } else {
               if (flags & TH_SYN) {
                  if (flags & TH_ACK) {
                     tcpExt->status |= ARGUS_SAW_SYN_SENT;
                     tcpExt->status |= ARGUS_CON_ESTABLISHED;
                  }
                  ArgusThisTCPsrc->status |= ARGUS_PKTS_RETRANS;
                  ArgusThisTCPsrc->retrans++;
               }
            }
            break;
    
         case TCPS_CLOSE_WAIT:
         case TCPS_FIN_WAIT_1:
            if ((flags & TH_SYN) && !(flags & TH_ACK)) {
               state = TCPS_LISTEN;
            } else

         case TCPS_LAST_ACK:
         case TCPS_FIN_WAIT_2:
            if (flags & TH_FIN) {
               if (!(flags & TH_ACK)) {
                  if (ArgusThisTCPdst->status & ARGUS_FIN_ACK) {
                     ArgusThisTCPsrc->status |= ARGUS_PKTS_RETRANS;
                     ArgusThisTCPsrc->retrans++;
                  }
               } else {
                  tcpExt->status |= ARGUS_FIN;
                  ArgusThisTCPsrc->status |= ARGUS_FIN;
               }
            }

            if ((flags & TH_ACK) && !(len)) {
               if (ArgusThisTCPdst->status & ARGUS_FIN) {
                  if (ArgusThisTCPdst->seq == ArgusThisTCPsrc->ack) {
                     state = TCPS_FIN_WAIT_2;
                     tcpExt->status |= ARGUS_FIN_ACK;
                     ArgusThisTCPdst->status |= ARGUS_FIN_ACK;
                  }
               }
            }

            break;
      
         case TCPS_CLOSING:
         case TCPS_TIME_WAIT:
            if ((flags & TH_SYN) && !(flags & TH_ACK))
               state = TCPS_LISTEN;
            else
            if (flags & TH_ACK)
               if ((ArgusThisTCPsrc->seq == ArgusThisTCPsrc->ack) &&
                         (ArgusThisTCPdst->seq == ArgusThisTCPsrc->ack))
                  state = TCPS_CLOSED;
            break;
         
         case TCPS_CLOSED:
            if ((flags & TH_SYN) && !(flags & TH_ACK))
               state = TCPS_LISTEN;
            break;
      }
   }

   if (state != TCPS_LISTEN)
      tcpExt->state = state;
   
   return (state);
}


int
ArgusUpdateTCPSequence (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, struct tcphdr *tcp)
{
   struct ArgusTCPObjectMetrics *ArgusThisTCPsrc, *ArgusThisTCPdst;
   struct ArgusTCPObject *tcpExt = (struct ArgusTCPObject *)&flowstr->canon.net.net_union.tcp;
   unsigned char flags = tcp->th_flags;
   int len = model->ArgusThisLength;

   int retn = 1, win, ArgusDuplicatePacket = 0;
   unsigned int maxseq = 0;
   unsigned int seq = tcp->th_seq;
   unsigned int newseq = seq + len;
   struct ArgusIPAttrStruct *attr = NULL;
   unsigned short ipid = 0, *tipid;

   if (model->ArgusThisDir) {
      ArgusThisTCPsrc = &tcpExt->src;
      ArgusThisTCPdst = &tcpExt->dst;
   } else {
      ArgusThisTCPsrc = &tcpExt->dst;
      ArgusThisTCPdst = &tcpExt->src;
   }
 
   if ((attr = (struct ArgusIPAttrStruct *) flowstr->dsrs[ARGUS_IPATTR_INDEX]) != NULL) {
      if (model->ArgusThisDir) {
         if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC)
            ipid = attr->src.ip_id;
         tipid = &flowstr->sipid;
      } else {
         if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST) 
            ipid = attr->dst.ip_id;
         tipid = &flowstr->dipid;
      }
   }

   if (flags == TH_SYN)           /* we started over */
      return (retn);

   model->ArgusInProtocol = 1;

   if (!(tcp->th_win) && !(flags & (TH_FIN|TH_RST))) {
      ArgusThisTCPsrc->status |= ARGUS_WINDOW_SHUT;
      model->ArgusInProtocol = 0;
   } else {
      if (!(flags & (TH_FIN|TH_RST))) {
         ArgusThisTCPsrc->win = tcp->th_win;
      }
   }

   if (len && (ArgusThisTCPdst->win != 0)) {
      ArgusThisTCPsrc->bytes += len;

      if (ArgusThisTCPsrc->winbytes == 0)
         model->ArgusInProtocol = 0;

      if (ArgusThisTCPsrc->flags & TH_FIN) {
         if (tcp->th_seq < ArgusThisTCPsrc->seq) {
            ArgusThisTCPsrc->retrans++;
            ArgusThisTCPsrc->status |= ARGUS_PKTS_RETRANS;
         } else
            if (!(flags & TH_FIN))
               ArgusThisTCPsrc->status |= ARGUS_OUTOFORDER;
      }

      if (!(flags & TH_SYN))
         ArgusThisTCPsrc->winbytes += len;

   } else
      model->ArgusInProtocol = 0;

   if (newseq < seq) {                                 /* we rolled over */
      ArgusThisTCPsrc->ackbytes += ArgusThisTCPsrc->seq - ArgusThisTCPsrc->seqbase; /* ackbytes holds the number of rollover bytes */
      ArgusThisTCPsrc->seqbase = newseq;
      ArgusThisTCPsrc->seq = newseq;

   } else {
      if (!ArgusThisTCPsrc->seqbase) {                 /* first packet in this direction */
         ArgusThisTCPsrc->seqbase = seq;
         ArgusThisTCPsrc->seq = newseq;
      } else {

         if (len) {
            if (model->ArgusTrackDuplicates && (tipid && ((ipid != 0) && (*tipid == ipid)))) {
               if (model->ArgusThisDir) 
                  ArgusThisTCPsrc->status |= ARGUS_SRC_DUPLICATES;
               else
                  ArgusThisTCPdst->status |= ARGUS_DST_DUPLICATES;
               ArgusDuplicatePacket = 1;

            } else {
               if (ArgusThisTCPdst->win != 0) {           /* not first packet seen in this direction */
                  if (tcp->th_seq < ArgusThisTCPdst->ack) {
                     if ((ArgusThisTCPdst->ack - tcp->th_seq) < (ArgusThisTCPsrc->win >> ArgusThisTCPsrc->winshift)) {
                        ArgusThisTCPsrc->retrans++;
                        ArgusThisTCPsrc->status |= ARGUS_PKTS_RETRANS;
                        ArgusThisTCPsrc->winbytes -= len;
                        model->ArgusInProtocol = 0;
                     }

                  } else {
                     if (newseq > ArgusThisTCPsrc->seq) {
                        maxseq = newseq;
                     } else {
                        maxseq = ArgusThisTCPsrc->seq;
                     }

                     if (ArgusThisTCPsrc->win) {
                        int dipid;
                        if (*tipid && ((dipid = (ipid - *tipid)) < 0) && (dipid > -5000)) {
                           ArgusThisTCPsrc->status |= ARGUS_OUTOFORDER;
                        } else
                        if (ArgusThisTCPsrc->winbytes > ((maxseq - 1) - ArgusThisTCPdst->ack)) {
                           ArgusThisTCPsrc->retrans++;
                           ArgusThisTCPsrc->status |= ARGUS_PKTS_RETRANS;
                           ArgusThisTCPsrc->winbytes -= len;
                           model->ArgusInProtocol = 0;

                        } else {
                           if (newseq < ArgusThisTCPsrc->seq) {
                              if (tcp->th_seq == (ArgusThisTCPdst->ack + 1)) {
                                 ArgusThisTCPsrc->retrans++;
                                 ArgusThisTCPsrc->status |= ARGUS_PKTS_RETRANS;
                                 ArgusThisTCPsrc->winbytes -= len;
                              } else {
                                 ArgusThisTCPsrc->status |= ARGUS_OUTOFORDER;
                              }
                           }
                        }
                     }

                     ArgusThisTCPsrc->seq = maxseq;
                  }
               }

               *tipid = ipid;
            }

         } else {
         }
      }
   }


   if (!(ArgusDuplicatePacket)) {
      if (tcp->th_ack && (flags & TH_ACK)) {
         if (ArgusThisTCPsrc->ack) {
            if (ArgusThisTCPdst->seq > ArgusThisTCPsrc->ack)
               ArgusThisTCPdst->winbytes = (ArgusThisTCPdst->seq - 1) - ArgusThisTCPsrc->ack;  
         }

         if (!(ArgusThisTCPsrc->ack == (tcp->th_ack - 1))) {
            if (!(ArgusThisTCPsrc->ack) || (ArgusThisTCPdst->seq == tcp->th_ack)) {

               ArgusThisTCPdst->winbytes = 0;
               if (!(ArgusThisTCPsrc->ack == (tcp->th_ack - 1)))
                  if (ArgusThisTCPdst->seq == tcp->th_ack)
                     ArgusThisTCPdst->winnum++;

            } else {
               if (!(flags & TH_SYN))
                  if (ArgusThisTCPsrc->ack) {
                     win = (tcp->th_ack - 1) - ArgusThisTCPsrc->ack;
                     win = (ArgusThisTCPdst->winbytes < win) ? ArgusThisTCPdst->winbytes : win;
                     ArgusThisTCPdst->winbytes -= win;
                     ArgusThisTCPdst->winnum++;
                  }
            }

            ArgusThisTCPsrc->ack = tcp->th_ack - 1;
         }
      }

   } else
      retn = 0;

/* ArgusInProtocol = 1; */

   return (retn);
}


void
ArgusTCPKeystroke (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char *state)
{
   struct ArgusKeyStrokeConf *ArgusKeyStroke = &model->ArgusKeyStroke;
   struct tcphdr *thdr = (struct tcphdr *) model->ArgusThisUpHdr;
   struct tcphdr tcpbuf, *tcp = &tcpbuf;

   if (thdr && STRUCTCAPTURED(model, *thdr)) {
      int tcplen = model->ArgusThisLength;
      int tcphlen = thdr->th_off * 4;
      int tcpdatalen = tcplen - tcphlen;

      if (ArgusKeyStroke->status & ARGUS_SSH_KEYSTROKE)
         if (!(flowstr->status & ARGUS_SSH_MONITOR))
            return;

      if (++flowstr->skey.n_pkts < ArgusKeyStroke->n_min) {
#ifdef ARGUSDEBUG
         ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld flow_n_pkts(%d) < n_min(%d)\n", 
            flowstr, model->ArgusTotalPacket, flowstr->skey.n_pkts, ArgusKeyStroke->n_min);
#endif
         return;
      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld flow_n_pkts(%d)\n", 
            flowstr, model->ArgusTotalPacket, flowstr->skey.n_pkts);
#endif
      }

      if (tcpdatalen > 0) {
#ifdef _LITTLE_ENDIAN
         bzero ((char *)tcp, sizeof(tcpbuf));
         tcp->th_dport = ntohs(thdr->th_dport);
         tcp->th_sport = ntohs(thdr->th_sport);
         tcp->th_seq   = ntohl(thdr->th_seq);
         tcp->th_ack   = ntohl(thdr->th_ack);
         tcp->th_win   = ntohs(thdr->th_win);
         tcp->th_flags = thdr->th_flags;
#else
         bcopy ((char *) thdr, (char *)tcp, sizeof(tcpbuf));
#endif

         if (ArgusKeyStroke->status & ARGUS_SSH_KEYSTROKE) {
            if (tcpdatalen % 4) {
               flowstr->status &= ~ARGUS_SSH_MONITOR;
#ifdef ARGUSDEBUG
               ArgusDebug (7, "ArgusTCPKeystroke: packet %lld flow %p ssh monitor and tcpdatalen(%d) not mod 4\n", flowstr->skey.n_pkts, flowstr, tcpdatalen);
#endif
               return;
            }
         }

         if (flowstr->dsrs[ARGUS_BEHAVIOR_INDEX] == NULL) {
            flowstr->dsrs[ARGUS_BEHAVIOR_INDEX] = (struct ArgusDSRHeader *) &flowstr->canon.actor.hdr;
            flowstr->dsrindex |= 1 << ARGUS_BEHAVIOR_INDEX;
         }

#define CLIENT	1
#define SERVER	0

         switch (model->ArgusThisDir) {
            case CLIENT: {
               if ((tcpdatalen >= ArgusKeyStroke->dc_min) && (tcpdatalen <= ArgusKeyStroke->dc_max)) {
                  int i = 0, found = 0;
#ifdef ARGUSDEBUG
                  ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld client packet seq(%u) size(%d) OK\n", flowstr, flowstr->skey.n_pkts, tcp->th_seq, tcpdatalen);
#endif
                  for (i = 0; i < ARGUS_NUM_KEYSTROKE_PKTS && !found; i++) {
                     struct ArgusKeyStrokePacket *pkt = &flowstr->skey.data.pkts[i];

                     if (pkt->n_pno == 0) {   // this is an empty slot, so use it
                        struct timeval tvpbuf, *tvp = &tvpbuf;
                        pkt->ts.tv_sec  = model->ArgusGlobalTime.tv_sec;
                        pkt->ts.tv_usec = model->ArgusGlobalTime.tv_usec;
                        pkt->intpkt = ArgusDiffTime (&pkt->ts, &flowstr->skey.prev_c_ts, tvp);
                        pkt->seq = tcp->th_seq + tcpdatalen;
                        pkt->n_pno = flowstr->skey.n_pkts;
                        found = 1;
                     }
                  }
                  if (!found) {   // don't have an empty slot, so create one.  clear earliest packet number client packet. keep tentatives
                     int lpno = 0x7FFFFFFF, npkt = -1;
                     for (i = 0; i < ARGUS_NUM_KEYSTROKE_PKTS; i++) {
                        struct ArgusKeyStrokePacket *pkt = &flowstr->skey.data.pkts[i];
                        if (pkt->status != ARGUS_KEYSTROKE_TENTATIVE) {
                           if (pkt->n_pno < lpno) {
                              npkt = i;
                              lpno = pkt->n_pno;
                           }
                        }
                     }
                     if (npkt < 0) {  // nothing but tentatives, so lets clear the tentative at index = 0
#ifdef ARGUSDEBUG
                        ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld no non-tentative packets to reject, clearing first\n", flowstr, flowstr->skey.n_pkts);
#endif
                        npkt = 0;
                     }
                     {
                        struct ArgusKeyStrokePacket *pkt = &flowstr->skey.data.pkts[npkt];
                        struct timeval tvpbuf, *tvp = &tvpbuf;
#ifdef ARGUSDEBUG
                        ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld clearing client %d seq(%u)\n", flowstr, flowstr->skey.n_pkts, npkt, pkt->seq);
#endif
                        pkt->ts.tv_sec  = model->ArgusGlobalTime.tv_sec;
                        pkt->ts.tv_usec = model->ArgusGlobalTime.tv_usec;
                        pkt->intpkt = ArgusDiffTime (&pkt->ts, &flowstr->skey.prev_c_ts, tvp);
                        pkt->seq = tcp->th_seq + tcpdatalen;
                        pkt->n_pno = flowstr->skey.n_pkts;

                     }
                  }
               }
#ifdef ARGUSDEBUG
                 else {
                  ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld client packet size(%d) NOK reset\n", flowstr, flowstr->skey.n_pkts, tcpdatalen);
               }
#endif
               break;
            }

            case SERVER: {
               struct ArgusKeyStrokePacket *pkt = NULL;
               int i, found = 0, reject = 1;

               for (i = 0; i < ARGUS_NUM_KEYSTROKE_PKTS && !found; i++) {
                  pkt = &flowstr->skey.data.pkts[i];
                  if ((pkt->status == 0) && (pkt->seq == tcp->th_ack))
                     found++;
               }

               if (found) {
                  struct ArgusTime stime;

                  stime.tv_sec  = model->ArgusGlobalTime.tv_sec;
                  stime.tv_usec = model->ArgusGlobalTime.tv_usec;

                  if ((flowstr->skey.n_pkts - pkt->n_pno) <= ArgusKeyStroke->gs_max) {
                     if ((tcpdatalen >= ArgusKeyStroke->ds_min) && (tcpdatalen <= ArgusKeyStroke->ds_max)) {
                        struct timeval tvpbuf, *tvp = &tvpbuf;

                        if (pkt->intpkt >= ArgusKeyStroke->ic_min) {
                           long long slint = ArgusDiffTime (&stime, &flowstr->skey.prev_s_ts, tvp);

                           float ic_ratio = (pkt->intpkt * 1.0) / (slint * 1.0);
                           if ((ic_ratio >= ArgusKeyStroke->icr_min) && (ic_ratio <= ArgusKeyStroke->icr_max)) {
                              if ((pkt->n_pno - flowstr->skey.prev_pno) <= ArgusKeyStroke->gpc_max) {
                                 int i;
#ifdef ARGUSDEBUG
                                 ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld server keystroke ", flowstr, flowstr->skey.n_pkts);
#endif
                                 flowstr->skey.n_strokes++;
                                 for (i = 0; i < ARGUS_NUM_KEYSTROKE_PKTS; i++) {
                                    struct ArgusKeyStrokePacket *tpkt = &flowstr->skey.data.pkts[i];
                                    if (tpkt->status == ARGUS_KEYSTROKE_TENTATIVE) {
#ifdef ARGUSDEBUG
                                       ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld TENTATIVE packet %lld keystroke ", flowstr, flowstr->skey.n_pkts, tpkt->n_pno);
#endif
                                       flowstr->skey.n_strokes++;
                                       bzero(tpkt, sizeof(*tpkt));
                                    }
                                 }
                                 flowstr->skey.prev_pno  = pkt->n_pno;
                                 flowstr->skey.prev_c_ts = pkt->ts;
                                 flowstr->skey.prev_s_ts = stime;
                                 bzero(pkt, sizeof(*pkt));

                              } else {
                                 for (i = 0; i < ARGUS_NUM_KEYSTROKE_PKTS; i++) {
                                    struct ArgusKeyStrokePacket *tpkt = &flowstr->skey.data.pkts[i];
                                    if (tpkt->status == ARGUS_KEYSTROKE_TENTATIVE)
                                       bzero(tpkt, sizeof(*tpkt));
                                 }
                                 pkt->status = ARGUS_KEYSTROKE_TENTATIVE;
#ifdef ARGUSDEBUG
                                 ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld server packet pc_gap(%d) > gpc_max(%d) TENTATIVE\n", 
                                       flowstr, flowstr->skey.n_pkts, (pkt->n_pno - flowstr->skey.prev_pno) , ArgusKeyStroke->gpc_max);
#endif
                                 flowstr->skey.prev_pno  = pkt->n_pno;
                                 flowstr->skey.prev_c_ts = pkt->ts;
                                 flowstr->skey.prev_s_ts = stime;
                              }
                              reject = 0;

                           } 
#ifdef ARGUSDEBUG
                           else {
                                 ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld server ic_ratio(%f) out of range\n", 
                                    flowstr, flowstr->skey.n_pkts, ic_ratio);
                           }
#endif
                        } 
#ifdef ARGUSDEBUG
                        else {
                           ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld rejected server IPA(%lld) < ic_min(%d)\n", 
                                    flowstr, flowstr->skey.n_pkts, pkt->intpkt, ArgusKeyStroke->ic_min);
                        }
#endif
                     } 
#ifdef ARGUSDEBUG
                     else {
                        ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld rejected server packet size(%d)\n", flowstr, flowstr->skey.n_pkts, tcpdatalen);
                     }
#endif
                  } 
#ifdef ARGUSDEBUG
                  else {
                     ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld rejected server packet flow s_gap(%d) > gs_gap(%d)\n", 
                           flowstr, flowstr->skey.n_pkts, (flowstr->skey.n_pkts - pkt->n_pno), ArgusKeyStroke->gs_max);
                  }
#endif
                  if (reject) {
                     for (i = 0; i < ARGUS_NUM_KEYSTROKE_PKTS; i++) {
                        struct ArgusKeyStrokePacket *tpkt = &flowstr->skey.data.pkts[i];
                        if (tpkt->status == ARGUS_KEYSTROKE_TENTATIVE)
                           bzero(tpkt, sizeof(*tpkt));
                     }
                     bzero(pkt, sizeof(*pkt));
                  }
               } 
#ifdef ARGUSDEBUG
               else {
                  ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld server packet ack(%u) no match\n", 
                     flowstr, flowstr->skey.n_pkts, tcp->th_ack);
               }
#endif
            }
         }

      } 
#ifdef ARGUSDEBUG
      else {
         ArgusDebug (7, "ArgusTCPKeystroke: flow %p packet %lld %s packet rejected tcpdatalen(%d)\n", 
               flowstr, flowstr->skey.n_pkts, (model->ArgusThisDir ? "server" : "client"), tcpdatalen);
      }
#endif
   }
}

#include <argus_out.h>

void
ArgusTCPFlowRecord (struct ArgusNetworkStruct *net, unsigned char state)
{
   struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;

   net->hdr.argus_dsrvl8.qual = 0;

   tcp->status &= ~(ARGUS_RESET | ARGUS_PKTS_RETRANS | ARGUS_WINDOW_SHUT | ARGUS_OUTOFORDER | ARGUS_DUPLICATES);

   if (tcp->src.status & ARGUS_RESET)
      tcp->status |= ARGUS_SRC_RESET;
   if (tcp->dst.status & ARGUS_RESET)
      tcp->status |= ARGUS_DST_RESET;

   if (tcp->src.status & ARGUS_PKTS_RETRANS)
      tcp->status |= ARGUS_SRC_PKTS_RETRANS;
   if (tcp->dst.status & ARGUS_PKTS_RETRANS)
      tcp->status |= ARGUS_DST_PKTS_RETRANS;

   if (tcp->src.status & ARGUS_WINDOW_SHUT)
      tcp->status |= ARGUS_SRC_WINDOW_SHUT;
   if (tcp->dst.status & ARGUS_WINDOW_SHUT)
      tcp->status |= ARGUS_DST_WINDOW_SHUT;

   if (tcp->src.status & ARGUS_OUTOFORDER)
      tcp->status |= ARGUS_SRC_OUTOFORDER;
   if (tcp->dst.status & ARGUS_OUTOFORDER)
      tcp->status |= ARGUS_DST_OUTOFORDER;

   if (tcp->src.status & ARGUS_DUPLICATES)
      tcp->status |= ARGUS_SRC_DUPLICATES;
   if (tcp->dst.status & ARGUS_DUPLICATES)
      tcp->status |= ARGUS_DST_DUPLICATES;

   switch (net->hdr.subtype) {
      case ARGUS_TCP_INIT:
         net->hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusTCPInitStatus)+3))/4 + 1;
         break;
      case ARGUS_TCP_STATUS:
         net->hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusTCPStatus)+3))/4 + 1;
         break;
      case ARGUS_TCP_PERF:
         net->hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusTCPObject)+3))/4 + 1;
         break;
   }
}

void
ArgusParseTCPOptions(struct ArgusModelerStruct *model, struct tcphdr *tcp, int len, u_int *options, struct ArgusTCPObjectMetrics *ArgusThisTCPsrc)
{
   register const u_char *cp;
   register int i, opt, alen, datalen;

   if ((tcp != NULL)) {
      cp = (const u_char *)tcp + sizeof(*tcp);

      while (len > 0) {
         opt = *cp++;
         if (ZEROLENOPT(opt))
            alen = 1;

         else {
            alen = *cp++;   /* total including type, len */
            if (alen < 2 || alen > len)
               goto bad;
            --len;      /* account for length byte */
         }
         --len;         /* account for type byte */
         datalen = 0;

         switch (opt) {
            case TCPOPT_MAXSEG:
               *options |= ARGUS_TCP_MAXSEG;
               datalen = 2;
               LENCHECK(model, datalen);
               break;

            case TCPOPT_EOL:
               break;

            case TCPOPT_NOP:
               break;

            case TCPOPT_WSCALE:
               *options |= ARGUS_TCP_WSCALE;
               datalen = 1;
               LENCHECK(model, datalen);
               ArgusThisTCPsrc->winshift = *cp;
               break;

            case TCPOPT_SACKOK:
               *options |= ARGUS_TCP_SACKOK;
               break;

            case TCPOPT_SACK:
               *options |= ARGUS_TCP_SACK;
               datalen = alen - 2;
               for (i = 0; i < datalen; i += 4) {
                  LENCHECK(model, i + 4);
               }
               break;

            case TCPOPT_ECHO:
               *options |= ARGUS_TCP_ECHO;
               datalen = 4;
               LENCHECK(model, datalen);
               break;

            case TCPOPT_ECHOREPLY:
               *options |= ARGUS_TCP_ECHOREPLY;
               datalen = 4;
               LENCHECK(model, datalen);
               break;

            case TCPOPT_TIMESTAMP:
               *options |= ARGUS_TCP_TIMESTAMP;
               datalen = 8;
               LENCHECK(model, 4);
               LENCHECK(model, datalen);
               break;

            case TCPOPT_CC:
               *options |= ARGUS_TCP_CC;
               datalen = 4;
               LENCHECK(model, datalen);
               break;

            case TCPOPT_CCNEW:
               *options |= ARGUS_TCP_CCNEW;
               datalen = 4;
               LENCHECK(model, datalen);
               break;

            case TCPOPT_CCECHO:
               *options |= ARGUS_TCP_CCECHO;
               datalen = 4;
               LENCHECK(model, datalen);
               break;

            default:
               datalen = alen - 2;
               for (i = 0; i < datalen; ++i)
                  LENCHECK(model, i);
               break;
            }

            cp += datalen;
            len -= datalen;

            ++datalen;         /* option octet */
            if (!ZEROLENOPT(opt))
               ++datalen;      /* size octet */

            if (opt == TCPOPT_EOL)
               break;
      }
   }

bad:
trunc: {
   }
}
