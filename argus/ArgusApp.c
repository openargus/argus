/*
 * Argus Software.  Argus files - Application Level
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
 * $Id: //depot/argus/argus/argus/ArgusApp.c#29 $
 * $DateTime: 2015/06/29 16:17:25 $
 * $Change: 3027 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusApp)
#define ArgusApp
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <argus_compat.h>
#include <ArgusModeler.h>
#include <ArgusNetflow.h>
#include <argus_def.h>

#define ARGUS_WELLKNOWN_PORT    1024
#define ARGUS_OFC_PORT          6633
#define ARGUS_AFS_PORT_MIN      7000
#define ARGUS_AFS_PORT_MAX      7010
#define ARGUS_UDT_PORT          9000

int ArgusControlPlaneProtocol (struct ArgusModelerStruct *, struct ArgusFlowStruct *);

u_char ArgusUpdateHTTPState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char);
u_char ArgusUpdateRTPState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char);
void ArgusUpdateUDTState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);


int ArgusParseRTCPBuffer (struct ArgusModelerStruct *, struct rtcphdr *);

int ArgusRTCPBadVersion = 0;
int ArgusRTCPBadPtr = 0;

void   ArgusParseRTCPSR (struct rtcphdr *);
void   ArgusParseRTCPRR (struct rtcphdr *);
void   ArgusParseRRRecs (struct rtcphdr *);
void  ArgusParseRTCPBYE (struct rtcphdr *);
void ArgusParseRTCPSDES (struct rtcphdr *);

int
ArgusControlPlaneProtocol (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr)
{
   int retn = 0;

   if (getArgusControlMonitor(model)) {
      struct ArgusSystemFlow *flow = (struct ArgusSystemFlow *)flowstr->dsrs[ARGUS_FLOW_INDEX];
      unsigned short proto, sport, dport;
      unsigned char ip_p;

      switch (proto = (model->ArgusThisNetworkFlowType & 0xFFFF)) {
         case ETHERTYPE_IPV6:
         case ETHERTYPE_IP: {
            if (proto == ETHERTYPE_IPV6) {
                ip_p = flow->ipv6_flow.ip_p;
               sport = flow->ipv6_flow.sport;
               dport = flow->ipv6_flow.dport;
            } else {
                ip_p = flow->ip_flow.ip_p;
               sport = flow->ip_flow.sport;
               dport = flow->ip_flow.dport;
            }

            if ((ip_p == IPPROTO_TCP) && ((sport == ARGUS_OFC_PORT) || (dport == ARGUS_OFC_PORT)))
               retn = 1;
         }
      }
   }
   return (retn);
}

void
ArgusParseRTCPSR (struct rtcphdr *rtcp)
{
/*
   unsigned int ssrc = ntohl(rtcp->rh_ssrc);
*/
}

void
ArgusParseRTCPRR (struct rtcphdr *rtcp)
{
/*
   unsigned int  ssrc = ntohl(rtcp->rh_ssrc);
   unsigned short len = ntohs(rtcp->rh_len);
*/
}

void
ArgusParseRRRecs (struct rtcphdr *rtcp)
{
}

void
ArgusParseRTCPSDES (struct rtcphdr *rtcp)
{
/*
   unsigned int ssrc = ntohl(rtcp->rh_ssrc);
   unsigned short len = ntohs(rtcp->rh_len);
*/
}

void
ArgusParseRTCPBYE (struct rtcphdr *rtcp)
{
/*
   unsigned int ssrc = ntohl(rtcp->rh_ssrc);
   unsigned short len = ntohs(rtcp->rh_len);
*/
}

int
ArgusParseRTCPBuffer (struct ArgusModelerStruct *model, struct rtcphdr *rtcp)
{
   int retn = 0;

   while (STRUCTCAPTURED(model, *rtcp)) {
      u_int len = (ntohs(rtcp->rh_len) << 2) + 4;
      unsigned char *ptr = ((unsigned char *)rtcp) + len;

      if (STRUCTCAPTURED(model, *rtcp)) {
         if (rtcp->rh_ver != RTP_VERSION) {
            ++ArgusRTCPBadVersion;
         } else {

            switch(rtcp->rh_pt) {
               case RTCP_PT_SR:
                  ArgusParseRTCPSR (rtcp);
                  retn++;
                  break;
               case RTCP_PT_RR:     
                  ArgusParseRTCPRR (rtcp); 
                  retn++;
                  break;
               case RTCP_PT_SDES: 
                  ArgusParseRTCPSDES (rtcp); 
                  break;
               case RTCP_PT_BYE:   
                  ArgusParseRTCPBYE (rtcp); 
                  break;
             default:
               ++ArgusRTCPBadPtr;
               break;
            }
         }
      }
      if (len > 4)
         rtcp = (struct rtcphdr *) ptr;
      else
         break;
   }

   return (retn);
}

#if !defined(FALSE)
#define FALSE	0
#endif
#if !defined(TRUE)
#define TRUE	1
#endif

void
ArgusUpdateAppState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char state)
{
   struct ArgusSystemFlow *flow = (struct ArgusSystemFlow *) flowstr->dsrs[ARGUS_FLOW_INDEX];
   int mode = model->ArgusSrc->mode;

   if (model->ArgusThisLength > 0) {
      if (flow != NULL) {
         unsigned short proto, sport = 0, dport = 0;
         unsigned char ip_p;
         int len;

         if (!(model->ArgusThisFlow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT)) {
            switch (proto = (model->ArgusThisNetworkFlowType & 0xFFFF)) {
               case ETHERTYPE_IPV6:
               case ETHERTYPE_IP: {
                  if (proto == ETHERTYPE_IPV6) {
                     ip_p  = flow->ipv6_flow.ip_p;
                     sport = flow->ipv6_flow.sport;
                     dport = flow->ipv6_flow.dport;
                  } else {
                     ip_p  = flow->ip_flow.ip_p;
                     sport = flow->ip_flow.sport;
                     dport = flow->ip_flow.dport;
                  }

                  switch (ip_p) {
                     case IPPROTO_UDP: {
                        switch (mode) {
                           case ARGUS_CISCO_DATA_SOURCE:
                              ArgusParseCiscoRecord(model, model->ArgusThisUpHdr);
                              break;

                            default: {
                               if (state == ARGUS_START) {
                                 struct rtphdr *rtp = (struct rtphdr *) model->ArgusThisUpHdr;

                                 if (STRUCTCAPTURED(model, *rtp)) {
                                    if ((rtp->rh_ver == RTP_VERSION) && 
                                          (!((sport < ARGUS_WELLKNOWN_PORT) || (dport < ARGUS_WELLKNOWN_PORT)) &&
                                           !((sport >= ARGUS_AFS_PORT_MIN) && (sport <= ARGUS_AFS_PORT_MAX)) &&
                                           !((dport >= ARGUS_AFS_PORT_MIN) && (dport <= ARGUS_AFS_PORT_MAX)))) {

                                       struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) flowstr->dsrs[ARGUS_NETWORK_INDEX];

                                       if (net == NULL) {
                                          net = (struct ArgusNetworkStruct *) &flowstr->canon.net;
                                          flowstr->dsrs[ARGUS_NETWORK_INDEX] = (struct ArgusDSRHeader *) net;
                                       }

                                       if (ArgusParseRTCPBuffer(model, (struct rtcphdr *) model->ArgusThisUpHdr)) {
                                          struct ArgusRTCPObject *rtcpObject = (struct ArgusRTCPObject *)(&net->hdr + 1);
                                          struct rtcphdr *rtcp = (struct rtcphdr *) model->ArgusThisUpHdr;
                                          net->hdr.type             = ARGUS_NETWORK_DSR;
                                          net->hdr.subtype          = ARGUS_RTCP_FLOW;
                                          net->hdr.argus_dsrvl8.qual = 0;
                                          net->hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusRTCPObject) + 3)/4) + 1;
                                          if (model->ArgusThisDir) {
                                             bcopy ((char *) rtcp, (char *)&rtcpObject->src, sizeof(*rtcp));
                                          } else {
                                             bcopy ((char *) rtcp, (char *)&rtcpObject->dst, sizeof(*rtcp));
                                          }

                                       } else {
                                          if (rtp->rh_pt < 128) {
                                             struct ArgusRTPObject *rtpObject = (struct ArgusRTPObject *)(&net->hdr + 1);
                                             struct rtphdr trtpbuf, *trtp = &trtpbuf;

                                             net->hdr.type             = ARGUS_NETWORK_DSR;
                                             net->hdr.subtype          = ARGUS_RTP_FLOW;
                                             net->hdr.argus_dsrvl8.qual = 0;
                                             net->hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusRTPObject) + 3)/4) + 1;


                                             bcopy(rtp, trtp, sizeof(*trtp));
                                             trtp->rh_seq  = ntohs(rtp->rh_seq);
                                             trtp->rh_time = ntohl(rtp->rh_time);
                                             trtp->rh_ssrc = ntohl(rtp->rh_ssrc);

                                             if (model->ArgusThisDir) {
                                                bcopy ((char *) trtp, (char *)&rtpObject->src, sizeof(*rtp));
                                             } else {
                                                bcopy ((char *) trtp, (char *)&rtpObject->dst, sizeof(*rtp));
                                             }
                                          }
                                       }
                                    } else {
                                       if ((sport == ARGUS_UDT_PORT) || (dport == ARGUS_UDT_PORT)) {
                                          unsigned int status = 0;
                                          if (ArgusParseUDTHeader (model, (struct udt_header *) model->ArgusThisUpHdr, &status)) {
                                             struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) flowstr->dsrs[ARGUS_NETWORK_INDEX];

                                             if (net == NULL) {
                                                net = (struct ArgusNetworkStruct *) &flowstr->canon.net;
                                                flowstr->dsrs[ARGUS_NETWORK_INDEX] = (struct ArgusDSRHeader *) net;
                                             }

                                             net->hdr.type              = ARGUS_NETWORK_DSR;
                                             net->hdr.subtype           = ARGUS_UDT_FLOW;
                                             net->hdr.argus_dsrvl8.qual = 0;
                                             net->hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusUDTObject) + 3)/4) + 1;

                                             if (ArgusThisUdtHshake != NULL) {
                                                struct ArgusUDTObject *udtObject = (struct ArgusUDTObject *)(&net->hdr + 1);
                                                bcopy (ArgusThisUdtHshake, &udtObject->hshake, sizeof(*ArgusThisUdtHshake));
                                             }

                                             if (status != 0) 
                                                net->net_union.udt.status |= status;
                                          }
                                       }
                                    }
                                 }
                              } else {
                                 struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) flowstr->dsrs[ARGUS_NETWORK_INDEX];
                                 if (net != NULL) {
                                    switch (net->hdr.subtype) {
                                       case ARGUS_RTP_FLOW:
                                       case ARGUS_RTCP_FLOW: {
                                          ArgusUpdateRTPState(model, flowstr, state);
                                          break;
                                       }

                                       case ARGUS_UDT_FLOW: {
                                          ArgusUpdateUDTState(model, flowstr, &state);
                                          break;
                                       }
                                    }
                                 }
                              }
                           }
                        }
                        break;
                     } /* IPPROTO_UDP */
                  }

                  break;
               }
            }
         }

         if (model->ArgusThisStats)
            model->ArgusThisStats->appbytes += model->ArgusThisLength;

         if ((len = flowstr->userlen) != 0) {
            struct ArgusDataStruct *user = NULL;
            int ind, tlen;

            if (model->ArgusThisDir)
               ind = ARGUS_SRCUSERDATA_INDEX;
            else
               ind = ARGUS_DSTUSERDATA_INDEX;

            if (len == -1) 
               len = model->ArgusThisLength;

            tlen = ((len + 3)/4) + 2;

            if (state == ARGUS_START) {
               if ((user = (struct ArgusDataStruct *) flowstr->dsrs[ind]) != NULL) {
                  if (len != user->size) {
                     ArgusFree(flowstr->dsrs[ind]);
                     flowstr->dsrs[ind] = NULL;
                  } else {
                     user->count = 0;
                     memset(user->array, 0, len);
                  }
               }
            }

            if ((user = (struct ArgusDataStruct *) flowstr->dsrs[ind]) == NULL) {
               if ((user = (void *) ArgusCalloc(tlen, 4)) != NULL) {
                  flowstr->dsrs[ind] = (void *) user;
                  user->size                 = len;
                  user->hdr.type             = ARGUS_DATA_DSR;
                  user->hdr.subtype          = ARGUS_LEN_16BITS;
                  user->hdr.argus_dsrvl16.len = tlen;

                  if (ind == ARGUS_SRCUSERDATA_INDEX)
                     user->hdr.subtype |= ARGUS_SRC_DATA;
                  else
                     user->hdr.subtype |= ARGUS_DST_DATA;

                  flowstr->dsrindex |= (0x1 << ind);
               }
            }

            if (user && (user->count < user->size)) {
               int thislen = user->size - user->count;
               int bytes = 0, ArgusThisUserLength = (model->ArgusThisLength < model->ArgusSnapLength) ? 
                                                     model->ArgusThisLength : model->ArgusSnapLength;

               if ((thislen > 0) && (ArgusThisUserLength > 0)) {

                  if (ArgusThisUserLength < thislen)
                     thislen = ArgusThisUserLength;

                  if ((bytes = model->ArgusThisSnapEnd - model->ArgusThisUpHdr) > 0) {
                     thislen = (thislen > bytes) ? bytes : thislen;
                     bcopy (model->ArgusThisUpHdr, &((char *)&user->array)[user->count], thislen);
                     user->count += thislen;
                  }
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusUpdateAppState(0x%x, %d) returning\n", flowstr, state);
#endif
}

u_char
ArgusUpdateHTTPState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char state)
{
   u_char retn = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (7, "ArgusUpdateHTTPState(0x%x, 0x%x, %d) returning\n", flowstr, state);
#endif
 
   return(retn);
}

u_char
ArgusUpdateRTPState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char state)
{
   struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) flowstr->dsrs[ARGUS_NETWORK_INDEX];
   u_char retn = 0;

   if (net == NULL)
      return(retn);

   switch (net->hdr.subtype) {
      case ARGUS_RTP_FLOW: {
         struct ArgusRTPObject *rtpObject = (struct ArgusRTPObject *)(&net->hdr + 1);
         struct rtphdr *rtp = (struct rtphdr *) model->ArgusThisUpHdr;
         struct rtphdr trtpbuf, *trtp = &trtpbuf;
         struct rtphdr *ArgusThisRtpHdr = NULL;

         bcopy(rtp, trtp, sizeof(*trtp));
         trtp->rh_seq  = ntohs(rtp->rh_seq);
         trtp->rh_time = ntohl(rtp->rh_time);
         trtp->rh_ssrc = ntohl(rtp->rh_ssrc);

         if (model->ArgusThisDir)
            ArgusThisRtpHdr = &rtpObject->src;
         else
            ArgusThisRtpHdr = &rtpObject->dst;

         if (!(ArgusThisRtpHdr->rh_seq)) {
            if (rtp->rh_ver == 2) 
               bcopy ((char *) trtp, (char *)ArgusThisRtpHdr, sizeof(*rtp));
         } else {
            if (rtp->rh_ver == 2) {
            if (!(trtp->rh_ssrc) || (ArgusThisRtpHdr->rh_ssrc != trtp->rh_ssrc))
               flowstr->dsrs[ARGUS_NETWORK_INDEX] = NULL;
            else
            if (trtp->rh_x) {
               struct rtpexthdr *xhdr = (struct rtpexthdr *) (rtp + 1);
               if ((xhdr->length > model->ArgusThisLength) || (xhdr->length < (model->ArgusThisLength - 4)))
                  flowstr->dsrs[ARGUS_NETWORK_INDEX] = NULL;
            }

            if (flowstr->dsrs[ARGUS_NETWORK_INDEX] != NULL) {
               int offset = ((trtp->rh_cc > 15) ? 15 : trtp->rh_cc) << 2;

               if (ArgusThisRtpHdr->rh_seq != (trtp->rh_seq - 1)) {
                  if (trtp->rh_seq < ArgusThisRtpHdr->rh_seq) {
                     if ((ArgusThisRtpHdr->rh_seq - trtp->rh_seq) < 0x7FFFFFFF) {
                        if (model->ArgusThisDir) {
                           if (rtpObject->sdrop > 0) {
                              rtpObject->sdrop--;
                              rtpObject->state |= ARGUS_SRC_OUTOFORDER;
                           }
                        } else {
                           if (rtpObject->ddrop > 0) {
                              rtpObject->ddrop--;
                              rtpObject->state |= ARGUS_DST_OUTOFORDER;
                           }
                        }
                     }

                  } else {
                     if (trtp->rh_seq > ArgusThisRtpHdr->rh_seq) {
                        if (model->ArgusThisDir) {
                           rtpObject->sdrop += trtp->rh_seq - (ArgusThisRtpHdr->rh_seq + 1);
                        } else {
                           rtpObject->ddrop += trtp->rh_seq - (ArgusThisRtpHdr->rh_seq + 1);
                        }
                     }
                  }
               }
    
               bcopy ((char *) trtp, (char *) ArgusThisRtpHdr, sizeof(*rtp));
         
               if (offset < model->ArgusThisLength) {
               model->ArgusThisUpHdr = (unsigned char *)(rtp + 1) + offset;
               model->ArgusThisLength -= (sizeof(struct rtphdr) + offset);
               model->ArgusSnapLength -= (sizeof(struct rtphdr) + offset);

               if (trtp->rh_x) {
                  struct rtpexthdr *ext = (struct rtpexthdr *)model->ArgusThisUpHdr;
                  if (STRUCTCAPTURED(model,*ext)) {
                     offset = sizeof(struct rtpexthdr) + ntohs(ext->length);
         
                     model->ArgusThisLength -= offset;
                     model->ArgusSnapLength -= offset;
                     model->ArgusThisUpHdr  += offset;
                  }
               }

               switch (trtp->rh_pt) {
                  case ARGUS_RTP_PCMU:
                  case ARGUS_RTP_PCMA:
                  case ARGUS_RTP_G722:
                  case ARGUS_RTP_G728:
                  case ARGUS_RTP_G729:
                     if ((model->ArgusThisLength == 0) || ((model->ArgusThisLength % 10) != 0)) {
                        model->ArgusInProtocol = 0;
                        if (model->ArgusThisDir) {
                           net->hdr.argus_dsrvl8.qual |= ARGUS_RTP_SRCSILENCE;
                        }else {
                           net->hdr.argus_dsrvl8.qual |= ARGUS_RTP_DSTSILENCE;
                        }
                     } else
                        if (trtp->rh_mark)
                           model->ArgusInProtocol = 0;
                     break;
      
                  case ARGUS_RTP_G723:
                     if ((model->ArgusThisLength == 0) || (model->ArgusThisLength == 4)) {
                        model->ArgusInProtocol = 0;
                        if (model->ArgusThisDir) {
                           net->hdr.argus_dsrvl8.qual |= ARGUS_RTP_SRCSILENCE;
                        } else {
                           net->hdr.argus_dsrvl8.qual |= ARGUS_RTP_DSTSILENCE;
                        }
                     } else
                        if (trtp->rh_mark)
                           model->ArgusInProtocol = 0;
                     break;
      
                  case ARGUS_RTP_H261:
                  case ARGUS_RTP_H263:
                     break;
               }

            }
            }
            }
         }
         break;

      }

      case ARGUS_RTCP_FLOW: {
         break;
      }
   }

   if (flowstr->dsrs[ARGUS_NETWORK_INDEX] == NULL)
      *(unsigned int *)&flowstr->canon.net.hdr = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (7, "ArgusUpdateRTPState(0x%x, 0x%x, %d) returning\n", model, flowstr, state);
#endif
 
   return(retn);
}
