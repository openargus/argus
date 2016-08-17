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
 * $Id: //depot/argus/argus/argus/ArgusFrag.c#30 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusFrag)
#define ArgusFrag
#endif

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <argus_compat.h>
#include <ArgusModeler.h>


struct ArgusSystemFlow *ArgusCreateFRAGFlow (struct ArgusModelerStruct *, void *, unsigned short);
int ArgusUpdateFRAGState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char, unsigned short);
int ArgusUpdateParentFlow (struct ArgusModelerStruct *, struct ArgusFlowStruct *);

void ArgusZeroRecord (struct ArgusFlowStruct *);


struct ArgusSystemFlow *
ArgusCreateFRAGFlow (struct ArgusModelerStruct *model, void *ptr, unsigned short proto)
{
   struct ArgusSystemFlow *retn = NULL;

   switch (proto) {
      case ETHERTYPE_IP: {
         struct ip tipbuf, *tip = &tipbuf; 
         struct ip *ip = (struct ip *) ptr;

#ifdef _LITTLE_ENDIAN
         bzero(tip, sizeof(*tip));
         tip->ip_len = ntohs(ip->ip_len);
         tip->ip_id  = ntohs(ip->ip_id);
         tip->ip_off = ntohs(ip->ip_off);
         tip->ip_p   = ip->ip_p;
         tip->ip_src.s_addr =  ntohl(ip->ip_src.s_addr);
         tip->ip_dst.s_addr =  ntohl(ip->ip_dst.s_addr);
#else
         tip = ip;
#endif
         model->state &= ~ARGUS_DIRECTION;
         if (STRUCTCAPTURED(model, *ip)) {
            if (model->ArgusFlowType == ARGUS_BIDIRECTIONAL) {
               if (tip->ip_src.s_addr > tip->ip_dst.s_addr) {
                  model->state |= ARGUS_DIRECTION;
                  model->ArgusThisFlow->hdr.argus_dsrvl8.qual |= ARGUS_DIRECTION;
                  model->ArgusThisFlow->hdr.subtype     |= ARGUS_REVERSE;
               }
            }
 
            model->ArgusThisFlow->hdr.argus_dsrvl8.qual |= ARGUS_FRAGMENT;

            if (model->state & ARGUS_DIRECTION) {
               model->ArgusThisFlow->ip_flow.ip_src   = tip->ip_dst.s_addr;
               model->ArgusThisFlow->ip_flow.ip_dst   = tip->ip_src.s_addr;
            } else {
               model->ArgusThisFlow->frag_flow.ip_src = tip->ip_src.s_addr;
               model->ArgusThisFlow->frag_flow.ip_dst = tip->ip_dst.s_addr;
            }
            model->ArgusThisFlow->frag_flow.ip_p       = tip->ip_p;
            model->ArgusThisFlow->frag_flow.ip_id      = tip->ip_id;
            model->ArgusThisFlow->frag_flow.pad[0]     = 0;
            model->ArgusThisFlow->frag_flow.pad[1]     = 0;
            retn = model->ArgusThisFlow;
         }
         break;
      }

      case ETHERTYPE_IPV6: {
         struct ip6_frag *frag = model->ArgusThisIpv6Frag;

         model->state &= ~ARGUS_DIRECTION;
         if (STRUCTCAPTURED(model, *frag)) {
            if (model->ArgusFlowType == ARGUS_BIDIRECTIONAL) {
            } else {
            }
            model->ArgusThisFlow->fragv6_flow.ip_id = frag->ip6f_ident;
            model->ArgusThisFlow->hdr.argus_dsrvl8.qual |= ARGUS_FRAGMENT;
            retn = model->ArgusThisFlow;
         }
         break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusCreateFRAGFlow(0x%x, 0x%x, %d)", model, ptr, proto);
#endif 

   return (retn);
}

/*
struct ArgusFragObject {
   unsigned int fragnum, frag_id;
   unsigned short totlen, currlen, maxfraglen, pad;
};
*/

int
ArgusUpdateFRAGState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char state, unsigned short proto)
{
   int retn = 0, up_p = 0;
   struct ArgusNetworkStruct *net = NULL;
   struct ArgusFragObject *frag = NULL;

   struct ArgusFragOffsetStruct *fragOffset = NULL;
   struct ArgusFragOffsetStruct *thisFragOffset = NULL;
   struct ArgusFragOffsetStruct *prvfragOffset = NULL;
   struct ArgusFragOffsetStruct *nxtfragOffset = NULL;

   int offset = 0, length = 0, end = 0, newbytes = 1, found = 0;

/* so the trick is to deal with out of order and missing fragments */
/* so lets figure out if this is the next chunk and get out fast if it is */

   switch (proto) {
      case ETHERTYPE_IP: {
         struct ip *ip = (struct ip *)model->ArgusThisIpHdr;

         up_p = ip->ip_p;
         offset = (ntohs(ip->ip_off) & 0x1fff) << 3;
         length = ntohs(ip->ip_len) - (ip->ip_hl * 4);
         end = offset + length;
         break;
      }

      case ETHERTYPE_IPV6: {
         struct ip6_frag *tfrag = model->ArgusThisIpv6Frag;
         up_p = tfrag->ip6f_nxt;
         offset = ntohs(tfrag->ip6f_offlg & IP6F_OFF_MASK);
         length = model->ArgusThisLength;
         end = offset + length;
         break;
      }
   }

   if ((net = (struct ArgusNetworkStruct *) flowstr->dsrs[ARGUS_FRAG_INDEX]) != NULL) {
      if (net->hdr.subtype != ARGUS_NETWORK_SUBTYPE_FRAG) {
         if (state == ARGUS_START) {
            memset (net, 0, sizeof(struct ArgusFragObject) + 4);

            net->hdr.subtype = ARGUS_NETWORK_SUBTYPE_FRAG;
            net->hdr.argus_dsrvl8.qual  = 0;
            net->hdr.argus_dsrvl8.len   = ((sizeof(struct ArgusFragObject) + 3)/4) + 1;
         }
      }

      frag = &net->net_union.frag;
      frag->totbytes += model->ArgusThisLength;

/* is this the first fragment chunk seen ?*/
      if (!(frag->offsets.end)) {
         frag->offsets.start = offset;
         frag->offsets.end   = end;
         found = 1;
      
      } else {
/* if not lets see if we've seen this data before */

         fragOffset = &frag->offsets;

         while ((fragOffset != NULL) && !(found)) {
/* this frag is past this frag chunk, so continue */
            if (offset > fragOffset->end) {
               prvfragOffset = fragOffset;
               fragOffset = fragOffset->nxt;

            } else

/* if frag is contiguous with previously frag, then update end */
            if (offset == fragOffset->end) {
/* check that we don't overlap next frag, prediction is that there is no nxt frag */
               if ((nxtfragOffset = fragOffset->nxt) == NULL) {
                  fragOffset->end = end;
                  found = 1;
               } else {
/* this frag connects the two frags so account and remove nxt chunk */
                  if (end == nxtfragOffset->start) {
                     fragOffset->nxt = nxtfragOffset->nxt;
                     fragOffset->end = nxtfragOffset->end;
                     free(nxtfragOffset);
                     found = 1;
                  } else
/* this frag ends before the next chunk, i.e. we missed several frags  */
                  if (end < nxtfragOffset->start) {
                     fragOffset->end = end;
                     found = 1;
                  } else {
/* this frag overlaps, so chop this frag, set overlap, and then continue */
                     offset = nxtfragOffset->start;
                     fragOffset->end = nxtfragOffset->start;
                     flowstr->canon.net.hdr.argus_dsrvl8.qual |= ARGUS_FRAGOVERLAP;
                     prvfragOffset = fragOffset;
                     fragOffset = nxtfragOffset;
                  }
               }

            } else
/* so this offset is before or in this chunk, so check if this is before or previous */
            if (offset < fragOffset->start) {
               if (end == fragOffset->start) {
                  fragOffset->start = offset;
                  found = 1;
               } else {
                  if (end < fragOffset->start) {
                     fragOffset = NULL;
                  } else {
/* so end is in or past this frag, if past, then remove the smaller frag in list and start over */
                     if (end > fragOffset->end) {
                        flowstr->canon.net.hdr.argus_dsrvl8.qual |= ARGUS_FRAGOVERLAP;
                        frag->bytes -= (fragOffset->end - fragOffset->start);
/* if there is a nxt fragment, replace the overlaping frag (fragOffset) with it */
                        if (fragOffset->nxt != NULL) {
                           if (prvfragOffset != NULL) {
                              prvfragOffset->nxt = fragOffset->nxt;
                           } else {
                              bcopy((char *) fragOffset->nxt , (char *)&frag->offsets, sizeof(frag->offsets));
                           }
/* else just update the prv fragments pointer to toss this one */
                        } else {
                           if (prvfragOffset != NULL) {
                              prvfragOffset->nxt = NULL;
                           } else {
/* else we're the first chunk just update this chunk */
                              fragOffset->start = offset;
                              fragOffset->end   = end;
                              found = 1;
                           }
                        }
                        if (fragOffset != &frag->offsets)
                           free(fragOffset);
                        prvfragOffset = NULL;
                        fragOffset = &frag->offsets;
                     } else {
/* so (end < fragOffset->end), overlap but account for previous missing chunk */
                        flowstr->canon.net.hdr.argus_dsrvl8.qual |= ARGUS_FRAGOVERLAP;
                        end = fragOffset->start;
                        fragOffset->start = offset;
                        found = 1;
                     }
                  }
               }

            } else
/* if frag is coincidental with this frag, then retransmission or overlap */
            if (offset >= fragOffset->start) {
               if (end <= fragOffset->end) {
                  if ((offset == fragOffset->start) && (end == fragOffset->end))
                     flowstr->canon.net.hdr.argus_dsrvl8.qual |= ARGUS_SRC_PKTS_RETRANS;
                  else
                     flowstr->canon.net.hdr.argus_dsrvl8.qual |= ARGUS_FRAGOVERLAP;
                  newbytes = 0;
                  found = 1;
               } else {
/* this end extends beyond this frag, so clip and continue */
                  flowstr->canon.net.hdr.argus_dsrvl8.qual |= ARGUS_FRAGOVERLAP;
/* if we do, chop this frag, set overlap, and then continue */
                  if ((fragOffset->nxt != NULL) && (fragOffset->nxt->start < end)) {
                        offset = fragOffset->nxt->start;
                        fragOffset->end = fragOffset->nxt->start;
                  } else 
                        offset = fragOffset->end;

                  prvfragOffset = fragOffset;
                  fragOffset = fragOffset->nxt;
               }
            }
         }

         if (flowstr->canon.net.hdr.argus_dsrvl8.qual & ARGUS_FRAGOVERLAP)
/* first check the TCP header overlap condition */
            if ((up_p == IPPROTO_TCP) && ((offset > 0) && (offset < 2)))
               flowstr->canon.net.hdr.argus_dsrvl8.qual |= ARGUS_TCPFRAGOFFSETERROR;
      }

/* if its new data update byte counters */
      if (newbytes)
         frag->bytes += end - offset;

      frag->fragnum++;

      if (model->ArgusThisLength > frag->maxfraglen)
         frag->maxfraglen = model->ArgusThisLength;

      switch (proto) {
         case ETHERTYPE_IP: {
            struct ip *iphdr = (struct ip *)model->ArgusThisIpHdr;

            if (!(ntohs(iphdr->ip_off) & IP_MF))
               frag->totlen = ((ntohs(iphdr->ip_off) & 0x1fff) << 3) +
                               (ntohs(iphdr->ip_len) - (iphdr->ip_hl << 2));
            break;
         }
         case ETHERTYPE_IPV6: {
            struct ip6_frag *tfrag = model->ArgusThisIpv6Frag;
            struct ip6_hdr  *iphdr = (struct ip6_hdr *)model->ArgusThisIpHdr;
            if (!(tfrag->ip6f_offlg & IP6F_MORE_FRAG))
               frag->totlen = (ntohs(tfrag->ip6f_offlg & IP6F_OFF_MASK) + (ntohs(iphdr->ip6_plen) - 8));
            break;
         }
      }
      
      /* so if we've seen the first fragment we can know how many bytes to expect */
      if (frag->totlen) {
         /* so if we've seen all the bytes */
         if (frag->totlen == frag->bytes) {
            if (!(ArgusUpdateParentFlow (model, flowstr)))
               ArgusSendFlowRecord(model, flowstr, ARGUS_STOP);

            /* don't try to deallocate the non-malloc first chunk */
            if ((fragOffset = frag->offsets.nxt) != NULL) {
               struct ArgusFragOffsetStruct *toffset = fragOffset->nxt;
               do { 
                  toffset = fragOffset->nxt;
                  free(fragOffset);
                  fragOffset = toffset;
               } while (fragOffset);
            }
            memset(&frag->offsets, 0, sizeof(frag->offsets));
            retn = 1;

         } else {
/* we could wait, thinking we'll get some fragments out of order
      may just want to finish up here with reported packet loss ?
      the option is to wait for the timeout */

         }

      } else {
         /* test if we need add this chunk */
         if (!found) {
            /* test if we've used the base frag offset */
            if (fragOffset || prvfragOffset) {
               /* yes so we're going to add a new chunk */

               if (fragOffset == NULL)
                  fragOffset = prvfragOffset;

               if ((thisFragOffset = (struct ArgusFragOffsetStruct *) malloc(sizeof(*thisFragOffset))) != NULL) {

                  thisFragOffset->nxt   = NULL;
                  thisFragOffset->start = offset;
                  thisFragOffset->end   = end;

                  /* so does this go as the next chunk or the first chunk */
                  /* the idea is that fragOffset is the pointer to the new previous chunk */
                  /* so add it as its nxt pointer */
                  if (fragOffset->nxt == NULL)
                     fragOffset->nxt = thisFragOffset;
                  else {
                     if ((fragOffset = &frag->offsets) != NULL) {
                        while (fragOffset->nxt != NULL)
                           fragOffset = fragOffset->nxt;

                        fragOffset->nxt = thisFragOffset;

                     }
                  }
               }

            } else {
            }
         }
      }

   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (4, "ArgusUpdateFRAGState (0x%x, %d) no frag struct\n", flowstr, state);
#endif 
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusUpdateFRAGState(0x%x, 0x%x, %d) returns %d\n", model, flowstr, state, retn);
#endif 

   return (retn);
}


int
ArgusUpdateParentFlow (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr)
{
   struct ArgusNetworkStruct *net = NULL;
   struct ArgusFragObject *frag = NULL;
   struct ArgusFlowStruct *parent;
   int retn = 0, found = 0;

   if (flowstr->canon.metric.src.pkts || flowstr->canon.metric.dst.pkts) {
      if ((net = (struct ArgusNetworkStruct *) flowstr->dsrs[ARGUS_FRAG_INDEX]) != NULL) {
         frag = &net->net_union.frag;
         if ((parent = frag->parent) != NULL) {
            if (flowstr->qhdr.queue == &parent->frag) {
               found++;
            } else {
            }
         }
   
      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "ArgusUpdateFRAGState(0x%x, 0x%x) parent has no frag struct", model, flowstr);
#endif 
         return (retn);
      }

      if (found) {
         struct ArgusTimeObject *ftime = NULL, *ptime = NULL;
         struct ArgusSystemFlow *flow = NULL;
         struct ArgusMetricStruct *metrics = NULL;

         if (parent->status & ARGUS_RECORD_WRITTEN)
            ArgusZeroRecord(parent);

         flow = (struct ArgusSystemFlow *)parent->dsrs[ARGUS_FLOW_INDEX];
         metrics = (struct ArgusMetricStruct *) parent->dsrs[ARGUS_METRIC_INDEX];

#define ARGUS_TYPES  (ARGUS_TYPE_IPV4 | ARGUS_TYPE_IPV6 | ARGUS_TYPE_ARP | ARGUS_TYPE_ETHER)

         if (flow && metrics) {
            switch (flow->hdr.argus_dsrvl8.qual & ARGUS_TYPES) {
               case ARGUS_TYPE_IPV4: 
               case ARGUS_TYPE_IPV6:  {
                  struct ArgusIPAttrStruct *attr = (struct ArgusIPAttrStruct *) parent->dsrs[ARGUS_IPATTR_INDEX];

                  if ((parent->state & ARGUS_DIRECTION) != (flowstr->state & ARGUS_DIRECTION)) {
                     metrics->dst.pkts  += flowstr->canon.metric.src.pkts;
                     metrics->dst.bytes += flowstr->canon.metric.src.bytes;
                     
                     flowstr->canon.metric.src.pkts = 0;
                     flowstr->canon.metric.src.bytes = 0;

                     if (attr != NULL)
                        attr->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_DST_FRAGMENTS;

                  } else {
                     metrics->src.pkts  += flowstr->canon.metric.src.pkts;
                     metrics->src.bytes += flowstr->canon.metric.src.bytes;
                     flowstr->canon.metric.src.pkts = 0;
                     flowstr->canon.metric.src.bytes = 0;

                     if (attr != NULL)
                        attr->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_SRC_FRAGMENTS;
                  }
                  break;
               }
            }
         }

         ftime = (struct ArgusTimeObject *) flowstr->dsrs[ARGUS_TIME_INDEX];
         ptime = (struct ArgusTimeObject *)  parent->dsrs[ARGUS_TIME_INDEX];

         if (ftime && ptime) {
            struct ArgusTimeStruct *pstime;

            if ((parent->state & ARGUS_DIRECTION) != (flowstr->state & ARGUS_DIRECTION)) {
               pstime = &ptime->dst;
            } else {
               pstime = &ptime->src;
            }

            if (ptime->hdr.subtype == ARGUS_TIME_ABSOLUTE_TIMESTAMP) {
               ptime->hdr.subtype           = ARGUS_TIME_ABSOLUTE_RANGE;
               ptime->hdr.argus_dsrvl8.qual = ARGUS_TYPE_UTC_MICROSECONDS;
               ptime->hdr.argus_dsrvl8.len  = 5;
               if ((pstime->start.tv_sec  > ftime->src.start.tv_sec) ||
                  ((pstime->start.tv_sec == ftime->src.start.tv_sec) &&
                   (pstime->start.tv_usec > ftime->src.start.tv_usec))) {
                  pstime->start = ftime->src.start;
               }
               pstime->end = ftime->src.end;

            } else {
               if ((pstime->end.tv_sec  < ftime->src.end.tv_sec) ||
                  ((pstime->end.tv_sec == ftime->src.end.tv_sec) &&
                   (pstime->end.tv_usec < ftime->src.end.tv_usec))) {
                  pstime->end = ftime->src.end;
               }
            }
            parent->dsrindex |= 1 << ARGUS_TIME_INDEX;
         }
         retn = 1;

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "ArgusUpdateParentFlow(0x%x) did not find parent 0x%x\n", flowstr, parent);
#endif 
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (7, "ArgusUpdateParentFlow(0x%x) returning 0x%x\n", flowstr, retn);
#endif 

   return (retn);
}
