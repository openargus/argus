/*
 * Argus-5.0 Software.  Argus files - Sflow record processing
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
 * $Id: //depot/gargoyle/argus/argus/ArgusSflow.c#5 $
 * $DateTime: 2016/02/16 17:07:05 $
 * $Change: 3096 $
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


void ArgusParseSFlowRecord (struct ArgusModelerStruct *, void *);

static void SFLengthCheck(SFSample *, u_char *, int);

void SFParseFlowSample_header(struct ArgusSourceStruct *, struct timeval *, SFSample *);
void SFParseFlowSample_ethernet(SFSample *);
void SFParseFlowSample_IPv4(SFSample *);
void SFParseFlowSample_IPv6(SFSample *);
void SFParseFlowSample_memcache(SFSample *);
void SFParseFlowSample_http(SFSample *);
void SFParseFlowSample_CAL(SFSample *);
void SFParseExtendedSwitch(SFSample *);
void SFParseExtendedRouter(SFSample *);
void SFParseExtendedGateway(SFSample *);
void SFParseExtendedUser(SFSample *);
void SFParseExtendedUrl(SFSample *);
void SFParseExtendedMpls(SFSample *);
void SFParseExtendedNat(SFSample *);
void SFParseExtendedMplsTunnel(SFSample *);
void SFParseExtendedMplsVC(SFSample *);
void SFParseExtendedMplsFTN(SFSample *);
void SFParseExtendedMplsLDP_FEC(SFSample *);
void SFParseExtendedVlanTunnel(SFSample *);
void SFParseExtendedWifiPayload(struct ArgusSourceStruct *, struct timeval *, SFSample *);
void SFParseExtendedWifiRx(SFSample *);
void SFParseExtendedWifiTx(SFSample *);
void SFParseExtendedAggregation(SFSample *);
void SFParseExtendedSocket4(SFSample *);
void SFParseExtendedSocket6(SFSample *);

void SFParseCounters_generic (SFSample *sptr);
void SFParseCounters_ethernet (SFSample *sptr);
void SFParseCounters_tokenring (SFSample *sptr);
void SFParseCounters_vg (SFSample *sptr);
void SFParseCounters_vlan (SFSample *sptr);
void SFParseCounters_80211 (SFSample *sptr);
void SFParseCounters_processor (SFSample *sptr);
void SFParseCounters_radio (SFSample *sptr);
void SFParseCounters_host_hid (SFSample *sptr);
void SFParseCounters_adaptors (SFSample *sptr);
void SFParseCounters_host_parent (SFSample *sptr);
void SFParseCounters_host_cpu (SFSample *sptr);
void SFParseCounters_host_mem (SFSample *sptr);
void SFParseCounters_host_dsk (SFSample *sptr);
void SFParseCounters_host_nio (SFSample *sptr);
void SFParseCounters_host_vnode (SFSample *sptr);
void SFParseCounters_host_vcpu (SFSample *sptr);
void SFParseCounters_host_vmem (SFSample *sptr);
void SFParseCounters_host_vdsk (SFSample *sptr);
void SFParseCounters_host_vnio (SFSample *sptr);
void SFParseCounters_memcache (SFSample *sptr);
void SFParseCounters_http (SFSample *sptr);
void SFParseCounters_CAL (SFSample *sptr);

static void SFDecodeLinkLayer(SFSample *);
static void SFDecode80211MAC(SFSample *);

static void SFDecodeIPV4(SFSample *);
static void SFDecodeIPV6(SFSample *);
static void SFDecodeIPLayer4(SFSample *, u_char *);


#define ARGUS_FALSE   0
#define ARGUS_TRUE   1

int ArgusProcessSflowDatagram (struct ArgusSourceStruct *, struct ArgusInterfaceStruct *, int);

static void ArgusParseSFFlowSample(struct ArgusSourceStruct *, SFSample *, int);
static void ArgusParseSFCountersSample(struct ArgusSourceStruct *, SFSample *, int);

static void 
ArgusParseSFFlowSample(struct ArgusSourceStruct *src, SFSample *sptr, int state)
{
   struct timeval tvbuf, *tvp = &tvbuf;
   gettimeofday(tvp, 0L);

   if (sptr->datagramVersion >= 5) {
      u_char *start;
      int i, len, num;
  
      len = SFGetData32 (sptr);
      start = (u_char *)sptr->datap;

//    seq = SFGetData32 (sptr);
      SFGetData32 (sptr);

      if (state) {
         sptr->ds_class = SFGetData32 (sptr);
         sptr->ds_index = SFGetData32 (sptr);
      } else {
         uint32_t sid = SFGetData32 (sptr);
         sptr->ds_class = sid >> 24;
         sptr->ds_index = sid & 0x00FFFFFF;
      }
      sptr->meanSkipCount = SFGetData32 (sptr);
      sptr->samplePool    = SFGetData32 (sptr);
      sptr->dropEvents    = SFGetData32 (sptr);
      if (state) {
         sptr->inputPortFormat  = SFGetData32 (sptr);
         sptr->inputPort        = SFGetData32 (sptr);
         sptr->outputPortFormat = SFGetData32 (sptr);
         sptr->outputPort       = SFGetData32 (sptr);
      } else {
         uint32_t inp  = SFGetData32 (sptr);
         uint32_t outp = SFGetData32 (sptr);
         sptr->inputPortFormat  = inp >> 30;
         sptr->inputPort        = inp & 0x3FFFFFFF;
         sptr->outputPortFormat = outp >> 30;
         sptr->outputPort       = outp & 0x3FFFFFFF;
      }

      num = SFGetData32 (sptr);
      for (i = 0; i < num; i++) {
         uint32_t stag, slen;
         u_char *sdp = NULL;

         stag = SFGetData32 (sptr);
         slen = SFGetData32 (sptr);
         sdp  = (u_char *)sptr->datap;

         switch (stag) {
            case SFLFLOW_HEADER:           SFParseFlowSample_header(src, tvp, sptr); break;
            case SFLFLOW_ETHERNET:         SFParseFlowSample_ethernet(sptr); break;
            case SFLFLOW_IPV4:             SFParseFlowSample_IPv4(sptr); break;
            case SFLFLOW_IPV6:             SFParseFlowSample_IPv6(sptr); break;
            case SFLFLOW_MEMCACHE:         SFParseFlowSample_memcache(sptr); break;
            case SFLFLOW_HTTP:             SFParseFlowSample_http(sptr); break;
            case SFLFLOW_CAL:              SFParseFlowSample_CAL(sptr); break;
            case SFLFLOW_EX_SWITCH:        SFParseExtendedSwitch(sptr); break;
            case SFLFLOW_EX_ROUTER:        SFParseExtendedRouter(sptr); break;
            case SFLFLOW_EX_GATEWAY:       SFParseExtendedGateway(sptr); break;
            case SFLFLOW_EX_USER:          SFParseExtendedUser(sptr); break;
            case SFLFLOW_EX_URL:           SFParseExtendedUrl(sptr); break;
            case SFLFLOW_EX_MPLS:          SFParseExtendedMpls(sptr); break;
            case SFLFLOW_EX_NAT:           SFParseExtendedNat(sptr); break;
            case SFLFLOW_EX_MPLS_TUNNEL:   SFParseExtendedMplsTunnel(sptr); break;
            case SFLFLOW_EX_MPLS_VC:       SFParseExtendedMplsVC(sptr); break;
            case SFLFLOW_EX_MPLS_FTN:      SFParseExtendedMplsFTN(sptr); break;
            case SFLFLOW_EX_MPLS_LDP_FEC:  SFParseExtendedMplsLDP_FEC(sptr); break;
            case SFLFLOW_EX_VLAN_TUNNEL:   SFParseExtendedVlanTunnel(sptr); break;
            case SFLFLOW_EX_80211_PAYLOAD: SFParseExtendedWifiPayload(src, tvp, sptr); break;
            case SFLFLOW_EX_80211_RX:      SFParseExtendedWifiRx(sptr); break;
            case SFLFLOW_EX_80211_TX:      SFParseExtendedWifiTx(sptr); break;
            case SFLFLOW_EX_AGGREGATION:   SFParseExtendedAggregation(sptr); break;
            case SFLFLOW_EX_SOCKET4:       SFParseExtendedSocket4(sptr); break;
            case SFLFLOW_EX_SOCKET6:       SFParseExtendedSocket6(sptr); break;
            default:                       SFSkipBytes(sptr, slen); break;
         }
         SFLengthCheck(sptr, sdp, slen);
      }

      SFLengthCheck(sptr, start, len);
   }
}

static void
ArgusParseSFCountersSample(struct ArgusSourceStruct *src, SFSample *sptr, int state)
{
   if (sptr->datagramVersion >= 5) {
      uint32_t slen, num;
      u_char *sdp, *start;
      int i;

      slen = SFGetData32 (sptr);
      sdp = (u_char *)sptr->datap;
      sptr->samplesGenerated = SFGetData32 (sptr);
      
      if (state) {
         sptr->ds_class = SFGetData32 (sptr);
         sptr->ds_index = SFGetData32 (sptr);
      } else {
         uint32_t sptrrId = SFGetData32 (sptr);
         sptr->ds_class = sptrrId >> 24;
         sptr->ds_index = sptrrId & 0x00ffffff;
      }
      
      num = SFGetData32 (sptr);
         
      for (i = 0; i < num; i++) {
         uint32_t tag, length;
         tag    = SFGetData32 (sptr);
         length = SFGetData32 (sptr);
         start  = (u_char *)sptr->datap;
         
         switch (tag) {
            case SFLCOUNTERS_GENERIC:       SFParseCounters_generic(sptr); break;
            case SFLCOUNTERS_ETHERNET:      SFParseCounters_ethernet(sptr); break;
            case SFLCOUNTERS_TOKENRING:     SFParseCounters_tokenring(sptr); break;
            case SFLCOUNTERS_VG:            SFParseCounters_vg(sptr); break;
            case SFLCOUNTERS_VLAN:          SFParseCounters_vlan(sptr); break;
            case SFLCOUNTERS_80211:         SFParseCounters_80211(sptr); break;
            case SFLCOUNTERS_PROCESSOR:     SFParseCounters_processor(sptr); break;
            case SFLCOUNTERS_RADIO:         SFParseCounters_radio(sptr); break;
            case SFLCOUNTERS_HOST_HID:      SFParseCounters_host_hid(sptr); break;
            case SFLCOUNTERS_ADAPTORS:      SFParseCounters_adaptors(sptr); break;
            case SFLCOUNTERS_HOST_PAR:      SFParseCounters_host_parent(sptr); break;
            case SFLCOUNTERS_HOST_CPU:      SFParseCounters_host_cpu(sptr); break;
            case SFLCOUNTERS_HOST_MEM:      SFParseCounters_host_mem(sptr); break;
            case SFLCOUNTERS_HOST_DSK:      SFParseCounters_host_dsk(sptr); break;
            case SFLCOUNTERS_HOST_NIO:      SFParseCounters_host_nio(sptr); break;
            case SFLCOUNTERS_HOST_VRT_NODE: SFParseCounters_host_vnode(sptr); break;
            case SFLCOUNTERS_HOST_VRT_CPU:  SFParseCounters_host_vcpu(sptr); break;
            case SFLCOUNTERS_HOST_VRT_MEM:  SFParseCounters_host_vmem(sptr); break;
            case SFLCOUNTERS_HOST_VRT_DSK:  SFParseCounters_host_vdsk(sptr); break;
            case SFLCOUNTERS_HOST_VRT_NIO:  SFParseCounters_host_vnio(sptr); break;
            case SFLCOUNTERS_MEMCACHE:      SFParseCounters_memcache(sptr); break;
            case SFLCOUNTERS_HTTP:          SFParseCounters_http(sptr); break;
            case SFLCOUNTERS_CAL:           SFParseCounters_CAL(sptr); break;
            default:                        SFSkipBytes(sptr, length); break;
         }
         SFLengthCheck(sptr, start, length);
      }
      SFLengthCheck(sptr, sdp, slen);
   }
}

extern unsigned int ArgusSourceCount;

void
ArgusParseSflowRecord (struct ArgusModelerStruct *model, void *ptr)
{
   struct ArgusSourceStruct *stask = model->ArgusSrc, *src = NULL;
   SFSample sample, *sptr = &sample;
   uint32_t count, cnt, srcid;
   int i;

/*
   if (ArgusSflowModel == NULL)
      if ((ArgusSflowModel = ArgusNewModeler()) == NULL)
         ArgusLog (LOG_ERR, "Error Creating Modeler: Exiting.\n");

   bcopy(model, ArgusSflowModel, sizeof(*model));
*/

   cnt = model->ArgusThisSnapEnd - (u_char *)ptr;

   bzero(sptr, sizeof (sample));
   sptr->rawSample = ptr;
   sptr->rawSampleLen = cnt;

   sptr->datap = (uint32_t *) ptr;
   sptr->endp  = model->ArgusThisSnapEnd;

   sptr->datagramVersion = SFGetData32 (sptr);

   switch (sptr->datagramVersion) {
      case 2:
      case 4:
      case 5:
         break;
      default: {
#ifdef ARGUSDEBUG
         ArgusDebug (5, "ArgusParseSflowRecord (%p, %p) bad version  %d\n", model, ptr);
#endif

         return;
      }
   }

   SFGetAddress(sptr, &sptr->agent_addr);
   if (sptr->datagramVersion >= 5) {
      sptr->agentSubId = SFGetData32 (sptr);
   }

   srcid = sptr->agent_addr.address.ip_v4.addr;
/*
  if(address->type == SFLADDRESSTYPE_IP_V4)
    address->address.ip_v4.addr = SFGetData32_nobswap(sample);
  else {
    memcpy(&address->address.ip_v6.addr, sample->datap, 16);
    SFSkipBytes(sample, 16);
  } 
*/
   for (i = 1; i < ArgusSourceCount; i++) {
      struct ArgusSourceStruct *st = stask->srcs[i];
      if (st != NULL) {
         if (sptr->agent_addr.type == SFLADDRESSTYPE_IP_V4) {
            if (st->trans.srcid.a_un.ipv4 == ntohl(srcid)) {
               src = st;
               break;
	    }
	 }
      } else
         break;
   }

   if (src == NULL) {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusProcessSflowDatagram (%p, %p) Sflow srcid '%s' not found.\n", model, ptr, inet_ntoa(*(struct in_addr *)&srcid));
#endif
      if (ArgusSourceCount < ARGUS_MAXINTERFACE) {
         struct ArgusDeviceStruct *device = NULL;
         unsigned char buf[32];
         int slen = 0;

         bzero(buf, 32);
         src = ArgusCloneSource(stask);
         if ((src->ArgusModel = ArgusNewModeler()) == NULL)
            ArgusLog (LOG_ERR, "Error Creating Modeler: Exiting.\n");

         src->ArgusModel->ArgusSrc = src;
         src->ArgusThisIndex = 0;
         ArgusInitModeler(src->ArgusModel);

         if (sptr->agent_addr.type == SFLADDRESSTYPE_IP_V4)
            src->trans.srcid.a_un.ipv4 = ntohl(srcid);

         pthread_mutex_lock(&stask->lock);
         stask->srcs[ArgusSourceCount++] = src;
         pthread_mutex_unlock(&stask->lock);

         slen = sizeof(src->trans.srcid.a_un.ipv4);
         bcopy(&srcid, buf, slen);
         setArgusID (src, buf, slen, ARGUS_TYPE_IPV4);
         device = src->ArgusInterface[0].ArgusDevice;
         device->trans = src->trans;

      } else {
         ArgusLog (LOG_ERR, "ArgusParseSflowRecord: Too many Sflow Source Id's\n");
      }
   }

   sptr->sequenceNo = SFGetData32 (sptr);
   sptr->sysUpTime = SFGetData32 (sptr);
   count = SFGetData32 (sptr);

   for (i = 0; i < count; i++) {
      if ((u_char *)sptr->datap < sptr->endp) {
         sptr->sampleType = SFGetData32 (sptr);
         if (sptr->datagramVersion >= 5) {
            switch (sptr->sampleType) {
               case SFLFLOW_SAMPLE:
                  ArgusParseSFFlowSample(src, sptr, ARGUS_FALSE);
                  break;
               case SFLCOUNTERS_SAMPLE:
                  ArgusParseSFCountersSample(src, sptr, ARGUS_FALSE);
                  break;
               case SFLFLOW_SAMPLE_EXPANDED:
                  ArgusParseSFFlowSample(src, sptr, ARGUS_TRUE);
                  break;
               case SFLCOUNTERS_SAMPLE_EXPANDED:
                  ArgusParseSFCountersSample(src, sptr, ARGUS_TRUE);
                  break;
               default:
                  SFSkipBytes(sptr, SFGetData32 (sptr));
                  break;
            }
         } else {
            switch (sptr->sampleType) {
               case FLOWSAMPLE:
                  ArgusParseSFFlowSample(src, sptr, ARGUS_FALSE);
                  break;
               case COUNTERSSAMPLE:
                  ArgusParseSFCountersSample(src, sptr, ARGUS_FALSE);
                  break;
            }
         }

      } else
         break;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusProcessSflowDatagram (%p, %p) returning\n", model, ptr);
#endif

   return;
}

int
ArgusProcessSflowDatagram (struct ArgusSourceStruct *src, struct ArgusInterfaceStruct *inf, int cnt)
{
   SFSample sample, *sptr = &sample;
   uint32_t count;
   int retn = 0, i;

   bzero(sptr, sizeof (sample));
   sptr->rawSample = inf->ArgusReadPtr;
   sptr->rawSampleLen = cnt;
   sptr->sourceIP = inf->addr;

   sptr->datap = (uint32_t *)inf->ArgusReadPtr;
   sptr->endp  = ((u_char *)inf->ArgusReadPtr) + cnt;

   sptr->datagramVersion = SFGetData32 (sptr);

   switch (sptr->datagramVersion) {
      case 2:
      case 4:
      case 5:
         break;
      default: {
#ifdef ARGUSDEBUG
         ArgusDebug (5, "ArgusReadSflowStreamSocket (%p, %p) bad version  %d\n", src, inf, sptr->datagramVersion);
#endif

         return (1);
      }
   }

   SFGetAddress(sptr, &sptr->agent_addr);
   if (sptr->datagramVersion >= 5) {
      sptr->agentSubId = SFGetData32 (sptr);
   }

   sptr->sequenceNo = SFGetData32 (sptr);
   sptr->sysUpTime = SFGetData32 (sptr);
   count = SFGetData32 (sptr);

   for (i = 0; i < count; i++) {
      if ((u_char *)sptr->datap < sptr->endp) {
         sptr->sampleType = SFGetData32 (sptr);
         if (sptr->datagramVersion >= 5) {
            switch (sptr->sampleType) {
               case SFLFLOW_SAMPLE:
                  ArgusParseSFFlowSample(src, sptr, ARGUS_FALSE);
                  break;
               case SFLCOUNTERS_SAMPLE:
                  ArgusParseSFCountersSample(src, sptr, ARGUS_FALSE);
                  break;
               case SFLFLOW_SAMPLE_EXPANDED:
                  ArgusParseSFFlowSample(src, sptr, ARGUS_TRUE);
                  break;
               case SFLCOUNTERS_SAMPLE_EXPANDED:
                  ArgusParseSFCountersSample(src, sptr, ARGUS_TRUE);
                  break;
               default:
                  SFSkipBytes(sptr, SFGetData32 (sptr));
                  break;
            }
         } else {
            switch (sptr->sampleType) {
               case FLOWSAMPLE:
                  ArgusParseSFFlowSample(src, sptr, ARGUS_FALSE);
                  break;
               case COUNTERSSAMPLE:
                  ArgusParseSFCountersSample(src, sptr, ARGUS_FALSE);
                  break;
            }
         }

      } else
         break;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusProcessSflowDatagram (%p, %p, %d) returning %d\n", src, inf, cnt, retn);
#endif

   return (retn);
}

/*
int
ArgusReadSflowStreamSocket (struct ArgusParserStruct *parser, struct ArgusInput *input)
{
   int retn = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusReadSflowStreamSocket (%p, %p) returning %d\n", parser, input, retn);
#endif

   return (retn);
}
*/

int
ArgusReadSflowDatagramSocket (struct ArgusSourceStruct *src, struct ArgusInterfaceStruct *inf)
{
   int retn = 0, cnt = 0;
   struct sockaddr from;
   socklen_t fromlen = sizeof(from);
   struct sockaddr_in *sin = (struct sockaddr_in *)&from;

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusReadSflowDatagramSocket (%p, %p) starting\n", src, inf);
#endif

   if ((cnt = recvfrom (inf->fd, inf->ArgusReadPtr, inf->ArgusReadSocketSize, 0L, &from, &fromlen)) > 0) {
      inf->ArgusReadSocketCnt = cnt;

      if (from.sa_family == AF_INET)
         inf->addr.s_addr = ntohl(sin->sin_addr.s_addr);
      else
         inf->addr.s_addr = 0;

#ifdef ARGUSDEBUG
      ArgusDebug (8, "ArgusReadSflowDatagramSocket (%p) read %d bytes, capacity %d\n",
                      inf, cnt, inf->ArgusReadSocketCnt, inf->ArgusReadSocketSize);
#endif

      if (ArgusProcessSflowDatagram(src, inf, cnt))
         retn = 1;

   } else {
#ifdef ARGUSDEBUG
     ArgusDebug (3, "ArgusReadSflowDatagramSocket (%p) read returned %d error %s\n", src, cnt, strerror(errno));
#endif
      if ((cnt < 0) && ((errno == EAGAIN) || (errno == EINTR))) {
         retn = 0;
      } else
         retn = 1;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusReadSflowDatagramSocket (%p, %p) returning %d\n", src, inf, retn);
#endif

   return (retn);
}


void 
SFParseFlowSample_header(struct ArgusSourceStruct *src, struct timeval *tvp, SFSample *sptr)
{
   sptr->headerProtocol    = SFGetData32 (sptr);
   sptr->sampledPacketSize = SFGetData32 (sptr);

   if (sptr->datagramVersion > 4)
      sptr->stripped = SFGetData32 (sptr);
  
   sptr->headerLen  = SFGetData32 (sptr);
   sptr->header     = (u_char *)sptr->datap;

   ArgusSflowPacket (src, tvp, (const u_char *)sptr->datap, sptr->headerLen);

   SFSkipBytes(sptr, sptr->headerLen);
   
   switch(sptr->headerProtocol) {
      case SFLHEADER_ETHERNET_ISO8023:
        SFDecodeLinkLayer(sptr);
        break;
      case SFLHEADER_IPv4: 
        sptr->gotIPV4 = ARGUS_TRUE;
        sptr->offsetToIPV4 = 0;
        break;
      case SFLHEADER_IPv6: 
        sptr->gotIPV6 = ARGUS_TRUE;
        sptr->offsetToIPV6 = 0;
        break;
      case SFLHEADER_IEEE80211MAC:
        SFDecode80211MAC(sptr);
        break;
      case SFLHEADER_ISO88024_TOKENBUS:
      case SFLHEADER_ISO88025_TOKENRING:
      case SFLHEADER_FDDI:
      case SFLHEADER_FRAME_RELAY:
      case SFLHEADER_X25:
      case SFLHEADER_PPP:
      case SFLHEADER_SMDS:
      case SFLHEADER_AAL5:
      case SFLHEADER_AAL5_IP:
      case SFLHEADER_MPLS:
      case SFLHEADER_POS:
      case SFLHEADER_IEEE80211_AMPDU:
      case SFLHEADER_IEEE80211_AMSDU_SUBFRAME:
      default:
        break;
    }
   
   if (sptr->gotIPV4)
     SFDecodeIPV4 (sptr);
   else
   if (sptr->gotIPV6) 
     SFDecodeIPV6 (sptr);
}

void
SFParseFlowSample_ethernet(SFSample *sptr)
{
   sptr->eth_len = SFGetData32 (sptr);
   memcpy(sptr->eth_src, sptr->datap, 6);
   SFSkipBytes(sptr, 6);
   memcpy(sptr->eth_dst, sptr->datap, 6);
   SFSkipBytes(sptr, 6);
   sptr->eth_type = SFGetData32 (sptr);
}

void
SFParseFlowSample_IPv4 (SFSample *sptr)
{
   SFLSampled_ipv4 nfKey;

   sptr->headerLen = sizeof(SFLSampled_ipv4);
   sptr->header = (u_char *)sptr->datap; /* just point at the header */
   SFSkipBytes(sptr, sptr->headerLen);
   
   memcpy(&nfKey, sptr->header, sizeof(nfKey));
   sptr->sampledPacketSize = ntohl(nfKey.length);
   sptr->ipsrc.type = SFLADDRESSTYPE_IP_V4;
   sptr->ipsrc.address.ip_v4 = nfKey.src_ip;
   sptr->ipdst.type = SFLADDRESSTYPE_IP_V4;
   sptr->ipdst.address.ip_v4 = nfKey.dst_ip;
   sptr->dcd_ipProtocol = ntohl(nfKey.protocol);
   sptr->dcd_ipTos = ntohl(nfKey.tos);
   sptr->dcd_sport = ntohl(nfKey.src_port);
   sptr->dcd_dport = ntohl(nfKey.dst_port);

   switch(sptr->dcd_ipProtocol) {
      case IPPROTO_TCP:
         sptr->dcd_tcpFlags = ntohl(nfKey.tcp_flags);
         break;

      default: /* some other protcol */
         break;
   }
}

void
SFParseFlowSample_IPv6(SFSample *sptr)
{
   SFLSampled_ipv6 nfKey6;

   sptr->header = (u_char *)sptr->datap; /* just point at the header */
   sptr->headerLen = sizeof(SFLSampled_ipv6);
   SFSkipBytes(sptr, sptr->headerLen);
   memcpy(&nfKey6, sptr->header, sizeof(nfKey6));
   sptr->sampledPacketSize = ntohl(nfKey6.length);
   sptr->ipsrc.type = SFLADDRESSTYPE_IP_V6;
   memcpy(&sptr->ipsrc.address.ip_v6, &nfKey6.src_ip, 16);
   sptr->ipdst.type = SFLADDRESSTYPE_IP_V6;
   memcpy(&sptr->ipdst.address.ip_v6, &nfKey6.dst_ip, 16);
   sptr->dcd_ipProtocol = ntohl(nfKey6.protocol);
   sptr->dcd_sport = ntohl(nfKey6.src_port);
   sptr->dcd_dport = ntohl(nfKey6.dst_port);
   switch(sptr->dcd_ipProtocol) {
      case IPPROTO_TCP:
         sptr->dcd_tcpFlags = ntohl(nfKey6.tcp_flags);
         break;

      default: /* some other protcol */
         break;
   }
}

#define ENC_KEY_BYTES (SFL_MAX_MEMCACHE_KEY * 3) + 1

void
SFParseFlowSample_memcache (SFSample *sptr)
{
  char key[SFL_MAX_MEMCACHE_KEY+1];

   SFGetData32 (sptr); // memchache_op_protocol
   SFGetData32 (sptr); // memchache_op_cmd

   SFGetString(sptr, key, SFL_MAX_MEMCACHE_KEY);

   SFGetData32 (sptr); // memchache_op_nkeys
   SFGetData32 (sptr); // memchache_op_value_bytes
   SFGetData32 (sptr); // memchache_op_duration_uS
   SFGetData32 (sptr); // memchache_op_status
}

void
SFParseFlowSample_http(SFSample *sptr)
{
   char uri[SFL_MAX_HTTP_URI+1];
   char host[SFL_MAX_HTTP_HOST+1];
   char referrer[SFL_MAX_HTTP_REFERRER+1];
   char useragent[SFL_MAX_HTTP_USERAGENT+1];
   char authuser[SFL_MAX_HTTP_AUTHUSER+1];
   char mimetype[SFL_MAX_HTTP_MIMETYPE+1];
// uint32_t method, protocol, status, duration;
// uint64_t bytes;

// method   = SFGetData32 (sptr);
// protocol = SFGetData32 (sptr);

   SFGetData32 (sptr);
   SFGetData32 (sptr);

   SFGetString(sptr, uri, SFL_MAX_HTTP_URI);
   SFGetString(sptr, host, SFL_MAX_HTTP_HOST);
   SFGetString(sptr, referrer, SFL_MAX_HTTP_REFERRER);
   SFGetString(sptr, useragent, SFL_MAX_HTTP_USERAGENT);
   SFGetString(sptr, authuser, SFL_MAX_HTTP_AUTHUSER);
   SFGetString(sptr, mimetype, SFL_MAX_HTTP_MIMETYPE);

// bytes    = SFGetData64 (sptr);
// duration = SFGetData32 (sptr);
// status   = SFGetData32 (sptr);

   SFGetData64 (sptr);
   SFGetData32 (sptr);
   SFGetData32 (sptr);
}

void
SFParseFlowSample_CAL(SFSample *sptr)
{
   char pool[SFLCAL_MAX_POOL_LEN];
   char transaction[SFLCAL_MAX_TRANSACTION_LEN];
   char operation[SFLCAL_MAX_OPERATION_LEN];
   char status[SFLCAL_MAX_STATUS_LEN];

   SFGetData32 (sptr); // ttype
   SFGetData32 (sptr); // depth

   SFGetString(sptr, pool, SFLCAL_MAX_POOL_LEN);
   SFGetString(sptr, transaction, SFLCAL_MAX_TRANSACTION_LEN);
   SFGetString(sptr, operation, SFLCAL_MAX_OPERATION_LEN);
   SFGetString(sptr, status, SFLCAL_MAX_STATUS_LEN);

   SFGetData64 (sptr); // duration_uS
}

void
SFParseExtendedSwitch(SFSample *sptr)
{
   sptr->in_vlan            = SFGetData32 (sptr);
   sptr->in_priority        = SFGetData32 (sptr);
   sptr->out_vlan           = SFGetData32 (sptr);
   sptr->out_priority       = SFGetData32 (sptr);
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_SWITCH;
}

void
SFParseExtendedRouter(SFSample *sptr)
{
   SFGetAddress(sptr, &sptr->nextHop);
   sptr->srcMask            = SFGetData32 (sptr);
   sptr->dstMask            = SFGetData32 (sptr);
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_ROUTER;
}

void
SFParseExtendedGateway(SFSample *sptr)
{
   uint32_t segments;
   uint32_t seg;

   if(sptr->datagramVersion >= 5)
      SFGetAddress(sptr, &sptr->bgp_nextHop);

   sptr->my_as       = SFGetData32 (sptr);
   sptr->src_as      = SFGetData32 (sptr);
   sptr->src_peer_as = SFGetData32 (sptr);
   segments          = SFGetData32 (sptr);

   // clear dst_peer_as and dst_as to make sure we are not
   // remembering values from a previous sptr - (thanks Marc Lavine)
   sptr->dst_peer_as = 0;
   sptr->dst_as = 0;

   if (segments > 0) {
      for (seg = 0; seg < segments; seg++) {
//       uint32_t i, seg_type, seg_len;
         uint32_t i, seg_len;

//       seg_type = SFGetData32 (sptr);
         SFGetData32 (sptr);
         seg_len  = SFGetData32 (sptr);
         for (i = 0; i < seg_len; i++) {
            uint32_t asNumber;
            asNumber = SFGetData32 (sptr);
            /* mark the first one as the dst_peer_as */
            if (i == 0 && seg == 0)
               sptr->dst_peer_as = asNumber;

            /* mark the last one as the dst_as */
            if (seg == (segments - 1) && i == (seg_len - 1))
               sptr->dst_as = asNumber;
         }
      }
   }

   sptr->communities_len = SFGetData32 (sptr);
   /* just point at the communities array */
   if (sptr->communities_len > 0)
      sptr->communities = sptr->datap;
   /* and skip over it in the input */
   SFSkipBytes(sptr, sptr->communities_len * 4);
 
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
   sptr->localpref = SFGetData32 (sptr);
}

void
SFParseExtendedUser(SFSample *sptr)
{
   if (sptr->datagramVersion >= 5)
      sptr->src_user_charset = SFGetData32 (sptr);

   sptr->src_user_len = SFGetString(sptr, sptr->src_user, SA_MAX_EXTENDED_USER_LEN);

   if (sptr->datagramVersion >= 5)
      sptr->dst_user_charset = SFGetData32 (sptr);

   sptr->dst_user_len = SFGetString(sptr, sptr->dst_user, SA_MAX_EXTENDED_USER_LEN);
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_USER;
}

void
SFParseExtendedUrl(SFSample *sptr)
{
   sptr->url_direction = SFGetData32 (sptr);
   sptr->url_len = SFGetString(sptr, sptr->url, SA_MAX_EXTENDED_URL_LEN);

   if(sptr->datagramVersion >= 5)
      sptr->host_len = SFGetString(sptr, sptr->host, SA_MAX_EXTENDED_HOST_LEN);

   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_URL;
}

void SFMplsLabelStack(SFSample *, char *);

void
SFMplsLabelStack(SFSample *sptr, char *fieldName)
{
   SFLLabelStack lstk;

   lstk.depth = SFGetData32 (sptr);
   /* just point at the lablelstack array */
   if(lstk.depth > 0)
      lstk.stack = (uint32_t *)sptr->datap;
   /* and skip over it in the input */
   SFSkipBytes(sptr, lstk.depth * 4);
}

void
SFParseExtendedMpls(SFSample *sptr)
{
   SFGetAddress(sptr, &sptr->mpls_nextHop);
  SFMplsLabelStack(sptr, "mpls_input_stack");
  SFMplsLabelStack(sptr, "mpls_output_stack");

  sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS;
}

void
SFParseExtendedNat(SFSample *sptr)
{
   SFGetAddress(sptr, &sptr->nat_src);
   SFGetAddress(sptr, &sptr->nat_dst);
  sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_NAT;
}


#define SA_MAX_TUNNELNAME_LEN 100

void
SFParseExtendedMplsTunnel(SFSample *sptr)
{
   char tunnel_name[SA_MAX_TUNNELNAME_LEN+1];
// uint32_t tunnel_id, tunnel_cos;

   SFGetString(sptr, tunnel_name, SA_MAX_TUNNELNAME_LEN);
// tunnel_id = SFGetData32 (sptr);
// tunnel_cos = SFGetData32 (sptr);
   SFGetData32 (sptr);
   SFGetData32 (sptr);
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL;
}


#define SA_MAX_VCNAME_LEN 100

void
SFParseExtendedMplsVC (SFSample *sptr)
{
   char vc_name[SA_MAX_VCNAME_LEN+1];
// uint32_t vll_vc_id, vc_cos;

   SFGetString(sptr, vc_name, SA_MAX_VCNAME_LEN);
// vll_vc_id = SFGetData32 (sptr);
// vc_cos = SFGetData32 (sptr);

   SFGetData32 (sptr);
   SFGetData32 (sptr);
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_VC;
}


#define SA_MAX_FTN_LEN 100

void
SFParseExtendedMplsFTN (SFSample *sptr)
{
   char ftn_descr[SA_MAX_FTN_LEN+1];
// uint32_t ftn_mask;
   SFGetString(sptr, ftn_descr, SA_MAX_FTN_LEN);
// ftn_mask = SFGetData32 (sptr);
   SFGetData32 (sptr);
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_FTN;
}

void
SFParseExtendedMplsLDP_FEC(SFSample *sptr)
{
   SFGetData32 (sptr); // fec_addr_prefix_len
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC;
}

void
SFParseExtendedVlanTunnel(SFSample *sptr)
{
   SFLLabelStack lstk;
   lstk.depth = SFGetData32 (sptr);

   /* just point at the lablelstack array */
   if(lstk.depth > 0)
      lstk.stack = (uint32_t *)sptr->datap;

   /* and skip over it in the input */
   SFSkipBytes(sptr, lstk.depth * 4);
   sptr->extended_data_tag |= SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL;
}

void
SFParseExtendedWifiPayload(struct ArgusSourceStruct *src, struct timeval *tvp, SFSample *sptr)
{
   SFGetData32 (sptr);  // "cipher_suite"
   SFParseFlowSample_header(src, tvp, sptr);
}

void
SFParseExtendedWifiRx(SFSample *sptr)
{
   char ssid[SFL_MAX_SSID_LEN+1];

   SFGetString(sptr, ssid, SFL_MAX_SSID_LEN);
   SFSkipBytes(sptr, 6);

   SFGetData32 (sptr); // "rx_version");
   SFGetData32 (sptr); // "rx_channel");
   SFGetData64 (sptr); // "rx_speed");
   SFGetData32 (sptr); // "rx_rsni");
   SFGetData32 (sptr); // "rx_rcpi");
   SFGetData32 (sptr); // "rx_packet_uS");
}

void
SFParseExtendedWifiTx(SFSample *sptr)
{
   char ssid[SFL_MAX_SSID_LEN+1];
   SFGetString(sptr, ssid, SFL_MAX_SSID_LEN);
   SFSkipBytes(sptr, 6);

   SFGetData32 (sptr); // "tx_version"
   SFGetData32 (sptr); // "tx_transmissions"
   SFGetData32 (sptr); // "tx_packet_uS"
   SFGetData32 (sptr); // "tx_retrans_uS"
   SFGetData32 (sptr); // "tx_channel"
   SFGetData64 (sptr); // "tx_speed"
   SFGetData32 (sptr); // "tx_power_mW"
}

void
SFParseExtendedAggregation(SFSample *sptr)
{
}

void
SFParseExtendedSocket4(SFSample *sptr)
{
   SFGetData32 (sptr); //   "socket4_ip_protocol"
   sptr->ipsrc.type                      = SFLADDRESSTYPE_IP_V4;
   sptr->ipsrc.address.ip_v4.addr = SFGetData32_nobswap(sptr);
   sptr->ipdst.type                      = SFLADDRESSTYPE_IP_V4;
   sptr->ipdst.address.ip_v4.addr = SFGetData32_nobswap(sptr);

   SFGetData32 (sptr); //   "socket4_local_port"
   SFGetData32 (sptr); //   "socket4_remote_port"
}

void
SFParseExtendedSocket6(SFSample *sptr)
{
   SFGetData32 (sptr);   // "socket6_ip_protocol"
   sptr->ipsrc.type = SFLADDRESSTYPE_IP_V6;
   memcpy(&sptr->ipsrc.address.ip_v6, sptr->datap, 16);
   SFSkipBytes(sptr, 16);
   sptr->ipdst.type = SFLADDRESSTYPE_IP_V6;
   memcpy(&sptr->ipdst.address.ip_v6, sptr->datap, 16);
   SFSkipBytes(sptr, 16);
   SFGetData32 (sptr);   // "socket6_local_port"
   SFGetData32 (sptr);   // "socket6_remote_port"
}


void
SFParseCounters_generic (SFSample *sptr)
{
  /* the first part of the generic counters block is really just more info about the interface. */
  sptr->ifCounters.ifIndex            = SFGetData32 (sptr);  // "ifIndex"
  sptr->ifCounters.ifType             = SFGetData32 (sptr);  // "networkType"
  sptr->ifCounters.ifSpeed            = SFGetData64 (sptr);  // "ifSpeed"
  sptr->ifCounters.ifDirection        = SFGetData32 (sptr);  // "ifDirection"
  sptr->ifCounters.ifStatus           = SFGetData32 (sptr);  // "ifStatus"

  /* the generic counters always come first */
  sptr->ifCounters.ifInOctets         = SFGetData64 (sptr);  // "ifInOctets"
  sptr->ifCounters.ifInUcastPkts      = SFGetData32 (sptr);  // "ifInUcastPkts"
  sptr->ifCounters.ifInMulticastPkts  = SFGetData32 (sptr);  // "ifInMulticastPkts"
  sptr->ifCounters.ifInBroadcastPkts  = SFGetData32 (sptr);  // "ifInBroadcastPkts"
  sptr->ifCounters.ifInDiscards       = SFGetData32 (sptr);  // "ifInDiscards"
  sptr->ifCounters.ifInErrors         = SFGetData32 (sptr);  // "ifInErrors"
  sptr->ifCounters.ifInUnknownProtos  = SFGetData32 (sptr);  // "ifInUnknownProtos"
  sptr->ifCounters.ifOutOctets        = SFGetData64 (sptr);  // "ifOutOctets"
  sptr->ifCounters.ifOutUcastPkts     = SFGetData32 (sptr);  // "ifOutUcastPkts"
  sptr->ifCounters.ifOutMulticastPkts = SFGetData32 (sptr);  // "ifOutMulticastPkts"
  sptr->ifCounters.ifOutBroadcastPkts = SFGetData32 (sptr);  // "ifOutBroadcastPkts"
  sptr->ifCounters.ifOutDiscards      = SFGetData32 (sptr);  // "ifOutDiscards"
  sptr->ifCounters.ifOutErrors        = SFGetData32 (sptr);  // "ifOutErrors"
  sptr->ifCounters.ifPromiscuousMode  = SFGetData32 (sptr);  // "ifPromiscuousMode"
}

void
SFParseCounters_ethernet (SFSample *sptr)
{
   SFGetData32 (sptr);  // "dot3StatsAlignmentErrors"
   SFGetData32 (sptr);  // "dot3StatsFCSErrors"
   SFGetData32 (sptr);  // "dot3StatsSingleCollisionFrames"
   SFGetData32 (sptr);  // "dot3StatsMultipleCollisionFrames"
   SFGetData32 (sptr);  // "dot3StatsSQETestErrors"
   SFGetData32 (sptr);  // "dot3StatsDeferredTransmissions"
   SFGetData32 (sptr);  // "dot3StatsLateCollisions"
   SFGetData32 (sptr);  // "dot3StatsExcessiveCollisions"
   SFGetData32 (sptr);  // "dot3StatsInternalMacTransmitErrors"
   SFGetData32 (sptr);  // "dot3StatsCarrierSenseErrors"
   SFGetData32 (sptr);  // "dot3StatsFrameTooLongs"
   SFGetData32 (sptr);  // "dot3StatsInternalMacReceiveErrors"
   SFGetData32 (sptr);  // "dot3StatsSymbolErrors"
}

void
SFParseCounters_tokenring (SFSample *sptr)
{
   SFGetData32 (sptr);  // "dot5StatsLineErrors"
   SFGetData32 (sptr);  // "dot5StatsBurstErrors"
   SFGetData32 (sptr);  // "dot5StatsACErrors"
   SFGetData32 (sptr);  // "dot5StatsAbortTransErrors"
   SFGetData32 (sptr);  // "dot5StatsInternalErrors"
   SFGetData32 (sptr);  // "dot5StatsLostFrameErrors"
   SFGetData32 (sptr);  // "dot5StatsReceiveCongestions"
   SFGetData32 (sptr);  // "dot5StatsFrameCopiedErrors"
   SFGetData32 (sptr);  // "dot5StatsTokenErrors"
   SFGetData32 (sptr);  // "dot5StatsSoftErrors"
   SFGetData32 (sptr);  // "dot5StatsHardErrors"
   SFGetData32 (sptr);  // "dot5StatsSignalLoss"
   SFGetData32 (sptr);  // "dot5StatsTransmitBeacons"
   SFGetData32 (sptr);  // "dot5StatsRecoverys"
   SFGetData32 (sptr);  // "dot5StatsLobeWires"
   SFGetData32 (sptr);  // "dot5StatsRemoves"
   SFGetData32 (sptr);  // "dot5StatsSingles"
   SFGetData32 (sptr);  // "dot5StatsFreqErrors"
}

void
SFParseCounters_vg (SFSample *sptr)
{
   SFGetData32 (sptr);  // "dot12InHighPriorityFrames"
   SFGetData64 (sptr);  // "dot12InHighPriorityOctets"
   SFGetData32 (sptr);  // "dot12InNormPriorityFrames"
   SFGetData64 (sptr);  // "dot12InNormPriorityOctets"
   SFGetData32 (sptr);  // "dot12InIPMErrors"
   SFGetData32 (sptr);  // "dot12InOversizeFrameErrors"
   SFGetData32 (sptr);  // "dot12InDataErrors"
   SFGetData32 (sptr);  // "dot12InNullAddressedFrames"
   SFGetData32 (sptr);  // "dot12OutHighPriorityFrames"
   SFGetData64 (sptr);  // "dot12OutHighPriorityOctets"
   SFGetData32 (sptr);  // "dot12TransitionIntoTrainings"
   SFGetData64 (sptr);  // "dot12HCInHighPriorityOctets"
   SFGetData64 (sptr);  // "dot12HCInNormPriorityOctets"
   SFGetData64 (sptr);  // "dot12HCOutHighPriorityOctets"
}

void
SFParseCounters_vlan (SFSample *sptr)
{
  sptr->in_vlan = SFGetData32 (sptr);

   SFGetData64 (sptr);  // "octets"
   SFGetData32 (sptr);  // "ucastPkts"
   SFGetData32 (sptr);  // "multicastPkts"
   SFGetData32 (sptr);  // "broadcastPkts"
   SFGetData32 (sptr);  // "discards"
}

void
SFParseCounters_80211 (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "dot11TransmittedFragmentCount"
   SFGetData32 (sptr);  //  "dot11MulticastTransmittedFrameCount"
   SFGetData32 (sptr);  //  "dot11FailedCount"
   SFGetData32 (sptr);  //  "dot11RetryCount"
   SFGetData32 (sptr);  //  "dot11MultipleRetryCount"
   SFGetData32 (sptr);  //  "dot11FrameDuplicateCount"
   SFGetData32 (sptr);  //  "dot11RTSSuccessCount"
   SFGetData32 (sptr);  //  "dot11RTSFailureCount"
   SFGetData32 (sptr);  //  "dot11ACKFailureCount"
   SFGetData32 (sptr);  //  "dot11ReceivedFragmentCount"
   SFGetData32 (sptr);  //  "dot11MulticastReceivedFrameCount"
   SFGetData32 (sptr);  //  "dot11FCSErrorCount"
   SFGetData32 (sptr);  //  "dot11TransmittedFrameCount"
   SFGetData32 (sptr);  //  "dot11WEPUndecryptableCount"
   SFGetData32 (sptr);  //  "dot11QoSDiscardedFragmentCount"
   SFGetData32 (sptr);  //  "dot11AssociatedStationCount"
   SFGetData32 (sptr);  //  "dot11QoSCFPollsReceivedCount"
   SFGetData32 (sptr);  //  "dot11QoSCFPollsUnusedCount"
   SFGetData32 (sptr);  //  "dot11QoSCFPollsUnusableCount"
   SFGetData32 (sptr);  //  "dot11QoSCFPollsLostCount"
}

void
SFParseCounters_processor (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "5s_cpu"
   SFGetData32 (sptr);  //  "1m_cpu"
   SFGetData32 (sptr);  //  "5m_cpu"
   SFGetData64(sptr);  //  "total_memory_bytes"
   SFGetData64(sptr);  //  "free_memory_bytes"
}

void
SFParseCounters_radio (SFSample *sptr)
{
   SFGetData32 (sptr);  // "radio_elapsed_time"
   SFGetData32 (sptr);  // "radio_on_channel_time"
   SFGetData32 (sptr);  // "radio_on_channel_busy_time"
}

void
SFParseCounters_host_hid (SFSample *sptr)
{
   char hostname[SFL_MAX_HOSTNAME_LEN+1];
   char os_release[SFL_MAX_OSRELEASE_LEN+1];

   SFGetString(sptr, hostname, SFL_MAX_HOSTNAME_LEN);
   SFSkipBytes(sptr, 16);
   SFGetData32 (sptr);  //  "machine_type");
   SFGetData32 (sptr);  //  "os_name");
   SFGetString(sptr, os_release, SFL_MAX_OSRELEASE_LEN);
}

void
SFParseCounters_adaptors (SFSample *sptr)
{
// uint32_t i, j, ifindex, num_macs;
   uint32_t i, j, num_macs;
   uint32_t num = SFGetData32 (sptr);

   for (i = 0; i < num; i++) {
//    ifindex  = SFGetData32 (sptr);
      SFGetData32 (sptr);
      num_macs = SFGetData32 (sptr);
      for (j = 0; j < num_macs; j++) 
         SFSkipBytes(sptr, 8);
   }
}

void
SFParseCounters_host_parent (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "parent_dsClass"
   SFGetData32 (sptr);  //  "parent_dsIndex"
}

void
SFParseCounters_host_cpu (SFSample *sptr)
{
   SFGetFloat (sptr);   // "cpu_load_one");
   SFGetFloat (sptr);   // "cpu_load_five");
   SFGetFloat (sptr);   // "cpu_load_fifteen");
   SFGetData32 (sptr);  // "cpu_proc_run");
   SFGetData32 (sptr);  // "cpu_proc_total");
   SFGetData32 (sptr);  // "cpu_num");
   SFGetData32 (sptr);  // "cpu_speed");
   SFGetData32 (sptr);  // "cpu_uptime");
   SFGetData32 (sptr);  // "cpu_user");
   SFGetData32 (sptr);  // "cpu_nice");
   SFGetData32 (sptr);  // "cpu_system");
   SFGetData32 (sptr);  // "cpu_idle");
   SFGetData32 (sptr);  // "cpu_wio");
   SFGetData32 (sptr);  // "cpuintr");
   SFGetData32 (sptr);  // "cpu_sintr");
   SFGetData32 (sptr);  // "cpuinterrupts");
   SFGetData32 (sptr);  // "cpu_contexts");
}

void
SFParseCounters_host_mem (SFSample *sptr)
{
   SFGetData64 (sptr);  //  "mem_total"
   SFGetData64 (sptr);  //  "mem_free"
   SFGetData64 (sptr);  //  "mem_shared"
   SFGetData64 (sptr);  //  "mem_buffers"
   SFGetData64 (sptr);  //  "mem_cached"
   SFGetData64 (sptr);  //  "swap_total"
   SFGetData64 (sptr);  //  "swap_free"
   SFGetData32 (sptr);  //  "page_in"
   SFGetData32 (sptr);  //  "page_out"
   SFGetData32 (sptr);  //  "swap_in"
   SFGetData32 (sptr);  //  "swap_out"
}

void
SFParseCounters_host_dsk (SFSample *sptr)
{
   SFGetData64 (sptr);  //  "disk_total"
   SFGetData64 (sptr);  //  "disk_free"
   SFGetData32 (sptr);  //  "disk_partition_max_used"
   SFGetData32 (sptr);  //  "disk_reads"
   SFGetData64 (sptr);  //  "disk_bytes_read"
   SFGetData32 (sptr);  //  "disk_read_time"
   SFGetData32 (sptr);  //  "disk_writes"
   SFGetData64 (sptr);  //  "disk_bytes_written"
   SFGetData32 (sptr);  //  "disk_write_time"
}

void
SFParseCounters_host_nio (SFSample *sptr)
{
   SFGetData64 (sptr);  //  "nio_bytes_in"
   SFGetData32 (sptr);  //  "nio_pkts_in"
   SFGetData32 (sptr);  //  "nio_errs_in"
   SFGetData32 (sptr);  //  "nio_drops_in"
   SFGetData64 (sptr);  //  "nio_bytes_out"
   SFGetData32 (sptr);  //  "nio_pkts_out"
   SFGetData32 (sptr);  //  "nio_errs_out"
   SFGetData32 (sptr);  //  "nio_drops_out"
}

void
SFParseCounters_host_vnode (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "vnode_mhz"
   SFGetData32 (sptr);  //  "vnode_cpus"
   SFGetData64 (sptr);  //  "vnode_memory"
   SFGetData64 (sptr);  //  "vnode_memory_free"
   SFGetData32 (sptr);  //  "vnode_num_domains"
}

void
SFParseCounters_host_vcpu (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "vcpu_state"
   SFGetData32 (sptr);  //  "vcpu_cpu_mS"
   SFGetData32 (sptr);  //  "vcpu_cpuCount"
}

void
SFParseCounters_host_vmem (SFSample *sptr)
{
   SFGetData64 (sptr);  //  "vmem_memory"
   SFGetData64 (sptr);  //  "vmem_maxMemory"
}

void
SFParseCounters_host_vdsk (SFSample *sptr)
{
   SFGetData64 (sptr);  //  "vdsk_capacity"
   SFGetData64 (sptr);  //  "vdsk_allocation"
   SFGetData64 (sptr);  //  "vdsk_available"
   SFGetData32 (sptr);  //  "vdsk_rd_req"
   SFGetData64 (sptr);  //  "vdsk_rd_bytes"
   SFGetData32 (sptr);  //  "vdsk_wr_req"
   SFGetData64 (sptr);  //  "vdsk_wr_bytes"
   SFGetData32 (sptr);  //  "vdsk_errs"
}

void
SFParseCounters_host_vnio (SFSample *sptr)
{
   SFGetData64 (sptr);  //  "vnio_bytes_in"
   SFGetData32 (sptr);  //  "vnio_pkts_in"
   SFGetData32 (sptr);  //  "vnio_errs_in"
   SFGetData32 (sptr);  //  "vnio_drops_in"
   SFGetData64 (sptr);  //  "vnio_bytes_out"
   SFGetData32 (sptr);  //  "vnio_pkts_out"
   SFGetData32 (sptr);  //  "vnio_errs_out"
   SFGetData32 (sptr);  //  "vnio_drops_out"
}

void
SFParseCounters_memcache (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "memcache_uptime"
   SFGetData32 (sptr);  //  "memcache_rusage_user"
   SFGetData32 (sptr);  //  "memcache_rusage_system"
   SFGetData32 (sptr);  //  "memcache_curr_connections"
   SFGetData32 (sptr);  //  "memcache_total_connections"
   SFGetData32 (sptr);  //  "memcache_connection_structures"
   SFGetData32 (sptr);  //  "memcache_cmd_get"
   SFGetData32 (sptr);  //  "memcache_cmd_set"
   SFGetData32 (sptr);  //  "memcache_cmd_flush"
   SFGetData32 (sptr);  //  "memcache_get_hits"
   SFGetData32 (sptr);  //  "memcache_get_misses"
   SFGetData32 (sptr);  //  "memcache_delete_misses"
   SFGetData32 (sptr);  //  "memcache_delete_hits"
   SFGetData32 (sptr);  //  "memcache_incr_misses"
   SFGetData32 (sptr);  //  "memcache_incr_hits"
   SFGetData32 (sptr);  //  "memcache_decr_misses"
   SFGetData32 (sptr);  //  "memcache_decr_hits"
   SFGetData32 (sptr);  //  "memcache_cas_misses"
   SFGetData32 (sptr);  //  "memcache_cas_hits"
   SFGetData32 (sptr);  //  "memcache_cas_badval"
   SFGetData32 (sptr);  //  "memcache_auth_cmds"
   SFGetData32 (sptr);  //  "memcache_auth_errors"
   SFGetData64 (sptr);  //  "memcache_bytes_read"
   SFGetData64 (sptr);  //  "memcache_bytes_written"
   SFGetData32 (sptr);  //  "memcache_limit_maxbytes"
   SFGetData32 (sptr);  //  "memcache_accepting_conns"
   SFGetData32 (sptr);  //  "memcache_listen_disabled_num"
   SFGetData32 (sptr);  //  "memcache_threads"
   SFGetData32 (sptr);  //  "memcache_conn_yields"
   SFGetData64 (sptr);  //  "memcache_bytes"
   SFGetData32 (sptr);  //  "memcache_curr_items"
   SFGetData32 (sptr);  //  "memcache_total_items"
   SFGetData32 (sptr);  //  "memcache_evictions"
}

void
SFParseCounters_http (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "http_method_option_count"
   SFGetData32 (sptr);  //  "http_method_get_count"
   SFGetData32 (sptr);  //  "http_method_head_count"
   SFGetData32 (sptr);  //  "http_method_post_count"
   SFGetData32 (sptr);  //  "http_method_put_count"
   SFGetData32 (sptr);  //  "http_method_delete_count"
   SFGetData32 (sptr);  //  "http_method_trace_count"
   SFGetData32 (sptr);  //  "http_methd_connect_count"
   SFGetData32 (sptr);  //  "http_method_other_count"
   SFGetData32 (sptr);  //  "http_status_1XX_count"
   SFGetData32 (sptr);  //  "http_status_2XX_count"
   SFGetData32 (sptr);  //  "http_status_3XX_count"
   SFGetData32 (sptr);  //  "http_status_4XX_count"
   SFGetData32 (sptr);  //  "http_status_5XX_count"
   SFGetData32 (sptr);  //  "http_status_other_count"
}

void
SFParseCounters_CAL (SFSample *sptr)
{
   SFGetData32 (sptr);  //  "transactions"
   SFGetData32 (sptr);  //  "errors"
   SFGetData64 (sptr);  //  "duration_uS"
}


static void
SFLengthCheck(SFSample *sample, u_char *start, int len) 
{
  uint32_t actualLen = (u_char *)sample->datap - start;
  uint32_t adjustedLen = ((len + 3) >> 2) << 2;
  if(actualLen != adjustedLen) {
    SFABORT(sample, SF_ABORT_LENGTH_ERROR);
  }
}

/* define my own IP header struct - to ease portability */
struct SFmyiphdr {
    uint8_t version_and_headerLen;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

/* same for tcp */
struct SFmytcphdr
  {
    uint16_t th_sport;          /* source port */
    uint16_t th_dport;          /* destination port */
    uint32_t th_seq;            /* sequence number */
    uint32_t th_ack;            /* acknowledgement number */
    uint8_t th_off_and_unused;
    uint8_t th_flags;
    uint16_t th_win;            /* window */
    uint16_t th_sum;            /* checksum */
    uint16_t th_urp;            /* urgent pointer */
};

/* and UDP */
struct SFmyudphdr {
  uint16_t uh_sport;           /* source port */
  uint16_t uh_dport;           /* destination port */
  uint16_t uh_ulen;            /* udp length */
  uint16_t uh_sum;             /* udp checksum */
};

/* and ICMP */
struct SFmyicmphdr
{
  uint8_t type;         /* message type */
  uint8_t code;         /* type sub-code */
  /* ignore the rest */
};


static void 
SFDecodeIPV4(SFSample *sptr)
{
   if (sptr->gotIPV4) {
      u_char *ptr = sptr->header + sptr->offsetToIPV4;
      /* Create a local copy of the IP header (cannot overlay structure in case it is not quad-aligned...some
          platforms would core-dump if we tried that).   It's OK coz this probably performs just as well anyway. */
      struct SFmyiphdr ip;
      memcpy(&ip, ptr, sizeof(ip));
      /* Value copy all ip elements into sptr */
      sptr->ipsrc.type = SFLADDRESSTYPE_IP_V4;
      sptr->ipsrc.address.ip_v4.addr = ip.saddr;
      sptr->ipdst.type = SFLADDRESSTYPE_IP_V4;
      sptr->ipdst.address.ip_v4.addr = ip.daddr;
      sptr->dcd_ipProtocol = ip.protocol;
      sptr->dcd_ipTos = ip.tos;
      sptr->dcd_ipTTL = ip.ttl;
      sptr->ip_fragmentOffset = ntohs(ip.frag_off) & 0x1FFF;
      if(sptr->ip_fragmentOffset > 0) {
      } else {
         /* advance the pointer to the next protocol layer */
         /* ip headerLen is expressed as a number of quads */
         ptr += (ip.version_and_headerLen & 0x0f) * 4;
         SFDecodeIPLayer4(sptr, ptr);
      }
   }
}


static void 
SFDecodeIPV6(SFSample *sptr)
{
// uint16_t payloadLen;
// uint32_t label;
   uint32_t nextHeader;
   u_char *end = sptr->header + sptr->headerLen;

   if(sptr->gotIPV6) {
      u_char *ptr = sptr->header + sptr->offsetToIPV6;
      int ipVersion = (*ptr >> 4);
      
      if(ipVersion != 6)
         return;

      // get the tos (priority)
      sptr->dcd_ipTos = *ptr++ & 15;
      // get past the 24-bit label
/*
      label = *ptr++;
      label <<= 8;
      label += *ptr++;
      label <<= 8;
      label += *ptr++;
      // payload
      // payloadLen = (ptr[0] << 8) + ptr[1];
      ptr += 2;
*/
      ptr += 5;
      // next header
      nextHeader = *ptr++;

      // TTL
      sptr->dcd_ipTTL = *ptr++;

      sptr->ipsrc.type = SFLADDRESSTYPE_IP_V6;
      memcpy(&sptr->ipsrc.address, ptr, 16);
      ptr +=16;
      sptr->ipdst.type = SFLADDRESSTYPE_IP_V6;
      memcpy(&sptr->ipdst.address, ptr, 16);
      ptr +=16;

      // skip over some common header extensions...
      // http://searchnetworking.techtarget.com/originalContent/0,289142,sid7_gci870277,00.html
      while(nextHeader == 0 ||   // hop
      nextHeader == 43 || // routing
      nextHeader == 44 || // fragment
      // nextHeader == 50 || // encryption - don't bother coz we'll not be able to read any further
      nextHeader == 51 || // auth
      nextHeader == 60) { // destination options
         uint32_t optionLen, skip;
         nextHeader = ptr[0];
         optionLen = 8 * (ptr[1] + 1);   // second byte gives option len in 8-byte chunks, not counting first 8
         skip = optionLen - 2;
         ptr += skip;
         if(ptr > end) return; // ran off the end of the header
      }
      
      // now that we have eliminated the extension headers, nextHeader should have what we want to
      // remember as the ip protocol...
      sptr->dcd_ipProtocol = nextHeader;
      SFDecodeIPLayer4(sptr, ptr);
   }
}

static void 
SFDecodeIPLayer4(SFSample *sptr, u_char *ptr)
{
   u_char *end = sptr->header + sptr->headerLen;
   if (ptr > (end - 8)) {
      // not enough header bytes left
      return;
   }
   switch (sptr->dcd_ipProtocol) {
      case IPPROTO_ICMP: { /* ICMP */
         struct SFmyicmphdr icmp;
         memcpy(&icmp, ptr, sizeof(icmp));
         sptr->dcd_sport = icmp.type;
         sptr->dcd_dport = icmp.code;
         sptr->offsetToPayload = ptr + sizeof(icmp) - sptr->header;
         break;
      }
      case IPPROTO_TCP: { /* TCP */
         struct SFmytcphdr tcp;
         int headerBytes;
         memcpy(&tcp, ptr, sizeof(tcp));
         sptr->dcd_sport = ntohs(tcp.th_sport);
         sptr->dcd_dport = ntohs(tcp.th_dport);
         sptr->dcd_tcpFlags = tcp.th_flags;
         headerBytes = (tcp.th_off_and_unused >> 4) * 4;
         ptr += headerBytes;
         sptr->offsetToPayload = ptr - sptr->header;
         break;
      }
      case IPPROTO_UDP: { /* UDP */
         struct SFmyudphdr udp;
         memcpy(&udp, ptr, sizeof(udp));
         sptr->dcd_sport = ntohs(udp.uh_sport);
         sptr->dcd_dport = ntohs(udp.uh_dport);
         sptr->udp_pduLen = ntohs(udp.uh_ulen);
         sptr->offsetToPayload = ptr + sizeof(udp) - sptr->header;
         break;
      }

      default: /* some other protcol */
         sptr->offsetToPayload = ptr - sptr->header;
         break;
   }
}



#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500
 
#define NFT_MIN_SIZ (NFT_ETHHDR_SIZ + sizeof(struct SFmyiphdr))


static void
SFDecodeLinkLayer(SFSample *sample)
{
   u_char *start = (u_char *)sample->header;
   u_char *end = start + sample->headerLen;
   u_char *ptr = start;
   uint16_t type_len;

   /* assume not found */
   sample->gotIPV4 = ARGUS_FALSE;
   sample->gotIPV6 = ARGUS_FALSE;

   if (sample->headerLen < NFT_ETHHDR_SIZ) return; /* not enough for an Ethernet header */

   memcpy(sample->eth_dst, ptr, 6);
   ptr += 6;

   memcpy(sample->eth_src, ptr, 6);
   ptr += 6;
   type_len = (ptr[0] << 8) + ptr[1];
   ptr += 2;

   if (type_len == 0x8100) {
      /* VLAN   - next two bytes */
      uint32_t vlanData = (ptr[0] << 8) + ptr[1];
      uint32_t vlan = vlanData & 0x0fff;
      ptr += 2;
      /*   _____________________________________ */
      /* |    pri   | c |             vlan-id            | */
      /*   ------------------------------------- */
      /* [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] */
      sample->in_vlan = vlan;
      /* now get the type_len again (next two bytes) */
      type_len = (ptr[0] << 8) + ptr[1];
      ptr += 2;
   }

   /* now we're just looking for IP */
   if (sample->headerLen < NFT_MIN_SIZ) return; /* not enough for an IPv4 header */
   
   /* peek for IPX */
   if(type_len == 0x0200 || type_len == 0x0201 || type_len == 0x0600) {
#define IPX_HDR_LEN 30
#define IPX_MAX_DATA 546
      int ipxChecksum = (ptr[0] == 0xff && ptr[1] == 0xff);
      int ipxLen = (ptr[2] << 8) + ptr[3];
      if (ipxChecksum &&
          ipxLen >= IPX_HDR_LEN &&
          ipxLen <= (IPX_HDR_LEN + IPX_MAX_DATA))
         /* we don't do anything with IPX here */
         return;
   } 
   
   if (type_len <= NFT_MAX_8023_LEN) {
      /* assume 802.3+802.2 header */
      /* check for SNAP */
      if (ptr[0] == 0xAA && ptr[1] == 0xAA && ptr[2] == 0x03) {
         ptr += 3;
         if (ptr[0] != 0 || ptr[1] != 0 || ptr[2] != 0) {
            return; /* no further decode for vendor-specific protocol */
         }
         ptr += 3;
         /* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
         type_len = (ptr[0] << 8) + ptr[1];
         ptr += 2;
      }
      else {
         if (ptr[0] == 0x06 &&
       ptr[1] == 0x06 &&
       (ptr[2] & 0x01)) {
    /* IP over 8022 */
    ptr += 3;
    /* force the type_len to be IP so we can inline the IP decode below */
    type_len = 0x0800;
         }
         else return;
      }
   }
   
   /* assume type_len is an ethernet-type now */
   sample->eth_type = type_len;

   if (type_len == 0x0800) {
      /* IPV4 */
      if((end - ptr) < sizeof(struct SFmyiphdr)) return;
      /* look at first byte of header.... */
      /*   ___________________________ */
      /* |    version    |      hdrlen    | */
      /*   --------------------------- */
      if((*ptr >> 4) != 4) return; /* not version 4 */
      if((*ptr & 15) < 5) return; /* not IP (hdr len must be 5 quads or more) */
      /* survived all the tests - store the offset to the start of the ip header */
      sample->gotIPV4 = ARGUS_TRUE;
      sample->offsetToIPV4 = (ptr - start);
   }

   if (type_len == 0x86DD) {
      /* IPV6 */
      /* look at first byte of header.... */
      if((*ptr >> 4) != 6) return; /* not version 6 */
      /* survived all the tests - store the offset to the start of the ip6 header */
      sample->gotIPV6 = ARGUS_TRUE;
      sample->offsetToIPV6 = (ptr - start);
   }
}


#define WIFI_MIN_HDR_SIZ 24

static void
SFDecode80211MAC(SFSample *sample)
{
   u_char *start = (u_char *)sample->header;
// u_char *end = start + sample->headerLen;
   u_char *ptr = start;

   /* assume not found */
   sample->gotIPV4 = ARGUS_FALSE;
   sample->gotIPV6 = ARGUS_FALSE;

   if(sample->headerLen < WIFI_MIN_HDR_SIZ) return; /* not enough for an 80211 MAC header */

   uint32_t fc = (ptr[1] << 8) + ptr[0];   // [b7..b0][b15..b8]
// uint32_t protocolVersion = fc & 3;
   uint32_t control = (fc >> 2) & 3;
// uint32_t subType = (fc >> 4) & 15;
   uint32_t toDS = (fc >> 8) & 1;
   uint32_t fromDS = (fc >> 9) & 1;
// uint32_t moreFrag = (fc >> 10) & 1;
// uint32_t retry = (fc >> 11) & 1;
// uint32_t pwrMgt = (fc >> 12) & 1;
// uint32_t moreData = (fc >> 13) & 1;
// uint32_t encrypted = (fc >> 14) & 1;
// uint32_t order = fc >> 15;

   ptr += 2;

// uint32_t duration_id = (ptr[1] << 8) + ptr[0]; // not in network byte order either?
   ptr += 2;

   switch (control) {
      case 0: // mgmt
      case 1: // ctrl
      case 3: // rsvd
         break;

      case 2: {    // data
         u_char *macAddr1 = ptr;
         ptr += 6;
         u_char *macAddr2 = ptr;
         ptr += 6;
         u_char *macAddr3 = ptr;
         ptr += 6;
//       uint32_t sequence = (ptr[0] << 8) + ptr[1];
         ptr += 2;

         // ToDS    FromDS    Addr1    Addr2   Addr3    Addr4
         // 0         0            DA         SA       BSSID    N/A (ad-hoc)
         // 0         1            DA         BSSID   SA         N/A
         // 1         0            BSSID    SA       DA         N/A
         // 1         1            RA         TA       DA         SA   (wireless bridge)

         u_char *srcMAC = NULL;
         u_char *dstMAC = NULL;

         if(toDS) {
            dstMAC = macAddr3;
            if(fromDS) {
               srcMAC = ptr; // macAddr4.   1,1 => (wireless bridge)
               ptr += 6;
            } else
               srcMAC = macAddr2;   // 1,0
         } else {
            dstMAC = macAddr1;
            if (fromDS)
               srcMAC = macAddr3; // 0,1
            else
               srcMAC = macAddr2; // 0,0
         }

         if(srcMAC)
            memcpy(sample->eth_src, srcMAC, 6);
         if(dstMAC) 
            memcpy(sample->eth_dst, srcMAC, 6);
         break;
      }
   }
}


void
ArgusParseSFlowRecord (struct ArgusModelerStruct *model, void *ptr)
{

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusParseSFlowRecord(%p, %p)", model, ptr);
#endif 
}



#endif
