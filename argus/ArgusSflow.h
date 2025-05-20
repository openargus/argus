/*
 * Argus-5.0 Software.  Argus files - Sflow processing includes
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
 * $Id: //depot/gargoyle/argus/argus/ArgusSflow.h#4 $
 * $DateTime: 2015/04/13 00:39:28 $
 * $Change: 2980 $
 */


#ifndef ArgusSflow_h
#define ArgusSflow_h

#include <ArgusModeler.h>
#include <argus/sflow.h>


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

void ArgusParseSflowRecord (struct ArgusModelerStruct *, void *);
/*
struct ArgusRecord *ArgusParseSFlowRecord (struct ArgusModelerStruct *, struct ArgusInput *, SFSample *, int *);
*/

#else
extern void ArgusParseSflowRecord (struct ArgusModelerStruct *, void *);
#endif
