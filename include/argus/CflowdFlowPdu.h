/*
 * Argus Software
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
 *  This file is orignally from CAIDA's cflowd source code, but has been
 *  amended and improved over the years.  All attempts have been made to
 *  keep the naming and type styles consistent with the original file.
 */

/*===========================================================================
 /  @(#) $Name:  $
 /  @(#) $Id: //depot/argus/argus-3.0/clients/include/CflowdFlowPdu.h#5 $
 /===========================================================================
 /  CAIDA Copyright Notice
 /
 /  By accessing this software, cflowd++, you are duly informed
 /  of and agree to be bound by the conditions described below in this
 /  notice:
 /
 /  This software product, cflowd++, is developed by Daniel W. McRobb, and
 /  copyrighted(C) 1998 by the University of California, San Diego
 /  (UCSD), with all rights reserved.  UCSD administers the CAIDA grant,
 /  NCR-9711092, under which part of this code was developed.
 /
 /  There is no charge for cflowd++ software. You can redistribute it
 /  and/or modify it under the terms of the GNU General Public License,
 /  v.  2 dated June 1991 which is incorporated by reference herein.
 /  cflowd++ is distributed WITHOUT ANY WARRANTY, IMPLIED OR EXPRESS, OF
 /  MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE or that the use
 /  of it will not infringe on any third party's intellectual property
 /  rights.
 /
 /  You should have received a copy of the GNU GPL along with cflowd++.
 /  Copies can also be obtained from:
 /
 /    http://www.gnu.org/copyleft/gpl.html
 /
 /  or by writing to:
 /
 /    University of California, San Diego
 /
 /    SDSC/CAIDA
 /    9500 Gilman Dr., MS-0505
 /    La Jolla, CA 92093 - 0505  USA
 /
 /  Or contact:
 /
 /    info@caida.org
 /===========================================================================
*/

/* 
 * $Id: //depot/argus/argus-3.0/clients/include/CflowdFlowPdu.h#5 $
 * $DateTime: 2006/02/23 13:25:52 $
 * $Change: 627 $
 */

/*---------------------------------------------------------------------------
    This header file contains the layout of flow-export packets for
    Cisco's flow-export.
  -------------------------------------------------------------------------*/
#ifndef _FLOWPDU_H_
#define _FLOWPDU_H_

#define k_maxFlowPacketSize  2048
#ifndef uint8_t
#define uint8_t unsigned char
#endif

#ifndef uint16_t
#define uint16_t unsigned short
#endif

#ifndef uint32_t
#define uint32_t unsigned int
#endif

#ifndef ipv4addr_t
#define ipv4addr_t unsigned int
#endif

/*---------------------------------------------------------------------------
    flow-export version 1 header
  -------------------------------------------------------------------------*/
typedef struct {
  uint16_t    version;        /*  flow-export version number */
  uint16_t    count;          /*  number of flow entries */
  uint32_t    sysUptime;
  uint32_t    unix_secs;
  uint32_t    unix_nsecs;
} CiscoFlowHeaderV1_t;

#define k_maxFlowsPerV1Packet   24

/*---------------------------------------------------------------------------
    flow-export version 1 flow entry
  -------------------------------------------------------------------------*/
typedef struct {
  ipv4addr_t   srcaddr;     /* source IP address */
  ipv4addr_t   dstaddr;     /* destination IP address */
  ipv4addr_t   nexthop;     /* next hop router's IP address */
  uint16_t     input;       /* input interface index */
  uint16_t     output;      /* output interface index */
  uint32_t     pkts;        /* packets sent in duration */
  uint32_t     bytes;       /* octets sent in duration */
  uint32_t     first;       /* SysUptime at start of flow */
  uint32_t     last;        /* and of last packet of flow */
  uint16_t     srcport;     /* TCP/UDP source port number or equivalent */
  uint16_t     dstport;     /* TCP/UDP destination port number or equivalent */
  uint16_t     pad0;  
  uint8_t      prot;        /* IP protocol, e.g., 6=TCP, 17=UDP, ... */
  uint8_t      tos;         /* IP Type-of-Service */
  uint8_t      flags;       /* TCP flags */
  uint8_t      pad1, pad2, pad3; /* pads */
  uint32_t     pad4;
} CiscoFlowEntryV1_t;

/*---------------------------------------------------------------------------
    flow-export version 5 header
  -------------------------------------------------------------------------*/
typedef struct {
  uint16_t    version;        /*  flow-export version number */
  uint16_t    count;          /*  number of flow entries */
  uint32_t    sysUptime;
  uint32_t    unix_secs;
  uint32_t    unix_nsecs;
  uint32_t    flow_sequence;  /*  sequence number */
  uint8_t     engine_type;    /*  no VIP = 0, VIP2 = 1 */
  uint8_t     engine_id;      /*  VIP2 slot number */
  uint16_t    reserved;       /*  unused */
} CiscoFlowHeaderV5_t;

#define k_maxFlowsPerV5Packet   30

/*---------------------------------------------------------------------------
    flow-export version 5 flow entry
  -------------------------------------------------------------------------*/
typedef struct {
  ipv4addr_t   srcaddr;     /* source IP address */
  ipv4addr_t   dstaddr;     /* destination IP address */
  ipv4addr_t   nexthop;     /* next hop router's IP address */
  uint16_t     input;       /* input interface index */
  uint16_t     output;      /* output interface index */
  uint32_t     pkts;        /* packets sent in duration */
  uint32_t     bytes;       /* octets sent in duration */
  uint32_t     first;       /* SysUptime at start of flow */
  uint32_t     last;        /* and of last packet of flow */
  uint16_t     srcport;     /* TCP/UDP source port number or equivalent */
  uint16_t     dstport;     /* TCP/UDP destination port number or equivalent */
  uint8_t      pad;  
  uint8_t      tcp_flags;   /* bitwise OR of all TCP flags in flow; 0x10 */
                            /*  for non-TCP flows */
  uint8_t      prot;        /* IP protocol, e.g., 6=TCP, 17=UDP, ... */
  uint8_t      tos;         /* IP Type-of-Service */
  uint16_t     src_as;      /* originating AS of source address */
  uint16_t     dst_as;      /* originating AS of destination address */
  uint8_t      src_mask;    /* source address prefix mask bits */
  uint8_t      dst_mask;    /* destination address prefix mask bits */
  uint16_t     reserved;  
} CiscoFlowEntryV5_t;

/*---------------------------------------------------------------------------
    flow-export version 6 header
  -------------------------------------------------------------------------*/
typedef struct {
  uint16_t  version;         /* version */
  uint16_t  count;           /* the number of records in PDU */
  uint32_t  sysUptime;       /* current time in msecs since router booted */
  uint32_t  unix_secs;       /* current seconds since 0000 UTC 1970 */
  uint32_t  unix_nsecs;      /* residual nanoseconds since 0000 UTC 1970 */
  uint32_t  flow_sequence;   /* seq counter of total flows seen */
  uint8_t   engine_type;     /* type of flow switching engine */
  uint8_t   engine_id;       /* ID number of the flow switching engine */
  uint16_t  reserved;
} CiscoFlowHeaderV6_t;

#define k_maxFlowsPerV6Packet   27

/*---------------------------------------------------------------------------
    flow-export version 6 flow entry
  -------------------------------------------------------------------------*/
typedef struct {
  ipv4addr_t  srcaddr;       /* source IP address */
  ipv4addr_t  dstaddr;       /* destination IP address */
  ipv4addr_t  nexthop;       /* next hop router's IP address */
  uint16_t    input;         /* input interface index */
  uint16_t    output;        /* output interface index */
  
  uint32_t    pkts;          /* packets sent in duration */
  uint32_t    bytes;         /* octets sent in duration */
  uint32_t    first;         /* SysUptime at start of flow */
  uint32_t    last;          /* and of last packet of flow */
  
  uint16_t    srcport;       /* TCP/UDP source port number or equivalent */
  uint16_t    dstport;       /* TCP/UDP destination port number or equivalent */
  uint8_t     rsvd;
  uint8_t     tcp_flags;     /* bitwise OR of all TCP flags seen in flow */
  uint8_t     prot;          /* IP protocol, e.g., 6=TCP, 17=UDP, ... */
  uint8_t     tos;           /* IP Type-of-Service */
  uint16_t    src_as;        /* originating AS of source address */
  uint16_t    dst_as;        /* originating AS of destination address */
  uint8_t     src_mask;      /* source address prefix mask bits */
  uint8_t     dst_mask;      /* destination address prefix mask bits */
  uint8_t     in_encaps;     /* size in bytes of the input encapsulation */
  uint8_t     out_encaps;    /* size in bytes of the output encapsulation */
  uint32_t    peer_nexthop;  /* IP address of the nexthop w/in the peer (FIB) */
} CiscoFlowEntryV6_t;

/*---------------------------------------------------------------------------
    flow-export version 7 header (Catalyst 5000)
  
    NOT USED, V7 FLOW-EXPORT HANDLING NOT IMPLEMENTED.
  -------------------------------------------------------------------------*/
typedef struct {
  uint16_t    version;        /*  flow-export version number */
  uint16_t    count;          /*  number of flow entries */
  uint32_t    sysUptime;
  uint32_t    unix_secs;
  uint32_t    unix_nsecs;
  uint32_t    flow_sequence;  /*  sequence number */
  uint32_t    reserved;       /*  unused  */
} CiscoFlowHeaderV7_t;
 
/*---------------------------------------------------------------------------
    flow-export version 7 flow entry (Catalyst 5000)
  
    NOT USED, V7 FLOW-EXPORT HANDLING NOT IMPLEMENTED.
  -------------------------------------------------------------------------*/
typedef struct {
  ipv4addr_t   srcaddr;     /* source IP address (0 for dest-only flows)  */
  ipv4addr_t   dstaddr;     /* destination IP address  */
  ipv4addr_t   nexthop;     /* next hop router's IP address (always 0)  */
  uint16_t     input;       /* input interface index (always 0)  */
  uint16_t     output;      /* output interface index  */
  uint32_t     pkts;        /* packets sent in duration  */
  uint32_t     bytes;       /* octets sent in duration  */
  uint32_t     first;       /* SysUptime at start of flow  */
  uint32_t     last;        /* and of last packet of flow  */
  uint16_t     srcport;     /* TCP/UDP source port number or equivalent,  */
                            /* 0 if flow mask is destination-only or  */
                            /* source-destination.  */
  uint16_t     dstport;     /* TCP/UDP destination port number or equivalent,  */
                            /* 0 if flow mask is destination-only or  */
                            /* source-destination.  */
  uint8_t      flags1;      /* ????  */
  uint8_t      tcp_flags;   /* bitwise OR of all TCP flags in flow (always 0)  */
  uint8_t      prot;        /* IP protocol, e.g., 6=TCP, 17=UDP, ...  */
  uint8_t      tos;         /* IP Type-of-Service  */
  uint16_t     src_as;      /* originating AS of source address (always 0)  */
  uint16_t     dst_as;      /* originating AS of destination address (always 0)  */
  uint8_t      src_mask;    /* source address prefix mask bits (always 0)  */
  uint8_t      dst_mask;    /* destination address prefix mask bits (always 0)  */
  uint16_t     flags2;      /* ????  */
  uint32_t     router_sc;   /* IP address of shortcut router  */
} CiscoFlowEntryV7_t;


/*---------------------------------------------------------------------------
    flow-export version 8
  ---------------------------------------------------------------------------
    This is the first flow-export version to support multiple types
    of flow-export records.  Each type is an aggregation, so that only
    specific types of data may be exported (saving processing and
    bandwidth).  Obviously flow level granularity is gone, but this type
    of data reduction is useful on high-speed routers like the GSR.
  -------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
    flow-export version 8 header
  -------------------------------------------------------------------------*/
typedef struct {
  uint16_t    version;        /* flow-export version number */
  uint16_t    count;          /* number of flow entries */
  uint32_t    sysUptime;      /* current time in msecs since router booted */
  uint32_t    unix_secs;      /* current seconds since 0000 UTC 1970 */
  uint32_t    unix_nsecs;     /* residual nanoseconds since 0000 UTC 1970 */
  uint32_t    flow_sequence;  /* sequence number */
  uint8_t     engine_type;    /* type of flow switching engine */
  uint8_t     engine_id;      /* ID number of the flow switching engine */
  uint8_t     agg_method;     /* aggregation method */
  uint8_t     agg_version;    /* aggregation version */
  uint32_t    reserved;       /* unused */
} CiscoFlowHeaderV8_t;

/*---------------------------------------------------------------------------
    V8 aggregation methods
  -------------------------------------------------------------------------*/
#define k_CiscoV8FlowExportASAggType            0x01  /* AS agg. */
#define k_CiscoV8FlowExportProtocolPortAggType  0x02  /* protocol/port agg. */
#define k_CiscoV8FlowExportSrcNetAggType        0x03  /* src network agg. */
#define k_CiscoV8FlowExportDstNetAggType        0x04  /* dst network agg. */
#define k_CiscoV8FlowExportNetMatrixAggType     0x05  /* net matrix agg. */

#define k_CiscoV8FlowExportMaxAggType   k_CiscoV8FlowExportNetMatrixAggType
#define k_CiscoV8FlowExportNumAggTypes  k_CiscoV8FlowExportMaxAggType

/*---------------------------------------------------------------------------
    max flows per packet for each of the different V8 aggregation methods
  -------------------------------------------------------------------------*/
#define k_maxFlowsPerV8AsAggPacket              51
#define k_maxFlowsPerV8ProtocolPortAggPacket    51
#define k_maxFlowsPerV8SrcNetAggPacket          44
#define k_maxFlowsPerV8DstNetAggPacket          44
#define k_maxFlowsPerV8NetMatrixAggPacket       35

/*---------------------------------------------------------------------------
    define max flows per packet, regardless of type of flows.
  -------------------------------------------------------------------------*/
#define k_maxFlowsPerAnyPacket                  51

/*---------------------------------------------------------------------------
    V8 AS aggregation flow entry version 2
  -------------------------------------------------------------------------*/
typedef struct {
  uint32_t  flows;    /* number of flows */
  uint32_t  pkts;     /* number of packets */
  uint32_t  bytes;    /* number of bytes */
  uint32_t  first;    /* sysUptime at start of flow */
  uint32_t  last;     /* sysUptime at end of flow */
  uint16_t  src_as;   /* source AS */
  uint16_t  dst_as;   /* destination AS */
  uint16_t  input;    /* input interface index */
  uint16_t  output;   /* output interface index */
} CiscoFlowEntryV8AsAggV2_t;


/*---------------------------------------------------------------------------
    V8 protocol/port aggregation flow entry version 2
  -------------------------------------------------------------------------*/
typedef struct {
  uint32_t  flows;     /* number of flows */
  uint32_t  pkts;      /* number of packets */
  uint32_t  bytes;     /* number of bytes */
  uint32_t  first;     /* sysUptime at start of flow */
  uint32_t  last;      /* sysUptime at end of flow */
  uint8_t   prot;      /* IP protocol (TCP=6, UDP=17, etc.) */
  uint8_t   pad;
  uint16_t  reserved;
  uint16_t  srcport;   /* source port */
  uint16_t  dstport;   /* destination port */
} CiscoFlowEntryV8ProtocolPortAggV2_t;

/*---------------------------------------------------------------------------
    V8 net matrix aggregation flow entry version 2
  -------------------------------------------------------------------------*/
typedef struct {
  uint32_t    flows;      /* number of flows */
  uint32_t    pkts;       /* number of packets */
  uint32_t    bytes;      /* number of bytes */
  uint32_t    first;      /* sysUptime at start of flow */
  uint32_t    last;       /* sysUptime at end of flow */
  ipv4addr_t  srcnet;     /* source network */
  ipv4addr_t  dstnet;     /* destination network */
  uint8_t     dst_mask;   /* destination netmask length (bits) */
  uint8_t     src_mask;   /* source netmask length (bits) */
  uint16_t    reserved;
  uint16_t    src_as;     /* source AS */
  uint16_t    dst_as;     /* destination AS */
  uint16_t    input;      /* input interface index */
  uint16_t    output;     /* output interface index */
} CiscoFlowEntryV8NetMatrixAggV2_t;

/*---------------------------------------------------------------------------
    V8 source network aggregation flow entry version 2
  -------------------------------------------------------------------------*/
typedef struct {
  uint32_t    flows;       /* number of flows */
  uint32_t    pkts;        /* number of packets */
  uint32_t    bytes;       /* number of bytes */
  uint32_t    first;       /* sysUptime at start of flow */
  uint32_t    last;        /* sysUptime at end of flow */
  ipv4addr_t  srcnet;      /* source network */
  uint8_t     src_mask;    /* source network mask length (bits) */
  uint8_t     pad;
  uint16_t    src_as;      /* source AS */
  uint16_t    input;       /* input interface index */
  uint16_t    reserved;
} CiscoFlowEntryV8SrcNetAggV2_t;

/*---------------------------------------------------------------------------
    V8 destination network aggregation flow entry version 2
  -------------------------------------------------------------------------*/
typedef struct {
  uint32_t    flows;      /* number of flows */
  uint32_t    pkts;       /* number of packets */
  uint32_t    bytes;      /* number of bytes */
  uint32_t    first;      /* sysUptime at start of flow */
  uint32_t    last;       /* sysUptime at end of flow */
  ipv4addr_t  dst_net;    /* destination network */
  uint8_t     dst_mask;   /* destination network mask length (bits) */
  uint8_t     pad;
  uint16_t    dst_as;     /* destination AS */
  uint16_t    output;     /* output interface index */
  uint16_t    reserved;
} CiscoFlowEntryV8DstNetAggV2_t;


/*---------------------------------------------------------------------------
    flow-export version 9 flow entry (NetflowV9)

  -------------------------------------------------------------------------*/

typedef struct {
   uint16_t    version;           /*  flow-export version number */
   uint16_t    count;             /*  number of flow entries */
   uint32_t    sysUptime;
   uint32_t    unix_secs;
   uint32_t    package_sequence;  /*  sequence number */
   uint32_t    source_id;         /*  unused  */
} CiscoFlowHeaderV9_t;

typedef struct {
   u_int16_t flowset_id, length;
} CiscoFlowEntryV9_t;

typedef struct {
   u_int16_t template_id, count;
} CiscoFlowTemplateHeaderV9_t;

typedef struct {
   u_int16_t type, length;
} CiscoFlowTemplateFlowEntryV9_t;

#define k_CiscoV9TemplateFlowsetId		0
#define k_CiscoV9OptionsFlowsetId		1
#define k_CiscoV9MinRecordFlowsetId		256

/* Flowset record types the we care about */
#define k_CiscoV9InBytes		1
#define k_CiscoV9InPackets		2
#define k_CiscoV9Flows			3
#define k_CiscoV9InProtocol		4
#define k_CiscoV9SrcTos			5
#define k_CiscoV9TcpFlags		6
#define k_CiscoV9L4SrcPort		7
#define k_CiscoV9IpV4SrcAddr		8
#define k_CiscoV9SrcMask		9
#define k_CiscoV9InputSnmp		10
#define k_CiscoV9L4DstPort		11
#define k_CiscoV9IpV4DstAddr		12
#define k_CiscoV9DstMask		13
#define k_CiscoV9OutputSnmp		14
#define k_CiscoV9IpV4NextHop		15
#define k_CiscoV9SrcAS			16
#define k_CiscoV9DstAS			17
#define k_CiscoV9BgpIpV4NextHop		18
#define k_CiscoV9MulDstPkts		19
#define k_CiscoV9MulDstBytes		20
#define k_CiscoV9LastSwitched		21
#define k_CiscoV9FirstSwitched		22
#define k_CiscoV9OutBytes		23
#define k_CiscoV9OutPkts		24
#define k_CiscoV9MinPktLen		25
#define k_CiscoV9MaxPktLen		26
#define k_CiscoV9IpV6SrcAddr		27
#define k_CiscoV9IpV6DstAddr		28
#define k_CiscoV9IPV6SrcMask		29
#define k_CiscoV9IpV6DstMask		30
#define k_CiscoV9IpV6FlowLabel		31
#define k_CiscoV9IpV6IcmpType		32
#define k_CiscoV9IpV6MulIgmpType	33
#define k_CiscoV9IpV6SamplingInterval	34
#define k_CiscoV9IpV6SamplingAlgorithm	35
#define k_CiscoV9FlowActiveTimeout	36
#define k_CiscoV9FlowInactiveTimeout	37
#define k_CiscoV9EngineType		38
#define k_CiscoV9EngineID		39
#define k_CiscoV9TotalBytesExp		40
#define k_CiscoV9TotalPktsExp		41
#define k_CiscoV9TotalFlowsExp		42

/* ... */

#define k_CiscoV9MplsTopLabelType	46
#define k_CiscoV9MplsTopLabelIPAddr	47
#define k_CiscoV9FlowSamplerID		48
#define k_CiscoV9FlowSamplerMode	49
#define k_CiscoV9FlowSamplerRandomInt	50

/* ... */

#define k_CiscoV9MinTtl			52
#define k_CiscoV9MaxTtl			53
#define k_CiscoV9IPv4IpId		54
#define k_CiscoV9DstTos			55
#define k_CiscoV9SrcMac			56
#define k_CiscoV9DstMac			57
#define k_CiscoV9SrcVlan		58
#define k_CiscoV9DstVlan		59
#define k_CiscoV9IpProtocolVersion	60
#define k_CiscoV9Direction		61
#define k_CiscoV9IpV6NextHop		62
#define k_CiscoV9BgpIpV6NextHop		63
#define k_CiscoV9IpV6OptionHeaders	64

/* ... */

#define k_CiscoV9MplsLabel1		70
#define k_CiscoV9MplsLabel2		71
#define k_CiscoV9MplsLabel3		72
#define k_CiscoV9MplsLabel4		73
#define k_CiscoV9MplsLabel5		74
#define k_CiscoV9MplsLabel6		75
#define k_CiscoV9MplsLabel7		76
#define k_CiscoV9MplsLabel8		77
#define k_CiscoV9MplsLabel9		78
#define k_CiscoV9MplsLabel10		79
#define k_CiscoV9InDstMac		80
#define k_CiscoV9OutSrcMac		81
#define k_CiscoV9IfName			82
#define k_CiscoV9IfDesc			83
#define k_CiscoV9SampleName		84
#define k_CiscoV9InPermanentBytes	85
#define k_CiscoV9InPermanentPkts	86

/* ... */

#define k_CiscoV9FragmentOffset		88
#define k_CiscoV9ForwardingStatus	89

#define k_CiscoV9MplsPalRD		90
#define k_CiscoV9MplsPrefixLen		91
#define k_CiscoV9SrcTrafficIndex	92
#define k_CiscoV9DstTrafficIndex	93
#define k_CiscoV9ApplicationDesc	94
#define k_CiscoV9ApplicationTag		95
#define k_CiscoV9ApplicationName	96

/* ... */

#define k_CiscoV9PostDSCP		98
#define k_CiscoV9MulticastReplication	99

/* ... */

#define k_CiscoV9ConnId			148

/* ... */

#define k_CiscoV9IcmpType		176
#define k_CiscoV9IcmpCode		177
#define k_CiscoV9IcmpTypeV6		178
#define k_CiscoV9IcmpCodeV6		179

/* ... */

#define k_CiscoV9NatInsideGlobalAddr	225
#define k_CiscoV9NatOutsideGlobalAddr	226
#define k_CiscoV9postNatL4SrcPort	227
#define k_CiscoV9postNatL4DstPort	228
#define k_CiscoV9postNatEvent		230

/* ... */

#define k_CiscoV9IngressVRFID		234

/* ... */

#define k_CiscoEventTimeMilliSec	323
#define k_CiscoEventTimeMicroSec	324
#define k_CiscoEventTimeNanoSec		325


#endif  /* _FlowPDU_H_ */
