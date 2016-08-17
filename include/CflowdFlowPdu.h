/*===========================================================================
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
 * $Id: //depot/argus/argus/include/CflowdFlowPdu.h#4 $
 * $DateTime: 2011/01/26 17:11:49 $
 * $Change: 2087 $
 */

/*---------------------------------------------------------------------------
    This header file contains the layout of flow-export packets for
    Cisco's flow-export.
  -------------------------------------------------------------------------*/
#if !defined(_FLOWPDU_H_)
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

#endif  /* _FLOWPDU_H_ */
