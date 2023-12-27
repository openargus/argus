/*
 * Gargoyle Software.  Common include files. L2 encapsulations
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 *
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/gargoyle/argus/include/argus_encapsulations.h#7 $
 * $DateTime: 2015/04/13 16:46:24 $
 * $Change: 2991 $
 */


/* list of supported encapsulations for filter */


#ifndef  Argus_Encapsulations_h
#define Argus_Encapsulations_h

#ifdef __cplusplus
extern "C" {
#endif

struct ArgusEncapsulationStruct {
   unsigned int code;
   char *label, *desc;
};

#define ARGUS_ENCAPS_TYPE       28
#define ARGUS_ENCAPS_MPLS       0x01
#define ARGUS_ENCAPS_ETHER      0x02
#define ARGUS_ENCAPS_8021Q      0x04
#define ARGUS_ENCAPS_LLC        0x08
#define ARGUS_ENCAPS_PPP        0x10
#define ARGUS_ENCAPS_ISL        0x20
#define ARGUS_ENCAPS_GRE        0x40
#define ARGUS_ENCAPS_AH         0x80
#define ARGUS_ENCAPS_IP         0x100
#define ARGUS_ENCAPS_IPV6       0x200
#define ARGUS_ENCAPS_HDLC       0x400
#define ARGUS_ENCAPS_CHDLC      0x800
#define ARGUS_ENCAPS_ATM        0x1000
#define ARGUS_ENCAPS_SLL        0x2000
#define ARGUS_ENCAPS_FDDI       0x4000
#define ARGUS_ENCAPS_SLIP       0x8000
#define ARGUS_ENCAPS_ARCNET     0x10000
#define ARGUS_ENCAPS_802_11     0x20000
#define ARGUS_ENCAPS_PRISM      0x40000
#define ARGUS_ENCAPS_AVS        0x80000
#define ARGUS_ENCAPS_IB_LRH     0x100000
#define ARGUS_ENCAPS_IB_GRH     0x200000
#define ARGUS_ENCAPS_TEREDO     0x400000
#define ARGUS_ENCAPS_UDT        0x800000
#define ARGUS_ENCAPS_SPI        0x1000000
#define ARGUS_ENCAPS_JUNIPER    0x2000000
#define ARGUS_ENCAPS_VXLAN      0x4000000
#define ARGUS_ENCAPS_L2TP       0x8000000

#if defined(ArgusUtil)
struct ArgusEncapsulationStruct argus_encapsulations [] = {
   { ARGUS_ENCAPS_MPLS,  "mpls", "Multiprotocol Label Switching"},
   { ARGUS_ENCAPS_ETHER, "eth", "Ethernet"},
   { ARGUS_ENCAPS_8021Q, "802q", "802.1PQ"},
   { ARGUS_ENCAPS_LLC,   "llc", "Link Layer Control"},
   { ARGUS_ENCAPS_PPP,   "pppoe", "PPP Over Ethernet"},
   { ARGUS_ENCAPS_ISL,   "isl", "Inter-Switch Link"},
   { ARGUS_ENCAPS_GRE,   "gre", "Generic Routing Encapsulation"},
   { ARGUS_ENCAPS_AH,    "ah", "Authentication Header"},
   { ARGUS_ENCAPS_IP,    "ipnip", "IP Version 4"},
   { ARGUS_ENCAPS_IPV6,  "ipnip6", "IP Version 6"},
   { ARGUS_ENCAPS_HDLC,  "hdlc", "HDLC"},
   { ARGUS_ENCAPS_CHDLC, "chdlc", "Cisco HDLC"},
   { ARGUS_ENCAPS_ATM,   "atm", "Atm"},
   { ARGUS_ENCAPS_SLL,   "sll", "Sll"},
   { ARGUS_ENCAPS_FDDI,  "fddi", "Fddi"},
   { ARGUS_ENCAPS_SLIP,  "slip", "Slip"},
   { ARGUS_ENCAPS_ARCNET,"arc", "Arcnet"},
   { ARGUS_ENCAPS_802_11,"wlan", "Wireless Lan"},
   { ARGUS_ENCAPS_PRISM, "prism", "Prism Wireless Lan"},
   { ARGUS_ENCAPS_AVS,   "avs", "Avs"},
   { ARGUS_ENCAPS_IB_LRH,"lrh", "Infiniband Local Route Header"},
   { ARGUS_ENCAPS_IB_GRH,"grh", "Infiniband Global Route Header"},
   { ARGUS_ENCAPS_TEREDO,"teredo", "Teredo IPV6 Tunneling"},
   { ARGUS_ENCAPS_SPI,   "enc", "IPsec Tunnel"},
   { ARGUS_ENCAPS_JUNIPER, "juniper", "Juniper Ethernet"},
   { ARGUS_ENCAPS_VXLAN, "vxlan", "VxLan Encapsulation"},
   { ARGUS_ENCAPS_L2TP,  "l2tp", "L2TP Encapsulation"},
   { 0, (char *) NULL, (char *) NULL }, 
};

#else

extern struct ArgusEncapsulationStruct argus_encapsulations [];

#endif
#ifdef __cplusplus
}
#endif
#endif
