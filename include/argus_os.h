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
 * $Id: //depot/argus/argus/include/argus_os.h#20 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

#ifndef ArgusOs_h
#define ArgusOs_h

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(Argus_os_h)
#define Argus_os_h

#if defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#endif

#if !defined(bsdi)
#define ETHER_SERVICE
#endif

#if defined(__APPLE_CC__) || defined(__APPLE__)
#define __OpenBSD__	1
#endif

#if defined(__OpenBSD__)
#include <arpa/inet.h>
#include <sched.h>
#endif


#if defined(ETHER_HEADER_HAS_EA)
#define ESRC(ep) ((ep)->ether_shost.ether_addr_octet)
#define EDST(ep) ((ep)->ether_dhost.ether_addr_octet)
#else
#define ESRC(ep) ((ep)->ether_shost)
#define EDST(ep) ((ep)->ether_dhost)
#endif

#if defined(ETHER_ARP_HAS_X)
#define SHA(ap) ((ap)->arp_xsha)
#define THA(ap) ((ap)->arp_xtha)
#define SPA(ap) ((ap)->arp_xspa)
#define TPA(ap) ((ap)->arp_xtpa)
#else
#if defined(ETHER_ARP_HAS_EA)
#define SHA(ap) ((ap)->arp_sha.ether_addr_octet)
#define THA(ap) ((ap)->arp_tha.ether_addr_octet)
#else
#define SHA(ap) ((ap)->arp_sha)
#define THA(ap) ((ap)->arp_tha)
#endif
#define SPA(ap) ((ap)->arp_spa)
#define TPA(ap) ((ap)->arp_tpa)
#endif

#if defined(sun)
#define ETHERPUP_IPTYPE ETHERTYPE_IP
#define ETHERPUP_REVARPTYPE ETHERTYPE_REVARP
#define ETHERPUP_ARPTYPE ETHERTYPE_ARP

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;
#endif

#if defined(__sgi)
#define SHA(ap) ((ap)->arp_sha)
#define SPA(ap) ((ap)->arp_spa)
#define THA(ap) ((ap)->arp_tha)
#define TPA(ap) ((ap)->arp_tpa)

#define EDST(ep) ((ep)->ether_dhost)
#define ESRC(ep) ((ep)->ether_shost)
#endif

#if defined(__FreeBSD__) || defined(CYGWIN)
#include <sys/types.h>
#include <netinet/in.h>
#else
#include <netinet/in.h>
#include <sys/types.h>
#endif


#include <netinet/icmp6.h>

#if !defined(ICMP6_MEMBERSHIP_QUERY)
#define ICMP6_MEMBERSHIP_QUERY          130
#endif
#if !defined(ICMP6_MEMBERSHIP_REPORT)
#define ICMP6_MEMBERSHIP_REPORT         131
#endif
#if !defined(ICMP6_MEMBERSHIP_REDUCTION)
#define ICMP6_MEMBERSHIP_REDUCTION      132
#endif
#if !defined(ICMP6_HADISCOV_REQUEST)
#define ICMP6_HADISCOV_REQUEST          202
#endif
#if !defined(ICMP6_HADISCOV_REPLY)
#define ICMP6_HADISCOV_REPLY            203
#endif



#if !defined(IPPROTO_HOPOPTS)
#define	IPPROTO_HOPOPTS		0
#endif
 
#if !defined(IPPROTO_ROUTING)
#define	IPPROTO_ROUTING		40
#endif
 
#if !defined(IPPROTO_FRAGMENT)
#define	IPPROTO_FRAGMENT	44
#endif

#if !defined(IPPROTO_GRE)
#define IPPROTO_GRE             47
#endif
 
#if !defined(IPPROTO_ESP)
#define	IPPROTO_ESP	50
#endif
 
#if !defined(IPPROTO_AH)
#define	IPPROTO_AH	51
#endif

#if !defined(IPPROTO_ICMPV6)
#define	IPPROTO_ICMPV6	58
#endif
 
#if !defined(IPPROTO_DSTOPTS)
#define	IPPROTO_DSTOPTS	60
#endif

#if !defined(IPPROTO_TTP)
#define IPPROTO_TTP    84
#endif
 
#if !defined(IPPROTO_OSPF)
#define	IPPROTO_OSPF	89
#endif
 
#if !defined(ETHERTYPE_REVARP)
#define ETHERTYPE_REVARP 0x8035
#endif

#if !defined(IPPROTO_ND)
#define IPPROTO_ND      77
#endif

#if !defined(REVARP_REQUEST)
#define REVARP_REQUEST 3
#endif

#if !defined(REVARP_REPLY)
#define REVARP_REPLY 4
#endif
#endif

#if !defined(IPPROTO_IB)
#define	IPPROTO_IB	253
#endif
 
#if !defined(IPPROTO_RTP)
#define	IPPROTO_RTP	257
#endif
 
#if !defined(IPPROTO_RTCP)
#define	IPPROTO_RTCP	258
#endif
 
#if !defined(IPPROTO_UDT)
#define	IPPROTO_UDT	259
#endif
 
 
/* newish RIP commands */
#if !defined(RIPCMD_POLL)
#define RIPCMD_POLL 5
#endif

#if !defined(RIPCMD_POLLENTRY)
#define RIPCMD_POLLENTRY 6
#endif

#if !defined(ICMP_SR_FAILED)
#define ICMP_SR_FAILED		5	/* Source Route failed	*/
#endif

#if !defined(ICMP_PARAMETERPROB)
#define ICMP_PARAMETERPROB	12	/* Parameter Problem	*/
#endif

#ifdef __cplusplus
}
#endif
#endif
