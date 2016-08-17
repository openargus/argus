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
 * $Id: //depot/argus/argus/include/argus_compat.h#9 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

#if !defined(Argus_compat_h)
#define Argus_compat_h


#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(HAVE_SYS_TYPES_H)
#include <sys/types.h>
#endif

#if defined(HAVE_SYS_WAIT_H)
#include <sys/wait.h>
#endif

#define argtimeval timeval

#include <string.h>

#if defined(HAVE_SOLARIS)
#include <strings.h>
#include <sys/byteorder.h>
#endif

#if defined(linux)
#include <endian.h>
#define __FAVOR_BSD
#endif

#if defined(CYGWIN)
#define _LITTLE_ENDIAN
#define USE_IPV6
#else

#if defined(HAVE_SOLARIS)
#include <sys/ethernet.h>
#else
#if defined(__OpenBSD__) && !defined(__APPLE__)
#include <net/ethertypes.h>
#endif
#endif

#include <argus_os.h>

#if defined(__FreeBSD__)
#if defined(BYTE_ORDER)
#define __BYTE_ORDER    BYTE_ORDER
#endif
#if defined(LITTLE_ENDIAN)
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#endif
#if defined(BIG_ENDIAN)
#define __BIG_ENDIAN    BIG_ENDIAN
#endif
#endif

#if !defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define _LITTLE_ENDIAN
#else
#define _BIG_ENDIAN
#endif
#endif
#endif

#if !defined(HAVE_STRTOF) && !defined(CYGWIN)
//float strtof (char *, char **);
#endif

#if defined(__sgi__) || defined(HAVE_SOLARIS) || defined(ultrix) || defined(__osf__) || defined(linux) || defined(bsdi) || defined(AIX) | defined(CYGWIN)

#define timelocal mktime

#if defined(__sgi__)
#include <bstring.h>
#include <ulimit.h>

#if _MIPS_SZLONG == 64
#undef argtimeval
#define argtimeval irix5_timeval
#endif

#undef TCPSTATES
#endif

#if defined(linux)
#include <time.h>
#endif

#if defined(__sgi) || defined(bsdi)
struct ether_addr {
        u_char  ether_addr_octet[6];
};
#endif


#if defined(AIX)
#define _SUN
#include <sys/select.h>
#include <net/nh.h>
#endif
#endif

#define arg_uint8   u_char
#define arg_int8    char
#define arg_uint16  u_short
#define arg_int16   short

#if HOST_BITS_PER_INT == 32
#define arg_uint32  u_int
#define arg_int32   int
#else
#define arg_uint32  u_long
#define arg_int32   long
#endif

#if defined(__FreeBSD__)
#include <sys/socket.h>
#include <netinet/if_ether.h>
#endif

#if !defined(ICMP_ROUTERADVERT)
#define	ICMP_ROUTERADVERT	9	/* router advertisement */
#endif

#if !defined(ICMP_ROUTERSOLICIT)
#define	ICMP_ROUTERSOLICIT	10	/* router solicitation */
#endif

#if !defined(TCPOPT_WSCALE)
#define	TCPOPT_WSCALE		3	/* window scale factor (rfc1072) */
#endif
#if !defined(TCPOPT_SACKOK)
#define	TCPOPT_SACKOK		4	/* selective ack ok (rfc1072) */
#endif
#if !defined(TCPOPT_SACK)
#define	TCPOPT_SACK		5	/* selective ack (rfc1072) */
#endif
#if !defined(TCPOPT_ECHO)
#define	TCPOPT_ECHO		6	/* echo (rfc1072) */
#endif
#if !defined(TCPOPT_ECHOREPLY)
#define	TCPOPT_ECHOREPLY	7	/* echo (rfc1072) */
#endif
#if !defined(TCPOPT_TIMESTAMP)
#define TCPOPT_TIMESTAMP	8	/* timestamps (rfc1323) */
#endif
#if !defined(TCPOPT_CC)
#define TCPOPT_CC		11	/* T/TCP CC options (rfc1644) */
#endif
#if !defined(TCPOPT_CCNEW)
#define TCPOPT_CCNEW		12	/* T/TCP CC options (rfc1644) */
#endif
#if !defined(TCPOPT_CCECHO)
#define TCPOPT_CCECHO		13	/* T/TCP CC options (rfc1644) */
#endif

#if !defined(ETHERTYPE_SPRITE)
#define	ETHERTYPE_SPRITE	0x0500
#endif
#if !defined(ETHERTYPE_NS)
#define ETHERTYPE_NS		0x0600
#endif
#if !defined(ETHERTYPE_IP)
#define ETHERTYPE_IP		0x0800
#endif
#if !defined(ETHERTYPE_X25L3)
#define ETHERTYPE_X25L3		0x0805
#endif
#if !defined(ETHERTYPE_ARP)
#define ETHERTYPE_ARP		0x0806
#endif
#if !defined(ETHERTYPE_VINES)
#define ETHERTYPE_VINES		0x0bad
#endif
#if !defined(ETHERTYPE_TRAIL)
#define ETHERTYPE_TRAIL		0x1000
#endif
#if !defined(ETHERTYPE_TRAIN)
#define ETHERTYPE_TRAIN		0x1984
#endif
#if !defined(ETHERTYPE_3C_NBP_DGRAM)
#define ETHERTYPE_3C_NBP_DGRAM	0x3c07
#endif
#if !defined(ETHERTYPE_DEC)
#define ETHERTYPE_DEC		0x6000
#endif
#if !defined(ETHERTYPE_MOPDL)
#define	ETHERTYPE_MOPDL		0x6001
#endif
#if !defined(ETHERTYPE_MOPRC)
#define	ETHERTYPE_MOPRC		0x6002
#endif
#if !defined(ETHERTYPE_DN)
#define	ETHERTYPE_DN		0x6003
#endif
#if !defined(ETHERTYPE_LAT)
#define ETHERTYPE_LAT		0x6004
#endif
#if !defined(ETHERTYPE_DEC_DIAG)
#define ETHERTYPE_DEC_DIAG	0x6005
#endif
#if !defined(ETHERTYPE_DEC_CUST)
#define ETHERTYPE_DEC_CUST	0x6006
#endif
#if !defined(ETHERTYPE_SCA)
#define ETHERTYPE_SCA		0x6007
#endif
#if !defined(ETHERTYPE_REVARP)
#define ETHERTYPE_REVARP	0x8035
#endif
#if !defined(ETHERTYPE_LANBRIDGE)
#define	ETHERTYPE_LANBRIDGE	0x8038
#endif
#if !defined(ETHERTYPE_DECDNS)
#define	ETHERTYPE_DECDNS	0x803c
#endif
#if !defined(ETHERTYPE_DECDTS)
#define	ETHERTYPE_DECDTS	0x803e
#endif
#if !defined(ETHERTYPE_VEXP)
#define	ETHERTYPE_VEXP		0x805b
#endif
#if !defined(ETHERTYPE_VPROD)
#define	ETHERTYPE_VPROD		0x805c
#endif
#if !defined(ETHERTYPE_ATALK)
#define ETHERTYPE_ATALK		0x809b
#endif
#if !defined(ETHERTYPE_AARP)
#define ETHERTYPE_AARP		0x80f3
#endif
#if !defined(ETHERTYPE_8021Q)
#define	ETHERTYPE_8021Q		0x8100
#endif
#if !defined(ETHERTYPE_IPX)
#define ETHERTYPE_IPX		0x8137
#endif
#if !defined(ETHERTYPE_SNMP)
#define ETHERTYPE_SNMP		0x814c
#endif
#if !defined(ETHERTYPE_IPV6)
#define ETHERTYPE_IPV6		0x86dd
#endif
#if !defined(ETHERTYPE_MPLS)
#define ETHERTYPE_MPLS		0x8847
#endif
#if !defined(ETHERTYPE_MPLS_MULTI)
#define ETHERTYPE_MPLS_MULTI	0x8848
#endif
#if !defined(ETHERTYPE_PPPOED)
#define ETHERTYPE_PPPOED	0x8863
#endif
#if !defined(ETHERTYPE_PPPOES)
#define ETHERTYPE_PPPOES	0x8864
#endif
#if !defined(ETHERTYPE_LOOPBACK)
#define	ETHERTYPE_LOOPBACK	0x9000
#endif

#ifdef __cplusplus
}
#endif
#endif /* Argus_compat_h */
