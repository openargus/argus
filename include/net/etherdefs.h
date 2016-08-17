/*
 * Argus Software.  Argus files - main argus processing
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
 * $Id: //depot/argus/argus/include/net/etherdefs.h#8 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */
#ifndef _NET_ETHERNET_H_
#define _NET_ETHERNET_H_

#define	ETHER_ADDR_LEN		6
#define	ETHER_TYPE_LEN		2
#define	ETHER_CRC_LEN		4
#define	ETHER_HDR_LEN		(ETHER_ADDR_LEN*2+ETHER_TYPE_LEN)
#define	ETHER_MIN_LEN		64
#define	ETHER_MAX_LEN		1518
 
#ifndef	ETHERTYPE_PUP
#define	ETHERTYPE_PUP		0x0200	/* PUP protocol */
#endif
#ifndef	ETHERTYPE_IP
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#endif
#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP	0x8035	/* reverse Addr. resolution protocol */
#endif
#ifndef	ETHERTYPE_VLAN
#define	ETHERTYPE_VLAN		0x8100	/* IEEE 802.1Q VLAN tagging */
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6		0x86dd	/* IPv6 */
#endif
#ifndef	ETHERTYPE_LOOPBACK
#define	ETHERTYPE_LOOPBACK	0x9000	/* used to test interfaces */
#endif

/*
 * The ETHERTYPE_NTRAILER packet types starting at ETHERTYPE_TRAIL have
 * (type-ETHERTYPE_TRAIL)*512 bytes of data followed
 * by an ETHER type (as given above) and then the (variable-length) header.
 */
#ifndef	ETHERTYPE_TRAIL
#define	ETHERTYPE_TRAIL		0x1000		/* Trailer packet */
#endif
#ifndef	ETHERTYPE_NTRAILER
#define	ETHERTYPE_NTRAILER	16
#endif

#endif /* !_NET_ETHERNET_H_ */
