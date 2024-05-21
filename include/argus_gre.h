/*
 * Argus-5.0 Software.  Common include files. Gre defines
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
 * Copyright (c) 1993, 1994, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

/* 
 * $Id: //depot/gargoyle/argus/include/argus_gre.h#3 $
 * $DateTime: 2015/04/13 00:39:28 $
 * $Change: 2980 $
 */

#if !defined(Argus_gre_h)
#define Argus_gre_h

/*
 * A definition of the global GRE context for a given flow ...
 * This should hold the IP addresses of the enclosing IP flow
 * for the GRE tunnel ...
 *
 */

struct argus_gre {
   unsigned short vers, proto;
   struct ArgusSystemFlow *tflow;
};

#define GRE_CP          0x8000          /* checksum present */
#define GRE_RP          0x4000          /* routing present */
#define GRE_KP          0x2000          /* key present */
#define GRE_SP          0x1000          /* sequence# present */
#define GRE_RECRS       0x0700          /* recursion count */
#define GRE_AP          0x0080          /* acknowledgment# present */

#define GRE_VERS_MASK   0x0007          /* protocol version */
#define GRE_VERS	0x0007		/* protocol version */

#define GREPROTO_IP     0x0800          /* IP */
#define GREPROTO_PPP    0x880b          /* PPTP */
#define GREPROTO_ISO    0x00fe          /* OSI */

/* source route entry types */          
#define GRESRE_IP       0x0800          /* IP */
#define GRESRE_ASN      0xfffe          /* ASN */

#endif
