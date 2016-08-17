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
 * Copyright (c) 1993, 1994 Carnegie Mellon University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and
 * that both that copyright notice and this permission notice appear
 * in supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

/* 
 * $Id: //depot/argus/argus/include/argus/cons_def.h#6 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */



/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|  Protocol   | L |  IP Opt   |  Exp  |         State         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1|  Operation  |                   Data                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                       Argus Status Field Format
          Note that one tick mark represents one bit position.

*/
/* Argus Operation */

#define ARGUSCONTROL		0x80000000

#define INIT			0x01000000
#define STATUS			0x02000000
#define CLOSE			0x04000000


/* Protocol Specification */

#define PROTOCONTROL	        0x00000000

#define IPPROTO			0x01000000
#define UDPPROTO		0x02000000
#define ICMPPROTO		0x04000000
#define TCPPROTO		0x08000000
#define EPPROTO			0x10000000
#define ARPPROTO		0x20000000

#define PROTOMASK               0x7F000000

/* Link Dependant Bits (L) */

#define FRAGMENTS		0x400000
#define MULTIADDR		0x800000


/* IP Option Status Bits */
  
#define TIMESTAMP		0x010000
#define SECURITY		0x020000
#define LSRCROUTE		0x040000
#define RECORDROUTE		0x080000
#define SSRCROUTE		0x100000
#define RTRALERT		0x200000

#define IPOPTIONMASK            0x3F0000


/* Report Status Bits  (Exp) */

#define REVERSE                 0x1000
#define MODIFIED                0x2000
#define LOGGED                  0x4000
#define DETAIL                  0x8000    


/* IP, TCP and UDP State Constants and Reporting Values */

#define IP_INIT                 0x0001
#define UDP_INIT                0x0001
#define SAW_SYN                 0x0001
#define SAW_SYN_SENT		0x0002
#define CON_ESTABLISHED		0x0004
#define CLOSE_WAITING           0x0008
#define PKTS_RETRANS            0x0410  /* SRC_PKTS_RETRANS | DST_PK*/
#define SRC_PKTS_RETRANS        0x0010
#define WINDOW_SHUT             0x0060  /* SRC_WINDOW_SHUT | DST_WIN*/
#define SRC_WINDOW_SHUT         0x0020
#define DST_WINDOW_SHUT         0x0040
#define NORMAL_CLOSE            0x0080
#define RESET                   0x0900  /* SRC_RESET | DST_RESET */
#define SRC_RESET               0x0100
#define TIMED_OUT               0x0200
#define DST_PKTS_RETRANS        0x0400
#define DST_RESET               0x0800

/* Fragment State Constants and Reporting Values */

#define FRAG_INIT               0x0001
#define FRAG_OUT_OF_ORDER       0x0002
#define TCP_FRAG_OFFSET_PROBLEM 0x0008
#define FRAG_ONLY               0x0010


