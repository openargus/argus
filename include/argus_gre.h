/*
 * Gargoyle Software.  Common include files. Gre support
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
 * $Id: //depot/gargoyle/argus/include/argus_gre.h#5 $
 * $DateTime: 2015/04/13 00:39:28 $
 * $Change: 2980 $
 */

#if !defined(Argus_gre_h)
#define(Argus_gre_h)

/*
 * A somewhat abstracted view of the GRE header
 */

struct gre {
   unsigned short vers, proto;
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
