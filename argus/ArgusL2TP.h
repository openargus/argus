/*
 * Argus-5.0 Software.  Argus files - UDP Protocol processing
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
 * $Id$
 * $DateTime: 2014/05/14 12:53:31 $
 * $Change: 2827 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#ifndef ArgusL2TP_h
#define ArgusL2TP_h

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <argus_compat.h>
#include <ArgusModeler.h>

#include <argus/bootp.h>
struct bootp *bp;

unsigned short ArgusParseL2TP (struct ArgusModelerStruct *, void *);

#define L2TP_FLAG_TYPE          0x8000  /* Type (0=Data, 1=Control) */
#define L2TP_FLAG_LENGTH        0x4000  /* Length */
#define L2TP_FLAG_SEQUENCE      0x0800  /* Sequence */
#define L2TP_FLAG_OFFSET        0x0200  /* Offset */
#define L2TP_FLAG_PRIORITY      0x0100  /* Priority */

#define L2TP_VERSION_MASK       0x000f  /* Version Mask */
#define L2TP_VERSION_L2F        0x0001  /* L2F */
#define L2TP_VERSION_L2TP       0x0002  /* L2TP */

#define L2TP_AVP_HDR_FLAG_MANDATORY     0x8000  /* Mandatory Flag */
#define L2TP_AVP_HDR_FLAG_HIDDEN        0x4000  /* Hidden Flag */
#define L2TP_AVP_HDR_LEN_MASK           0x03ff  /* Length Mask */

#define L2TP_FRAMING_CAP_SYNC_MASK      0x00000001      /* Synchronous */
#define L2TP_FRAMING_CAP_ASYNC_MASK     0x00000002      /* Asynchronous */

#define L2TP_FRAMING_TYPE_SYNC_MASK     0x00000001      /* Synchronous */
#define L2TP_FRAMING_TYPE_ASYNC_MASK    0x00000002      /* Asynchronous */

#define L2TP_BEARER_CAP_DIGITAL_MASK    0x00000001      /* Digital */
#define L2TP_BEARER_CAP_ANALOG_MASK     0x00000002      /* Analog */

#define L2TP_BEARER_TYPE_DIGITAL_MASK   0x00000001      /* Digital */
#define L2TP_BEARER_TYPE_ANALOG_MASK    0x00000002      /* Analog */

/* Authen Type */
#define L2TP_AUTHEN_TYPE_RESERVED       0x0000  /* Reserved */
#define L2TP_AUTHEN_TYPE_TEXTUAL        0x0001  /* Textual username/password exchange */
#define L2TP_AUTHEN_TYPE_CHAP           0x0002  /* PPP CHAP */
#define L2TP_AUTHEN_TYPE_PAP            0x0003  /* PPP PAP */
#define L2TP_AUTHEN_TYPE_NO_AUTH        0x0004  /* No Authentication */
#define L2TP_AUTHEN_TYPE_MSCHAPv1       0x0005  /* MSCHAPv1 */

#define L2TP_PROXY_AUTH_ID_MASK         0x00ff

#define L2TP_MSGTYPE_SCCRQ      	1  /* Start-Control-Connection-Request */
#define L2TP_MSGTYPE_SCCRP      	2  /* Start-Control-Connection-Reply */
#define L2TP_MSGTYPE_SCCCN      	3  /* Start-Control-Connection-Connected */
#define L2TP_MSGTYPE_STOPCCN    	4  /* Stop-Control-Connection-Notification */
#define L2TP_MSGTYPE_HELLO      	6  /* Hello */
#define L2TP_MSGTYPE_OCRQ       	7  /* Outgoing-Call-Request */
#define L2TP_MSGTYPE_OCRP       	8  /* Outgoing-Call-Reply */
#define L2TP_MSGTYPE_OCCN       	9  /* Outgoing-Call-Connected */
#define L2TP_MSGTYPE_ICRQ       	10 /* Incoming-Call-Request */
#define L2TP_MSGTYPE_ICRP       	11 /* Incoming-Call-Reply */
#define L2TP_MSGTYPE_ICCN       	12 /* Incoming-Call-Connected */
#define L2TP_MSGTYPE_CDN        	14 /* Call-Disconnect-Notify */
#define L2TP_MSGTYPE_WEN        	15 /* WAN-Error-Notify */
#define L2TP_MSGTYPE_SLI        	16 /* Set-Link-Info */

#define L2TP_AVP_MSGTYPE		0  /* Message Type */
#define L2TP_AVP_RESULT_CODE		1  /* Result Code */
#define L2TP_AVP_PROTO_VER		2  /* Protocol Version */
#define L2TP_AVP_FRAMING_CAP		3  /* Framing Capabilities */
#define L2TP_AVP_BEARER_CAP		4  /* Bearer Capabilities */
#define L2TP_AVP_TIE_BREAKER		5  /* Tie Breaker */
#define L2TP_AVP_FIRM_VER		6  /* Firmware Revision */
#define L2TP_AVP_HOST_NAME		7  /* Host Name */
#define L2TP_AVP_VENDOR_NAME		8  /* Vendor Name */
#define L2TP_AVP_ASSND_TUN_ID 		9  /* Assigned Tunnel ID */
#define L2TP_AVP_RECV_WIN_SIZE		10 /* Receive Window Size */
#define L2TP_AVP_CHALLENGE		11 /* Challenge */
#define L2TP_AVP_Q931_CC		12 /* Q.931 Cause Code */
#define L2TP_AVP_CHALLENGE_RESP		13 /* Challenge Response */
#define L2TP_AVP_ASSND_SESS_ID  	14 /* Assigned Session ID */
#define L2TP_AVP_CALL_SER_NUM 		15 /* Call Serial Number */
#define L2TP_AVP_MINIMUM_BPS		16 /* Minimum BPS */
#define L2TP_AVP_MAXIMUM_BPS		17 /* Maximum BPS */
#define L2TP_AVP_BEARER_TYPE		18 /* Bearer Type */
#define L2TP_AVP_FRAMING_TYPE 		19 /* Framing Type */
#define L2TP_AVP_PACKET_PROC_DELAY	20 /* Packet Processing Delay (OBSOLETE) */
#define L2TP_AVP_CALLED_NUMBER		21 /* Called Number */
#define L2TP_AVP_CALLING_NUMBER		22 /* Calling Number */
#define L2TP_AVP_SUB_ADDRESS		23 /* Sub-Address */
#define L2TP_AVP_TX_CONN_SPEED		24 /* (Tx) Connect Speed */
#define L2TP_AVP_PHY_CHANNEL_ID		25 /* Physical Channel ID */
#define L2TP_AVP_INI_RECV_LCP		26 /* Initial Received LCP CONFREQ */
#define L2TP_AVP_LAST_SENT_LCP		27 /* Last Sent LCP CONFREQ */
#define L2TP_AVP_LAST_RECV_LCP		28 /* Last Received LCP CONFREQ */
#define L2TP_AVP_PROXY_AUTH_TYPE	29 /* Proxy Authen Type */
#define L2TP_AVP_PROXY_AUTH_NAME	30 /* Proxy Authen Name */
#define L2TP_AVP_PROXY_AUTH_CHAL	31 /* Proxy Authen Challenge */
#define L2TP_AVP_PROXY_AUTH_ID		32 /* Proxy Authen ID */
#define L2TP_AVP_PROXY_AUTH_RESP	33 /* Proxy Authen Response */
#define L2TP_AVP_CALL_ERRORS		34 /* Call Errors */
#define L2TP_AVP_ACCM			35 /* ACCM */
#define L2TP_AVP_RANDOM_VECTOR		36 /* Random Vector */
#define L2TP_AVP_PRIVATE_GRP_ID		37 /* Private Group ID */
#define L2TP_AVP_RX_CONN_SPEED		38 /* (Rx) Connect Speed */
#define L2TP_AVP_SEQ_REQUIRED 		39 /* Sequencing Required */
#define L2TP_AVP_PPP_DISCON_CC		46 /* PPP Disconnect Cause Code */


struct l2tphdr {
   unsigned short opts, len;
   unsigned short tunid, sessid;
   unsigned short ns, nr;
   unsigned short offS, offP;
};
#endif
