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
 * $Id: //depot/argus/argus/include/netinet/rtp.h#7 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */


#ifndef _netinet_rtp_h
#define _netinet_rtp_h

/* RTP Upper Layer Format Numbers */

#define	IPPROTO_RTP	257
#define	IPPROTO_RTCP	258

#define RTP_VERSION		2

#define RTP_PT_BVC              22      /* Berkeley video codec */
#define RTP_PT_RGB8             23      /* 8-bit dithered RGB */
#define RTP_PT_HDCC             24      /* SGI proprietary */
#define RTP_PT_CELLB            25      /* Sun CellB */
#define RTP_PT_JPEG             26      /* JPEG */
#define RTP_PT_CUSEEME          27      /* Cornell CU-SeeMe */
#define RTP_PT_NV               28      /* Xerox PARC nv */ 
#define RTP_PT_PICW             29      /* BB&N PictureWindow */ 
#define RTP_PT_CPV              30      /* Concept/Bolter/Viewpoint codec */
#define RTP_PT_H261             31      /* ITU H.261 */ 
#define RTP_PT_MPEG             32      /* MPEG-I & MPEG-II */ 
#define RTP_PT_MP2T             33      /* MPEG-II either audio or video */
#define RTP_PT_H263		34
 
/* backward compat hack for decoding RTPv1 ivs streams */
#define RTP_PT_H261_COMPAT 127
 
/* RTP standard content encodings for audio */

#define RTP_PT_PCMU             0
#define RTP_PT_CELP             1
#define RTP_PT_GSM              3
#define RTP_PT_G723		4
#define RTP_PT_DVI              5
#define RTP_PT_LPC              7
#define RTP_PT_PCMA		8
#define RTP_PT_G722		9
#define RTP_PT_G728		15
#define RTP_PT_G729		18

#define RTP_TIME_OFFSET		2208988800UL
 
#define RTP_M			0x0080
#define RTP_P			0x2000
#define RTP_X			0x1000

#define RTCP_PT_SR		200  
#define RTCP_PT_RR		201      
#define RTCP_PT_SDES		202
#define RTCP_PT_BYE		203      
#define RTCP_PT_APP		204      

#define RTCP_SDES_MIN		1
#define RTCP_SDES_MAX		7

#define RTCP_SDES_CNAME		1
#define RTCP_SDES_NAME		2
#define RTCP_SDES_EMAIL		3
#define RTCP_SDES_PHONE		4
#define RTCP_SDES_LOC		5
#define RTCP_SDES_TOOL		6
#define RTCP_SDES_NOTE		7

/* RTP Header as defined in H.225 */

struct rtphdr {
#ifdef _LITTLE_ENDIAN
  unsigned char rh_cc:4,    /* CSRC count */
                 rh_x:1,    /* extension */
                 rh_p:1,    /* padding */
                rh_ver:2;   /* version */
#else
  unsigned char rh_ver:2,    /* version */
                  rh_p:1,    /* padding */
                  rh_x:1,    /* extension */
                 rh_cc:4;   /* CSRC count */
#endif
#ifdef _LITTLE_ENDIAN
  unsigned char   rh_pt:7,   /* payload type */
                rh_mark:1;   /* marker */
#else
  unsigned char rh_mark:1,   /* marker */
                  rh_pt:7;   /* payload type */
#endif
   unsigned short rh_seq;
   unsigned int   rh_time;
   unsigned int   rh_ssrc;
};


struct rtcphdr {
#ifdef _LITTLE_ENDIAN
  unsigned char  rh_rc:5,    /* report count */
                  rh_p:1,    /* padding */
                rh_ver:2;    /* version */
#else
  unsigned char rh_ver:2,    /* version */
                  rh_p:1,    /* padding */
                 rh_rc:5;    /* report count */
#endif
   unsigned char  rh_pt;     /* payload type */
   unsigned short rh_len;
   unsigned int   rh_ssrc;
};


struct rtpexthdr {
   unsigned short profile, length;
};

typedef struct {
   unsigned int high;
   unsigned int low;
} ntp64;
 
/*
 * Sender report.
 */

struct rtcp_sr {
   ntp64 sr_ntp;           /* 64-bit ntp timestamp */
   unsigned int sr_ts;        /* reference media timestamp */
   unsigned int sr_np;        /* no. packets sent */
   unsigned int sr_nb;        /* no. bytes sent */
};
 
/*
 * Receiver report.
 * Time stamps are middle 32-bits of ntp timestamp.
 */
struct rtcp_rr {
   unsigned int rr_srcid;     /* sender being reported */
   unsigned int rr_loss;      /* loss stats (8:fraction, 24:cumulative)*/
   unsigned int rr_ehsr;      /* ext. highest seqno received */
   unsigned int rr_dv;        /* jitter (delay variance) */
   unsigned int rr_lsr;       /* orig. ts from last rr from this src  */
   unsigned int rr_dlsr;      /* time from recpt of last rr to xmit time */
};

#endif /*!_netinet_rtp_h*/
