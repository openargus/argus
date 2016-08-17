/* @(#) $Header: /tcpdump/master/tcpdump/ieee802_11.h,v 1.9.4.2 2005/11/13 12:07:44 guy Exp $ (LBL) */
/*
 * Copyright (c) 2001
 *	Fortress Technologies
 *      Charlie Lenahan ( clenahan@fortresstech.com )
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
 */

#if !defined(ARGUS_802_11)
#define ARGUS_802_11

/* Lengths of 802.11 header components. */
#define	IEEE802_11_FC_LEN		2
#define	IEEE802_11_DUR_LEN		2
#define	IEEE802_11_DA_LEN		6
#define	IEEE802_11_SA_LEN		6
#define	IEEE802_11_BSSID_LEN		6
#define	IEEE802_11_RA_LEN		6
#define	IEEE802_11_TA_LEN		6
#define	IEEE802_11_SEQ_LEN		2
#define	IEEE802_11_IV_LEN		3
#define	IEEE802_11_KID_LEN		1

/* Frame check sequence length. */
#define	IEEE802_11_FCS_LEN		4

/* Lengths of beacon components. */
#define	IEEE802_11_TSTAMP_LEN		8
#define	IEEE802_11_BCNINT_LEN		2
#define	IEEE802_11_CAPINFO_LEN		2
#define	IEEE802_11_LISTENINT_LEN	2

#define	IEEE802_11_AID_LEN		2
#define	IEEE802_11_STATUS_LEN		2
#define	IEEE802_11_REASON_LEN		2

/* Length of previous AP in reassocation frame */
#define	IEEE802_11_AP_LEN		6

#define	T_MGMT 0x0  /* management */
#define	T_CTRL 0x1  /* control */
#define	T_DATA 0x2 /* data */
#define	T_RESV 0x3  /* reserved */

#define	ST_ASSOC_REQUEST   	0x0
#define	ST_ASSOC_RESPONSE 	0x1
#define	ST_REASSOC_REQUEST   	0x2
#define	ST_REASSOC_RESPONSE  	0x3
#define	ST_PROBE_REQUEST   	0x4
#define	ST_PROBE_RESPONSE   	0x5
/* RESERVED 			0x6  */
/* RESERVED 			0x7  */
#define	ST_BEACON   		0x8
#define	ST_ATIM			0x9
#define	ST_DISASSOC		0xA
#define	ST_AUTH			0xB
#define	ST_DEAUTH		0xC
/* RESERVED 			0xD  */
/* RESERVED 			0xE  */
/* RESERVED 			0xF  */


#define	CTRL_PS_POLL	0xA
#define	CTRL_RTS	0xB
#define	CTRL_CTS	0xC
#define	CTRL_ACK	0xD
#define	CTRL_CF_END	0xE
#define	CTRL_END_ACK	0xF

#define	DATA_DATA		0x0
#define	DATA_DATA_CF_ACK	0x1
#define	DATA_DATA_CF_POLL	0x2
#define	DATA_DATA_CF_ACK_POLL	0x3
#define	DATA_NODATA		0x4
#define	DATA_NODATA_CF_ACK	0x5
#define	DATA_NODATA_CF_POLL	0x6
#define	DATA_NODATA_CF_ACK_POLL	0x7

#define DATA_QOS_DATA                   0x8
#define DATA_QOS_DATA_CF_ACK            0x9
#define DATA_QOS_DATA_CF_POLL           0xA
#define DATA_QOS_DATA_CF_ACK_POLL       0xB
#define DATA_QOS_NODATA                 0xC
#define DATA_QOS_CF_POLL_NODATA         0xE
#define DATA_QOS_CF_ACK_POLL_NODATA     0xF

/*
 * The subtype field of a data frame is, in effect, composed of 4 flag
 * bits - CF-Ack, CF-Poll, Null (means the frame doesn't actually have
 * any data), and QoS.
 */
#define DATA_FRAME_IS_CF_ACK(x)         ((x) & 0x01)
#define DATA_FRAME_IS_CF_POLL(x)        ((x) & 0x02)
#define DATA_FRAME_IS_NULL(x)           ((x) & 0x04)
#define DATA_FRAME_IS_QOS(x)            ((x) & 0x08)


/*
 * Bits in the frame control field.
 */
#define	FC_VERSION(fc)		((fc) & 0x3)
#define	FC_TYPE(fc)		(((fc) >> 2) & 0x3)
#define	FC_SUBTYPE(fc)		(((fc) >> 4) & 0xF)
#define	FC_TO_DS(fc)		((fc) & 0x0100)
#define	FC_FROM_DS(fc)		((fc) & 0x0200)
#define	FC_MORE_FLAG(fc)	((fc) & 0x0400)
#define	FC_RETRY(fc)		((fc) & 0x0800)
#define	FC_POWER_MGMT(fc)	((fc) & 0x1000)
#define	FC_MORE_DATA(fc)	((fc) & 0x2000)
#define	FC_WEP(fc)		((fc) & 0x4000)
#define	FC_ORDER(fc)		((fc) & 0x8000)

struct mgmt_header_t {
	u_int16_t	fc;
	u_int16_t 	duration;
	u_int8_t	da[6];
	u_int8_t	sa[6];
	u_int8_t	bssid[6];
	u_int16_t	seq_ctrl;
};

#define	MGMT_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
			 IEEE802_11_DA_LEN+IEEE802_11_SA_LEN+\
			 IEEE802_11_BSSID_LEN+IEEE802_11_SEQ_LEN)

#define	CAPABILITY_ESS(cap)	((cap) & 0x0001)
#define	CAPABILITY_IBSS(cap)	((cap) & 0x0002)
#define	CAPABILITY_CFP(cap)	((cap) & 0x0004)
#define	CAPABILITY_CFP_REQ(cap)	((cap) & 0x0008)
#define	CAPABILITY_PRIVACY(cap)	((cap) & 0x0010)

typedef enum {
	NOT_PRESENT,
	PRESENT,
	TRUNCATED
} elem_status_t;

struct ssid_t {
	u_int8_t	element_id;
	u_int8_t	length;
	u_char		ssid[33];  /* 32 + 1 for null */
};

struct rates_t {
	u_int8_t	element_id;
	u_int8_t	length;
	u_int8_t	rate[16];
};

struct challenge_t {
	u_int8_t	element_id;
	u_int8_t	length;
	u_int8_t	text[254]; /* 1-253 + 1 for null */
};

struct fh_t {
	u_int8_t	element_id;
	u_int8_t	length;
	u_int16_t	dwell_time;
	u_int8_t	hop_set;
	u_int8_t 	hop_pattern;
	u_int8_t	hop_index;
};

struct ds_t {
	u_int8_t	element_id;
	u_int8_t	length;
	u_int8_t	channel;
};

struct cf_t {
	u_int8_t	element_id;
	u_int8_t	length;
	u_int8_t	count;
	u_int8_t	period;
	u_int16_t	max_duration;
	u_int16_t	dur_remaing;
};

struct tim_t {
	u_int8_t	element_id;
	u_int8_t	length;
	u_int8_t	count;
	u_int8_t	period;
	u_int8_t	bitmap_control;
	u_int8_t	bitmap[251];
};

#define	E_SSID 		0
#define	E_RATES 	1
#define	E_FH	 	2
#define	E_DS 		3
#define	E_CF	 	4
#define	E_TIM	 	5
#define	E_IBSS 		6
/* reserved 		7 */
/* reserved 		8 */
/* reserved 		9 */
/* reserved 		10 */
/* reserved 		11 */
/* reserved 		12 */
/* reserved 		13 */
/* reserved 		14 */
/* reserved 		15 */
/* reserved 		16 */

#define	E_CHALLENGE 	16
/* reserved 		17 */
/* reserved 		18 */
/* reserved 		19 */
/* reserved 		16 */
/* reserved 		16 */


struct mgmt_body_t {
	u_int8_t   	timestamp[IEEE802_11_TSTAMP_LEN];
	u_int16_t  	beacon_interval;
	u_int16_t 	listen_interval;
	u_int16_t 	status_code;
	u_int16_t 	aid;
	u_char		ap[IEEE802_11_AP_LEN];
	u_int16_t	reason_code;
	u_int16_t	auth_alg;
	u_int16_t	auth_trans_seq_num;
	elem_status_t	challenge_status;
	struct challenge_t  challenge;
	u_int16_t	capability_info;
	elem_status_t	ssid_status;
	struct ssid_t	ssid;
	elem_status_t	rates_status;
	struct rates_t 	rates;
	elem_status_t	ds_status;
	struct ds_t	ds;
	elem_status_t	cf_status;
	struct cf_t	cf;
	elem_status_t	fh_status;
	struct fh_t	fh;
	elem_status_t	tim_status;
	struct tim_t	tim;
};

struct ctrl_rts_t {
	u_int16_t	fc;
	u_int16_t	duration;
	u_int8_t	ra[6];
	u_int8_t	ta[6];
	u_int8_t	fcs[4];
};

#define	CTRL_RTS_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
			 IEEE802_11_RA_LEN+IEEE802_11_TA_LEN)

struct ctrl_cts_t {
	u_int16_t	fc;
	u_int16_t	duration;
	u_int8_t	ra[6];
	u_int8_t	fcs[4];
};

#define	CTRL_CTS_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+IEEE802_11_RA_LEN)

struct ctrl_ack_t {
	u_int16_t	fc;
	u_int16_t	duration;
	u_int8_t	ra[6];
	u_int8_t	fcs[4];
};

#define	CTRL_ACK_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+IEEE802_11_RA_LEN)

struct ctrl_ps_poll_t {
	u_int16_t	fc;
	u_int16_t	aid;
	u_int8_t	bssid[6];
	u_int8_t	ta[6];
	u_int8_t	fcs[4];
};

#define	CTRL_PS_POLL_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_AID_LEN+\
				 IEEE802_11_BSSID_LEN+IEEE802_11_TA_LEN)

struct ctrl_end_t {
	u_int16_t	fc;
	u_int16_t	duration;
	u_int8_t	ra[6];
	u_int8_t	bssid[6];
	u_int8_t	fcs[4];
};

#define	CTRL_END_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
			 IEEE802_11_RA_LEN+IEEE802_11_BSSID_LEN)

struct ctrl_end_ack_t {
	u_int16_t	fc;
	u_int16_t	duration;
	u_int8_t	ra[6];
	u_int8_t	bssid[6];
	u_int8_t	fcs[4];
};

#define	CTRL_END_ACK_HDRLEN	(IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
				 IEEE802_11_RA_LEN+IEEE802_11_BSSID_LEN)

#define	IV_IV(iv)	((iv) & 0xFFFFFF)
#define	IV_PAD(iv)	(((iv) >> 24) & 0x3F)
#define	IV_KEYID(iv)	(((iv) >> 30) & 0x03)



/* $FreeBSD: src/sys/net80211/ieee80211_radiotap.h,v 1.5 2005/01/22 20:12:05 sam Exp $ */
/* $NetBSD: ieee80211_radiotap.h,v 1.18 2007/03/26 21:22:35 dyoung Exp $ */

/*-
 * Copyright (c) 2003, 2004 David Young.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of David Young may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID YOUNG ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL DAVID
 * YOUNG BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */
#ifndef _NET80211_IEEE80211_RADIOTAP_H_
#define _NET80211_IEEE80211_RADIOTAP_H_

/* A generic radio capture format is desirable. It must be
 * rigidly defined (e.g., units for fields should be given),
 * and easily extensible.
 *
 * The following is an extensible radio capture format. It is
 * based on a bitmap indicating which fields are present.
 *
 * I am trying to describe precisely what the application programmer
 * should expect in the following, and for that reason I tell the
 * units and origin of each measurement (where it applies), or else I
 * use sufficiently weaselly language ("is a monotonically nondecreasing
 * function of...") that I cannot set false expectations for lawyerly
 * readers.
 */
#if defined(__KERNEL__) || defined(_KERNEL)
#ifndef DLT_IEEE802_11_RADIO
#define	DLT_IEEE802_11_RADIO	127	/* 802.11 plus WLAN header */
#endif
#endif /* defined(__KERNEL__) || defined(_KERNEL) */

/* XXX tcpdump/libpcap do not tolerate variable-length headers,
 * yet, so we pad every radiotap header to 64 bytes. Ugh.
 */
#define IEEE80211_RADIOTAP_HDRLEN	64

/*
 * The radio capture header precedes the 802.11 header.
 *
 * Note well: all radiotap fields are little-endian.
 */
struct ieee80211_radiotap_header {
	uint8_t	it_version;	/* Version 0. Only increases
					 * for drastic changes,
					 * introduction of compatible
					 * new fields does not count.
					 */
	uint8_t	it_pad;
	uint16_t       it_len;         /* length of the whole
					 * header in bytes, including
					 * it_version, it_pad,
					 * it_len, and data fields.
					 */
	uint32_t       it_present;     /* A bitmap telling which
					 * fields are present. Set bit 31
					 * (0x80000000) to extend the
					 * bitmap by another 32 bits.
					 * Additional extensions are made
					 * by setting bit 31.
					 */
} __attribute__((__packed__, __aligned__(8)));


struct ieee80211_xchannel {
   u_int32_t   bitmap;
   u_int16_t   mhz;
   u_int8_t    channum;
   u_int8_t    powercap;
};

struct ieee80211_radiotap {
   struct ieee80211_radiotap_header hdr;
   u_int64_t                        tsft;
   u_int16_t                        txchan, rxchan;
   u_int16_t                        fhss;
   u_int8_t                         rate;
   u_int8_t                         dbm_antsignal;
   u_int8_t                         dbm_antnoise;
   u_int8_t                         db_antsignal;
   u_int8_t                         db_antnoise;
   u_int16_t                        lock_quality;
   u_int16_t                        tx_attenuation;
   u_int16_t                        db_tx_attenuation;
   u_int8_t                         dbm_tx_power;
   u_int8_t                         flags;
   u_int8_t                         antenna;
   struct ieee80211_xchannel        xchan;
};

/*
 * Name                                 Data type       Units
 * ----                                 ---------       -----
 *
 * IEEE80211_RADIOTAP_TSFT              uint64_t       microseconds
 *
 *      Value in microseconds of the MAC's 64-bit 802.11 Time
 *      Synchronization Function timer when the first bit of the
 *      MPDU arrived at the MAC. For received frames, only.
 *
 * IEEE80211_RADIOTAP_CHANNEL           2 x uint16_t   MHz, bitmap
 *
 *      Tx/Rx frequency in MHz, followed by flags (see below).
 *
 * IEEE80211_RADIOTAP_FHSS              uint16_t       see below
 *
 *      For frequency-hopping radios, the hop set (first byte)
 *      and pattern (second byte).
 *
 * IEEE80211_RADIOTAP_RATE              uint8_t        500kb/s
 *
 *      Tx/Rx data rate
 *
 * IEEE80211_RADIOTAP_DBM_ANTSIGNAL     int8_t          decibels from
 *                                                      one milliwatt (dBm)
 *
 *      RF signal power at the antenna, decibel difference from
 *      one milliwatt.
 *
 * IEEE80211_RADIOTAP_DBM_ANTNOISE      int8_t          decibels from
 *                                                      one milliwatt (dBm)
 *
 *      RF noise power at the antenna, decibel difference from one
 *      milliwatt.
 *
 * IEEE80211_RADIOTAP_DB_ANTSIGNAL      uint8_t        decibel (dB)
 *
 *      RF signal power at the antenna, decibel difference from an
 *      arbitrary, fixed reference.
 *
 * IEEE80211_RADIOTAP_DB_ANTNOISE       uint8_t        decibel (dB)
 *
 *      RF noise power at the antenna, decibel difference from an
 *      arbitrary, fixed reference point.
 *
 * IEEE80211_RADIOTAP_LOCK_QUALITY      uint16_t       unitless
 *
 *      Quality of Barker code lock. Unitless. Monotonically
 *      nondecreasing with "better" lock strength. Called "Signal
 *      Quality" in datasheets.  (Is there a standard way to measure
 *      this?)
 *
 * IEEE80211_RADIOTAP_TX_ATTENUATION    uint16_t       unitless
 *
 *      Transmit power expressed as unitless distance from max
 *      power set at factory calibration.  0 is max power.
 *      Monotonically nondecreasing with lower power levels.
 *
 * IEEE80211_RADIOTAP_DB_TX_ATTENUATION uint16_t       decibels (dB)
 *
 *      Transmit power expressed as decibel distance from max power
 *      set at factory calibration.  0 is max power.  Monotonically
 *      nondecreasing with lower power levels.
 *
 * IEEE80211_RADIOTAP_DBM_TX_POWER      int8_t          decibels from
 *                                                      one milliwatt (dBm)
 *
 *      Transmit power expressed as dBm (decibels from a 1 milliwatt
 *      reference). This is the absolute power level measured at
 *      the antenna port.
 *
 * IEEE80211_RADIOTAP_FLAGS             uint8_t        bitmap
 *
 *      Properties of transmitted and received frames. See flags
 *      defined below.
 *
 * IEEE80211_RADIOTAP_ANTENNA           uint8_t        antenna index
 *
 *      Unitless indication of the Rx/Tx antenna for this packet.
 *      The first antenna is antenna 0.
 *
 * IEEE80211_RADIOTAP_RX_FLAGS          uint16_t       bitmap
 *
 *     Properties of received frames. See flags defined below.
 *
 * IEEE80211_RADIOTAP_TX_FLAGS          uint16_t       bitmap
 *
 *     Properties of transmitted frames. See flags defined below.
 *
 * IEEE80211_RADIOTAP_RTS_RETRIES       uint8_t        data
 *
 *     Number of rts retries a transmitted frame used.
 *
 * IEEE80211_RADIOTAP_DATA_RETRIES      uint8_t        data
 *
 *     Number of unicast retries a transmitted frame used.
 */
enum ieee80211_radiotap_type {
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	IEEE80211_RADIOTAP_RX_FLAGS = 14,
	IEEE80211_RADIOTAP_TX_FLAGS = 15,
	IEEE80211_RADIOTAP_RTS_RETRIES = 16,
	IEEE80211_RADIOTAP_DATA_RETRIES = 17,
        IEEE80211_RADIOTAP_XCHANNEL = 18,
	IEEE80211_RADIOTAP_EXT = 31
};

#ifndef _KERNEL
/* Channel flags. */
#define	IEEE80211_CHAN_TURBO	0x0010	/* Turbo channel */
#define	IEEE80211_CHAN_CCK	0x0020	/* CCK channel */
#define	IEEE80211_CHAN_OFDM	0x0040	/* OFDM channel */
#define	IEEE80211_CHAN_2GHZ	0x0080	/* 2 GHz spectrum channel. */
#define	IEEE80211_CHAN_5GHZ	0x0100	/* 5 GHz spectrum channel */
#define	IEEE80211_CHAN_PASSIVE	0x0200	/* Only passive scan allowed */
#define	IEEE80211_CHAN_DYN	0x0400	/* Dynamic CCK-OFDM channel */
#define	IEEE80211_CHAN_GFSK	0x0800	/* GFSK channel (FHSS PHY) */
#endif /* !_KERNEL */

/* For IEEE80211_RADIOTAP_FLAGS */
#define	IEEE80211_RADIOTAP_F_CFP	0x01	/* sent/received
						 * during CFP
						 */
#define	IEEE80211_RADIOTAP_F_SHORTPRE	0x02	/* sent/received
						 * with short
						 * preamble
						 */
#define	IEEE80211_RADIOTAP_F_WEP	0x04	/* sent/received
						 * with WEP encryption
						 */
#define	IEEE80211_RADIOTAP_F_FRAG	0x08	/* sent/received
						 * with fragmentation
						 */
#define	IEEE80211_RADIOTAP_F_FCS	0x10	/* frame includes FCS */
#define	IEEE80211_RADIOTAP_F_DATAPAD	0x20	/* frame has padding between
						 * 802.11 header and payload
						 * (to 32-bit boundary)
						 */
#define	IEEE80211_RADIOTAP_F_BADFCS	0x40	/* does not pass FCS check */

/* For IEEE80211_RADIOTAP_RX_FLAGS */
#define IEEE80211_RADIOTAP_F_RX_BADFCS 0x0001  /* Frame failed CRC check.
						*
						* Deprecated: use the flag
						* IEEE80211_RADIOTAP_F_BADFCS in
						* the IEEE80211_RADIOTAP_FLAGS
						* field, instead.
						*/

/* For IEEE80211_RADIOTAP_TX_FLAGS */
#define IEEE80211_RADIOTAP_F_TX_FAIL   0x0001  /* failed due to excessive
						* retries
						*/
#define IEEE80211_RADIOTAP_F_TX_CTS    0x0002  /* used cts 'protection' */
#define IEEE80211_RADIOTAP_F_TX_RTS    0x0004  /* used rts/cts handshake */

#endif /* !_NET80211_IEEE80211_RADIOTAP_H_ */
#endif
