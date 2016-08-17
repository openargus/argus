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
 * $Id: //depot/argus/argus/include/argus_llc.h#4 $
 * $DateTime: 2011/01/26 17:11:49 $
 * $Change: 2087 $
 */

#if !defined(Argus_llc_h)
#define Argus_llc_h

/*
 * This stuff should come from a system header file, but there's no
 * obviously portable way to do that and it's not really going
 * to change from system to system.
 */

/*
 * A somewhat abstracted view of the LLC header
 */

struct llc {
	u_char dsap;
	u_char ssap;
	union {
		u_char u_ctl;
		u_short is_ctl;
		struct {
			u_char snap_ui;
			u_char snap_pi[5];
		} snap;
		struct {
			u_char snap_ui;
			u_char snap_orgcode[3];
			u_char snap_ethertype[2];
		} snap_ether;
	} ctl;
};

#define	llcui		ctl.snap.snap_ui
#define	llcpi		ctl.snap.snap_pi
#define	orgcode		ctl.snap_ether.snap_orgcode
#define	ethertype	ctl.snap_ether.snap_ethertype
#define	llcis		ctl.is_ctl
#define	llcu		ctl.u_ctl

#define	LLC_U_FMT	3
#define	LLC_GSAP	1
#define LLC_S_FMT	1

#define	LLC_U_POLL	0x10
#define	LLC_IS_POLL	0x0001
#define	LLC_XID_FI	0x81

#define	LLC_U_CMD(u)	((u) & 0xef)
#define	LLC_UI		0x03
#define	LLC_UA		0x63
#define	LLC_DISC	0x43
#define	LLC_DM		0x0f
#define	LLC_SABME	0x6f
#define	LLC_TEST	0xe3
#define	LLC_XID		0xaf
#define	LLC_FRMR	0x87

#define	LLC_S_CMD(is)	(((is) >> 10) & 0x03)
#define	LLC_RR		0x0100
#define	LLC_RNR		0x0500
#define	LLC_REJ		0x0900

#define LLC_IS_NR(is)	(((is) >> 1) & 0x7f)
#define LLC_I_NS(is)	(((is) >> 9) & 0x7f)

#if !defined(LLCSAP_NULL)
#define	LLCSAP_NULL		0x00
#endif
#if !defined(LLCSAP_8021B_I)
#define	LLCSAP_8021B_I		0x02
#endif
#if !defined(LLCSAP_8021B_G)
#define	LLCSAP_8021B_G		0x03
#endif
#if !defined(LLCSAP_SNAPATH)
#define	LLCSAP_SNAPATH		0x04
#endif
#if !defined(LLCSAP_IP)
#define	LLCSAP_IP		0x06
#endif
#if !defined(LLCSAP_SNA1)
#define	LLCSAP_SNA1		0x08
#endif
#if !defined(LLCSAP_SNA2)
#define	LLCSAP_SNA2		0x0c
#endif
#if !defined(LLCSAP_PROWAYNM)
#define	LLCSAP_PROWAYNM		0x0e
#endif
#if !defined(LLCSAP_TI)
#define	LLCSAP_TI		0x18
#endif
#if !defined(LLCSAP_BPDU)
#define	LLCSAP_BPDU		0x42
#endif
#if !defined(LLCSAP_RS511)
#define	LLCSAP_RS511		0x4e
#endif
#if !defined(LLCSAP_ISO8208)
#define	LLCSAP_ISO8208		0x7e
#endif
#if !defined(LLCSAP_XNS)
#define	LLCSAP_XNS		0x80
#endif
#if !defined(LLCSAP_NESTAR)
#define	LLCSAP_NESTAR		0x86
#endif
#if !defined(LLCSAP_PROWAYASLM)
#define	LLCSAP_PROWAYASLM	0x8e
#endif
#if !defined(LLCSAP_ARP)
#define	LLCSAP_ARP		0x98
#endif
#if !defined(LLCSAP_SNAP)
#define	LLCSAP_SNAP		0xaa
#endif
#if !defined(LLCSAP_VINES1)
#define LLCSAP_VINES1		0xba
#endif
#if !defined(LLCSAP_VINES2)
#define LLCSAP_VINES2		0xbc
#endif
#if !defined(LLCSAP_NETWARE)
#define LLCSAP_NETWARE		0xe0
#endif
#if !defined(LLCSAP_NETBIOS)
#define LLCSAP_NETBIOS		0xf0
#endif
#if !defined(LLCSAP_IBMNM)
#define LLCSAP_IBMNM		0xf4
#endif
#if !defined(LLCSAP_RPL1)
#define LLCSAP_RPL1		0xf8
#endif
#if !defined(LLCSAP_UB)
#define LLCSAP_UB		0xfa
#endif
#if !defined(LLCSAP_RPL2)
#define LLCSAP_RPL2		0xfc
#endif
#if !defined(LLCSAP_ISONS)
#define	LLCSAP_ISONS		0xfe
#endif
#if !defined(LLCSAP_GLOBAL)
#define	LLCSAP_GLOBAL		0xff
#endif
#endif

