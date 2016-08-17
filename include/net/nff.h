/*
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence 
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)nff.h       7.1 (Berkeley) 5/7/91
 *
 */

/* 
 * $Id: //depot/argus/argus-3.0/clients/include/net/nff.h#11 $
 * $DateTime: 2006/04/08 16:37:11 $
 * $Change: 816 $
 */

#ifndef NFF_MAJOR_VERSION

/* BSD style release date */
#define NFF_RELEASE 200611

typedef	int nff_int32;
typedef	unsigned int nff_u_int32;
typedef	long long nff_int64;
typedef	unsigned long long nff_u_int64;

/*
 * Alignment macros.  NFF_WORDALIGN rounds up to the next 
 * even multiple of NFF_ALIGNMENT. 
 */
#ifndef __NetBSD__
#define NFF_ALIGNMENT sizeof(nff_int64)
#else
#define NFF_ALIGNMENT sizeof(long long)
#endif
#define NFF_WORDALIGN(x) (((x)+(NFF_ALIGNMENT-1))&~(NFF_ALIGNMENT-1))

#define NFF_MAXINSNS 1024
#define NFF_MAXBUFSIZE 0x8000
#define NFF_MINBUFSIZE 32

/*
 *  Structure for BIOCSETF.
 */
struct nff_program {
  unsigned int bf_len;
  struct nff_insn *bf_insns;
};
 
/*
 * Struct returned by BIOCGSTATS.
 */
struct nff_stat {
   unsigned int bs_recv;		/* number of packets received */
   unsigned int bs_drop;		/* number of packets dropped */
};

/*
 * Struct return by BIOCVERSION.  This represents the version number of 
 * the filter language described by the instruction encodings below.
 * nff understands a program iff kernel_major == filter_major &&
 * kernel_minor >= filter_minor, that is, if the value returned by the
 * running kernel has the same major number and a minor number equal
 * equal to or less than the filter being downloaded.  Otherwise, the
 * results are undefined, meaning an error may be returned or packets
 * may be accepted haphazardly.
 * It has nothing to do with the source code version.
 */
struct nff_version {
  unsigned short bv_major;
  unsigned short bv_minor;
};

/* Current version number of filter architecture. */
#define NFF_MAJOR_VERSION 3
#define NFF_MINOR_VERSION 0

/*
 * NFF ioctls
 *
 * The first set is for compatibility with Sun's pcc style
 * header files.  If your using gcc, we assume that you
 * have run fixincludes so the latter set should work.
 */
#if (defined(sun) || defined(ibm032)) && !defined(__GNUC__)
#endif

/*
 * Structure prepended to each packet.
 */
struct nff_hdr {
   struct timeval  bh_tstamp;	/* time stamp */
   nff_u_int32     bh_caplen;	/* length of captured portion */
   nff_u_int32     bh_datalen;	/* original length of packet */
   unsigned short  bh_hdrlen;	/* length of nff header (this struct
				   plus alignment padding) */
};

/*
 * Data-link level type codes.
 */

/*
 * These are the types that are the same on all platforms; on other
 * platforms, a <net/nff.h> should be supplied that defines the additional
 * DLT_* codes appropriately for that platform (the BSDs, for example,
 * should not just pick up this version of "nff.h"; they should also define
 * the additional DLT_* codes used by their kernels, as well as the values
 * defined here - and, if the values they use for particular DLT_ types
 * differ from those here, they should use their values, not the ones
 * here).
 */
#if !defined(DLT_NULL)
#define DLT_NULL	0	/* no link-layer encapsulation */
#endif
#if !defined(DLT_EN10MB)
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#endif
#if !defined(DLT_EN3MB)
#define DLT_EN3MB	2	/* Experimental Ethernet (3Mb) */
#endif
#if !defined(DLT_AX25)
#define DLT_AX25	3	/* Amateur Radio AX.25 */
#endif
#if !defined(DLT_PRONET)
#define DLT_PRONET	4	/* Proteon ProNET Token Ring */
#endif
#if !defined(DLT_CHAOS)
#define DLT_CHAOS	5	/* Chaos */
#endif
#if !defined(DLT_IEE802)
#define DLT_IEEE802	6	/* IEEE 802 Networks */
#endif
#if !defined(DLT_ARCNET)
#define DLT_ARCNET	7	/* ARCNET */
#endif
#if !defined(DLT_SLIP)
#define DLT_SLIP	8	/* Serial Line IP */
#endif
#if !defined(DLT_PPP)
#define DLT_PPP		9	/* Point-to-point Protocol */
#endif
#if !defined(DLT_FDDI)
#define DLT_FDDI	10	/* FDDI */
#endif

/*
 * These are values from the traditional libpcap "nff.h".
 * Ports of this to particular platforms should replace these definitions
 * with the ones appropriate to that platform, if the values are
 * different on that platform.
*/
 
#if !defined(DLT_ATM_RFC1483)
#define DLT_ATM_RFC1483	11	/* LLC/SNAP encapsulated atm */
#endif

#if !defined(DLT_RAW)
#define DLT_RAW		12	/* raw IP */
#endif

/*
 * These are values from BSD/OS's "bpf.h".
 * These are not the same as the values from the traditional libpcap
 * "bpf.h"; however, these values shouldn't be generated by any
 * OS other than BSD/OS, so the correct values to use here are the
 * BSD/OS values.
 *
 * Platforms that have already assigned these values to other
 * DLT_ codes, however, should give these codes the values
 * from that platform, so that programs that use these codes will
 * continue to compile - even though they won't correctly read
 * files of these types.
 */

#if !defined(__NetBSD__)
#if !defined(DLT_SLIP_BSDOS)
#define DLT_SLIP_BSDOS	15	/* BSD/OS Serial Line IP */
#define DLT_PPP_BSDOS	16	/* BSD/OS Point-to-point Protocol */
#endif
#if !defined(DLT_PPP_BSDOS)
#define DLT_PPP_BSDOS	16	/* BSD/OS Point-to-point Protocol */
#endif
#endif

#if !defined(DLT_ATM_CLIP)
#define DLT_ATM_CLIP	19	/* Linux Classical-IP over ATM */
#endif

/*
 * This value is defined by NetBSD; other platforms should refrain from
 * using it for other purposes, so that NetBSD savefiles with a link
 * type of 50 can be read as this type on all platforms.
 */
#if !defined(DLT_PPP_SERIAL)
#define DLT_PPP_SERIAL	50	/* PPP over serial with HDLC encapsulation */
#endif

/*
 * This value was defined by libpcap 0.5; platforms that have defined
 * it with a different value should define it here with that value -
 * a link type of 104 in a save file will be mapped to DLT_C_HDLC,
 * whatever value that happens to be, so programs will correctly
 * handle files with that link type regardless of the value of
 * DLT_C_HDLC.
 *
 * The name DLT_C_HDLC was used by BSD/OS; we use that name for source
 * compatibility with programs written for BSD/OS.
 *
 * libpcap 0.5 defined it as DLT_CHDLC; we define DLT_CHDLC as well,
 * for source compatibility with programs written for libpcap 0.5.
 */

#if !defined(DLT_C_HDLC)
#define DLT_C_HDLC	104	/* Cisco HDLC */
#endif

#if !defined(DLT_CHDLC)
#define DLT_CHDLC	DLT_C_HDLC
#endif

/*
 * Reserved for future use.
 * Do not pick other numerical value for these unless you have also
 * picked up the tcpdump.org top-of-CVS-tree version of "savefile.c",
 * which will arrange that capture files for these DLT_ types have
 * the same "network" value on all platforms, regardless of what
 * value is chosen for their DLT_ type (thus allowing captures made
 * on one platform to be read on other platforms, even if the two
 * platforms don't use the same numerical values for all DLT_ types).
 */
#if !defined(DLT_IEEE802_11)
#define DLT_IEEE802_11	105	/* IEEE 802.11 wireless */
#endif

/*
 * Values between 106 and 107 are used in capture file headers as
 * link-layer types corresponding to DLT_ types that might differ
 * between platforms; don't use those values for new DLT_ new types.
 */

/*
 * OpenBSD DLT_LOOP, for loopback devices; it's like DLT_NULL, except
 * that the AF_ type in the link-layer header is in network byte order.
 *
 * OpenBSD defines it as 12, but that collides with DLT_RAW, so we
 * define it as 108 here.  If OpenBSD picks up this file, it should
 * define DLT_LOOP as 12 in its version, as per the comment above -
 * and should not use 108 for any purpose.
 */
#if !defined(DLT_LOOP)
#define DLT_LOOP	108
#endif

/*
 * Values between 109 and 112 are used in capture file headers as
 * link-layer types corresponding to DLT_ types that might differ
 * between platforms; don't use those values for new DLT_ new types.
 */

/*
 * This is for Linux cooked sockets.
 */
#if !defined(DLT_LINUX_SLL)
#define DLT_LINUX_SLL	113
#endif

/*
 * The instruction encodings.
 */
/* instruction classes */
#define NFF_CLASS(code) ((code) & 0x0007)
#define		NFF_LD		0x0000
#define		NFF_LDX		0x0001
#define		NFF_ST		0x0002
#define		NFF_STX		0x0003
#define		NFF_ALU		0x0004
#define		NFF_JMP		0x0005
#define		NFF_RET		0x0006
#define		NFF_MISC	0x0007

/* ld/ldx fields */
#define NFF_SIZE(code)	((code) & 0x004F)
#define		NFF_W		0x0000
#define		NFF_H		0x0008
#define		NFF_B		0x0010
#define		NFF_L		0x0020
#define		NFF_D		0x0040
#define		NFF_F		0x0080

/* misc */
#define NFF_MISCOP(code) ((code) & 0x100)
#define		NFF_TAX		0x0000
#define		NFF_TXA		0x0100

#define NFF_MODE(code)	((code) & 0x0e00)
#define		NFF_IMM 	0x0000
#define		NFF_ABS		0x0200
#define		NFF_IND		0x0400
#define		NFF_MEM		0x0600
#define		NFF_LEN		0x0800
#define		NFF_MSH		0x0a00
#define		NFF_DSR		0x0c00

/* alu/jmp fields */
#define NFF_OP(code)	((code) & 0xf000)
#define		NFF_ADD		0x0000
#define		NFF_SUB		0x1000
#define		NFF_MUL		0x2000
#define		NFF_DIV		0x3000
#define		NFF_OR		0x4000
#define		NFF_AND		0x5000
#define		NFF_LSH		0x6000
#define		NFF_RSH		0x7000
#define		NFF_NEG		0x8000
#define		NFF_JA		0x0000
#define		NFF_JEQ		0x1000
#define		NFF_JGT		0x2000
#define		NFF_JGE		0x3000
#define		NFF_JSET	0x4000

#define NFF_SRC(code)	((code) & 0x0008)
#define		NFF_K		0x0000
#define		NFF_X		0x0008

/* ret - NFF_K and NFF_X also apply */
#define NFF_RVAL(code)	((code) & 0x0018)
#define		NFF_A		0x0010

/*
 * The instruction data structure.
 */
struct nff_insn {
   int dsr, type;
   unsigned short code;
   unsigned char jt;
   unsigned char jf;
   union {
      int	  i;
      float	  f;
      char        s[8];
      nff_int64   k;
   } data;
};

/*
 * Macros for insn array initializers.
 */
#define NFF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#define NFF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }

#if defined(BSD) && (defined(KERNEL) || defined(_KERNEL))
/*
 * Systems based on non-BSD kernels don't have ifnet's (or they don't mean
 * anything if it is in <net/if.h>) and won't work like this.
 */
# if __STDC__
extern void nff_tap(struct ifnet *, unsigned char *, unsigned int);
extern void nff_mtap(struct ifnet *, struct mbuf *);
extern void nffattach(struct ifnet *, unsigned int, unsigned int);
extern void nffilterattach(int);
# else
extern void nff_tap();
extern void nff_mtap();
extern void nffattach();
extern void nffilterattach();
# endif /* __STDC__ */
#endif /* BSD && (_KERNEL || KERNEL) */
#if __STDC__
extern int nff_validate(struct nff_insn *, int);
extern unsigned int nff_filter(struct nff_insn *, unsigned char *, unsigned int, unsigned int);
#else
extern int nff_validate();
extern unsigned int nff_filter();
#endif

/*
 * Number of scratch memory words (for NFF_LD|NFF_MEM and NFF_ST).
 */
#define NFF_MEMWORDS 16

#endif
