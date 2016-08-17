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
 * Copyright (c) 1990, 1991, 1992, 1993, 1994
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
 * $Id: //depot/argus/argus/include/argus/gencode.h#8 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

/*
 * filter.h must be included before this file.
 */

#include <argus_os.h>

/* Address qualifers. */

#define Q_HOST		1
#define Q_SRCID		2
#define Q_NET		3
#define Q_PORT		4
#define Q_GATEWAY	5
#define Q_PROTO		6
#define Q_IPID		7
#define Q_TTL		8
#define Q_TOS		9
#define Q_DSB		10
#define Q_VID		11
#define Q_VPRI		12
#define Q_MPLSID	13
#define Q_SERVICE	14
#define Q_BYTE		15
#define Q_PKT		16
#define Q_TCPBASE	17
#define Q_TRANS		18
#define Q_RATE		19
#define Q_LOAD		20
#define Q_INTER		21
#define Q_JITTER	22
#define Q_DUR		23
#define Q_AVGDUR	24
#define Q_DELTADUR	25
#define Q_DELTASTART	26
#define Q_DELTALAST	27
#define Q_DELTASPKTS	28
#define Q_DELTADPKTS	29
#define Q_SPI		30
#define Q_LOSS		31
#define Q_PLOSS		32
#define Q_ABR		139
#define Q_PCR		139
#define Q_APPBYTE	33
#define Q_CO		34
#define Q_COCODE	35
#define Q_INODE		36
#define Q_ASN		37
#define Q_SEQ		137
#define Q_STRING	138
#define Q_INTEGER	139
#define Q_FLOAT		140
#define Q_GAP		141
#define Q_DUP		142

/* Protocol qualifiers. */

#define Q_MAN		38
#define Q_FAR		132
#define Q_EVENT		133
#define Q_INDEX		134

/* Keystroke Behavior Keywords */

#define Q_NKEY		135
#define Q_NSTROKE	136

#define Q_LINK		39
#define Q_IP		40
#define Q_IPV6		41
#define Q_IPV4		42
#define Q_IB		43
#define Q_IBGBL		44
#define Q_IBLCL		45
#define Q_ISO		46
#define Q_SVC		47
#define Q_ETHER		48
#define Q_LLC		49
#define Q_ARP		50
#define Q_RARP		51
#define Q_TCP		52
#define Q_UDP		53
#define Q_ICMP		54
#define Q_IGMP		55
#define Q_IGRP		56
#define Q_UDT		57
#define Q_LID		58
#define Q_QP		59

#define	Q_DECNET	60
#define	Q_LAT		62
#define	Q_MOPRC		63
#define	Q_MOPDL		64

#define Q_ANON		65
#define Q_MERGED	66

/* TCP Protocol qualifiers. */

#define Q_NORMAL	67
#define Q_MULTIPATH	68
#define Q_RESET		69
#define Q_TIMEDOUT	70
#define Q_WINSHUT	71
#define Q_ESTABLISHED	72
#define Q_RETRANS	73
#define Q_SRCRETRANS	74
#define Q_DSTRETRANS	75
#define Q_OUTOFORDER	76
#define Q_SRCOUTOFORDER	77
#define Q_DSTOUTOFORDER	78
#define Q_FRAG		79
#define Q_SRCFRAG	80
#define Q_DSTFRAG	81
#define Q_FRAG_ONLY	82
#define Q_CONNECTED 	83
#define Q_REJECT    	84
#define Q_ECHO    	85
#define Q_UNREACH    	86
#define Q_REDIRECT    	87
#define Q_TIMEXED     	88
#define Q_LOOP      	89
#define Q_CORRELATED    90
#define Q_ICMPMAP    	91

#define Q_SYN		92
#define Q_SYNACK	93
#define Q_DATA		94
#define Q_SRCDATA	95
#define Q_DSTDATA	96
#define Q_FIN		97
#define Q_FINACK	98
#define Q_WAIT		99
#define Q_ACK		100
#define Q_URGENT	101
#define Q_PUSH		102
#define Q_ECE		103
#define Q_CWR		104

#define Q_TCPRTT	105

/* RTP Protocol qualifiers. */

#define Q_RTP   	106
#define Q_RTCP   	107
#define Q_ESP   	108
#define Q_ECN   	109
#define Q_MPLS   	110
#define Q_VLAN   	111

#define Q_RTR   	112
#define Q_MBR   	113
#define Q_LVG   	114

/* Cause qualifers. */

#define Q_START   	115
#define Q_STOP   	116
#define Q_STATUS   	117
#define Q_SHUTDOWN   	118
#define Q_ERROR   	119

/* Application Specific qualifers. */
#define Q_DNS   	120

/* Encapsulations */
#define Q_ENCAPS	121

/* ISIS */

#define Q_ISIS		122
#define Q_HELLO		123
#define Q_LSP		124
#define Q_CSNP          125
#define Q_PSNP          126
#define Q_RSVP          127


/* Directional qualifers. */

#define Q_SRC		128
#define Q_DST		129
#define Q_OR		130
#define Q_AND		131

/* TCP Option qualifiers. */

#define Q_TCPOPT		143
#define Q_MSS			144
#define Q_WSCALE		145
#define Q_SELECTIVEACKOK	146
#define Q_SELECTIVEACK		147
#define Q_TCPECHO		148
#define Q_TCPECHOREPLY		149
#define Q_TCPTIMESTAMP		150
#define Q_TCPCC			151
#define Q_TCPCCNEW		152
#define Q_TCPCCECHO		153
#define Q_SECN			154
#define Q_DECN			155

#define Q_JITTERACTIVE		156
#define Q_JITTERIDLE  		157
#define Q_INTERACTIVE		158
#define Q_INTERIDLE  		159

#define Q_DEFAULT	0
#define Q_UNDEF		255

/* Operational qualifiers. */
#define Q_EQUAL		1
#define Q_LESS		2
#define Q_GREATER	3
#define Q_GEQ		4
#define Q_LEQ		5

/* DNS Opcode qualifiers. */
#define Q_AUTH		1
#define Q_RECURS	2


struct stmt {
   u_int dsr;
   int code, type;
   struct slist *jt;       /*only for relative jump in ablock*/
   struct slist *jf;       /*only for relative jump in ablock*/
   union {
      int i;
      float f;
      char s[8];
      long long k;
   } data;
};

struct slist {
   struct stmt s;
   struct slist *next;
};

/* 
 * A bit vector to represent definition sets.  We assume TOT_REGISTERS
 * is smaller than 8*sizeof(atomset).
 */

typedef unsigned int atomset;
#define ATOMMASK(n) (1 << (n))
#define ATOMELEM(d, n) (d & ATOMMASK(n))

/*
 * An unbounded set.
 */

typedef unsigned int *uset;

/*
 * Total number of atomic entities, including accumulator (A) and index (X).
 * We treat all these guys similarly during flow analysis.
 */

#define N_ATOMS		(NFF_MEMWORDS+2)

struct edge {
   int id;
   int code;
   uset edom;
   struct ablock *succ;
   struct ablock *pred;
   struct edge *next;	/* link list of incoming edges for a node */
};

struct ablock {
   int id;
   struct slist *stmts;	/* side effect stmts */
   struct stmt s;		/* branch stmt */
   int mark;
   int longjt;             /* jt branch requires long jump */
   int longjf;             /* jf branch requires long jump */
   int level;
   int offset;
   int sense;
   struct edge et;
   struct edge ef;
   struct ablock *head;
   struct ablock *link;	/* link field used by optimizer */
   uset dom;
   uset closure;
   struct edge *in_edges;
   atomset def, kill;
   atomset in_use;
   atomset out_use;
   long long oval;
   long long val[N_ATOMS];
};

struct arth {
   struct ablock *b;	/* protocol checks */
   struct slist *s;	/* stmt list */
   int regno;		/* virtual register number of result */
};

struct qual {
   unsigned short type;    /* is this IPv4 or IPv6; */
   unsigned short proto;
   unsigned char dir;
   unsigned char addr;
};

#define ARGUS_ADDR_VALUE	1
#define ARGUS_FLOAT_VALUE	2

#ifndef __GNUC__
#define volatile
#endif

/*
#define yylex argus_lex
#define yyparse argus_parse
*/

extern int argus_lex(void);
extern int argus_parse (void);
extern void argus_lex_init(char *buf);

struct arth *ArgusLoadI(int);
struct arth *ArgusLoad(int, struct arth *, int);
struct arth *ArgusLoadLen(void);
struct arth *ArgusArth(int, struct arth *, struct arth *);
struct arth *ArgusNeg(struct arth *);

void Argusgen_and(struct ablock *, struct ablock *);
void Argusgen_or(struct ablock *, struct ablock *);
void Argusgen_not(struct ablock *);

struct ablock *Argusgen_stat(struct ablock *, struct ablock *, unsigned int);

struct ablock *Argusgen_ocode(int, struct qual);
struct ablock *Argusgen_scode(char *, struct qual);
struct ablock *Argusgen_tcode(int, struct qual);
struct ablock *Argusgen_ecode(unsigned char *, struct qual);
struct ablock *Argusgen_mcode(char *, char *, int, struct qual);
struct ablock *Argusgen_ncode(char *, int, struct qual, unsigned int);
struct ablock *Argusgen_fcode(char *, float, struct qual, unsigned int);
struct ablock *Argusgen_proto_abbrev(int);
struct ablock *Argusgen_relation(int, struct arth *, struct arth *, int);
struct ablock *Argusgen_less(int);
struct ablock *Argusgen_greater(int);
struct ablock *Argusgen_byteop(int, int, int);
struct ablock *Argusgen_broadcast(int);
struct ablock *Argusgen_multicast(int);
struct ablock *Argusgen_inbound(int);
struct ablock *Argusgen_dns(int, int, int);
struct ablock *Argusgen_appbytes(int, int, u_int);

void Argusnff_optimize(struct ablock **);

void Argus_error(char *fmt, ...);

void Argusfinish_parse(struct ablock *);
char *Argussdup(char *);

struct nff_insn *Argusicode_to_fcode(struct ablock *, int *);

int Arguspcap_parse(void);
void Arguslex_init(char *);
void Argussappend(struct slist *, struct slist *);

char *ArgusFilterCompile(struct nff_program *, char *, int);

/* XXX */
#define JT(b)  ((b)->et.succ)
#define JF(b)  ((b)->ef.succ)
