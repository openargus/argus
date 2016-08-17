%{
/* Argus Software
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
 *
 * $Id: //depot/argus/argus/common/grammar.y#23 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */
/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994
 *	The Regents of the University of California.  Af rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) af advertising materials mentioning
 * features or use of this software display the fofowing acknowledgement:
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

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#include <argus_compat.h>
#include <sys/types.h>

#if defined(HAVE_SOLARIS) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/socket.h>
#endif

#include <stdlib.h>
#include <sys/time.h>
#include <net/if.h>

#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>

#include <argus_filter.h>

#include <argus_ethertype.h>
#include <argus_compat.h>

#include <syslog.h>

extern void ArgusLog (int, char *, ...);
extern int argus_error (char *);

#define YYDEBUG		1

#define QSET(q, p, d, a) (q).proto = (p),\
			 (q).dir = (d),\
			 (q).addr = (a)

int argus_n_errors = 0;

static struct qual qerr = { Q_UNDEF, Q_UNDEF, Q_UNDEF};

%}

%union {
	int i;
	float f;
	u_long h;
	u_char *e;
	char *s;
	struct stmt *stmt;
	struct arth *a;
	struct {
		struct qual q;
		struct ablock *b;
	} blk;
	struct ablock *rblk;
}

%type	<blk>	expr id nid pid term rterm qid tid oid
%type	<blk>	head thead
%type	<i>	pqual dqual aqual iqual ndaqual 
%type	<f>	fqual
%type	<a>	arth narth
%type	<i>	oname pname sname tname pnum relop irelop
%type	<f>	fnum
%type	<blk>	and or paren not nuf prog
%type	<rblk>	other

%token  START STOP STATUS SHUTDOWN ERROR
%token  MAN FAR EVENT INDEX
%token  DST SRC HOST INODE GATEWAY IPID TTL TOS DSB SRCID TCPBASE
%token  NET AMASK PORT EQUAL LESS GREATER PROTO BYTE PKT APPBYTE
%token  TRANS ARP RARP IP IPV4 IPV6 TCP UDP ICMP IGMP 
%token  ISIS HELLO LSP CSNP PSNP
%token  UDT SVC TCPRTT TCPOPT
%token  MSS WSCALE SELECTIVEACKOK SELECTIVEACK TCPECHO TCPECHOREPLY
%token  TCPTIMESTAMP TCPCC TCPCCNEW TCPCCECHO SECN DECN

%token  ETHER MPLS VLAN ANON VID VPRI MPLSID SPI
%token  ENCAPS RTP RTCP ESP DECNET LAT MOPRC MOPDL
%token  TK_BROADCAST TK_MULTICAST FRAG FRAG_ONLY 
%token  ABR PCR RATE LOAD LOSS PLOSS GAP DUP CO 
%token  INTER INTERACTIVE INTERIDLE JITTER JITTERACTIVE JITTERIDLE
%token  DUR AVGDUR DELTADUR DELTASTART DELTALAST
%token  DELTASPKTS DELTADPKTS
%token  SEQ NSTROKE
%token  NUM FLOAT INBOUND OUTBOUND
%token  LINK AUTH RECURS REQ RSP
%token	GEQ LEQ NEQ
%token	ID EID HIDV4 HIDV6 STRING
%token	LSH RSH
%token  LEN

%token  OUTOFORDER RETRANS NORMAL WAIT MULTIPATH RESET TIMEDOUT WINSHUT
%token  SYN SYNACK ACK PUSH URGENT DATA ECE CWR FIN FINACK ICMPECHO ICMPMAP
%token  UNREACH REDIRECT ECN TIMEXED ESTABLISHED CONNECTED CORRELATED
%token  RTR MBR LVG COCODE ASN

%type	<s>  ID
%type	<e>  EID
%type	<s>  HIDV4
%type	<s>  HIDV6
%type	<s>  STRING
%type	<i>  NUM
%type	<f>  FLOAT

%left OR AND
%nonassoc  '!'
%left '|'
%left '&'
%left LSH RSH
%left '+' '-'
%left '*' '/'
%nonassoc UMINUS
%%
prog:	  nuf expr
{
	Argusfinish_parse($2.b);
}
	| nuf
	;
nuf:	  /* nuf */		{ $$.q = qerr; }
	;
expr:	  term
	| expr and term		{ Argusgen_and($1.b, $3.b); $$ = $3; }
	| expr and id		{ Argusgen_and($1.b, $3.b); $$ = $3; }
	| expr or term		{ Argusgen_or($1.b, $3.b); $$ = $3; }
	| expr or id		{ Argusgen_or($1.b, $3.b); $$ = $3; }
	;
and:	  AND			{ $$ = $<blk>0; }
	;
or:	  OR			{ $$ = $<blk>0; }
	;
id:	  nid
	| pnum			{ $$.b = Argusgen_ncode(NULL, (int)$1, $$.q = $<blk>0.q, Q_EQUAL); }
        | fnum                  { $$.b = Argusgen_fcode(NULL, (float)$1, $$.q = $<blk>0.q, Q_EQUAL); }

	| LESS pnum		{ $$.b = Argusgen_ncode(NULL, (int)$2, $$.q = $<blk>0.q, Q_LESS); }
	| GREATER pnum		{ $$.b = Argusgen_ncode(NULL, (int)$2, $$.q = $<blk>0.q, Q_GREATER); }
	| EQUAL pnum		{ $$.b = Argusgen_ncode(NULL, (int)$2, $$.q = $<blk>0.q, Q_EQUAL); }
	| GEQ pnum		{ $$.b = Argusgen_ncode(NULL, (int)$2, $$.q = $<blk>0.q, Q_GEQ); }
	| LEQ pnum		{ $$.b = Argusgen_ncode(NULL, (int)$2, $$.q = $<blk>0.q, Q_LEQ); }

        | LESS fnum             { $$.b = Argusgen_fcode(NULL, (float)$2, $$.q = $<blk>0.q, Q_LESS); }
        | GREATER fnum          { $$.b = Argusgen_fcode(NULL, (float)$2, $$.q = $<blk>0.q, Q_GREATER); }
        | EQUAL fnum            { $$.b = Argusgen_fcode(NULL, (float)$2, $$.q = $<blk>0.q, Q_EQUAL); }
        | GEQ fnum              { $$.b = Argusgen_fcode(NULL, (float)$2, $$.q = $<blk>0.q, Q_GEQ); }
        | LEQ fnum              { $$.b = Argusgen_fcode(NULL, (float)$2, $$.q = $<blk>0.q, Q_LEQ); }

	| paren pid ')'		{ $$ = $2; }
	;
tid:	  tname			{ $$.b = Argusgen_tcode($1, $$.q = $<blk>0.q); }

oid:	  oname			{ $$.b = Argusgen_ocode($1, $$.q = $<blk>0.q); }
	;
nid:	  ID			{ $$.b = Argusgen_scode($1, $$.q = $<blk>0.q); }
	| STRING       		{ $$.q = $<blk>0.q; $$.q.type = Q_STRING;
                                  $$.b = Argusgen_scode($1, $$.q); }
	| HIDV4 '/' NUM		{ $$.q = $<blk>0.q; $$.q.type = Q_IPV4;
                                  $$.b = Argusgen_mcode($1, NULL, $3, $$.q); }
	| HIDV4 AMASK HIDV4	{ $$.q = $<blk>0.q; $$.q.type = Q_IPV4;
                                  $$.b = Argusgen_mcode($1, (char *)$3, 0, $$.q); }
	| HIDV4			{ $$.q = $<blk>0.q; $$.q.type = Q_IPV4;
                                  $$.b = Argusgen_ncode($1, 0, $$.q, Q_EQUAL); }
	| HIDV6 '/' NUM		{ $$.q = $<blk>0.q; $$.q.type = Q_IPV6;
                                  $$.b = Argusgen_mcode($1, NULL, $3, $$.q); }
	| HIDV6			{ $$.q = $<blk>0.q; $$.q.type = Q_IPV6;
                                  $$.b = Argusgen_ncode($1, 0, $$.q, Q_EQUAL); }
	| EID			{ $$.q = $<blk>0.q; $$.q.type = Q_IPV6;
				  $$.b = Argusgen_ecode($1, $$.q); }
	| not id		{ Argusgen_not($2.b); $$ = $2; }
	;
not:	  '!'			{ $$ = $<blk>0; }
	;
paren:	  '('			{ $$ = $<blk>0; }
	;
pid:	  nid
	| qid and id		{ Argusgen_and($1.b, $3.b); $$ = $3; }
	| qid or id		{ Argusgen_or($1.b, $3.b); $$ = $3; }
	;
qid:	  pnum			{ $$.b = Argusgen_ncode(NULL, (int)$1, $$.q = $<blk>0.q, Q_EQUAL); }
        | fnum                  { $$.b = Argusgen_fcode(NULL, (float)$1, $$.q = $<blk>0.q, Q_EQUAL); }
	| pid
	;
term:	  rterm
	| not term		{ Argusgen_not($2.b); $$ = $2; }
	;
head:	  pqual dqual aqual	{ QSET($$.q, $1, $2, $3); }
	| pqual dqual		{ QSET($$.q, $1, $2, Q_DEFAULT); }
	| pqual aqual		{ QSET($$.q, $1, Q_DEFAULT, $2); }
	| pqual iqual 		{ QSET($$.q, $1, Q_DEFAULT, $2); $$.q.type = Q_INTEGER; }
	| pqual fqual 		{ QSET($$.q, $1, Q_DEFAULT, $2); $$.q.type = Q_FLOAT; }
	| pqual dqual iqual 	{ QSET($$.q, $1, $2, $3); $$.q.type = Q_INTEGER; }
	| pqual dqual fqual 	{ QSET($$.q, $1, $2, $3); $$.q.type = Q_FLOAT; }
	| pqual PROTO		{ QSET($$.q, $1, Q_DEFAULT, Q_PROTO); }
	| pqual ndaqual		{ QSET($$.q, $1, Q_DEFAULT, $2); }
	;

thead:	  pqual dqual		{ QSET($$.q, $1, $2, Q_DEFAULT); }
	;

rterm:	  head id		{ $$ = $2; }
	| thead tid		{ $$ = $2; }
	| paren expr ')'	{ $$.b = $2.b; $$.q = $1.q; }
	| pname			{ $$.b = Argusgen_proto_abbrev($1); $$.q = qerr; }
	| sname			{ $$.b = Argusgen_proto_abbrev($1); $$.q = qerr; }
	| tid			{ $$ = $1; }
	| oid			{ $$ = $1; }
	| arth relop arth	{ $$.b = Argusgen_relation($2, $1, $3, 0); $$.q = qerr; }
	| arth irelop arth	{ $$.b = Argusgen_relation($2, $1, $3, 1); $$.q = qerr; }
	| other			{ $$.b = $1; $$.q = qerr; }
	;

/* protocol level qualifiers */
pqual:	  pname
	|			{ $$ = Q_DEFAULT; }
	;
/* 'direction' qualifiers */
dqual:	  SRC			{ $$ = Q_SRC; }
	| DST			{ $$ = Q_DST; }
	| SRC OR DST		{ $$ = Q_OR; }
	| DST OR SRC		{ $$ = Q_OR; }
	| SRC AND DST		{ $$ = Q_AND; }
	| DST AND SRC		{ $$ = Q_AND; }
	;
/* address type qualifiers */
aqual:	  HOST			{ $$ = Q_HOST; }
	| SRCID			{ $$ = Q_SRCID; }
	| INODE			{ $$ = Q_INODE; }
	| NET			{ $$ = Q_NET; }
	;
/* identifier types */
iqual:    PORT			{ $$ = Q_PORT; }
	| IPID			{ $$ = Q_IPID; }
	| TTL			{ $$ = Q_TTL; }
	| TOS			{ $$ = Q_TOS; }
	| DSB			{ $$ = Q_DSB; }
	| CO			{ $$ = Q_CO; }
	| ASN			{ $$ = Q_ASN; }
	| VID			{ $$ = Q_VID; }
	| VPRI			{ $$ = Q_VPRI; }
	| MPLSID		{ $$ = Q_MPLSID; }
	| BYTE			{ $$ = Q_BYTE; }
	| APPBYTE		{ $$ = Q_APPBYTE; }
	| PKT			{ $$ = Q_PKT; }
	| TRANS  		{ $$ = Q_TRANS; }
	| TCPRTT 		{ $$ = Q_TCPRTT; }
	| TCPBASE		{ $$ = Q_TCPBASE; }
	| LOSS  		{ $$ = Q_LOSS; }
	| GAP   		{ $$ = Q_GAP; }
	| DUP   		{ $$ = Q_DUP; }
	| SPI	  		{ $$ = Q_SPI; }
	| ENCAPS  		{ $$ = Q_ENCAPS; }
	| DELTADUR		{ $$ = Q_DELTADUR; }
	| DELTASTART		{ $$ = Q_DELTASTART; }
	| DELTALAST		{ $$ = Q_DELTALAST; }
	| NSTROKE		{ $$ = Q_NSTROKE; }
	| SEQ			{ $$ = Q_SEQ; }
	;
/* identifier types */
fqual:    DUR			{ $$ = Q_DUR; }
	| AVGDUR		{ $$ = Q_AVGDUR; }
	| INTER			{ $$ = Q_INTER; }
	| INTERACTIVE		{ $$ = Q_INTERACTIVE; }
	| INTERIDLE		{ $$ = Q_INTERIDLE; }
	| JITTER		{ $$ = Q_JITTER; }
	| JITTERACTIVE		{ $$ = Q_JITTERACTIVE; }
	| JITTERIDLE		{ $$ = Q_JITTERIDLE; }
	| RATE  		{ $$ = Q_RATE; }
	| LOAD  		{ $$ = Q_LOAD; }
	| PLOSS  		{ $$ = Q_PLOSS; }
	| ABR	 		{ $$ = Q_PCR; }
	| PCR	 		{ $$ = Q_PCR; }
        ;
/* non-directional address type qualifiers */
ndaqual:  GATEWAY		{ $$ = Q_GATEWAY; }
	;

sname:	  START			{ $$ = Q_START; }
	| STOP			{ $$ = Q_STOP; }
	| STATUS		{ $$ = Q_STATUS; }
	| SHUTDOWN		{ $$ = Q_SHUTDOWN; }
	| ERROR			{ $$ = Q_ERROR; }
	| MAN			{ $$ = Q_MAN; }
	| FAR  			{ $$ = Q_FAR; }
	| EVENT			{ $$ = Q_EVENT; }
	| INDEX			{ $$ = Q_INDEX; }
	| SVC			{ $$ = Q_SVC; }
        | NORMAL		{ $$ = Q_NORMAL; }
        | WAIT			{ $$ = Q_WAIT; }
	| SYNACK		{ $$ = Q_SYNACK; }
	| FINACK		{ $$ = Q_FINACK; }
	| ESTABLISHED		{ $$ = Q_ESTABLISHED; }
	| CONNECTED		{ $$ = Q_CONNECTED; }
	| CORRELATED		{ $$ = Q_CORRELATED; }
	| TIMEDOUT		{ $$ = Q_TIMEDOUT; }
	| ICMPMAP		{ $$ = Q_ICMPMAP; }
	| ICMPECHO		{ $$ = Q_ECHO; }
	| UNREACH		{ $$ = Q_UNREACH; }
	| REDIRECT		{ $$ = Q_REDIRECT; }
	| TIMEXED 		{ $$ = Q_TIMEXED; }
	| RTR			{ $$ = Q_RTR; }
	| MBR			{ $$ = Q_MBR; }
	| LVG			{ $$ = Q_LVG; }
	| COCODE		{ $$ = Q_COCODE; }
	;

pname:	  LINK			{ $$ = Q_LINK; }
	| ETHER			{ $$ = Q_ETHER; }
	| IP			{ $$ = Q_IP; }
	| IPV4			{ $$ = Q_IPV4; }
	| IPV6			{ $$ = Q_IPV6; }
	| ARP			{ $$ = Q_ARP; }
	| RARP			{ $$ = Q_RARP; }
	| ESP			{ $$ = Q_ESP; }
	| RTP			{ $$ = Q_RTP; }
	| RTCP			{ $$ = Q_RTCP; }
	| TCP			{ $$ = Q_TCP; }
	| UDP			{ $$ = Q_UDP; }
	| ICMP			{ $$ = Q_ICMP; }
	| IGMP			{ $$ = Q_IGMP; }
	| MPLS			{ $$ = Q_MPLS; }
	| ISIS			{ $$ = Q_ISIS; }
	| VLAN			{ $$ = Q_VLAN; }
	| UDT			{ $$ = Q_UDT; }
	| ANON			{ $$ = Q_ANON; }
	| DECNET		{ $$ = Q_DECNET; }
	| LAT			{ $$ = Q_LAT; }
	| MOPDL			{ $$ = Q_MOPDL; }
	| MOPRC			{ $$ = Q_MOPRC; }
	;

tname:	  OUTOFORDER		{ $$ = Q_OUTOFORDER; }
	| RETRANS		{ $$ = Q_RETRANS; }
	| WINSHUT		{ $$ = Q_WINSHUT; }
	| SYN			{ $$ = Q_SYN; }
	| FIN			{ $$ = Q_FIN; }
	| RESET			{ $$ = Q_RESET; }
	| ACK			{ $$ = Q_ACK; }
	| PUSH			{ $$ = Q_PUSH; }
	| URGENT		{ $$ = Q_URGENT; }
	| CWR			{ $$ = Q_CWR; }
	| ECE			{ $$ = Q_ECE; }
	| FRAG			{ $$ = Q_FRAG; }
	| FRAG_ONLY		{ $$ = Q_FRAG_ONLY; }
	| ECN			{ $$ = Q_ECN; }
	| MULTIPATH		{ $$ = Q_MULTIPATH; }
	| HELLO                 { $$ = Q_HELLO; }
	| LSP                   { $$ = Q_LSP; }
	| CSNP                  { $$ = Q_CSNP; }
	| PSNP                  { $$ = Q_PSNP; }
	;
oname:     TCPOPT               { $$ = Q_TCPOPT; }
        |  MSS                  { $$ = Q_MSS; }
        |  WSCALE               { $$ = Q_WSCALE; }
        |  SELECTIVEACKOK       { $$ = Q_SELECTIVEACKOK; }
        |  SELECTIVEACK         { $$ = Q_SELECTIVEACK; }
        |  TCPECHO              { $$ = Q_TCPECHO; }
        |  TCPECHOREPLY         { $$ = Q_TCPECHOREPLY; }
        |  TCPTIMESTAMP         { $$ = Q_TCPTIMESTAMP; }
        |  TCPCC                { $$ = Q_TCPCC; }
        |  TCPCCNEW             { $$ = Q_TCPCCNEW; }
        |  TCPCCECHO            { $$ = Q_TCPCCECHO; }
        |  SECN                 { $$ = Q_SECN; }
        |  DECN                 { $$ = Q_DECN; }
	;

other:	  pqual TK_BROADCAST	{ $$ = Argusgen_broadcast($1); }
	| pqual TK_MULTICAST	{ $$ = Argusgen_multicast($1); }
	| INBOUND		{ $$ = Argusgen_inbound(0); }
	| OUTBOUND		{ $$ = Argusgen_inbound(1); }
	;
relop:	  '>'			{ $$ = NFF_JGT; }
	| GEQ			{ $$ = NFF_JGE; }
	| '='			{ $$ = NFF_JEQ; }
	| EQUAL			{ $$ = NFF_JEQ; }
	;
irelop:	  LEQ			{ $$ = NFF_JGT; }
	| '<'			{ $$ = NFF_JGE; }
	| NEQ			{ $$ = NFF_JEQ; }
	;
arth:	  pnum			{ $$ = ArgusLoadI($1); }
	| narth
	;
narth:	  pname '[' arth ']'		{ $$ = ArgusLoad($1, $3, 1); }
	| pname '[' arth ':' NUM ']'	{ $$ = ArgusLoad($1, $3, $5); }
	| arth '+' arth			{ $$ = ArgusArth(NFF_ADD, $1, $3); }
	| arth '-' arth			{ $$ = ArgusArth(NFF_SUB, $1, $3); }
	| arth '*' arth			{ $$ = ArgusArth(NFF_MUL, $1, $3); }
	| arth '/' arth			{ $$ = ArgusArth(NFF_DIV, $1, $3); }
	| arth '&' arth			{ $$ = ArgusArth(NFF_AND, $1, $3); }
	| arth '|' arth			{ $$ = ArgusArth(NFF_OR, $1, $3); }
	| arth LSH arth			{ $$ = ArgusArth(NFF_LSH, $1, $3); }
	| arth RSH arth			{ $$ = ArgusArth(NFF_RSH, $1, $3); }
	| paren narth ')'		{ $$ = $2; }
	| LEN				{ $$ = ArgusLoadLen(); }
	;
pnum:	  NUM
	| paren pnum ')'	{ $$ = $2; }
	;
fnum:	  FLOAT
	| paren fnum ')'	{ $$ = $2; }
	;
%%

int
yyerror(char *msg)
{
   ++argus_n_errors;
   return(1);
}
