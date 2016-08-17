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
 * Copyright (c) 1990, 1991, 1992, 1993
 *   The Regents of the University of California.  All rights reserved.
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
 *   This product includes software developed by the University of
 *   California, Berkeley and its contributors.
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
 *   @(#)nff.c   7.5 (Berkeley) 7/15/91
 *
 */

/* 
 * $Id: //depot/argus/argus/common/argus_filter.c#24 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#ifndef ArgusFilter
#define ArgusFilter
#endif


#include <stdlib.h>
#include <unistd.h>

#if defined(ARGUS_PLURIBUS)
#define _STDC_C99
#else
#if !defined(__USE_ISOC99)
#define __USE_ISOC99
#endif
#endif

#include <math.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#if defined(HAVE_SOLARIS)
#include <fcntl.h>
#endif

#include <argus_compat.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <argus_int.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>

#include <sys/param.h>
#include <sys/time.h>
#include <net/nff.h>

#include <argus_filter.h>

#ifdef sun
#include <netinet/in.h>
#endif

#include <argus_ethertype.h>

extern void ArgusLog (int, char *, ...);

#define EXTRACT_SHORT(p)	((arg_uint16)*(arg_uint16 *)p)
#define EXTRACT_LONG(p)		(*(unsigned int *)p)
#define EXTRACT_FLOAT(p)	(*(float *)p)
#define EXTRACT_DOUBLE(p)	(*(double *)p)
#define EXTRACT_LONGLONG(p)	(*(unsigned long long *)p)

static int floatisequal(double, double);
static int floatisgreaterthan(double, double);
static int floatislessthan(double, double);
static int floatisgreaterthanequal(double, double);

#include <ctype.h>

#if defined(ARGUS_PLURIBUS)
#ifndef signbit
#include <ieeefp.h>

inline int
signbit(double x)
{
   switch (fpclass(x)) {
     case FP_SNAN:
     case FP_QNAN:
     case FP_PZERO:
     case FP_PNORM:
     case FP_PDENORM:
     case FP_PINF:
        return(0);

     case FP_NDENORM:
     case FP_NZERO:
     case FP_NINF:
     case FP_NNORM:
        return(1);
   }
}
#endif
#endif

/* Hex digit to integer. */
int
xdtoi(int c)
{
   if (isdigit(c))
      return c - '0';
   else if (islower(c))
      return c - 'a' + 10;
   else
      return c - 'A' + 10;
}

/*
 * Execute the filter program starting at pc on the packet p
 * buflen is the amount of data present
 */
int ArgusFilterRecord (struct nff_insn *, struct ArgusRecordStruct *);
int ArgusFilterOrig (struct nff_insn *, struct ArgusRecordStruct *, int, int);

int
ArgusFilterRecord (struct nff_insn *pc, struct ArgusRecordStruct *argus)
{
   int buflen = sizeof(*argus);

   if (pc)
      return ArgusFilterOrig (pc, argus, buflen, buflen);
   else
      return -1;
}

static int
floatisequal(double F, double f)
{
   extern struct ArgusParserStruct *ArgusParser;
   double epsilon = pow(0.1, ((ArgusParser->pflag + 1) * 1.0));
   double pval = pow(10.0, ArgusParser->pflag);

   F = round(F * pval) / pval;
   f = round(f * pval) / pval;
   return ((fabs(F - f) <= epsilon) ? ((F == 0) ? (signbit(F) == signbit(f))  : 1) : 0);
}

static int
floatisgreaterthan(double F, double f)
{
   extern struct ArgusParserStruct *ArgusParser;
   double pval = pow(10.0, ArgusParser->pflag);

   F = round(F * pval) / pval;
   f = round(f * pval) / pval;
   return ((F > f) ? 1 : (((F == 0) && (f == 0)) ? ((!(signbit(F)) && signbit(f)) ? 1 : 0)  : 0));
}

static int
floatislessthan(double F, double f)
{
   extern struct ArgusParserStruct *ArgusParser;
   double pval = pow(10.0, ArgusParser->pflag);

   F = round(F * pval) / pval;
   f = round(f * pval) / pval;
   return ((F < f) ? 1 : (((F == 0) && (f == 0)) ? ((!(signbit(F)) && signbit(f)) ? 0 : 1)  : 0));
}

static int
floatisgreaterthanequal(double F, double f)
{
   return (!(floatislessthan(F, f)));
}

int
ArgusFilterOrig (struct nff_insn *pc, struct ArgusRecordStruct *argus, int wirelen, int buflen)
{
   nff_int64 A = 0, X = 0;
   nff_int64 mem [NFF_MEMWORDS];
   int k, retn;
   u_char *p = (u_char *)argus;
   float F;

   --pc;
   while (1) {
      ++pc;
      switch (pc->code) {
         default:
            abort();

         case NFF_RET|NFF_K: {
            retn = pc->data.k;
            return retn;
         }

         case NFF_RET|NFF_A:
            return (unsigned int)A;

         case NFF_LD|NFF_D|NFF_DSR: {
            if (pc->dsr >= 0) {
               struct ArgusDSRHeader *dsr;
               if ((dsr = argus->dsrs[pc->dsr]) != NULL) {
                  u_char *ptr = (u_char *)dsr;
                  k = pc->data.k;
                  if (k + sizeof(double) > (dsr->argus_dsrvl8.len * 4)) 
                     A = -1;
                  else
                     A = EXTRACT_DOUBLE(&ptr[k]);
               } else
                  A = -1;
            } else {
               if (argus != NULL) {
                  u_char *ptr = (u_char *)&argus->hdr;
                  k = pc->data.k;
                  if ((k + sizeof(double)) > sizeof(struct ArgusRecordStruct))
                     A = -1;
                  else
                     A = EXTRACT_DOUBLE(&ptr[k]);
               } else
                  A = -1;
            }
            continue;
         }

         case NFF_LD|NFF_D|NFF_ABS: {
            k = pc->data.k;
            if (k + sizeof(double) > buflen) {
               A = -1;
            } else
               A = EXTRACT_DOUBLE(&p[k]);
            continue;
         }

         case NFF_LD|NFF_F|NFF_DSR: {
            if (pc->dsr >= 0) {
               struct ArgusDSRHeader *dsr;
               if ((dsr = argus->dsrs[pc->dsr]) != NULL) {
                  u_char *ptr = (u_char *)dsr;
                  k = pc->data.k;
                  if ((k + sizeof(float)) > (dsr->argus_dsrvl8.len * 4))
                     F = -10000000;
                  else
                     F = EXTRACT_FLOAT(&ptr[k]);
               } else
                  F = -10000000;
            } else {
               if (argus != NULL) {
                  u_char *ptr = (u_char *)&argus->hdr;
                  k = pc->data.k;
                  if ((k + sizeof(float)) > sizeof(struct ArgusRecordStruct))
                     F = -10000000;
                  else
                     F = EXTRACT_FLOAT(&ptr[k]);
               } else
                  F = -10000000;
            }
            continue;
         }

         case NFF_LD|NFF_F|NFF_ABS: {
            k = pc->data.k;
            if (k + sizeof(float) > buflen) {
               F = -10000000;
            } else
               F = EXTRACT_FLOAT(&p[k]);
            continue;
         }

         case NFF_LD|NFF_L|NFF_DSR: {
            if (pc->dsr >= 0) {
               struct ArgusDSRHeader *dsr;
               if ((dsr = argus->dsrs[pc->dsr]) != NULL) {
                  u_char *ptr = (u_char *)dsr;
                  k = pc->data.k;
                  if (k + sizeof(long long) > (dsr->argus_dsrvl8.len * 4)) 
                     A = -1;
                  else
                     A = EXTRACT_LONGLONG(&ptr[k]);
               } else
                  A = -1;
            } else {
               if (argus != NULL) {
                  u_char *ptr = (u_char *)&argus->hdr;
                  k = pc->data.k;
                  if ((k + sizeof(long long)) > sizeof(struct ArgusRecordStruct))
                     A = -1;
                  else
                     A = EXTRACT_LONGLONG(&ptr[k]);
               } else
                  A = -1;
            }
            continue;
         }

         case NFF_LD|NFF_L|NFF_ABS: {
            k = pc->data.k;
            if ((k + sizeof(long long)) > buflen) {
               A = -1;
            } else
               A = EXTRACT_LONGLONG(&p[k]);
            continue;
         }

         case NFF_LD|NFF_W|NFF_DSR: {
            if (pc->dsr >= 0) {
               struct ArgusDSRHeader *dsr;
               if ((dsr = argus->dsrs[pc->dsr]) != NULL) {
                  u_char *ptr = (u_char *)dsr;
                  k = pc->data.k;
                  if ((k + sizeof(int)) > (dsr->argus_dsrvl8.len * 4))
                     A = -1;
                  else
                     A = EXTRACT_LONG(&ptr[k]);
               } else
                  A = -1;

            } else {
               if (argus != NULL) {
                  u_char *ptr = (u_char *)&argus->hdr;
                  k = pc->data.k;
                  if ((k + sizeof(int)) > sizeof(struct ArgusRecordStruct))
                     A = -1;
                  else
                     A = EXTRACT_LONG(&ptr[k]);
               } else
                  A = -1;
            }
            continue;
         }

         case NFF_LD|NFF_W|NFF_ABS: {
            k = pc->data.k;
            if ((k + sizeof(int)) > buflen) {
               A = -1;
            } else
               A = EXTRACT_LONG(&p[k]);
            continue;
         }

         case NFF_LD|NFF_H|NFF_DSR: {
            if (pc->dsr >= 0) {
               struct ArgusDSRHeader *dsr;
               if ((dsr = argus->dsrs[pc->dsr]) != NULL) {
                  u_char *ptr = (u_char *)dsr;
                  k = pc->data.k;
                  if ((k + sizeof(short)) > (dsr->argus_dsrvl8.len * 4))
                     A = -1;
                  else
                     A = EXTRACT_SHORT(&ptr[k]);
               } else
                  A = -1;
            } else {
               if (argus != NULL) {
                  u_char *ptr = (u_char *)&argus->hdr;
                  k = pc->data.k;
                  if ((k + sizeof(short)) > sizeof(struct ArgusRecordStruct))
                     A = -1;
                  else
                     A = EXTRACT_SHORT(&ptr[k]);
               } else
                  A = -1;
            }
            continue;
         }

         case NFF_LD|NFF_H|NFF_ABS: {
            k = pc->data.k;
            if ((k + sizeof(short)) > buflen)
               A = -1;
            else
               A = EXTRACT_SHORT(&p[k]);
            continue;
         }

         case NFF_LD|NFF_B|NFF_DSR: {
            if (pc->dsr >= 0) {
               struct ArgusDSRHeader *dsr;
               if ((dsr = argus->dsrs[pc->dsr]) != NULL) {
                  u_char *ptr = (u_char *)dsr;
                  k = pc->data.k;
                  if (k > (dsr->argus_dsrvl8.len * 4))
                     A = -1;
                  else
                     A = ptr[k];
               } else
                  A = -1;
            } else {
               if (argus != NULL) {
                  u_char *ptr = (u_char *)&argus->hdr;
                  k = pc->data.k;
                  if (k > sizeof(struct ArgusRecordStruct))
                     A = -1;
                  else
                     A = ptr[k];
               } else
                  A = -1;
            }
            continue;
         }

         case NFF_LD|NFF_B|NFF_ABS: {
            k = pc->data.k;
            if (k >= buflen) {
               A = -1;
            } else
               A = p[k];
            continue;
         }

         case NFF_LD|NFF_W|NFF_LEN: {
            A = wirelen;
            continue;
         }

         case NFF_LDX|NFF_W|NFF_LEN: {
            X = wirelen;
            continue;
         }

         case NFF_LD|NFF_W|NFF_IND: {
            k = X + pc->data.k;
            if ((k + sizeof(int)) > buflen) {
               A = -1;
            } else
               A = EXTRACT_LONG(&p[k]);
            continue;
         }

         case NFF_LD|NFF_H|NFF_IND: {
            k = X + pc->data.k;
            if ((k + sizeof(short)) > buflen) {
               A = -1;
            } else
               A = EXTRACT_SHORT(&p[k]);
            continue;
         }

         case NFF_LD|NFF_B|NFF_IND: {
            k = X + pc->data.k;
            if (k >= buflen) {
               A = -1;
            } else
               A = p[k];
            continue;
         }

         case NFF_LDX|NFF_MSH|NFF_B: {
            k = pc->data.k;
            if (k >= buflen) {
               X = -1;
            } else
               X = (p[k] & 0xf) << 2;
            continue;
         }

         case NFF_LD|NFF_IMM: {
            A = pc->data.k;
            continue;
         }

         case NFF_LDX|NFF_IMM: {
            X = pc->data.k;
            continue;
         }

         case NFF_LD|NFF_MEM: {
            k = pc->data.k;
            A = mem[k];
            continue;
         }
            
         case NFF_LDX|NFF_MEM: {
            k = pc->data.k;
            X = mem[k];
            continue;
         }

         case NFF_ST: {
            k = pc->data.k;
            mem[k] = A;
            continue;
         }

         case NFF_STX: {
            k = pc->data.k;
            mem[k] = X;
            continue;
         }

         case NFF_JMP|NFF_JA: {
            k = pc->data.k;
            pc += k;
            continue;
         }

         case NFF_JMP|NFF_JGT|NFF_K: {
            pc += ((A > pc->data.k) && (A != -1)) ? pc->jt : pc->jf;
            continue;
         }

         case NFF_JMP|NFF_JGE|NFF_K: {
            pc += ((A >= pc->data.k) && (A != -1)) ? pc->jt : pc->jf;
            continue;
         }

         case NFF_JMP|NFF_JEQ|NFF_K: {
            pc += ((A == pc->data.k) && (A != -1)) ? pc->jt : pc->jf;
            continue;
         }

         case NFF_JMP|NFF_JGT|NFF_F: {
            pc += ((floatisgreaterthan(F, pc->data.f)) && (F != -10000000)) ? pc->jt : pc->jf;
            continue;
         }

         case NFF_JMP|NFF_JGE|NFF_F: {
            pc += ((floatisgreaterthanequal(F, pc->data.f)) && (F != -10000000)) ? pc->jt : pc->jf;
            continue;
         }

         case NFF_JMP|NFF_JEQ|NFF_F: {
            pc += ((floatisequal(F, pc->data.f)) && (F != -10000000)) ? pc->jt : pc->jf;
            continue;
         }

         case NFF_JMP|NFF_JSET|NFF_K: {
            pc += ((A & pc->data.k) && (A != -1)) ? pc->jt : pc->jf;
            continue;
         }

         case NFF_JMP|NFF_JGT|NFF_X: {
            pc += ((A > X) && (A != -1)) ? pc->jt : pc->jf;
            continue;
         }

         case NFF_JMP|NFF_JGE|NFF_X: {
            pc += ((A >= X) && (A != -1)) ? pc->jt : pc->jf;
            continue;
         }

         case NFF_JMP|NFF_JEQ|NFF_X: {
            pc += ((A == X) && (A != -1)) ? pc->jt : pc->jf;
            continue;
         }

         case NFF_JMP|NFF_JSET|NFF_X: {
            pc += ((A & X) && (A != -1)) ? pc->jt : pc->jf;
            continue;
         }

         case NFF_ALU|NFF_ADD|NFF_X: {
            A += X;
            continue;
         }
            
         case NFF_ALU|NFF_SUB|NFF_X: {
            A -= X;
            continue;
         }
            
         case NFF_ALU|NFF_MUL|NFF_X: {
            A *= X;
            continue;
         }
            
         case NFF_ALU|NFF_DIV|NFF_X: {
            if (X == 0)
               return 0;
            A /= X;
            continue;
         }
            
         case NFF_ALU|NFF_AND|NFF_X: {
            A &= X;
            continue;
         }
            
         case NFF_ALU|NFF_OR|NFF_X: {
            A |= X;
            continue;
         }

         case NFF_ALU|NFF_LSH|NFF_X: {
            A <<= X;
            continue;
         }

         case NFF_ALU|NFF_RSH|NFF_X: {
            A >>= X;
            continue;
         }

         case NFF_ALU|NFF_ADD|NFF_K: {
            A += pc->data.k;
            continue;
         }
            
         case NFF_ALU|NFF_SUB|NFF_K: {
            A -= pc->data.k;
            continue;
         }
            
         case NFF_ALU|NFF_MUL|NFF_K: {
            A *= pc->data.k;
            continue;
         }
            
         case NFF_ALU|NFF_DIV|NFF_K: {
            A /= pc->data.k;
            continue;
         }
            
         case NFF_ALU|NFF_AND|NFF_K: {
            A &= pc->data.k;
            continue;
         }
            
         case NFF_ALU|NFF_OR|NFF_K: {
            A |= pc->data.k;
            continue;
         }

         case NFF_ALU|NFF_LSH|NFF_K: {
            A <<= pc->data.k;
            continue;
         }

         case NFF_ALU|NFF_RSH|NFF_K: {
            A >>= pc->data.k;
            continue;
         }

         case NFF_ALU|NFF_NEG: {
            A = -A;
            continue;
         }

         case NFF_MISC|NFF_TAX: {
            X = A;
            continue;
         }

         case NFF_MISC|NFF_TXA: {
            A = X;
            continue;
         }
      }
   }
}

/*
 * Copyright (c) 1990, 1993, 1994
 *   The Regents of the University of California.  All rights reserved.
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


#ifndef __GNUC__
#define inline
#endif

static inline int skip_space(FILE *);
static inline int skip_line(FILE *);

static inline int
skip_space(f)
FILE *f;
{
   int c;

   do {
      c = getc(f);
   } while (isspace(c) && c != '\n');

   return c;
}

static inline int
skip_line(f)
   FILE *f;
{
   int c;

   do
      c = getc(f);
   while (c != '\n' && c != EOF);

   return c;
}


#include <argus_namedb.h>

struct argus_etherent *
argus_next_etherent(FILE *fp)
{
   int c, d, i;
   char *bp;
   static struct argus_etherent e;
   static int nline = 1;
 top:
   while (nline) {
      /* Find addr */
      c = skip_space(fp);
      if (c == '\n')
         continue;
      /* If this is a comment, or first thing on line
         cannot be ethernet address, skip the line. */
      else if (!isxdigit(c))
         c = skip_line(fp);
      else {
         /* must be the start of an address */
         for (i = 0; i < 6; i += 1) {
            d = xdtoi(c);
            c = getc(fp);
            if (c != ':') {
               d <<= 4;
               d |= xdtoi(c);
               c = getc(fp);
            }
            e.addr[i] = d;
            if (c != ':')
               break;
            c = getc(fp);
         }
         nline = 0;
      }
      if (c == EOF)
         return 0;
   }

   /* If we started a new line, 'c' holds the char past the ether addr,
      which we assume is white space.  If we are continuing a line,
      'c' is garbage.  In either case, we can throw it away. */

   c = skip_space(fp);
   if (c == '\n') {
      nline = 1;
      goto top;
   }
   else if (c == '#') {
      (void)skip_line(fp);
      nline = 1;
      goto top;
   }
   else if (c == EOF)
      return 0;

   /* Must be a name. */
   bp = e.name;
   /* Use 'd' to prevent argus_strbuffer overflow. */
   d = sizeof(e.name) - 1;
   do {
      *bp++ = c;
      c = getc(fp);
   } while (!isspace(c) && c != EOF && --d > 0);
   *bp = '\0';
   if (c == '\n')
      nline = 1;

   return &e;
}


/*
 * Copyright (c) 1994
 *   The Regents of the University of California.  All rights reserved.
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
 *   This product includes software developed by the Computer Systems
 *   Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
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
 */


#if defined(HAVE_SOLARIS)
#include <sys/sockio.h>
#endif

/* Not all systems have IFF_LOOPBACK */
#ifdef IFF_LOOPBACK
#define ISLOOPBACK(p) ((p)->ifr_flags & IFF_LOOPBACK)
#else
#define ISLOOPBACK(p) (strcmp((p)->ifr_name, "lo0") == 0)
#endif

#if !defined(__OpenBSD__)
#include <net/if.h>
#endif

/*
 * Return the name of a network interface attached to the system, or NULL
 * if none can be found.  The interface must be configured up; the
 * lowest unit number is preferred; loopback is ignored.
 */
char *
ArgusLookupDev(ebuf)
char *ebuf;
{
   int fd, minunit, n;
   char *cp;
   struct ifreq *ifrp, *ifend, *ifnext, *mp;
   struct ifconf ifc;
   struct ifreq ibuf[16], ifr;
   static char device[sizeof(ifrp->ifr_name) + 1];

   fd = socket(AF_INET, SOCK_DGRAM, 0);
   if (fd < 0) {
      (void)snprintf(ebuf, MAXSTRLEN, "socket: %s", argus_strerror(errno));
      return (NULL);
   }
   ifc.ifc_len = sizeof ibuf;
   ifc.ifc_buf = (caddr_t)ibuf;

   if (ioctl(fd, SIOCGIFCONF, (char *)&ifc) < 0 ||
       ifc.ifc_len < sizeof(struct ifreq)) {
      (void)snprintf(ebuf, MAXSTRLEN, "SIOCGIFCONF: %s", argus_strerror(errno));
      (void)close(fd);
      return (NULL);
   }
   ifrp = ibuf;
   ifend = (struct ifreq *)((char *)ibuf + ifc.ifc_len);

   mp = NULL;
   minunit = 666;
   for (; ifrp < ifend; ifrp = ifnext) {
#if BSD - 0 >= 199006
      n = ifrp->ifr_addr.sa_len + sizeof(ifrp->ifr_name);
      if (n < sizeof(*ifrp))
         ifnext = ifrp + 1;
      else
         ifnext = (struct ifreq *)((char *)ifrp + n);
      if (ifrp->ifr_addr.sa_family != AF_INET)
         continue;
#else
      ifnext = ifrp + 1;
#endif
      /*
       * Need a template to preserve address info that is
       * used below to locate the next entry.  (Otherwise,
       * SIOCGIFFLAGS stomps over it because the requests
       * are returned in a union.)
       */
      strncpy(ifr.ifr_name, ifrp->ifr_name, sizeof(ifr.ifr_name));
      if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifr) < 0) {
         (void)snprintf(ebuf, MAXSTRLEN, "SIOCGIFFLAGS: %s",
             argus_strerror(errno));
         (void)close(fd);
         return (NULL);
      }

      /* Must be up and not the loopback */
      if ((ifr.ifr_flags & IFF_UP) == 0 || ISLOOPBACK(&ifr))
         continue;

      for (cp = ifrp->ifr_name; !isdigit((int)*cp); ++cp)
         continue;
      n = atoi(cp);
      if (n < minunit) {
         minunit = n;
         mp = ifrp;
      }
   }
   (void)close(fd);
   if (mp == NULL) {
      (void)strncpy(ebuf, "no suitable device found", MAXSTRLEN);
      return (NULL);
   }

   (void)strncpy(device, mp->ifr_name, sizeof(device) - 1);
   device[sizeof(device) - 1] = '\0';
   return (device);
}

int
ArgusLookupNet(char *device, unsigned int *netp, unsigned int *maskp, char *ebuf)
{
   int fd;
   struct sockaddr_in *sin;
   struct ifreq ifr;

   fd = socket(AF_INET, SOCK_DGRAM, 0);
   if (fd < 0) {
      (void)snprintf(ebuf, MAXSTRLEN, "socket: %s", argus_strerror(errno));
      return (-1);
   }
   (void)strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
   if (ioctl(fd, SIOCGIFADDR, (char *)&ifr) < 0) {
      (void)snprintf(ebuf, MAXSTRLEN, "SIOCGIFADDR: %s: %s",
          device, argus_strerror(errno));
      (void)close(fd);
      return (-1);
   }
   sin = (struct sockaddr_in *)&ifr.ifr_addr;
   *netp = sin->sin_addr.s_addr;
   if (ioctl(fd, SIOCGIFNETMASK, (char *)&ifr) < 0) {
      (void)snprintf(ebuf, MAXSTRLEN, "SIOCGIFNETMASK: %s: %s",
          device, argus_strerror(errno));
      (void)close(fd);
      return (-1);
   }
   (void)close(fd);
   *maskp = sin->sin_addr.s_addr;
   if (*maskp == 0) {
      if (IN_CLASSA(*netp))
         *maskp = IN_CLASSA_NET;
      else if (IN_CLASSB(*netp))
         *maskp = IN_CLASSB_NET;
      else if (IN_CLASSC(*netp))
         *maskp = IN_CLASSC_NET;
      else {
         (void)snprintf(ebuf, MAXSTRLEN, "inet class for 0x%x unknown",
             *netp);
         return (-1);
      }
   }
   *netp &= *maskp;
   return (0);
}

#if defined(ARGUS_SYS_ERRLIST) && defined(HAVE_SOLARIS)
static char ArgusErrorString[128];
#endif

char *
argus_strerror(int errnum)
{
#if defined(ARGUS_SYS_ERRLIST) && defined(HAVE_SOLARIS)
   if ((unsigned int)errnum < sys_nerr)
      return ((char *) sys_errlist[errnum]);

   (void)snprintf(ArgusErrorString, 128, "Unknown error: %d", errnum);
   return (ArgusErrorString);
#else
   return (strerror(errnum));
#endif
}


/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1993, 1994
 *   The Regents of the University of California.  All rights reserved.
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
 *  Optimization module for tcpdump intermediate representation.
 */


#ifdef __osf__
#include <malloc.h>
#endif
#include <memory.h>


#ifdef linux
#include <values.h>
#endif

#define A_ATOM NFF_MEMWORDS
#define X_ATOM (NFF_MEMWORDS+1)

#define NOP -1

/*#define BDEBUG*/
#if defined(BDEBUG)
int dflag = 2;
#endif

/*
 * This define is used to represent *both* the accumulator and
 * x register in use-def computations.
 * Currently, the use-def code assumes only one definition per instruction.
 */
#define AX_ATOM N_ATOMS

/*
 * A flag to indicate that further optimization is needed.
 * Iterative passes are continued until a given pass yields no
 * branch movement.
 */
static int done;

/*
 * A ablock is marked if only if its mark equals the current mark.
 * Rather than traverse the code array, marking each item, 'cur_mark' is
 * incremented.  This automatically makes each element unmarked.
 */
static int cur_mark;
#define isMarked(p) ((p)->mark == cur_mark)
#define unMarkAll() cur_mark += 1
#define Mark(p) ((p)->mark = cur_mark)

static void opt_init(struct ablock *);
static void opt_cleanup(void);

static void make_marks(struct ablock *);
static void mark_code(struct ablock *);

static void intern_blocks(struct ablock *);

static int eq_slist(struct slist *, struct slist *);

static void find_levels_r(struct ablock *);

static void find_levels(struct ablock *);
static void find_dom(struct ablock *);
static void propedom(struct edge *);
static void find_edom(struct ablock *);
static void find_closure(struct ablock *);
static int atomuse(struct stmt *);
static int atomdef(struct stmt *);
static void compute_local_ud(struct ablock *);
static void find_ud(struct ablock *);
static void init_val(void);
static long long F(int, unsigned long long, unsigned long long);
static inline void vstore(struct stmt *, long long *, long long, int);
static void opt_blk(struct ablock *, int);
static int use_conflict(struct ablock *, struct ablock *);
static void opt_j(struct edge *);
static void or_pullup(struct ablock *);
static void and_pullup(struct ablock *);
static void opt_blks(struct ablock *, int);
static inline void link_inedge(struct edge *, struct ablock *);
static void find_inedges(struct ablock *);
static void opt_root(struct ablock **);
static void opt_loop(struct ablock *, int);
static void fold_op(struct stmt *, long long, long long);
static inline struct slist *this_op(struct slist *);
static void opt_not(struct ablock *);
static void opt_peep(struct ablock *);
static void opt_stmt(struct stmt *, long long[], int);
static void deadstmt(struct stmt *, struct stmt *[]);
static void opt_deadstores(struct ablock *);
static void opt_blk(struct ablock *, int);
static int use_conflict(struct ablock *, struct ablock *);
static void opt_j(struct edge *);
static struct ablock *fold_edge(struct ablock *, struct edge *);
static inline int eq_blk(struct ablock *, struct ablock *);
static int slength(struct slist *);
static int count_blocks(struct ablock *);
static void number_blks_r(struct ablock *);
static int count_stmts(struct ablock *);
static int convert_code_r(struct ablock *);
#ifdef BDEBUG
static void opt_dump(struct ablock *);
#endif

static int n_blocks;
struct ablock **blocks;
static int n_edges;
struct edge **edges;

/*
 * A bit vector set representation of the dominators.
 * We round up the set size to the next power of two.
 */
static int nodewords;
static int edgewords;
struct ablock **levels;
nff_u_int32 *space;
#define BITS_PER_WORD (8*sizeof(nff_u_int32))
/*
 * True if a is in uset {p}
 */
#define SET_MEMBER(p, a) \
((p)[(unsigned)(a) / BITS_PER_WORD] & (1 << ((unsigned)(a) % BITS_PER_WORD)))

/*
 * Add 'a' to uset p.
 */
#define SET_INSERT(p, a) \
(p)[(unsigned)(a) / BITS_PER_WORD] |= (1 << ((unsigned)(a) % BITS_PER_WORD))

/*
 * Delete 'a' from uset p.
 */
#define SET_DELETE(p, a) \
(p)[(unsigned)(a) / BITS_PER_WORD] &= ~(1 << ((unsigned)(a) % BITS_PER_WORD))

/*
 * a := a intersect b
 */
#define SET_INTERSECT(a, b, n)\
{\
   register nff_u_int32 *_x = a, *_y = b;\
   register int _n = n;\
   while (--_n >= 0) *_x++ &= *_y++;\
}

/*
 * a := a - b
 */
#define SET_SUBTRACT(a, b, n)\
{\
   register nff_u_int32 *_x = a, *_y = b;\
   register int _n = n;\
   while (--_n >= 0) *_x++ &=~ *_y++;\
}

/*
 * a := a union b
 */
#define SET_UNION(a, b, n)\
{\
   register nff_u_int32 *_x = a, *_y = b;\
   register int _n = n;\
   while (--_n >= 0) *_x++ |= *_y++;\
}

static uset all_dom_sets;
static uset all_closure_sets;
static uset all_edge_sets;

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

static void
find_levels_r(struct ablock *b)
{
   int level;

   if (isMarked(b))
      return;

   Mark(b);
   b->link = 0;

   if (JT(b)) {
      find_levels_r(JT(b));
      find_levels_r(JF(b));
      level = MAX(JT(b)->level, JF(b)->level) + 1;
   } else
      level = 0;
   b->level = level;
   b->link = levels[level];
   levels[level] = b;
}

/*
 * Level graph.  The levels go from 0 at the leaves to
 * N_LEVELS at the root.  The levels[] array points to the
 * first node of the level list, whose elements are linked
 * with the 'link' field of the struct block.
 */
static void
find_levels(struct ablock *root)
{
   memset((char *)levels, 0, n_blocks * sizeof(*levels));
   unMarkAll();
   find_levels_r(root);
}

/*
 * Find dominator relationships.
 * Assumes graph has been leveled.
 */
static void
find_dom(struct ablock *root)
{
   int i;
   struct ablock *b;
   nff_u_int32 *x;

   /*
    * Initialize sets to contain all nodes.
    */
   x = all_dom_sets;
   i = n_blocks * nodewords;
   while (--i >= 0)
      *x++ = ~0;
   /* Root starts off empty. */
   for (i = nodewords; --i >= 0;)
      root->dom[i] = 0;

   /* root->level is the highest level no found. */
   for (i = root->level; i >= 0; --i) {
      for (b = levels[i]; b; b = b->link) {
         SET_INSERT(b->dom, b->id);
         if (JT(b) == 0)
            continue;
         SET_INTERSECT(JT(b)->dom, b->dom, nodewords);
         SET_INTERSECT(JF(b)->dom, b->dom, nodewords);
      }
   }
}

static void
propedom(struct edge *ep)
{
   SET_INSERT(ep->edom, ep->id);
   if (ep->succ) {
      SET_INTERSECT(ep->succ->et.edom, ep->edom, edgewords);
      SET_INTERSECT(ep->succ->ef.edom, ep->edom, edgewords);
   }
}

/*
 * Compute edge dominators.
 * Assumes graph has been leveled and predecessors established.
 */
static void
find_edom(struct ablock *root)
{
   int i;
   uset x;
   struct ablock *b;

   x = all_edge_sets;
   for (i = n_edges * edgewords; --i >= 0; )
      x[i] = ~0;

   /* root->level is the highest level no found. */
   memset(root->et.edom, 0, edgewords * sizeof(*(uset)0));
   memset(root->ef.edom, 0, edgewords * sizeof(*(uset)0));
   for (i = root->level; i >= 0; --i) {
      for (b = levels[i]; b != 0; b = b->link) {
         propedom(&b->et);
         propedom(&b->ef);
      }
   }
}

/*
 * Find the backwards transitive closure of the flow graph.  These sets
 * are backwards in the sense that we find the set of nodes that reach
 * a given node, not the set of nodes that can be reached by a node.
 *
 * Assumes graph has been leveled.
 */
static void
find_closure(struct ablock *root)
{
   int i;
   struct ablock *b;

   /*
    * Initialize sets to contain no nodes.
    */
   memset((char *)all_closure_sets, 0,
         n_blocks * nodewords * sizeof(*all_closure_sets));

   /* root->level is the highest level no found. */
   for (i = root->level; i >= 0; --i) {
      for (b = levels[i]; b; b = b->link) {
         SET_INSERT(b->closure, b->id);
         if (JT(b) == 0)
            continue;
         SET_UNION(JT(b)->closure, b->closure, nodewords);
         SET_UNION(JF(b)->closure, b->closure, nodewords);
      }
   }
}

/*
 * Return the register number that is used by s.  If A and X are both
 * used, return AX_ATOM.  If no register is used, return -1.
 *
 * The implementation should probably change to an array access.
 */
static int
atomuse(struct stmt *s)
{
   register int c = s->code;

   if (c == NOP)
      return -1;

   switch (NFF_CLASS(c)) {

   case NFF_RET:
      return (NFF_RVAL(c) == NFF_A) ? A_ATOM :
         (NFF_RVAL(c) == NFF_X) ? X_ATOM : -1;

   case NFF_LD:
   case NFF_LDX:
      return (NFF_MODE(c) == NFF_IND) ? X_ATOM :
         (NFF_MODE(c) == NFF_MEM) ? s->data.k : -1;

   case NFF_ST:
      return A_ATOM;

   case NFF_STX:
      return X_ATOM;

   case NFF_JMP:
   case NFF_ALU:
      if (NFF_SRC(c) == NFF_X)
         return AX_ATOM;
      return A_ATOM;

   case NFF_MISC:
      return NFF_MISCOP(c) == NFF_TXA ? X_ATOM : A_ATOM;
   }
   abort();
   /* NOTREACHED */
}

/*
 * Return the register number that is defined by 's'.  We assume that
 * a single stmt cannot define more than one register.  If no register
 * is defined, return -1.
 *
 * The implementation should probably change to an array access.
 */
static int
atomdef(struct stmt *s)
{
   if (s->code == NOP)
      return -1;

   switch (NFF_CLASS(s->code)) {

   case NFF_LD:
   case NFF_ALU:
      return A_ATOM;

   case NFF_LDX:
      return X_ATOM;

   case NFF_ST:
   case NFF_STX: {
      int k = s->data.k;
      return k;
   }

   case NFF_MISC:
      return NFF_MISCOP(s->code) == NFF_TAX ? X_ATOM : A_ATOM;
   }
   return -1;
}

static void
compute_local_ud(struct ablock *b)
{
   struct slist *s;
   atomset def = 0, use = 0, kill = 0;
   int atom;

   for (s = b->stmts; s; s = s->next) {
      if (s->s.code == NOP)
         continue;
      atom = atomuse(&s->s);
      if (atom >= 0) {
         if (atom == AX_ATOM) {
            if (!ATOMELEM(def, X_ATOM))
               use |= ATOMMASK(X_ATOM);
            if (!ATOMELEM(def, A_ATOM))
               use |= ATOMMASK(A_ATOM);
         }
         else if (atom < N_ATOMS) {
            if (!ATOMELEM(def, atom))
               use |= ATOMMASK(atom);
         }
         else
            abort();
      }
      atom = atomdef(&s->s);
      if (atom >= 0) {
         if (!ATOMELEM(use, atom))
            kill |= ATOMMASK(atom);
         def |= ATOMMASK(atom);
      }
   }
   if (!ATOMELEM(def, A_ATOM) && NFF_CLASS(b->s.code) == NFF_JMP)
      use |= ATOMMASK(A_ATOM);

   b->def = def;
   b->kill = kill;
   b->in_use = use;
}

/*
 * Assume graph is already leveled.
 */
static void
find_ud(root)
   struct ablock *root;
{
   int i, maxlevel;
   struct ablock *p;

   /*
    * root->level is the highest level no found;
    * count down from there.
    */
   maxlevel = root->level;
   for (i = maxlevel; i >= 0; --i)
      for (p = levels[i]; p; p = p->link) {
         compute_local_ud(p);
         p->out_use = 0;
      }

   for (i = 1; i <= maxlevel; ++i) {
      for (p = levels[i]; p; p = p->link) {
         p->out_use |= JT(p)->in_use | JF(p)->in_use;
         p->in_use |= p->out_use &~ p->kill;
      }
   }
}

/*
 * These data structures are used in a Cocke and Shwarz style
 * value numbering scheme.  Since the flowgraph is acyclic,
 * exit values can be propagated from a node's predecessors
 * provided it is uniquely defined.
 */
struct valnode {
   int code;
   unsigned long long v0, v1;
   unsigned long long val;
   struct valnode *next;
};

#define MODULUS 213
static struct valnode *hashtbl[MODULUS];
static int curval;
static int maxval;

/* Integer constants mapped with the load immediate opcode. */
#define K(i) F(NFF_LD|NFF_IMM, i, 0L)

struct vmapinfo {
   int is_const;
   unsigned long long const_val;
};

struct vmapinfo *vmap;
struct valnode *vnode_base;
struct valnode *next_vnode;

static void
init_val()
{
   curval = 0;
   next_vnode = vnode_base;
   memset((char *)vmap, 0, maxval * sizeof(*vmap));
   memset((char *)hashtbl, 0, sizeof hashtbl);
}

/* Because we really don't have an IR, this stuff is a little messy. */

static long long
F(int code, unsigned long long v0, unsigned long long v1)
{
   u_int hash;
   long long val;
   struct valnode *p;

   hash = (u_int)code ^ (v0 << 4) ^ (v1 << 8);
   hash %= MODULUS;

   for (p = hashtbl[hash]; p; p = p->next)
      if (p->code == code && p->v0 == v0 && p->v1 == v1)
         return p->val;

   val = ++curval;
   if (NFF_MODE(code) == NFF_IMM && (NFF_CLASS(code) == NFF_LD || NFF_CLASS(code) == NFF_LDX)) {
      vmap[val].const_val = v0;
      vmap[val].is_const = 1;
   }
   p = next_vnode++;
   p->val = val;
   p->code = code;
   p->v0 = v0;
   p->v1 = v1;
   p->next = hashtbl[hash];
   hashtbl[hash] = p;

   return val;
}

static inline void
vstore( struct stmt *s, long long *valp, long long newval, int alter)
{
   if (alter && *valp == newval)
      s->code = NOP;
   else
      *valp = newval;
}

static void
fold_op(struct stmt *s, long long v0, long long v1)
{
   long long a, b;

   a = vmap[v0].const_val;
   b = vmap[v1].const_val;

   switch (NFF_OP(s->code)) {
   case NFF_ADD:
      a += b;
      break;

   case NFF_SUB:
      a -= b;
      break;

   case NFF_MUL:
      a *= b;
      break;

   case NFF_DIV:
      if (b == 0)
         ArgusLog(LOG_ERR, "division by zero");
      a /= b;
      break;

   case NFF_AND:
      a &= b;
      break;

   case NFF_OR:
      a |= b;
      break;

   case NFF_LSH:
      a <<= b;
      break;

   case NFF_RSH:
      a >>= b;
      break;

   case NFF_NEG:
      a = -a;
      break;

   default:
      abort();
   }
   s->data.k = a;
   s->code = NFF_LD|NFF_IMM;
   done = 0;
}

static inline struct slist *
this_op(struct slist *s)
{
   while (s != 0 && s->s.code == NOP)
      s = s->next;
   return s;
}

static void
opt_not(struct ablock *b)
{
   struct ablock *tmp = JT(b);

   JT(b) = JF(b);
   JF(b) = tmp;
}

static void
opt_peep(struct ablock *b)
{
   struct slist *s;
   struct slist *next, *last;
   long long val;

   s = b->stmts;
   if (s == 0)
      return;

   last = s;
   while (1) {
      s = this_op(s);
      if (s == 0)
         break;
      next = this_op(s->next);
      if (next == 0)
         break;
      last = next;

      /*
       * st  M[k]   -->   st  M[k]
       * ldx M[k]      tax
       */
      if ((s->s.code == NFF_ST) && (next->s.code == (NFF_LDX|NFF_MEM)) && (s->s.data.k == next->s.data.k)) {
         done = 0;
         next->s.code = NFF_MISC|NFF_TAX;
      }
      /*
       * ld  #k   -->   ldx  #k
       * tax         txa
       */
      if ((s->s.code == (NFF_LD|NFF_IMM)) && (next->s.code == (NFF_MISC|NFF_TAX))) {
         s->s.code = NFF_LDX|NFF_IMM;
         next->s.code = NFF_MISC|NFF_TXA;
         done = 0;
      }
      /*
       * This is an ugly special case, but it happens
       * when you say tcp[k] or udp[k] where k is a constant.
       */
      if (s->s.code == (NFF_LD|NFF_IMM)) {
         struct slist *add, *tax, *ild;

         /*
          * Check that X isn't used on exit from this
          * ablock (which the optimizer might cause).
          * We know the code generator won't generate
          * any local dependencies.
          */
         if (ATOMELEM(b->out_use, X_ATOM))
            break;

         if (next->s.code != (NFF_LDX|NFF_MSH|NFF_B))
            add = next;
         else
            add = this_op(next->next);
         if (add == 0 || add->s.code != (NFF_ALU|NFF_ADD|NFF_X))
            break;

         tax = this_op(add->next);
         if (tax == 0 || tax->s.code != (NFF_MISC|NFF_TAX))
            break;

         ild = this_op(tax->next);
         if (ild == 0 || NFF_CLASS(ild->s.code) != NFF_LD ||
             NFF_MODE(ild->s.code) != NFF_IND)
            break;
         /*
          * XXX We need to check that X is not
          * subsequently used.  We know we can eliminate the
          * accumulator modifications since it is defined
          * by the last stmt of this sequence.
          *
          * We want to turn this sequence:
          *
          * (004) ldi     #0x2      {s}
          * (005) ldxms   [14]      {next}  -- optional
          * (006) addx         {add}
          * (007) tax         {tax}
          * (008) ild     [x+0]      {ild}
          *
          * into this sequence:
          *
          * (004) nop
          * (005) ldxms   [14]
          * (006) nop
          * (007) nop
          * (008) ild     [x+2]
          *
          */
         ild->s.data.k += s->s.data.k;
         s->s.code = NOP;
         add->s.code = NOP;
         tax->s.code = NOP;
         done = 0;
      }
      s = next;
   }
   /*
    * If we have a subtract to do a comparison, and the X register
    * is a known constant, we can merge this value into the
    * comparison.
    */
   if (last->s.code == (NFF_ALU|NFF_SUB|NFF_X) && !ATOMELEM(b->out_use, A_ATOM)) {
      val = b->val[X_ATOM];
      if (vmap[val].is_const) {
         int op;

         b->s.data.k += vmap[val].const_val;
         op = NFF_OP(b->s.code);
         if (op == NFF_JGT || op == NFF_JGE) {
            struct ablock *t = JT(b);
            JT(b) = JF(b);
            JF(b) = t;
            b->s.data.k *= -1;
         }
         last->s.code = NOP;
         done = 0;

      } else if (b->s.data.k == 0) {
         /*
          * sub x  ->   nop
          * j  #0   j  x
          */
         last->s.code = NOP;
         b->s.code = NFF_CLASS(b->s.code) | NFF_OP(b->s.code) |NFF_X;
         done = 0;
      }
   }
   /*
    * Likewise, a constant subtract can be simplified.
    */
   else if (last->s.code == (NFF_ALU|NFF_SUB|NFF_K) &&
       !ATOMELEM(b->out_use, A_ATOM)) {
      int op;

      b->s.data.k += last->s.data.k;
      last->s.code = NOP;
      op = NFF_OP(b->s.code);
      if (op == NFF_JGT || op == NFF_JGE) {
         struct ablock *t = JT(b);
         JT(b) = JF(b);
         JF(b) = t;
         b->s.data.k *= -1;
      }
      done = 0;
   }

   /*
    * and #k   nop
    * jeq #0  ->   jset #k
    */
   if (last->s.code == (NFF_ALU|NFF_AND|NFF_K) &&
       !ATOMELEM(b->out_use, A_ATOM) && b->s.data.k == 0) {
      b->s.data.k = last->s.data.k;
      b->s.code = NFF_JMP|NFF_K|NFF_JSET;
      last->s.code = NOP;
      done = 0;
      opt_not(b);
   }

   /*
    * If the accumulator is a known constant, we can compute the
    * comparison result.
    */
   val = b->val[A_ATOM];
   if (vmap[val].is_const && NFF_SRC(b->s.code) == NFF_K) {
      long long v = vmap[val].const_val;
      switch (NFF_OP(b->s.code)) {

      case NFF_JEQ:
         v = (v == b->s.data.k);
         break;

      case NFF_JGT:
         v = v > b->s.data.k;
         break;

      case NFF_JGE:
         v = v >= b->s.data.k;
         break;

      case NFF_JSET:
         v &= b->s.data.k;
         break;

      default:
         abort();
      }
      if (JF(b) != JT(b))
         done = 0;
      if (v)
         JF(b) = JT(b);
      else
         JT(b) = JF(b);
   }
}

/*
 * Compute the symbolic value of expression of 's', and update
 * anything it defines in the value table 'val'.  If 'alter' is true,
 * do various optimizations.  This code would be cleaner if symbolic
 * evaluation and code transformations weren't folded together.
 */

static void
opt_stmt( struct stmt *s, long long val[], int alter)
{
   int op;
   long long v;

   switch (s->code) {
      case NFF_LD|NFF_DSR|NFF_L:
      case NFF_LD|NFF_ABS|NFF_L:
      case NFF_LD|NFF_DSR|NFF_W:
      case NFF_LD|NFF_ABS|NFF_W:
      case NFF_LD|NFF_DSR|NFF_H:
      case NFF_LD|NFF_ABS|NFF_H:
      case NFF_LD|NFF_DSR|NFF_B:
      case NFF_LD|NFF_ABS|NFF_B:
      case NFF_LD|NFF_DSR|NFF_F:
      case NFF_LD|NFF_ABS|NFF_F:
         v = F(s->code, s->data.k, 0L);
         vstore(s, &val[A_ATOM], v, alter);
         break;

      case NFF_LD|NFF_IND|NFF_L:
      case NFF_LD|NFF_IND|NFF_W:
      case NFF_LD|NFF_IND|NFF_H:
      case NFF_LD|NFF_IND|NFF_B:
      case NFF_LD|NFF_IND|NFF_F:
         v = val[X_ATOM];
         if (alter && vmap[v].is_const) {
            s->code = NFF_LD|NFF_ABS|NFF_SIZE(s->code);
            s->data.k += vmap[v].const_val;
            v = F(s->code, s->data.k, 0L);
            done = 0;
         } else
            v = F(s->code, s->data.k, v);
         vstore(s, &val[A_ATOM], v, alter);
         break;

      case NFF_LD|NFF_LEN:
         v = F(s->code, 0L, 0L);
         vstore(s, &val[A_ATOM], v, alter);
         break;

      case NFF_LD|NFF_IMM:
         v = K(s->data.k);
         vstore(s, &val[A_ATOM], v, alter);
         break;

      case NFF_LDX|NFF_IMM:
         v = K(s->data.k);
         vstore(s, &val[X_ATOM], v, alter);
         break;

      case NFF_LDX|NFF_MSH|NFF_B:
         v = F(s->code, s->data.k, 0L);
         vstore(s, &val[X_ATOM], v, alter);
         break;

      case NFF_ALU|NFF_NEG:
         if (alter && vmap[val[A_ATOM]].is_const) {
            s->code = NFF_LD|NFF_IMM;
            s->data.k = -vmap[val[A_ATOM]].const_val;
            val[A_ATOM] = K(s->data.k);
         }
         else
            val[A_ATOM] = F(s->code, val[A_ATOM], 0L);
         break;

      case NFF_ALU|NFF_ADD|NFF_K:
      case NFF_ALU|NFF_SUB|NFF_K:
      case NFF_ALU|NFF_MUL|NFF_K:
      case NFF_ALU|NFF_DIV|NFF_K:
      case NFF_ALU|NFF_AND|NFF_K:
      case NFF_ALU|NFF_OR|NFF_K:
      case NFF_ALU|NFF_LSH|NFF_K:
      case NFF_ALU|NFF_RSH|NFF_K:
         op = NFF_OP(s->code);
         if (alter) {
            if (s->data.k == 0) {
               /* don't optimize away "sub #0"
                * as it may be needed later to
                * fixup the generated math code */
               if (op == NFF_ADD ||
                   op == NFF_LSH || op == NFF_RSH ||
                   op == NFF_OR) {
                  s->code = NOP;
                  break;
               }
               if (op == NFF_MUL || op == NFF_AND) {
                  s->code = NFF_LD|NFF_IMM;
                  val[A_ATOM] = K(s->data.k);
                  break;
               }
            }
            if (vmap[val[A_ATOM]].is_const) {
               fold_op(s, val[A_ATOM], K(s->data.k));
               val[A_ATOM] = K(s->data.k);
               break;
            }
         }
         val[A_ATOM] = F(s->code, val[A_ATOM], K(s->data.k));
         break;

      case NFF_ALU|NFF_ADD|NFF_X:
      case NFF_ALU|NFF_SUB|NFF_X:
      case NFF_ALU|NFF_MUL|NFF_X:
      case NFF_ALU|NFF_DIV|NFF_X:
      case NFF_ALU|NFF_AND|NFF_X:
      case NFF_ALU|NFF_OR|NFF_X:
      case NFF_ALU|NFF_LSH|NFF_X:
      case NFF_ALU|NFF_RSH|NFF_X:
         op = NFF_OP(s->code);
         if (alter && vmap[val[X_ATOM]].is_const) {
            if (vmap[val[A_ATOM]].is_const) {
               fold_op(s, val[A_ATOM], val[X_ATOM]);
               val[A_ATOM] = K(s->data.k);
            }
            else {
               s->code = NFF_ALU|NFF_K|op;
               s->data.k = vmap[val[X_ATOM]].const_val;
               done = 0;
               val[A_ATOM] =
                  F(s->code, val[A_ATOM], K(s->data.k));
            }
            break;
         }
         /*
          * Check if we're doing something to an accumulator
          * that is 0, and simplify.  This may not seem like
          * much of a simplification but it could open up further
          * optimizations.
          * XXX We could also check for mul by 1, and -1, etc.
          */
         if (alter && vmap[val[A_ATOM]].is_const
             && vmap[val[A_ATOM]].const_val == 0) {
            if (op == NFF_ADD || op == NFF_OR ||
                op == NFF_LSH || op == NFF_RSH || op == NFF_SUB) {
               s->code = NFF_MISC|NFF_TXA;
               vstore(s, &val[A_ATOM], val[X_ATOM], alter);
               break;
            }
            else if (op == NFF_MUL || op == NFF_DIV ||
                op == NFF_AND) {
               s->code = NFF_LD|NFF_IMM;
               s->data.k = 0;
               vstore(s, &val[A_ATOM], K(s->data.k), alter);
               break;
            }
            else if (op == NFF_NEG) {
               s->code = NOP;
               break;
            }
         }
         val[A_ATOM] = F(s->code, val[A_ATOM], val[X_ATOM]);
         break;

      case NFF_MISC|NFF_TXA:
         vstore(s, &val[A_ATOM], val[X_ATOM], alter);
         break;

      case NFF_LD|NFF_MEM:
         v = val[s->data.k];
         if (alter && vmap[v].is_const) {
            s->code = NFF_LD|NFF_IMM;
            s->data.k = vmap[v].const_val;
            done = 0;
         }
         vstore(s, &val[A_ATOM], v, alter);
         break;

      case NFF_MISC|NFF_TAX:
         vstore(s, &val[X_ATOM], val[A_ATOM], alter);
         break;

      case NFF_LDX|NFF_MEM:
         v = val[s->data.k];
         if (alter && vmap[v].is_const) {
            s->code = NFF_LDX|NFF_IMM;
            s->data.k = vmap[v].const_val;
            done = 0;
         }
         vstore(s, &val[X_ATOM], v, alter);
         break;

      case NFF_ST:
         vstore(s, &val[s->data.k], val[A_ATOM], alter);
         break;

      case NFF_STX:
         vstore(s, &val[s->data.k], val[X_ATOM], alter);
         break;

      case NOP:
         break;

      default:
         ArgusLog(LOG_ERR, "opt_stmt: statement not in list");
         break;
   }
}

static void
deadstmt(struct stmt *s, struct stmt *last[])
{
   register int atom;

   atom = atomuse(s);
   if (atom >= 0) {
      if (atom == AX_ATOM) {
         last[X_ATOM] = 0;
         last[A_ATOM] = 0;
      }
      else
         last[atom] = 0;
   }
   atom = atomdef(s);
   if (atom >= 0) {
      if (last[atom]) {
         done = 0;
         last[atom]->code = NOP;
      }
      last[atom] = s;
   }
}

static void
opt_deadstores(struct ablock *b)
{
   register struct slist *s;
   register int atom;
   struct stmt *last[N_ATOMS];

   memset((char *)last, 0, sizeof last);

   for (s = b->stmts; s != 0; s = s->next)
      deadstmt(&s->s, last);
   deadstmt(&b->s, last);

   for (atom = 0; atom < N_ATOMS; ++atom)
      if (last[atom] && !ATOMELEM(b->out_use, atom)) {
         last[atom]->code = NOP;
         done = 0;
      }
}

static void
opt_blk( struct ablock *b, int do_stmts)
{
   long long aval;
   struct slist *s;
   struct edge *p;
   int i;

#if 0
   for (s = b->stmts; s && s->next; s = s->next)
      if (NFF_CLASS(s->s.code) == NFF_JMP) {
         do_stmts = 0;
         break;
      }
#endif

   /*
    * Initialize the atom values.
    * If we have no predecessors, everything is undefined.
    * Otherwise, we inherent our values from our predecessors.
    * If any register has an ambiguous value (i.e. control paths are
    * merging) give it the undefined value of 0.
    */

   p = b->in_edges;
   if (p == 0)
      memset((char *)b->val, 0, sizeof(b->val));
   else {
      memcpy((char *)b->val, (char *)p->pred->val, sizeof(b->val));
      while ((p = p->next) != NULL) {
         for (i = 0; i < N_ATOMS; ++i)
            if (b->val[i] != p->pred->val[i])
               b->val[i] = 0;
      }
   }
   aval = b->val[A_ATOM];
   for (s = b->stmts; s; s = s->next)
      opt_stmt(&s->s, b->val, do_stmts);

   /*
    * This is a special case: if we don't use anything from this
    * block, and we load the accumulator with value that is
    * already there, or if this ablock is a return,
    * eliminate all the statements.
    */
   if (do_stmts && 
       ((b->out_use == 0 && aval != 0 &&b->val[A_ATOM] == aval) ||
        NFF_CLASS(b->s.code) == NFF_RET)) {
      if (b->stmts != 0) {
         b->stmts = 0;
         done = 0;
      }
   } else {
      opt_peep(b);
      opt_deadstores(b);
   }
   /*
    * Set up values for branch optimizer.
    */
   if (NFF_SRC(b->s.code) == NFF_K)
      b->oval = K(b->s.data.k);
   else
      b->oval = b->val[X_ATOM];
   b->et.code = b->s.code;
   b->ef.code = -b->s.code;
}

/*
 * Return true if any register that is used on exit from 'succ', has
 * an exit value that is different from the corresponding exit value
 * from 'b'.
 */
static int
use_conflict(struct ablock *b, struct ablock *succ)
{
   int atom;
   atomset use = succ->out_use;

   if (use == 0)
      return 0;

   for (atom = 0; atom < N_ATOMS; ++atom)
      if (ATOMELEM(use, atom))
         if (b->val[atom] != succ->val[atom])
            return 1;
   return 0;
}

static struct ablock *
fold_edge(struct ablock *child, struct edge *ep)
{
   int sense;
   int code = ep->code;
   long long aval0, aval1, oval0, oval1;

   if (code < 0) {
      code = -code;
      sense = 0;
   } else
      sense = 1;

   if (child->s.code != code)
      return 0;

   aval0 = child->val[A_ATOM];
   oval0 = child->oval;
   aval1 = ep->pred->val[A_ATOM];
   oval1 = ep->pred->oval;

   if (aval0 != aval1)
      return 0;

   if (oval0 == oval1)
      /*
       * The operands are identical, so the
       * result is true if a true branch was
       * taken to get here, otherwise false.
       */
      return sense ? JT(child) : JF(child);

   if (sense && code == (NFF_JMP|NFF_JEQ|NFF_K))
      /*
       * At this point, we only know the comparison if we
       * came down the true branch, and it was an equality
       * comparison with a constant.  We rely on the fact that
       * distinct constants have distinct value numbers.
       */
      return JF(child);

   return 0;
}

static void
opt_j(struct edge *ep)
{
   register int i, k;
   register struct ablock *target = NULL;

   if (JT(ep->succ) == 0)
      return;

   if (JT(ep->succ) == JF(ep->succ)) {
      /*
       * Common branch targets can be eliminated, provided
       * there is no data dependency.
       */
      if (!use_conflict(ep->pred, ep->succ->et.succ)) {
         done = 0;
         ep->succ = JT(ep->succ);
      }
   }
   /*
    * For each edge dominator that matches the successor of this
    * edge, promote the edge successor to the its grandchild.
    *
    * XXX We violate the set abstraction here in favor a reasonably
    * efficient loop.
    */
 top:
   for (i = 0; i < edgewords; ++i) {
      register nff_u_int32 x = ep->edom[i];

      while (x != 0) {
         k = ffs(x) - 1;
         x &=~ (1 << k);
         k += i * BITS_PER_WORD;

         target = fold_edge(ep->succ, edges[k]);

         /*
          * Check that there is no data dependency between
          * nodes that will be violated if we move the edge.
          */

         if (target != 0 && !use_conflict(ep->pred, target)) {
            done = 0;
            ep->succ = target;
            if (JT(target) != 0)
               /*
                * Start over unless we hit a leaf.
                */
               goto top;
            return;
         }
      }
   }
}


static void
or_pullup(struct ablock *b)
{
   long long val;
   int at_top;
   struct ablock *pull;
   struct ablock **diffp, **samep;
   struct edge *ep;

   ep = b->in_edges;
   if (ep == 0)
      return;

   /*
    * Make sure each predecessor loads the same value.
    * XXX why?
    */
   val = ep->pred->val[A_ATOM];
   for (ep = ep->next; ep != 0; ep = ep->next)
      if (val != ep->pred->val[A_ATOM])
         return;

   if (JT(b->in_edges->pred) == b)
      diffp = &JT(b->in_edges->pred);
   else
      diffp = &JF(b->in_edges->pred);

   at_top = 1;
   while (1) {
      if (*diffp == 0)
         return;

      if (JT(*diffp) != JT(b))
         return;

      if (!SET_MEMBER((*diffp)->dom, b->id))
         return;

      if ((*diffp)->val[A_ATOM] != val)
         break;

      diffp = &JF(*diffp);
      at_top = 0;
   }
   samep = &JF(*diffp);
   while (1) {
      if (*samep == 0)
         return;

      if (JT(*samep) != JT(b))
         return;

      if (!SET_MEMBER((*samep)->dom, b->id))
         return;

      if ((*samep)->val[A_ATOM] == val)
         break;

      /* XXX Need to check that there are no data dependencies
         between dp0 and dp1.  Currently, the code generator
         will not produce such dependencies. */
      samep = &JF(*samep);
   }
#ifdef notdef
   /* XXX This doesn't cover everything. */
   for (i = 0; i < N_ATOMS; ++i)
      if ((*samep)->val[i] != pred->val[i])
         return;
#endif
   /* Pull up the node. */
   pull = *samep;
   *samep = JF(pull);
   JF(pull) = *diffp;

   /*
    * At the top of the chain, each predecessor needs to point at the
    * pulled up node.  Inside the chain, there is only one predecessor
    * to worry about.
    */
   if (at_top) {
      for (ep = b->in_edges; ep != 0; ep = ep->next) {
         if (JT(ep->pred) == b)
            JT(ep->pred) = pull;
         else
            JF(ep->pred) = pull;
      }
   }
   else
      *diffp = pull;

   done = 0;
}

static void
and_pullup(struct ablock *b)
{
   long long val;
   int at_top;
   struct ablock *pull;
   struct ablock **diffp, **samep;
   struct edge *ep;

   ep = b->in_edges;
   if (ep == 0)
      return;

   /*
    * Make sure each predecessor loads the same value.
    */
   val = ep->pred->val[A_ATOM];
   for (ep = ep->next; ep != 0; ep = ep->next)
      if (val != ep->pred->val[A_ATOM])
         return;

   if (JT(b->in_edges->pred) == b)
      diffp = &JT(b->in_edges->pred);
   else
      diffp = &JF(b->in_edges->pred);

   at_top = 1;
   while (1) {
      if (*diffp == 0)
         return;

      if (JF(*diffp) != JF(b))
         return;

      if (!SET_MEMBER((*diffp)->dom, b->id))
         return;

      if ((*diffp)->val[A_ATOM] != val)
         break;

      diffp = &JT(*diffp);
      at_top = 0;
   }
   samep = &JT(*diffp);
   while (1) {
      if (*samep == 0)
         return;

      if (JF(*samep) != JF(b))
         return;

      if (!SET_MEMBER((*samep)->dom, b->id))
         return;

      if ((*samep)->val[A_ATOM] == val)
         break;

      /* XXX Need to check that there are no data dependencies
         between diffp and samep.  Currently, the code generator
         will not produce such dependencies. */
      samep = &JT(*samep);
   }
#ifdef notdef
   /* XXX This doesn't cover everything. */
   for (i = 0; i < N_ATOMS; ++i)
      if ((*samep)->val[i] != pred->val[i])
         return;
#endif
   /* Pull up the node. */
   pull = *samep;
   *samep = JT(pull);
   JT(pull) = *diffp;

   /*
    * At the top of the chain, each predecessor needs to point at the
    * pulled up node.  Inside the chain, there is only one predecessor
    * to worry about.
    */
   if (at_top) {
      for (ep = b->in_edges; ep != 0; ep = ep->next) {
         if (JT(ep->pred) == b)
            JT(ep->pred) = pull;
         else
            JF(ep->pred) = pull;
      }
   }
   else
      *diffp = pull;

   done = 0;
}

static void
opt_blks( struct ablock *root, int do_stmts)
{
   int i, maxlevel;
   struct ablock *p;

   init_val();
   maxlevel = root->level;

   find_inedges(root);
   for (i = maxlevel; i >= 0; --i)
      for (p = levels[i]; p; p = p->link)
         opt_blk(p, do_stmts);

   if (do_stmts)
      /*
       * No point trying to move branches; it can't possibly
       * make a difference at this point.
       */
      return;

   for (i = 1; i <= maxlevel; ++i) {
      for (p = levels[i]; p; p = p->link) {
         opt_j(&p->et);
         opt_j(&p->ef);
      }
   }

   find_inedges(root);
   for (i = 1; i <= maxlevel; ++i) {
      for (p = levels[i]; p; p = p->link) {
         or_pullup(p);
         and_pullup(p);
      }
   }
}

static inline void
link_inedge(struct edge *parent, struct ablock *child)
{
   parent->next = child->in_edges;
   child->in_edges = parent;
}

static void
find_inedges(struct ablock *root)
{
   int i;
   struct ablock *b;

   for (i = 0; i < n_blocks; ++i)
      blocks[i]->in_edges = 0;

   /*
    * Traverse the graph, adding each edge to the predecessor
    * list of its successors.  Skip the leaves (i.e. level 0).
    */
   for (i = root->level; i > 0; --i) {
      for (b = levels[i]; b != 0; b = b->link) {
         link_inedge(&b->et, JT(b));
         link_inedge(&b->ef, JF(b));
      }
   }
}

static void
opt_root(struct ablock **b)
{
   struct slist *tmp, *s;

   s = (*b)->stmts;
   (*b)->stmts = 0;
   while (NFF_CLASS((*b)->s.code) == NFF_JMP && JT(*b) == JF(*b))
      *b = JT(*b);

   tmp = (*b)->stmts;
   if (tmp != 0)
      Argussappend(s, tmp);
   (*b)->stmts = s;

   /*
    * If the root node is a return, then there is no
    * point executing any statements (since the nff machine
    * has no side effects).
    */
   if (NFF_CLASS((*b)->s.code) == NFF_RET)
      (*b)->stmts = 0;
}

static void
opt_loop(struct ablock *root, int do_stmts)
{

#ifdef BDEBUG
   if (dflag > 1) {
      printf("opt_loop(root, %d) begin\n", do_stmts);
      opt_dump(root);
   }
#endif
   do {
      done = 1;
      find_levels(root);
      find_dom(root);
      find_closure(root);
      find_ud(root);
      find_edom(root);
      opt_blks(root, do_stmts);
#ifdef BDEBUG
      if (dflag > 1) {
         printf("opt_loop(root, %d) bottom, done=%d\n", do_stmts, done);
         opt_dump(root);
      }
#endif
   } while (!done);
}

/*
 * Optimize the filter code in its dag representation.
 */
void
Argusnff_optimize(struct ablock **rootp)
{
   struct ablock *root;

   root = *rootp;

   opt_init(root);
   opt_loop(root, 0);
   opt_loop(root, 1);
   intern_blocks(root);
#ifdef BDEBUG
   if (dflag > 1) {
      printf("after intern_blocks()\n");
      opt_dump(root);
   }
#endif
   opt_root(rootp);
#ifdef BDEBUG
   if (dflag > 1) {
      printf("after opt_root()\n");
      opt_dump(root);
   }
#endif
   opt_cleanup();

#ifdef ARGUSDEBUG
   ArgusDebug (6, "Argusnff_optimize (0x%x)", rootp);
#endif
}

static void
make_marks(struct ablock *p)
{
   if (!isMarked(p)) {
      Mark(p);
      if (NFF_CLASS(p->s.code) != NFF_RET) {
         make_marks(JT(p));
         make_marks(JF(p));
      }
   }
}

/*
 * Mark code array such that isMarked(i) is true
 * only for nodes that are alive.
 */
static void
mark_code(struct ablock *p)
{
   cur_mark += 1;
   make_marks(p);
}

/*
 * True iff the two stmt lists load the same value from the packet into
 * the accumulator.
 */
static int
eq_slist(struct slist *x, struct slist *y)
{
   while (1) {
      while (x && x->s.code == NOP)
         x = x->next;
      while (y && y->s.code == NOP)
         y = y->next;
      if (x == 0)
         return y == 0;
      if (y == 0)
         return x == 0;
      if (x->s.code != y->s.code || x->s.data.k != y->s.data.k)
         return 0;
      x = x->next;
      y = y->next;
   }
}

static inline int
eq_blk(struct ablock *b0, struct ablock *b1)
{
   if (b0->s.code == b1->s.code &&
       b0->s.dsr == b1->s.dsr &&
       b0->s.data.k == b1->s.data.k &&
       b0->et.succ == b1->et.succ &&
       b0->ef.succ == b1->ef.succ)
      return eq_slist(b0->stmts, b1->stmts);
   return 0;
}

static void
intern_blocks(struct ablock *root)
{
   struct ablock *p;
   int i, j;
   int done;
 top:
   done = 1;
   for (i = 0; i < n_blocks; ++i)
      blocks[i]->link = 0;

   mark_code(root);

   for (i = n_blocks - 1; --i >= 0; ) {
      if (!isMarked(blocks[i]))
         continue;
      for (j = i + 1; j < n_blocks; ++j) {
         if (!isMarked(blocks[j]))
            continue;
         if (eq_blk(blocks[i], blocks[j])) {
            blocks[i]->link = blocks[j]->link ?
               blocks[j]->link : blocks[j];
            break;
         }
      }
   }
   for (i = 0; i < n_blocks; ++i) {
      p = blocks[i];
      if (JT(p) == 0)
         continue;
      if (JT(p)->link) {
         done = 0;
         JT(p) = JT(p)->link;
      }
      if (JF(p)->link) {
         done = 0;
         JF(p) = JF(p)->link;
      }
   }
   if (!done)
      goto top;
}

static void
opt_cleanup()
{
   free((void *)vnode_base);
   free((void *)vmap);
   free((void *)edges);
   free((void *)space);
   free((void *)levels);
   free((void *)blocks);
}

/*
 * Return the number of stmts in 's'.
 */
static int
slength(struct slist *s)
{
   int n = 0;

   for (; s; s = s->next)
      if (s->s.code != NOP)
         ++n;
   return n;
}

/*
 * Return the number of nodes reachable by 'p'.
 * All nodes should be initially unmarked.
 */
static int
count_blocks(struct ablock *p)
{
   if (p == 0 || isMarked(p))
      return 0;
   Mark(p);
   return count_blocks(JT(p)) + count_blocks(JF(p)) + 1;
}

/*
 * Do a depth first search on the flow graph, numbering the
 * the basic blocks, and entering them into the 'blocks' array.`
 */
static void
number_blks_r(struct ablock *p)
{
   int n;

   if (p == 0 || isMarked(p))
      return;

   Mark(p);
   n = n_blocks++;
   p->id = n;
   blocks[n] = p;

   number_blks_r(JT(p));
   number_blks_r(JF(p));
}

/*
 * Return the number of stmts in the flowgraph reachable by 'p'.
 * The nodes should be unmarked before calling.
 *
 * Note that "stmts" means "instructions", and that this includes
 *
 *   side-effect statements in 'p' (slength(p->stmts));
 *
 *   statements in the true branch from 'p' (count_stmts(JT(p)));
 *
 *   statements in the false branch from 'p' (count_stmts(JF(p)));
 *
 *   the conditional jump itself (1);
 *
 *   an extra long jump if the true branch requires it (p->longjt);
 *
 *   an extra long jump if the false branch requires it (p->longjf).
 */
static int
count_stmts(struct ablock *p)
{
   int n;

   if (p == 0 || isMarked(p))
      return 0;
   Mark(p);
   n = count_stmts(JT(p)) + count_stmts(JF(p));
   return slength(p->stmts) + n + 1 + p->longjt + p->longjf;
}

/*
 * Allocate memory.  All allocation is done before optimization
 * is begun.  A linear bound on the size of all data structures is computed
 * from the total number of blocks and/or statements.
 */
static void
opt_init(struct ablock *root)
{
   nff_u_int32 *p;
   int i, n, max_stmts;

   /*
    * First, count the blocks, so we can malloc an array to map
    * ablock number to block.  Then, put the blocks into the array.
    */
   unMarkAll();
   n = count_blocks(root);
   blocks = (struct ablock **)malloc(n * sizeof(*blocks));
   unMarkAll();
   n_blocks = 0;
   number_blks_r(root);

   n_edges = 2 * n_blocks;
   edges = (struct edge **)malloc(n_edges * sizeof(*edges));

   /*
    * The number of levels is bounded by the number of nodes.
    */
   levels = (struct ablock **)malloc(n_blocks * sizeof(*levels));

   edgewords = n_edges / (8 * sizeof(nff_u_int32)) + 1;
   nodewords = n_blocks / (8 * sizeof(nff_u_int32)) + 1;

   /* XXX */
   space = (nff_u_int32 *)malloc(2 * n_blocks * nodewords * sizeof(*space)
             + n_edges * edgewords * sizeof(*space));
   p = space;
   all_dom_sets = p;
   for (i = 0; i < n; ++i) {
      blocks[i]->dom = p;
      p += nodewords;
   }
   all_closure_sets = p;
   for (i = 0; i < n; ++i) {
      blocks[i]->closure = p;
      p += nodewords;
   }
   all_edge_sets = p;
   for (i = 0; i < n; ++i) {
      register struct ablock *b = blocks[i];

      b->et.edom = p;
      p += edgewords;
      b->ef.edom = p;
      p += edgewords;
      b->et.id = i;

      edges[i] = &b->et;

      b->ef.id = n_blocks + i;

      edges[n_blocks + i] = &b->ef;

      b->et.pred = b;
      b->ef.pred = b;
   }

   max_stmts = 0;
   for (i = 0; i < n; ++i)
      max_stmts += slength(blocks[i]->stmts) + 1;
   /*
    * We allocate at most 3 value numbers per statement,
    * so this is an upper bound on the number of valnodes
    * we'll need.
    */
   maxval = 3 * max_stmts;
   vmap = (struct vmapinfo *)malloc(maxval * sizeof(*vmap));
   vnode_base = (struct valnode *)malloc(maxval * sizeof(*vnode_base));
}

/*
 * Some pointers used to convert the basic ablock form of the code,
 * into the array form that NFF requires.  'fstart' will point to
 * the malloc'd array while 'ftail' is used during the recursive traversal.
 */
static struct nff_insn *fstart;
static struct nff_insn *ftail;

#ifdef BDEBUG
int bids[1000];
#endif

/*
 * Returns true if successful.  Returns false if a branch has
 * an offset that is too large.  If so, we have marked that
 * branch so that on a subsequent iteration, it will be treated
 * properly.
 */
static int
convert_code_r(struct ablock *p)
{
   struct nff_insn *dst;
   struct slist *src;
   int slen;
   u_int off;
   int extrajmps;      /* number of extra jumps inserted */
   struct slist **offset = NULL;

   if (p == 0 || isMarked(p))
      return (1);
   Mark(p);

   if (convert_code_r(JF(p)) == 0)
      return (0);
   if (convert_code_r(JT(p)) == 0)
      return (0);

   slen = slength(p->stmts);
   dst = ftail -= (slen + 1 + p->longjt + p->longjf);
      /* inflate length by any extra jumps */

   p->offset = dst - fstart;

   /* generate offset[] for convenience  */
   if (slen) {
      offset = (struct slist **)calloc(sizeof(struct slist *), slen);
      if (!offset) {
         ArgusLog(LOG_ERR, "not enough core");
         /*NOTREACHED*/
      }
   }
   src = p->stmts;
   for (off = 0; off < slen && src; off++) {
#if 0
      printf("off=%d src=%x\n", off, src);
#endif
      offset[off] = src;
      src = src->next;
   }

   off = 0;
   for (src = p->stmts; src; src = src->next) {
      if (src->s.code == NOP)
         continue;
      dst->dsr = src->s.dsr;
      dst->code = (u_short)src->s.code;
      dst->type = src->s.type;
      dst->data.k = src->s.data.k;

      /* fill block-local relative jump */
      if (NFF_CLASS(src->s.code) != NFF_JMP || src->s.code == (NFF_JMP|NFF_JA)) {
#if 0
         if (src->s.jt || src->s.jf) {
            ArgusLog(LOG_ERR, "illegal jmp destination");
            /*NOTREACHED*/
         }
#endif
         goto filled;
      }
      if (off == slen - 2)   /*???*/
         goto filled;

       {
      int i;
      int jt, jf;
      char *ljerr = "%s for block-local relative jump: off=%d";

#if 0
      printf("code=%x off=%d %x %x\n", src->s.code,
         off, src->s.jt, src->s.jf);
#endif

      if (!src->s.jt || !src->s.jf) {
         ArgusLog(LOG_ERR, "no jmp destination %d, %d", ljerr, off);
         /*NOTREACHED*/
      }

      jt = jf = 0;
      for (i = 0; i < slen; i++) {
         if (offset[i] == src->s.jt) {
            if (jt) {
               ArgusLog(LOG_ERR, "multiple matches %d, %d", ljerr, off);
               /*NOTREACHED*/
            }

            dst->jt = i - off - 1;
            jt++;
         }
         if (offset[i] == src->s.jf) {
            if (jf) {
               ArgusLog(LOG_ERR, "multiple matches %d, %d", ljerr, off);
               /*NOTREACHED*/
            }
            dst->jf = i - off - 1;
            jf++;
         }
      }
      if (!jt || !jf) {
         ArgusLog(LOG_ERR, "no destination found %d, %d", ljerr, off);
         /*NOTREACHED*/
      }
       }
filled:
      ++dst;
      ++off;
   }
   if (offset)
      free(offset);

#ifdef BDEBUG
   bids[dst - fstart] = p->id + 1;
#endif
   dst->dsr = p->s.dsr;
   dst->code = (u_short)p->s.code;
   dst->type = p->s.type;
   dst->data.k = p->s.data.k;
   if (JT(p)) {
      extrajmps = 0;
      off = JT(p)->offset - (p->offset + slen) - 1;
      if (off >= 256) {
          /* offset too large for branch, must add a jump */
          if (p->longjt == 0) {
             /* mark this instruction and retry */
         p->longjt++;
         return(0);
          }
          /* branch if T to following jump */
          dst->jt = extrajmps;
          extrajmps++;
          dst[extrajmps].code = NFF_JMP|NFF_JA;
          dst[extrajmps].type = dst->type;
          dst[extrajmps].data.k = off - extrajmps;
      }
      else
          dst->jt = off;
      off = JF(p)->offset - (p->offset + slen) - 1;
      if (off >= 256) {
          /* offset too large for branch, must add a jump */
          if (p->longjf == 0) {
             /* mark this instruction and retry */
         p->longjf++;
         return(0);
          }
          /* branch if F to following jump */
          /* if two jumps are inserted, F goes to second one */
          dst->jf = extrajmps;
          extrajmps++;
          dst[extrajmps].code = NFF_JMP|NFF_JA;
          dst[extrajmps].type = dst->type;
          dst[extrajmps].data.k = off - extrajmps;
      }
      else
          dst->jf = off;
   }
   return (1);
}


/*
 * Convert flowgraph intermediate representation to the
 * NFF array representation.  Set *lenp to the number of instructions.
 */
struct nff_insn *
Argusicode_to_fcode(struct ablock *root, int *lenp)
{
   int n;
   struct nff_insn *fp;

   /*
    * Loop doing convert_code_r() until no branches remain
    * with too-large offsets.
    */
   while (1) {
      unMarkAll();
      n = *lenp = count_stmts(root);
    
      fp = (struct nff_insn *)malloc(sizeof(*fp) * n);
      memset((char *)fp, 0, sizeof(*fp) * n);
      fstart = fp;
      ftail = fp + n;
    
      unMarkAll();
      if (convert_code_r(root))
         break;
      free(fp);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "Argusicode_to_fcode () returning 0x%x", fp);
#endif

   return fp;
}



#ifdef BDEBUG
static void
opt_dump(struct ablock *root)
{
   struct nff_program f;
   char buf[MAXSTRLEN];

   memset(bids, 0, sizeof bids);
   f.bf_insns = Argusicode_to_fcode(root, &f.bf_len);
   nff_dump(&f, buf, MAXSTRLEN, 1);
   printf("%s\n", buf);
   free((char *)f.bf_insns);
}
#endif


extern void nff_dump(struct nff_program *, char *, int, int);
static char *nff_image(struct nff_insn *p, int n);

void
nff_dump(struct nff_program *p, char *buf, int buflen, int option)
{
   struct nff_insn *insn;
   int i, slen;
   int n = p->bf_len;

   insn = p->bf_insns;
   if (option > 2) {
      slen = strlen(buf);
      snprintf(&buf[slen], buflen - slen, "%d\n", n);
      for (i = 0; i < n; ++insn, ++i) {
         slen = strlen(buf);
         snprintf(&buf[slen], buflen - slen, "%lu %lu %lu %llu\n", (long)insn->code,
                (long)insn->jt, (long)insn->jf, insn->data.k);
      }
      return ;
   }
   if (option > 1) {
      for (i = 0; i < n; ++insn, ++i)
         slen = strlen(buf);
         snprintf(&buf[slen], buflen - slen, "{ 0x%x, %d, %d, 0x%08llx },\n",
                insn->code, insn->jt, insn->jf, insn->data.k);
      return;
   }
   for (i = 0; i < n; ++insn, ++i) {
      slen = strlen(buf);
#ifdef BDEBUG
      extern int bids[];
      snprintf(&buf[slen], buflen - slen, bids[i] > 0 ? "[%02d]" : " -- ", bids[i] - 1);
#endif
      snprintf(&buf[slen], buflen - slen, "%s\n", nff_image(insn, i));
   }
}

/*
 * Copyright (c) 1990, 1991, 1992, 1994
 *   The Regents of the University of California.  All rights reserved.
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


static char *nff_image(struct nff_insn *, int);

static char *
nff_image(struct nff_insn *p, int n)
{
   int v, dsr;
   static char image[256];
   char operand[64], op[32];
   char *fmt, *s;
   float f;

   dsr = p->dsr;
     v = p->data.k;
     f = p->data.f;
     s = p->data.s;

   switch (p->code) {

   default:
      sprintf(op, "unimp");
      fmt = "0x%x";
      v = p->code;
      break;

   case NFF_RET|NFF_K:
      sprintf(op, "ret");
      fmt = " #%d";
      break;

   case NFF_RET|NFF_A:
      sprintf(op, "ret");
      fmt = " ";
      break;

   case NFF_LD|NFF_F|NFF_DSR:
      if (dsr < 0)
         sprintf(op, "ldf      hdr");
      else
         sprintf(op, "ldf      dsr[%d]", dsr);
      fmt = "[%d]";
      break;

   case NFF_LD|NFF_F|NFF_ABS:
      sprintf(op, "ldf");
      fmt = "[%d]";
      break;

   case NFF_LD|NFF_L|NFF_DSR:
      if (dsr < 0)
         sprintf(op, "ldll     hdr");
      else
      sprintf(op, "ldll      dsr[%d]", dsr);
      fmt = "[%Ld]";
      break;

   case NFF_LD|NFF_L|NFF_ABS:
      sprintf(op, "ldll");
      fmt = "[%Ld]";
      break;

   case NFF_LD|NFF_W|NFF_DSR:
      if (dsr < 0)
         sprintf(op, "ld       hdr");
      else
         sprintf(op, "ld       dsr[%d]", dsr);
      fmt = "[%d]";
      break;

   case NFF_LD|NFF_W|NFF_ABS:
      sprintf(op, "ld");
      fmt = "[%d]";
      break;

   case NFF_LD|NFF_H|NFF_DSR:
      if (dsr < 0)
         sprintf(op, "ldh      hdr");
      else
         sprintf(op, "ldh      dsr[%d]", dsr);
      fmt = "[%d]";
      break;

   case NFF_LD|NFF_H|NFF_ABS:
      sprintf(op, "ldh");
      fmt = "[%d]";
      break;

   case NFF_LD|NFF_B|NFF_DSR:
      if (dsr < 0)
         sprintf(op, "ldb      hdr");
      else
         sprintf(op, "ldb      dsr[%d]", dsr);
      fmt = "[%d]";
      break;

   case NFF_LD|NFF_B|NFF_ABS:
      sprintf(op, "ldb");
      fmt = "[%d]";
      break;

   case NFF_LD|NFF_W|NFF_LEN:
      sprintf(op, "ld");
      fmt = "#pktlen";
      break;

   case NFF_LD|NFF_F|NFF_IND:
      sprintf(op, "ldf");
      fmt = "[x + %d]";
      break;

   case NFF_LD|NFF_L|NFF_IND:
      sprintf(op, "ldll");
      fmt = "[x + %Ld]";
      break;

   case NFF_LD|NFF_W|NFF_IND:
      sprintf(op, "ld");
      fmt = "[x + %d]";
      break;

   case NFF_LD|NFF_H|NFF_IND:
      sprintf(op, "ldh");
      fmt = "[x + %d]";
      break;

   case NFF_LD|NFF_B|NFF_IND:
      sprintf(op, "ldb");
      fmt = "[x + %d]";
      break;

   case NFF_LD|NFF_IMM:
      sprintf(op, "ld");
      fmt = "#0x%x";
      break;

   case NFF_LDX|NFF_IMM:
      sprintf(op, "ldx");
      fmt = "#0x%x";
      break;

   case NFF_LDX|NFF_MSH|NFF_B:
      sprintf(op, "ldxb");
      fmt = "4*([%d]&0xf)";
      break;

   case NFF_LD|NFF_MEM:
      sprintf(op, "ld");
      fmt = "M[%d]";
      break;

   case NFF_LDX|NFF_MEM:
      sprintf(op, "ldx");
      fmt = "M[%d]";
      break;

   case NFF_ST:
      sprintf(op, "st");
      fmt = "M[%d]";
      break;

   case NFF_STX:
      sprintf(op, "stx");
      fmt = "M[%d]";
      break;

   case NFF_JMP|NFF_JA:
      sprintf(op, "ja");
      fmt = "%d";
      v = n + p->data.k;
      break;

   case NFF_JMP|NFF_JGT|NFF_F:
      sprintf(op, "jgt");
      fmt = "#%f";
      break;

   case NFF_JMP|NFF_JGE|NFF_F:
      sprintf(op, "jge");
      fmt = "#%f";
      break;

   case NFF_JMP|NFF_JEQ|NFF_F:
      sprintf(op, "jeq");
      fmt = "#%f";
      break;

   case NFF_JMP|NFF_JGT|NFF_K:
      sprintf(op, "jgt");
      fmt = "#0x%x";
      break;

   case NFF_JMP|NFF_JGE|NFF_K:
      sprintf(op, "jge");
      fmt = "#0x%x";
      break;

   case NFF_JMP|NFF_JEQ|NFF_K:
      sprintf(op, "jeq");
      switch (p->type) {
         case Q_STRING:  fmt = "\"%s\""; break;
         case Q_DEFAULT: fmt = "#0x%x"; break;
      }
      break;

   case NFF_JMP|NFF_JSET|NFF_K:
      sprintf(op, "jset");
      fmt = "#0x%x";
      break;

   case NFF_JMP|NFF_JGT|NFF_X:
      sprintf(op, "jgt");
      fmt = "x";
      break;

   case NFF_JMP|NFF_JGE|NFF_X:
      sprintf(op, "jge");
      fmt = "x";
      break;

   case NFF_JMP|NFF_JEQ|NFF_X:
      sprintf(op, "jeq");
      fmt = "x";
      break;

   case NFF_JMP|NFF_JSET|NFF_X:
      sprintf(op, "jset");
      fmt = "x";
      break;

   case NFF_ALU|NFF_ADD|NFF_X:
      sprintf(op, "add");
      fmt = "x";
      break;

   case NFF_ALU|NFF_SUB|NFF_X:
      sprintf(op, "sub");
      fmt = "x";
      break;

   case NFF_ALU|NFF_MUL|NFF_X:
      sprintf(op, "mul");
      fmt = "x";
      break;

   case NFF_ALU|NFF_DIV|NFF_X:
      sprintf(op, "div");
      fmt = "x";
      break;

   case NFF_ALU|NFF_AND|NFF_X:
      sprintf(op, "and");
      fmt = "x";
      break;

   case NFF_ALU|NFF_OR|NFF_X:
      sprintf(op, "or");
      fmt = "x";
      break;

   case NFF_ALU|NFF_LSH|NFF_X:
      sprintf(op, "lsh");
      fmt = "x";
      break;

   case NFF_ALU|NFF_RSH|NFF_X:
      sprintf(op, "rsh");
      fmt = "x";
      break;

   case NFF_ALU|NFF_ADD|NFF_K:
      sprintf(op, "add");
      fmt = " #%d";
      break;

   case NFF_ALU|NFF_SUB|NFF_K:
      sprintf(op, "sub");
      fmt = " #%d";
      break;

   case NFF_ALU|NFF_MUL|NFF_K:
      sprintf(op, "mul");
      fmt = " #%d";
      break;

   case NFF_ALU|NFF_DIV|NFF_K:
      sprintf(op, "div");
      fmt = " #%d";
      break;

   case NFF_ALU|NFF_AND|NFF_K:
      sprintf(op, "and");
      fmt = " #%d";
      break;

   case NFF_ALU|NFF_OR|NFF_K:
      sprintf(op, "or");
      fmt = " #%d";
      break;

   case NFF_ALU|NFF_LSH|NFF_K:
      sprintf(op, "lsh");
      fmt = " #%d";
      break;

   case NFF_ALU|NFF_RSH|NFF_K:
      sprintf(op, "rsh");
      fmt = " #%d";
      break;

   case NFF_ALU|NFF_NEG:
      sprintf(op, "neg");
      fmt = "";
      break;

   case NFF_MISC|NFF_TAX:
      sprintf(op, "tax");
      fmt = "";
      break;

   case NFF_MISC|NFF_TXA:
      sprintf(op, "txa");
      fmt = "";
      break;
   }

   if (!(strcmp (fmt, "#%f")))
      (void)snprintf(operand, 64, fmt, f);
   else
   if (!(strcmp (fmt, "\"%s\""))) {
      (void)snprintf(operand, 64, fmt, s);
   } else
      (void)snprintf(operand, 64, fmt, v);

   if ((NFF_CLASS(p->code) == NFF_JMP) && (NFF_OP(p->code) != NFF_JA))
      (void)snprintf(image, 256, "(%03d) %-8s %-16s jt %d\tjf %d",
            n, op, operand, (n + 1 + p->jt), (n + 1 + p->jf));
   else
      (void)snprintf(image, 256, "(%03d) %-8s%s", n, op, operand);

   return image;
}
