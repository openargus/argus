/*
 * Argus Software Common include files - name database
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
 * Copyright (c) 1994
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
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
 *
 */

/* 
 * $Id: //depot/argus/argus/include/argus_namedb.h#13 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

#if !defined(Argus_namedb_h)
#define Argus_namedb_h

/*
 * As returned by the argus_next_etherent()
 * XXX this stuff doesn't belong in this inteface, but this
 * library already must do name to address translation, so
 * on systems that don't have support for /etc/ethers, we
 * export these hooks since they'll
 */
struct argus_etherent {
	unsigned char addr[6];
	char name[122];
};
#if !defined(PCAP_ETHERS_FILE)
#define PCAP_ETHERS_FILE "/etc/ethers"
#endif
struct	argus_etherent *argus_next_etherent(FILE *);
unsigned char *argus_ether_hostton(char*);
unsigned char *argus_ether_aton(char *);

unsigned int	**argus_nametoaddr(char *);
unsigned int	argus_nametonetaddr(char *);

int	argus_nametoport(char *, int *, int *);
int	argus_nametoproto(char *);
int	argus_nametoeproto(char *);
/*
 * If a protocol is unknown, PROTO_UNDEF is returned.
 * Also, argus_nametoport() returns the protocol along with the port number.
 * If there are ambiguous entried in /etc/services (i.e. domain
 * can be either tcp or udp) PROTO_UNDEF is returned.
 */
#define PROTO_UNDEF		-1

/* XXX move these to pcap-int.h? */
unsigned int	__argus_atodn(char *);
unsigned int	__argus_atoin(char *, unsigned int *);
unsigned short	__argus_nametodnaddr(char *);

#endif
