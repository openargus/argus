/*
 * Copyright (c) 2001 Mark Fullmer and The Ohio State University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
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
 * $Id: //depot/argus/argus-3.0/clients/include/cflowd.h#5 $
 * $DateTime: 2006/02/23 13:25:52 $
 * $Change: 627 $
 */

/* Adapted from cflowd */

#define CF_ROUTERMASK         0x00000001
#define CF_SRCIPADDRMASK      0x00000002
#define CF_DSTIPADDRMASK      0x00000004
#define CF_INPUTIFINDEXMASK   0x00000008
#define CF_OUTPUTIFINDEXMASK  0x00000010
#define CF_SRCPORTMASK        0x00000020
#define CF_DSTPORTMASK        0x00000040
#define CF_PKTSMASK           0x00000080
#define CF_BYTESMASK          0x00000100
#define CF_IPNEXTHOPMASK      0x00000200
#define CF_STARTTIMEMASK      0x00000400
#define CF_ENDTIMEMASK        0x00000800
#define CF_PROTOCOLMASK       0x00001000
#define CF_TOSMASK            0x00002000
#define CF_SRCASMASK          0x00004000
#define CF_DSTASMASK          0x00008000
#define CF_SRCMASKLENMASK     0x00010000
#define CF_DSTMASKLENMASK     0x00020000
#define CF_TCPFLAGSMASK       0x00040000
#define CF_INPUTENCAPMASK     0x00080000
#define CF_OUTPUTENCAPMASK    0x00100000
#define CF_PEERNEXTHOPMASK    0x00200000
#define CF_ENGINETYPEMASK     0x00400000
#define CF_ENGINEIDMASK       0x00800000

#define CF_INDEX_V1_MASK      0x00043FFF
#define CF_INDEX_V5_MASK      0x00C7FFFF
#define CF_INDEX_V6_MASK      0x00FFFFFF
#define CF_INDEX_V7_MASK      0x00C7FFFF
#define CF_INDEX_V8_1_MASK    0x00C0CD99
#define CF_INDEX_V8_2_MASK    0x00C00DE1
#define CF_INDEX_V8_3_MASK    0x00C14D8B
#define CF_INDEX_V8_4_MASK    0x00C28D95
#define CF_INDEX_V8_5_MASK    0x00C3CD9F
#define CF_INDEX_V8_6_MASK    0x00C02D95
#define CF_INDEX_V8_7_MASK    0x00C02D9F
#define CF_INDEX_V8_8_MASK    0x00C02DFF
#define CF_INDEX_V8_9_MASK    0x00C0ED99
#define CF_INDEX_V8_10_MASK   0x00C02DE1
#define CF_INDEX_V8_11_MASK   0x00C16D8B
#define CF_INDEX_V8_12_MASK   0x00C2AD95
#define CF_INDEX_V8_13_MASK   0x00C3ED9F
#define CF_INDEX_V8_14_MASK   0x00C32DFF

