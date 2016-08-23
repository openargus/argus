/*
 * Argus Software
 * Copyright (c) 2000-2020 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 *
 * Written by Carter Bullard
 * QoSient, LLC
 *
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/gargoyle/argus/include/argus_debug.h#5 $
 * $DateTime: 2015/04/13 00:39:28 $
 * $Change: 2980 $
 */


#ifndef ArgusDebug_h
#define ArgusDebug_h

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __GNUC__
#define inline
#endif

#define ARGUS_DEBUG_ALL			0xffffffff
#define ARGUS_DEBUG_MAIN		0x00000001  /* 1 */
#define ARGUS_DEBUG_CORE		0x00000002  /* 2 */
#define ARGUS_DEBUG_INIT		0x00000004  /* 4 */
#define ARGUS_DEBUG_FILTER		0x00000008  /* 8 */
#define ARGUS_DEBUG_FILTERCOMPILE	0x00000010  /* 16 */
#define ARGUS_DEBUG_FILTERCORE		0x00000020  /* 32 */
#define ARGUS_DEBUG_AUTH		0x00000040  /* 64 */
#define ARGUS_DEBUG_DECODE		0x00000080  /* 128 */
#define ARGUS_DEBUG_MEMORY		0x00000100  /* 256 */
#define ARGUS_DEBUG_UTIL		0x00000200  /* 512 */
#define ARGUS_DEBUG_PARSE		0x00000400  /* 1024 */
#define ARGUS_DEBUG_PARSECORE		0x00000800  /* 2048 */
#define ARGUS_DEBUG_READ		0x00001000  /* 4096 */
#define ARGUS_DEBUG_WRITE		0x00002000  /* 8192 */
#define ARGUS_DEBUG_CLIENT		0x00004000  /* 16384 */
#define ARGUS_DEBUG_POLICY		0x00008000  /* 32768 */
#define ARGUS_DEBUG_APPLICATION		0x00010000  /* 65536 */
#define ARGUS_DEBUG_MERGE		0x00020000  /* 131072 */
#define ARGUS_DEBUG_TIME		0x00040000  /* 262144 */
#define ARGUS_DEBUG_SERVICES		0x00080000  /* 524288 */

extern void ArgusDebug (int, char *, ...);

#ifdef __cplusplus
}
#endif
#endif  /* ArgusFilter_h */

