/*
 * Gargoyle Software.  Common include files. dscodepoints
 * Copyright (c) 2000-2024 QoSient, LLC
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
 */

/* 
 * $Id: //depot/gargoyle/argus/include/argus_dscodepoints.h#5 $
 * $DateTime: 2015/04/13 00:39:28 $
 * $Change: 2980 $
 */


/* prepared from IANA DS codepoint definitions Wed Aug 16 11:45:21 EDT 2000 */


#ifndef  DSCodePoints_h
#define DSCodePoints_h

#ifdef __cplusplus
extern "C" {
#endif

#define ARGUS_IANA_DSCODES	0
#define ARGUS_DISA_DSCODES	1

struct ArgusDSCodePointStruct {
   char code, *label, *desc;
};


#if defined(ArgusUtil)
struct ArgusDSCodePointStruct *ArgusSelectDSCodesTable(struct ArgusParserStruct *);

struct ArgusDSCodePointStruct argus_dscodepoints [] = {
   { 0x00,   "cs0", "Pool 1 Recommended"},
   { 0x08,   "cs1", "Pool 1 Recommended"},
   { 0x10,   "cs2", "Pool 1 Recommended"},
   { 0x18,   "cs3", "Pool 1 Recommended"},
   { 0x20,   "cs4", "Pool 1 Recommended"},
   { 0x28,   "cs5", "Pool 1 Recommended"},
   { 0x30,   "cs6", "Pool 1 Recommended"},
   { 0x38,   "cs7", "Pool 1 Recommended"},
   { 0x0A,  "af11", ""},
   { 0x0C,  "af12", ""},
   { 0x0E,  "af13", ""},
   { 0x12,  "af21", ""},
   { 0x14,  "af22", ""},
   { 0x16,  "af23", ""},
   { 0x1A,  "af31", ""},
   { 0x1C,  "af32", ""},
   { 0x1E,  "af33", ""},
   { 0x22,  "af41", ""},
   { 0x24,  "af42", ""},
   { 0x26,  "af43", ""},
   { 0x2E,  "ef",   ""},
   { 0x00, (char *) 0, (char *) 0 }, 
};

struct ArgusDSCodePointStruct argus_disa_dscodepoints [] = {
   { 40, "US", "Tail Drop"},
   { 46, "Voice", "Tail Drop"},
   { 48, "NC", "Tail Drop"},
   { 16, "OAM", "Tail Drop"},

   { 38, "Video", "WRED-L"},
   { 26, "SMMS", "WRED-M"},
   { 28, "SMMS", "WRED-H"},
   { 30, "SMMS", "WRED-H"},

   { 32, "SM", "WRED-L"},
   { 25, "HPMMS", "WRED-L"},
   {  9, "HPHTD", "WRED-L"},
   { 17, "HPLLD", "WRED-L"},

   { 10, "SHTD", "WRED-L"},
   { 12, "SHTD", "WRED-L"},
   { 14, "SHTD", "WRED-L"},
   { 18, "SHLLD", "WRED-L"},
   { 20, "SHLLD", "WRED-L"},
   { 22, "SHLLD", "WRED-L"},
   {  0, "BE", "Tail Drop"},

   { 0x00, (char *) 0, (char *) 0 },
};

#else

extern struct ArgusDSCodePointStruct *ArgusSelectDSCodesTable(struct ArgusParserStruct *);
extern struct ArgusDSCodePointStruct argus_dscodepoints [];
extern struct ArgusDSCodePointStruct argus_disa_dscodepoints [];

#endif
#ifdef __cplusplus
}
#endif
#endif
