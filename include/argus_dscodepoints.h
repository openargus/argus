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
 * $Id: //depot/argus/argus/include/argus_dscodepoints.h#7 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
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
