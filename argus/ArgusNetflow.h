/*
 * Argus Software.  Argus files - Modeler
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
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/argus/argus/argus/ArgusNetflow.h#1 $
 * $DateTime: 2011/01/26 17:21:20 $
 * $Change: 2089 $
 */


#define CISCO_VERSION_1         1
#define CISCO_VERSION_5         5
#define CISCO_VERSION_6         6
#define CISCO_VERSION_7         7
#define CISCO_VERSION_8         8
#define CISCO_VERSION_9         9


#ifndef ArgusNetflow_h
#define ArgusNetflow_h

#include <ArgusModeler.h>

void ArgusParseCiscoRecord (struct ArgusModelerStruct *, void *);
void ArgusParseCiscoRecordV1 (struct ArgusModelerStruct *, void *);
void ArgusParseCiscoRecordV5 (struct ArgusModelerStruct *, void *);
void ArgusParseCiscoRecordV6 (struct ArgusModelerStruct *, void *);
void ArgusParseCiscoRecordV7 (struct ArgusModelerStruct *, void *);
void ArgusParseCiscoRecordV8 (struct ArgusModelerStruct *, void *);
void ArgusParseCiscoRecordV9 (struct ArgusModelerStruct *, void *);

#else
extern void ArgusParseCiscoRecord (struct ArgusModelerStruct *, void *);
extern void ArgusParseCiscoRecordV1 (struct ArgusModelerStruct *, void *);
extern void ArgusParseCiscoRecordV5 (struct ArgusModelerStruct *, void *);
extern void ArgusParseCiscoRecordV6 (struct ArgusModelerStruct *, void *);
extern void ArgusParseCiscoRecordV7 (struct ArgusModelerStruct *, void *);
extern void ArgusParseCiscoRecordV8 (struct ArgusModelerStruct *, void *);
extern void ArgusParseCiscoRecordV9 (struct ArgusModelerStruct *, void *);
#endif
