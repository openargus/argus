/*
 * Argus-5.0 Software.  Argus files - Netflow processing includes
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software, released under the GNU General
 * Public License; you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software
 * Foundation; either version 3, or any later version.
 *
 * Other licenses are available through QoSient, LLC.
 * Inquire at info@qosient.com.
 *
 * This program is distributed WITHOUT ANY WARRANTY; without even the
 * implied warranty of * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */

#ifndef ArgusNetflow_h
#define ArgusNetflow_h

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
#endif
