/*
 * Argus-5.0 Software.  Argus files - VxLan Protocol Includes
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


/* 
 * $Id$
 * $DateTime: 2014/05/14 12:53:31 $
 * $Change: 2827 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#ifndef ArgusVxLan_h
#define ArgusVxLan_h

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <argus_compat.h>
#include <ArgusModeler.h>

#include <argus/bootp.h>

unsigned short ArgusParseVxLan (struct ArgusModelerStruct *, void *);
#endif
