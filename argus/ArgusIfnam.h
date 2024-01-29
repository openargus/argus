/*
 * Argus-5.0 Software. Argus files - Events include files
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

#ifndef __ARGUS_IFNAM_H
# define __ARGUS_IFNAM_H

# ifdef HAVE_CONFIG_H
#  include "argus_config.h"
# endif

# include "argus_compat.h"
# include "ArgusModeler.h"
# include "ArgusSource.h"

int
shortname_ethdev_unique(char *in, char *out, size_t outlen,
                        struct ArgusListStruct *ArgusDeviceList);

#endif
