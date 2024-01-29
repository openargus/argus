#!/bin/bash
#
#  Argus Software
#  Copyright (c) 2006-2020 QoSient, LLC
#  All rights reserved.
#
#  This program is free software, released under the GNU General
#  Public License; you can redistribute it and/or modify it under the terms
#  of the GNU General Public License as published by the Free Software
#  Foundation; either version 3, or any later version.
#
#  Other licenses are available through QoSient, LLC.
#  Inquire at info@qosient.com.
#
#  This program is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the * GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
#  Written by Carter Bullard
#  QoSient, LLC
#
#  vmstat - report vmstat output as XML oriented argus event.
#           This example is provided to show how you can format most programs
#           to get to the XML oriented output used by the argus events system.
#
# Carter Bullard
# QoSient, LLC
#

output=`vm_stat | sed -e 's/"//g' -e 's/\.//' -e 's/: */:/' | \
        awk 'BEGIN {FS = ":"}{ if ($1=="Mach Virtual Memory Statistics") \
        print "   <ArgusEventData Type = \""$1"\" Comment = \""$2"\" >" ; \
        else print "      < Label = \""$1"\" Value = \""$2"\" />"}'`
#
# 
echo "<ArgusEvent>"
echo "$output"
echo "   </ArgusEventData>"
echo "</ArgusEvent>"
