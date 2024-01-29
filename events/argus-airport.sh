#!/bin/bash
#
#  Argus-5.0 Software.  Argus Event scripts - airport
#  Copyright (c) 2000-2024 QoSient, LLC
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
#  airport - report apple airport wireless interface stats.
# 

output=`/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | sed -e 's/^[ \t]*//' -e 's/:/,/' -e 's/op mode/opMode/' -e 's/link auth/linkAuth/' -e 's/802.11 auth/802.11.auth/' | awk 'BEGIN{FS=","}{print "      < "$1" ="$2"\" />"}' | sed -e 's/= /= "/'`

#
# 
echo "<ArgusEvent>"
echo "   <ArgusEventData Type = \"Program: com.apple.airport\" >"
echo "$output"
echo "   </ArgusEventData>"
echo "</ArgusEvent>"
