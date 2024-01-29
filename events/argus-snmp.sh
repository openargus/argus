#!/bin/sh
#
#  Argus-5.0 Software.  Argus Event scripts - snmp
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
#  argus-snmp - collect snmp stats and report them as XML oriented argus events.
#               This program requires a lot of site specific customization, and
#               so, be sure and change the community string for snmp agent access
#               and pick the interfaces of interest.
#
#
#  $Id: //depot/gargoyle/argus/events/argus-snmp.sh#5 $
#  $DateTime: 2015/04/13 00:39:28 $
#  $Change: 2980 $
# 

prog="/usr/bin/snmpwalk -Os -c qosient -v 2c 10.0.1.1" 
stats="/usr/bin/snmpget -Os -c qosient -v 2c 10.0.1.1" 
interfaces="2 3 9"

echo "<ArgusEvent>"

echo "   <ArgusEventData Type = \"Program: $prog\" >"
retn=`$prog ipNetToMediaPhysAddress | awk 'BEGIN{FS="="}{print "      < Label = \""$1"\" Value = \""$2"\" />"}'`;
echo "$retn"
echo "   </ArgusEventData>"

echo "   <ArgusEventData Type = \"Program: $stats\" >"
for i in $interfaces; do
   echo "      "`$stats ifInUcastPkts.$i | awk 'BEGIN{FS="="}{print "< Label = \""$1"\" Value = \""$2"\" />"}'`;
   echo "      "`$stats ifOutUcastPkts.$i | awk 'BEGIN{FS="="}{print "< Label = \""$1"\" Value = \""$2"\" />"}'`;
   echo "      "`$stats ifInOctets.$i | awk 'BEGIN{FS="="}{print "< Label = \""$1"\" Value = \""$2"\" />"}'`;
   echo "      "`$stats ifOutOctets.$i | awk 'BEGIN{FS="="}{print "< Label = \""$1"\" Value = \""$2"\" />"}'`;
   echo "      "`$stats ifOutDiscards.$i | awk 'BEGIN{FS="="}{print "< Label = \""$1"\" Value = \""$2"\" />"}'`;
done
echo "   </ArgusEventData>"

echo "</ArgusEvent>"
