#!/bin/sh
#
#  Argus Software
#  Copyright (c) 2006-2015 QoSient, LLC
#  All rights reserved.
#
#  argus-snmp - collect snmp stats and report them as XML oriented argus events.
#               This program requires a lot of site specific customization, and
#               so, be sure and change the community string for snmp agent access
#               and pick the interfaces of interest.
#
# Carter Bullard
# QoSient, LLC
#
#  $Id: //depot/argus/argus/events/argus-snmp.sh#7 $
#  $DateTime: 2015/04/06 10:38:44 $
#  $Change: 2973 $
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
