#!/bin/sh
#
#  Gargoyle Software.  Argus Event scripts - snmp
#  Copyright (c) 2000-2015 QoSient, LLC
#  All rights reserved.
#
#  THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
#  AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
#  EXPRESS PERMISSION OF QoSIENT, LLC.
#
#  QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
#  SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
#  SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
#  IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
#  ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
#  THIS SOFTWARE.
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
