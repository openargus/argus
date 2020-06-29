#!/bin/bash
#
#  Gargoyle Software.  Argus Event scripts - vmstat
#  Copyright (c) 2000-2016 QoSient, LLC
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
#  airport - report apple airport wireless interface stats.
# 
#  $Id$
#  $DateTime$
#  $Change$
#

output=`/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | sed -e 's/^[ \t]*//' -e 's/:/,/' -e 's/op mode/opMode/' -e 's/link auth/linkAuth/' -e 's/802.11 auth/802.11.auth/' | awk 'BEGIN{FS=","}{print "      < "$1" ="$2"\" />"}' | sed -e 's/= /= "/'`

#
# 
echo "<ArgusEvent>"
echo "   <ArgusEventData Type = \"Program: com.apple.airport\" >"
echo "$output"
echo "   </ArgusEventData>"
echo "</ArgusEvent>"
