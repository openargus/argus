#!/bin/bash
#
#  Argus Software
#  Copyright (c) 2006-2020 QoSient, LLC
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
