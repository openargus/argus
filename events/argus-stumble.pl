#!@PERLBIN@
#
#  Gargoyle Software.  Argus Event scripts - stumble
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
#  argus-stumble - Report available wireless networks.
#

use POSIX;
use strict;

my $stumble = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
my @args = "$stumble -s";
my $data;

print "<ArgusEvent>\n";
print "  <ArgusEventData Type = \"Program: argus-stumble\">\n";

open(SESAME, "@args |");

while ($data = <SESAME>) {
   print "    $data";
}
close(SESAME);

print "  </ArgusEventData>\n";
print "</ArgusEvent>\n";