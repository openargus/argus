#!@PERLBIN@
# 
#  Gargoyle Software.  Argus Event scripts - stumbler
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
#  stumbler - report available wireless networks - using airport.
#
#  $Id$
#  $DateTime$
#  $Change$
#
# Complain about undeclared variables
use strict;

my $count    = 0;
 
my $ssid     = "";
my $bssid    = "";
my $rssi     = "";
my $channel  = "";
my $ht       = "";
my $cc       = "";
my $security = "";

if (my $arg = shift(@ARGV)) {
   open(SESAME, $arg);
} else {
   my $STUMBLER = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
   my $Options = "-s";
   my @args = ($STUMBLER, $Options);
   open(SESAME, "@args |");
}

print "<ArgusEvent>\n";
print "   <ArgusEventData Type = \"Program: com.qosient.stumbler\" >\n";

while (my $data = <SESAME>) {
   my $parsing = 1;
   if ($count++ > 0) {
      for ($data) {
         if    (/SSID/) { $parsing = 0; }
         elsif (/IBSS/) { $parsing = 0; }
         else {
            my @fields = split /\s+/, $data;
            $parsing  = 0;

            for (my $i = 1; $i < ($#fields + 1); $i++) {
               chomp $fields[$i];
               $fields[$i] =~ s/^\s+|\s+$//g;
               for ($parsing) {
                 if    (/0/) { $ssid = $fields[$i]; $parsing++;}
                 elsif (/1/) { 
                       if ($fields[$i] =~ m/:/) {
                         $bssid = $fields[$i];
                         $parsing++;
                       } else {
                         $ssid = $ssid . " " . $fields[$i];
                       } }
                 elsif (/2/) { $rssi     = $fields[$i]; $parsing++;}
                 elsif (/3/) { $channel  = $fields[$i]; $parsing++;}
                 elsif (/4/) { $ht       = $fields[$i]; $parsing++;}
                 elsif (/5/) { $cc       = $fields[$i]; $parsing++;}
                 elsif (/6/) { $security = $fields[$i]; $parsing++;}
                 elsif (/7/) { $security = $security . " " . $fields[$i];}
                 else        { }
               }
            }

            if ($parsing) {
               print "      <Network>Ssid=\"$ssid\" Bssid=\"$bssid\" Rssi=\"$rssi\" Channel=\"$channel\" Ht=\"$ht\" Cc=\"$cc\" Security=\"$security\"</Network>\n";
            }
         }
      }
   }
}

print "   </ArgusEventData>\n";
print "</ArgusEvent>\n";
exit;

