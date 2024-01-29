#!@PERLBIN@
# 
#  Argus-5.0 Software.  Argus Event scripts - stumbler
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

