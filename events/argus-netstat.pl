#!@PERLBIN@
#
#  Argus-5.0 Software.  Argus Event scripts - netstat
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
#  netstat - report IPv4 routing table using netstat polling.
#
#  $Id: //depot/gargoyle/argus/events/argus-netstat.pl#2 $
#  $DateTime: 2016/06/06 12:23:00 $
#  $Change: 3158 $

# Mac OS X generates this type of output for the "netstat -rn" command.
# We'll send the whole thing.
# 
# Routing tables
# 
# Internet:
# Destination        Gateway            Flags        Refs      Use   Netif Expire
# default            link#4             UCSI            1        0     en0
# 10.92.104.14       4c:7c:5f:c5:9b:94  UHLWI           0        0     en0   1196
# 127                127.0.0.1          UCS             0        0     lo0
# 127.0.0.1          127.0.0.1          UH              3   105680     lo0
# 169.254            link#4             UCS           131        0     en0
# 169.254.4.99       dc:86:d8:db:d6:c7  UHLSW           0        0     en0    819
# 169.254.7.133      e0:f8:47:14:dd:1e  UHLSW           0        0     en0    756
# 169.254.46.133     f8:16:54:71:d4:e1  UHLSW           1       29     en0   1168
# 169.254.48.214     e8:2a:ea:66:60:93  UHLSW           0        0     en0   1178
# 169.254.105.181    e4:d5:3d:ac:e8:4e  UHLSW           0      181     en0   1124
# 169.254.109.113    a4:b8:5:bf:8b:10   UHLSW           0        0     en0   1159
# 169.254.123.227/32 link#4             UCS             1        0     en0
# 169.254.126.5      cc:29:f5:bb:91:1f  UHLSW           0        0     en0   1160
# 169.254.253.47     b0:34:95:5f:2d:7e  UHLSW           0        0     en0   1170
# 169.254.255.255    ff:ff:ff:ff:ff:ff  UHLWb           0      121     en0
# 
# Internet6:
# Destination                             Gateway                         Flags         Netif Expire
# ::1                                     ::1                             UHL             lo0
# fd8a:7ca4:5ae0:bf6d::/64                fe80::1590:f573:fef6:fcee%utun0 Uc            utun0
# .....
# ff02::%utun0/32                         fe80::1590:f573:fef6:fcee%utun0 UmCI          utun0
#
# Complain about undeclared variables
use strict;

my $NETSTAT = "/usr/sbin/netstat";
my $Options = "-rn";

my @args = ($NETSTAT, $Options);
my $count    = 0;

my $parsing  = "";
print "<ArgusEvent>\n";
print "   <ArgusEventData Type = \"Program: $NETSTAT $Options\" >\n";

open(SESAME, "@args |");
while (my $data = <SESAME>) {
   if ($count++ > 0) {
      my @fields = split /\s+/, $data;
      if ($parsing > 0) {
         for ($fields[0]) {
            if (/Internet6/) { $parsing = 0; }
            elsif (/Destination/) { }
            else {
               my $dest = $fields[0];
               my $gate = $fields[1];
               my $flag = $fields[2];
               my $refs = $fields[3];
               my $use  = $fields[4];
               my $inf  = $fields[5];
               my $exp  = $fields[6];

               if ($dest) {
                 print "     <Route Dest=\"$dest\" Gateway=\"$gate\" Flags=\"$flag\" Refs=\"$refs\" Use=\"$use\" Inf=\"$inf\" Expire=\"$exp\"\\>\n";
               }
            }
         }
      } else {
         for ($fields[0]) {
            if (/Internet\:/) { $parsing++;}
         }
      }
   }
}

print "   </ArgusEventData>\n";
print "</ArgusEvent>\n";
exit;

