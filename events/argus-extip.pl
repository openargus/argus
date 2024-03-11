#!@PERLBIN@
#
#  Argus-5.0 Software.  Argus Event scripts - argus-extip
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
#  argus-extip - get external IP address for this node.
#
# Carter Bullard
# QoSient, LLC
#

use POSIX;
use strict;

my $curl    = `which curl`;
my $host    = "qosient.com/argus/argusPublicIP.php";
my $options = "-L -s";

chomp($curl);

my @args = "$curl $options $host";
my $data;

print "<ArgusEvent>\n";
print "  <ArgusEventData Type = \"Program: $curl $host $options\">\n";

open(SESAME, "@args |");

while ($data = <SESAME>) {
   $data =~ s/</    </gs;
   $data =~ s/>/>\n/gs;
   print "$data";
}
close(SESAME);

print "  </ArgusEventData>\n";
print "</ArgusEvent>\n";
