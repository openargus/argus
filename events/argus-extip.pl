#!@PERLBIN@
#
#  Argus Software
#  Copyright (c) 2006-2020 QoSient, LLC
#  All rights reserved.
#
#  argus-lsof - Report open inet sockets and provide application names as
#               XML oriented argus events.
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
