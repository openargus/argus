#!@PERLBIN@
#
#  Argus Software
#  Copyright (c) 2006-2015 QoSient, LLC
#  All rights reserved.
#
#  argus-extip - get external IP address for this node.
#
# Carter Bullard
# QoSient, LLC
#

use POSIX;
use strict;

my $wget    = `which wget`;
my $host    = "qosient.com/argus/argusPublicIP.php";
my $options = "-q -O -";

chomp($wget);

my @args = "$wget $host $options";
my $data;

print "<ArgusEvent>\n";
print "  <ArgusEventData Type = \"Program: $wget $host $options\">\n";

open(SESAME, "@args |");

while ($data = <SESAME>) {
   $data =~ s/</    </gs;
   $data =~ s/>/>\n/gs;
   print "$data";
}
close(SESAME);

print "  </ArgusEventData>\n";
print "</ArgusEvent>\n";
