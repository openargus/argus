#!@PERLBIN@
#
#  Argus Software
#  Copyright (c) 2006-2015 QoSient, LLC
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
