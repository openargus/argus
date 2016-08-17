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

my $lsof = `which lsof`;
chomp($lsof);
my @args = "$lsof -i -n -P ";
my $data;

print "<ArgusEvent>\n";
print "  <ArgusEventData Type = \"Program: $lsof -i -n -P\">\n";

open(SESAME, "@args |");

while ($data = <SESAME>) {
   print "    $data";
}
close(SESAME);

print "  </ArgusEventData>\n";
print "</ArgusEvent>\n";
