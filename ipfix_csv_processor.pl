#!/usr/bin/perl

use strict;
use warnings;

# This script can convert data from http://www.iana.org/assignments/ipfix/ipfix.xhtml ipfix standard
# represented in CSV form into form suitable for us
# http://www.iana.org/assignments/ipfix/ipfix-information-elements.csv
# to our C/C++ frndly storage format

open my $fl, "<", "ipfix_fields.csv" or die "Can't open input file";

my $field_id = 0;
while (<$fl>) {
    chomp;

    my $we_will_process_this_line = /^(\d+),/;

    # Skip crap
    unless ($we_will_process_this_line) {
        next;
    }

    # Numbers should growth monotonous
    if ($1 < $field_id) {
        next;
    }

    $field_id++;

    my @keys = ("id", "name", "data_type", "data_type_semantics", "status", "description","units", "range", "reference", "requester", "revision", "date");

    my %data = ();
    @data{ @keys } = split /,/, $_;

    # skip deprecated fields
    if ($data{status} eq 'deprecated') {
        next;
    }

    print "$data{id} $data{name} $data{data_type}\n"; 
}
