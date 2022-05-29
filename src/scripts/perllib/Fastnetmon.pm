package Fastnetmon;

use strict;
use warnings;

use File::Copy;
use File::Basename;

# Retrieve all required modules
BEGIN {

eval { require Env; };

if ($@) {
    die "Perl module Env is not installed, install it:\nsudo yum install -y perl-Env.noarch\n";
}

}

use Env qw(PATH);

BEGIN {

eval { require Archive::Tar; };

if ($@) {
    die "Perl module Archive::Tar is not installed, install it:\nsudo yum install -y perl-Archive-Tar.noarch\n";
}

}



use Archive::Tar;



require Exporter;
our @ISA = qw(Exporter);

1;
