#!/usr/bin/perl

use strict;
use warnings;

use File::Copy;
use File::Basename;
use File::Path qw(make_path);

#
# This script will produce binary archive withh all libraries which required for FastNetMon
#

my $global_path = '/opt';

my $target_path = `mktemp -d`;
chomp $target_path;

unless (-e $target_path && -d $target_path) {
    die "Can't create target path\n";
}

my @our_libraries = (
    'boost_1_58_0',
    'gcc520',
    'json-c-0.12',
    'libhiredis_0_13',
    'log4cpp1.1.1',
    'luajit_2.0.4',
    'ndpi',
    'pf_ring_6.0.3'
);

for my $library (@our_libraries) {
    my $library_path = "$global_path/$library";

    unless (-e $library_path) {
        die "Can't find library $library please check\n";
    }

    print "Library: $library\n";

    my @files = `find $library_path`;

    for my $file_full_path (@files) {
        chomp $file_full_path;

        if ($file_full_path =~ /\.so$/) {
            my $dir_name = dirname($file_full_path);
            my $file_name = basename($file_full_path);

            print "$dir_name $file_name \n";

            my $target_full_path = $file_full_path;
            $target_full_path =~ s/^$global_path/$target_path/;

            # Create target folder 
            my $target_full_folder_path = $dir_name;
            $target_full_folder_path =~ s/^$global_path/$target_path/;

            print "Create folder $target_full_folder_path\n";
            make_path( $target_full_folder_path );

            #print "copy file from $file_full_path to $target_full_path\n";
            copy($file_full_path, $target_full_folder_path);
        }
    }
}

# manually handle toolkit itself
mkdir "$target_path/fastnetmon";
copy("$global_path/fastnetmon/fastnetmon",        "$target_path/fastnetmon");
copy("$global_path/fastnetmon/fastnetmon_client", "$target_path/fastnetmon");

my $archive_bundle_name = 'fastnetmon_bundle.tar.gz';
unlink $archive_bundle_name;

`tar -cpzf $archive_bundle_name $target_path/*`;
print "We have created bundle $archive_bundle_name\n";
