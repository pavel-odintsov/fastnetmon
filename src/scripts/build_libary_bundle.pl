#!/usr/bin/perl

use strict;
use warnings;

use Data::Dumper;
use File::Copy;
use File::Basename;
use File::Path qw(make_path);

#
# This script will produce binary archive with all libraries which required for FastNetMon
# 
# Script params: path to bundle archive
#

unless (scalar @ARGV == 1 && $ARGV[0]) {
    die "Please provide path to bundle file\n";
}

my $archive_bundle_name = $ARGV[0];

if (-e $archive_bundle_name) {
    warn "Bundle file is already exists but we could remove it automatically\n";
    unlink $archive_bundle_name;
}

my $global_path = '/opt';

my $target_path = `mktemp -d`;
chomp $target_path;

unless (-e $target_path && -d $target_path) {
    die "Can't create target path\n";
}

my @our_libraries = qw(
boost_1_74_0
json-c-0.13
libicu_65_1
log4cpp1.1.1
pf_ring_6.0.3
gobgp_2_17_0
grpc_1_30_2
libhiredis_0_13 
mongo_c_driver_1_16_1
protobuf_3.11.4
gcc930
capnproto_0_8_0
openssl_1_0_2d
);

for my $library (@our_libraries) {
    my $library_path = "$global_path/$library";

    unless (-e $library_path) {
        warn "Can't find library $library please check\n";
        
        if ($library eq 'pf_ring_6.0.3') {
            next;
        } else {
            die "Some required libraries are missing\n";
        }
    }

    print "Library: $library\n";

    my @files = `find $library_path`;

    for my $file_full_path (@files) {
        chomp $file_full_path;

        if ($file_full_path =~ /\.so[\.\d]*/) {
            my $dir_name = dirname($file_full_path);
            my $file_name = basename($file_full_path);

            print "$dir_name $file_name\n";

            my $target_full_path = $file_full_path;
            $target_full_path =~ s/^$global_path/$target_path/;

            # Create target folder 
            my $target_full_folder_path = $dir_name;
            $target_full_folder_path =~ s/^$global_path/$target_path/;

            unless (-e $target_full_folder_path) {
                print "Create folder $target_full_folder_path\n";
                make_path( $target_full_folder_path );
            }

            if (-l $file_full_path) {
                my $symlink_target_name = readlink($file_full_path);

                #print "We have symlink which aims to $symlink_target_name\n";

                # This way we copy symlinks
                my $symlink_result = symlink($symlink_target_name, $target_full_path);

                unless ($symlink_result) {
                    die "Symlink from $symlink_target_name to $target_full_path failed\n";
                }

            } else {
                copy($file_full_path, $target_full_folder_path);

		# Strip debug information from library, we need it to reduce distribution size
		# It's pretty serious disk space saving (from 260Mb to 95Mb in my tests)
		system("strip --strip-debug $target_full_path");
            }
        }
    }
}

# Manually handle toolkit itself
mkdir "$target_path/fastnetmon";
copy("$global_path/fastnetmon/fastnetmon",        "$target_path/fastnetmon/fastnetmon");
copy("$global_path/fastnetmon/fastnetmon_client", "$target_path/fastnetmon/fastnetmon_client");
copy("$global_path/fastnetmon/fastnetmon_api_client", "$target_path/fastnetmon/fastnetmon_api_client");

# Set exec flag
chmod 0755, "$target_path/fastnetmon/fastnetmon";
chmod 0755, "$target_path/fastnetmon/fastnetmon_client";
chmod 0755, "$target_path/fastnetmon/fastnetmon_api_client";

# Install GoBGP's binary files
my $gobgp_folder_name = "gobgp_2_17_0";
mkdir "$target_path/$gobgp_folder_name";

for my $gobgp_binary ('gobgp', 'gobgpd') {
    unless (-e "$global_path/$gobgp_folder_name/$gobgp_binary") {
        die "GoBGP binary $gobgp_binary does not exist\n";
    }

    my $gobgp_copy_result = copy("$global_path/$gobgp_folder_name/$gobgp_binary",
        "$target_path/$gobgp_folder_name/$gobgp_binary");

    unless ($gobgp_copy_result) {
        die "Could not copy GoBGP's binary $gobgp_binary $!\n";
    }

    # Enable exec flag
    chmod 0755, "$target_path/$gobgp_folder_name/$gobgp_binary";
}


`tar -cpzf $archive_bundle_name -C $target_path ./`;
print "We have created bundle $archive_bundle_name\n";
