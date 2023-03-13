#!/usr/bin/perl



use strict;
use warnings;

use Data::Dumper;
use File::Copy;
use File::Basename;
use File::Path qw(make_path);

#
# This script will produce binary archive with all libraries required for FastNetMon
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

# It may be different for community edition
my $project_folder_name = 'fastnetmon-community';

my $global_path = "/opt/$project_folder_name";
my $fastnetmon_libraries_path = "$global_path/libraries";

my $temp_build_folder_path = `mktemp -d`;
chomp $temp_build_folder_path;

print "We will create temp folder for build: $temp_build_folder_path\n";

unless (-e $temp_build_folder_path && -d $temp_build_folder_path) {
    die "Can't create temporary folder for build\n";
}

# Path to FastNetMon's folder int temp folder
my $temp_folder_global_path = "$temp_build_folder_path/$project_folder_name";

# Open path which has all developer libraries (including binaries)
opendir my $fastnetmon_libs_handle, $fastnetmon_libraries_path or die "Could not open library directory $fastnetmon_libraries_path with error: $!";

# List all files and folders in directory excluding special files . and ..
my @libraries_list = grep { !/^\.+$/ } readdir $fastnetmon_libs_handle;
closedir $fastnetmon_libs_handle; 

# Iterate all libraries in developer folder
for my $library (@libraries_list) {
    my $library_path = "$fastnetmon_libraries_path/$library";

    unless (-e $library_path) {
        die "Can't find library $library at path $library_path please check\n";
    }

    # We do not need these libraries on customer machines
    if ($library =~ m/clang/) {
        next;
    }

    # print "Library: $library\n";

    my @files = `find $library_path`;

    for my $file_full_path (@files) {
        chomp $file_full_path;

        if ($file_full_path =~ /\.so[\.\d]*/) {
            # Skip some unrelated files captured by reg exp
            if ($file_full_path =~ m/\.json$/ or $file_full_path =~ m/\.cpp$/) {
                next;
            }

            my $dir_name = dirname($file_full_path);
            my $file_name = basename($file_full_path);

            # print "$dir_name $file_name\n";

            my $target_full_path = $file_full_path;
            $target_full_path =~ s#^$global_path#$temp_folder_global_path#;

            # Create target folder 
            my $target_full_folder_path = $dir_name;
            $target_full_folder_path =~ s#^$global_path#$temp_folder_global_path/#;

            unless (-e $target_full_folder_path) {
                # print "Create folder $target_full_folder_path\n";
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

sub list_files_in_folder {
    my $folder_path = shift;
        
    opendir my $fastnetmon_libs_handle, $folder_path or die "Could not open directory: $folder_path";
    my @libraries_list = grep { !/^\.+$/ } readdir $fastnetmon_libs_handle;
    closedir $fastnetmon_libs_handle;

    return [ @libraries_list ];
}

### Copy binary files

my $binary_files = list_files_in_folder("$global_path/app/bin");

mkdir "$temp_folder_global_path/app";
mkdir "$temp_folder_global_path/app/bin";

for my $binary_file (@$binary_files) {
    my $source_full_file_name = "$global_path/app/bin/$binary_file";
    my $target_full_file_name = "$temp_folder_global_path/app/bin/$binary_file";

    my $copy_result = copy($source_full_file_name, $target_full_file_name);

    unless ($copy_result) {
        die "Could not copy binary file from $source_full_file_name to $target_full_file_name\n";
    }

    chmod 0755, $target_full_file_name;

}

# Install GoBGP binary files
my $gobgp_folder_name = "gobgp_3_12_0";
mkdir "$temp_folder_global_path/libraries/$gobgp_folder_name";

for my $gobgp_binary ('gobgp', 'gobgpd') {
    unless (-e "$fastnetmon_libraries_path/$gobgp_folder_name/$gobgp_binary") {
        die "GoBGP binary $gobgp_binary does not exist\n";
    }

    my $gobgp_copy_result = copy("$fastnetmon_libraries_path/$gobgp_folder_name/$gobgp_binary",
        "$temp_folder_global_path/libraries/$gobgp_folder_name/$gobgp_binary");

    unless ($gobgp_copy_result) {
        die "Could not copy GoBGP's binary $gobgp_binary $!\n";
    }

    # Enable exec flag
    chmod 0755, "$temp_folder_global_path/libraries/$gobgp_folder_name/$gobgp_binary";
}

# Just tar it. We do not need compression here because this bundle will be unpacked by our own code later
# I explicitly set uid and git to zero here to prevent any non zero owners for production build
`tar -cpf $archive_bundle_name -C $temp_build_folder_path --owner=0 --group=0 ./`;
print "We have created bundle $archive_bundle_name\n";
