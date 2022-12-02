#!/usr/bin/perl

use strict;
use warnings;

use FindBin;

use lib "$FindBin::Bin/perllib";

use Fastnetmon;

if (scalar @ARGV < 1) {
    die "Please provide package name\n";
}

my $package_name = $ARGV[0];

print "We will install package: $package_name\n";

install_package($package_name);

sub install_package {
    my $package_name = shift;

    die "Please provide package name" unless $package_name;

    # In this folder we create temp sub folders for building packages
    my $global_path_where_we_build_libraries = '/tmp/library_builder_folder';

    my $distro_architecture = `uname -m`;
    chomp $distro_architecture;

    unless (-e $global_path_where_we_build_libraries) {
        mkdir $global_path_where_we_build_libraries;

        unless ($? == 0) {
            die "Could not create folder $global_path_where_we_build_libraries\n";
        }
    }

    $Fastnetmon::library_install_folder = "/opt/fastnetmon-community/libraries";

    unless (-e $Fastnetmon::library_install_folder) {
        mkdir $Fastnetmon::library_install_folder;

        unless ($? == 0) {
            die "Could not create folder: " . $Fastnetmon::library_install_folder . "\n";
        }
    }

    $Fastnetmon::temp_folder_for_building_project =
        `mktemp -d $global_path_where_we_build_libraries/$package_name.build.dir.XXXXXXXXXX`;
    chomp $Fastnetmon::temp_folder_for_building_project;

    # Not in all cases mktemp can create folder, we need to explicitly create it
    system("mkdir -p " . $Fastnetmon::temp_folder_for_building_project);

    print "We will build package in folder " . $Fastnetmon::temp_folder_for_building_project . "\n";
    print "We will install package in folder " . $Fastnetmon::library_install_folder . "\n";

    $Fastnetmon::install_log_path = "/tmp/library_installer.log";

    # We should init compiler before any operations
    Fastnetmon::init_compiler();

    Fastnetmon::install_package_by_name_with_dependencies($package_name);
}

