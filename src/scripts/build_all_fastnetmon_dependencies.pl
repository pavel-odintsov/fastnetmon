#!/usr/bin/perl

###
### This tool builds all binary dependencies required for FastNetMon
###


use strict;
use warnings;

use FindBin;

use lib "$FindBin::Bin/perllib";

use Fastnetmon;
use Getopt::Long;

#
# CentOS
# sudo yum install perl perl-Archive-Tar
#

my $library_install_folder = '/opt/fastnetmon-community/libraries';

my $os_type = '';  
my $distro_type = '';  
my $distro_version = '';  
my $distro_architecture = '';  
my $appliance_name = ''; 

my $temp_folder_for_building_project = `mktemp -d /tmp/fastnetmon.build.dir.XXXXXXXXXX`;
chomp $temp_folder_for_building_project;

unless ($temp_folder_for_building_project && -e $temp_folder_for_building_project) {
    die "Can't create temp folder in /tmp for building project: $temp_folder_for_building_project\n";
}

# Pass log path to module
$Fastnetmon::install_log_path = '/tmp/fastnetmon_install.log';

# We do not need default very safe permissions
exec_command("chmod 755 $temp_folder_for_building_project");

my $start_time = time();

my $fastnetmon_code_dir = "$temp_folder_for_building_project/fastnetmon/src";

my $cpus_number = 1;

# We could pass options to make with this variable
my $make_options = '';

unless (-e $library_install_folder) {
    exec_command("mkdir -p $library_install_folder");
}

main();

### Functions start here
sub main {
    my $machine_information = Fastnetmon::detect_distribution();

    unless ($machine_information) {
        die "Could not collect machine information\n";
    }

    $distro_version = $machine_information->{distro_version};
    $distro_type = $machine_information->{distro_type};
    $os_type = $machine_information->{os_type};
    $distro_architecture = $machine_information->{distro_architecture};
    $appliance_name = $machine_information->{appliance_name};
	
    $Fastnetmon::library_install_folder = $library_install_folder;
    $Fastnetmon::temp_folder_for_building_project = $temp_folder_for_building_project;

    $cpus_number = Fastnetmon::get_logical_cpus_number();

    # We could get huge speed benefits with this option
    if ($cpus_number > 1) { 
        print "You have really nice server with $cpus_number CPU's and we will use they all for build process :)\n";
        $make_options = "-j $cpus_number";
    }

    # Install packages required for build
    if ($distro_type eq 'ubuntu' or $distro_type eq 'debian') {
        print "Update package manager cache\n";
        exec_command("apt-get update");
        apt_get('make', 'wget', 'git');
    } elsif ( $distro_type eq 'centos') {
        # We need libmpc for our custom built gcc
        yum('make', 'wget', 'libmpc', 'glibc-devel', 'git'); 
    }

    # Init environment
    init_compiler();

    my @required_packages = (
        # 'gcc', # we build it separately as it requires excessive amount of time
        'openssl',
        'cmake',
        'boost_builder',
        'icu',
        'boost',
        'capnproto',
        'hiredis',
        'mongo_client',
        'protobuf',
        'grpc',
        'libbpf',
        'libelf',
        'gobgp',
        'log4cpp',
    );
 
    for my $package (@required_packages) {
       print "Install package $package\n";
       my $package_install_start_time = time();

       my $install_res = Fastnetmon::install_package_by_name($package);
  
       my $elapse = time() - $package_install_start_time;

       my $build_time_minutes = sprintf("%.2f", $elapse / 60);

       # Build only long time
       if ($build_time_minutes > 1) {
           print "Package build time: " . int($build_time_minutes) . " Minutes\n";
       }

       unless ($install_res) {
           die "Cannot install package $package: $install_res\n";
       }

       print "\n\n";
    }

    my $install_time = time() - $start_time;
    my $pretty_install_time_in_minutes = sprintf("%.2f", $install_time / 60);

    print "We have built project in $pretty_install_time_in_minutes minutes\n";
}
