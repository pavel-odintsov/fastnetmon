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

    print "Your machine has $cpus_number CPUs\n";

    # We could get huge speed benefits with this option
    if ($cpus_number > 1) { 
        print "You have really nice server with $cpus_number CPU's and we will use they all for build process :)\n";
        $make_options = "-j $cpus_number";
    }

    # Install build dependencies
    my $dependencies_install_start_time = time();
    install_build_dependencies();

    print "Installed dependencies in ", time() - $dependencies_install_start_time, " seconds\n";

    # Init environment
    init_compiler();

    # We do not use prefix "lib" in names as all of them are libs and it's meaning less
    # We use target folder names in this list for clarity
    # Versions may be in different formats and we do not use them yet
    my @required_packages = (
        # 'gcc', # we build it separately as it requires excessive amount of time
        'openssl_1_1_1q',
        'cmake_3_23_4',
        'boost_build_4_9_2',
        'icu_65_1',
        'boost_1_80_0',
        'capnproto_0_8_0',
        'hiredis_0_14',
        'mongo_c_driver_1_23_0',
        
        # gRPC dependencies 
        're2_2022_12_01',
        'abseil_2022_06_23',        
        'zlib_1_2_13',,
        'cares_1_18_1',

        'protobuf_21_12',
        'grpc_1_49_2',
        'bpf_1_0_1',
        'elfutils_0_186',
        'gobgp_2_27_0',
        'log4cpp_1_1_3',
    );

    # Accept package name from command line argument
    if (scalar @ARGV > 0) {
        @required_packages = @ARGV;
    }

    # To guarantee that binary dependencies are not altered in storage side we store their hashes in repository
    my $binary_build_hashes = { 
        'gcc_12_1_0' => {
            'debian:10'           => '2c18964400a6660eae4ee36369c50829fda4ad4ee049c29aa1fd925bf96c3f8eed3ecb619cc02c6f470d0170d56aee1c840a4ca58d8132ca7ae395759aa49fc7',
            'debian:11'           => '3ad28bf950a7be070f1de9b3184f1fe9f42405cdbc0f980ab97e13d571a5be1441963a43304d784c135a43278454149039bd2a6252035c7755d4ba5e0eb41480',
            'debian:bookworm/sid' => '907bf0bb451c5575105695a98c3b9c61ff67ad607bcd6a133342dfddd80d8eac69c7af9f97d215a7d4469d4885e5d6914766c77db8def4efa92637ab2c12a515',
            'ubuntu:16_04'        => '433789f72e40cb8358ea564f322d6e6c117f6728e5e1f16310624ee2606a1d662dad750c90ac60404916aaad1bbf585968099fffca178d716007454e05c49237',
            'centos:7'            => 'f7bb6b23d338fa80e1a72912d001ef926cbeb1df26f53d4c75d5e20ffe107e146637cb583edd08d02d252fc1bb93b2af6b827bd953713a9f55de148fb10b55aa',
        },
        'openssl_1_1_1q'        => {}, 
        'cmake_3_23_4'          => {},
        'boost_build_4_9_2'     => {},
        'icu_65_1'              => {},
        'boost_1_80_0'          => {},
        'capnproto_0_8_0'       => {},
        'hiredis_0_14'          => {},
        'mongo_c_driver_1_23_0' => {},
        're2_2022_12_01'        => {},
        'abseil_2022_06_23'     => {},
        'zlib_1_2_13'           => {},
        'cares_1_18_1'          => {},
        'protobuf_21_12'        => {},
        'grpc_1_49_2'           => {},
        'bpf_1_0_1'             => {},
        'elfutils_0_186'        => {},
        'gobgp_2_27_0'          => {},
        'log4cpp_1_1_3'         => {},
    };

    for my $package (@required_packages) {
        print "Install package $package\n";
        my $package_install_start_time = time();

        # We need to get package name from our folder name
        # We use regular expression which matches first part of folder name before we observe any numeric digits after _ (XXX_12345)
        # Name may be multi word like: aaa_bbb_123
        my ($function_name) = $package =~ m/^(.*?)_\d/;

        # Check that package is not installed
        my $package_install_path = "$library_install_folder/$package";

        if (-e $package_install_path) {
            warn "$package is installed, skip build\n";
            next;
        }

        # This check just validates that entry for package exists in $binary_build_hashes
        # But it does not validate that anything in that entry is populated
        # When add new package you just need to add it as empty hash first
        # And then populate with hashes
        my $binary_hash = $binary_build_hashes->{$package}; 

        unless ($binary_hash) {
            die "Binary hash does not exist for $package, please do fresh build and add hash for it\n";
        }

        # Try to retrieve it from S3 bucket 
        my $get_from_cache = Fastnetmon::get_library_binary_build_from_google_storage($package, $binary_hash);

        if ($get_from_cache == 1) {
            print "Got $package from cache\n";
            next;
        }

        # In case of any issues with hashes we must break build procedure to raise attention
        if ($get_from_cache == 2) {
            die "Detected hash issues for package $package, stop build process, it may be sign of data tampering, manual checking is needed\n";
        }

        # We can reach this step only if file did not exist previously
        print "Cannot get package $package from cache, starting build procedure\n";

        # We provide full package name i.e. package_1_2_3 as second argument as we will use it as name for installation folder
        my $install_res = Fastnetmon::install_package_by_name($function_name, $package);
 
        unless ($install_res) {
            die "Cannot install package $package using handler $function_name: $install_res\n";
        }

        # We successfully built it, let's upload it to cache

        my $elapse = time() - $package_install_start_time;

        my $build_time_minutes = sprintf("%.2f", $elapse / 60);

        # Build only long time
        if ($build_time_minutes > 1) {
            print "Package build time: " . int($build_time_minutes) . " Minutes\n";
        }

        # Upload successfully built package to S3
        my $upload_binary_res = Fastnetmon::upload_binary_build_to_google_storage($package);

        # We can ignore upload failures as they're not critical
        if (!$upload_binary_res) {
            warn "Cannot upload dependency to cache\n";
            next;
        }


        print "\n\n";
    }

    my $install_time = time() - $start_time;
    my $pretty_install_time_in_minutes = sprintf("%.2f", $install_time / 60);

    print "We have built project in $pretty_install_time_in_minutes minutes\n";
}
