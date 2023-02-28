#!/usr/bin/perl

use strict;
use warnings;

use File::Basename;

# Use path to our libraries folder relvant to path where we keep script itself 
use FindBin;
use lib "$FindBin::Bin/perllib";

my $fastnetmon_install_folder = '/opt/fastnetmon-community';
my $library_install_folder = "$fastnetmon_install_folder/libraries";

my $gcc_compiler_path = "$library_install_folder/gcc_12_1_0";

my $default_c_compiler_path = "$gcc_compiler_path/bin/gcc";
my $default_cpp_compiler_path = "$gcc_compiler_path/bin/g++";

my $cmake_path = "$library_install_folder/cmake_3_23_4/bin/cmake";

my $os_type = '';
my $distro_type = '';  
my $distro_version = '';  
my $distro_architecture = '';

my $install_log_path = "/tmp/fastnetmon_install_$$.log";

if (defined($ENV{'CI'}) && $ENV{'CI'}) {
    $install_log_path = "/tmp/fastnetmon_install.log";
}

my $fastnetmon_git_path = 'https://github.com/pavel-odintsov/fastnetmon.git';

my $temp_folder_for_building_project = `mktemp -d /tmp/fastnetmon.build.dir.XXXXXXXXXX`;
chomp $temp_folder_for_building_project;

unless ($temp_folder_for_building_project && -e $temp_folder_for_building_project) {
    die("Can't create temp folder in /tmp for building project: $temp_folder_for_building_project");
}

my $start_time = time();

my $fastnetmon_code_dir = "$temp_folder_for_building_project/fastnetmon/src";

# Used for VyOS and different appliances based on rpm/deb
my $appliance_name = ''; 

my $cpus_number = 1;

# We could pass options to make with this variable
my $make_options = '';

main();

sub get_logical_cpus_number {
    if ($os_type eq 'linux') {
        my @cpuinfo = `cat /proc/cpuinfo`;
        chomp @cpuinfo;
        
        my $cpus_number = scalar grep {/processor/} @cpuinfo;
    
        return $cpus_number;
    } elsif ($os_type eq 'macosx' or $os_type eq 'freebsd') {
        my $cpus_number = `sysctl -n hw.ncpu`;
        chomp $cpus_number;
    }
}

sub install_additional_repositories {
    if ($distro_type eq 'centos') {
        if ($distro_version == 7) {
            print "Install EPEL repository for your system\n"; 
            yum('https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm');
        } elsif ($distro_version == 8) {
            print "Install EPEL repository for your system\n";
            yum('https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm');

            # Part of devel libraries was moved here https://github.com/pavel-odintsov/fastnetmon/issues/801
            print "Enable PowerTools repo\n";
            yum('dnf-plugins-core');
            system("dnf config-manager --set-enabled powertools");
        } elsif ($distro_version == 9) {
            print "Install EPEL repository for your system\n";
            system("dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm");

            print "Install CodeReady Linux Builder repository\n";
            yum('dnf-plugins-core');
            system("dnf config-manager --set-enabled crb");
        }
    }
}

### Functions start here
sub main {
    # Open log file, we need to append it to keep logs for CI in single file
    open my $global_log, ">>", $install_log_path or warn "Cannot open log file: $! $install_log_path";
    print {$global_log} "Install started";

    detect_distribution();

    # Set environment variables to collect more information about installation failures

    $cpus_number = get_logical_cpus_number();

    if (defined($ENV{'CIRCLECI'}) && $ENV{'CIRCLECI'}) { 
        my $circle_ci_cpu_number = 4;
        # We use machine with X CPUs, let's set explicitly X threads, get_logical_cpus_number returns 36 which is not real number of CPU cores
	    $make_options = "-j $circle_ci_cpu_number";
        print "Will use $circle_ci_cpu_number CPUs for build process\n";
    } else {
        if ($cpus_number > 1) {
            print "Will use $cpus_number CPUs for build process\n";
            $make_options = "-j $cpus_number";
        }
    }

    # CentOS base repository is very very poor and we need EPEL for some dependencies
    install_additional_repositories();

    # Refresh information about packages
    init_package_manager();

    unless (-e $library_install_folder) {
        exec_command("mkdir -p $library_install_folder");
    }

    install_fastnetmon();

    my $install_time = time() - $start_time;
    my $pretty_install_time_in_minutes = sprintf("%.2f", $install_time / 60);

    print "We have built project in $pretty_install_time_in_minutes minutes\n";
}

sub exec_command {
    my $command = shift;

    open my $fl, ">>", $install_log_path;
    print {$fl} "We are calling command: $command\n\n";
 
    my $output = `$command >> $install_log_path 2>&1`;
  
    print {$fl} "Command finished with code $?\n\n";

    if ($? == 0) {
        return 1;
    } else {
        return '';
    }
}

sub init_package_manager { 

    print "Update package manager cache\n";
    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        exec_command("apt-get update");
    }
}

# Detect operating system of this machine
sub detect_distribution { 
    # We use following global variables here:
    # $os_type, $distro_type, $distro_version, $appliance_name

    my $uname_s_output = `uname -s`;
    chomp $uname_s_output;

    # uname -a output examples:
    # FreeBSD  10.1-STABLE FreeBSD 10.1-STABLE #0 r278618: Thu Feb 12 13:55:09 UTC 2015     root@:/usr/obj/usr/src/sys/KERNELWITHNETMAP  amd64
    # Darwin MacBook-Pro-Pavel.local 14.5.0 Darwin Kernel Version 14.5.0: Wed Jul 29 02:26:53 PDT 2015; root:xnu-2782.40.9~1/RELEASE_X86_64 x86_64
    # Linux ubuntu 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:43:14 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

    if ($uname_s_output =~ /FreeBSD/) {
        $os_type = 'freebsd';
    } elsif ($uname_s_output =~ /Darwin/) {
        $os_type = 'macosx';
    } elsif ($uname_s_output =~ /Linux/) {
        $os_type = 'linux';
    } else {
        warn "Can't detect platform operating system\n";
    }

    if ($os_type eq 'linux') {
        # x86_64 or i686
        $distro_architecture = `uname -m`;
        chomp $distro_architecture;

        if (-e "/etc/debian_version") {
            # Well, on this step it could be Ubuntu or Debian

            # We need check issue for more details 
            my @issue = `cat /etc/issue`;
            chomp @issue;

            my $issue_first_line = $issue[0];

            # Possible /etc/issue contents: 
            # Debian GNU/Linux 8 \n \l
            # Ubuntu 14.04.2 LTS \n \l
            # Welcome to VyOS - \n \l 
            my $is_proxmox = '';

            # Really hard to detect https://github.com/proxmox/pve-manager/blob/master/bin/pvebanner
            for my $issue_line (@issue) {
                if ($issue_line =~ m/Welcome to the Proxmox Virtual Environment/) {
                    $is_proxmox = 1;
                    $appliance_name = 'proxmox';
                    last;
                }
            }

            if ($issue_first_line =~ m/Debian/ or $is_proxmox) {
                $distro_type = 'debian';

                $distro_version = `cat /etc/debian_version`;
                chomp $distro_version;

                # Debian 6 example: 6.0.10
                # We will try transform it to decimal number
                if ($distro_version =~ /^(\d+\.\d+)\.\d+$/) {
                    $distro_version = $1;
                }
            } elsif ($issue_first_line =~ m/Ubuntu Jammy Jellyfish/) {
                # It's pre release Ubuntu 22.04
                $distro_type = 'ubuntu';
                $distro_version = "22.04";
            } elsif ($issue_first_line =~ m/Ubuntu (\d+(?:\.\d+)?)/) {
                $distro_type = 'ubuntu';
                $distro_version = $1;
            } elsif ($issue_first_line =~ m/VyOS/) {
                # Yes, VyOS is a Debian
                $distro_type = 'debian';
                $appliance_name = 'vyos';

                my $vyos_distro_version = `cat /etc/debian_version`;
                chomp $vyos_distro_version;

                # VyOS have strange version and we should fix it
                if ($vyos_distro_version =~ /^(\d+)\.\d+\.\d+$/) {
                    $distro_version = $1;
                }
            }
        }

        if (-e "/etc/redhat-release") {
            $distro_type = 'centos';

            my $distro_version_raw = `cat /etc/redhat-release`;
            chomp $distro_version_raw;

            # CentOS 6:
            # CentOS release 6.6 (Final)
            # CentOS 7:
            # CentOS Linux release 7.0.1406 (Core) 
            # Fedora release 21 (Twenty One)
            if ($distro_version_raw =~ /(\d+)/) {
                $distro_version = $1;
            }
        }

        if (-e "/etc/gentoo-release") {
            $distro_type = 'gentoo';

            my $distro_version_raw = `cat /etc/gentoo-release`;
            chomp $distro_version_raw;
        }

        unless ($distro_type) {
            die("This distro is unsupported");
        }

        print "We detected your OS as $distro_type Linux $distro_version\n";
    } elsif ($os_type eq 'macosx') {
        my $mac_os_versions_raw = `sw_vers -productVersion`;
        chomp $mac_os_versions_raw;

        if ($mac_os_versions_raw =~ /(\d+\.\d+)/) {
            $distro_version = $1; 
        }

        print "We detected your OS as Mac OS X $distro_version\n";
    } elsif ($os_type eq 'freebsd') {
        my $freebsd_os_version_raw = `uname -r`;
        chomp $freebsd_os_version_raw;

        if ($freebsd_os_version_raw =~ /^(\d+)\.?/) {
            $distro_version = $1;
        }

        print "We detected your OS as FreeBSD $distro_version\n";
    } 
}

sub apt_get {
    my @packages_list = @_; 

    # We install one package per apt-get call because installing multiple packages in one time could fail of one package is broken
    for my $package (@packages_list) {
        exec_command("DEBIAN_FRONTEND=noninteractive apt-get install -y --force-yes $package");

        if ($? != 0) {
            print "Package '$package' install failed with code $?\n"
        }   
    }   
}

sub yum {
    my @packages_list = @_;

    for my $package (@packages_list) {
        exec_command("yum install -y $package");

        if ($? != 0) {
            print "Package '$package' install failed with code $?\n";
        }
    }
}

sub install_fastnetmon_dependencies {
    print "Install FastNetMon dependency list\n";

    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        my @fastnetmon_deps = ("libncurses5-dev", "libpcap-dev");

        apt_get(@fastnetmon_deps);
    } elsif ($distro_type eq 'centos') {
        my @fastnetmon_deps = ('ncurses-devel', 'libpcap-devel');

        yum(@fastnetmon_deps);
    }
}

sub install_fastnetmon {
    install_fastnetmon_dependencies();

    print "Clone FastNetMon repo\n";
    chdir $temp_folder_for_building_project;

    # Pull code
    exec_command("git clone $fastnetmon_git_path");

    if ($? != 0) {
        die "Can't clone source code";
    }

    exec_command("mkdir -p $fastnetmon_code_dir/build");
    chdir "$fastnetmon_code_dir/build";
    
    # We enable Kafka support only for our releases
    # By default it's disabled as we have no cppkafka for many distributions
    my $cmake_params = "-DDO_NOT_USE_SYSTEM_LIBRARIES_FOR_BUILD=ON -DKAFKA_SUPPORT=ON -DBUILD_TESTS=ON";


    # Test that atomics build works as expected
    # $cmake_params .= " -DUSE_NEW_ATOMIC_BUILTINS=ON";

    # We need to specify path to libraries of gcc. Otherwise it will not work well
    my $ld_library_path = "LD_LIBRARY_PATH=$gcc_compiler_path/lib64";

    print "Run cmake to generate make file\n";
    
    my $cmake_result = system("$ld_library_path CC=$default_c_compiler_path CXX=$default_cpp_compiler_path $cmake_path .. $cmake_params");

    if ($cmake_result != 0) {
        die "cmake call failed\n";
    }

    print "Run make to build FastNetMon\n";
    
    my $make_result = system("$ld_library_path make $make_options");

    if ($make_result != 0) {
        die "make call failed\n";
    }

    my $fastnetmon_build_binary_path = "$fastnetmon_code_dir/build/fastnetmon";

    mkdir $fastnetmon_install_folder;

    print "Install fastnetmon to directory $fastnetmon_install_folder\n";
    system("mkdir -p $fastnetmon_install_folder/app/bin");
    exec_command("cp $fastnetmon_build_binary_path $fastnetmon_install_folder/app/bin/fastnetmon");
    exec_command("cp $fastnetmon_code_dir/build/fastnetmon_client $fastnetmon_install_folder/app/bin/fastnetmon_client");
    exec_command("cp $fastnetmon_code_dir/build/fastnetmon_api_client $fastnetmon_install_folder/app/bin/fastnetmon_api_client");

    my $fastnetmon_config_path = "/etc/fastnetmon.conf";
    unless (-e $fastnetmon_config_path) {
        print "Create stub configuration file\n";
        exec_command("cp $fastnetmon_code_dir/fastnetmon.conf $fastnetmon_config_path");
    }
}



