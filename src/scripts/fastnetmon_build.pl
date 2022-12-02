#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;
use File::Basename;

# Use path to our libraries folder relvant to path where we keep script itself 
use FindBin;
use lib "$FindBin::Bin/perllib";

# It's from base system
use Archive::Tar;

my $have_ansi_color = '';

# We should handle cases when customer does not have perl modules package installed
BEGIN {
    unless (eval "use Term::ANSIColor") {
	# warn "Cannot load module Term::ANSIColor";
    } else {
        $have_ansi_color = 1;
    }
}

my $fastnetmon_install_folder = '/opt/fastnetmon-community';
my $library_install_folder = "$fastnetmon_install_folder/libraries";

my $ld_library_path_for_make = "";

# We should specify custom compiler path
my $default_c_compiler_path = '/usr/bin/gcc';
my $default_cpp_compiler_path = '/usr/bin/g++';

my $os_type = '';
my $distro_type = '';  
my $distro_version = '';  
my $distro_architecture = '';

my $gcc_version = '12.1.0';

# We need it for all OpenSSL dependencies
my $openssl_folder_name = "openssl_1_1_1q";

my $user_email = '';

my $install_log_path = "/tmp/fastnetmon_install_$$.log";

if (defined($ENV{'CI'}) && $ENV{'CI'}) {
    $install_log_path = "/tmp/fastnetmon_install.log";
}

# For all libs build we use custom cmake
my $cmake_path = "$library_install_folder/cmake-3.18.4/bin/cmake";

# die wrapper to send message to tracking server
sub fast_die {
    my $message = shift;

    print "$message Please share $install_log_path with FastNetMon team at GitHub to get help: https://github.com/pavel-odintsov/fastnetmon/issues/new\n";

    exit(1);
}

my $fastnetmon_git_path = 'https://github.com/pavel-odintsov/fastnetmon.git';

my $temp_folder_for_building_project = `mktemp -d /tmp/fastnetmon.build.dir.XXXXXXXXXX`;
chomp $temp_folder_for_building_project;

unless ($temp_folder_for_building_project && -e $temp_folder_for_building_project) {
    fast_die("Can't create temp folder in /tmp for building project: $temp_folder_for_building_project");
}

my $start_time = time();

my $fastnetmon_code_dir = "$temp_folder_for_building_project/fastnetmon/src";

# By default do not use mirror
my $use_mirror = '';

my $mirror_url = 'https://github.com/pavel-odintsov/fastnetmon_dependencies/raw/master/files'; 

# Used for VyOS and different appliances based on rpm/deb
my $appliance_name = ''; 

my $cpus_number = 1;

# We could pass options to make with this variable
my $make_options = '';

# We could pass options to configure with this variable
my $configure_options = '';

my $show_help = '';

my $build_fastnetmon_only = '';

my $build_gcc_only = '';

# Get options from command line
GetOptions(
    'use-mirror' => \$use_mirror,
    'build_fastnetmon_only' => \$build_fastnetmon_only,
    'help' => \$show_help,
    'build_gcc_only' => \$build_gcc_only
);

if ($show_help) {
    print "We have following options:\n" .
        "--use-git-master\n" .
        "--use-mirror\n" .
        "--build_fastnetmon_only\n" . 
        "--build_gcc_only\n--help\n";
    exit (0);
}

welcome_message();

main();

# Applies colors to terminal if we have this module
sub fast_color {
    if ($have_ansi_color) {
        color(@_);
    }
}

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

# This code will init global compiler settings used in options for other packages build
sub init_compiler {
    # 530 instead of 5.3.0
    my $gcc_version_for_path = $gcc_version;
    $gcc_version_for_path =~ s/\.//g;

    # We are using this for Boost build system
    # 5.3 instead of 5.3.0
    my $gcc_version_only_major = $gcc_version;
    $gcc_version_only_major =~ s/\.\d$//;

    $default_c_compiler_path = "$library_install_folder/gcc$gcc_version_for_path/bin/gcc";
    $default_cpp_compiler_path = "$library_install_folder/gcc$gcc_version_for_path/bin/g++";


    # Add new compiler to configure options
    # It's mandatory for log4cpp
    $configure_options = "CC=$default_c_compiler_path CXX=$default_cpp_compiler_path";


    my @make_library_path_list_options = ("$library_install_folder/gcc$gcc_version_for_path/lib64");


    $ld_library_path_for_make = "LD_LIBRARY_PATH=" . join ':', @make_library_path_list_options;

    # More detailes about jam lookup: http://www.boost.org/build/doc/html/bbv2/overview/configuration.html

    # We use non standard gcc compiler for Boost builder and Boost and specify it this way
    open my $fl, ">", "/root/user-config.jam" or die "Can't open $! file for writing manifest\n";
    print {$fl} "using gcc : $gcc_version_only_major : $default_cpp_compiler_path ;\n";
    close $fl;

    # When we run it with vzctl exec we ahve broken env and should put config in /etc too
    open my $etcfl, ">", "/etc/user-config.jam" or die "Can't open $! file for writing manifest\n";
    print {$etcfl} "using gcc : $gcc_version_only_major : $default_cpp_compiler_path ;\n";
    close $etcfl;
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

    # Install standard tools for building packages
    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        my @debian_packages_for_build = ('build-essential', 'make', 'tar', 'wget');

        apt_get(@debian_packages_for_build);
    } elsif ($distro_type eq 'centos') {
        my @centos_dependency_packages = ('make', 'gcc', 'gcc-c++');

        yum(@centos_dependency_packages);
    }

    unless (-e $library_install_folder) {
        exec_command("mkdir -p $library_install_folder");
    }


    if ($build_gcc_only) {
        install_gcc_dependencies();
        install_gcc();
        exit(0);
    }

    # For all platforms we use custom compiler
    init_compiler();
    
    if ($build_fastnetmon_only) {
        install_fastnetmon();
        exit(0);
    }

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

sub get_sha1_sum {
    my $path = shift;

    if ($os_type eq 'freebsd') {
        # # We should not use 'use' here because we haven't this package on non FreeBSD systems by default
        require Digest::SHA;

        # SHA1
        my $sha = Digest::SHA->new(1);

        $sha->addfile($path);

        return $sha->hexdigest; 
    }

    my $hasher_name = '';

    if ($os_type eq 'macosx') {
        $hasher_name = 'shasum';
    } elsif ($os_type eq 'freebsd') {
        $hasher_name = 'sha1';
    } else {
        # Linux
        $hasher_name = 'sha1sum';
    }

    my $output = `$hasher_name $path`;
    chomp $output;
   
    my ($sha1) = ($output =~ m/^(\w+)\s+/);

    return $sha1;
}

sub download_file {
    my ($url, $path, $expected_sha1_checksumm) = @_;

    # We use pretty strange format for $path and need to sue special function to extract it
    my ($path_filename, $path_dirs, $path_suffix) = fileparse($path);

    # $path_filename
    if ($use_mirror) {
        $url = $mirror_url . "/" . $path_filename;
    }

    `wget --no-check-certificate --quiet '$url' -O$path`;

    if ($? != 0) {
        print "We can't download archive $url correctly\n";
        return '';
    }

    if ($expected_sha1_checksumm) {
        my $calculated_checksumm = get_sha1_sum($path);

        if ($calculated_checksumm eq $expected_sha1_checksumm) {
            return 1;
        } else {
            print "Downloaded archive has incorrect sha1: $calculated_checksumm expected: $expected_sha1_checksumm\n";
            return '';
        }      
    } else {
        return 1;
    }     
}

sub init_package_manager { 

    print "Update package manager cache\n";
    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        exec_command("apt-get update");
    }
}

sub read_file {
    my $file_name = shift;

    my $res = open my $fl, "<", $file_name;

    unless ($res) {
        return "";
    }

    my $content = join '', <$fl>;
    chomp $content;

    return $content;
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
            fast_die("This distro is unsupported, please do manual install");
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


# Get folder name from archive
sub get_folder_name_inside_archive {
    my $file_path = shift;

    unless ($file_path && -e $file_path) {
        return '';
    }

    my $tar = Archive::Tar->new;
    $tar->read($file_path);

    for my $file($tar->list_files()) {
        # if name has / in the end we could assume it's folder
        if ($file =~ m#/$#) {
            return $file;
        }
    }

    # For some reasons we can have case when we do not have top level folder alone but we can extract it from path:
    # libcmime-0.2.1/VERSION
    for my $file($tar->list_files()) {
        # if name has / in the end we could assume it's folder
        if ($file =~ m#(.*?)/.*+$#) {
            return $1;
        }
    }

    return '';
}

# Extract file name from URL
# https://github.com/mongodb/mongo-cxx-driver/archive/r3.0.0-rc0.tar.gz => r3.0.0-rc0.tar.gz
sub get_file_name_from_url {
    my $url = shift;

    # Remove prefix
    $url =~ s#https?://##;
    my @components = split '/', $url;

    return $components[-1];
}

sub install_configure_based_software {
    my ($url_to_archive, $sha1_summ_for_archive, $library_install_path, $configure_options) = @_;

    unless ($url_to_archive && $sha1_summ_for_archive && $library_install_path) {
        warn "You haven't specified all mandatory arguments for install_configure_based_software\n";
        return '';
    }

    unless (defined($configure_options)) {
        $configure_options = '';
    }

    chdir $temp_folder_for_building_project;

    my $file_name = get_file_name_from_url($url_to_archive);

    unless ($file_name) {
        die "Could not extract file name from URL $url_to_archive";
    }

    print "Download archive\n";
    my $archive_download_result = download_file($url_to_archive, $file_name, $sha1_summ_for_archive);

    unless ($archive_download_result) {
        die "Could not download URL $url_to_archive";
    }

    unless (-e $file_name) {
        die "Could not find downloaded file in current folder";
    }

    print "Read file list inside archive\n";
    my $folder_name_inside_archive = get_folder_name_inside_archive("$temp_folder_for_building_project/$file_name");

    unless ($folder_name_inside_archive) {
        die "We could not extract folder name from tar archive '$temp_folder_for_building_project/$file_name'\n";
    }

    print "Unpack archive\n";
    my $unpack_result = exec_command("tar -xf $file_name");

    unless ($unpack_result) {
        die "Unpack failed";
    }

    chdir $folder_name_inside_archive;

    unless (-e "configure") {
        die "We haven't configure script here";
    }

    print "Execute configure\n";
    my $configure_command = "CC=$default_c_compiler_path CXX=$default_cpp_compiler_path ./configure --prefix=$library_install_path $configure_options";

    my $configure_result = exec_command($configure_command);

    unless ($configure_result) {
        die "Configure failed";
    }

    ### TODO: this is ugly thing! But here you could find hack for poco libraries
    if ($url_to_archive =~ m/Poco/i) {
        exec_command("sed -i 's#^CC .*#CC = $default_c_compiler_path#' build/config/Linux");
        exec_command("sed -i 's#^CXX .*#CXX = $default_cpp_compiler_path#' build/config/Linux");

        #print `cat build/config/Linux`;
    }

    # librdkafka does not like make+make install approach, we should use them one by one
    print "Execute make\n";

    my $make_result = exec_command("$ld_library_path_for_make make $make_options");

    unless ($make_result) {
        die "Make failed";
    }

    print "Execute make install\n";
    # We explicitly added path to library folders from our custom compiler here
    my $make_install_result = exec_command("$ld_library_path_for_make make install");

    unless ($make_install_result) {
        die "Make install failed";
    }

    return 1;
}

sub install_gcc_dependencies {
    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        my @dependency_list = ('libmpfr-dev', 'libmpc-dev', 'libgmp-dev');
        apt_get(@dependency_list);
    } elsif ($distro_type eq 'centos') {
        yum('gmp-devel', 'mpfr-devel', 'libmpc-devel', 'diffutils');
    }
}

sub install_gcc {
    # 530 instead of 5.3.0
    my $gcc_version_for_path = $gcc_version;
    $gcc_version_for_path =~ s/\.//g;

    my $gcc_package_install_path = "$library_install_folder/gcc$gcc_version_for_path";

    if (-e $gcc_package_install_path) {
        warn "Found already installed gcc in $gcc_package_install_path. Skip compilation\n";
        return '1'; 
    }    

    print "Download gcc archive\n";
    chdir $temp_folder_for_building_project;
 
    my $archive_file_name = "gcc-$gcc_version.tar.gz";
    my $gcc_download_result = download_file("ftp://ftp.mpi-sb.mpg.de/pub/gnu/mirror/gcc.gnu.org/pub/gcc/releases/gcc-$gcc_version/$archive_file_name", $archive_file_name, '7e79c695a0380ac838fa7c876a121cd28a73a9f5');

    unless ($gcc_download_result) {
        die "Can't download gcc sources\n";
    }    

    print "Unpack archive\n";
    unless (exec_command("tar -xf $archive_file_name")) {
        die "Cannot unpack gcc";
    }

    # Remove source archive
    unlink "$archive_file_name";
    
    unless (exec_command("mkdir $temp_folder_for_building_project/gcc-$gcc_version-objdir")) {
        die "Cannot crete objdir";
    }

    chdir "$temp_folder_for_building_project/gcc-$gcc_version-objdir";

    print "Configure build system\n";
    # We are using  --enable-host-shared because we should build gcc as dynamic library for jit compiler purposes
    unless (exec_command("$temp_folder_for_building_project/gcc-$gcc_version/configure --prefix=$gcc_package_install_path --enable-languages=c,c++,jit  --enable-host-shared --disable-multilib")) {
        die "Cannot configure gcc";
    }

    print "Build gcc\n";

    unless( exec_command("make $make_options")) {
        die "Cannot make gcc";
    }

    print "Install gcc\n";

    unless (exec_command("make $make_options install")) {
        die "Cannot make install";
    }

    return 1;
}

sub install_fastnetmon {
    print "Clone FastNetMon repo\n";
    chdir $temp_folder_for_building_project;

    if (-e $fastnetmon_code_dir) {
        # Code already downloaded
        chdir $fastnetmon_code_dir;

        exec_command("git checkout master");
        printf("\n");

        exec_command("git pull");
    } else {
        # Pull code
        exec_command("git clone $fastnetmon_git_path");

        if ($? != 0) {
            fast_die("Can't clone source code");
        }
    }

    exec_command("mkdir -p $fastnetmon_code_dir/build");
    chdir "$fastnetmon_code_dir/build";

    my $cmake_params = "";


    # Test that atomics build works as expected
    # $cmake_params .= " -DUSE_NEW_ATOMIC_BUILTINS=ON";

    # We use $configure_options to pass CC and CXX variables about custom compiler when we use it 
    if ((defined($ENV{'TRAVIS'}) && $ENV{'TRAVIS'}) or (defined($ENV{'CI'}) && $ENV{'CI'})) {
        system("$configure_options $ld_library_path_for_make $cmake_path .. $cmake_params");
        system("$ld_library_path_for_make make $make_options");
    } else {
        print "Run cmake to generate make file\n";
        system("$configure_options $ld_library_path_for_make $cmake_path .. $cmake_params >> $install_log_path 2>&1");

        print "Run make to build FastNetMon\n";
        system("$ld_library_path_for_make make $make_options >> $install_log_path 2>&1");
    }

    my $fastnetmon_build_binary_path = "$fastnetmon_code_dir/build/fastnetmon";

    unless (-e $fastnetmon_build_binary_path) {
        fast_die("Can't build fastnetmon!");
    }

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



