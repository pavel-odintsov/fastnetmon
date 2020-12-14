#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;
use File::Basename;

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

my $library_install_folder = '/opt';
my $we_use_code_from_master = '';

my $ld_library_path_for_make = "";

# We should specify custom compiler path
my $default_c_compiler_path = '/usr/bin/gcc';
my $default_cpp_compiler_path = '/usr/bin/g++';

my $os_type = '';
my $distro_type = '';  
my $distro_version = '';  
my $distro_architecture = '';

my $gcc_version = '9.3.0';

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

my $pf_ring_version = '6.0.3';
my $pf_ring_url = "https://github.com/ntop/PF_RING/archive/v$pf_ring_version.tar.gz";
my $pf_ring_sha = '9fb8080defd1a079ad5f0097e8a8adb5bc264d00';

my $fastnetmon_git_path = 'https://github.com/pavel-odintsov/fastnetmon.git';

my $temp_folder_for_building_project = `mktemp -d /tmp/fastnetmon.build.dir.XXXXXXXXXX`;
chomp $temp_folder_for_building_project;

unless ($temp_folder_for_building_project && -e $temp_folder_for_building_project) {
    fast_die("Can't create temp folder in /tmp for building project: $temp_folder_for_building_project");
}

my $start_time = time();

my $fastnetmon_code_dir = "$temp_folder_for_building_project/fastnetmon/src";

# Official mirror: https://github.com/ntop/nDPI.git
# But we have some patches for NTP and DNS protocols here
my $ndpi_repository = 'https://github.com/pavel-odintsov/nDPI.git';

my $stable_branch_name = 'v1.1.5';

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

my $use_modern_pf_ring = '';

my $show_help = '';

my $install_dependency_packages_only = '';

my $build_fastnetmon_only = '';

my $build_gcc_only = '';

my $build_dependencies_only = '';

# Get options from command line
GetOptions(
    'use-git-master' => \$we_use_code_from_master,
    'use-modern-pf-ring' => \$use_modern_pf_ring,
    'use-mirror' => \$use_mirror,
    'build_fastnetmon_only' => \$build_fastnetmon_only,
    'build_dependencies_only' => \$build_dependencies_only,
    'help' => \$show_help,
    'install_dependency_packages_only' => \$install_dependency_packages_only, 
    'build_gcc_only' => \$build_gcc_only
);

if ($show_help) {
    print "We have following options:\n" .
        "--use-git-master\n" .
        "--use-mirror\n" .
        "--use-modern-pf-ring\n" . 
        "--install_dependency_packages_only\n" . 
        "--build_dependencies_only\n" .
        "--build_fastnetmon_only\n" . 
        "--build_gcc_only\n--help\n";
    exit (0);
}

welcome_message();

# Bump PF_RING version
if ($use_modern_pf_ring) {
    $pf_ring_version = '6.6.0';
    $pf_ring_url = "https://github.com/ntop/PF_RING/archive/$pf_ring_version.tar.gz";
    $pf_ring_sha = '79ff86e48df857e4e884646accfc97bdcdc54b04';
}

my $we_have_ndpi_support = '1';
my $we_have_hiredis_support = '1';
my $we_have_log4cpp_support = '1';
my $we_have_mongo_support = '1';
my $we_have_protobuf_support = '1';
my $we_have_grpc_support = '1';
my $we_have_gobgp_support = '1';

# We allow it only for legacy systems
my $we_have_pfring_support = '';

main();

# Applies colors to terminal if we have this module
sub fast_color {
    if ($have_ansi_color) {
        color(@_);
    }
}

sub welcome_message {
    # Clear screen
    print "\033[2J";
    # Jump to 0.0 position
    print "\033[0;0H";

    print fast_color('bold green');
    print "Hi there!\n\n";
    print fast_color('reset');
    
    print "We need about ten minutes of your time for installing FastNetMon toolkit\n\n";
    print "Also, we have ";

    print fast_color('bold cyan');
    print "FastNetMon Advanced";
    print fast_color('reset');

    print " version with big number of improvements: ";

    print fast_color('bold cyan');
    print "https://fastnetmon.com/fastnetmon-advanced/?utm_source=community_install_script&utm_medium=email\n\n";
    print fast_color('reset');

    print "You could order free one-month trial for Advanced version here ";
    print fast_color('bold cyan');
    print "https://fastnetmon.com/trial/?utm_source=community_install_script&utm_medium=email\n\n";
    print fast_color('reset');

    print "In case of any issues with install script please use ";
    print fast_color('bold cyan');
    print "https://fastnetmon.com/contact/?utm_source=community_install_script&utm_medium=email";
    print fast_color('reset');
    print " to report them\n\n";
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
        if ($distro_version == 6) {
            print "Install EPEL repository for your system\n"; 
            yum('https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm');
        }    

        if ($distro_version == 7) {
            print "Install EPEL repository for your system\n"; 
            yum('https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm');
        }

        if ($distro_version == 8) {
            print "Install EPEL repository for your system\n";
            yum('https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm');

	        # Part of devel libraries was moved here https://github.com/pavel-odintsov/fastnetmon/issues/801
	        print "Enable PowerTools repo\n";
	        yum('dnf-plugins-core');
	        system("yum config-manager --set-enabled PowerTools");
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
        # We use machine with 2 CPUs, let's set explicitly 2 threads, get_logical_cpus_number returns 36 which is not real number of CPU cores
	    $make_options = "-j 2"; 
    } else {
        if ($cpus_number > 1) {
            print "Will use $cpus_number CPUs for build process\n";
            $make_options = "-j $cpus_number";
        }
    }

    # We use PF_RING only for very old Linux distros, all new one should use AF_PACKET
    if ($os_type eq 'linux') {
        if ($distro_type eq 'ubuntu' && $distro_version =~ m/^12\.04/) {
            $we_have_pfring_support = 1;
        }

        if ($distro_type eq 'centos' && $distro_version == 6) {
            $we_have_pfring_support = 1;
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

    if ($build_gcc_only) {
        install_gcc_dependencies();
        install_gcc();
        exit(0);
    }

    # For all platforms we use custom compiler
    init_compiler();
    
    # Install only depencdency packages, we need it to cache installed packages in CI
    if ($install_dependency_packages_only) {
        if ($we_have_pfring_support) {
            install_pf_ring_dependencies();
    	}

        if ($we_have_ndpi_support) {
            install_ndpi_dependencies();
        }

        if ($we_have_protobuf_support) {
            install_protobuf_dependencies();
        }

        if ($we_have_grpc_support) {
            install_grpc_dependencies();
        }

        install_fastnetmon_dependencies();

        exit(0);
    }

    if ($build_dependencies_only) {
        if ($we_have_pfring_support) {
       	   install_pf_ring_dependencies();
           install_pf_ring();
        }

        install_json_c();

        install_openssl();

        install_capnproto();

        install_poco();

        install_gcc_dependencies();

        install_cmake_dependencies();
        install_cmake();
        install_icu();
        install_boost_builder();
        install_boost_dependencies();
        install_boost();

        if ($we_have_ndpi_support) {
	        install_ndpi_dependencies();
            install_ndpi();
        }

        if ($we_have_hiredis_support) {
           install_hiredis();
        }

        if ($we_have_mongo_support) {
            install_mongo_client();
        }

        if ($we_have_protobuf_support) {
	        install_protobuf_dependencies();
            install_protobuf();
        }

        if ($we_have_grpc_support) {
	        install_grpc_dependencies();
            install_grpc();
        }

        if ($we_have_gobgp_support) {
            install_gobgp();
        }
    
        if ($we_have_log4cpp_support) {
            install_log4cpp();
        }

        install_fastnetmon_dependencies();
    }

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

sub install_json_c {
    my $archive_name  = 'json-c-0.13-20171207.tar.gz';
    my $install_path = "$library_install_folder/json-c-0.13";

    if (-e $install_path) {
	    print "json-c was already installed\n";
	    return 1;
    }

    print "Install json library\n";

    chdir $temp_folder_for_building_project;

    print "Download archive\n";

    my $json_c_download_result = download_file("https://github.com/json-c/json-c/archive/$archive_name",
        $archive_name,
        '6fc7fdd11eadd5a05e882df11bb4998219615de2');

    unless ($json_c_download_result) {
        fast_die("Can't download json-c sources");
    }

    print "Uncompress it\n";
    exec_command("tar -xf $archive_name");
    chdir "json-c-json-c-0.13-20171207";

    print "Build it\n";
    exec_command("$configure_options ./configure --prefix=$install_path");

    print "Install it\n";
    exec_command("make $make_options install");
}

sub install_init_scripts {
    # Init file for any systemd aware distro
    my $systemd_distro = '';

    # All new versions of Debian use systemd
    if ($distro_type eq 'debian' && $distro_version > 7) {
        $systemd_distro = 1;
    }

    # All new versions of CentOS/RHEL use systemd
    if ($distro_type eq 'centos' && $distro_version >= 7) {
        $systemd_distro = 1;
    }

    # Some heuristic approach for Debian-like distros
    if (-e "/bin/systemd") {
        $systemd_distro = 1;
    }

    if ($systemd_distro) {
        my $systemd_service_path = "/etc/systemd/system/fastnetmon.service";
        exec_command("cp $fastnetmon_code_dir/fastnetmon.service.in $systemd_service_path");

        exec_command("sed -i 's#\@CMAKE_INSTALL_SBINDIR\@#$library_install_folder/fastnetmon#' $systemd_service_path");

        print "We found systemd enabled distro and created service: fastnetmon.service\n";
        print "You could run it with command: systemctl start fastnetmon.service\n";

        return 1;
    }

    # Init file for CentOS 6
    if ($distro_type eq 'centos' && $distro_version == 6) {
        my $system_init_path = '/etc/init.d/fastnetmon';
        exec_command("cp $fastnetmon_code_dir/fastnetmon_init_script_centos6 $system_init_path");

        exec_command("sed -i 's#/usr/sbin/fastnetmon#$library_install_folder/fastnetmon/fastnetmon#' $system_init_path");

        print "We created service fastnetmon for you\n";
        print "You could run it with command: /etc/init.d/fastnetmon start\n";

        return 1;
    }

    # For Debian Squeeze and Wheezy 
    # And any stable Ubuntu version
    if ( ($distro_type eq 'debian' && ($distro_version == 6 or $distro_version == 7)) or $distro_type eq 'ubuntu') {
        my $init_path_in_src = "$fastnetmon_code_dir/fastnetmon_init_script_debian_6_7";
        my $system_init_path = '/etc/init.d/fastnetmon';

        # Checker for source code version, will work only for 1.1.3+ versions
        if (-e $init_path_in_src) {
           exec_command("cp $init_path_in_src $system_init_path");

            exec_command("sed -i 's#/usr/sbin/fastnetmon#$library_install_folder/fastnetmon/fastnetmon#' $system_init_path");

            print "We created service fastnetmon for you\n";
            print "You could run it with command: /etc/init.d/fastnetmon start\n";

            return 1;
        }
    }
}

sub install_log4cpp {
    my $distro_file_name = 'log4cpp-1.1.1.tar.gz';
    my $log4cpp_url = 'https://sourceforge.net/projects/log4cpp/files/log4cpp-1.1.x%20%28new%29/log4cpp-1.1/log4cpp-1.1.1.tar.gz/download';
    my $log4cpp_install_path = "$library_install_folder/log4cpp1.1.1";

    if (-e $log4cpp_install_path) {
        print "log4cpp was installed\n";
        return 1;
    }

    chdir $temp_folder_for_building_project;

    print "Download log4cpp sources\n";
    my $log4cpp_download_result = download_file($log4cpp_url, $distro_file_name, '23aa5bd7d6f79992c92bad3e1c6d64a34f8fcf68');

    unless ($log4cpp_download_result) {
        fast_die("Can't download log4cpp");
    }

    print "Unpack log4cpp sources\n";
    exec_command("tar -xf $distro_file_name");
    chdir "$temp_folder_for_building_project/log4cpp";

    print "Build log4cpp\n";

    my $configure_res = '';

    # TODO: we need some more reliable way to specify options here
    if ($configure_options) {
        $configure_res = exec_command("$configure_options ./configure --prefix=$log4cpp_install_path");
    } else {
        $configure_res = exec_command("./configure --prefix=$log4cpp_install_path");
    }

    if (!$configure_res) {
        fast_die("Cannot configure log4cpp");
    }

    exec_command("make $make_options install"); 
}

sub install_grpc_dependencies {
    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        apt_get('gcc', 'make', 'autoconf', 'automake', 'git', 'libtool', 'g++', 'python-all-dev', 'python-virtualenv', 'pkg-config');
    } elsif ($distro_type eq 'centos') {
        yum('pkgconfig');    
    }
}

sub install_grpc {
    my $grpc_git_commit = "v1.30.2";

    my $grpc_install_path = "$library_install_folder/grpc_1_30_2";

    if (-e $grpc_install_path) {
	print "gRPC was already installed\n";
        return 1;
    }

    chdir $temp_folder_for_building_project;

    print "Clone gRPC repository\n";
    exec_command("git clone https://github.com/grpc/grpc.git");
    chdir "grpc";

    # For back compatibility with old git
    exec_command("git checkout $grpc_git_commit");

    print "Update project submodules\n";
    exec_command("git submodule update --init");

    ### Patch makefile for custom gcc: https://github.com/grpc/grpc/issues/3893
    exec_command("sed -i '81i DEFAULT_CC=$default_c_compiler_path' Makefile");
    exec_command("sed -i '82i DEFAULT_CXX=$default_cpp_compiler_path' Makefile");

    print "Build gRPC\n";
    # We need to specify PKG config path to pick up our custom OpenSSL instead of system one
    my $make_result = exec_command("$ld_library_path_for_make PKG_CONFIG_PATH=/opt/openssl_1_0_2d/lib/pkgconfig make $make_options");

    unless ($make_result) {
        fast_die( "Could not build gRPC: make failed\n");
    }

    print "Install gRPC\n";
    exec_command("make install prefix=$grpc_install_path");

    1;
}

sub install_gobgp {
    chdir $temp_folder_for_building_project;

    my $gobgp_install_path = "$library_install_folder/gobgp_2_17_0";

    if (-e $gobgp_install_path) {
        print "GoBGP was already installed\n";
	return 1;
    }

    my $distro_file_name = '';
    my $distro_file_hash = '';

    if ($distro_architecture eq 'x86_64') {
	    $distro_file_name = 'gobgp_2.17.0_linux_amd64.tar.gz';
	    $distro_file_hash = '3b12cf212eb7455be4ac2008fe7389666f1bc5ea';
    } elsif ($distro_architecture eq 'i686') {
        $distro_file_name = 'gobgp_2.17.0_linux_386.tar.gz';
        $distro_file_hash = '9d6f031058589618f414b4493b5cfa34230c0505';
    } else {
        fast_die("We do not have GoBGP for your platform, please check: https://github.com/osrg/gobgp/releases for available builds");
    }

    print "Download GoBGP\n";

    my $gobgp_download_result = download_file("https://github.com/osrg/gobgp/releases/download/v2.17.0/$distro_file_name",
        $distro_file_name, $distro_file_hash);

    unless ($gobgp_download_result) {
        fast_die("Can't download gobgp sources");
    }

    exec_command("tar -xf $distro_file_name");

    print "Install gobgp daemon files\n";

    mkdir $gobgp_install_path;
    exec_command("cp gobgp $gobgp_install_path");
    exec_command("cp gobgpd $gobgp_install_path");
}

sub install_protobuf_dependencies {
    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        apt_get('make', 'autoconf', 'automake', 'git', 'libtool', 'curl', "g++");
    }
}

sub install_protobuf {
    chdir $temp_folder_for_building_project;

    my $protobuf_install_path = "$library_install_folder/protobuf_3.11.4";

    if (-e $protobuf_install_path) {
	    print "protobuf was already installed\n";
        return 1;
    }

    my $distro_file_name = 'protobuf-all-3.11.4.tar.gz';

    chdir $temp_folder_for_building_project;
    print "Download protocol buffers\n";

    my $protobuf_download_result = download_file("https://github.com/protocolbuffers/protobuf/releases/download/v3.11.4/$distro_file_name",
        $distro_file_name, '318f4d044078285db7ae69b68e77f148667f98f4');

    unless ($protobuf_download_result) {
        fast_die("Can't download protobuf\n");
    }

    print "Unpack protocol buffers\n";
    exec_command("tar -xf $distro_file_name");

    chdir "protobuf-3.11.4";
    print "Configure protobuf\n";

    print "Execute autogen\n";
    exec_command("./autogen.sh");

    exec_command("$configure_options ./configure --prefix=$protobuf_install_path");

    print "Build protobuf\n";
    exec_command("$ld_library_path_for_make make $make_options install");
    1;
}

sub install_cmake_based_software {
    my ($url_to_archive, $sha1_summ_for_archive, $library_install_path, $cmake_with_options, $make_env_variables) = @_;

    unless ($url_to_archive && $sha1_summ_for_archive && $library_install_path && $cmake_with_options) {
        return '';
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
        die "We could not extract folder name from tar archive: $temp_folder_for_building_project/$file_name\n";
    }

    print "Unpack archive\n";
    my $unpack_result = exec_command("tar -xf $file_name");

    unless ($unpack_result) {
        die "Unpack failed";
    }

    chdir $folder_name_inside_archive;

    unless (-e "CMakeLists.txt") {
        die "We haven't CMakeLists.txt in top project folder! Could not build project";
    }

    unless (-e "build") {
        mkdir "build";
    }

    chdir "build";

    print "Generate make file with cmake\n";
    # print "cmake command: $cmake_with_options\n";
    my $cmake_result = exec_command($cmake_with_options);

    unless ($cmake_result) {
        die "cmake command failed";
    }

    print "Build project with make\n";

    my $make_command = "$make_env_variables make $make_options";
    my $make_result = exec_command($make_command);

    unless ($make_result) {
        die "Make command '$make_command' failed\n";
    } 

    print "Install project to target directory\n";
    my $install_result = exec_command("$make_env_variables make install");

    unless ($install_result) {
        die "Install failed";
    } 

    return 1;
}


sub install_mongo_client {
    my $install_path = "$library_install_folder/mongo_c_driver_1_16_1";
    
    if (-e $install_path) {
        warn "mongo_c_driver is already installed, skip build";
        return 1;
    }    

    # OpenSSL is mandatory for SCRAM-SHA-1 auth mode
    # I also use flag ENABLE_ICU=OFF to disable linking against icu system library. I do no think that we really need it
    my $res = install_cmake_based_software("https://github.com/mongodb/mongo-c-driver/releases/download/1.16.1/mongo-c-driver-1.16.1.tar.gz",
        "f9bd005195895538af821708112bf861090da354",
    $install_path,
    "$ld_library_path_for_make $cmake_path -DENABLE_AUTOMATIC_INIT_AND_CLEANUP=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX:STRING=$library_install_folder/mongo_c_driver_1_16_1 -DCMAKE_C_COMPILER=$default_c_compiler_path -DOPENSSL_ROOT_DIR=$library_install_folder/openssl_1_0_2d -DCMAKE_CXX_COMPILER=$default_cpp_compiler_path -DENABLE_ICU=OFF ..", $ld_library_path_for_make);

    if (!$res) {
        die "Could not install mongo c client\n";
    }    

    return 1;
}

sub install_hiredis {
    my $disto_file_name = 'v0.13.1.tar.gz'; 
    my $hiredis_install_path = "$library_install_folder/libhiredis_0_13";

    if (-e $hiredis_install_path) {
	    print "hiredis was already installed\n";
        return 1;
    }

    chdir $temp_folder_for_building_project;

    print "Download hiredis\n";
    my $hiredis_download_result = download_file("https://github.com/redis/hiredis/archive/$disto_file_name",
        $disto_file_name, '737c4ed101096c5ec47fcaeba847664352d16204');

    unless ($hiredis_download_result) {
        fast_die("Can't download hiredis");
    }

    exec_command("tar -xf $disto_file_name");

    print "Build hiredis\n";
    chdir "hiredis-0.13.1";
    exec_command("PREFIX=$hiredis_install_path make $make_options install");
}

# We use global variable $ndpi_repository here
sub install_ndpi_dependencies {
    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        apt_get('git', 'autoconf', 'libtool', 'automake', 'libpcap-dev');
    } elsif ($distro_type eq 'centos') {
        # We have json-c-devel for CentOS 6 and 7 and will use it for nDPI build system
        yum('git', 'autoconf', 'automake', 'libtool', 'libpcap-devel', 'json-c-devel', 'which');
    }
}

# We use global variable $ndpi_repository here
sub install_ndpi {
    my $ndpi_install_path = "$library_install_folder/ndpi";

    if (-e $ndpi_install_path) {
	    print "nDPI was already installed\n";
        return 1;
    }

    print "Download nDPI\n";

    if (-e "$temp_folder_for_building_project/nDPI") {
        # Get new code from the repository
        chdir "$temp_folder_for_building_project/nDPI";
        exec_command("git pull");
    } else {
        chdir $temp_folder_for_building_project;
        exec_command("git clone $ndpi_repository");
        chdir "$temp_folder_for_building_project/nDPI";
    }   

    print "Configure nDPI\n";
    unless (exec_command("./autogen.sh")) {
        fast_die("Cannot generate configuration for nDPI");
    }

    # We have specified direct path to json-c here because it required for example app compilation
    exec_command("PKG_CONFIG_PATH=$library_install_folder/json-c-0.13/lib/pkgconfig $configure_options ./configure --prefix=$ndpi_install_path");

   if ($? != 0) {
        print "Configure failed\n";
        fast_die("Cannot configure nDPI");
    }

    print "Build and install nDPI\n";
    unless (exec_command("make $make_options install")) {
        fast_die("Cannot build nDPI");
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

sub install_pf_ring_dependencies {
    my $kernel_version = `uname -r`;
    chomp $kernel_version;

    print "Install PF_RING dependencies with package manager\n";

    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        my @debian_packages_for_pfring = ('build-essential', 'bison', 'flex', 'subversion',
            'libnuma-dev', 'wget', 'tar', 'make', 'dpkg-dev', 'dkms', 'debhelper');
  
        # Install kernel headers only when we could compile kernel modules there
        my $kernel_headers_package_name = "linux-headers-$kernel_version";

        push @debian_packages_for_pfring, $kernel_headers_package_name;

        apt_get(@debian_packages_for_pfring);
    } elsif ($distro_type eq 'centos') {
        my @centos_dependency_packages = ('make', 'bison', 'flex', 'gcc', 'gcc-c++', 'dkms', 'numactl-devel', 'subversion');

        # This package is not going to install devel headers for current kernel!
        my $kernel_package_name = 'kernel-devel';

        # Fix deplist for OpenVZ
        if ($kernel_version =~ /stab/) {
            $kernel_package_name = "vzkernel-devel-$kernel_version";
        }

        push @centos_dependency_packages, $kernel_package_name;
  
        my $centos_kernel_version = `uname -r`;
        chomp $centos_kernel_version;
 
        # But this package will install kernel devel headers for current kernel version!
        push @centos_dependency_packages, "$kernel_package_name-$centos_kernel_version";

        yum(@centos_dependency_packages);
    }
}

sub install_pf_ring {
    my $pf_ring_archive_path = "$temp_folder_for_building_project/PF_RING-$pf_ring_version.tar.gz";
    my $pf_ring_sources_path = "$temp_folder_for_building_project/PF_RING-$pf_ring_version";

    my $pf_ring_install_path = "$library_install_folder/pf_ring_$pf_ring_version";

    if (-e $pf_ring_install_path) {
	    print "PF_RING was already installed\n";
        return 1;
    }

    # Sometimes we do not want to build kernel module (Docker, KVM and other cases)
    my $we_could_install_kernel_modules = 1;
    
    if ($we_could_install_kernel_modules) {
        print "Download PF_RING $pf_ring_version sources\n";
        my $pfring_download_result = download_file($pf_ring_url, $pf_ring_archive_path, $pf_ring_sha);

        unless ($pfring_download_result) {
            fast_die("Can't download PF_RING sources");
        }
 
        my $archive_file_name = $pf_ring_archive_path;

        if ($? == 0) {
            print "Unpack PF_RING\n";
            mkdir $pf_ring_sources_path;
            exec_command("tar -xf $pf_ring_archive_path -C $temp_folder_for_building_project");

            print "Build PF_RING kernel module\n";
            exec_command("make $make_options -C $pf_ring_sources_path/kernel clean");
            exec_command("make $make_options -C $pf_ring_sources_path/kernel");
            exec_command("make $make_options -C $pf_ring_sources_path/kernel install");

            print "Unload PF_RING if it was installed earlier\n";
            exec_command("rmmod pf_ring 2>/dev/null");

            print "Load PF_RING module into kernel\n";
            exec_command("modprobe pf_ring");

            my @dmesg = `dmesg`;
            chomp @dmesg;
    
            if (scalar grep (/\[PF_RING\] Initialized correctly/, @dmesg) > 0) {
                print "PF_RING loaded correctly\n";

            } else {
                warn "PF_RING load error! Please fix this issue manually\n";

                # We need this headers for building userspace libs
                exec_command("cp $pf_ring_sources_path/kernel/linux/pf_ring.h /usr/include/linux");
            }
        } else {
            warn "Can't download PF_RING source code. Disable support of PF_RING\n";
        } 
    }

    print "Build PF_RING lib\n";
    # Because we can't run configure from another folder because it can't find ZC dependency :(
    chdir "$pf_ring_sources_path/userland/lib";
    exec_command("$configure_options ./configure --prefix=$pf_ring_install_path");
    exec_command("make $make_options");
    exec_command("make $make_options install"); 
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

sub install_capnproto {
    my $capnp_install_path = "$library_install_folder/capnproto_0_8_0";

    if (-e $capnp_install_path) {
        warn "Cap'n'proto already existis, skip compilation\n";
        return 1;
    }    

    my $configure_arguments = '';

    # We need it to address this bug: https://github.com/capnproto/capnproto/issues/1092
    if ($distro_type eq 'centos' && $distro_version == 6) {
        $configure_arguments = 'LIBS="-lrt"';
    }

    my $res = install_configure_based_software("https://capnproto.org/capnproto-c++-0.8.0.tar.gz", 
        "fbc1c65b32748029f1a09783d3ebe9d496d5fcc4", $capnp_install_path, 
        $configure_arguments);

    unless ($res) { 
        die "Could not install capnproto";
    }    

    return 1;
}

sub install_openssl {
    my $distro_file_name = 'openssl-1.0.2d.tar.gz';
    my $openssl_install_path = "$library_install_folder/openssl_1_0_2d";
 
    if (-e $openssl_install_path) {
        warn "We found already installed openssl in folder $openssl_install_path Skip compilation\n";
        return 1;
    }    

    chdir $temp_folder_for_building_project;
   
    my $openssl_download_result = download_file("https://www.openssl.org/source/old/1.0.2/$distro_file_name", 
        $distro_file_name, 'd01d17b44663e8ffa6a33a5a30053779d9593c3d');

    unless ($openssl_download_result) {    
        die "Could not download openssl";
    }    

    exec_command("tar -xf $distro_file_name");
    chdir "openssl-1.0.2d";

    exec_command("./config shared --prefix=$openssl_install_path");
    exec_command("make -j $make_options");
    exec_command("make install");
    1;   
}


sub install_poco {
    if (-e "$library_install_folder/poco_1_10_0") {
         warn "poco already installed, skip compilation\n";
         return 1;
    }    

    # Actually it's not standard "configure". That is custom bash based script! And it's not handling options suitable for
    # configure (i.e. CC and other)
    my $res = install_configure_based_software("https://github.com/pocoproject/poco/archive/poco-1.10.0-release.tar.gz",
        'cc75c9ca9d21422683ee7d71c5a98aaf72b45bcc', "$library_install_folder/poco_1_10_0",
        "--minimal --shared --no-samples --no-tests --include-path=$library_install_folder/openssl_1_0_2d/include --library-path=$library_install_folder/openssl_1_0_2d/lib --cflags=\"-std=c++11\"");

    unless ($res) {
        die "Could not install poco";
    }    

    return 1;
}


sub install_icu {
    my $distro_file_name = 'icu4c-65_1-src.tgz';

    chdir $temp_folder_for_building_project;

    my $icu_install_path = "$library_install_folder/libicu_65_1";

    if (-e $icu_install_path) {
        warn "Found installed icu at $icu_install_path\n";
        return 1;
    }

    print "Download icu\n";
    my $icu_download_result = download_file("https://github.com/unicode-org/icu/releases/download/release-65-1/$distro_file_name",
        $distro_file_name, 'd1e6b58aea606894cfb2495b6eb1ad533ccd2a25');

    unless ($icu_download_result) {
        fast_die("Could not download ibicu");
    }

    print "Unpack icu\n";
    exec_command("tar -xf $distro_file_name");
    chdir "icu/source";

    print "Build icu\n";
    exec_command("LDFLAGS=\"-Wl,-rpath,$library_install_folder/libicu_65_1/lib\" $configure_options ./configure --prefix=$icu_install_path");
    exec_command("make $make_options");
    exec_command("make $make_options install");
    1;
}


sub install_cmake_dependencies {
    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        apt_get("libssl-dev");
    } elsif ($distro_type eq 'centos') {
        yum("openssl-devel");
    }
}

sub install_cmake {
    print "Install cmake\n";

    my $cmake_install_path = "$library_install_folder/cmake-3.18.4";

    if (-e $cmake_install_path) {
        warn "Found installed cmake at $cmake_install_path\n";
        return 1;
    }

    my $distro_file_name = "cmake-3.18.4.tar.gz";

    chdir $temp_folder_for_building_project;

    print "Download archive\n";
    my $cmake_download_result = download_file("https://github.com/Kitware/CMake/releases/download/v3.18.4/$distro_file_name", $distro_file_name, '73ab5348c881f1a53c250b66848b6ee101c9fe1f');

    unless ($cmake_download_result) {
        fast_die("Can't download cmake\n");
    }

    exec_command("tar -xf $distro_file_name");

    chdir "cmake-3.18.4";

    print "Execute bootstrap, it will need time\n";
    my $boostrap_result = exec_command("$ld_library_path_for_make $configure_options ./bootstrap --prefix=$cmake_install_path");

    unless ($boostrap_result) {
        fast_die("Cannot run bootstrap\n");
    }

    print "Make it\n";
    my $make_command = "$ld_library_path_for_make $configure_options make $make_options";
    my $make_result = exec_command($make_command);

    unless ($make_result) {
        fast_die("Make command '$make_command' failed\n");
    }

    unless (exec_command("$ld_library_path_for_make make install")) {
        fast_die("Cannot install cmake");
    }

    return 1;
}


sub install_boost_builder {
    chdir $temp_folder_for_building_project;

    # We use another name because it uses same name as boost distribution
    my $archive_file_name = '4.3.0.tar.gz';

    my $boost_builder_install_folder = "$library_install_folder/boost_build_4_3_0";

    if (-e $boost_builder_install_folder) {
        warn "Found installed Boost builder at $boost_builder_install_folder\n";
        return 1;
    }

    print "Download boost builder\n";
    my $boost_build_result = download_file("https://github.com/boostorg/build/archive/$archive_file_name", $archive_file_name,
        '');

    unless ($boost_build_result) {
        fast_die("Can't download boost builder\n");
    }

    print "Unpack boost builder\n";
    exec_command("tar -xf $archive_file_name");

    unless (chdir "build-4.3.0") {
        fast_die("Cannot do chdir to build boost folder\n");
    }

    print "Build Boost builder\n";
    my $bootstrap_result = exec_command("CC=$default_c_compiler_path CXX=$default_cpp_compiler_path  ./bootstrap.sh --with-toolset=gcc");

    unless ($bootstrap_result) {
        fast_die("bootstrap of Boost Builder failed, please check logs\n");
    }

    # We should specify toolset here if we want to do build with custom compiler
    my $b2_install_result = exec_command("$ld_library_path_for_make ./b2 install --prefix=$boost_builder_install_folder");

    unless ($b2_install_result) {
        fast_die("Can't execute b2 install\n");
    }

    1;
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
    my $gcc_download_result = download_file("ftp://ftp.mpi-sb.mpg.de/pub/gnu/mirror/gcc.gnu.org/pub/gcc/releases/gcc-$gcc_version/$archive_file_name", $archive_file_name, 'd93d8950229b23d7e7c5cd0037fb4a51e3ce3a19');

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

# We need it to recompress Boost source code
sub install_boost_dependencies {
    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        apt_get("bzip2");
    } elsif ($distro_type eq 'centos') {
        yum("bzip2");
    }
}

sub install_boost {
    my $boost_install_path = "$library_install_folder/boost_1_74_0";

    if (-e $boost_install_path) {
        warn "Boost libraries already exist in $boost_install_path. Skip build process\n";
        return 1;
    }

    chdir $library_install_folder;
    my $archive_file_name = 'boost_1_74_0.tar.gz';

    print "Install Boost dependencies\n";
   
    my $url_boost = "https://dl.bintray.com/boostorg/release/1.74.0/source/boost_1_74_0.tar.bz2";

    # For some reasons we cannot download default URL on Debian 8 
    if ($distro_type eq 'debian' && int($distro_version) == 8) {
        $url_boost = "http://ftp.osuosl.org/pub/blfs/conglomeration/boost/boost_1_74_0.tar.bz2";
    }
    

    print "Download Boost source code\n";
    my $boost_download_result = download_file($url_boost, $archive_file_name, 'f82c0d8685b4d0e3971e8e2a8f9ef1551412c125');

    unless ($boost_download_result) {
        fast_die("Can't download Boost source code\n");
    }

    print "Unpack Boost source code\n";
    exec_command("tar -xf $archive_file_name");

    my $folder_name_inside_archive = 'boost_1_74_0';

    print "Fix permissions\n";
    # Fix permissions because they are broken inside official archive
    exec_command("find $folder_name_inside_archive -type f -exec chmod 644 {} \\;");
    exec_command("find $folder_name_inside_archive -type d -exec chmod 755 {} \\;");
    exec_command("chown -R root:root $folder_name_inside_archive");

    print "Remove archive\n";
    unlink "$archive_file_name";

    chdir $folder_name_inside_archive;

    my $boost_build_threads = $cpus_number;

    # Boost compilation needs lots of memory, we need to reduce number of threads on CircleCI
    if (defined($ENV{'CI'}) && $ENV{'CI'}) {
        $boost_build_threads = 1;
    }

    print "Build Boost\n";
    # We have troubles when run this code with vzctl exec so we should add custom compiler in path 
    # linkflags is required to specify custom path to libicu from regexp library
    my $b2_build_result = exec_command("$ld_library_path_for_make $library_install_folder/boost_build_4_3_0/bin/b2 -j $boost_build_threads -sICU_PATH=$library_install_folder/libicu_65_1 linkflags=\"-Wl,-rpath,$library_install_folder/libicu_65_1/lib\" --build-dir=$temp_folder_for_building_project/boost_build_temp_directory_1_7_4 link=shared --without-test --without-python --without-wave --without-log --without-mpi");

    unless ($b2_build_result) {
        die "Can't execute b2 build correctly\n";
    }

    1;
}


sub install_fastnetmon_dependencies {
    print "Install FastNetMon dependency list\n";

    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        my @fastnetmon_deps = ("git", "g++", "gcc", "libgpm-dev", "libncurses5-dev",
            "liblog4cpp5-dev", "libnuma-dev", "libpcap-dev", "cmake", "pkg-config",
        );

        apt_get(@fastnetmon_deps);
    } elsif ($distro_type eq 'centos') {
        my @fastnetmon_deps = ('git', 'make', 'gcc', 'gcc-c++',
            'ncurses-devel', 'libpcap-devel',
            'gpm-devel', 'cmake', 'pkgconfig',
        );

        if ($distro_type eq 'centos' && int($distro_version) == 7) {
            push @fastnetmon_deps, 'net-tools';
        }

        yum(@fastnetmon_deps);
    }
}

sub install_fastnetmon {
    print "Clone FastNetMon repo\n";
    chdir $temp_folder_for_building_project;

    if (-e $fastnetmon_code_dir) {
        # Code already downloaded
        chdir $fastnetmon_code_dir;

        # Switch to master if we on stable branch
        if ($we_use_code_from_master) {
            exec_command("git checkout master");
            printf("\n");
        }

        exec_command("git pull");
    } else {
        # Pull code
        exec_command("git clone $fastnetmon_git_path");

        if ($? != 0) {
            fast_die("Can't clone source code");
        }
    }

    unless ($we_use_code_from_master) {
        # We use this approach because older git versions do not support git clone -b ... correctly
        # warning: Remote branch v1.1.2 not found in upstream origin, using HEAD instead
        chdir "fastnetmon";
        exec_command("git checkout $stable_branch_name");
    } 

    exec_command("mkdir -p $fastnetmon_code_dir/build");
    chdir "$fastnetmon_code_dir/build";

    my $cmake_params = "";

    if ($we_have_pfring_support) {
        $cmake_params .= " -DENABLE_PF_RING_SUPPORT=ON";
    }
   
    if ($distro_type eq 'centos' && $distro_version == 6) {
        # Disable cmake script from Boost package because it's broken:
        # http://public.kitware.com/Bug/view.php?id=15270
        $cmake_params .= " -DBoost_NO_BOOST_CMAKE=BOOL:ON";
    }

    # Bump version in cmake build system
    if ($use_modern_pf_ring) {
        system("sed -i 's/pf_ring_6.0.3/pf_ring_$pf_ring_version/' ../CMakeLists.txt")
    }

    # Fix dependencies for Netmap in 1.1.4
    if ($distro_type eq 'centos' && int($distro_version) == 6) {
        system("sed -i 's/netmap_plugin fastnetmon_packet_parser/netmap_plugin fastnetmon_packet_parser unified_parser/' ../CMakeLists.txt")
    }

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

    my $fastnetmon_dir = "$library_install_folder/fastnetmon";
    my $fastnetmon_build_binary_path = "$fastnetmon_code_dir/build/fastnetmon";

    unless (-e $fastnetmon_build_binary_path) {
        fast_die("Can't build fastnetmon!");
    }

    mkdir $fastnetmon_dir;

    print "Install fastnetmon to dir $fastnetmon_dir\n";
    exec_command("cp $fastnetmon_build_binary_path $fastnetmon_dir/fastnetmon");
    exec_command("cp $fastnetmon_code_dir/build/fastnetmon_client $fastnetmon_dir/fastnetmon_client");

    if (-e "$fastnetmon_code_dir/build/fastnetmon_api_client") {
        exec_command("cp $fastnetmon_code_dir/build/fastnetmon_api_client $fastnetmon_dir/fastnetmon_api_client");
    }

    my $fastnetmon_config_path = "/etc/fastnetmon.conf";
    unless (-e $fastnetmon_config_path) {
        print "Create stub configuration file\n";
        exec_command("cp $fastnetmon_code_dir/fastnetmon.conf $fastnetmon_config_path");
    }

    print "If you have any issues, please check /var/log/fastnetmon.log file contents\n";
    print "Please add your subnets in /etc/networks_list in CIDR format one subnet per line\n";

    my $init_script_result = install_init_scripts();

    # Print unified run message 
    unless ($init_script_result) {
        print "You can run fastnetmon with command: $fastnetmon_dir/fastnetmon\n";
    }
}



