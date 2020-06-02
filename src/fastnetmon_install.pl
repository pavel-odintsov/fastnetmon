#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;
use File::Basename;

my $have_ansi_color = '';

# We should handle cases when customer does not have perl modules package installed
BEGIN {
    unless (eval "use Term::ANSIColor") {
	# warn "Cannot load module Term::ANSIColor";
    } else {
        $have_ansi_color = 1;
    }
}

my $we_use_code_from_master = '';

my $os_type = '';
my $distro_type = '';  
my $distro_version = '';  
my $distro_architecture = '';

my $user_email = '';

my $install_log_path = "/tmp/fastnetmon_install_$$.log";

if (defined($ENV{'CI'}) && $ENV{'CI'}) {
    $install_log_path = "/tmp/fastnetmon_install.log";
}

# For all lib build we use custom cmake
my $cmake_path = "cmake";

# So, you could disable this option but without this feature we could not improve FastNetMon for your distribution
my $do_not_track_me = '';

sub send_tracking_information {
    my $step = shift;

    unless ($do_not_track_me) {
        my $stats_url = "http://178.62.227.110/new_fastnetmon_installation";
        my $post_data = "distro_type=$distro_type&os_type=$os_type&distro_version=$distro_version&distro_architecture=$distro_architecture&step=$step&we_use_code_from_master=$we_use_code_from_master&user_email=$user_email";
        my $user_agent = 'FastNetMon install tracker v1';

        `wget --post-data="$post_data" --user-agent="$user_agent" -q '$stats_url' -o /dev/null`;
    } 
}


# die wrapper to send message to tracking server
sub fast_die {
    my $message = shift;

	# Report failed installs
	send_tracking_information("error");

    # Send detailed report about issue to Sentry
    unless ($do_not_track_me) {
        system("SENTRY_DSN=https://121eca215532431cb7521eafdbca23d3:292cfd7ac2af46a7bc32356141e62592\@sentry.io/1504559 /opt/sentry-cli " .
            " send-event -m \"$message\" --logfile $install_log_path");
    }

    die "$message Please share $install_log_path with FastNetMon team at GitHub to get help: https://github.com/pavel-odintsov/fastnetmon/issues/new\n";
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

# By default use mirror
my $use_mirror = 1;

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

my $enable_gobgp_backend = '';
my $enable_api = '';

my $install_dependency_packages_only = '';

my $build_boost = '';

my $do_not_use_mirror = '';

# Get options from command line
GetOptions(
    'use-git-master' => \$we_use_code_from_master,
    'do-not-track-me' => \$do_not_track_me,
    'use-modern-pf-ring' => \$use_modern_pf_ring,
    'gobgp' => \$enable_gobgp_backend,
    'api' => \$enable_api,
    'boost' => \$build_boost,
    'do-not-use-mirror' => \$do_not_use_mirror,
    'help' => \$show_help,
    'install_dependency_packages_only' => \$install_dependency_packages_only, 
);

if ($show_help) {
    print "We have following options:\n--use-git-master\n--do-not-use-mirror\n--do-not-track-me\n--use-modern-pf-ring\n--gobgp\n--api\n--install_dependency_packages_only\n--boost\n--help\n";
    exit (0);
}

if ($do_not_use_mirror) {
     $use_mirror = '';
}

welcome_message();

# Bump PF_RING version
if ($use_modern_pf_ring) {
    $pf_ring_version = '6.6.0';
    $pf_ring_url = "https://github.com/ntop/PF_RING/archive/$pf_ring_version.tar.gz";
    $pf_ring_sha = '79ff86e48df857e4e884646accfc97bdcdc54b04';
}

my $we_have_ndpi_support = '1';
my $we_have_luajit_support = '';
my $we_have_hiredis_support = '1';
my $we_have_log4cpp_support = '1';
my $we_have_pfring_support = '';
my $we_have_mongo_support = '1';
my $we_have_protobuf_support = '';
my $we_have_grpc_support = '';
my $we_have_gobgp_support = '';

# These modes use same modules
if ($enable_gobgp_backend || $enable_api) {
    $we_have_protobuf_support = 1;
    $we_have_grpc_support = 1;
    $we_have_gobgp_support = 1;
}

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

sub get_user_email {
    # http://docs.travis-ci.com/user/environment-variables/#Default-Environment-Variables
    if (defined($ENV{'TRAVIS'}) && $ENV{'TRAVIS'}) {
        return;
    }

    # https://circleci.com/docs/2.0/env-vars/
    if (defined($ENV{'CI'}) && $ENV{'CI'}) {
        return;
    }

    my $user_entered_valid_email = 0;

    do {
        print "\n";
        print "Please provide your business email address to receive important information about security updates\n";
        print "In addition, we can send promotional messages to this email (very rare)\n";
        print "You can find our privacy policy here https://fastnetmon.com/privacy-policy/\n";
        print "We will provide an option to disable any email from us\n";
        print "We will not share your email with any third party companies.\n\n";
        print "If you continue install process you accept our subscription rules automatically\n\n";
        
        print "Email: ";
        my $raw_email = <STDIN>;
        chomp $raw_email;
        
        if ($raw_email =~ /\@/ && length $raw_email > 3) {
            $user_entered_valid_email = 1;
            $user_email = $raw_email;
        } else {
            print "Sorry you have entered invalid email, please try again!\n";
        }
    } while !$user_entered_valid_email;

    print "\nThank you so much!\n\n"; 
}

# Installs Sentry for error tracking
sub install_sentry {
    my $machine_arch = `uname -m`;
    chomp $machine_arch;

    my $download_res = system("wget --quiet 'https://downloads.sentry-cdn.com/sentry-cli/1.46.0/sentry-cli-Linux-$machine_arch' -O/opt/sentry-cli");

    if ($download_res != 0) {
        warn "Cannot download Sentry";
    }

    system("chmod +x /opt/sentry-cli");
}

### Functions start here
sub main {
    # Open log file
    open my $global_log, ">", $install_log_path or warn "Cannot open log file: $! $install_log_path";
    print {$global_log} "Install started";

    detect_distribution();

    get_user_email();

    # Set environment variables to collect more information about installation failures

    $ENV{'FASTNETMON_DISTRO_TYPE'} = $distro_type;
    $ENV{'FASTNETMON_DISTRO_VERSION'} = $distro_version;
    $ENV{'FASTNETMON_USER'} = $user_email;

    install_sentry();

    $cpus_number = get_logical_cpus_number();

    if (defined($ENV{'CIRCLECI'}) && $ENV{'CIRCLECI'}) { 
        # We use machine with 2 CPUs, let's set explicitly 2 threads, get_logical_cpus_number returns 36 which is not real number of CPU cores
	$make_options = "-j 2"; 
    } else {
        if ($cpus_number > 8) {
            print "You have really nice server with $cpus_number CPUs and we will use them all for build process :)\n";
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

    if ($os_type eq 'macosx') {
        # Really strange issue https://github.com/pavel-odintsov/fastnetmon/issues/415 
        $we_have_hiredis_support = 0;
    }

    # CentOS base repository is very very poor and we need EPEL for some dependencies
    install_additional_repositories();

    # Refresh information about packages
    init_package_manager();

    if ($os_type eq 'freebsd') {
        exec_command("pkg install -y wget");
    }

    send_tracking_information('started');

    my $install_from_official_distro = '';

    # For these Ubuntu version we have FastNetMon in standard repos, will use it instead
    if ($distro_type eq 'ubuntu' && (
        $distro_version =~ m/^18\.04/ or
        $distro_version =~ m/^19\.04/)) {

         $install_from_official_distro = 1;
    }

    # For Debian Buster we also have FastNetMon in standard repos
    if ($distro_type eq 'debian' && $distro_version =~ m/^10\./) {
        $install_from_official_distro = 1;
    }

    if ($install_from_official_distro && !$we_use_code_from_master) {
        apt_get("fastnetmon");

        # Switch off sflow and netflow plugins enabled by default
        system("sed -i 's/sflow = on/sflow = off/' /etc/fastnetmon.conf");
        system("sed -i 's/netflow = on/netflow = off/' /etc/fastnetmon.conf");
        # Remove trailing space in Debian/Ubuntu configuration, it was fixed in upstream
        system("sed -i 's/ban_for_tcp_pps = off /ban_for_tcp_pps = off/' /etc/fastnetmon.conf");

        # Apply changes
        system("systemctl restart fastnetmon");

        print "FastNetMon was installed and started correctly\n";
        print "Below you can find some useful commands and paths\n\n";
        print "Main configuration file: /etc/fastnetmon.conf\n";
        print "Daemon restart command: systemctl restart fastnetmon\n";
        print "Client tool: fastnetmon_client\n";
        print "Log file: /var/log/fastnetmon.log\n";

        send_tracking_information('finished');
        exit(0);
    }


    # Install standard tools for building packages
    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        my @debian_packages_for_build = ('build-essential', 'make', 'tar', 'wget');

        apt_get(@debian_packages_for_build);
    } elsif ($distro_type eq 'centos') {
        my @centos_dependency_packages = ('make', 'gcc', 'gcc-c++');

        yum(@centos_dependency_packages);
    }
 
    # Install only depencdency packages, we need it to cache installed packages in CI
    if ($install_dependency_packages_only) {
        if ($we_have_pfring_support) {
            install_pf_ring_dependencies();
    	}

	if ($we_have_ndpi_support) {
            install_ndpi_dependencies();
        }

	if ($we_have_luajit_support) {
            install_luajit_dependencies();
	}

	if ($we_have_protobuf_support) {
            install_protobuf_dependencies();
	}

	if ($we_have_grpc_support) {
            install_grpc_dependencies();
	}

	install_fastnetmon_dependencies();
    } else {

        if ($we_have_pfring_support) {
       	   install_pf_ring_dependencies();
           install_pf_ring();
        }

        install_json_c();

        if ($build_boost) {
           # We need fresh cmake for this build, Boost requires it
           $cmake_path = "/opt/cmake-3.16.4/bin/cmake";

	   install_cmake_dependencies();
	   install_cmake();
           install_icu();
	   install_boost_builder();
	   install_boost();
	}

        if ($we_have_ndpi_support) {
	   install_ndpi_dependencies();
           install_ndpi();
        }

        if ($we_have_luajit_support) {
	   install_luajit_dependencies();

           install_luajit();
           install_luajit_libs();
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
        install_fastnetmon();
    }

    send_tracking_information('finished');

    my $install_time = time() - $start_time;
    my $pretty_install_time_in_minutes = sprintf("%.2f", $install_time / 60);

    print "We have built project in $pretty_install_time_in_minutes minutes\n";
}

sub exec_command {
    my $command = shift;

    open my $fl, ">>", $install_log_path;
    print {$fl} "We are calling command: $command\n\n";
 
    my $output = `$command 2>&1 >> $install_log_path`;
  
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

sub install_luajit_dependencies {
    if ($os_type eq 'freebsd') {
        exec_command("pkg install -y gcc gmake");
    }
}

sub install_luajit {
    chdir $temp_folder_for_building_project;

    my $archive_file_name = "LuaJIT-2.0.4.tar.gz";

    my $luajit_install_path = "/opt/luajit_2.0.4";

    if (-e $luajit_install_path && defined($ENV{'CI'})) {
	print "Luajit was installed already\n";
        return 1;
    }

    print "Download Luajit\n";
   
    my $luajit_download_result = download_file(
        "http://luajit.org/download/$archive_file_name",
        $archive_file_name,
        '6e533675180300e85d12c4bbeea2d0e41ad21172'
    ); 

    unless ($luajit_download_result) {
        fast_die("Can't download luajit");
    }

    print "Unpack Luajit\n";
    exec_command("tar -xf LuaJIT-2.0.4.tar.gz");
    chdir "LuaJIT-2.0.4";
    
    if ($os_type eq 'macosx' or $os_type eq 'freebsd') {
        # FreeBSD's sed has slightly different syntax
        exec_command("sed -i -e 's#export PREFIX= /usr/local#export PREFIX= $luajit_install_path#' Makefile");
    } else {
        # Standard Linux sed
        exec_command("sed -i 's#export PREFIX= /usr/local#export PREFIX= $luajit_install_path#' Makefile"); 
    }

    print "Build and install Luajit\n";
    if ($os_type eq 'freebsd') {
        exec_command('gmake CC=gcc48 CXX=g++48 CPP="gcc48 -E" install')
    } else {
        exec_command("make $make_options install");
    }
}

sub install_luajit_libs {
    install_lua_lpeg();
    install_lua_json();
} 

sub install_lua_lpeg {
    print "Install LUA lpeg module\n";

    print "Download archive\n";
    chdir $temp_folder_for_building_project;

    my $archive_file_name = 'lpeg-0.12.2.tar.gz';

    my $lpeg_download_result = download_file("http://www.inf.puc-rio.br/~roberto/lpeg/$archive_file_name",
        $archive_file_name, '69eda40623cb479b4a30fb3720302d3a75f45577'); 

    unless ($lpeg_download_result) {
        fast_die("Can't download lpeg");
    }

    exec_command("tar -xf lpeg-0.12.2.tar.gz");
    chdir "lpeg-0.12.2";

    # Set path
    print "Install lpeg library\n";
    if ($os_type eq 'macosx' or $os_type eq 'freebsd') {
        exec_command("sed -i -e 's#LUADIR = ../lua/#LUADIR = /opt/luajit_2.0.4/include/luajit-2.0#' makefile");
    } else {
        exec_command("sed -i 's#LUADIR = ../lua/#LUADIR = /opt/luajit_2.0.4/include/luajit-2.0#' makefile");
    }

    exec_command("make $make_options");
    exec_command("cp lpeg.so /opt/luajit_2.0.4/lib/lua/5.1");
}

sub install_json_c {
    my $archive_name  = 'json-c-0.13-20171207.tar.gz';
    my $install_path = '/opt/json-c-0.13';

    if (-e $install_path && defined($ENV{'CI'})) {
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

    # Fix bugs (assigned but not used variable) which prevent code compilation
    if ($os_type eq 'macosx' or $os_type eq 'freebsd') {
        exec_command("sed -i -e '355 s#^#//#' json_tokener.c");
        exec_command("sed -i -e '360 s#^#//#' json_tokener.c");
    } else {
        
    }

    print "Build it\n";
    exec_command("./configure --prefix=$install_path");

    print "Install it\n";
    exec_command("make $make_options install");
}

sub install_lua_json {
    print "Install LUA json module\n";
    
    chdir $temp_folder_for_building_project;

    print "Download archive\n";

    my $archive_file_name = '1.3.3.tar.gz';

    my $lua_json_download_result = download_file("https://github.com/harningt/luajson/archive/$archive_file_name", $archive_file_name,
        '53455f697c3f1d7cc955202062e97bbafbea0779');

    unless ($lua_json_download_result) {
        fast_die("Can't download lua json");
    }

    exec_command("tar -xf $archive_file_name");

    chdir "luajson-1.3.3";

    print "Install it\n";
    exec_command("PREFIX=/opt/luajit_2.0.4 make $make_options install");
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

        exec_command("sed -i 's#\@CMAKE_INSTALL_SBINDIR\@#/opt/fastnetmon#' $systemd_service_path");

        print "We found systemd enabled distro and created service: fastnetmon.service\n";
        print "You could run it with command: systemctl start fastnetmon.service\n";

        return 1;
    }

    # Init file for CentOS 6
    if ($distro_type eq 'centos' && $distro_version == 6) {
        my $system_init_path = '/etc/init.d/fastnetmon';
        exec_command("cp $fastnetmon_code_dir/fastnetmon_init_script_centos6 $system_init_path");

        exec_command("sed -i 's#/usr/sbin/fastnetmon#/opt/fastnetmon/fastnetmon#' $system_init_path");

        print "We created service fastnetmon for you\n";
        print "You could run it with command: /etc/init.d/fastnetmon start\n";

        return 1;
    }

    # For Gentoo
    if ( $distro_type eq 'gentoo' ) {
        my $init_path_in_src = "$fastnetmon_code_dir/fastnetmon_init_script_gentoo";
        my $system_init_path = '/etc/init.d/fastnetmon';

        # Checker for source code version, will work only for 1.1.3+ versions
        if (-e $init_path_in_src) {
            exec_command("cp $init_path_in_src $system_init_path");

            print "We created service fastnetmon for you\n";
            print "You could run it with command: /etc/init.d/fastnetmon start\n";

            return 1;
        }
    }

    # For Debian Squeeze and Wheezy 
    # And any stable Ubuntu version
    if ( ($distro_type eq 'debian' && ($distro_version == 6 or $distro_version == 7)) or $distro_type eq 'ubuntu') {
        my $init_path_in_src = "$fastnetmon_code_dir/fastnetmon_init_script_debian_6_7";
        my $system_init_path = '/etc/init.d/fastnetmon';

        # Checker for source code version, will work only for 1.1.3+ versions
        if (-e $init_path_in_src) {
           exec_command("cp $init_path_in_src $system_init_path");

            exec_command("sed -i 's#/usr/sbin/fastnetmon#/opt/fastnetmon/fastnetmon#' $system_init_path");

            print "We created service fastnetmon for you\n";
            print "You could run it with command: /etc/init.d/fastnetmon start\n";

            return 1;
        }
    }
}

sub install_log4cpp {
    my $distro_file_name = 'log4cpp-1.1.1.tar.gz';
    my $log4cpp_url = 'https://sourceforge.net/projects/log4cpp/files/log4cpp-1.1.x%20%28new%29/log4cpp-1.1/log4cpp-1.1.1.tar.gz/download';
    my $log4cpp_install_path = '/opt/log4cpp1.1.1';

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
        apt_get('gcc', 'make', 'autoconf', 'automake', 'git', 'libtool', 'g++', 'python-all-dev', 'python-virtualenv');
    }
}

sub install_grpc {
    # Here we are storing revisions of code which are using multiple times in code
    # https://github.com/grpc/grpc/releases/tag/v1.27.3
    my $grpc_git_commit = "e73882dc0fcedab1ffe789e44ed6254819639ce3";

    my $grpc_install_path = "/opt/grpc_1_27_3_$grpc_git_commit";

    if (-e $grpc_install_path && defined($ENV{'CI'})) {
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

    print "Build gRPC\n";
    my $make_result = exec_command("make $make_options");

    unless ($make_result) {
        fast_die( "Could not build gRPC: make failed\n");
}

    print "Install gRPC\n";
    exec_command("make install prefix=$grpc_install_path");

    1;
}

sub install_gobgp {
    chdir $temp_folder_for_building_project;

    my $gobgp_install_path = '/opt/gobgp_2_16_0';

    if (-e $gobgp_install_path && defined($ENV{'CI'})) {
        print "GoBGP was already installed\n";
	return 1;
    }

    my $distro_file_name = '';
    my $distro_file_hash = '';

    if ($distro_architecture eq 'x86_64') {
	$distro_file_name = 'gobgp_2.16.0_linux_amd64.tar.gz';
	$distro_file_hash = '58dcf1f4b4b64383c5fbb731322c9fc2a2fcd5f0';
    } elsif ($distro_architecture eq 'i686') {
        $distro_file_name = 'gobgp_2.16.0_linux_386.tar.gz';
        $distro_file_hash = '9d6f031058589618f414b4493b5cfa34230c0505';
    } else {
        fast_die("We do not have GoBGP for your platform, please check: https://github.com/osrg/gobgp/releases for available builds");
    }

    print "Download GoBGP\n";

    my $gobgp_download_result = download_file("https://github.com/osrg/gobgp/releases/download/v2.16.0/$distro_file_name",
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

    my $protobuf_install_path = "/opt/protobuf_3.11.4";

    if (-e $protobuf_install_path && defined($ENV{'CI'})) {
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

    exec_command("./configure --prefix=$protobuf_install_path");

    print "Build protobuf\n";
    exec_command("make $make_options install");
    1;
}

sub install_mongo_client {
    my $distro_file_name = 'mongo-c-driver-1.1.9.tar.gz';
    my $mongo_install_path = '/opt/mongo_c_driver_1_1_9';

    if (-e $mongo_install_path && defined($ENV{'CI'})) {
        print "mongo client was already installed\n";
	return 1;
    }

    chdir $temp_folder_for_building_project;
    print "Download mongo\n";

    my $mongo_download_result = download_file("https://github.com/mongodb/mongo-c-driver/releases/download/1.1.9/$distro_file_name",
        $distro_file_name, '32452481be64a297e981846e433b2b492c302b34');
    
    unless ($mongo_download_result) {
        fast_die("Can't download mongo");
    }

    exec_command("tar -xf $distro_file_name");
    print "Build mongo client\n";
    chdir "mongo-c-driver-1.1.9";
    exec_command("./configure --prefix=$mongo_install_path");

    exec_command("make $make_options install");
}

sub install_hiredis {
    my $disto_file_name = 'v0.13.1.tar.gz'; 
    my $hiredis_install_path = '/opt/libhiredis_0_13';

    if (-e $hiredis_install_path && defined($ENV{'CI'})) {
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
    } elsif ($os_type eq 'freebsd') {
        exec_command("pkg install -y git autoconf automake libtool");
    } 
}

# We use global variable $ndpi_repository here
sub install_ndpi {
    my $ndpi_install_path = "/opt/ndpi";

    if (-e $ndpi_install_path && defined($ENV{'CI'})) {
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
    exec_command("./autogen.sh");

    # We have specified direct path to json-c here because it required for example app compilation
    exec_command("PKG_CONFIG_PATH=/opt/json-c-0.13/lib/pkgconfig ./configure --prefix=$ndpi_install_path");

   if ($? != 0) {
        print "Configure failed\n";
        return;
    }

    print "Build and install nDPI\n";
    exec_command("make $make_options install");
}

sub init_package_manager { 

    print "Update package manager cache\n";
    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        exec_command("apt-get update");
    }

    if ($os_type eq 'freebsd') {
        exec_command("pkg update");
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

        if ($appliance_name eq 'vyos') { 
            # VyOS uses another name for package for building kernel modules
            $kernel_headers_package_name = 'linux-vyatta-kbuild';
        } elsif ($appliance_name eq 'proxmox') {
            $kernel_headers_package_name = "pve-headers-$kernel_version";
        }

        push @debian_packages_for_pfring, $kernel_headers_package_name;

        apt_get(@debian_packages_for_pfring);

        if ($appliance_name eq 'vyos') {
            # By default we waven't this symlink and should add it manually

            if ($distro_architecture eq 'x86_64') {  
                exec_command("ln -s /usr/src/linux-image/debian/build/build-amd64-none-amd64-vyos/ /lib/modules/$kernel_version/build");
            } else {
                # i686
                exec_command("ln -s /usr/src/linux-image/debian/build/build-i386-none-586-vyos/ /lib/modules/$kernel_version/build");
            }
        }
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
    } elsif ($distro_type eq 'gentoo') {
        my @gentoo_packages_for_pfring = ('subversion', 'sys-process/numactl', 'wget', 'tar');

        my $gentoo_packages_for_pfring_as_string = join " ", @gentoo_packages_for_pfring;
        exec_command("emerge -vu $gentoo_packages_for_pfring_as_string");

        if ($? != 0) {
            print "Emerge fail with code $?\n";
        }
    }
}

sub install_pf_ring {
    my $pf_ring_archive_path = "$temp_folder_for_building_project/PF_RING-$pf_ring_version.tar.gz";
    my $pf_ring_sources_path = "$temp_folder_for_building_project/PF_RING-$pf_ring_version";

    my $pf_ring_install_path = "/opt/pf_ring_$pf_ring_version";

    if (-e $pf_ring_install_path && defined($ENV{'CI'})) {
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
    exec_command("./configure --prefix=$pf_ring_install_path");
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


sub install_icu {
    my $distro_file_name = 'icu4c-65_1-src.tgz';

    chdir $temp_folder_for_building_project;

    my $icu_install_path = "/opt/libicu_65_1";

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
    exec_command("./configure --prefix=$icu_install_path");
    exec_command("make $make_options");
    exec_command("make $make_options install");
    1;
}


sub install_cmake_dependencies {
    apt_get("libssl-dev");
}

sub install_cmake {
    print "Install cmake\n";

    my $cmake_install_path = "/opt/cmake-3.16.4";

    if (-e $cmake_install_path && defined($ENV{'CI'})) {
        warn "Found installed cmake at $cmake_install_path\n";
        return 1;
    }

    my $distro_file_name = "cmake-3.16.4.tar.gz";

    chdir $temp_folder_for_building_project;

    print "Download archive\n";
    my $cmake_download_result = download_file("https://github.com/Kitware/CMake/releases/download/v3.16.4/$distro_file_name", $distro_file_name, '3ae23da521d5c0e871dd820a0d3af5504f0bd6db');

    unless ($cmake_download_result) {
        fast_die("Can't download cmake\n");
    }

    exec_command("tar -xf $distro_file_name");

    chdir "cmake-3.16.4";

    print "Execute bootstrap, it will need time\n";
    my $boostrap_result = exec_command("./bootstrap --prefix=$cmake_install_path --parallel=$cpus_number");

    unless ($boostrap_result) {
        fast_die("Cannot run bootstrap\n");
    }

    print "Make it\n";
    my $make_command = "make $make_options";
    my $make_result = exec_command($make_command);

    unless ($make_result) {
        die "Make command '$make_command' failed\n";
    }

    exec_command("make install");

    return 1;
}


sub install_boost_builder {
    chdir $temp_folder_for_building_project;

    # We use another name because it uses same name as boost distribution
    my $archive_file_name = 'build-boost-1.72.0.tar.gz';

    my $boost_builder_install_folder = "/opt/boost_build1.72.0";

    if (-e $boost_builder_install_folder && defined($ENV{'CI'}) ) {
        warn "Found installed Boost builder at $boost_builder_install_folder\n";
        return 1;
    }

    print "Download boost builder\n";
    my $boost_build_result = download_file("https://github.com/boostorg/build/archive/boost-1.72.0.tar.gz", $archive_file_name,
        '8d4aede249cc414f5f375423e26feca99f1c1088');

    unless ($boost_build_result) {
        die "Can't download boost builder\n";
    }

    print "Unpack boost builder\n";
    exec_command("tar -xf $archive_file_name");

    unless (chdir "build-boost-1.72.0") {
        die "Cannot do chdir to build boost folder\n";
    }

    print "Build Boost builder\n";
    my $bootstrap_result = exec_command("./bootstrap.sh --with-toolset=gcc");

    unless ($bootstrap_result) {
        die "bootstrap of Boost Builder failed, please check logs\n";
    }

    # We should specify toolset here if we want to do build with custom compiler
    # We have troubles when run this code with vzctl exec so we should add custom compiler in path 
    my $b2_install_result = exec_command("./b2 install --prefix=$boost_builder_install_folder");

    unless ($b2_install_result) {
        die "Can't execute b2 install\n";
    }

    1;
}

sub install_boost {
    my $boost_install_path = "/opt/boost_1_72_0";

    if (-e $boost_install_path && defined($ENV{'CI'})) {
        warn "Boost libraries already exist in $boost_install_path. Skip build process\n";
        return 1;
    }

    chdir "/opt";
    my $archive_file_name = 'boost_1_72_0.tar.gz';

    print "Install Boost dependencies\n";

    print "Download Boost source code\n";
    my $boost_download_result = download_file("https://dl.bintray.com/boostorg/release/1.72.0/source/boost_1_72_0.tar.bz2", $archive_file_name, '88866e4075e12255e7a7189d0b8a686e0b1ee9c1');

    unless ($boost_download_result) {
        die "Can't download Boost source code\n";
    }

    print "Unpack Boost source code\n";
    exec_command("tar -xf $archive_file_name");

    my $folder_name_inside_archive = 'boost_1_72_0';

    print "Fix permissions\n";
    # Fix permissions because they are broken inside official archive
    exec_command("find $folder_name_inside_archive -type f -exec chmod 644 {} \\;");
    exec_command("find $folder_name_inside_archive -type d -exec chmod 755 {} \\;");
    exec_command("chown -R root:root $folder_name_inside_archive");

    print "Remove archive\n";
    unlink "$archive_file_name";

    chdir $folder_name_inside_archive;

    print "Build Boost\n";
    # We have troubles when run this code with vzctl exec so we should add custom compiler in path 
    # So without HOME=/root nothing worked correctly due to another "openvz" feature
    my $b2_build_result = exec_command("/opt/boost_build1.72.0/bin/b2 -j$cpus_number -sICU_PATH=/opt/libicu_65_1 --build-dir=$temp_folder_for_building_project/boost_build_temp_directory_1_7_2 link=shared --without-test --without-python --without-wave --without-log --without-mpi");

    # We should not do this check because b2 build return bad return code even in success case... when it can't build few non important targets
    unless ($b2_build_result) {
        ### die "Can't execute b2 build correctly\n";
    }

    1;
}


sub install_fastnetmon_dependencies {
    print "Install FastNetMon dependency list\n";

    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        my @fastnetmon_deps = ("git", "g++", "gcc", "libgpm-dev", "libncurses5-dev",
            "liblog4cpp5-dev", "libnuma-dev", "libgeoip-dev","libpcap-dev", "cmake", "pkg-config", "libhiredis-dev",
        );

        # We add this dependencies because package libboost-all-dev is broken on VyOS
        if ($appliance_name eq 'vyos') {
            push @fastnetmon_deps, ('libboost-regex-dev', 'libboost-system-dev', 'libboost-thread-dev');
        } else {
            push @fastnetmon_deps, "libboost-all-dev";
        }

        apt_get(@fastnetmon_deps);
    } elsif ($distro_type eq 'centos') {
        my @fastnetmon_deps = ('git', 'make', 'gcc', 'gcc-c++', 'GeoIP-devel',
            'ncurses-devel', 'glibc-static', 'ncurses-static', 'libpcap-devel', 'gpm-static',
            'gpm-devel', 'cmake', 'pkgconfig', 'hiredis-devel',
        );

        if ($distro_type eq 'centos' && int($distro_version) == 7) {
            push @fastnetmon_deps, 'net-tools';
        }

        @fastnetmon_deps = (@fastnetmon_deps, 'boost-devel', 'boost-thread');

        yum(@fastnetmon_deps);
    } elsif ($distro_type eq 'gentoo') {
        my @fastnetmon_deps = ("dev-vcs/git", "gcc", "sys-libs/gpm", "sys-libs/ncurses", "dev-libs/log4cpp", "dev-libs/geoip", 
            "net-libs/libpcap", "dev-util/cmake", "pkg-config", "dev-libs/hiredis", "dev-libs/boost"
        );

        my $fastnetmon_deps_as_string = join " ", @fastnetmon_deps;
        exec_command("emerge -vu $fastnetmon_deps_as_string");

        if ($? != 0) {
            print "Emerge fail with code $?\n";
        }
    } elsif ($os_type eq 'freebsd') {
        exec_command("pkg install -y cmake git ncurses boost-all log4cpp");
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
   
    if ($build_boost) {
	$cmake_params .= " -DENABLE_CUSTOM_BOOST_BUILD=ON";
    }

     
    if ($distro_type eq 'centos' && $distro_version == 6) {
        # Disable cmake script from Boost package because it's broken:
        # http://public.kitware.com/Bug/view.php?id=15270
        $cmake_params .= " -DBoost_NO_BOOST_CMAKE=BOOL:ON";
    }

    if ($enable_gobgp_backend) {
        $cmake_params .= " -DENABLE_GOBGP_SUPPORT=ON";
    }

    # Bump version in cmake build system
    if ($use_modern_pf_ring) {
        system("sed -i 's/pf_ring_6.0.3/pf_ring_$pf_ring_version/' ../CMakeLists.txt")
    }

    # Fix dependencies for Netmap in 1.1.4
    if ($distro_type eq 'centos' && int($distro_version) == 6) {
        system("sed -i 's/netmap_plugin fastnetmon_packet_parser/netmap_plugin fastnetmon_packet_parser unified_parser/' ../CMakeLists.txt")
    }

    # We do not need LUA by default
    unless ($we_have_luajit_support) {
        $cmake_params .= " -DENABLE_LUA_SUPPORT=OFF ";
    }

    if ((defined($ENV{'TRAVIS'}) && $ENV{'TRAVIS'}) or (defined($ENV{'CI'}) && $ENV{'CI'})) {
        system("$cmake_path .. $cmake_params");
        system("make $make_options");
    } else {
        print "Run cmake to generate make file\n";
        system("$cmake_path .. $cmake_params 2>&1 | tee -a $install_log_path");

        print "Run make to build FastNetMon\n";
        system("make $make_options 2>&1 | tee -a $install_log_path");
    }

    my $fastnetmon_dir = "/opt/fastnetmon";
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

