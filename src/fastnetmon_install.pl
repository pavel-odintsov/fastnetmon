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

my $os_type = '';
my $distro_type = '';  
my $distro_version = '';  
my $distro_architecture = '';

# Used for VyOS and different appliances based on rpm/deb
my $appliance_name = ''; 

my $user_email = '';

my $install_log_path = "/tmp/fastnetmon_install_$$.log";

if (defined($ENV{'CI'}) && $ENV{'CI'}) {
    $install_log_path = "/tmp/fastnetmon_install.log";
}

# So, you could disable this option but without this feature we could not improve FastNetMon for your distribution
my $do_not_track_me = '';

sub send_tracking_information {
    my $step = shift;

    unless ($do_not_track_me) {
        my $stats_url = "http://178.62.227.110/new_fastnetmon_installation";
        my $post_data = "distro_type=$distro_type&os_type=$os_type&distro_version=$distro_version&distro_architecture=$distro_architecture&step=$step&user_email=$user_email";
        my $user_agent = 'FastNetMon install tracker v1';

        `wget --post-data="$post_data" --user-agent="$user_agent" -q '$stats_url' -O /dev/null`;
    } 
}


sub send_ga_event {
    my $step = shift;

    unless ($do_not_track_me) {
        `wget "https://www.google-analytics.com/collect?tid=UA-83642378-1&t=event&ec=fastnetmon_community&ea=$step&v=1&cid=0" -q -O /dev/null`;
    }
}

# die wrapper to send message to tracking server
sub fast_die {
    my $message = shift;

    print "$message Please share $install_log_path with FastNetMon team at GitHub to get help: https://github.com/pavel-odintsov/fastnetmon/issues/new\n";

    # Report failed installs
    send_tracking_information("error");

    send_ga_event("installation_failed");

    # Send detailed report about issue to Sentry
    unless ($do_not_track_me) {
        system("SENTRY_DSN=https://121eca215532431cb7521eafdbca23d3:292cfd7ac2af46a7bc32356141e62592\@sentry.io/1504559 /opt/sentry-cli " .
            " send-event -m \"$message\" --logfile $install_log_path");
    }

    exit(1);
}

my $show_help = '';

# Get options from command line
GetOptions(
    'do-not-track-me' => \$do_not_track_me,
    'help' => \$show_help,
);

# Export all meaningful customer facing flags to Sentry for better failure tracking
$ENV{'do-not-track-me'} = $do_not_track_me;

if ($show_help) {
    print "We have following options:\n--do-not-track-me\n--help\n If you're looking for more options, please use fastnetmon_build.pl instead\n";
    exit (0);
}

if (defined($ENV{'CI'}) && $ENV{'CI'}) {
    $do_not_track_me = 1; 
}

welcome_message();

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
    
    print "We need few minutes of your time for installing FastNetMon Community\n\n";
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

    my $download_path = "https://community-downloads.fastnetmon.com/releases/1.1.6";

    print "We will install FastNetMon using official binary packages\n";
    send_tracking_information('started');   

    send_ga_event("installation_started");

    if ($os_type eq 'freebsd') {
        fast_die("I'm sorry but we do not support FreeBSD in official builds but we offer official FreeBSD port, please check it instead");
    } elsif ($os_type eq 'macosx') {
        fast_die("I'm sorry but we do not support macos in current version, please raise GitHub issue if you want support for it: https://github.com/pavel-odintsov/fastnetmon");
    } elsif ($os_type eq 'linux') {
        if ($distro_type eq 'ubuntu') {
            my $ubuntu_package_name = "fastnetmon_1.1.6_amd64.deb";

            if ($distro_version =~ m/^14\.04/) {
                print "Install dependencies\n";
                exec_command("apt-get update");
                exec_command("DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=\"--force-confold\" libpcap0.8 libatomic1");

                print "Download FastNetMon\n";
                my $curl_res = system("wget -q $download_path/ubuntu/14.04/$ubuntu_package_name -O$ubuntu_package_name");

                if ($curl_res != 0) {
                    fast_die("Cannot download FastNetMon package");
                }

                print "Install FastNetMon\n";
                my $res = system("dpkg -i $ubuntu_package_name >> $install_log_path 2>&1");

                if ($res != 0) {
                    fast_die("Cannot install FastNetMon package with error code $res");
                }
            } elsif ($distro_version =~ m/^16\.04/) {
                print "Refresh repositories\n";
                exec_command("apt-get update");

                print "Download FastNetMon\n";
                my $curl_res = system("wget -q $download_path/ubuntu/16.04/$ubuntu_package_name -O$ubuntu_package_name");

                if ($curl_res != 0) { 
                    fast_die("Cannot download FastNetMon package");
                }    

                print "Install FastNetMon\n";
                my $install_res = system("DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=\"--force-confold\" ./$ubuntu_package_name >> $install_log_path 2>&1");

                if ($install_res != 0) {
                    fast_die("Cannot install FastNetMon package with error code $install_res");
                }
            } elsif ($distro_version =~ m/^18\.04/) {
                print "Refresh repositories\n";
                exec_command("apt-get update");

                print "Download FastNetMon\n";
                my $curl_res = system("wget -q $download_path/ubuntu/18.04/$ubuntu_package_name -O$ubuntu_package_name");

                if ($curl_res != 0) {
                    fast_die("Cannot download FastNetMon package");
                }

                print "Install FastNetMon\n";
                my $install_res = system("DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=\"--force-confold\" ./$ubuntu_package_name >> $install_log_path 2>&1");

                if ($install_res != 0) {
                    fast_die("Cannot install FastNetMon package with error code $install_res");
                }

            } elsif ($distro_version =~ m/^20\.04/) {
                print "Refresh repositories\n";
                exec_command("apt-get update");

                print "Download FastNetMon\n";
                my $curl_res = system("wget -q $download_path/ubuntu/20.04/$ubuntu_package_name -O$ubuntu_package_name");

                if ($curl_res != 0) { 
                    fast_die("Cannot download FastNetMon package");
                }    

                print "Install FastNetMon\n";
                my $install_res = system("DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=\"--force-confold\" ./$ubuntu_package_name >> $install_log_path 2>&1");

                if ($install_res != 0) {
                    fast_die("Cannot install FastNetMon package with error code $install_res");
                }

            } else {
                fast_die("I'm sorry but we do not support Ubuntu $distro_version in current version, please check that you use LTS and stable distribution");
            }
        } elsif ($distro_type eq 'debian') {
            my $debian_package_name = "fastnetmon_1.1.6_amd64.deb";

         if ($distro_version =~ m/^8\.?/) {
                print "Install dependencies\n";
                exec_command("apt-get update");
                exec_command("DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=\"--force-confold\" libpcap0.8 libatomic1");

                print "Download FastNetMon\n";
                my $curl_res = system("wget -q $download_path/debian/8/$debian_package_name -O$debian_package_name");

                if ($curl_res != 0) { 
                    fast_die("Cannot download FastNetMon package");
                }

                print "Install FastNetMon\n";
                my $res = system("dpkg -i $debian_package_name >> $install_log_path 2>&1");

                if ($res != 0) { 
                    fast_die("Cannot install FastNetMon package with error code $res");
                }
            } elsif ($distro_version =~ m/^9\.?/) {
                print "Refresh repositories\n";
                exec_command("apt-get update");

                print "Download FastNetMon\n";
                my $curl_res = system("wget -q $download_path/debian/9/$debian_package_name -O$debian_package_name");

                if ($curl_res != 0) { 
                    fast_die("Cannot download FastNetMon package");
                }

                print "Install FastNetMon\n";
                my $install_res = system("DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=\"--force-confold\" ./$debian_package_name >> $install_log_path 2>&1");

                if ($install_res != 0) { 
                    fast_die("Cannot install FastNetMon package with error code $install_res");
                }
            } elsif ($distro_version =~ m/^10\.?/) {
                print "Refresh repositories\n";
                exec_command("apt-get update");

                print "Download FastNetMon\n";
                my $curl_res = system("wget -q $download_path/debian/10/$debian_package_name -O$debian_package_name");

                if ($curl_res != 0) { 
                    fast_die("Cannot download FastNetMon package");
                }

                print "Install FastNetMon\n";
                my $install_res = system("DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=\"--force-confold\" ./$debian_package_name >> $install_log_path 2>&1");

                if ($install_res != 0) { 
                    fast_die("Cannot install FastNetMon package with error code $install_res");
                }
            } else {
                fast_die("I'm sorry but we do not support Debian $distro_version in current version, please check that you use stable version");                
            }

        } elsif ($distro_type eq 'centos') {
            if (int($distro_version) == 6) {
                print "Download and install FastNetMon\n";
                my $yum_install_res = system("yum install -y $download_path/centos/6/fastnetmon-1.1.6-1.el6.x86_64.rpm >> $install_log_path 2>&1");

                if ($yum_install_res != 0) {
                    fast_die("Cannot install FastNetmon via yum with error code: $yum_install_res");
                }
            } elsif (int($distro_version) == 7) {
                print "Download and install FastNetMon\n";
                my $yum_install_res = system("yum install -y $download_path/centos/7/fastnetmon-1.1.6-1.el7.x86_64.rpm >> $install_log_path 2>&1");

                if ($yum_install_res != 0) {
                    fast_die("Cannot install FastNetmon via yum with error code: $yum_install_res");
                }    
            } elsif (int($distro_version) == 8) {
                print "Download and install FastNetMon\n";
                my $yum_install_res = system("yum install -y $download_path/centos/8/fastnetmon-1.1.6-1.el8.x86_64.rpm >> $install_log_path 2>&1");

                if ($yum_install_res != 0) {
                    fast_die("Cannot install FastNetmon via yum with error code: $yum_install_res");
                }    
            } else {
                fast_die("I'm sorry but we do not support CentOS $distro_version in current version, please check that you use stable version");
            }
        } else {
            fast_die("I'm sorry but we do not support your Linux distribution $distro_type. Please raise GitHub issue if you want support for it: https://github.com/pavel-odintsov/fastnetmon");
        }
    } else {
        fast_die("I'm sorry but we do not support your operating system $os_type. Please raise GitHub issue if you want support for it: https://github.com/pavel-odintsov/fastnetmon");
    }

    print "\n\n";
    print "FastNetMon was installed and started successfully\n";
    print "Below you can find some useful commands and paths\n\n";
    print "Main configuration file: /etc/fastnetmon.conf\n";
    print "Daemon restart command: systemctl restart fastnetmon or service restart fastnetmon\n";
    print "Client tool: fastnetmon_client\n";
    print "API client: fastnetmon_api_client\n";
    print "Log file: /var/log/fastnetmon.log\n";

    send_tracking_information('finished');
    send_ga_event("installation_finished");

    exit(0);
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

