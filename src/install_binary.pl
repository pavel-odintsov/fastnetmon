#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;

my $start_time = time();

my $install_log_path = '/tmp/fastnetmon_install.log';

my $distro_type = ''; 
my $distro_version = ''; 
my $distro_architecture = '';

# Used for VyOS and different appliances based on rpm/deb
my $appliance_name = ''; 

# So, you could disable this option but without this feature we could not improve FastNetMon for your distribution
my $do_not_track_me = '';

my $cpus_number = get_logical_cpus_number();

main();

sub get_logical_cpus_number {
    my @cpuinfo = `cat /proc/cpuinfo`;
    chomp @cpuinfo;
        
    my $cpus_number = scalar grep {/processor/} @cpuinfo;
    
    return $cpus_number;
}

### Functions start here
sub main {
    detect_distribution();

    # Refresh information about packages
    init_package_manager();

    send_tracking_information('started');

    install_fastnetmon();

    my $install_time = time() - $start_time;
    my $pretty_install_time_in_minutes = sprintf("%.2f", $install_time / 60);

    print "We have installed project in $pretty_install_time_in_minutes minutes\n";
}

sub send_tracking_information {
    my $step = shift;

    unless ($do_not_track_me) {
        my $stats_url = "http://178.62.227.110/new_fastnetmon_installation";
        my $post_data = "distro_type=$distro_type&distro_version=$distro_version&distro_architecture=$distro_architecture&step=$step";
        my $user_agent = 'FastNetMon install tracker v1';

        `wget --post-data="$post_data" --user-agent="$user_agent" -q '$stats_url'`;
    }
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
    my $output = `sha1sum $path`;
    chomp $output;
    
    my ($sha1) = ($output =~ m/^(\w+)\s+/);

    return $sha1;
}

sub download_file {
    my ($url, $path, $expected_sha1_checksumm) = @_;

    `wget --quiet '$url' -O$path`;

    if ($? != 0) {
        print "We can't download archive $url correctly\n";
        return '';
    }

    if ($expected_sha1_checksumm) {
        if (get_sha1_sum($path) eq $expected_sha1_checksumm) {
            return 1;
        } else {
            print "Downloaded archive has incorrect sha1\n";
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
    # $distro_type, $distro_version, $appliance_name

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
        if ($issue_first_line =~ m/Debian/) {
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
        die "This distro is unsupported, please do manual install";
    }

}

sub apt_get {
    my @packages_list = @_; 

    # We install one package per apt-get call because installing multiple packages in one time could fail of one package is broken
    for my $package (@packages_list) {
        exec_command("apt-get install -y --force-yes $package");

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

sub install_fastnetmon {
    print "Install FastNetMon dependency list\n";
  
    my $repository_address = 'http://178.62.227.110/fastnetmon_binary_repository/test_package_build'; 

    my $file_name = '';
 
    if ($distro_type eq 'ubuntu') {
        $file_name = "ubuntu-$distro_version-x86_64.deb"; 
    } elsif ($distro_type eq 'debian') {
        my $our_own_debian_version = $distro_version;
        # Convert 6.x to 6.0 
        $our_own_debian_version =~ s/\.\d+/.0/;

        $file_name = "debian-$our_own_debian_version-x86_64.deb";
    } elsif ($distro_type eq 'centos') {
        my $our_own_centos_version = int($distro_version);

        $file_name = "centos-$our_own_centos_version-x86_64.rpm";
    } else {
        die "Sorry, we haven't binary packages for your distribution\n";
    }

    # http://178.62.227.110/fastnetmon_binary_repository/test_package_build/fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-centos-6-x86_64_x86_64.rpm
 
    my $git_version = '447aa5b86bb5a248e310c15a4d5945e72594d6cf';
    my $bundle_file_name = "fastnetmon-git-$git_version-$file_name";
 
    my $full_url = "$repository_address/$bundle_file_name";

    print "I will try to download file from $full_url\n";

    my $fastnetmon_download_result = download_file($full_url, "/tmp/$bundle_file_name");

    unless ($fastnetmon_download_result) {
        die "Can't download FastNetMon distribution\n";
    }

    if ($distro_type eq 'debian') {
        if (int($distro_version) == 6) {
            apt_get('libpcap0.8', 'libnuma1', 'libicu44');
        }
 
        if (int($distro_version) == 7) {
            apt_get('libpcap0.8', 'libnuma1', 'libicu48');
        }

        if (int($distro_version) == 8) {
            apt_get('libpcap0.8', 'libnuma1', 'libicu52');
        }
    }

    if ($distro_type eq 'centos') {
        # For CentOS 6 and 7 this list is equal
        yum('libpcap', 'libicu');

        if (int($distro_version) == 7) {
            yum('numactl-libs');
        } elsif (int($distro_version) == 6) {
            yum('numactl');
        } 
    }

    if ($distro_type eq 'ubuntu') {
        if ($distro_version eq '14.04') {
            apt_get('libicu52', 'libpcap0.8', 'libnuma1');
        }    
    }

    if ($distro_type eq 'centos') {
        yum("/tmp/$bundle_file_name");
    } elsif ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        exec_command("dpkg -i /tmp/$bundle_file_name");
    }

    print "If you have any issues, please check /var/log/fastnetmon.log file contents\n";
    print "Please add your subnets in /etc/networks_list in CIDR format one subnet per line\n";
}

