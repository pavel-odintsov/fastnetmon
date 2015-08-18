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

    print "We have built project in $pretty_install_time_in_minutes minutes\n";
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

# TODO return this code
my $fastnetmon_code_dir = '/tmp/fake_path';

sub install_init_scripts {
    # Init file for any systemd aware distro
    if ( ($distro_type eq 'debian' && $distro_version > 7) or ($distro_type eq 'centos' && $distro_version >= 7) ) {
        my $systemd_service_path = "/etc/systemd/system/fastnetmon.service";
        exec_command("cp $fastnetmon_code_dir/fastnetmon.service $systemd_service_path");

        exec_command("sed -i 's#/usr/sbin/fastnetmon#/opt/fastnetmon/fastnetmon#' $systemd_service_path");

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
  
    my $repository_address = 'http://178.62.227.110/fastnetmon_binary_repository'; 
    my $bundle_version = '';
 
    my $bundle_file_name = "fastnetmon-binary-$bundle_version-$distro_type-$distro_version-$distro_architecture.tar.gz";

    if ($distro_type eq 'ubuntu' && $distro_version eq '12.04') {
        $bundle_version = 'git-9e20adc243c2f2949cc18cae3dc466b3f6f8604c';
    }

    if ($distro_type eq 'ubuntu' && $distro_version eq '14.04') {
        $bundle_version = 'git-c7831ff71a182a15903f47de2afd99ed24ca7201';
    }

    unless ($bundle_version) {
        die "Sorry! We haven't packages for your distribution now\n";
    }
    
    my $full_url = "$repository_address/$bundle_file_name";

    print "I will try to download file from $full_url\n";

    my $fastnetmon_download_result = download_file($full_url, "/tmp/$bundle_file_name");

    unless ($fastnetmon_download_result) {
        die "Can't download FastNetMon distribution\n";
    }

    # TODO: use seoarate folder instead
    # Unpack everything in /opt
    exec_command("tar -xf /tmp/$bundle_file_name -C /opt");

    if ($distro_type eq 'debian') {
        if ($distro_version == 8) {
            apt_get('libpcap0.8', 'libicu52', 'libnuma1');
        }
    
        # TODO
    }

    if ($distro_type eq 'centos') {
        # For CentOS 6 and 7 this list is equal
        yum('libpcap', 'libicu', 'numactl-libs');
    }

    if ($distro_type eq 'ubuntu') {
        if ($distro_version eq '14.04') {
            apt_get('libicu52', 'libpcap0.8', 'libnuma1');
        }    
    }

    my $fastnetmon_config_path = "/etc/fastnetmon.conf";
    unless (-e $fastnetmon_config_path) {
        print "Create stub configuration file\n";
        exec_command("cp $fastnetmon_code_dir/fastnetmon.conf $fastnetmon_config_path");
    
        my @interfaces = get_active_network_interfaces();
        my $interfaces_as_list = join ',', @interfaces;
        print "Select $interfaces_as_list as active interfaces\n";

        print "Tune config\n";
        exec_command("sed -i 's/interfaces.*/interfaces = $interfaces_as_list/' $fastnetmon_config_path");
    }

    print "If you have any issues, please check /var/log/fastnetmon.log file contents\n";
    print "Please add your subnets in /etc/networks_list in CIDR format one subnet per line\n";

    # TODO: return this code ASAP!!!
    #my $init_script_result = install_init_scripts();

    # Print unified run message 
    #unless ($init_script_result) {
    #    print "You can run fastnetmon with command: /opt/fastnetmon/fastnetmon\n";
    #}
}

sub get_active_network_interfaces {
    my @interfaces = `LANG=C netstat -i|egrep -v 'lo|Iface|Kernel'|awk '{print \$1}'`;
    chomp @interfaces;

    my @clean_interfaces = ();

    for my $iface (@interfaces) {
        # skip aliases
        if ($iface =~ /:/) {
            next;
        }

        push @clean_interfaces, $iface;
    }

    return  @clean_interfaces;
}

