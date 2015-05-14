#!/usr/bin/perl

use strict;
use warnings;

use Data::Dumper;

my $vm_name = "fastnetmonvm.fastvps.ru";

execute_precheck();
execute_detach();

sub execute_precheck {
    my $cmdline = `cat /proc/cmdline`;
    chomp $cmdline;
 
    unless ($cmdline =~ /intel_iommu=on/) {
        print "Please add intel_iommu=on to kernel params\n";
        
        print "You could do it in file /etc/default/grub\n";
        print 'With param: GRUB_CMDLINE_LINUX_DEFAULT="intel_iommu=on"', "\n";
        print "update-grub\n";
        print "reboot\n";

        exit(1);
    }  
    
    my $conf_path = '/etc/modprobe.d/vfio_iommu_type1.conf';

    # Debian Jessie, 3.16, Intel(R) Core(TM) i7-3820 CPU @ 3.60GHz desktop 
    # Could be fixed in runtime:
    # echo 1 > /sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts
    unless (-e $conf_path) {
        print "Please apply work around for error\n";
        print "vfio_iommu_type1_attach_group: No interrupt remapping support.\n\n";

        print "echo \"options vfio_iommu_type1 allow_unsafe_interrupts=1\" > /etc/modprobe.d/vfio_iommu_type1.conf";
        print "\n";
        print "And reboot server \n";
        
        exit(0);
    }
}

sub execute_detach {
    # 03:00.0 Ethernet controller: Intel Corporation 82599ES 10-Gigabit SFI/SFP+ Network Connection (rev 01)
    my @lspci = `lspci`;
    chomp @lspci;

    # We process only Ethernet devices
    @lspci = grep {/Ethernet/} @lspci;

    @lspci = grep {/82599/} @lspci;

    my @nic_addresses = ();

    for my $nic (@lspci) {
        if ($nic =~ /(\d+\:\d+\.\d+)/) {
            push @nic_addresses, $1;
        }
    }

    my @virsh_full_addresses = ();
    for my $nic_address (@nic_addresses) {
        my $nic_address_in_virsh_format = $nic_address;
        $nic_address_in_virsh_format =~ s/[\:\.]/_/;

        my $virsh_address_full_format = `virsh nodedev-list | grep '$nic_address_in_virsh_format'`;
        chomp $virsh_address_full_format;

        push @virsh_full_addresses, $virsh_address_full_format;
    }

    # We use hash because multy port NICs could produce multiple equal address groups
    my $xml_blocks = {};

    print "Detach NICs from the system\n";
    for my $virsh_address (@virsh_full_addresses) {
        my $output = `virsh nodedev-dettach $virsh_address 2>&1`;
        chomp $output;

        if ($? != 0) {
            die "virsh nodedev-dettach failed with output: $output\n";
        }
   
        # <address domain='0x0000' bus='0x03' slot='0x00' function='0x0'/> 
        my @xml_address_data = `virsh nodedev-dumpxml $virsh_address | grep address`;
        chomp @xml_address_data;

        for my $xml_line (@xml_address_data) {
            # cleanup
            $xml_line =~ s/^\s+//g;
            $xml_line =~ s/\s+$//g;

            $xml_blocks->{ $xml_line } = 1;
        }
    }

    my $target_xml = '';
    for my $address_block (keys %$xml_blocks) {
        $target_xml .= "<hostdev mode='subsystem' type='pci' managed='yes'><source>$address_block</source></hostdev>\n";
    }

    print "Please run virsh edit $vm_name and insert this xml to devices block\n\n";
    
    print $target_xml, "\n";

    print "After this please execute virsh destroy $vm_name and virsh start $vm_name for applying changes\n";
} 
