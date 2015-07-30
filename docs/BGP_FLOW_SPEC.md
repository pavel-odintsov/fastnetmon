### All this docs about ExaBGP 4.0 (Git master branch)

Clone code:
```bash
cd /usr/src/
git clone git clone https://github.com/Exa-Networks/exabgp.git
```

They are not compatible with ExaBGP 3.0

vim /root/announcer.py:

```bash
#!/usr/bin/python
 
fl=open("/var/run/exabgp.cmd", "w")
 
fl.write("announce flow route source 4.0.0.0/24 destination 127.0.0.0/24 protocol [ udp ] source-port [ =53 ] destination-port [ =80 ] packet-length [ =777 =1122 ] fragment [ is-fragment dont-fragment ] rate-limit 1024" + '\n')
fl.flush()
 
fl.close
```

Please be careful about flush and trailing '\n'!!!

vim /etc/exabgp_flowspec.conf:
```bash
process announce-routes {
    run /usr/bin/socat stdout pipe:/var/run/exabgp.cmd;
    encoder json;
}

neighbor 127.0.0.1 {
    router-id 1.2.3.4;
    local-address 127.0.0.1;
    local-as 1;
    peer-as 1;
    group-updates false;

  family {
        ipv4 flow;
    }
    api {
        processes [ anounce-routes ];
    }
}

```

Run it:
```bash
cd /usr/src/exabgp
env  exabgp.api.file=/tmp/exabgp.cmd exabgp.daemon.user=root exabgp.daemon.daemonize=false exabgp.daemon.pid=/var/run/exabgp.pid exabgp.log.destination=/var/log/exabgp.log sbin/exabgp --debug /etc/exabgp_flowspec.conf 
```

Then, please install Git version of FastNetMon (stable version do not support this features yet):
```bash
wget https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl 
sudo perl fastnetmon_install.pl --use-git-master
```

FastNetMon configuration /etc/fastnetmon.conf:
```bash
# This options are mandatory for Flow Spec attack detector
collect_attack_pcap_dumps = on
process_pcap_attack_dumps_with_dpi = on

exabgp = on
exabgp_command_pipe = /var/run/exabgp.cmd
exabgp_community = 65001:666
exabgp_next_hop = 10.0.3.114

exabgp_flow_spec_announces = on

# Please switch off unicast BGP announces with ExaBGP because they are not compatible with Flow Spec
exabgp_announce_whole_subnet = no
exabgp_announce_host = no
```

Be aware! We will announce rules with discard option!

Currently we support only most popular amplification attack types:
- DNS amplification (we drop all udp traffic originating from 53 port)
- NTP amplification (we drop all udp traffic originating from 123 port)
- SSDP amplification (we drop all udp traffic originating from 1900 port)
- SNMP amplification (we drop all udp traffic originating from 161 port)
