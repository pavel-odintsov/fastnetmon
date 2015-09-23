# FastNetMon and ExaBGP integration

FastNetMon could enable/disable announce of blackholed IPs (/32) to BGP core router (Cisco, Juniper, Quagga). This feature implemented with ExaBGP toolkit.

If you want to use this capability, please set following params in /etc/fastnetmon.conf and tune they to values suitable in your network:
```bash
exabgp = on
exabgp_command_pipe = /var/run/exabgp.cmd
exabgp_community = 65001:666
exabgp_next_hop = 10.0.3.114
exabgp_announce_host = on
```

Secondly, you should install, configure and run ExaBGP toolkit.

Install ExaBGP:
```bash
apt-get install python-pip
pip install exabgp
```

Install socat (if you haven't socat for your platform, please check this [manual](EXABGP_INTEGRATION_WITHOUT_SOCAT.md)):
```bash
apt-get install -y socat
yum install -y socat
```

Create example configuration: ```vim /etc/exabgp_blackhole.conf```

Example here (please fix this configuration to your network):
```bash
group Core_v4 {
    hold-time 180;
    # local AS number
    local-as 65001;
    # Remote AS number
    peer-as 1234;
    # ID for this ExaBGP router
    router-id 10.0.3.114;
    graceful-restart 1200;

    # Remote peer
    neighbor 10.0.3.115 {
        # Local IP addess which used for connections to this peer
        local-address 10.0.3.114;
        description "Quagga";
    }   

    # Add this line for process management
    process service-dynamic {
        run /usr/bin/socat stdout pipe:/var/run/exabgp.cmd;
    }   
}
```

Run ExaBGP:
```bash
env exabgp.daemon.user=root exabgp.daemon.daemonize=true exabgp.daemon.pid=/var/run/exabgp.pid exabgp.log.destination=/var/log/exabgp.log exabgp /etc/exabgp_blackhole.conf
```

You could read my articles about ExaBGP configuration too: [first](http://www.stableit.ru/2015/04/quagga-bgp-and-exabgp-work-together-for.html) and [second](http://www.stableit.ru/2015/04/how-to-control-exabgp-from-external-tool.html)
