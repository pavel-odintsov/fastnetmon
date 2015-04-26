# FastNetMon and ExaBGP integration

FastNetMon could enable/disable announce of blackholed IPs (/32) to BGP core router (Cisco, Juniper, Quagga). This feature implemented with ExaBGP toolkit.

If you want to use this capability, please set following params in /etc/fastnetmon.conf and tune they to values suitable in your network:
```bash
exabgp = on
exabgp_command_pipe = /var/run/exabgp.cmd
exabgp_community = 65001:666
exabgp_next_hop = 10.0.3.114
```

Secondly, you should install, configure and run ExaBGP toolkit.

Install ExaBGP:
```bash
pip install exabgp
```

Create example configuration: ```vim /etc/exabgp_blackhole.conf```

Example here (please fix this configuration to your network):
```bash
group Core_v4 {
    hold-time 180;
    local-as 65001;
    peer-as 1234;
    router-id 10.0.3.114;
    graceful-restart 1200;

    # Static announce is not used
    # static {
    #     route 10.10.10.1/32 next-hop 10.0.3.114 community 65001:666;
    # }   

    neighbor 10.0.3.115 {
        local-address 10.0.3.114;
        description "Quagga";
    }   

    # Add this line for process management
    process service-dynamic {
        run /etc/exabgp/exabgp_pipe_provider.sh;
    }   
}
```

For PIPE API we need create this script: ```vim /etc/exabgp/exabgp_pipe_provider.sh```

Script code here:
```bash

```#!/bin/sh
FIFO="/var/run/exabgp.cmd"

rm -f $FIFO
mkfifo $FIFO
tail -f $FIFO
```

Set exec flag for script: ```chmod +x /etc/exabgp/exabgp_pipe_provider.sh```

Run ExaBGP:
```bash
env exabgp.daemon.user=root exabgp.daemon.daemonize=true exabgp.daemon.pid=/var/run/exabgp.pid exabgp.log.destination=/var/log/exabgp.log exabgp /etc/exabgp_blackhole.conf
```

You could read my articles about ExaBGP configuration too: [first](http://www.stableit.ru/2015/04/quagga-bgp-and-exabgp-work-together-for.html) and [second](http://www.stableit.ru/2015/04/how-to-control-exabgp-from-external-tool.html)
