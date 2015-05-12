### With this guide you could integrate ExaBGP and FastNetMon without socat tool

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
