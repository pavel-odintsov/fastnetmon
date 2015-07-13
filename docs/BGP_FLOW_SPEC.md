### All this docs about ExaBGP 4.0 (Git master branch)

Thay are not compatible with ExaBGP 3.0

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
env  exabgp.api.file=/tmp/exabgp.cmd exabgp.daemon.user=root exabgp.daemon.daemonize=false exabgp.daemon.pid=/var/run/exabgp.pid exabgp.log.destination=/var/log/exabgp.log sbin/exabgp --debug /etc/exabgp_flowspec.conf 
```
