Documentation to integrate Fastnetmon with inline jflow using Juniper MX Series routers (MX5, MX10, MX40, MX80, MX104, MX120, MX240, MX480, MX960).

In this example, we use rate=10, but you can change to rate=100, depending on your traffic. You need to change fastnetmon.conf netflow_sampling_ratio with same rate you setup on your MX router.

Our topology is two MX80 routers, named r1 and r2. From each router connected directly to Fastnetmon server. 

Fastnetmon server have 2 interfaces:
10.50.1.2/30 - connected to r1
10.50.1.6/30 - connected to r2

R1 have 1 transit connected to ge-1/0/0.0
R2 have 1 transit connected to ge-1/0/0.0

Setting sampling on transit interfaces. Run that on those interfaces on each router.

```
set interfaces ge-1/0/0.0 family inet sampling input
```


You can check https://github.com/FastVPSEestiOu/fastnetmon/blob/master/docs/DOCKER_INSTALL.md to see how to configure Fastnetmon to work with inline-jflow

```
r1# show interfaces ge-1/0/4  
unit 0 {
    description netflow-coletor;
    family inet {
        address 10.50.1.1/30;
    }
}



r1# show interfaces ge-1/0/4 | display set 
set interfaces ge-1/0/4 unit 0 description netflow-coletor
set interfaces ge-1/0/4 unit 0 family inet address 10.50.1.1/30

r2# show interfaces ge-1/0/4  
unit 0 {
    description netflow-coletor;
    family inet {
        address 10.50.1.5/30;
    }
}
r2# show interfaces ge-1/0/4 | display set 
set interfaces ge-1/0/4 unit 0 description netflow-coletor
set interfaces ge-1/0/4 unit 0 family inet address 10.50.1.5/30
```

Now add templates configuration on r1 and r2. Take care of flow-active-timeout and flow-inactive-timeout it should be less than average_calculation_time. Try average_calculation_time=20 where flow-active-timeout=10:
```
set services flow-monitoring version-ipfix template ipv4 flow-active-timeout 10
set services flow-monitoring version-ipfix template ipv4 flow-inactive-timeout 10
set services flow-monitoring version-ipfix template ipv4 template-refresh-rate packets 1000
set services flow-monitoring version-ipfix template ipv4 template-refresh-rate seconds 10
set services flow-monitoring version-ipfix template ipv4 option-refresh-rate packets 1000
set services flow-monitoring version-ipfix template ipv4 option-refresh-rate seconds 10
set services flow-monitoring version-ipfix template ipv4 ipv4-template
set chassis tfeb slot 0 sampling-instance ipfix


flow-monitoring {
    version-ipfix {
        template ipv4 {
            flow-active-timeout 60;
            flow-inactive-timeout 60;
            template-refresh-rate {
                packets 1000;
                seconds 10;
            }
            option-refresh-rate {
                packets 1000;
                seconds 10;
            }
            ipv4-template;
        }
    }
}

slot 0 {
    sampling-instance ipfix;
}


```


Now setup ipfix exports:
```
r1# show forwarding-options 
sampling {
    instance {
        ipfix {
            input {
                rate 10;
            }
            family inet {
                output {
                    flow-server 10.50.1.2 {
                        port 2055;
                        version-ipfix {
                            template {
                                ipv4;
                            }
                        }
                    }
                    inline-jflow {
                        source-address 10.50.1.1;
                    }
                }
            }
        }
    }
}

r1# show forwarding-options | display set 
set forwarding-options sampling instance ipfix input rate 10
set forwarding-options sampling instance ipfix family inet output flow-server 10.50.1.2 port 2055
set forwarding-options sampling instance ipfix family inet output flow-server 10.50.1.2 version-ipfix template ipv4
set forwarding-options sampling instance ipfix family inet output inline-jflow source-address 10.50.1.1


r2# show forwarding-options 
sampling {
    instance {
        ipfix {
            input {
                rate 10;
            }
            family inet {
                output {
                    flow-server 10.50.1.6 {
                        port 2055;
                        version-ipfix {
                            template {
                                ipv4;
                            }
                        }
                    }
                    inline-jflow {
                        source-address 10.50.1.5;
                    }
                }
            }
        }
    }
}

r2# show forwarding-options | display set 
set forwarding-options sampling instance ipfix input rate 10
set forwarding-options sampling instance ipfix family inet output flow-server 10.50.1.6 port 2055
set forwarding-options sampling instance ipfix family inet output flow-server 10.50.1.6 version-ipfix template ipv4
set forwarding-options sampling instance ipfix family inet output inline-jflow source-address 10.50.1.5
```




```
