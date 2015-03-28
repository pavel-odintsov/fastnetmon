How to collect data for debugging netflow:
```bash
tcpdump -w ipfix_example_ipt_netflow_syn_flood.pcap -n 'udp dst port 2055' 
```

How to collect data for debugging sFLOW:
```bash
 tcpdump -w /root/sflow5_network_dump.dat -n -i eth0 'udp dst port 6343'
```
