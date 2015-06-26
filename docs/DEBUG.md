How to collect data for debugging netflow:
```bash
tcpdump -w /root/netflow_data.pcap -n 'udp dst port 2055'
```

How to collect data for debugging sFLOW:
```bash
 tcpdump -w /root/sflow_data.pcap -n 'udp dst port 6343'
```
