How to collect data for debugging netflow:
```bash
tcpdump -w ipfix_example_ipt_netflow_syn_flood.pcap -n 'udp dst port 2055' 
```
