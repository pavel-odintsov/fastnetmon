### This article describes everything about ongoing MongoDB integration

Debian 8 Jessie.

Install MongoDB itself:
```bash
apt-get install -y mongodb-server mongodb-clients
```

Build FastNetMon from Git's master branch.

Enable it in configuration file:
```bash
mongodb_enabled = on
```

Query data about attacks:
```bash
> use fastnetmon
switched to db fastnetmon
> show collections
attacks
system.indexes
> db.attacks.find()
{ "_id" : ObjectId("560bf6f5d6db1e6921740261"), "192_168_1_1_information_30_09_15_16:51:33" : { "ip" : "192.168.1.1", "attack_details" : { "attack_type" : "syn_flood", "initial_attack_power" : 11495, "peak_attack_power" : 11495, "attack_direction" : "incoming", "attack_protocol" : "tcp", "total_incoming_traffic" : 689822, "total_outgoing_traffic" : 0, "total_incoming_pps" : 11495, "total_outgoing_pps" : 0, "total_incoming_flows" : 0, "total_outgoing_flows" : 0, "average_incoming_traffic" : 689822, "average_outgoing_traffic" : 0, "average_incoming_pps" : 11495, "average_outgoing_pps" : 0, "average_incoming_flows" : 0, "average_outgoing_flows" : 0, "incoming_ip_fragmented_traffic" : 0, "outgoing_ip_fragmented_traffic" : 0, "incoming_ip_fragmented_pps" : 0, "outgoing_ip_fragmented_pps" : 0, "incoming_tcp_traffic" : 43615380, "outgoing_tcp_traffic" : 0, "incoming_tcp_pps" : 726922, "outgoing_tcp_pps" : 0, "incoming_syn_tcp_traffic" : 43615380, "outgoing_syn_tcp_traffic" : 0, "incoming_syn_tcp_pps" : 726923, "outgoing_syn_tcp_pps" : 0, "incoming_udp_traffic" : 0, "outgoing_udp_traffic" : 0, "incoming_udp_pps" : 0, "outgoing_udp_pps" : 0, "incoming_icmp_traffic" : 0, "outgoing_icmp_traffic" : 0, "incoming_icmp_pps" : 0, "outgoing_icmp_pps" : 0 } } }
```
