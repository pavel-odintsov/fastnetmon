# Redis backend

I introduced Redis support for store information about attacks.

Please call ```redis-cli``` and input following commands

```bash
keys *
1) "10.10.10.200_flow_dump"
2) "10.10.10.200_information"
3) "10.10.10.200_packets_dump"
```

Basic information about attack (stored immediately)
```get 10.10.10.200_information```

Complete flow dump for attack if flow tracking enabled (stored immediately)
```get 10.10.10.200_flow_dump```

Complete per packet attack dump (stored with some delay; can be absent in some cases of slow attacks)
```get 10.10.10.200_packets_dump```


