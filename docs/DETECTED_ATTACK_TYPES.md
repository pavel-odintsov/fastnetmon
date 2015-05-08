### We could detect really any attack targeted to channel overflow

But for very popular attack types we prepared algorithm which could give name for every attack of following type:
- syn_flood: TCP packets with enabled SYN flag 
- udp_flood: flood with UDP packets (so recently in result of amplification)
- icmp flood: flood with ICMP packets
- ip_fragmentation_flood: IP packets with MF flag set or with non zero fragment offset
