### GoBGP integration

We have complete GoBGP integration for unicast IPv4.

We have following configuration options for GoBGP:
```bash
gobgp = off
gobgp_next_hop = 0.0.0.0
gobgp_announce_host = on
gobgp_announce_whole_subnet = off
```

We haven't enabled GoBGP build by default because it needs really huge dependency list.

Please use following reference:
```bash
wget https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl 
```

Open fastnetmon_install.pl file and replace ```my $enable_gobgp_backend = '';``` by ```my $enable_gobgp_backend = '1';```.

```bash
sudo perl fastnetmon_install.pl --use-git-master
```

Create example configuration for GoBGPD in gobgpd.conf file in current directory:
```bash
[Global]
  [Global.GlobalConfig]
    As = 65001
    RouterId = "213.133.111.200"

[Neighbors]
  [[Neighbors.NeighborList]]
    [Neighbors.NeighborList.NeighborConfig]
      NeighborAddress = "10.10.10.250"
      PeerAs = 65001
    [Neighbors.NeighborList.AfiSafis]
      [[Neighbors.NeighborList.AfiSafis.AfiSafiList]]
        AfiSafiName = "ipv4-unicast"
```

Run it:
```bash
/opt/gobgp_1_0_0/gobgpd -f gobgpd.conf
```

Check announced routes:
```bash
/opt/gobgp_1_0_0/gobgp global rib 
    Network             Next Hop             AS_PATH              Age        Attrs
*>  192.168.1.1/32      0.0.0.0                                   00:00:08   [{Origin: ?}]
```

Announce custom route:
```bash
gobgp global rib add 10.33.0.0/24 -a ipv4
```

Withdraw route (please be careful! FastNetMon do not expect this from your side):
```bash
gobgp global rib del 10.33.0.0/24 -a ipv4
```
