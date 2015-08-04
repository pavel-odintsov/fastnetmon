### InfluxDB integration

You could install InfluxDB from [binary packages](https://influxdb.com/download/index.html)

For Debian 8 Jessie I could offer part of manual here:
```bash
wget https://s3.amazonaws.com/influxdb/influxdb_0.9.2_amd64.deb
sudo dpkg -i influxdb_0.9.2_amd64.deb 
```

Then we should enable graphite protocol emulation in configuration file: /etc/opt/influxdb/influxdb.conf:
```bash
[[graphite]]
  enabled = true
  bind-address = ":2003"
  protocol = "tcp"
  consistency-level = "one"
  name-separator = "." 
```

And disable Graphite daemons if you use they before:
```bash
systemctl stop carbon-cache
```

And start InfluxDB:
```bash
systemctl restart influxdb
```

You will got web frontend on 8083 port and query API interface on 8086.

Then we need fix some parts of /etc/fastnetmon.conf configuration file:
```bash
graphite = on
graphite_host = 127.0.0.1
graphite_port = 2003
graphite_prefix = fastnetmon
```

And apply changes to configuration file:
```bash
systemctl restart fastnetmon
```

Finally you could query data from InfluxDB with CLI tool /opt/influxdb/influx:
```bash
select MEAN(value) from "fastnetmon.outgoing.pps"
name: fastnetmon.outgoing.pps
-----------------------------
time            mean
1970-01-01T00:00:00Z    334968.38950276235
```
