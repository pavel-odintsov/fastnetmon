### InfluxDB integration

InfluxDB is a very fast time series database written in awesome Go language. You could find some performance tests for InfluxDB and Graphite [here](https://groups.google.com/forum/#!topic/influxdb/0VeUQCqzgVg).

You could install InfluxDB from [binary packages](https://influxdb.com/download/index.html).

For Debian 8 Jessie I could offer part of this manual here:
Recommended version: >=0.9.4 with support for graphite/batch

```bash
wget https://s3.amazonaws.com/influxdb/influxdb_0.9.4.2_amd64.deb
dpkg -i influxdb_0.9.4.2_amd64.deb
```

Then we should enable graphite protocol emulation in configuration file: /etc/opt/influxdb/influxdb.conf
As well enable batch for avoid metric loss under load, and add templates for converting graphite metrics
to InfluxDB measurements, with its proper tags.

```bash
[[graphite]]
  enabled = true
  bind-address = ":2003"
  protocol = "tcp"
  consistency-level = "one"
  name-separator = "."

  # batch-size / batch-timeout requires InfluxDB >= 0.9.3
  batch-size = 5000 # will flush if this many points get buffered
  batch-timeout = "1s" # will flush at least this often even if we haven't hit buffer limit

  templates = [
    "fastnetmon.hosts.* app.measurement.cidr.direction.function.resource",
    "fastnetmon.networks.* app.measurement.cidr.direction.resource",
    "fastnetmon.total.* app.measurement.direction.resource"
  ]

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
Connected to http://localhost:8086 version 0.9.3-nightly-c2dbf16
InfluxDB shell 0.9.3-nightly-c2dbf16
> use graphite
Using database graphite
> show measurements
name: measurements
------------------
hosts
networks
total

>
> select mean(value) from networks where direction = 'incoming' and resource = 'bps' group by *
name: networks
tags: app=fastnetmon, cidr=10.20.30.40_24, direction=incoming, resource=bps
time      mean
----      ----
1970-01-01T00:00:00Z  408540.85148584365

```

Or you could install [Grafana](http://grafana.org) and make awesome Dashboard ;)
