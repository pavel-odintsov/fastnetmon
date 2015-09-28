### We could run multiple instances of FastNetMon on same server

First of all please create multiple configuration files for each instance.

In each file you should specify uniq paths for following options for each separate instance:
```bash
# Path to pid file for checking process liveness 
pid_path = /var/run/fastnetmon.pid

# Path to file where we store information for fastnetmon_client
cli_stats_file_path = /tmp/fastnetmon.dat
```

Next you need to specify custom path to configuration file:
```bash
./fastnetmon --configuration_file=/etc/fastnetmon_mayflower.conf --daemonize
./fastnetmon --configuration_file=/etc/fastnetmon_hetzner.conf --daemonize
```

FastNetMon cli client expects stats file with default path /tmp/fastnetmon.dat so you need to set custom path with environment variable:
```bash
cli_stats_file_path=/tmp/fastnetmon_second_instance.dat  ./fastnetmon_client
```
