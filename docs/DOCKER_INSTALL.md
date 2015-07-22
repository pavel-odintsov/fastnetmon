
You can run docker from pre built container.

First, get fastnetmon.conf from github, edit it after download.

```
wget https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon.conf -O /etc/fastnetmon.conf
```


Now create networks.list. Include all your networks CIDR 

```
echo "10.10.0.0/20
10.200.0.0/19" > /etc/networks.list
````

Add your whitelist networks:

```
echo "10.240.0.0/24" > /etc/networks_whitelist
```


Now create log files to access them outside cointainer

```
touch /var/log/fastnetmon.log
chmod 0644 /var/log/fastnetmon.log

mkdir /var/log/fastnetmon_attacks
chmod 0700 /var/log/fastnetmon_attacks

```

Downloading image

```
docker pull robertoberto/fastnetmon
```


You can run docker manually to test it, or run from a screen. 

In this case we're mapping IPFIX to container. Replace IPFIX1 and IPFIX2 with your local network interface ip which listen to IPFIX from your routers. You can use only one IPFIX interface or more.


```
docker run -a stdin -a stdout -i \
-v /var/log/fastnetmon_attacks:/var/log/fastnetmon_attacks \
-v /var/log/fastnetmon.log:/var/log/fastnetmon.log \
-v /etc/networks_list:/etc/networks_list \
-v /etc/networks_whitelist:/etc/networks_whitelist \
-v /etc/fastnetmon.conf:/etc/fastnetmon.conf \
-p IPFIX1:2055:2055/udp \
-p IPFIX2:2055:2055/udp \
-t robertoberto/fastnetmon /bin/bash
```

Now you're inside container. Run

```
fastnetmon &

fastnetmon_client
```


Also you can build your own image using Dockerfile at packages/docker

```
cd packages/docker
docker build .
```


