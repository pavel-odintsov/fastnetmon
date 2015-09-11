
You can run docker from pre-built image:
```
docker pull robertoberto/fastnetmon
```

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


To send email, we recommend you to use a external and linked postfix container such:

```
docker pull panubo/postfix

docker run \
-e MAILNAME="example.com" \
-e MYNETWORKS="127.0.0.0/8, 172.16.0.0/12" \
--name postfix \
-t panubo/postfix
```

When you link another container with docker other container name will be added to /etc/hosts pointing to its internal IP. So you can use python script notify (https://github.com/FastVPSEestiOu/fastnetmon/blob/master/src/scripts/fastnetmon_notify.py), instead of bash one.

Just change MAIL_HOSTNAME="localhost" to MAIL_HOSTNAME="postfix" if you start fastnetmon docker container with --link postfix:postfix and create another docker instance with panubo/postfix as --name postfix, for example.


A full example of running fastnetmon linked to postfix:
```
docker run -a stdin -a stdout -i \
-v /var/log/fastnetmon_attacks:/var/log/fastnetmon_attacks \
-v /var/log/fastnetmon.log:/var/log/fastnetmon.log \
-v /etc/networks_list:/etc/networks_list \
-v /etc/fastnetmon.conf:/etc/fastnetmon.conf \
-v /etc/networks_whitelist:/etc/networks_whitelist \
-v /usr/local/fastnetmon:/usr/local/fastnetmon \
-v /etc/exabgp_blackhole.conf:/etc/exabgp_blackhole.conf \
-v /var/log/fastnetmon-notify.log:/var/log/fastnetmon-notify.log \
-p 10.100.20.2:2055:2055/udp \
-p 10.100.20.6:2055:2055/udp \
-p 10.100.20.2:179:179/tcp \
--name fastnetmon \
--link postfix:postfix \
-t robertoberto/fastnetmon:latest /bin/bash
```

First, you need to create all those files and dirs in main Linux system.
```
mkdir /usr/local/fastnetmon
touch /var/log/fastnetmon_attacks /var/log/fastnetmon.log /etc/networks_list /etc/networks_whitelist /etc/fastnetmon.conf /etc/exabgp_blackhole.conf/var/log/fastnetmon-notify.log

cp /etc/fastnetmon.conf /etc/fastnetmon.conf.bkp
cp /usr/local/fastnetmon/fastnetmon_notify.py /usr/local/fastnetmon/fastnetmon_notify.py.bkp

wget https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/scripts/fastnetmon_notify.py -O /usr/local/fastnetmon/fastnetmon_notify.py 
chmod +x /usr/local/fastnetmon/fastnetmon_notify.py 
wget https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon.conf -O /etc/fastnetmon.conf
```

