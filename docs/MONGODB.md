### This article describes everything about ongoing MongoDB integration

Sorry, we haven't integration for it now but we will finish this work sometimes :)

Debian 8 Jessie.

Install MongoDB itself:
```bash
apt-get install -y mongodb-server mongodb-clients mongodb-dev  
```

Library compilation:
```bash
cd /usr/src
wget https://github.com/mongodb/mongo-c-driver/releases/download/1.1.9/mongo-c-driver-1.1.9.tar.gz
tar xzf mongo-c-driver-1.1.9.tar.gz
cd mongo-c-driver-1.1.9
./configure --prefix=/opt/mongo_c_driver
make
make install
echo /opt/mongo_c_driver/lib > /etc/ld.so.conf.d/mongodb_c_driver.conf
ldconfig
```

Build test example:
```bash
g++ mongodb_client.cpp $(PKG_CONFIG_PATH=/opt/mongo_c_driver/lib/pkgconfig pkg-config --cflags --libs libmongoc-1.0)
```

Query test data:
```bash
> use test
switched to db test
> show collections
system.indexes
test
> db.test.find()
{ "_id" : ObjectId("55a57b77d6db1e6ab778b4f1"), "hello" : "world" }
{ "_id" : ObjectId("55a57cf5d6db1e6ae37dc6b1"), "hello" : "world" }
{ "_id" : ObjectId("55a57d95d6db1e6afa70ca41"), "hello" : "world" }
```
