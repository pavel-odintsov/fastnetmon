### We have API built on top of gRPC framework

You could ban IP:
```bash
/opt/fastnetmon/fastnetmon_api_client ban 192.168.1.1
```

You could unban IP:
```bash
/opt/fastnetmon/fastnetmon_api_client unban 192.168.1.1
```

You could check banlist:
```bash
/opt/fastnetmon/fastnetmon_api_client get_banlist
```

Sample output:
```bash
192.168.1.1/32
```

