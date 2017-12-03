### We have API built on top of gRPC framework

It's very-very developer feature and we do not support it right now. You could use instructions from [GoBGP integration](https://fastnetmon.com/docs/gobgp-integration/) and enable it.

Enable API in configuration file:
```bash
# Enable gRPC api (required for fastnetmon_api_client tool)
enable_api = on
```

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

