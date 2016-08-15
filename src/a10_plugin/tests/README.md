##Sample Test Output

```
echou@a10-ubuntu3:~/fastnetmon/src/a10_plugin/tests$ python helperTests.py
Testing GET
{
  "version": {
    "oper" : {
      "hw-platform":"TH4435 TPS",
      "copyright":"Copyright 2007-2014 by A10 Networks, Inc.",
      "sw-version":"3.2.1 build 175 (May-17-2016,16:57)",
      "plat-features":"",
      "boot-from":"HD_PRIMARY",
      "serial-number":"<skip?",
      "firmware-version":"5.6",
      "hd-pri":"3.2.1.175",
      "hd-sec":"3.2.1-SP2.4",
      "cf-pri":"3.0.0.419",
      "cf-sec":"",
      "last-config-saved-time":"Jul-26-2016, 10:56",
      "virtualization-type":"NA",
      "hw-code":"<skip>",
      "current-time":"Jul-27-2016, 09:46",
      "up-time":"70 days, 22 hours, 44 minutes"
    },
    "a10-url":"/axapi/v3/version/oper"
  }
}

Testing POST
{
  "hostname": {
    "value":"TH4435",
    "uuid":"<skip>",
    "a10-url":"/axapi/v3/hostname"
  }
}

.Testing axapi_auth
('base url: ', 'https://192.168.199.152', 'Signature: ', u'0855fef4da06d7beb89b27e7d2d042')
.
----------------------------------------------------------------------
Ran 2 tests in 0.092s

OK
echou@a10-ubuntu3:~/fastnetmon/src/a10_plugin/tests$
```
