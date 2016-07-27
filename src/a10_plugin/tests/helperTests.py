import unittest,sys
sys.path.append('../')
from a10 import axapi_auth, axapi_action

a10_tps = "192.168.199.152"
username = "admin"
password = "a10"
hostname = "TH4435"

class Test_Auth(unittest.TestCase):

    def testAssertTrue(self):
        print("Testing axapi_auth")
        try:
            mitigator_base_url, signature = axapi_auth(a10_tps, username, password)
            print("base url: ", mitigator_base_url, "Signature: ", signature)
            axapi_action(mitigator_base_url+"/axapi/v3/logoff")
        
        except Exception as e:
            self.fail("Not authenticated")


class Test_API_Actions(unittest.TestCase):

    def testAssertTrue(self):
        try:
            print("Testing GET")
            mitigator_base_url, signature = axapi_auth(a10_tps, username, password)
            r = axapi_action(mitigator_base_url+"/axapi/v3/version/oper", method='GET', signature=signature)
            print(str(r))
            print("Testing POST")
            hostname_payload = {"hostname": {"value": hostname}}
            r = axapi_action(mitigator_base_url+"/axapi/v3/hostname", payload=hostname_payload, signature=signature)
            print(str(r))
            axapi_action(mitigator_base_url+"/axapi/v3/logoff")

        except Exception as e:
            self.fail("Failed")

if __name__ == "__main__":
    unittest.main()


