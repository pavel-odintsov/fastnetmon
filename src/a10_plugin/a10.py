
#
# v0.2
# ericc@a10networks.com
#

import json, urllib2, ssl

def axapi_auth(host, username, password):
    base_uri = 'https://'+host
    auth_payload = {"credentials": {"username": username, "password": password}}
    r = axapi_action(base_uri + '/axapi/v3/auth', payload=auth_payload)
    signature = json.loads(r)['authresponse']['signature']
    return base_uri, signature


def axapi_action(uri, payload='', signature='', method='POST'):
    # PEP476  2.7.9+ / 3.4.3+ cert check
    new_context = ssl._create_unverified_context()
    try:
        if method == 'POST':
            req = urllib2.Request(uri)
            req.add_header('content-type', 'application/json')
            if signature:
                req.add_header('Authorization', 'A10 {0}'.format(signature))
            response = urllib2.urlopen(req, json.dumps(payload), context=new_context)
        elif method == 'GET':
            req = urllib2.Request(uri)
            req.add_header('content-type', 'application/json')
            if signature:
                req.add_header('Authorization', 'A10 {0}'.format(signature))
            response = urllib2.urlopen(req, context=new_context)
        elif method == 'DELETE':
            req = urllib2.Request(uri)
            req.add_header('content-type', 'application/json')
            req.get_method = lambda: 'DELETE'
            if signature:
                req.add_header('Authorization', 'A10 {0}'.format(signature))
            response = urllib2.urlopen(req, context=new_context)
        return response.read()
    except Exception as e:
        raise 



