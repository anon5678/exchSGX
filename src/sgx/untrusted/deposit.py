#!env python

import requests
import json

# from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
# rpc_user and rpc_password are set in the bitcoin.conf file
# rpc_user = 'exch'
# rpc_password = 'goodpass'
# rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%(rpc_user, rpc_password))

url = "http://localhost:1234"
headers = {'content-type': 'application/json'}


def deposit(merkle_proof, public_key):
    try:
        payload = {
            'method': 'deposit',
            'params': [merkle_proof, public_key],
            'jsonrpc': '2.0',
            'id': 0,
        }

        resp = requests.post(url, data=json.dumps(payload), headers=headers).json()

        print resp

    except Exception as e:
        print e.message


import sys

with open(sys.argv[1]) as _proof:
    proof = json.load(_proof)

proof["deposit_recv_addr"] = '03d7c6052544bc42eb2bc0d27c884016adb933f15576a1a2d21cd4dd0f2de0c37d'
proof["deposit_refund_addr"] = '021844989a2bd7acd127dd7ed51aa2f4d55b32dbb414de6325ae37e05c1067598d'
proof["deposit_timeout"] = 0x389900

deposit(proof, "key")
