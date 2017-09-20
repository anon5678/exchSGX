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

def deposit():
    merkle_proof = 'merkle proof placeholder'
    public_key = 'pubkey to be registered'
    try:
        payload = {
                'method': 'deposit',
                'params': [merkle_proof, public_key],
                'jsonrpc': '2.0',
                'id' : 0,
                }

        resp = requests.post(url, data=json.dumps(payload), headers=headers).json()

        print resp

    except JSONRPCException as e:
        print e.message


deposit()
