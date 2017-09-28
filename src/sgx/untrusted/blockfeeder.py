#!env python

import requests
import json

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

# rpc_user and rpc_password are set in the bitcoin.conf file
rpc_user = 'exch'
rpc_password = 'goodpass'
rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%(rpc_user, rpc_password))


def append(block_height):
    try:
        block_hash = rpc_connection.getblockhash(block_height)
        block_header = rpc_connection.getblockheader(block_hash, False)

        url = "http://localhost:1234"
        headers = {'content-type': 'application/json'}

        payload = {
                'method': 'appendBlock2FIFO',
                'params': [block_header],
                'jsonrpc': '2.0',
                'id' : 0,
                }

        resp = requests.post(url, data=json.dumps(payload), headers=headers).json()

        print resp

    except JSONRPCException as e:
        print 'Exception:', e.message


import sys
append(int(sys.argv[1]))
