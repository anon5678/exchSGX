#!env python

import requests
import json
import sys
def request_account_proof(block_height, address, user, token, pos):
    url = "http://94.130.38.179:1234"
    headers = {'content-type': 'application/json'}
    payload = {
        'method': 'exch_getAccountProof',
        'params': [hex(block_height),address,user,token,pos],
        'jsonrpc': '2.0',
        'id' : 0,
    }
    print 'requesting: {}'.format(payload)
    resp = requests.post(url, data=json.dumps(payload), headers=headers).json()
    print resp['result']
    return resp['result']


def ethBalanceProofVerify(block_height, address, user, token, pos):
    try:
        proof = request_account_proof(block_height, address, user, token, pos)
        url = "http://localhost:1234"
        headers = {'content-type': 'application/json'}

        payload = {
            'method': 'ethBalanceProofVerify',
            'params': [proof],
            'jsonrpc': '2.0',
            'id' : 0,
        }

        resp = requests.post(url, data=json.dumps(payload), headers=headers).json()

        print resp

    except Exception as e:
        print 'Exception:', e.message

# python eth_balance_proof_feed.py blocknumber contract_addr user_addr token_addr offset
# python eth_balance_proof_feed.py 4646516 0x8d12A197cB00D4747a1fe03395095ce2A5CC6819 0x2c6512deAAAcf0C27470b91C1781859C0C46a20F 0x0000000000000000000000000000000000000000 0x0000000000000000000000000000000000000006

ethBalanceProofVerify(int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])