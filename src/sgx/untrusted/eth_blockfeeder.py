#!env python

import requests
import json
import sys

def request_header(block_height):
    url = "http://localhost:8101"
    headers = {'content-type': 'application/json'}
    payload = {
        'method': 'exch_getHeaderByNumber',
        'params': [hex(block_height)],
        'jsonrpc': '2.0',
        'id' : 0,
    }
    resp = requests.post(url, data=json.dumps(payload), headers=headers).json()
    print resp['result']
    return resp['result']


def append(block_height):
    try:
        block_header = request_header(block_height)
        url = "http://localhost:1234"
        headers = {'content-type': 'application/json'}

        payload = {
            'method': 'ethAddNewHeader',
            'params': [block_header],
            'jsonrpc': '2.0',
            'id' : 0,
        }

        resp = requests.post(url, data=json.dumps(payload), headers=headers).json()

        print resp

    except Exception as e:
        print 'Exception:', e.message

append(int(sys.argv[1]))
