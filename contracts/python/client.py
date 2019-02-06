import requests
import json
from web3 import Web3, HTTPProvider

from contract_utils import Address

url = "http://localhost:4000/jsonrpc"
headers = {'content-type': 'application/json'}

w3 = Web3(HTTPProvider("http://localhost:8101"))
w3.eth.defaultAccount = w3.eth.accounts[0]
user_addr = Address(w3.eth.defaultAccount)
exch_addr = Address("0x7b0657faB3a85Bb811Cd04d463C6F242E7c2071b")
token_addr = Address("0x4dD1DCEB0bb5D11B2a25d8274Bf03AAd9821F916")
ETH_addr = Address('0x0000000000000000000000000000000000000000')



def request_admin():
    payload = {
        "method": "admin",
        "params": {},
        "jsonrpc": "2.0",
        "id": 0,
    }
    response = requests.post(
        url, data=json.dumps(payload), headers=headers).json()
    print("request_admin: ", response["result"])
    assert response["jsonrpc"]
    assert response["id"] == 0

def request_fee():
    payload = {
        "method": "fee",
        "params": {},
        "jsonrpc": "2.0",
        "id": 0,
    }
    response = requests.post(
        url, data=json.dumps(payload), headers=headers).json()
    print("request_fee: ", response["result"])
    assert response["jsonrpc"]
    assert response["id"] == 0

def request_expire_time():
    payload = {
        "method": "expire_time",
        "params": {},
        "jsonrpc": "2.0",
        "id": 0,
    }
    response = requests.post(
        url, data=json.dumps(payload), headers=headers).json()
    print("request_expire_time: ",response["result"])
    assert response["jsonrpc"]
    assert response["id"] == 0


def expiration_of_token(token:str, user:str):
    payload = {
        "method": "expiration_of_token",
        "params": {'token':token, 'user': user},
        "jsonrpc": "2.0",
        "id": 0,
    }
    response = requests.post(
        url, data=json.dumps(payload), headers=headers).json()
    print(f"expiration_of_token({token}, {user}) :",response["result"])
    assert response["jsonrpc"]
    assert response["id"] == 0



request_admin()
request_fee()
request_expire_time()
expiration_of_token(token_addr.address, user_addr.address)



