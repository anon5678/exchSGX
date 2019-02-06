import json
from time import sleep

from web3 import Web3,HTTPProvider
from web3.contract import Contract

from contract_utils import Address
from contract_utils.exchange_with_token import ExchangeWithToken
from contract_utils.token import ReserveToken

w3 = Web3(HTTPProvider("http://localhost:8101"))


w3.eth.defaultAccount = w3.eth.accounts[0]

with open('./contract_utils/abi/ReserveToken.abi') as f:
    abi = json.load(f)

with open('./contract_utils/abi/ReserveToken.bin') as f:
    bin = f.read()


reserve_token_deploy = w3.eth.contract(abi=abi, bytecode=bin)

tx_hash = reserve_token_deploy.constructor().transact()

print("Transaction Hash: ", tx_hash.hex())


tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

print("Transaction Receipt: ", tx_receipt)

addr = Address(tx_receipt.contractAddress)

print("Token Contract Address:", addr)

reserve_token = ReserveToken(web3=w3, address=addr)

print('Done!')









