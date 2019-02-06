import json
from time import sleep

from web3 import Web3,HTTPProvider
from web3.contract import Contract

from contract_utils import Address, Wad
from contract_utils.exchange_with_token import ExchangeWithToken

w3 = Web3(HTTPProvider("http://localhost:8101"))


w3.eth.defaultAccount = w3.eth.accounts[0]

with open('./contract_utils/abi/ExchangeWithToken.abi') as f:
    abi = json.load(f)

with open('./contract_utils/abi/ExchangeWithToken.bin') as f:
    bin = f.read()


exch_deploy = w3.eth.contract(abi=abi, bytecode=bin)

tx_hash = exch_deploy.constructor(Wad.from_number(0.003).value).transact()

print("Transaction Hash: ", tx_hash.hex())


tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

print("Transaction Receipt: ", tx_receipt)

addr = Address(tx_receipt.contractAddress)

print("Contract Address:", addr)

exch_contract = ExchangeWithToken(web3=w3, address=addr)


print('Done!')









