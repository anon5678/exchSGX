import json
import logging
import time

from web3 import Web3,HTTPProvider
from web3.contract import Contract

from contract_utils import Address, Wad
from contract_utils.exchange_with_token import ExchangeWithToken
from contract_utils.token import ReserveToken

logging.basicConfig(level=logging.INFO, format='%(asctime)-15s %(levelname)-8s %(name)-6s %(message)s')
logging.Formatter.converter = time.gmtime


w3 = Web3(HTTPProvider("http://localhost:8101"))

w3.eth.defaultAccount = w3.eth.accounts[0]

user_addr = Address(w3.eth.defaultAccount)

exch_addr = Address("0xadF17b570783ED30860263b29a70687572DB8Ad5")

token_addr = Address("0x836d73669C714a180211903C8f2c3fD108D00bDB")

ETH_addr = Address('0x0000000000000000000000000000000000000000')

print("Exch Contract Address:", exch_addr)

print("Token Contract Address: ", token_addr)

token = ReserveToken(web3=w3, address=token_addr)

exch_contract = ExchangeWithToken(web3=w3, address=exch_addr)

print("Admin:", exch_contract.admin())

print("Fee: ",exch_contract.fee())

print("Expire Time: ",exch_contract.expire_time())

print("Safe Time: ",exch_contract.safe_time())

print("Exist Tokens: ", exch_contract.exist_tokens() )


def test_deposit_withdraw_ether():
    w3.eth.defaultAccount = w3.eth.accounts[0]
    print(f"ETH Balance of {w3.eth.defaultAccount} : {exch_contract.balance_of(user_addr)}")
    print("Depositing 1 Ether")
    exch_contract.deposit_ether(amount=Wad.from_number(1))
    print(f"ETH Balance of {w3.eth.defaultAccount} : {exch_contract.balance_of(user_addr)}")


    print(f'Current block {w3.eth.blockNumber}')
    while w3.eth.blockNumber <= exch_contract.expiration_of_ether(user_addr):
        time.sleep(1)
        print(f'submmiting trasaction, blocknumber {w3.eth.blockNumber} <= {exch_contract.expiration_of_ether(user_addr)}')
        tx_hash = w3.eth.sendTransaction(
            {'to': user_addr.address, 'from': user_addr.address, 'value': 0})
        print('tx_hash',tx_hash.hex())
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)


    time.sleep(1)
    print(f"ETH Balance of {w3.eth.defaultAccount} : {exch_contract.balance_of(user_addr)}")
    print("Withdrawing 1 Ether")
    exch_contract.withdraw_ether(amount=Wad.from_number(1))
    print(f"ETH Balance of {w3.eth.defaultAccount} : {exch_contract.balance_of(user_addr)}")

def test_deposit_withdraw_token():
    w3.eth.defaultAccount = w3.eth.accounts[0]
    print(f"TOK Balance of {w3.eth.defaultAccount} : {exch_contract.balance_of_token(token=token_addr, user=user_addr)}")

    print("Creating 1 TOK")
    time.sleep(1)
    token.create(user_addr, Wad.from_number(1))
    

    
    print("Approving 1 TOK")
    time.sleep(1)
    token.approve(exch_addr, Wad.from_number(1))


    print("Depositing 1 TOK")
    time.sleep(1)
    exch_contract.deposit_token(token.address, Wad.from_number(1))

    print(
        f"TOK Balance of {w3.eth.defaultAccount} : {exch_contract.balance_of_token(token=token_addr, user=user_addr)}")

    print(f'Current block {w3.eth.blockNumber}')
    while w3.eth.blockNumber <= exch_contract.expiration_of_token(token.address, user_addr):
        time.sleep(1)
        print(
            f'submmiting trasaction, blocknumber {w3.eth.blockNumber} <= {exch_contract.expiration_of_token(token.address, user_addr)}')
        tx_hash = w3.eth.sendTransaction(
            {'to': user_addr.address, 'from': user_addr.address, 'value': 0})
        print('tx_hash', tx_hash.hex())
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)


    print("Withdrawing 1 TOK")
    time.sleep(1)
    exch_contract.withdraw_token(token.address, Wad.from_number(1))

    print(f"TOK Balance of {w3.eth.defaultAccount} : {exch_contract.balance_of_token(token=token_addr, user=user_addr)}")

def test_trade():

    ETH_addr = Address('0x0000000000000000000000000000000000000000')

    user1 = Address(w3.eth.accounts[0])
    user2 = Address(w3.eth.accounts[1])

    print('user1 deposit 1 ETH: ')
    w3.eth.defaultAccount = user1.address
    time.sleep(1)
    exch_contract.deposit_ether(Wad.from_number(1))

    print(f'user1 ETH balance: {exch_contract.balance_of(user1)}, user2 ETH balance: {exch_contract.balance_of(user2)}')
    time.sleep(1)
    exch_contract.trade(tokenA=[ETH_addr],tokenB=[ETH_addr], userA=[user1], userB=[user2],amountA=[Wad.from_number(1)],amountB=[Wad(0)])

    print(f'user1 ETH balance: {exch_contract.balance_of(user1)}, user2 ETH balance: {exch_contract.balance_of(user2)}')


def test_trade_partial():


    user1 = Address(w3.eth.accounts[0])
    user2 = Address(w3.eth.accounts[1])

    print('user1 deposit 1 ETH: ')
    w3.eth.defaultAccount = user1.address
    time.sleep(1)
    exch_contract.deposit_ether(Wad.from_number(1))

    print(f'user1 ETH balance: {exch_contract.balance_of(user1)}, user2 ETH balance: {exch_contract.balance_of(user2)}')
    time.sleep(1)
    exch_contract.trade_partial(token=[ETH_addr], userA=[user1], userB=[user2],amount=[Wad.from_number(1)])

    print(f'user1 ETH balance: {exch_contract.balance_of(user1)}, user2 ETH balance: {exch_contract.balance_of(user2)}')


def test_withraw_all_ether():
    w3.eth.defaultAccount = w3.eth.accounts[0]
    print(f"ETH Balance of {w3.eth.defaultAccount} : {exch_contract.balance_of(user_addr)}")
    print("Depositing 1 Ether")
    exch_contract.deposit_ether(amount=Wad.from_number(1))
    print(f"ETH Balance of {w3.eth.defaultAccount} : {exch_contract.balance_of(user_addr)}")

    print(f'Current block {w3.eth.blockNumber}')
    while w3.eth.blockNumber <= exch_contract.expiration_of_ether(user_addr):
        time.sleep(1)
        print(
            f'submmiting trasaction, blocknumber {w3.eth.blockNumber} <= {exch_contract.expiration_of_ether(user_addr)}')
        tx_hash = w3.eth.sendTransaction(
            {'to': user_addr.address, 'from': user_addr.address, 'value': 0})
        print('tx_hash', tx_hash.hex())
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

    time.sleep(1)
    print(f"ETH Balance of {w3.eth.defaultAccount} : {exch_contract.balance_of(user_addr)}")
    print("Withdrawing 1 Ether")
    exch_contract.withdraw_all_ether()
    print(f"ETH Balance of {w3.eth.defaultAccount} : {exch_contract.balance_of(user_addr)}")


def test_withraw_all_token():
    w3.eth.defaultAccount = w3.eth.accounts[0]
    print(
        f"TOK Balance of {w3.eth.defaultAccount} : {exch_contract.balance_of_token(token=token_addr, user=user_addr)}")

    print("Creating 1 TOK")
    time.sleep(1)
    token.create(user_addr, Wad.from_number(1))

    print("Approving 1 TOK")
    time.sleep(1)
    token.approve(exch_addr, Wad.from_number(1))

    print("Depositing 1 TOK")
    time.sleep(1)
    exch_contract.deposit_token(token.address, Wad.from_number(1))

    print(
        f"TOK Balance of {w3.eth.defaultAccount} : {exch_contract.balance_of_token(token=token_addr, user=user_addr)}")

    print(f'Current block {w3.eth.blockNumber}')
    while w3.eth.blockNumber <= exch_contract.expiration_of_token(token.address, user_addr):
        time.sleep(1)
        print(
            f'submmiting trasaction, blocknumber {w3.eth.blockNumber} <= {exch_contract.expiration_of_token(token.address, user_addr)}')
        tx_hash = w3.eth.sendTransaction(
            {'to': user_addr.address, 'from': user_addr.address, 'value': 0})
        print('tx_hash', tx_hash.hex())
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

    print("Withdrawing 1 TOK")
    time.sleep(1)
    exch_contract.withdraw_all_token(token_addr)

    print(
        f"TOK Balance of {w3.eth.defaultAccount} : {exch_contract.balance_of_token(token=token_addr, user=user_addr)}")

def test_renew():
    w3.eth.defaultAccount = w3.eth.accounts[0]

    print("Depositing 1 Ether")
    exch_contract.deposit_ether(amount=Wad.from_number(1))

    print("Creating 1 TOK")
    time.sleep(1)
    token.create(user_addr, Wad.from_number(1))

    print("Approving 1 TOK")
    time.sleep(1)
    token.approve(exch_addr, Wad.from_number(1))

    print("Depositing 1 TOK")
    time.sleep(1)
    exch_contract.deposit_token(token.address, Wad.from_number(1))


    print(f'Current block {w3.eth.blockNumber}')
    print(f"ETH expires at {exch_contract.expiration_of_ether(user_addr)}")
    print(f"TOK expires at {exch_contract.expiration_of_token(user=user_addr, token=token_addr)}")


    exch_contract.renew([token_addr],[user_addr])

    print(f'Current block {w3.eth.blockNumber}')
    print(f"ETH expires at {exch_contract.expiration_of_ether(user_addr)}")
    print(f"TOK expires at {exch_contract.expiration_of_token(user=user_addr, token=token_addr)}")


def test_renew_all():
    w3.eth.defaultAccount = w3.eth.accounts[0]
    print("Depositing 1 Ether")
    exch_contract.deposit_ether(amount=Wad.from_number(1))
    print("Creating 1 TOK")
    time.sleep(1)
    token.create(user_addr, Wad.from_number(1))

    print("Approving 1 TOK")
    time.sleep(1)
    token.approve(exch_addr, Wad.from_number(1))

    print("Depositing 1 TOK")
    time.sleep(1)
    exch_contract.deposit_token(token.address, Wad.from_number(1))


    print(f'Current block {w3.eth.blockNumber}')
    print(f"ETH expires at {exch_contract.expiration_of_ether(user_addr)}")
    print(f"TOK expires at {exch_contract.expiration_of_token(user=user_addr, token=token_addr)}")

    exch_contract.renew_all([user_addr])

    print(f'Current block {w3.eth.blockNumber}')
    print(f"ETH expires at {exch_contract.expiration_of_ether(user_addr)}")
    print(f"TOK expires at {exch_contract.expiration_of_token(user=user_addr, token=token_addr)}")

#test_deposit_withdraw_token()

#test_trade()

#test_trade_partial()


#test_withraw_all_ether()

#test_withraw_all_token()


test_renew_all()
print('Done!')









