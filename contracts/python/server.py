from werkzeug.wrappers import Request, Response
from werkzeug.serving import run_simple
from jsonrpc import JSONRPCResponseManager, dispatcher
import logging
import time

from web3 import Web3,HTTPProvider
from contract_utils import Address, Wad
from contract_utils.exchange_with_token import ExchangeWithToken
from contract_utils.token import ReserveToken

logging.basicConfig(level=logging.INFO, format='%(asctime)-15s %(levelname)-8s %(name)-6s %(message)s')
logging.Formatter.converter = time.gmtime



w3 = Web3(HTTPProvider("http://localhost:8101"))
w3.eth.defaultAccount = w3.eth.accounts[0]
user_addr = Address(w3.eth.defaultAccount)
exch_addr = Address("0x7b0657faB3a85Bb811Cd04d463C6F242E7c2071b")
token_addr = Address("0x4dD1DCEB0bb5D11B2a25d8274Bf03AAd9821F916")
ETH_addr = Address('0x0000000000000000000000000000000000000000')

print("Exch Contract Address:", exch_addr)
print("Token Contract Address: ", token_addr)
token = ReserveToken(web3=w3, address=token_addr)
exch_contract = ExchangeWithToken(web3=w3, address=exch_addr)



@dispatcher.add_method
def admin() -> str:
    return exch_contract.admin().address

@dispatcher.add_method
def fee() -> int:
    return exch_contract.fee().value

@dispatcher.add_method
def expire_time() -> int:
    return exch_contract.expire_time()

@dispatcher.add_method
def safe_time() -> int:
    return exch_contract.safe_time()

@dispatcher.add_method
def expiration_of_token(**kwargs) -> int:
    token = Address(kwargs['token'])
    user = Address(kwargs['user'])
    return exch_contract.expiration_of_token(token, user)

@dispatcher.add_method
def expiration_of_ether(**kwargs) -> int:
    user = Address(kwargs['user'])
    return exch_contract.expiration_of_ether(user)


@dispatcher.add_method
def balance_of(**kwargs) -> int:
    user = Address(kwargs['user'])
    return exch_contract.balance_of(user).value

@dispatcher.add_method
def balance_of_token(**kwargs) -> int:
    user = Address(kwargs['user'])
    token = Address(kwargs['token'])
    return exch_contract.balance_of_token(token, user).value

@dispatcher.add_method
def deposit_ether(**kwargs) -> str:
    amount = Wad(kwargs['amount'])
    return exch_contract.deposit_ether(amount).__repr__()

@dispatcher.add_method
def withdraw_ether(**kwargs) -> str:
    amount = Wad(kwargs['amount'])
    return exch_contract.withdraw_ether(amount).__repr__()

@dispatcher.add_method
def withdraw_all_ether() -> str:
    return exch_contract.withdraw_all_ether().__repr__()

@dispatcher.add_method
def deposit_token(**kwargs) -> str:
    token = Address(kwargs['token'])
    amount = Wad(kwargs['amount'])
    return exch_contract.deposit_token(token,amount).__repr__()

@dispatcher.add_method
def withdraw_token(**kwargs) -> str:
    token = Address(kwargs['token'])
    amount = Wad(kwargs['amount'])
    return exch_contract.withdraw_token(token,amount).__repr__()

@dispatcher.add_method
def withdraw_all_token(**kwargs) -> str:
    token = Address(kwargs['token'])
    return exch_contract.withdraw_all_token(token).__repr__()

@dispatcher.add_method
def trade(**kwargs) -> str:
    tokenA = [Address(token) for token in kwargs['tokenA']]
    tokenB = [Address(token) for token in kwargs['tokenB']]
    userA = [Address(user) for user in kwargs['userA']]
    userB = [Address(user) for user in kwargs['userB']]
    amountA = [Wad(amount) for amount in kwargs['amountA']]
    amountB = [Wad(amount) for amount in kwargs['amountB']]
    return exch_contract.trade(tokenA,tokenB,userA,userB,amountA,amountB).__repr__()


@dispatcher.add_method
def trade_partial(**kwargs) -> str:
    token = [Address(token) for token in kwargs['token']]
    userA = [Address(user) for user in kwargs['userA']]
    userB = [Address(user) for user in kwargs['userB']]
    amount = [Wad(amount) for amount in kwargs['amountB']]
    return exch_contract.trade_partial(token,userA,userB,amount).__repr__()

@dispatcher.add_method
def renew(**kwargs) -> str:
    token = [Address(token) for token in kwargs['token']]
    user = [Address(user) for user in kwargs['user']]
    return exch_contract.renew(token,user).__repr__()

@dispatcher.add_method
def renew_all(**kwargs) -> str:
    user = [Address(user) for user in kwargs['user']]
    return exch_contract.renew_all(user).__repr__()


@Request.application
def application(request):
    response = JSONRPCResponseManager.handle(
        request.data, dispatcher)
    return Response(response.json, mimetype='application/json')


if __name__ == '__main__':
    run_simple('localhost', 4000, application)
