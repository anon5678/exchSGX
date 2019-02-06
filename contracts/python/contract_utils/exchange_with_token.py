import hashlib
import json
import time
import random
import sys
from pprint import pformat
from typing import Optional, List

import logging
import requests
from web3 import Web3

from contract_utils import Contract, Address, Receipt
from contract_utils.numeric import Wad
from contract_utils.token import ERC20Token
from contract_utils.util import bytes_to_hexstring, hexstring_to_bytes

class ExchangeWithToken(Contract):
    """A client for the ExchangeWithToken contract.

    Attributes:
        web3: An instance of `Web` from `web3.py`.
        address: Ethereum address of the contract.
    """

    abi = Contract._load_abi(__name__, 'abi/ExchangeWithToken.abi')

    ETH_TOKEN = Address('0x0000000000000000000000000000000000000000')

    def __init__(self, web3: Web3, address: Address):
        assert(isinstance(address, Address))

        self.web3 = web3
        self.address = address
        self._assert_contract_exists(web3, address)
        self._contract = web3.eth.contract(abi=self. abi,address=address.address)
        self.logger = logging.getLogger("ExchangeWithToken")


    def admin(self) -> Address:
        """Returns the address of the admin account.

        Returns:
            The address of the admin account.
        """
        return Address(self._contract.call().admin())

    def fee(self) -> Wad:
        return Wad(self._contract.call().fee())

    def expire_time(self) -> int:
        return self._contract.call().ExpireTime()

    def safe_time(self) -> int:
        return self._contract.call().SafeTime()

    def expiration_of_token(self, token: Address, user: Address) -> int:
        return self._contract.call().expirationOf(token.address, user.address)

    def expiration_of_ether(self, user: Address) -> int:
        return self._contract.call().expirationOf('0x0000000000000000000000000000000000000000', user.address)

    def exist_tokens(self):
        return self._contract.call().existTokens()


    def balance_of(self, user: Address) -> Wad:
        """Returns the amount of raw ETH deposited by the specified user.

        Args:
            user: Address of the user to check the balance of.

        Returns:
            The raw ETH balance kept in the exchange contract by the specified user.
        """
        assert (isinstance(user, Address))
        return Wad(self._contract.call().balanceOf('0x0000000000000000000000000000000000000000', user.address))

    def balance_of_token(self, token: Address, user: Address) -> Wad:
        """Returns the amount of ERC20 token `token` deposited by the specified user.

        Args:
            token: Address of the ERC20 token return the balance of.
            user: Address of the user to check the balance of.

        Returns:
            The ERC20 token `token` balance kept in the exchange contract by the specified user.
        """
        assert (isinstance(token, Address))
        assert (isinstance(user, Address))
        return Wad(self._contract.call().balanceOf(token.address, user.address))



    def deposit_ether(self, amount: Wad) -> Optional[Receipt]:
        """Deposits `amount` of raw ETH to ExchangeWithToken.

        Args:
            amount: Amount of raw ETH to be deposited on ExchangeWithToken.

        Returns:
            A `Receipt` if the Ethereum transaction was successful and the amount has been deposited.
            `None` if the Ethereum transaction failed.
        """
        assert(isinstance(amount, Wad))
        return self._transact(self.web3, f"ExchangeWithToken('{self.address}').depositEther() with value='{amount}'",
                              lambda: self._contract.transact({'value': amount.value}).depositEther())




    def withdraw_ether(self, amount: Wad) -> Optional[Receipt]:
        """Withdraws `amount` of raw ETH from ExchangeWithToken.

        The withdrawn ETH will get transferred to the calling account.

        Args:
            amount: Amount of raw ETH to be withdrawn from ExchangeWithToken.

        Returns:
            A `Receipt` if the Ethereum transaction was successful and the amount has been withdrawn.
            `None` if the Ethereum transaction failed.
        """
        assert(isinstance(amount, Wad))
        return self._transact(self.web3, f"ExchangeWithToken('{self.address}').withdrawEther('{amount}')",
                              lambda: self._contract.transact().withdrawEther(amount.value))

    def withdraw_all_ether(self) -> Optional[Receipt]:
        return self._transact(self.web3, f"ExchangeWithToken('{self.address}').withdrawAllEther()",
                              lambda: self._contract.transact().withdrawAllEther())



    def deposit_token(self, token: Address, amount: Wad) -> Optional[Receipt]:
        assert(isinstance(amount, Wad))
        return self._transact(self.web3, f"ExchangeWithToken('{self.address}').depositToken('{amount}')'",
                              lambda: self._contract.transact().depositToken(token.address, amount.value))


    def withdraw_token(self, token: Address, amount: Wad) -> Optional[Receipt]:
        """Withdraws `amount` of ERC20 token `token` from ExchangeWithToken.

        Tokens will get transferred to the calling account.

        Args:
            token: Address of the ERC20 token to be withdrawn.
            amount: Amount of token `token` to be withdrawn from ExchangeWithToken.

        Returns:
            A `Receipt` if the Ethereum transaction was successful and the tokens have been withdrawn.
            `None` if the Ethereum transaction failed.
        """
        assert(isinstance(token, Address))
        assert(isinstance(amount, Wad))
        return self._transact(self.web3, f"ExchangeWithToken('{self.address}').withdrawToken('{token}', '{amount}')",
                              lambda: self._contract.transact().withdrawToken(token.address, amount.value))

    def withdraw_all_token(self, token: Address) -> Optional[Receipt]:
        assert (isinstance(token, Address))
        return self._transact(self.web3, f"ExchangeWithToken('{self.address}').WithdrawAllToken('{token}')",
                              lambda: self._contract.transact().WithdrawAllToken(token.address))


    def trade(self, tokenA: [Address], tokenB: [Address], userA: [Address], userB:[Address], amountA:[Address], amountB:[Address]) -> Optional[Receipt]:
        _tokenA = [token.address for token in tokenA]
        _tokenB = [token.address for token in tokenB]
        _userA = [user.address for user in userA]
        _userB = [user.address for user in userB]
        _amountA = [amount.value for amount in amountA]
        _amountB = [amount.value for amount in amountB]
        return self._transact(self.web3, f"ExchangeWithToken('{self.address}')"
                                         f".trade('{tokenA}', '{tokenB}', '{userA}', '{userB}', '{amountA}', '{amountB}')",
                              lambda: self._contract.transact().trade(_tokenA, _tokenB, _userA, _userB, _amountA, _amountB))

    def trade_partial(self, token: [Address], userA: [Address], userB: [Address], amount: [Address]) -> Optional[Receipt]:
        _token = [token.address for token in token]
        _userA = [user.address for user in userA]
        _userB = [user.address for user in userB]
        _amount = [amount.value for amount in amount]
        return self._transact(self.web3, f"ExchangeWithToken('{self.address}')"
                                         f".tradePartial('{token}', '{userA}', '{userB}', '{amount}')",
                              lambda: self._contract.transact().tradePartial(_token, _userA, _userB, _amount))

    def renew(self, token:[Address], user:[Address]) -> Optional[Receipt]:
        _token = [token.address for token in token]
        _user = [user.address for user in user]
        return self._transact(self.web3, f"ExchangeWithToken('{self.address}').renew('{token}', '{user}')",
                              lambda: self._contract.transact().renew(_token, _user))

    def renew_all(self, user:[Address]) -> Optional[Receipt]:
        _user = [user.address for user in user]
        return self._transact(self.web3, f"ExchangeWithToken('{self.address}').renewAll('{user}')",
                              lambda: self._contract.transact().renewAll(_user))