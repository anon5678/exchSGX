pragma solidity ^0.4.11;

import "./SafeMath.sol";
import "./Token.sol";

contract ExchangeWithToken is SafeMath {

    uint constant public ExpireTime = 10;
    uint constant public SafeTime = 5;
    
    uint public tokenNumber = 0;
    mapping (uint => address) public index2Token;
    mapping (address => bool) tokenExist;
    
    mapping (address => mapping (address => uint)) public balance; // (token => (user => balance))
    mapping (address => mapping (address => uint)) public expiration; // (token => (user => timeout_in_block))

    address public admin;
    uint public fee;

    function ExchangeWithToken(uint _fee) {
        admin = msg.sender;
        fee = _fee;
    }
    
    function balanceOf(address token) constant returns (uint) {
        return balance[token][msg.sender];
    }

    function balanceOf(address token, address user) constant returns(uint) {
        return balance[token][user];
    }

    function balanceOf() constant returns (address[], uint[]) {
        uint i;
        address[] memory tokens = new address[](tokenNumber);
        uint[] memory balances = new uint[](tokenNumber);
        for (i = 0; i < tokenNumber; i++) {
            tokens[i] = index2Token[i];
            balances[i] = balance[index2Token[i]][msg.sender];
        }
        return (tokens, balances);
    }

    function expirationOf(address token) constant returns (uint) {
        return expiration[token][msg.sender];
    }

    function expirationOf(address token, address user) constant returns (uint) {
        return expiration[token][user];
    }

    function expirationOf() constant returns (address[], uint[]) {
        uint i;
        address[] memory tokens = new address[](tokenNumber);
        uint[] memory expirations = new uint[](tokenNumber);
        for (i = 0; i < tokenNumber; i++) {
            tokens[i] = index2Token[i];
            expirations[i] = expiration[index2Token[i]][msg.sender];
        }
        return (tokens, expirations);
    }

    function existTokens() constant returns (address[]) {
        uint i;
        address[] memory tokens = new address[](tokenNumber);
        for (i = 0; i < tokenNumber; i++) {
            tokens[i] = index2Token[i];
        }
        return tokens;
    }

    function currentBlock() constant returns (uint) {
        return block.number;
    }
    
    event Deposit(address token, address user, uint amount, uint presentBalance);
    
    function depositEther() payable {
        if (!tokenExist[0]) {
            tokenExist[0] = true;
            index2Token[tokenNumber++] = 0;
        }
        balance[0][msg.sender] = safeAdd(balance[0][msg.sender], msg.value);
        expiration[0][msg.sender] = block.number + ExpireTime;
        Deposit(0, msg.sender, msg.value, balance[0][msg.sender]);
    }
    
    function depositToken(address token, uint amount) {
        require(token != 0);
        if (!tokenExist[token]) {
            tokenExist[token] = true;
            index2Token[tokenNumber++] = token;
        }
        require(Token(token).transferFrom(msg.sender, this, amount));
        balance[token][msg.sender] = safeAdd(balance[token][msg.sender], amount);
        expiration[token][msg.sender] = block.number + ExpireTime;
        Deposit(token, msg.sender, amount, balance[token][msg.sender]);
    }

     function withdrawToken(address token, uint amount) {
        require(token != 0);
        require(balance[token][msg.sender] >= amount);
        require(expiration[token][msg.sender] < block.number);
        balance[token][msg.sender] = safeSub(balance[token][msg.sender], amount);
        require(Token(token).transfer(msg.sender, amount));
        Withdraw(token, msg.sender, amount, balance[token][msg.sender]);
    }
    
    event Withdraw(address token, address user, uint amount, uint presentNalance);
    
    function withdrawEther(uint amount) {
        require(balance[0][msg.sender] >= amount);
        require(expiration[0][msg.sender] < block.number);
        balance[0][msg.sender] = safeSub(balance[0][msg.sender], amount);
        require(msg.sender.send(amount));
        Withdraw(0, msg.sender, amount, balance[0][msg.sender]);
    }

    function withdrawAllEther() {
        require(expiration[0][msg.sender] < block.number);
        uint amount = balance[0][msg.sender];
        balance[0][msg.sender] = 0;
        require(msg.sender.send(amount));
        Withdraw(0, msg.sender, amount, balance[0][msg.sender]);
    }
    


    function WithdrawAllToken(address token) {
        require(token != 0);
        require(expiration[token][msg.sender] < block.number);
        uint amount = balance[token][msg.sender];
        balance[token][msg.sender] = 0;
        require(Token(token).transfer(msg.sender, amount));
        Withdraw(token, msg.sender, amount, balance[token][msg.sender]);
    }
    
    event Renew(address token, address user, uint timeout);
    event RenewFail(address token, address user);
    
    function renew(address[] _token, address[] _user) {
        assert(msg.sender == admin);
        assert(_token.length == _user.length);

        uint i;
        for (i = 0; i < _token.length; i++) {
            address token = _token[i];
            address user = _user[i];

            if (block.number <= expiration[token][user] - SafeTime) {
                expiration[token][user] = block.number + ExpireTime;
                Renew(token, user, expiration[token][user]);
            }
            else {
                RenewFail(token, user);
            }
        }
    }
    
    event RenewAll(address user, uint timeout);
    event RenewAllFail(address user);
    
    function renewAll(address[] _user) {
        assert(msg.sender == admin);

        uint i;
        uint j;
        for (i = 0; i < _user.length; i++) {
            address user = _user[i];
            for (j = 0; j < tokenNumber; j++) {
                if (block.number < expiration[index2Token[j]][user] - SafeTime) {
                    expiration[index2Token[j]][user] = block.number + ExpireTime;
                }
            }
            RenewAll(user, block.number + ExpireTime);
        }
    }

    event Trade(address tokenA, address tokenB, address userA, address userB, uint amountA, uint amountB, uint balanceTokenBuserA, uint balanceTokenAuserB);
    event TradeFail(address tokenA, address tokenB, address userA, address userB, uint amountA, uint amountB);

    function trade(
        address[] _tokenA, address[] _tokenB,
        address[] _userA, address[] _userB,
        uint[] _amountA, uint[] _amountB
    ) {
        assert(msg.sender == admin);

        assert(_tokenA.length == _tokenB.length);
        assert(_tokenB.length == _userA.length);
        assert(_userA.length == _userB.length);
        assert(_userB.length == _amountA.length);
        assert(_amountA.length == _amountB.length);

        uint i;
        for (i = 0; i < _tokenA.length; i++) {
            address tokenA = _tokenA[i];
            address tokenB = _tokenB[i];
            address userA = _userA[i];
            address userB = _userB[i];
            uint amountA = _amountA[i];
            uint amountB = _amountB[i];

            if (expiration[tokenA][userA] - SafeTime >= block.number &&
                expiration[tokenB][userB] - SafeTime >= block.number &&
                balance[tokenA][userA] >= amountA &&
                balance[tokenB][userB] >= amountB &&
                balance[tokenB][userA] <= balance[tokenB][userA] + amountB &&
                balance[tokenA][userB] <= balance[tokenA][userB] + amountA) {

                balance[tokenA][userA] = safeSub(balance[tokenA][userA], amountA);
                balance[tokenB][userB] = safeSub(balance[tokenB][userB], amountB);
                balance[tokenB][userA] = safeAdd(balance[tokenB][userA], amountB);
                balance[tokenA][userB] = safeAdd(balance[tokenA][userB], amountA);

                expiration[tokenA][userA] = block.number + ExpireTime;
                expiration[tokenA][userB] = block.number + ExpireTime;
                expiration[tokenB][userA] = block.number + ExpireTime;
                expiration[tokenB][userB] = block.number + ExpireTime;

                Trade(tokenA, tokenB, userA, userB, amountA, amountB, balance[tokenB][userA], balance[tokenA][userB]);
            }
            else {
                TradeFail(tokenA, tokenB, userA, userB, amountA, amountB);
            }
        }
    }

    event TradePartial(address token, address userA, address userB, uint amount, uint balanceA, uint balanceB);
    event TradePartialFail(address token, address userA, address userB, uint amount);

    function tradePartial(address[] _token, address[] _userA, address[] _userB, uint[] _amount) {
        assert(msg.sender == admin);

        assert(_token.length == _userA.length);
        assert(_userA.length == _userB.length);
        assert(_userB.length == _amount.length);

        uint i;
        for (i = 0; i < _token.length; i++) {
            address token = _token[i];
            address userA = _userA[i];
            address userB = _userB[i];
            uint amount = _amount[i];

            if (expiration[token][userA] - SafeTime >= block.number &&
                balance[token][userA] >= amount &&
                balance[token][userB] <= balance[token][userB] + amount) {

                balance[token][userA] = safeSub(balance[token][userA], amount);
                balance[token][userB] = safeAdd(balance[token][userB], amount);

                expiration[token][userA] = block.number + ExpireTime;
                expiration[token][userB] = block.number + ExpireTime;

                TradePartial(token, userA, userB, amount, balance[token][userA], balance[token][userB]);
            }
            else {
                TradePartialFail(token, userA, userB, amount);
            }
        }
    }

    function kill() {
        if (msg.sender == admin) {
            selfdestruct(admin);
        }
    }
    
}