pragma solidity ^0.4.11;

import "./SafeMath.sol";

contract Exchange is SafeMath {
    uint constant Duration = 100;

    mapping (address => uint) public balance;
    mapping (address => uint) public expiration;

    address owner;
    
    event Deposit(address user, uint amount, uint present_balance, uint timeout);
    
    function Exchange() {
        owner = msg.sender;
        balance[msg.sender] = 0;
        expiration[msg.sender] = 0;
    }
    
    function deposit() payable {
        balance[msg.sender] = safeAdd(balance[msg.sender], msg.value);
        expiration[msg.sender] = block.number + Duration;
        Deposit(msg.sender, msg.value, balance[msg.sender], expiration[msg.sender]);
    }
    
    event Withdraw(address user, uint amount, uint present_balance);
    
    function withdraw(uint amount) {
        require(balance[msg.sender] >= amount);
        require(expiration[msg.sender] < block.number);
        balance[msg.sender] = safeSub(balance[msg.sender], amount);
        require(msg.sender.send(amount));
        Withdraw(msg.sender, amount, balance[msg.sender]);
    }
    
    function withdraw() {
        require(expiration[msg.sender] < block.number);
        uint amount = balance[msg.sender];
        balance[msg.sender] = 0;
        require(msg.sender.send(amount));
        Withdraw(msg.sender, amount, balance[msg.sender]);
    }
    
    event Renew(address user, uint timeout);
    
    function renew() {
        expiration[msg.sender] = block.number + Duration;
        Renew(msg.sender, expiration[msg.sender]);
    }
    
    function balanceOf() constant returns (uint) {
        return balance[msg.sender];
    }
    
    function expirationOf() constant returns (uint) {
        return expiration[msg.sender];
    }
    
    event Trade(address userA, address userB, uint amount, uint balanceA, uint balanceB, uint expireA, uint expireB);
  
    function trade(address userA, address userB, uint amount) {
        assert(msg.sender == owner);
        require(balance[userA] >= amount);
        require(balance[userB] <= balance[userB] + amount);
        require(block.number <= expiration[userA]);
        balance[userA] = safeSub(balance[userA], amount);
        balance[userB] = safeAdd(balance[userB], amount);
        expiration[userA] = block.number + Duration;
        expiration[userB] = block.number + Duration;
        Trade(userA, userB, amount, balance[userA], balance[userB], expiration[userA], expiration[userB]);
    }

    function kill() {
        if (msg.sender == owner) {
            selfdestruct(owner);
        }
    }
    
}