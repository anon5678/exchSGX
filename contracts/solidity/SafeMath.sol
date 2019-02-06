pragma solidity ^0.4.11;

contract SafeMath {
    function safeAdd(uint a, uint b) internal constant returns (uint) {
        uint c = a + b;
        assert(c >= a && c >= b);
        return c;
    }
    
    function safeSub(uint a, uint b) internal constant returns (uint) {
        assert(a >= b);
        return a - b;
    }
    
    function safeMul(uint a, uint b) internal constant returns (uint) {
        uint c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }
}