pragma solidity ^0.4.23;

contract MultipleWriteOneTx {
    uint256 private initialized = 0;
    uint256 public count = 0;

    function increment() public {
        require(initialized == 0);
        count++;
        initialized = 1;
        count++;
    }

    function run(uint256 input) {
        require(count == 2);
        selfdestruct(msg.sender);
    }
}
