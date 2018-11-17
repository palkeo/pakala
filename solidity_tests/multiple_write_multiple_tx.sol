pragma solidity ^0.4.23;

contract MultipleWriteMultipleTx {
    uint256 public count = 0;

    function increment() public {
        count++;
    }

    function run(uint256 input) {
        if (count < 2) {
            return;
        }

        selfdestruct(msg.sender);
    }
}
