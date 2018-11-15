// See:
// https://github.com/Arachnid/uscc/tree/master/submissions-2017/doughoyte
// for inspiration.

contract ArbitraryStorageWrite {
  uint256[] private people;
  uint256 private magic;

  function addPeople(uint256 key, uint256 value) public {
    people[key] = value;
  }

  function removePeople() public {
    people.length--;
  }

  function () public payable {
    require(magic == 42);
    selfdestruct(msg.sender);
  }

}
