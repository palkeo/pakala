contract ArbitraryStorageWrite {
  uint256[] private people;
  mapping (address => bool) owners;

  modifier onlyOwners() {
    require(owners[msg.sender]);
    _;
  }

  function addPeople(uint256 key, uint256 value) public {
    people[key] = value;
  }

  function removePeople() public {
    people.length--;
  }

  function withdraw() public onlyOwners {
    selfdestruct(msg.sender);
  }

}
