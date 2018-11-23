contract String {
  function passwordSend(bytes32 s) public payable {
    require(s == "12345678901234567890magic");
    msg.sender.send(this.balance / 5 - (0.1 ether));
  }
}
