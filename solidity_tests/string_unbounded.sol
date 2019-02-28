library StringUtils {
    function equal(string memory _a, string memory _b) internal returns (bool) {
        bytes memory a = bytes(_a);
        bytes memory b = bytes(_b);
        if (a.length != b.length) return false;
        for (uint i = 0; i < a.length; i ++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}

contract String {
  function passwordSend(string memory s) public payable {
    require(StringUtils.equal(s, "Hi!"));
    msg.sender.send(address(this).balance / 10);
  }
}
