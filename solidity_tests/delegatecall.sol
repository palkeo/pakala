contract Proxy {
  function forward(address callee, bytes memory _data) public {
    bool status;
    bytes memory result;
    (status, result) = callee.delegatecall(_data);
    require(status);
  }

}
