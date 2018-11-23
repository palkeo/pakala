contract RecursiveMapping {
    struct Participant {
        uint total_paid;
        mapping(address => uint) balances;
    }

    mapping(address => Participant) participants;

    function deposit(address deposit_to) public payable {
        var p = participants[msg.sender];
        p.total_paid += msg.value;
        p.balances[deposit_to] += msg.value;
    }

    function transfer(uint amount, address take_from, address deposit_to) public {
        var p = participants[msg.sender];
        p.balances[take_from] -= amount;
        p.balances[deposit_to] += amount;
    }

    function withdraw(address withdraw_from) public returns (int) {
        var p = participants[withdraw_from];
        msg.sender.transfer(p.balances[msg.sender]);
        p.balances[msg.sender] = 0;
        return 42;
    }

}
