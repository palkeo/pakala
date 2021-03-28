contract RecursiveMapping {
    struct Participant {
        uint256 total_paid;
        mapping(address => uint256) balances;
    }

    mapping(address => Participant) participants;

    function deposit(address deposit_to) public payable {
        Participant storage p = participants[msg.sender];
        p.total_paid += msg.value;
        p.balances[deposit_to] += msg.value;
    }

    function transfer(
        uint256 amount,
        address take_from,
        address deposit_to
    ) public {
        Participant storage p = participants[msg.sender];
        p.balances[take_from] -= amount;
        p.balances[deposit_to] += amount;
    }

    function withdraw(address withdraw_from) public returns (int256) {
        Participant storage p = participants[withdraw_from];
        msg.sender.transfer(p.balances[msg.sender]);
        p.balances[msg.sender] = 0;
        return 42;
    }
}
