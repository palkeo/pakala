contract Mapping {
    struct Participant {
        uint total_paid;
        uint payout;
    }

    mapping(address => Participant) participants;

    function deposit() public payable {
        require(msg.value > 0.1 ether);

        var p = participants[msg.sender];
        p.total_paid += msg.value;
        p.payout += msg.value;
    }

    function transfer(uint amount, address beneficiary) public {
        require(beneficiary != msg.sender);

        var p = participants[msg.sender];
        p.payout -= amount;

        var b = participants[beneficiary];
        b.payout += amount;
    }

    function withdraw() public returns (int) {
        var p = participants[msg.sender];
        require(p.payout > 0.1 ether && p.total_paid > 0);
        msg.sender.transfer(p.payout);
        p.payout = 0;
        return 42;
    }

}
