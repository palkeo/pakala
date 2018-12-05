contract Mapping {
    struct Participant {
        uint total_paid;
        uint payout;
    }

    mapping(address => Participant) participants;

    function deposit() public payable {
        require(msg.value > 0.1 ether);

        Participant storage p = participants[msg.sender];
        p.total_paid += msg.value;
        p.payout += msg.value;
    }

    function transfer(uint amount, address beneficiary) public {
        require(beneficiary != msg.sender);

        Participant storage p = participants[msg.sender];

        // The following require will always hold because we are substracting
        // two uint...
        require(p.payout - amount > 0);
        // This would be better:
        //require((int)(p.payout) - (int)(amount) > 0 && (int)(amount) > 0);

        p.payout -= amount;

        Participant storage b = participants[beneficiary];
        b.payout += amount;
    }

    function withdraw() public returns (int) {
        Participant storage p = participants[msg.sender];
        require(p.payout > 0.1 ether && p.total_paid > 0);
        msg.sender.transfer(p.payout);
        p.payout = 0;
        return 42;
    }

}
