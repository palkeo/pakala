contract Mapping {
    struct Participant {
        uint256 total_paid;
        uint256 payout;
    }

    mapping(address => Participant) participants;

    function deposit(address beneficiary) public payable {
        Participant storage b = participants[beneficiary];
        b.total_paid += msg.value;
        b.payout += msg.value / 2;
    }

    function remove(uint256 amount, address beneficiary) public {
        Participant storage b = participants[beneficiary];
        require(b.payout > 0);
        require(b.total_paid > 0);
        b.payout -= amount;
    }

    function withdraw() public {
        Participant storage p = participants[msg.sender];
        require(p.payout > 1 ether);
        msg.sender.transfer(p.payout);
        p.payout = 0;
    }
}
