contract Mapping {
    struct Participant {
        uint total_paid;
        uint payout;
    }

    mapping(address => Participant) participants;


    function deposit(address beneficiary) public payable {
        var b = participants[beneficiary];
        b.total_paid += msg.value;
        b.payout += msg.value / 2;
    }

    function remove(uint amount, address beneficiary) public {
        var b = participants[beneficiary];
        require(b.payout > 0);
        require(b.total_paid > 0);
        b.payout -= amount;
    }

    function withdraw() public {
        var p = participants[msg.sender];
        require(p.payout > 1 ether);
        msg.sender.transfer(p.payout);
        p.payout = 0;
    }

}
