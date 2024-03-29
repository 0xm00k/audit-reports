### [H-1] Anyone can change the password of the owner.

**Description:**
The `PasswordStore::setPassword` function does not have a check to ensure that only the owner can change the password. This means that anyone can change the password of the owner.

**Impact:**
An attacker can change the password of the owner and take over the protocol.

**Proof of Concept:**

```solidity
function test_anyone_can_set_password(uint256 addr) public {
    vm.assume(addr != 0 && addr < 10);
    address caller = address(1);

    vm.startPrank(caller);

    string memory expectedPassword = "myNewPassword";
    passwordStore.setPassword(expectedPassword);
    vm.stopPrank();
}
```

**Recommended Mitigation:**
Add a check to ensure that only the owner can change the password.

```diff
+ require(msg.sender == s_owner, "PasswordStore: Only the owner can change the password");
```

### [H-2] Variables stored in private can be accessed by attackers.

**Description:** 
There are multiple instances where variables stored in private can be accessed by attackers.

**Impact:** 
Since the essence of the protocol is to store passwords, if an attacker can access the password, it means the protocol is compromised.

**Proof of Concept:**
We can use `cast` and `anvil` from Foundry to deploy and assess the storage of the contract.
if `0x5FbDB2315678afecb367f032d93F642f64180aa3` is the address of the contract, we can run the following command to access the storage of the contract and the 1 is the index of the storage.(`s_password`)


```solidity
 cast storage 0x5FbDB2315678afecb367f032d93F642f64180aa3 1
```
returns `0x6d7950617373776f726400000000000000000000000000000000000000000014` in bytes which then can be converted to a string using the `cast parse-bytes32-string` command.

```solidity
cast parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014
```
Which returns `myPassword` which is the password stored in the contract.

**Recommended Mitigation:**
Encrypt the password before storing it in the contract.

```diff
- private string s_password = "myPassword";
+ private string s_password = keccak256(abi.encodePacked("myPassword"));
```

### [NC-1] The `Password::getPassword()` natspec parameter is never used.

**Description:**
The `Password::getPassword()` function has a natspec parameter that is never used.

```diff
>@ @param newPassword The new password to set.
```

**Recommended Mitigation:**
Remove the natspec parameter.


### [NC-2] The `emit SetNetPassword();` does not have parameters.

**Description:**
The `emit SetNetPassword();` does not have parameters.

**Recommended Mitigation:**
Add parameters to the event.

```diff
- emit SetNetPassword();
+ emit SetNetPassword(newPassword);
```
