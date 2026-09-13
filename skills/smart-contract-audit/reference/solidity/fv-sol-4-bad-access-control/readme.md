# FV-SOL-4 Bad Access Control

## TLDR

Improper access control can let unauthorized users access or modify restricted functionality

## Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BadAccessControl {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {}

    function withdraw() public {
        // No access control here, anyone can call this
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

## Classifications

Run `cat $SKILL_DIR/reference/solidity/fv-sol-4-bad-access-control/<filename>` to read any case file listed below.

#### fv-sol-4-c1-using-tx.origin-for-authorization.md

#### fv-sol-4-c2-unrestricted-role-assignment.md

#### fv-sol-4-c3-lack-of-multi-signature-for-crucial-operations.md

#### fv-sol-4-c4-signature-security-flaws.md

Covers: signature malleability, `ecrecover` returning `address(0)`, signature replay via missing nonce.

#### fv-sol-4-c5-callback-authorization-bypass.md

Covers: flash loan callback spoofing, `onERC721Received` caller spoofing, ERC1155 unauthorized burn, ERC4626 missing allowance check, `setApprovalForAll` over-permission.

#### fv-sol-4-c6-arbitrary-external-call.md

Covers: user-supplied `target` + `calldata` enabling asset theft via crafted `transferFrom`.

#### fv-sol-4-c7-erc1271-signature-delegation.md

Covers: `isValidSignature` delegated to untrusted or user-set module.

#### fv-sol-4-c8-arbitrary-storage-write.md

#### fv-sol-4-c9-constructor-bypass-and-create2-squatting.md

extcodesize returns zero during constructor execution, bypassing EOA checks; CREATE2 salt not bound to msg.sender allows address squatting.

#### fv-sol-4-c10-commit-reveal-merkle-binding.md

Commit-reveal not bound to msg.sender enables front-running; merkle second preimage attack; merkle proof not bound to caller allows replay.

#### fv-sol-4-c11-hash-collision-and-encoding.md

abi.encodePacked collision with multiple dynamic types; calldata malleability bypasses raw msg.data deduplication.

Covers: assembly `sstore` with user-controlled slot, Solidity <0.6 array length assignment.

## Mitigation Patterns

### Ownership Pattern (FV-SOL-4-M1)

The ownership pattern restricts critical functions to the contract owner, usually set during contract deployment. This is commonly achieved with an `onlyOwner` modifier

### Proper RBAC (FV-SOL-4-M2)

Role-Based Access Control allows defining multiple roles, each with specific permissions. For example, roles like `Admin`, `Minter`, or `Pauser` can be created, allowing more granular control

### Multi-Signature Approval (FV-SOL-4-M3)

Multi-sig patterns require multiple accounts to approve a critical action before it can be executed. This reduces the risk of unauthorized actions due to a compromised account

## Actual Occurrences

* [https://solodit.cyfrin.io/issues/h-02-eth-gets-locked-in-the-groupcoinfactory-contract-pashov-audit-group-none-groupcoin-markdown](https://solodit.cyfrin.io/issues/h-02-eth-gets-locked-in-the-groupcoinfactory-contract-pashov-audit-group-none-groupcoin-markdown)
