# FV-SOL-1 Reentrancy

## TLDR

When a contract calls an external contract or function, it temporarily hands control over to that external entity. If the external contract has permission to call back into the original contract before it has updated critical state variables (e.g., balances), this creates an opening for repeated re-entries, allowing an attacker to manipulate funds or states before they are finalized

## Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vulnerable {
    mapping(address => uint) public balances;

    // Deposit function
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerable withdraw function
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Send funds before updating balance (vulnerability)
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Failed to send Ether");

        // Update balance after sending (allowing reentrancy)
        balances[msg.sender] -= amount;
    }
}
```

## Classifications

Run `cat $SKILL_DIR/reference/solidity/fv-sol-1-reentrancy/<filename>` to read any case file listed below.

#### fv-sol-1-c1-single-function.md

#### fv-sol-1-c2-cross-function.md

#### fv-sol-1-c3-cross-contract.md

#### fv-sol-1-c4-cross-chain.md

#### fv-sol-1-c5-dynamic.md

#### fv-sol-1-c6-read-only.md

#### fv-sol-1-c7-erc721-erc1155-callback.md

Covers: `safeTransferFrom`/`safeMint` callback before state update, ERC1155 batch partial-state window, ERC1155 `totalSupply` inflation via post-mint increment.

#### fv-sol-1-c8-erc777-hook-reentrancy.md

Covers: `tokensToSend`/`tokensReceived` hooks on ERC20-style calls to ERC777 tokens.

#### fv-sol-1-c9-transient-storage-reentrancy.md

Covers: EIP-1153 `TSTORE` bypassing 2300-gas guard; transient mutex not cleared causing DoS in multicall.

## Mitigation Patterns

### FV-SOL-1-M1 Checks-Effects-Interactions

Perform all internal state changes before making any external calls. This ensures that the contract’s state is updated before control is handed over to external contracts, e.g. update the user’s balance before transferring funds to avoid reentrant calls exploiting unfinalized states.

### FV-SOL-1-M2 Reentrancy Guard

Use a reentrancy guard (e.g. OpenZeppelin's `ReentrancyGuard`), typically implemented as a modifier, to prevent reentrant calls by tracking whether a function is already being executed.

## Actual Occurrences

* [https://solodit.cyfrin.io/issues/h-01-reentrancy-in-buy-function-for-erc777-tokens-allows-buying-funds-with-considerable-discount-code4rena-caviar-caviar-contest-git](https://solodit.cyfrin.io/issues/h-01-reentrancy-in-buy-function-for-erc777-tokens-allows-buying-funds-with-considerable-discount-code4rena-caviar-caviar-contest-git)