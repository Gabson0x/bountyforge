# FV-SOL-9 Unbounded Loops

### TLDR

Overly verbose iterations can result in failed transactions, denial of service, and reduced contract usability

## Code


```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UnboundedLoopExample {
    address public owner;
    address[] public recipients;
    uint256 public rewardAmount = 1 ether;

    constructor() {
        owner = msg.sender;
    }

    // Adds a recipient to the list (for testing)
    function addRecipient(address _recipient) external {
        recipients.push(_recipient);
    }

    // Distributes rewards to all recipients in the array
    function distributeRewards() external {
        require(msg.sender == owner, "Only owner can distribute rewards");

        // Unbounded loop over dynamic array "recipients"
        for (uint256 i = 0; i < recipients.length; i++) {
            // For demonstration, we assume "transfer" sends the reward.
            // In practice, we might call an ERC20 transfer or similar function.
            (bool success, ) = recipients[i].call{value: rewardAmount}("");
            require(success, "Transfer failed");
        }
    }

    // Receive Ether to fund the contract
    receive() external payable {}
}

```

## Classifications

Run `cat $SKILL_DIR/reference/solidity/fv-sol-9-unbounded-loops/<filename>` to read any case file listed below.

#### fv-sol-9-c1-dynamic-array.md

#### fv-sol-9-c2-unrestricted-mapping.md

#### fv-sol-9-c3-recursive-calls.md

#### fv-sol-9-c4-reentrancy-loops.md

#### fv-sol-9-c5-nested-loops.md

#### fv-sol-9-c6-blacklistable-token-payment.md

Covers: push-model transfer with USDC/USDT in critical payment path; single blacklisted address blocks entire operation.

#### fv-sol-9-c7-gas-griefing.md

Covers: block stuffing of time-sensitive windows; 63/64 rule insufficient gas forwarding in relayer patterns.

#### fv-sol-9-c8-dust-griefing.md

Covers: dust deposit resetting timelocks/cooldowns; zero-balance gate bricked by dust transfer.

## Mitigation Patterns

### Batch Processing (FV-SOL-9-M1)

Break down large loops into smaller batches, allowing users to process data over multiple transactions rather than a single on

### Gas Hard Limit (FV-SOL-9-M2)

Set a gas threshold or limit for loop processing and exit the loop once it approaches that threshold

### Avoid Dynamic Data in Loops (FV-SOL-9-M3)

Limit loop iterations to fixed-sized arrays or arrays with capped sizes. Avoid using user-input data or dynamic arrays in loop conditions

### Events Instead of Iteration (FV-SOL-9-M4)

In cases where a function needs to notify many users or accounts, consider emitting events instead of looping through recipients, allowing users to handle their own state separately

## Actual Occurrences

* [https://solodit.cyfrin.io/issues/h-04-unbounded-loop-in-\_removenft-could-lead-to-a-griefingdos-attack-code4rena-visor-visor-contest-git](https://solodit.cyfrin.io/issues/h-04-unbounded-loop-in-_removenft-could-lead-to-a-griefingdos-attack-code4rena-visor-visor-contest-git)