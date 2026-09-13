# FV-SOL-7 Proxy Insecurities

### TLDR

Upgradeability is essential for maintaining and improving deployed contracts and fixes over time

Due to their nature, they are often misunderstood or implemented insecurely

## Code


```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Delegate contract contains logic but no storage
contract Delegate {
    uint public storedData;  // This variable will be ignored when using delegatecall

    // Function to be called via delegatecall
    function setValue(uint _value) public {
        storedData = _value;  // This will set the caller's storage, not Delegate's
    }
}

// Caller contract with storage that will be updated
contract Caller {
    uint public storedData;  // The storage slot used in Delegate

    // Function to execute delegatecall to Delegate contract
    function setDelegateValue(address _delegateAddress, uint _value) public {
        // Prepare data for delegatecall (function selector + argument)
        (bool success, ) = _delegateAddress.delegatecall(
            abi.encodeWithSignature("setValue(uint256)", _value)
        );
        require(success, "Delegatecall failed");
    }
}
```

## Classifications

Run `cat $SKILL_DIR/reference/solidity/fv-sol-7-proxy-insecurities/<filename>` to read any case file listed below.

#### fv-sol-7-c1-delegatecall-storage-collision.md

#### fv-sol-7-c2-function-selector-collision.md

#### fv-sol-7-c3-centralized-update-control.md

#### fv-sol-7-c4-uninitialized-proxy.md

#### fv-sol-7-c5-proxy-implementation-attacks.md

Immutable context mismatch across proxies; arbitrary delegatecall in implementation; assembly proxy missing returndata propagation; minimal proxy implementation destruction; metamorphic CREATE2 code swap.

#### fv-sol-7-c6-proxy-upgrade-lifecycle.md

Re-initialization with wrong version; UUPS upgrade logic removed in V2; upgrade race condition; missing _authorizeUpgrade access control; non-atomic initialization front-running.

#### fv-sol-7-c7-diamond-proxy-pitfalls.md

Cross-facet storage collision from top-level variables; selector collision on diamondCut; DiamondStorage not at EIP-7201 namespaced position.

## Mitigation Patterns

### Validate Addresses Being Called (FV-SOL-7-M1)

Ensure that the address used with `delegatecall` is fixed or restricted to trusted sources

### Limit State Changes (FV-SOL-7-M2)

Be cautious of contracts that use `delegatecall` to avoid unintended storage changes

### \_\_gap Array (FV-SOL-7-M3)

The `__gap` variable is a common technique used in Solidity's upgradeable contract design to prevent storage layout issues during contract upgrades. It is essentially a reserved area in the contract's storage layout that provides "padding" for future storage variables

## Actual Occurrences

* [https://solodit.cyfrin.io/issues/h-03-attacker-can-gain-control-of-counterfactual-wallet-code4rena-biconomy-biconomy-smart-contract-wallet-contest-git](https://solodit.cyfrin.io/issues/h-03-attacker-can-gain-control-of-counterfactual-wallet-code4rena-biconomy-biconomy-smart-contract-wallet-contest-git)
* [https://solodit.cyfrin.io/issues/h01-corruptible-storage-upgradeability-pattern-openzeppelin-ribbon-finance-audit-markdown](https://solodit.cyfrin.io/issues/h01-corruptible-storage-upgradeability-pattern-openzeppelin-ribbon-finance-audit-markdown)
* [https://solodit.cyfrin.io/issues/diamond-proxy-initialize-functions-can-be-called-multiple-times-halborn-polemos-lending-pdf](https://solodit.cyfrin.io/issues/diamond-proxy-initialize-functions-can-be-called-multiple-times-halborn-polemos-lending-pdf)
