# FV-SOL-3 Arithmetic Errors

## TLDR

Arithmetic-related security vulnerabilities primarily stem from issues with numeric operations, particularly when they handle unexpected values or edge cases

## Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract OverflowExample {
    uint256 public count = 2**256 - 1;

    function increment() public {
        count += 1; // This will overflow and wrap to 0
    }
}
```

## Classifications

Run `cat $SKILL_DIR/reference/solidity/fv-sol-3-arithmetic-errors/<filename>` to read any case file listed below.

#### fv-sol-3-c1-overflow-and-underflow.md

#### fv-sol-3-c2-sign-extension.md

#### fv-sol-3-c3-truncation-in-type-casting.md

#### fv-sol-3-c4-misuse-of-environment-variables.md

#### fv-sol-3-c5-assembly-arithmetic.md

Assembly `div`/`mul`/`sub` silent overflow and division-by-zero; narrow-type arithmetic overflow before upcast in `unchecked` blocks.

#### fv-sol-3-c6-assembly-memory-calldata-pitfalls.md

mstore8 dirty bytes, scratch space corruption between assembly blocks, dirty higher-order bits, returndatasize-as-zero misuse, calldataload out-of-bounds, free memory pointer corruption.

### Update Solidity Version (FV-SOL-3-M1)

Solidity 0.8+ offers built-In Overflow and Underflow protection

### Using Established Math Libraries (FV-SOL-3-M2)

Complex calculations should be using hard work premade in trusted math libraries available

### Unit Testing on Edge Cases (FV-SOL-3-M3)

Write tests for edge cases, such as small or very large values, fractions close to rounding boundaries, zero values, and more.

## Actual Occurrences

* [https://solodit.cyfrin.io/issues/h-06-incorrect-solidity-version-in-fullmathsol-can-cause-permanent-freezing-of-assets-for-arithmetic-underflow-induced-revert-code4rena-good-entry-good-entry-git](https://solodit.cyfrin.io/issues/h-06-incorrect-solidity-version-in-fullmathsol-can-cause-permanent-freezing-of-assets-for-arithmetic-underflow-induced-revert-code4rena-good-entry-good-entry-git)
