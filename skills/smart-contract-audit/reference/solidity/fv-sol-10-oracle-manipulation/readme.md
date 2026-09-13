# FV-SOL-10 Oracle Manipulation

## TLDR

Tampering with the mechanisms that provide asset price data to smart contracts

## Code


```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface Oracle {
    function getCurrentOraclePrice() external view returns (uint256);
}

contract VulnerableCompound {
    Oracle public oracle;
    uint256 public oraclePrice;

    constructor(address _oracle) {
        oracle = Oracle(_oracle);
        oraclePrice = 1e18;
    }

    function getPricingImportant() public {
        // Vulnerable reliance on the oracle
        oraclePrice = oracle.getCurrentOraclePrice(); // Assumes truthfull results
    }
}
```

## Classifications

Run `cat $SKILL_DIR/reference/solidity/fv-sol-10-oracle-manipulation/<filename>` to read any case file listed below.

#### fv-sol-10-c1-incorrect-compounding-mechanism.md

#### fv-sol-10-c2-price-drift.md

#### fv-sol-10-c3-manipulation-through-external-markets.md

#### fv-sol-10-c4-time-lags.md

#### fv-sol-10-c5-chainlink-feed-validity.md

Covers: missing staleness check, incomplete round check, deprecated feed, wrong decimal assumption.

#### fv-sol-10-c6-l2-sequencer-uptime.md

Covers: Chainlink feed on L2 without Sequencer Uptime Feed check; stale prices during/after sequencer downtime.

#### fv-sol-10-c7-missing-price-bounds.md

Covers: no min/max sanity bounds on oracle price; TWAP window under 30 minutes manipulable post-Merge.

## Mitigation Patterns

### Multi-Sourced Oracles (FV-SOL-10-M1)

Use multiple oracle data sources to calculate an aggregated price

## Actual Occurrences

* [https://solodit.cyfrin.io/issues/h-01-oracle-price-does-not-compound-code4rena-volt-protocol-volt-protocol-contest-git](https://solodit.cyfrin.io/issues/h-01-oracle-price-does-not-compound-code4rena-volt-protocol-volt-protocol-contest-git)