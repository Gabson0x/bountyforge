# FV-SOL-8 Slippage

### TLDR

Slippage vulnerabilities in Solidity typically refer to situations where unexpected price changes or inadequate checks on the value transferred in transactions cause a user to receive less than expected. This is especially relevant in decentralized exchanges (DEXs) and automated market makers (AMMs)

## Code


```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract VulnerableSwap {
    IERC20 public tokenA;
    IERC20 public tokenB;
    uint256 public rate; // Rate of tokenA to tokenB

    constructor(address _tokenA, address _tokenB, uint256 _rate) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
        rate = _rate; // Number of tokenB units per 1 tokenA unit
    }

    function swap(uint256 amountIn) external {
        uint256 amountOut = amountIn * rate;

        // No slippage check! The user will receive whatever `amountOut` is, even if rate changes.
        require(tokenA.transferFrom(msg.sender, address(this), amountIn), "Transfer of tokenA failed");
        require(tokenB.transfer(msg.sender, amountOut), "Transfer of tokenB failed");
    }
}
```

## Classifications

Run `cat $SKILL_DIR/reference/solidity/fv-sol-8-slippage/<filename>` to read any case file listed below.

#### fv-sol-8-c1-price-manipulation.md

#### fv-sol-8-c2-front-running.md

#### fv-sol-8-c3-insufficient-liquidity.md

#### fv-sol-8-c4-unexpected-gas-increase.md

#### fv-sol-8-c5-missing-deadline.md

`deadline: block.timestamp` or `type(uint256).max` provides no protection; multi-hop slippage enforced at intermediate step only.

#### fv-sol-8-c6-oracle-price-update-frontrunning.md

Push-model oracle update visible in public mempool; attacker front-runs with position at stale price before update lands.

## Mitigation Patterns

### Minimum Amount Checks (FV-SOL-8-M1)

Accept a `minAmountOut` parameter in functions that perform token swaps or trades. Before finalizing the transaction, check that the amount received meets or exceeds `minAmountOut`

### Time-Weighted Average Price (FV-SOL-8-M2)

Use a time-weighted average price (TWAP) instead of the immediate spot price to reduce the impact of temporary price manipulation

### Decentralized Oracles (FV-SOL-8-M3)

Use a decentralized oracle network (e.g., Chainlink) to provide reliable and tamper-resistant price data for slippage calculations

## Actual Occurrences

* [https://solodit.cyfrin.io/issues/h-07-missing-slippage-checks-code4rena-spartan-protocol-spartan-protocol-contest-git](https://solodit.cyfrin.io/issues/h-07-missing-slippage-checks-code4rena-spartan-protocol-spartan-protocol-contest-git)
