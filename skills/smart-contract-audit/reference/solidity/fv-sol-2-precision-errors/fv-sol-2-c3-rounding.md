# FV-SOL-2-C3 Rounding

## TLDR

Solidity performs integer division with truncation (floor rounding toward zero), which silently discards fractional remainders. In contracts that distribute funds, accrue rewards, or compute fees across many users or iterations, these per-operation losses accumulate into meaningful discrepancies - either funds become permanently stuck, or repeated operations allow users to extract slightly more than they contributed.

## Detection Heuristics

**Unscaled Division in Share or Reward Allocation**
- `allocation = (totalFunds * recipientShares) / totalShares` without a prior scaling multiplication
- `reward = (elapsed * rewardRate) / PERIOD` where elapsed and rewardRate are raw values without WAD scaling
- Share price computed as `totalAssets / totalShares` used directly in downstream arithmetic

**Rounding Direction Not Considered**
- Same division formula used for both deposit (should round down) and withdrawal (should round up) paths
- No use of `Math.mulDiv(..., Rounding.Ceil)` or equivalent ceiling division for user-unfavorable paths
- Protocol claims ERC4626 compliance but `previewWithdraw` and `previewRedeem` both round the same direction

**Accumulated Dust**
- `totalFunds` decremented by a rounded `allocation` value across many calls - final state leaves unclaimable residue
- No reconciliation or sweep function for remainder dust in distribution contracts
- Sum of all per-user allocations computed independently and then compared to total - verify they can diverge

**Fee Calculation Precision Loss**
- `fee = amount * feeBps / 10000` where `amount` values can be small enough to round the fee to zero
- Protocol collects fees by subtracting rounded values, allowing fee-free micro-transactions

## False Positives

- A WAD or RAY scaling factor is applied before every division, making truncated remainders sub-wei
- Protocol explicitly tracks and periodically redistributes dust remainder to a designated address
- Rounding direction is intentionally protocol-favorable: deposit rounds down (fewer shares), withdrawal rounds up (more shares burned), consistent with EIP-4626
- Values involved are large enough by protocol invariant (e.g., minimum deposit enforced) that per-operation dust is negligible and bounded
