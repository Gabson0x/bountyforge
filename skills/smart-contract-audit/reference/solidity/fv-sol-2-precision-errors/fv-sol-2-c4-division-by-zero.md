# FV-SOL-2-C4 Division by Zero

## TLDR

Division by zero in Solidity causes an unconditional revert since 0.8.x (via the built-in overflow/underflow checks) or silent undefined behavior in earlier versions. Beyond crashes, an attacker who can set a denominator to zero can selectively brick functions, trigger denial-of-service, or force a contract into an unrecoverable state. The risk is highest when the denominator is user-controlled, derived from an external call, or can reach zero through normal protocol lifecycle (e.g., all shares redeemed, pool fully drained).

## Detection Heuristics

**Denominator From User Input or State**
- `return (userContribution * 100) / totalShares` where `totalShares` is set by any caller via a public setter
- `price = totalAssets / totalSupply()` without a guard - supply can reach zero after all redemptions
- Division by a `mapping` value, an `ERC20.totalSupply()` call, or any balance that legitimately reaches zero

**Missing Zero Guard Before Division**
- No `require(denominator > 0, ...)` or `if (denominator == 0) revert` preceding the division
- Division directly in a `view` function that returns price or rate - callers may not expect it to revert
- Denominator computed via subtraction (e.g., `totalAssets - withdrawnAmount`) that can underflow to zero

**External Call Result as Denominator**
- Result of `oracle.getPrice()` or `pool.getReserves()` used directly as divisor without a zero check
- `reserve0` or `reserve1` from a Uniswap/Curve pool used in a price formula - pools can be drained

**Lifecycle Edge Cases**
- First interaction before any deposits: `totalShares == 0` or `totalAssets == 0` on an uninitialized vault
- All users exit: `totalSupply() == 0` causes price functions to revert, blocking re-entry

## False Positives

- Denominator is a compile-time constant or immutable set in constructor with a `require(> 0)` check
- Guard `require(totalShares > 0)` or equivalent is present immediately before every division by that variable
- Protocol enforces a minimum locked deposit (dead shares) that prevents the denominator from ever reaching zero
- The division is inside an `if` block that is only reached when the denominator is already proven non-zero by the surrounding control flow
