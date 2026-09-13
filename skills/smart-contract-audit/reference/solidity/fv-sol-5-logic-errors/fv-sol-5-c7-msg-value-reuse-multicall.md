# FV-SOL-5-C7 msg.value Reuse in Loop and Multicall

## TLDR

`msg.value` is a global that persists for the entire transaction. Reading it inside a loop or inside `delegatecall`-based multicall credits the full original ETH value on every iteration - a single payment appears as N payments.

This also applies to `delegatecall` multicall: each sub-call executes in the same context and sees the same `msg.value`, so calling a payable function N times via multicall charges ETH once but credits N times.

## Detection Heuristics

- `msg.value` read inside a `for` loop without a local accumulator variable
- `msg.value` compared against per-iteration cost without decrement
- `delegatecall`-based multicall where any sub-function is `payable`
- Uniswap V3 / OZ `Multicall` inherited with added `payable` functions
- Pattern: `address(this).delegatecall(data[i])` in a payable function

## False Positives

- `msg.value` captured to local variable before loop: `uint256 remaining = msg.value`
- `remaining -= cost` enforced per iteration
- Multicall uses `call` (not `delegatecall`) - separate context, `msg.value` is 0
- Function is `nonpayable` - `msg.value` always 0
- Single-item loop (length enforced as 1)
