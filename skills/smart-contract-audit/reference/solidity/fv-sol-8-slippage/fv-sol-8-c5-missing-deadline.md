# FV-SOL-8-C5 Missing or Ineffective Deadline on Swaps

## TLDR

Without a meaningful deadline, a swap transaction can be held in the mempool indefinitely by validators and executed at an arbitrary future time when conditions may be unfavorable. `deadline = block.timestamp` is always valid (the transaction executes in the same block it appears to be submitted), and `deadline = type(uint256).max` provides no protection at all.

A related issue is enforcing slippage only at intermediate hops in a multi-hop route. If only the first hop has `minAmountOut`, the final output to the user has no bound - subsequent hops can be freely sandwiched.

## Detection Heuristics

**Deadline Issues**
- `deadline: block.timestamp` passed to router - trivially always passes
- `deadline: type(uint256).max` - no expiry protection
- No `deadline` parameter in swap wrapper function - hardcoded internally
- Deadline not forwarded from user calldata: derived from `block.timestamp + N` internally

**Multi-Hop Slippage Gap**
- `minAmountOut` enforced on first or intermediate hop but final output amount unchecked
- `_swapBtoC(mid, 0)` - zero minimum on second leg
- `amountOutMinimum` checked against mid-route output, not user's final received balance
- Delta check (`post - pre`) not performed on user's final token balance after multi-hop

## False Positives

- Deadline is calldata parameter validated with `require(deadline >= block.timestamp)` on-chain
- `minAmountOut` validated against final user balance delta: `require(token.balanceOf(user) - before >= minOut)`
- Single-hop swap where there are no intermediate steps
- Protocol is an aggregator - each hop has independent user-specified minimums
