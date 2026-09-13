# FV-SOL-8-C2 Front-Running

## TLDR

Swap transactions published to the public mempool expose their parameters - token pair, input amount, and minimum output - before inclusion. MEV bots observe these parameters and sandwich the victim: a buy is inserted before the transaction to move the price up, and a sell is inserted after, extracting value from the slippage tolerance the victim granted.

## Detection Heuristics

**Transparent Swap Parameters**
- Swap function accepts `tokenIn`, `amountIn`, and `minAmountOut` directly as calldata with no obfuscation
- No commit-reveal pattern: trade details are visible in the pending transaction before it mines
- No private relay integration documented or enforced at the contract level

**Permissive or Hardcoded Slippage**
- `minAmountOut` is zero or derived from a hardcoded constant rather than a caller-supplied tight bound
- Slippage tolerance set to a percentage wide enough to make sandwiching profitable (e.g. >1% on liquid pairs)
- `minAmountOut` computed from a stale off-chain price without deadline enforcement

**No Commitment Verification**
- No `mapping(address => bytes32) tradeCommitments` or equivalent on-chain hash commitment
- Reveal step does not `require(hash(params) == commitment[msg.sender])`
- Stale commitments not invalidated - no block number or timestamp bound on the commit

## False Positives

- Commit-reveal scheme used: trade hash committed on-chain and verified at reveal time
- Transactions submitted via private relay (Flashbots Protect, MEV Blocker) - not visible in public mempool
- `minAmountOut` is a tightly calibrated caller-supplied parameter combined with a short deadline
- Protocol operates on a sequencer with a private mempool where ordering is not publicly observable


