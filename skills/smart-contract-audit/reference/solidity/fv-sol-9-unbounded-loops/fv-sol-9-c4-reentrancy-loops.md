# FV-SOL-9-C4 Reentrancy Loops

## TLDR

Loops that perform external calls on each iteration compound two risks: unbounded gas cost from the iteration itself, and reentrancy from any external call within the loop body. A malicious recipient can re-enter the looping function mid-iteration, causing state corruption, double-spending, or out-of-gas reversions that permanently lock funds.

## Detection Heuristics

**External Call Inside Loop With State Updated After Call**
- `payable(addr).transfer(amount)` or `addr.call{value:...}("")` inside a `for` loop where the balance decrement follows the transfer
- `IERC20(token).transfer(recipient, amount)` inside a loop over untrusted recipient addresses
- State invariant (total balance, processed flag) is not fully committed before the first external call in the loop

**No Reentrancy Protection on Looping Function**
- Function performing the loop lacks a `nonReentrant` modifier
- Checks-effects-interactions pattern violated: effects (state writes) interleaved with or after interactions (external calls)
- No per-recipient state isolation preventing a re-entering call from replaying a prior iteration

**Caller-Controlled Recipient List**
- `recipients` array is passed as a calldata or memory argument by an untrusted caller
- Caller can include a contract address they control as a recipient
- No address validation or whitelist applied to the recipient list

## False Positives

- All state updates occur before any external calls in the loop (strict checks-effects-interactions order)
- `nonReentrant` modifier applied to the function
- Pull-over-push pattern: recipients claim individually rather than being iterated over in a single transaction
- Recipients are a protocol-controlled, pre-validated set containing no external contracts
