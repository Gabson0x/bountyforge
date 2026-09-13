# FV-SOL-1-C3 Cross Contract

## TLDR

An attacker deploys a dedicated malicious contract that acts as `msg.sender` and re-enters the victim contract during an external call callback. The malicious contract's `receive` or `fallback` calls back into the victim before the victim's state update, allowing repeated exploitation across a contract boundary.

## Detection Heuristics

**External Call to Caller-Controlled Address Before State Update**
- `.call{value:}("")" to `msg.sender` before `balances[msg.sender]` is zeroed or decremented
- Any pattern where the recipient of an external call can be a contract address supplied or implied by the caller
- `withdraw`, `redeem`, `claim`, or `payout` functions that send ETH or tokens to `msg.sender` as the last step

**No Verification That Recipient Is an EOA**
- No `extcodesize(msg.sender) == 0` check (note: this check is bypassable during construction, but absence is a signal)
- No `msg.sender == tx.origin` guard (note: this has other trade-offs, but absence is a signal worth investigating)
- No `nonReentrant` modifier restricting reentry from any external address

**State Update Ordering**
- Balance or ownership mapping updated after the external call in functions that transfer ETH or tokens out
- Local variable caches the pre-call balance (`uint256 balance = balances[msg.sender]`) but the mapping is cleared only after the call

## False Positives

- State zeroed or decremented before the `.call{value:}("")` (CEI strictly followed)
- `nonReentrant` modifier present on the withdrawing function
- Function uses `transfer()` or `send()` and no `TSTORE` path is reachable in 2300 gas from any attacker-controlled fallback
- Recipient is a protocol-controlled address (not caller-supplied), verified via access control before the call
