# FV-ANC-5-CL10 Cross-Program Reentrancy via Callback

## TLDR

Solana's CPI depth limit does not prevent reentrancy when program A calls program B which calls back into program A at a different instruction before A's state is finalized. Unlike EVM, there is no automatic reentrancy guard at the runtime level; account state is accessible across CPI hops within the same transaction, and a callback into the caller can observe intermediate or inconsistent state.

## Detection Heuristics

**CPI to Program Accepting a Callback Target**
- Program calls an external program that accepts a callback target address as an instruction parameter; that external program may invoke instructions on the protocol before the outer instruction completes
- Hook-style architectures (e.g., transfer hooks, liquidation hooks) that allow user-supplied callback program IDs without restricting which programs can be called
- No reentrancy guard flag in any account state checked at instruction entry

**State Read Before CPI, Written After**
- A security-critical account field (balance, borrow amount, share count) is read before an external CPI call and written after, with no lock preventing the external program from reading the intermediate value
- The protocol's invariant check (e.g., collateral ratio, available liquidity) occurs after all CPIs have returned rather than before any external call

**Missing Reentrancy Guard**
- No boolean `is_executing` or `reentrancy_guard` field in any program-owned account that is set to true at instruction entry and reset on exit
- No check that an instruction is not reentrant via a stored slot or instruction counter in the program's global state account

## False Positives

- All external calls are to known static programs (SPL Token, System Program) that do not accept user-supplied callbacks and have no callback mechanism
- Callback target is validated against an allowlist of trusted non-reentrant programs before the CPI
- Reentrancy guard flag stored in account state is checked and set atomically at instruction entry
