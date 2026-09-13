# FV-SOL-1-C2 Cross Function

## TLDR

Multiple functions within the same contract share a state variable. One function makes an external call before updating that variable, while another function relies on the same variable for access control or accounting. An attacker re-enters the second function during the callback window to exploit the stale shared state.

## Detection Heuristics

**Shared State Variable Across Functions with Mixed Access Patterns**
- Two or more functions read or write the same `mapping` or state variable (e.g., `balances[msg.sender]`)
- One function contains an external call before the shared variable is updated; another function checks or decrements that same variable
- Pattern: `withdraw` does `.call{value: balance}("")` before `balances[x] = 0`, while `play` or `transfer` reads `balances[x]` for authorization or deduction

**Re-entry Path Through a Different Function**
- Attacker's `receive`/`fallback` calls a sibling function (not the same entry point) during the callback window
- The sibling function passes its own `require` because the shared state has not yet been updated by the original caller
- Functions that deduct from `balances` without an external call become weaponizable if a co-function leaves the balance stale during a call

**Missing Guard Coverage**
- `nonReentrant` applied to only one function while the sibling function that shares state is unprotected
- Guard covers `withdraw` but not `play`, `transfer`, `borrow`, or other functions that read the same balance slot

## False Positives

- CEI followed in every function that touches the shared state variable - no function leaves state stale during an external call
- `nonReentrant` applied to all functions that read or write the shared state variable
- Shared variable is written atomically at the start of each function before any interaction (checks-effects pattern, not checks-interactions)


