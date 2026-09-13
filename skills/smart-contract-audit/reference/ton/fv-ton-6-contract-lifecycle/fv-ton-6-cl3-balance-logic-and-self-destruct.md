# FV-TON-6-CL3 Balance-Based Logic and Self-Destruct

## TLDR

Using the contract's raw TON balance for business decisions is manipulable since anyone can send TON to any contract. Send mode flag +32 accidentally included in non-terminal paths destroys the contract permanently when its balance reaches zero.

## Detection Heuristics

**Balance-based logic**
- `my_balance` or `get_balance()` used as a condition for unlocking features, determining pool size, or computing share prices - an attacker can inflate the balance by sending TON directly
- Protocol accounting uses raw balance instead of an internally tracked `total_deposits` variable
- Fee calculations, liquidation thresholds, or rate calculations derived from the raw contract balance

**Accidental mode +32 reachability**
- `send_raw_message(msg, 160)` (128 + 32) present in a code path reachable by non-admin callers
- Mode +32 used in refund logic or error recovery paths where the intent was to send remaining balance, not destroy the contract
- Contract balance can be reduced to zero through user-triggered operations, activating mode +32 destruction

**Missing global variable initialization**
- FunC handler uses global variables before calling `load_data()` - globals contain zero/default values, bypassing stored admin addresses or configuration
- `load_data()` called conditionally (only in some op branches) - other branches read uninitialized globals

## False Positives

- Mode +32 is used intentionally in an admin-gated shutdown function and is clearly documented as the terminal state for the contract
- Balance is used only as a sanity check upper bound (e.g., cannot withdraw more than balance) alongside a tracked internal accounting variable that is the primary source of truth
