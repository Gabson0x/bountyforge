# FV-ANC-13-CL4 Log Truncation Hiding Critical Security Events

## TLDR

Solana transactions are limited in total compute units per transaction. When a program emits extensive logs near the compute limit, the Solana runtime truncates log output silently. Security-critical events emitted near or after the compute budget is exhausted will not appear in the transaction logs, making off-chain monitoring systems blind to them. An attacker can intentionally exhaust compute budget before a security event to prevent its detection.

## Detection Heuristics

**Security Events Emitted Late in Instruction**
- Critical `msg!` or `emit!` calls (failed access checks, unusual amounts, emergency flags) placed near the end of an instruction after expensive computation that consumes most of the compute budget
- Log emission order not reviewed against compute budget consumption; a long iteration loop before a security event log may truncate the event

**No Compute Budget Reservation for Logging**
- Program does not reserve a compute budget margin (e.g., `request_heap_frame` or early return if remaining compute < threshold) to ensure logging calls are not truncated
- Off-chain indexer or monitoring system relies exclusively on transaction logs without checking for log truncation indicators in the transaction metadata

**Event Emission via emit! Macro**
- Anchor `emit!` macro calls placed after large account iteration loops; the macro incurs CPI cost and can be truncated if budget is exhausted
- No fallback mechanism (e.g., storing the event in account state) for critical events that must be observable even under compute pressure

## False Positives

- All security-critical events emitted at the very beginning of the instruction before any expensive computation, ensuring they are never truncated
- Protocol uses account-state-based event recording rather than log emission; events are always readable from account data regardless of compute budget
