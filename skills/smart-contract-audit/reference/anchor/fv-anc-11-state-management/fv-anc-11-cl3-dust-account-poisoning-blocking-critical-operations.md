# FV-ANC-11-CL3 Dust Account Poisoning Blocking Critical Operations

## TLDR

An attacker can send a tiny lamport amount to a program-controlled account, increasing its balance above the rent-exempt minimum for zero bytes but below what a later `close` or realloc operation expects. This can cause `close` constraints to fail (because balance != expected), leave accounts in an un-closeable state, or force the protocol to accept griefing dust that accumulates indefinitely.

## Detection Heuristics

**Close Operation Depending on Exact Balance**
- Account close logic checks `account.lamports() == rent_exempt_minimum` rather than `account.lamports() >= rent_exempt_minimum`; a dust deposit shifts the balance above the expected value and breaks the comparison
- Protocol sweeps lamports to a fixed recipient and uses a hardcoded sweep amount rather than `account.lamports()`; dust leaves a residual balance that prevents account deletion

**Rent-Exempt Check Bypassed by Dust**
- An account below the rent-exempt threshold gains just enough lamports from a dust attack to cross the threshold, preventing the runtime from garbage-collecting it but not giving the attacker meaningful control
- Protocol relies on an account being garbage-collected after reaching zero lamports; dust prevents this and keeps the account alive indefinitely

**Unbounded Dust Accumulation**
- Protocol holds a token account or program-owned account that anyone can send lamports to; no mechanism to sweep or reject unsolicited lamport deposits
- Close operation fails due to residual balance from a dust deposit; the account is now stuck open and consuming space permanently

## False Positives

- Close operation uses `account.lamports()` as the sweep amount unconditionally, handling any non-zero balance correctly regardless of dust
- Anchor's `close = recipient` constraint sweeps the full lamport balance to the recipient atomically and cannot be blocked by dust
