# FV-SOL-6-C1 Unchecked Call Return

## TLDR

Low-level calls (`call`, `delegatecall`, `staticcall`, `send`) return a boolean success flag instead of reverting on failure. When the return value is discarded the caller continues execution under the false assumption that the operation succeeded, enabling lost funds, skipped logic, and corrupted state.

## Detection Heuristics

**Discarded Return Value**
- `target.call(data)` as a standalone statement with no `(bool success, ...)` capture
- `target.delegatecall(data)` or `target.staticcall(data)` return value not stored or checked
- `target.send(amount)` without storing and checking the returned bool

**Captured but Unchecked**
- `(bool success, bytes memory ret) = target.call(data)` followed by no `require(success)` or conditional revert
- `bool ok = addr.call(...)` where `ok` is never read after assignment

**Indirect Patterns**
- Helper function wraps a low-level call and returns void, discarding the inner bool
- Assembly `call` opcode with the success value popped from stack rather than stored

## False Positives

- `require(success, "...")` or `if (!success) revert ...` immediately follows the captured bool
- Intentional fire-and-forget call where failure is an accepted outcome and is explicitly documented in a NatSpec comment
- Wrapped in an internal helper that itself reverts on failure and is used consistently throughout the codebase
