# FV-ANC-11-CL4 Unbounded Account Collection Causing DoS

## TLDR

Instructions that iterate over a variable-length collection stored in an account (a Vec of positions, orders, or members) can exhaust compute units when the collection grows large. An attacker can repeatedly add entries to grow the collection to a size that makes all dependent instructions fail due to compute budget exhaustion, effectively bricking any protocol operation that touches that account.

## Detection Heuristics

**Iteration Over User-Controlled Vec**
- Instruction iterates over `account.positions`, `account.orders`, or similar Vec fields with no cap on collection length
- Vec is extended by user-callable instructions without a maximum length constraint (`require!(list.len() < MAX_ITEMS)`)
- Gas or compute cost of the iteration grows linearly with collection size and can be pushed above 1.4M compute units

**Missing Collection Size Cap**
- `Vec::push` called in a user-accessible instruction without checking current length against a protocol-defined maximum
- Protocol documentation mentions a maximum but the on-chain check is absent or uses an incorrect bound
- A separate attacker-controlled account's Vec is iterated in the same instruction that processes the victim's main operation, doubling the iteration work

**Cleanup Path Also Blocked**
- The only way to remove entries from the collection is via an instruction that also iterates the full collection; once the collection is large enough to DoS the iteration, entries cannot be removed either, making the DoS permanent
- No privileged admin function to forcibly truncate or migrate oversized collections

## False Positives

- Collection length is bounded by a `require!` check at every append site and the maximum is low enough that compute budget is never exhausted
- Protocol charges a fee per entry that makes unbounded growth economically irrational
- Fixed-size arrays used instead of Vec; the size is a compile-time constant that bounds compute cost
