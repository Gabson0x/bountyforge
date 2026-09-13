# FV-VYP-4-C2 Gas Griefing via External Calls

## TLDR

When a Vyper contract forwards all available gas to an untrusted external callee via `raw_call`, a malicious recipient can consume the gas intentionally to cause the transaction to run out of gas, or execute arbitrary expensive logic to grief callers. This is particularly dangerous in batch distribution patterns where one bad actor blocks the entire operation.

## Detection Heuristics

**`raw_call` with no explicit `gas=` parameter forwarding to caller-influenced addresses**
- `raw_call(recipient, b"", value=amount)` with no `gas=` argument, forwarding all remaining gas to an address supplied by or derived from user input
- Loop over a `DynArray` of addresses calling `raw_call` without a gas cap, where any entry could be a contract with an expensive or infinite `__default__` function

**ETH distribution to user-supplied addresses without gas limit**
- `raw_call(self.recipients[i], b"", value=reward)` inside a `for` loop where `self.recipients` is populated by untrusted callers via a public `add_recipient` function
- Reward or refund dispatch to `msg.sender` via `raw_call` with no `gas=2300` or equivalent cap

**`gas=` set to a value derived from user input**
- `raw_call(target, data, gas=user_provided_gas)` where `user_provided_gas` is a function parameter not bounded by a constant maximum

**Loop structure vulnerable to single-recipient griefing**
- A `for` loop calls `raw_call` with no `revert_on_failure=False`, meaning one griefing recipient reverts the entire batch and all other recipients receive nothing
- No per-iteration gas budget check or batch-pause mechanism to resume from a failed index

## False Positives

- `raw_call` to a hardcoded or owner-controlled address where the callee is trusted and cannot be replaced by user input
- Gas cap of `2300` or a similar low constant already applied: `raw_call(recipient, b"", value=amount, gas=2300)`
- Pull-payment pattern where recipients call a separate `claim` function, eliminating the push-to-untrusted-address risk entirely