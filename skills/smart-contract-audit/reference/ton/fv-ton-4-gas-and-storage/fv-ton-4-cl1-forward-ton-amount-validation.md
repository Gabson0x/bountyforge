# FV-TON-4-CL1 Forward TON Amount Validation

## TLDR

A user-controlled `forward_ton_amount` used directly in `send_raw_message` without validating it against `msg_value` lets attackers specify a large forward amount while sending minimal gas - the contract covers the difference from its own balance.

## Detection Heuristics

**Unbounded user-controlled forward amount**
- `int forward_ton_amount = in_msg_body~load_coins();` used directly as the forward amount in an outgoing send without any upper bound check
- No assertion that `msg_value >= tx_fees + forward_ton_amount` before sending
- Contract uses send mode 1 (pay fees from contract balance) with a user-controlled forward amount

**Indirect drain patterns**
- A chain of messages is initiated with user-supplied amounts at each hop - cumulative forward costs drain the contract
- Fixed forward amounts that were safe at deployment but become insufficient as gas costs change, causing the contract to silently subsidize the difference

**Secure patterns to look for (confirm they are present)**
- Fixed constant for `forward_ton_amount` that cannot be overridden by message body
- `throw_unless(error::insufficient_value, msg_value > tx_fee + forward_ton_amount)` before any send
- Send mode 64 (return remaining incoming value) used - automatically limits forward to what was received

## False Positives

- Contract deliberately subsidizes forward fees as a product feature, with an explicit per-call maximum enforced to cap the subsidy
- `msg_value` validation happens in a wrapper function called before the forward amount is used - trace the full call path
