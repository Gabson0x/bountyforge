# FV-VYP-7-C1 Transaction Order Dependencies

## TLDR

Front-running in Vyper contracts arises when a pending transaction reveals information (price, amount, action) that an observer can exploit by submitting a competing transaction with a higher gas price before the original is included. Vyper's lack of function overloading means slippage protection and deadline parameters must be explicitly added to every affected function signature.

## Detection Heuristics

**Price or rate read from storage with no caller-specified maximum**
- `assert msg.value >= self.price` with no `max_price: uint256` parameter in the function signature, allowing a price increase sandwiched around the buyer's transaction
- `rate: uint256 = self.exchange_rate` read inside a swap or purchase function with no tolerance parameter, enabling the owner or a bot to change the rate between block submission and inclusion

**Owner-controlled parameter update with no time lock**
- `self.price = new_price` or `self.fee_rate = new_rate` executable by the owner in the same block as a pending user transaction, with no `price_lock_until` or equivalent delay
- No minimum notice period before a parameter change takes effect, allowing atomic front-run of user actions

**Approval front-running on ERC-20-like allowance patterns**
- `self.allowance[owner][spender] = amount` set unconditionally, enabling a spender to observe the pending approval and spend the old allowance before the new one overwrites it
- No `increase_allowance` / `decrease_allowance` pattern; direct `approve`-style setter without a zero-first requirement

**Predictable function selector exploitation**
- A function with a known selector and profitable outcome (e.g., arbitrage, liquidation) callable by anyone, allowing MEV bots to replicate the call with higher gas and claim the profit

**Commit-reveal patterns absent for sensitive submissions**
- Order book entries, bids, or game moves submitted in plaintext in a single transaction without a prior commitment phase, enabling other participants to react before the transaction is confirmed

## False Positives

- Functions that accept a `max_price`, `min_output`, or `deadline` parameter already providing slippage and timing protection to the caller
- Price updates protected by a time lock or multi-sig governance process that prevents atomic front-running
- Contracts operating on private mempools, L2 sequencers with guaranteed ordering, or MEV-protected RPC endpoints where transaction ordering is not manipulable by external parties