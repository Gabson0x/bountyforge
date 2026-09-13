# Oracle Integration Security Patterns

> Applies to: Pyth oracle consumers, Switchboard oracle consumers, on-chain price feeds, lending collateral pricing, margin systems, liquidation engines, perpetuals pricing, synthetic asset minting, any protocol consuming external price data on Solana

## Protocol Context

Oracle-consuming protocols on Solana are architecturally exposed to the update frequency and reliability characteristics of the specific feed they integrate. Pyth publishes confidence intervals and status flags alongside each price; Switchboard aggregates multiple sources with configurable staleness windows. Both models require the consuming program to make active decisions about what constitutes an acceptable price - staleness tolerance, confidence ratio, and status validity must be explicitly enforced on-chain at every price consumption site. Off-chain oracle manipulation is not feasible for Pyth or Switchboard, but on-chain spot price manipulation via flash loans remains a viable attack vector for protocols that derive prices from AMM pool reserves rather than dedicated oracle feeds.

## Bug Classes

---

### Stale Price Acceptance

**Protocol-Specific Preconditions**

- Program reads `Price.price` from a Pyth feed account without calling `try_get_price_no_older_than(clock, max_age_seconds)` or equivalent
- Switchboard feed read without checking `latest_confirmed_round.round_open_slot` against current slot
- Max staleness threshold is set to an unreasonably large value relative to the protocol's liquidation and collateral sensitivity
- Oracle account not validated against a hardcoded or governance-registered expected address, allowing submission of a different feed with a recently-updated but wrong price

**Detection Heuristics**

- Search for `get_price_unchecked()` or direct `price_account.try_deserialize()` usage without a subsequent staleness check
- Check every oracle price consumption site for a comparison of `publish_time` or `round_open_slot` against `Clock.unix_timestamp` or `Clock.slot` within an acceptable window
- Verify that the staleness window parameter is configurable and its current value is appropriate for the protocol's risk model
- Identify any oracle account passed as an instruction parameter (not hardcoded); verify it is compared against a registered expected address before use

**False Positives**

- Protocol exclusively uses `try_get_price_no_older_than` with an appropriate max age for all price consumption sites
- Feed update frequency is documented to be faster than the protocol's staleness window and this is enforced by the on-chain check

---

### Confidence Interval and Status Ignored

**Protocol-Specific Preconditions**

- `Price.conf` not validated against a maximum acceptable ratio before using `Price.price`
- `Price.status` not compared against `PriceStatus::Trading` at every consumption site; price used when status is `Unknown` or `Halted`
- No circuit breaker for extreme price deviation; a compromised or malfunctioning oracle can report any value without on-chain rejection

**Detection Heuristics**

- Grep for all `Price.price` or `price.agg.price` access sites; trace each to find whether `conf`, `status`, and `publish_time` are all validated in the same code path
- Check whether the max confidence ratio is a protocol parameter that governance can update, or a hardcoded constant; constants that are too loose cannot be tightened post-deployment
- Verify the circuit breaker logic if present: max deviation from last accepted price, minimum/maximum absolute price bounds

**False Positives**

- Protocol applies all three checks (staleness, confidence ratio, status) before every price use and returns a descriptive error on violation
- Confidence ratio check applies a reasonable bound (e.g., reject if `conf * 100 / abs(price) > 2`) for the asset class being priced

---

### Flash Loan Oracle Manipulation

**Protocol-Specific Preconditions**

- Price derived from AMM pool reserves (`token_a_reserve / token_b_reserve`) rather than a dedicated oracle feed
- Protocol integrates with a flash loan provider and the flash loan target pool is the same pool used for price derivation
- No TWAP or multi-block price averaging; price reflects instantaneous reserve ratio at instruction execution time

**Detection Heuristics**

- Identify all price or exchange rate computation sites; check whether the rate is derived from on-chain pool reserves or from a dedicated oracle account
- For protocols using pool-derived prices, verify whether the protocol also integrates a TWAP oracle account from the same pool that uses a historical average
- Check for minimum time between price-sensitive operations that would prevent rapid manipulation within a single slot

**False Positives**

- Protocol uses only off-chain aggregated oracle feeds (Pyth, Switchboard) that cannot be manipulated via on-chain flash loans
- AMM TWAP oracle used with a sufficiently long window (e.g., 30 minutes) that a single-block flash loan cannot meaningfully move the time-weighted average

---

### Fake Oracle Injection (ref: fv-anc-8-cl3)

**Protocol-Specific Preconditions**

- Oracle account passed as an instruction parameter and validated only by checking it is non-zero or owned by a known oracle program, not by comparing its address to an expected feed address
- Multiple oracles supported but the registry of accepted oracle addresses is not enforced on-chain at the price consumption site
- Program ID check performed on the oracle account (Pyth program, Switchboard program) but not the specific feed address within that program

**Detection Heuristics**

- Find every instruction that accepts an oracle or price feed account as a parameter; check whether it is compared against a hardcoded constant or a governance-stored expected address
- Verify that oracle address registration is gated behind a privileged admin or governance instruction, not freely settable by users
- Check for Anchor `#[account(address = expected_oracle_address)]` constraint or equivalent manual key comparison

**False Positives**

- Oracle accounts are hardcoded as program constants and not accepted as instruction parameters
- Protocol uses a governance-managed oracle registry with a privileged update path; any oracle address used must first be registered by governance

---

### Retroactive or Delayed Price Application

**Protocol-Specific Preconditions**

- Signed price updates submitted via durable nonce transactions can be submitted at any future time at the submitter's convenience
- Protocol allows price updates to be applied to positions that were opened before the price update's timestamp
- Settlement or liquidation can use a price snapshot from a previous slot rather than the current slot price

**Detection Heuristics**

- Check whether price update instructions validate that the price timestamp is strictly later than the position's open timestamp
- Verify that settlement prices are bounded to a freshness window relative to the settlement execution time, not just relative to when the price was published
- Identify any signed-price or voucher mechanism (price attested off-chain and submitted on-chain); check that the on-chain consumer enforces an expiry window

**False Positives**

- Protocol only applies oracle prices at the current slot; no mechanism exists to submit past prices for current operations
- Settlement price must be within a tight freshness window (e.g., 5 seconds) relative to the settlement transaction's Clock.unix_timestamp
