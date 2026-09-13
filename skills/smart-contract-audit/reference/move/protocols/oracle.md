# Oracle Integration Security Patterns (Sui/Move)

> Applies to: Pyth on Sui, Switchboard on Sui, custom oracle implementations, Move-based oracle consumers, lending collateral pricing, perpetuals mark price feeds, synthetic asset minting, any Move module reading external price data on Sui

## Protocol Context

Oracle integrations on Sui use the Sui object model, where price feed data is accessed through shared objects or owned capability objects. Pyth on Sui exposes price data as a `PriceInfoObject` (shared object) with a hot-potato pattern for pulling and verifying price updates in a single PTB. A key Sui-specific risk is fake oracle injection: since Move's type system enforces struct provenance, an attacker cannot pass a counterfeit `PriceFeed` of the official Pyth type to a module, but they can pass an object of a homonymous type from a malicious module if the consumer validates only struct layout rather than the originating module address. Staleness and confidence validation must be applied explicitly at every consumption site; the Pyth SDK provides helpers but they must be called correctly.

## Bug Classes

---

### Stale Price Acceptance

**Protocol-Specific Preconditions**

- `PriceInfoObject` read via `pyth::price_info::get_price_unsafe` or without calling `pyth::price::get_price_no_older_than` with a clock reference
- `Price.timestamp` not compared against `clock::timestamp_ms(clock) / 1000` with a staleness tolerance
- Switchboard `Aggregator` object read without checking `latest_confirmed_round.round_open_timestamp`

**Detection Heuristics**

- Find all calls to `pyth::price_feeds::get_price` or equivalent; check whether the next statement validates the returned `Price.timestamp`
- Verify that `get_price_no_older_than(price_info, clock, max_age_secs)` is used rather than `get_price_unsafe` at every price consumption site
- For Switchboard, check whether `aggregator.latest_confirmed_round.round_open_timestamp` is compared against `clock::timestamp_ms(clock) / 1000` within an acceptable window
- Verify that the maximum staleness tolerance is stored in a mutable admin-controlled config and is appropriate for the protocol's liquidation time horizon

**False Positives**

- All price consumption sites use `get_price_no_older_than` with an appropriate max age
- Custom staleness check: `assert!(clock::timestamp_ms(clock) / 1000 - price.timestamp <= max_staleness_secs, ERROR_STALE_PRICE)` applied immediately after every price read

---

### Oracle Confidence Interval and Status Ignored

**Protocol-Specific Preconditions**

- `price.conf` not validated against a maximum acceptable ratio before using `price.price`
- Pyth `Price` struct has both `price` (i64) and `conf` (u64) fields; only `price` is read and used in collateral calculations
- No circuit breaker for extreme price deviation; a malfunctioning oracle can report an arbitrarily low or high value without on-chain rejection

**Detection Heuristics**

- Find all sites reading `price.price`; check whether `price.conf` is also read and validated: `assert!(price.conf * 100 / (price.price as u64) <= max_conf_bps, ERROR_LOW_CONFIDENCE)`
- Check whether the Pyth `PriceFeed.status` field is validated as `PRICE_STATUS_TRADING` before use
- Verify the protocol has configurable confidence and deviation bounds stored in a mutable `OracleConfig` object
- Check for minimum and maximum price bounds that reject implausible oracle values regardless of confidence

**False Positives**

- Protocol applies both confidence ratio and status checks before every price use with configurable thresholds
- Price used in a context where confidence validation is documented as intentionally relaxed (e.g., only for monitoring, not for protocol state changes)

---

### Fake Oracle Object Injection

**Protocol-Specific Preconditions**

- Protocol's oracle consumer function accepts a generic `&PriceInfoObject` by type but does not validate the object's ID against a registered expected address stored in a config object
- A malicious actor deploys a module that re-exports the same struct type from the Pyth package (not possible in Move due to module provenance) or passes an object from a forked/unofficial Pyth deployment
- Protocol uses an unofficial Pyth deployment address (testnet vs mainnet, unofficial deployment) without verifying the `PriceInfoObject`'s parent package address

**Detection Heuristics**

- Find every function accepting a Pyth `PriceInfoObject` or Switchboard `Aggregator`; check whether the object's ID is compared against a stored expected ID from a config: `assert!(object::id(price_info) == config.btc_price_feed_id, ERROR_WRONG_ORACLE)`
- Verify that oracle object IDs are registered through an admin-gated function, not hardcoded in the bytecode (hardcoding makes upgrades difficult but is more secure)
- Check whether the module validates the Pyth state object passed to the update call; using an unofficial Pyth deployment means the price authority chain is not the official Pyth network

**False Positives**

- Oracle object ID validated against a governance-controlled `OracleConfig` at every price consumption site
- Protocol uses only the official Pyth deployment addresses documented by the Pyth network and these are verified at deployment

---

### Single Oracle Source Dependency

**Protocol-Specific Preconditions**

- Protocol depends on a single oracle source for all price-sensitive operations with no fallback
- Oracle source goes offline or reports a faulty price; no circuit breaker halts protocol operations until the oracle is restored
- Single oracle source for liquidation pricing means a brief oracle failure window can be exploited to prevent legitimate liquidations (too-stale price) or force illegitimate ones (manipulated price)

**Detection Heuristics**

- Count the number of distinct oracle sources used for any single asset price; one source with no fallback is a medium finding; one source for liquidation pricing is high
- Check whether the protocol has a fallback oracle that is used when the primary oracle is stale
- Verify there is a pause mechanism triggered when all oracle sources are stale, rather than using the last known price indefinitely
- Check whether multiple oracle sources are averaged or the minimum/maximum is taken; document the aggregation method and its security implications

**False Positives**

- Protocol uses two independent oracle sources (e.g., Pyth + Switchboard) and takes the median or the more conservative value
- Protocol has a documented and tested oracle failure mode that halts price-dependent operations when all sources are stale
