# Oracle Integration Security Patterns (TON)

> Applies to: TON lending collateral pricing, TON derivatives and perpetuals, synthetic asset minting, margin trading contracts, any FunC or Tact contract consuming external price data on TON, Pyth on TON integrations, Redstone on TON, off-chain oracle with on-chain delivery

## Protocol Context

Oracle integrations on TON face a structural challenge unique to the actor model: price updates arrive as asynchronous inbound messages rather than being pulled synchronously from an on-chain contract. This means a price update message and a subsequent action message (borrow, liquidate, swap) can be reordered or batched in ways that create a window where stale prices are applied. Unlike EVM where a single transaction reads the current oracle state atomically, TON contracts must store the last received price in their persistent data and explicitly validate its recency on every use. An additional attack vector is the fake oracle sender: any contract can send a message to a TON smart contract, so the price update handler must verify the sender address matches the registered oracle.

## Bug Classes

---

### Stale Price Acceptance

**Protocol-Specific Preconditions**

- Contract stores `last_price` and `last_update_time` in persistent data; a price-consuming instruction does not compare `now() - last_update_time` against a maximum allowed staleness
- Oracle messages delayed by network congestion arrive minutes after being published; no on-chain check detects the gap
- Oracle contract itself goes silent due to a backend outage; last stored price is arbitrarily old with no circuit breaker

**Detection Heuristics**

- Find all reads of stored oracle price data; check each for a staleness guard: `throw_unless(error::stale_price, now() - last_update_time <= MAX_STALENESS_SECONDS)`
- Verify `last_update_time` is stored alongside the price in a dedicated persistent variable and is updated atomically with the price value in the same oracle message handler
- Check whether `MAX_STALENESS_SECONDS` is a hardcoded constant or a configurable parameter; if hardcoded, verify its value is appropriate for the protocol's liquidation time horizon
- Look for any path that reads the price without first checking freshness, such as an internal helper function called from multiple places where only some callers validate staleness

**False Positives**

- Every price consumption site includes a staleness guard with an appropriate threshold
- Contract uses a circuit breaker that halts all price-dependent operations if the oracle has not updated within the acceptable window

---

### Missing Confidence Validation

**Protocol-Specific Preconditions**

- Pyth on TON publishes both a price midpoint and a confidence interval in each price update message; contract stores only the midpoint
- During volatile market conditions, the confidence interval widens significantly, making the midpoint unreliable for collateral valuations or liquidation thresholds
- No maximum confidence ratio is enforced; protocol acts on prices with extreme uncertainty

**Detection Heuristics**

- Check whether the oracle message handler stores the confidence field alongside the price; if not, confidence validation is impossible
- Verify the price-consuming instruction checks `throw_unless(error::low_confidence, confidence <= MAX_CONF_RATIO * price / 100)` before using the price
- For lending protocols, verify that a high-confidence price threshold is applied more strictly for liquidation decisions than for regular borrows, given the asymmetry of impact
- Check whether `MAX_CONF_RATIO` is a mutable admin parameter; an immutable constant that cannot be tightened post-deployment is a risk

**False Positives**

- Contract receives both `price` and `confidence` in the oracle message and validates the ratio before storing or using the price
- Protocol uses a price range (`price - confidence, price + confidence`) and applies conservative bounds for each operation type

---

### Fake Oracle Sender

**Protocol-Specific Preconditions**

- TON actor model: any contract can send a message to any other contract; the price update handler does not authenticate the sender
- Oracle address stored in contract data but not compared against `msg_sender` in the price update handler
- Multiple oracle addresses supported but the allowlist check is missing or incomplete

**Detection Heuristics**

- Find the `op::oracle_price_update` (or equivalent op-code) handler in the main receive function; verify the first statement checks `throw_unless(error::unauthorized, equal_slices(sender_address, stored_oracle_address))`
- If multiple oracle sources are supported, verify the sender check iterates the allowlist or compares against all valid oracle addresses
- Check whether the oracle address in persistent data can be updated by a privileged admin instruction; if so, verify the admin check on that instruction
- Look for any handler that processes external price data via `parse_cell` on a message body without verifying the sender

**False Positives**

- Price update op-code handler has `throw_unless` on sender address as the first instruction before any data parsing
- Oracle contract is a deterministic PDA-equivalent (StateInit-derived address) whose address is computed at deployment and hardcoded in the consumer contract

---

### On-Chain Spot Price as Oracle

**Protocol-Specific Preconditions**

- Collateral or swap price derived from live AMM pool reserves (`reserve_a / reserve_b`) in the same transaction chain as the dependent operation
- No TWAP or multi-block averaging; price reflects instantaneous reserves at message processing time
- Multi-hop message chain: swap message arrives, contract reads AMM price, proceeds with collateral valuation - the AMM price was set by the attacker in a prior message in the same transaction chain

**Detection Heuristics**

- Identify all price computation sites; check whether the price is read from a stored oracle variable or computed from pool reserve fields in real time
- For any protocol reading DEX reserves for pricing, verify whether a TWAP accumulator or time-delayed price snapshot is used
- Check message ordering: if the protocol sends a message to the AMM to fetch the price and then acts on the response, verify the response validation enforces freshness independent of when the AMM was manipulated

**False Positives**

- Protocol uses a dedicated off-chain oracle with an independent update feed not connected to any on-chain DEX pool
- TWAP accumulator with a sufficiently long window (multiple minutes) maintained in the AMM contract and used exclusively for pricing in this protocol
