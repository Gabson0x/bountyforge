# AMM and DEX Security Patterns (Sui/Move)

> Applies to: Cetus-style CLMM protocols, KriyaDEX, Turbos, Aftermath AMM, DeepBook, any Move module implementing constant-product or curve invariant swap pools, liquidity managers, position managers, flash swap providers on Sui

## Protocol Context

AMM and DEX protocols on Sui operate with shared pool objects accessible concurrently by multiple transactions in the same checkpoint. Unlike EVM where pool state is modified sequentially, Sui's parallel execution model means two transactions touching different pool objects can proceed simultaneously, but two transactions touching the same pool object are sequenced by the Sui runtime. Flash swaps on Sui are enabled by Sui's hot-potato pattern: a module borrows liquidity as a non-droppable non-storable receipt that must be returned (with repayment) before the transaction block ends. The Cetus exploit (2024) demonstrated that concentrated liquidity math with overflow in tick arithmetic can produce incorrect prices that drain the pool, highlighting the importance of Move integer safety in invariant computation.

## Bug Classes

---

### Missing Slippage Protection (ref: fv-mov-8-cl1)

**Protocol-Specific Preconditions**

- Swap function accepts `min_amount_out: 0` without rejection; caller can set zero slippage intentionally or by omission
- Protocol's Move SDK or TypeScript SDK defaults to zero slippage for simplicity; integrators copy the defaults without adjusting
- Automated keeper paths (liquidation, rebalancing, compound) call swap with hardcoded zero minimum

**Detection Heuristics**

- Find all `swap` and `swap_with_partner` entry functions; check whether `min_amount_out == 0` is rejected by an `assert!`
- Verify that slippage parameters are caller-supplied rather than computed from pool state at execution time
- Check protocol's automated compound or harvest entry points for hardcoded zero minimums
- Verify `assert!(amount_out >= min_amount_out, ERROR_SLIPPAGE_EXCEEDED)` is applied to the actual output after fees, not before

**False Positives**

- Zero slippage explicitly rejected: `assert!(min_amount_out > 0, ERROR_ZERO_SLIPPAGE)`
- Protocol's automated paths use an oracle-derived minimum with a configurable maximum deviation tolerance

---

### Pool Invariant Violation in CLMM Tick Arithmetic (ref: fv-mov-5-cl1)

**Protocol-Specific Preconditions**

- Concentrated liquidity math involves tick-indexed price computations using fixed-point arithmetic; overflow in tick boundary calculations can produce an incorrect `sqrt_price_x64` value
- Swap across tick boundaries accumulates rounding errors; multiple small swaps may produce a different state than one large swap, violating the invariant
- Tick spacing constraints not enforced consistently between position creation and liquidity addition

**Detection Heuristics**

- Review all arithmetic operations on `sqrt_price_x64` and tick values for integer overflow; Cetus exploit involved overflow in tick-to-sqrt-price conversion producing an exploitable price
- Verify that after a swap crossing one or more tick boundaries, the pool's effective price matches `token_b_reserve / token_a_reserve` at the current tick
- Check whether `u128::MAX` overflow is possible in any intermediate step of the invariant computation; Move's default arithmetic aborts on overflow in debug mode but may wrap in release
- Verify the invariant check is applied after multi-tick swaps, not only within a single tick range

**False Positives**

- All fixed-point arithmetic uses checked or saturating operations with explicit error codes on overflow
- Invariant verified after every swap operation with a tolerance for integer rounding

---

### Flash Swap Hot-Potato Escape (ref: fv-mov-3-cl1, fv-mov-8-cl3)

**Protocol-Specific Preconditions**

- Flash swap receipt (hot potato) can be destroyed via a public `destroy` function rather than only through the repayment path
- Repayment amount check uses the pool's current balance rather than the borrowed amount plus fee, allowing a re-donation to satisfy the check
- Flash swap receipt wrapped in another struct or stored in a dynamic field, bypassing Move's hot-potato linearity guarantee

**Detection Heuristics**

- Find the flash swap receipt struct definition; verify it has no `drop` ability; any struct with `drop` ability can be discarded without repayment
- Confirm the only function consuming (destroying) the receipt is the repayment function; no other function takes the receipt by value
- Verify the repayment check compares `pool.balance - initial_balance >= borrow_amount + fee`, not just `pool.balance >= threshold`
- Check whether the receipt can be stored in a `Table` or other persistent storage between PTB steps, enabling a deferred repayment that escapes the PTB boundary

**False Positives**

- Receipt struct has no `drop` or `store` ability; it can only be consumed by the pool's repayment function
- Repayment amount check is based on the borrowed amount stored in the receipt, not derived from pool balance

---

### Shared Object Concurrency in LP Operations

**Protocol-Specific Preconditions**

- Pool's shared object is read by two concurrent transactions: one adding liquidity and one swapping; if the liquidity addition modifies `total_supply` non-atomically, the concurrent swap may observe an intermediate state
- Sui's object-level locking serializes access to a single shared pool object, so true concurrent modification is not possible; however, sequenced transactions in the same checkpoint can still observe state from a prior transaction that has not yet been reflected in their local view

**Detection Heuristics**

- Verify that every modification to pool reserves, total supply, and fee accumulators occurs atomically within a single Move function call with no view reads between mutations
- Check whether LP token minting and pool reserve update occur in separate steps that could be interleaved by another transaction between checkpoints
- For multi-pool operations (cross-pool arbitrage, routing), verify each pool's state is read fresh at the start of each operation on that pool

**False Positives**

- All pool state modifications are atomic within a single transaction; Sui's object-level locking prevents interleaving within a single checkpoint
- Protocol uses owned objects for intermediate computation and only modifies the shared pool object once per transaction
