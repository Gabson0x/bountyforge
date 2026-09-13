# FV-SOL-10-C1 Incorrect Compounding Mechanism

## TLDR

Oracle price is used as a direct multiplier in interest or yield compounding logic without validation. An attacker who can influence the oracle can inflate or deflate the calculated interest in a single call, permanently distorting the cumulative value.

## Detection Heuristics

**Oracle-Dependent Compounding**
- `oracle.getPrice()` return value multiplied directly into an interest or yield calculation with no prior sanity check
- No `require(price > 0)` guard before the price is used in compounding arithmetic
- No `lastPrice` or equivalent state variable stored to compare against the current reading
- No maximum change check between consecutive price reads (e.g., `currentPrice <= lastPrice * 2 && currentPrice >= lastPrice / 2`)

**Missing Time-Weighted or Rate-Limited Input**
- Compounding function callable by anyone with no access control, allowing repeated calls to amplify manipulation
- No TWAP or time-weighted mechanism smoothing price inputs into the compounding calculation
- Interest rate itself derived from or scaled by an oracle value with no independent governance-set cap

## False Positives

- Compounding uses a hardcoded or governance-set interest rate with no oracle input to the rate itself; oracle is used only for display or accounting in a separate path
- Price is validated as non-zero and within a configured deviation band from `lastPrice` before compounding proceeds
- Oracle is a manipulation-resistant source (e.g., Chainlink with full validity suite) and the compounding function enforces per-block or per-period rate limits
