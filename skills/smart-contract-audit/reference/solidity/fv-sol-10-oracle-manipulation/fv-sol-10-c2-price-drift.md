# FV-SOL-10-C2 Price Drift

## TLDR

An oracle price that drifts gradually from reality causes cumulative accounting errors that compound over time. Because no reference price is stored and no deviation band is enforced, each incremental update silently accepts a slightly-wrong value, allowing long-term exploitation through slowly accumulated pricing error.

## Detection Heuristics

**Stateless Price Validation**
- `totalValue` multiplied by oracle price each call with no stored reference price to detect gradual drift
- No `lastValidPrice` or equivalent state variable tracking the previously accepted price
- Price accepted as valid on the sole condition `price > 0` - any non-zero value passes

**Unchecked Incremental Price Updates**
- Percentage-band check (e.g., `price <= lastValidPrice * 105/100 && price >= lastValidPrice * 95/100`) absent between consecutive oracle reads
- Function callable by anyone with no access control, allowing rapid successive calls to compound drift
- No minimum update interval enforced, permitting an attacker to iterate the drift in a single transaction through repeated calls

## False Positives

- `lastValidPrice` stored and compared against the current price with a tight percentage band before each update is accepted
- Price feed is a long-window TWAP that inherently smooths gradual moves and makes single-block drift economically infeasible
- Protocol enforces a minimum update interval (e.g., per-block or per-hour) that prevents rapid successive calls from compounding drift
