# FV-SOL-9-C7 Gas Griefing and 63/64 Rule

## TLDR

Two related gas-based DoS patterns: block stuffing fills blocks with high-gas-price transactions to prevent time-sensitive protocol operations from executing within their window; the 63/64 rule allows a relayer to forward insufficient gas so the inner call silently fails while the outer call marks the request as processed.

## Detection Heuristics

**Block Stuffing**
- Time-sensitive function with a short execution window (seconds to minutes)
- No economic incentive protection against block stuffing
- Protocol on PoS Ethereum where validators control slot timing

**63/64 Gas Forwarding**
- `target.call(data)` with no explicit gas parameter in a relayer or meta-transaction pattern
- Request or operation marked as completed regardless of subcall return value
- No `require(gasleft() >= minGas)` before the forwarded call
- Return value and returndata not validated; outer call does not revert on subcall failure

## False Positives

- Time window long enough that block stuffing is economically infeasible given gas costs
- `require(gasleft() >= minGas)` present before subcall
- Return value and returndata both validated; failure reverts the outer call
- EIP-2771 trusted forwarder with verified gas parameter in signed payload
