# FV-MOV-4-CL3: PTB Atomic Price Manipulation

## TLDR

Sui PTBs allow up to 1024 operations in one atomic transaction. An attacker can compose: (1) borrow via flash loan, (2) manipulate an on-chain price oracle or pool reserve ratio, (3) call the vulnerable function at the manipulated price, (4) repay the flash loan - all within a single transaction. This is the Sui-native equivalent of the flash loan attack vector.

## Detection Heuristics

- Identify all price or valuation sources - are they derived from on-chain pool reserve ratios or spot prices? Those are manipulable within a single PTB
- Check whether any critical operation (collateral valuation, swap execution, liquidation trigger) reads price from the same pool that could be atomically manipulated in the same transaction
- Verify that borrow-then-use-same-pool-price paths exist - if so, TWAP or external oracle is required
- Look for missing `min_amount_out` slippage protection - no user-supplied minimum enables sandwich attacks
- Check for `deadline_ms` parameter on all swap and liquidity operations

## False Positives

- All price feeds use TWAP or external oracle (Pyth, Switchboard) that cannot be manipulated within a single transaction
- Slippage protection from user calldata (`min_amount_out`) present on all swap functions
- Deviation check between oracle price and pool price blocks manipulation
