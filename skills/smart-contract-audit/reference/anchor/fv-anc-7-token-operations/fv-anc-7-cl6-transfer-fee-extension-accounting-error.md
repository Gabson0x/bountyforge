# FV-ANC-7-CL6 Transfer Fee Extension Accounting Error

## TLDR

Token-2022 transfer fee extensions deduct a fee from transferred amounts at the SPL level. Programs that send X tokens and expect X tokens to arrive at the destination will undercount the actual received amount. This causes shortfalls in vault deposits, incorrect share issuance, fee revenue discrepancies, and protocol invariant violations when the actual received balance differs from what was recorded.

## Detection Heuristics

**Sent Amount Used Instead of Received Amount**
- Vault deposit logic records the sent amount as the deposited value rather than reading the destination account's post-transfer balance
- Share issuance computed from `amount` parameter rather than `post_transfer_balance - pre_transfer_balance`
- No pre- and post-transfer balance snapshot on the destination account to determine the actual received amount

**Fee Not Pre-Computed Before Protocol Logic**
- `calculate_fee(amount, fee_bps, max_fee)` not called before determining how much to record as received
- Fee calculation skipped entirely; program assumes transfers are fee-free for all accepted mints
- Protocol accepts arbitrary mints including those with `TransferFeeConfig` but applies no fee compensation in accounting

**Cumulative Shortfall Under Repeated Operations**
- Under repeated deposits with fee-bearing mints, the vault progressively owes more tokens than it holds, eventually becoming insolvent
- Fee withheld amount accumulates in the token account's withheld field without the protocol accounting for it as a liability

## False Positives

- Mint's `TransferFeeConfig` extension has `transfer_fee_basis_points` set to 0 and `maximum_fee` of 0, making actual fees zero
- Protocol explicitly calls `calculate_fee` and subtracts the result before recording received amounts
- Protocol rejects mints with a non-zero transfer fee at initialization by checking the `TransferFeeConfig` extension
