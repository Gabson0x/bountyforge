# FV-TON-7-CL1 Jetton Wallet Validation

## TLDR

Accepting Jetton deposits without verifying the sender is the legitimate wallet (derived from the minter's StateInit) lets attackers send fake `transfer_notification` messages to credit themselves with tokens they never transferred.

## Detection Heuristics

**transfer_notification without wallet address check**
- Handler credits balance based on `amount` in the notification body without verifying `sender_address == expected_jetton_wallet_address`
- `jetton_wallet_address` is not stored during initialization or not retrieved from storage before the check
- Check present but uses `from_user` (a body field the attacker controls) instead of `sender_address` (the actual message sender)

**Wallet address not recomputed**
- Contract does not implement or call `calculate_user_jetton_wallet_address(owner, jetton_minter)` to derive the expected wallet address from the StateInit hash
- Wallet addresses accepted as parameters from user messages without on-chain derivation

**internal_transfer sender not validated**
- Jetton wallet's `internal_transfer` handler does not verify the sender is either the minter or another wallet of the same minter - any contract can call and inflate balances

## False Positives

- Contract is the Jetton minter itself and receives `burn_notification` (not `transfer_notification`) - confirm the opcode being handled
- Jetton wallet address was validated at the contract level via a factory deployment and is stored immutably - confirm the stored address is derived correctly and cannot be updated without authorization
