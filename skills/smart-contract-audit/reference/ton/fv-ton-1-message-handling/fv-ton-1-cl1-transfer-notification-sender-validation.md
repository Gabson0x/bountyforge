# FV-TON-1-CL1 Transfer Notification Sender Validation

## TLDR

`transfer_notification` (op `0x7362d09c`) handlers that do not verify `sender_address` against the stored Jetton wallet address allow attackers to fake token deposits by sending a crafted message from any contract.

## Detection Heuristics

**Missing sender check in notification handler**
- `recv_internal` branches on `op::transfer_notification` without `throw_unless(error::wrong_jetton_wallet, equal_slices(sender_address, jetton_wallet_address))`
- Handler reads `from_user` or `amount` from the notification body and credits balances without verifying who sent the message
- `jetton_wallet_address` never stored in contract data, making validation impossible

**Trusting payload body instead of sender identity**
- Code extracts a `depositor` or `from_user` field from the payload and uses it as proof of depositor - this field is attacker-controlled
- No call to `calculate_user_jetton_wallet_address()` to derive and compare the expected wallet address

**Multi-Jetton contracts with per-token wallet storage**
- Contract supports several Jetton types but only validates sender for some of them
- Wallet address stored for initialization but not re-checked on every notification

## False Positives

- Contract deliberately accepts notifications from any sender as a relay or aggregator with no balance-crediting logic
- Sender check present but uses a local helper function that wraps `equal_slices` - follow the call chain before concluding the check is absent
