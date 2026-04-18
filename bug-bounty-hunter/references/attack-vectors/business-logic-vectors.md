# Business Logic Attack Vectors

## State Machine
- Skip workflow state (pending → completed without approved)
- Replay completed transition
- Reverse completed action to recover assets
- Concurrent state transitions (two users advancing the same state)

## Limits & Caps
- Rate limit bypass (IP headers, parallel accounts)
- Allowance decrement race (TOCTOU)
- Max withdrawal split into sub-limit chunks
- KYC/tier step skip via direct API call

## Payments & Deposits
- Negative or zero amount accepted
- Price captured at order time, fulfilled at different price
- Coupon stacking beyond intended limits
- Refund + retain resource
- Token type mismatch in deposit/withdrawal

## Rewards & Incentives
- Self-referral across accounts
- Circular referral chain
- Double-claim via revert/reset
- Airdrop Sybil: multiple wallets, one entity

## Cross-Feature
- Deprecated endpoint bypasses new validation
- Webhook triggers privileged action when crafted
- Import/export bypasses create/update validation
- Feature A state consumed by Feature B without validation

## Identity & Account
- Account merge to combine limits
- Delete + re-register to reset flags
- Pending action hijack (token not bound to requesting account)
- Email case sensitivity: two accounts for same address
- Phone number recycling (carrier reassigns numbers)
