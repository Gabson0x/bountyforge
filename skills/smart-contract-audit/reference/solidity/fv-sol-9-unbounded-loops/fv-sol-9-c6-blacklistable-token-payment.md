# FV-SOL-9-C6 Blacklistable Token in Payment Path

## TLDR

Push-model payment loops that transfer tokens to recipient addresses will revert entirely if any recipient is blacklisted by the token contract (USDC, USDT, and other compliant stablecoins support blacklisting). A single blacklisted address in a liquidation path, fee distribution loop, or withdrawal route can permanently brick that operation.

## Detection Heuristics

**Push Transfer to Untrusted Address With Blacklistable Token**
- `IERC20(token).transfer(recipient, amount)` or `safeTransfer` inside a loop where the token is USDC, USDT, or any contract exposing a `blacklist`, `blocklist`, or `isBlacklisted` function
- Token address is a constructor or governance parameter, not a hardcoded non-blacklistable token
- No `try/catch` or skip-on-failure logic around the individual transfer call

**Blocking Liquidation or Settlement Path**
- Liquidation function iterates over collateral recipients or debt holders and pushes token payments in the loop body
- A single revert from one recipient causes the entire liquidation to fail and revert
- Protocol provides no alternative to complete the operation without the blocked recipient

**Missing Pull-Pattern or Fallback**
- No `pendingClaims` or equivalent mapping allowing recipients to withdraw independently
- No mechanism to remove or skip a recipient that has caused prior reverts
- Fee distribution, reward claiming, or airdrop uses a single-transaction push loop with no recovery path

## False Positives

- Pull-over-push pattern: recipients withdraw own funds independently
- `try/catch` wraps individual transfers and continues on failure
- Token whitelist explicitly excludes blacklistable tokens
