# FV-SOL-4-C6 Arbitrary External Call

## TLDR

When a contract executes `target.call{value: v}(data)` where `target` or `data` are caller-supplied, an attacker can craft parameters to invoke unintended functions on any target contract. Common impact includes draining ERC20 allowances the contract holds, invoking `transferFrom` on behalf of the contract, or calling governance or upgrade functions on contracts that trust the calling contract as an authorized party.

## Detection Heuristics

**Caller-Controlled Target or Calldata**
- `target.call{value: v}(data)` where `target` or `data` (or both) arrive as function parameters from `msg.sender`
- No whitelist check on `target` before the call is executed
- Selector filtering absent, bypassable, or only applied to `data[0:4]` without validating the full calldata layout

**Token Allowance Drain**
- Contract holds ERC20 `approve` allowances or NFT custody - attacker crafts calldata to call `transferFrom` or `safeTransferFrom` on the token contract with the vulnerable contract as `from`
- Contract previously called `token.approve(address(this), type(uint256).max)` and exposes a generic call executor

**Privilege Escalation via Trusted Caller**
- Target contract grants special permissions to the calling contract's address - arbitrary call lets attacker invoke those privileged functions through the trusted intermediary

## False Positives

- Target restricted to a hardcoded address or a governance-approved whitelist
- Function selector restricted to a known-safe enumerated set before execution
- Contract holds no token approvals and no asset custody, removing economic impact
- Only `delegatecall` variant present - covered separately in fv-sol-7, not this class
