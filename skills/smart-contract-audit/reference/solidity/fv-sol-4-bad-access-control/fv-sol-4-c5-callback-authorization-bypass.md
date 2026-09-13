# FV-SOL-4-C5 Callback Authorization Bypass

## TLDR

External callback functions (`onFlashLoan`, `onERC721Received`, `onERC1155Received`) are invoked by third-party contracts. If the callback does not verify `msg.sender` is the expected caller, anyone can invoke it directly with fabricated parameters, bypassing intended access control. ERC4626 `withdraw`/`redeem` has a related variant: when `msg.sender != owner`, allowance must be checked and decremented or any address can burn an arbitrary owner's shares.

## Detection Heuristics

**Flash Loan Callback**
- `onFlashLoan` does not verify `msg.sender == address(lendingPool)`
- Initiator, token, or amount parameters unchecked - callable directly without a real flash loan
- State changes or fund transfers triggered solely by caller-supplied parameters

**ERC721 onERC721Received Spoofing**
- `onERC721Received` uses `from` or `tokenId` to update state without checking `msg.sender == address(expectedNFT)`
- Any caller can invoke directly with fabricated parameters to trigger unintended state changes

**ERC1155 Burn Without Authorization**
- Public `burn(address from, ...)` callable by anyone without `msg.sender == from` or operator approval check
- Any caller can burn another user's tokens

**ERC4626 Missing Allowance Check**
- `withdraw(assets, receiver, owner)` or `redeem(shares, receiver, owner)` where `msg.sender != owner` but no `_spendAllowance` call present

**ERC1155 setApprovalForAll Over-Permission**
- Protocol requires `setApprovalForAll(protocol, true)` for deposits - operator can transfer any token ID at full balance, not just the deposited amount

## False Positives

- `require(msg.sender == address(lendingPool))` and `initiator == address(this)` both validated in flash loan callback
- `require(msg.sender == address(nft))` present before state update in `onERC721Received`
- `require(from == msg.sender || isApprovedForAll(from, msg.sender))` in custom burn
- OZ `ERC4626` used without custom overrides (allowance check is built in)
- Protocol uses direct `safeTransferFrom` with user as `msg.sender` (no `setApprovalForAll` needed)
