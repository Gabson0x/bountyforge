# FV-SOL-6-C9 ERC721 Unsafe Transfer to Non-Receiver Contract

## TLDR

`ERC721._transfer()` and the low-level `transferFrom()` do not check whether the recipient contract implements `IERC721Receiver`. Sending an NFT to a contract that lacks the receiver interface permanently locks the token - it can never be recovered.

`safeTransferFrom()` and `_safeMint()` trigger `onERC721Received()` on the recipient and revert if the return value is not the expected selector. Using the unsafe variants on user-supplied or unknown recipient addresses silently locks tokens.

## Detection Heuristics

- `_mint(to, tokenId)` or `_transfer(from, to, tokenId)` called directly where `to` is user-supplied
- `nft.transferFrom(from, to, id)` in marketplace/escrow/settlement logic without `to.code.length` check
- Custom token contract overrides `_transfer` and calls base `_transfer` without safe receiver check
- `nft.transferFrom` used because `safeTransferFrom` was "too expensive" (common comment in code)

## False Positives

- All mint/transfer paths use `_safeMint`/`safeTransferFrom` exclusively
- Recipient is always an EOA (enforced: `require(to.code.length == 0)`)
- Function is `nonReentrant` AND a prior check confirms recipient implements the interface
- Protocol explicitly limits recipients to whitelisted contracts verified to implement `IERC721Receiver`
