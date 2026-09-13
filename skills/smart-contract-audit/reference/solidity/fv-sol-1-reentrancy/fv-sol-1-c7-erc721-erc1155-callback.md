# FV-SOL-1-C7 ERC721 / ERC1155 Callback Reentrancy

## TLDR

`safeTransferFrom`, `safeMint`, and batch ERC1155 transfers invoke receiver callbacks (`onERC721Received`, `onERC1155Received`, `onERC1155BatchReceived`) before the calling contract has finished updating state. This enables reentrancy through the callback.

A related variant affects custom batch mint/transfer loops that update `_balances` per-ID and call `onERC1155Received` per iteration: callbacks execute while balances for later IDs in the loop are still uncredited, allowing reads of stale state.

A second variant causes `totalSupply` inflation: if `totalSupply[id]` is incremented after `_mint` fires the callback, the supply is stale-low during the callback, inflating share calculations.

## Detection Heuristics

**ERC721/ERC1155 Callback Reentrancy**
- `safeTransferFrom` or `safeMint` called before state updates
- Callback hooks (`onERC721Received` / `onERC1155Received`) enable reentry into the protocol
- `ownerOf[tokenId]` or equivalent ownership mapping deleted or updated after `safeTransferFrom` rather than before
- `withdraw`, `redeem`, or `claim` functions that send an NFT to `msg.sender` as their last step

**ERC1155 Batch Partial-State Window**
- Custom batch mint/transfer updates `_balances` and calls `onERC1155Received` per ID in a loop
- Callback reads stale balances for uncredited IDs in later loop iterations
- `for` loop over token IDs where each iteration fires a callback before the next ID's balance is set

**ERC1155 totalSupply Inflation**
- `totalSupply[id]` incremented after `_mint` callback fires
- During `onERC1155Received`, supply is stale-low - inflates share in any supply-dependent formula
- Affected: OZ ERC1155Supply before version 4.3.2 (CVE GHSA-9c22-pwxw-p6hx)

## False Positives

- All state committed before safe transfer (CEI followed)
- `nonReentrant` applied to all entry points that trigger callbacks
- OZ >= 4.3.2 used without custom `_mint` override
- No supply-dependent logic callable from mint callback
