# FV-TON-7-CL3 NFT Ownership and Index

## TLDR

NFT item ownership can be overwritten by unauthorized parties if the transfer handler lacks a current-owner check, and the collection index can be manipulated to mint duplicate items or overwrite existing ones if `next_item_index` is not atomically incremented.

## Detection Heuristics

**Ownership transfer without current owner check**
- NFT item's transfer handler does not verify `equal_slices(sender_address, owner_address)` before updating ownership
- Any contract can send a transfer message and become the new owner
- No check that the sender is either the owner or an approved operator

**Index manipulation**
- Minting function accepts a user-supplied index instead of using `next_item_index` - allows minting at arbitrary indices, including existing ones
- `next_item_index` incremented after the mint message is sent rather than before - race condition allows two minters to claim the same index
- No `throw_unless(error::invalid_index, index == next_item_index)` when an index is provided

**Metadata URI manipulation**
- NFT metadata URI can be changed by unauthorized parties - buyers purchase based on displayed metadata that is later swapped
- No admin check on metadata update handler

**TEP-62 non-compliance**
- Standard getters (`get_nft_data`, `get_collection_data`) absent or returning non-standard formats
- Transfer message format deviates from TEP-62 - breaks marketplace integrations

## False Positives

- Index is admin-controlled for a curated collection where the admin manually assigns indices, but minting is restricted to admin only and index reuse is prevented by explicit check
