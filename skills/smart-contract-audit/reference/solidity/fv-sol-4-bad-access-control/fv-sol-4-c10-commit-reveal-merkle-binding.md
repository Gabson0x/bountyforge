# FV-SOL-4-C10 Commit-Reveal and Merkle Proof Binding

## TLDR

Cryptographic access control schemes fail when the protected value is not bound to `msg.sender`. A commitment hash that omits the sender can be front-run or replayed from a different address. A Merkle leaf that omits the sender is claimable by anyone who observes the proof on-chain. Single-hashed leaves are additionally vulnerable to second-preimage attacks where a 64-byte intermediate node is passed as a leaf.

## Detection Heuristics

**Commit-Reveal Not Bound to Sender**
- `keccak256(abi.encodePacked(value, salt))` without `msg.sender` included in the hash
- Commitment stored in a public mapping - visible on-chain once committed, allowing front-running
- Reveal function does not validate `msg.sender` against the address that originally committed

**Merkle Second Preimage**
- `keccak256(abi.encodePacked(input))` where `input` is user-supplied bytes with no length constraint
- A 64-byte user input can masquerade as two sibling hashes and pass as a valid intermediate node
- Leaf constructed as a single hash: `bytes32 leaf = keccak256(abi.encodePacked(addr, amount))`
- OZ `MerkleProof` version below v4.9.2 used without manual double-hashing

**Merkle Proof Reuse and Front-Running**
- Leaf does not include `msg.sender`: `keccak256(abi.encodePacked(amount))` or `keccak256(abi.encodePacked(tokenId))`
- Proof not recorded as consumed after first use - replayable across multiple transactions
- Public whitelist where proof is visible on-chain before the intended user claims

## False Positives

- Commitment includes sender: `keccak256(abi.encodePacked(msg.sender, value, salt))`
- Reveal function validates that the stored committer address equals `msg.sender`
- Merkle leaf double-hashed: `keccak256(bytes.concat(keccak256(abi.encode(...))))`
- OZ `MerkleProof` v4.9.2 or later used with sorted-pair leaf validation
- Proof recorded as spent (`hasClaimed[leaf] = true`) before payout is executed
