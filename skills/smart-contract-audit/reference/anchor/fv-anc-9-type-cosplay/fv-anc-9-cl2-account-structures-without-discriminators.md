# FV-ANC-9-CL2 Account Structures Without Discriminators

## TLDR

Account structs defined without Anchor's `#[account]` attribute do not receive an automatic 8-byte discriminator. This means all instances of such structs look identical at the byte level regardless of their intended type, enabling type substitution attacks across any instruction that accepts them.

## Detection Heuristics

**Structs Used as Accounts Without #[account] Attribute**
- `pub struct MyState { ... }` used as an on-chain account type without `#[account]` attribute, meaning no discriminator is prepended
- Struct deserialized directly via `borsh::BorshDeserialize` derive without discriminator bytes in the layout

**Manual Discriminator Without Enforcement**
- Struct includes a `discriminator: [u8; 8]` field but no instruction checks this field against a known constant before using the account
- `DISCRIMINATOR` constant defined but not compared during account validation

**Multiple Account Types With Identical Initial Fields**
- Two or more account structs share the same first field types (e.g., `authority: Pubkey` as the first field), making them indistinguishable without a discriminator when the owner program is the same

**Deserializer Does Not Reject Wrong Discriminator**
- Custom `try_deserialize` implementation does not check the discriminator, allowing any account data to deserialize successfully as any type

## False Positives

- Structs used only as instruction data (not on-chain accounts) and never deserialized from account data; discriminators are not relevant for instruction parameters
- Program uses a single account type and type confusion between types is structurally impossible
