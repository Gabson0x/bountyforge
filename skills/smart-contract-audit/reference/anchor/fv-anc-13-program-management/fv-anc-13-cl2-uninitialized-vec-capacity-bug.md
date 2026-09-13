# FV-ANC-13-CL2 Uninitialized Vec Capacity Bug

## TLDR

Creating a `Vec` with `Vec::with_capacity(n)` allocates space for n elements but leaves the length at 0. Accessing elements of a capacity-allocated but not length-populated Vec via index operators will produce an out-of-bounds panic. If an initialization instruction fails to push actual elements and a subsequent instruction assumes the Vec is populated, state will be incorrect or instructions will panic.

## Detection Heuristics

**with_capacity Without Corresponding Pushes**
- `Vec::with_capacity(n)` called during account initialization or instruction processing without a corresponding loop that pushes n default elements
- Account state field is a Vec; after initialization its length is 0 but the protocol's subsequent logic reads from it by index assuming length == capacity

**Default Initialization Confusion**
- Account struct derives `Default` for a Vec field; `Default::default()` for Vec is an empty Vec with zero length; code that assumes the Vec contains pre-allocated slots will panic on first access
- `account.items[0]` accessed after initialization without checking `items.len() > 0`

**Serialization Length Mismatch**
- Account size allocated for n elements (via `space = 8 + n * ELEMENT_SIZE`) but Vec serialized with length prefix of 0; deserialized length is 0 and index access panics
- Realloc extends account space but Vec's length field is not updated to match the new capacity

## False Positives

- Vec capacity allocation is immediately followed by a fill loop or `.extend(iter)` that populates all capacity slots before the account is used
- Protocol never accesses Vec by index; all access is via iteration over the Vec's actual elements, which correctly handles a zero-length Vec
