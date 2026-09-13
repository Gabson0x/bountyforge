# FV-MOV-8-CL2: Table and Collection Bugs

## TLDR

`table::add` aborts on duplicate keys - missing existence checks cause DoS when a user interacts a second time. Move vectors are limited to ~1000 entries - unbounded vectors DoS when full. Both create permanent denial-of-service.

## Detection Heuristics

- Search for every `table::add` and `dynamic_field::add` call - verify a preceding `table::contains` / `dynamic_field::exists_` check
- Safe pattern: `if (table::contains(&t, key)) { table::remove(&t, key); }; table::add(&mut t, key, value)` for upsert semantics
- For user registration, staking position tracking, or whitelist patterns: check whether the same user can trigger an add twice (e.g., via two deposits before first is settled)
- Identify all `vector<T>` used for unbounded user data (registrations, positions, orders) - these should be `sui::table_vec::TableVec<T>` or `sui::table::Table` instead
- Verify loops over vectors in public functions have a bounded count - loops over growing unbounded vectors eventually exceed gas limits and become permanently uncallable

## False Positives

- `table::contains` check present before every `table::add`
- `TableVec` or `Table` used instead of plain `vector` for unbounded user data
- Vector size explicitly capped with `assert!(vector::length(&v) < MAX_SIZE)` before push
