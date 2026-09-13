# FV-TON-1-CL3 Deserialization and end_parse

## TLDR

Omitting `end_parse()` after deserializing a message or storage slice silently ignores trailing bytes, masking injected extra data, storage corruption, or format version mismatches.

## Detection Heuristics

**Missing end_parse after message body read**
- `in_msg_body~load_uint(32)` (opcode), followed by field reads, with no final `in_msg_body.end_parse()` or `in_msg_body~end_parse()`
- Handler returns or continues after all expected fields are read without verifying the slice is empty

**Missing end_parse after storage load**
- `get_data().begin_parse()` sequence that loads all fields but does not end with `end_parse()`
- Storage loaded into a slice variable reused across multiple handlers, each reading some fields - last handler does not verify exhaustion

**Bit/ref layout mismatch**
- `store_uint(x, N)` on the sending side but `load_uint(M)` where `M ≠ N` on the receiving side
- References stored in a different order than they are loaded, causing field-shift bugs
- Optional fields (present/absent conditionally) handled inconsistently between writer and reader

## False Positives

- `end_parse()` absent but the slice is provably empty after all reads due to a fixed-length format with no variable-length fields - confirm this holds for all code paths, including future versions
- Forward payload slices intentionally passed through to another contract unmodified, where the downstream contract performs its own validation
