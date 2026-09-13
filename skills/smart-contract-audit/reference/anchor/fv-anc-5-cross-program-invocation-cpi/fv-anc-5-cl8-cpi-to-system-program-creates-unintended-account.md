# FV-ANC-5-CL8 CPI to System Program Creates Unintended Account

## TLDR

A CPI to the system program's `create_account` or `assign` instruction with attacker-influenced parameters can create or reassign accounts at addresses that hold special protocol meaning. If the target address is a protocol PDA, config account, or authority record, the CPI can overwrite or initialize it with attacker-controlled owner and data, compromising the protocol's trust model.

## Detection Heuristics

**Unconstrained create_account Target**
- `system_program::create_account` called with a target address derived from user-supplied instruction data or account keys not validated against a known expected address
- Space, lamports, or owner parameters in the create_account call sourced from caller-controlled values rather than protocol constants
- No assertion that the account being created does not already hold protocol state before the CPI

**Assign Without Ownership Verification**
- `system_program::assign` CPI called with an owner program derived from input rather than a hardcoded constant
- Reassignment target not verified to be a freshly initialized zero-data account
- No check that the account's lamport balance matches the rent-exempt minimum for the declared space

**Protocol PDA Overwrite**
- Target address of the create_account CPI could match a protocol PDA that is initialized later; attacker pre-creates the account with the wrong owner before legitimate initialization
- Program does not check for a pre-existing discriminator or non-zero data before calling create_account on a PDA it intends to use

## False Positives

- Account creation targets are deterministic PDAs owned by the calling program; the program derives and validates the address before the CPI
- All system program CPI parameters are hardcoded or derived from validated on-chain constants, not user input
