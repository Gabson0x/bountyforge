# FV-ANC-5-CL4 Passing Unnecessary Accounts to CPIs

## TLDR

Including accounts in a CPI that the callee does not need expands the trust surface. A malicious callee can read data from, or attempt privileged operations on, any account passed to it. Each unnecessary account increases the blast radius if the callee is compromised or malicious.

## Detection Heuristics

**Accounts Not Required by Callee Instruction Included**
- `AccountInfo` for accounts not listed in the callee's expected account structure included in the CPI accounts array
- Entire `ctx.accounts` struct forwarded to a CPI helper rather than selecting only the required accounts

**Writable Accounts Passed When Only Readable**
- Accounts that the callee only needs to read passed with `is_writable = true`, granting unnecessary write authority
- High-value accounts (vaults, admin configs) included as writable in CPIs where only their key is needed for verification

**Signer Accounts Forwarded Unnecessarily**
- Accounts with `is_signer = true` included in a CPI when the callee does not require them to sign, unnecessarily extending signer privileges

## False Positives

- All included accounts are required by the callee's instruction as documented in the callee program's interface
- CPI uses Anchor's typed context structs which only include the fields defined in the callee's `Accounts` struct
