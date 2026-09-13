# FV-TON-6-CL2 Contract Deployment and StateInit

## TLDR

Child contracts deployed without StateInit are never created, causing messages to bounce or funds to be lost. Address computation using different code or data than the actual StateInit sends messages to the wrong address - which may be an attacker-controlled contract.

## Detection Heuristics

**Missing StateInit in deploy message**
- Message intended to deploy a child contract (Jetton wallet, sub-account) is missing the `state_init` flag bit or the StateInit cell in the message layout
- `store_uint(1, 1)` + StateInit cell absent from the `begin_cell()` message builder
- Init data cell does not match the format the child contract expects on first execution

**Address computation mismatch**
- `calculate_address()` uses different code or data than what is actually sent in the StateInit - the computed address and the deployed address differ
- `cell_hash(state_init)` not used as the address hash, or workchain ID prepended incorrectly
- Contract stores a "derived" address but derives it differently from how the child contract was actually deployed - `equal_slices` checks against this address never match

**Sending to uninitialized accounts**
- Message sent to an address that may not have a deployed contract, using a bounceable flag - message bounces if the account is uninitialized
- Operational (non-deploy) message sent to a calculated address before confirming the child is deployed

## False Positives

- Child contract deployment is one-time and the address is verified off-chain or via a getter before operational messages are sent - confirm the getter is called and the result validated
- StateInit computation matches what is documented in the protocol spec; verify by tracing `cell_hash` of the sent StateInit against the stored expected address
