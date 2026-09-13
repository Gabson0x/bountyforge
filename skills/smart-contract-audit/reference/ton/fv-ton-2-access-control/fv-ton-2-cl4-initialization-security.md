# FV-TON-2-CL4 Initialization Security

## TLDR

Contracts whose initialization function is callable by anyone, or re-callable after first deployment, can have their entire state overwritten - including the admin address - by an attacker who sends the init opcode.

## Detection Heuristics

**Initialization callable by anyone**
- Handler for the initialization opcode does not verify `sender_address` is the deployer or a factory contract
- No check that the message includes the original StateInit (which would tie deployment to initialization)
- Init data (admin address, configuration) accepted from the message body without any authorization gate

**Re-initialization possible**
- No `is_initialized` boolean flag in storage - contract does not record that initialization already occurred
- Second call to the init handler overwrites `admin_address`, `total_supply`, or critical configuration with attacker-supplied values
- `set_data()` in the init handler executable any number of times

**State accessible through standard opcodes post-deployment**
- Contract does not separate initialization from normal operation opcodes - a crafted message with the init opcode triggers re-initialization during live operation

## False Positives

- Contract uses a factory pattern where only the factory can deploy and the factory address is hardcoded or derived via a hash - confirm the factory itself enforces one-time initialization
- Re-initialization intentionally allowed but gated behind admin authorization and limited to non-critical parameters
