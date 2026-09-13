# FV-SOL-6-C11 CREATE / CREATE2 Deployment Silent Failure

## TLDR

Assembly `create(v, offset, size)` and `create2(v, offset, size, salt)` return `address(0)` on failure - insufficient ETH balance, address collision, or init code revert. Unlike the high-level `new Contract()` syntax, these opcodes do not revert automatically on failure.

If the code does not check for the zero return value, `address(0)` is stored or used in subsequent logic. Calls to `address(0)` succeed as no-ops (no deployed code) or interact with precompiles, silently corrupting state.

## Detection Heuristics

- `create(...)` or `create2(...)` in assembly without `if iszero(addr) { revert(0,0) }` immediately after
- Returned address stored in mapping/array or used in an interface call without zero check
- Factory pattern: result passed directly to `IContract(addr).initialize(...)` 
- `create2` with user-supplied salt where collision is possible (salt not bound to `msg.sender`)
- No Solidity-level `require(addr != address(0))` after the assembly block

## False Positives

- `if iszero(addr) { revert(0, 0) }` immediately after create/create2 in assembly
- High-level `new Contract{salt: s}(args)` syntax (reverts automatically on failure)
- Address validated with `require(addr != address(0))` after the assembly block before any use
- Salt collision impossible by construction (salt = `keccak256(abi.encodePacked(msg.sender, nonce))`)
