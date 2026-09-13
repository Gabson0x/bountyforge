# FV-MOV-5-CL4: Rounding Direction and Wrong Constants

## TLDR

Vault and share protocols must round against the user to prevent slow pool drain: deposits should issue fewer shares (round down), withdrawals should return fewer tokens (round up). First-depositor vault inflation exploits the absence of virtual shares. Hardcoded constants with wrong digit counts (MAX_U64, SECONDS_PER_DAY, precision) cause silent logic errors - Bluefin lost a Critical finding to a MAX_U64 with a missing digit.

## Detection Heuristics

- Trace deposit calculations: shares minted = `(deposit * total_shares) / total_assets` - verify this rounds DOWN (integer division in Move rounds down by default for unsigned; confirm no adjustments reverse this)
- Trace withdrawal calculations: tokens returned = `(shares * total_assets) / total_shares` - this should also round DOWN (fewer tokens to the user)
- Check the initial deposit (empty vault): if `total_shares == 0`, verify virtual shares or a minimum deposit prevents the first-depositor inflation attack
- For all constants, count digits: u64 max is 18446744073709551615 (20 digits); SECONDS_PER_DAY = 86400; SECONDS_PER_YEAR = 31536000; basis points = 10000
- Verify precision constants (1e6, 1e9, 1e12, 1e18) match the token decimals they represent

## False Positives

- Virtual shares / dead shares pattern correctly prevents first-depositor inflation
- Constants match the intended unit with documentation
- Round-trip test verified: `deposit(X) → withdraw(all) <= X`
