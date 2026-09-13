# FV-ANC-8-CL4 Durable Nonce Transaction Ordering Attack

## TLDR

Durable nonce transactions replace the `recent_blockhash` field with a nonce value that does not expire with slots, allowing a signed transaction to be submitted at any future time. Protocols that rely on transaction recency for security (signed price updates, authority transfers, time-bounded operations) are vulnerable when those operations can be submitted via a durable nonce transaction long after the signing context has changed.

## Detection Heuristics

**No Expiry Check Independent of Blockhash**
- Protocol accepts signed instructions or price updates without checking a timestamp from the `Clock` sysvar that must fall within a validity window
- Authority-modifying instructions carry no expiry field in their instruction data, relying only on the implicit blockhash expiry that durable nonces bypass
- Signed operations (e.g., signed delegate approvals, signed configurations) do not include a slot or Unix timestamp that the on-chain program validates against the current clock

**Durable Nonce Account Present Without Single-Use Enforcement**
- Transaction includes a nonce account and a `AdvanceNonce` instruction but the nonce authority is not invalidated or rotated after use
- Protocol does not treat transactions with a recognized nonce account as requiring additional expiry validation
- Signed off-chain messages that authorize on-chain state changes do not embed an expiry timestamp verified at execution time

**Retroactively Favorable Execution**
- Attacker holds a signed transaction that was unfavorable at signing time; conditions change (price movement, governance vote, authority change) and the transaction becomes profitable; submits it after the change
- Liquidation or settlement operations signed with durable nonces can be withheld and executed when market conditions are most advantageous to the submitter

## False Positives

- Protocol validates instruction timestamps independently of transaction blockhash using the `Clock` sysvar with an explicit validity window (e.g., `require!(clock.unix_timestamp - signed_at < MAX_VALIDITY_SECONDS)`)
- Nonce authority is a single-use keypair that is destroyed or transferred after the single authorized transaction
