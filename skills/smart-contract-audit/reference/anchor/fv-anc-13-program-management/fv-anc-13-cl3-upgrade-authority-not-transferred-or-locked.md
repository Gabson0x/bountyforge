# FV-ANC-13-CL3 Upgrade Authority Not Transferred or Locked

## TLDR

Anchor programs deployed with a live upgrade authority can be modified by the authority holder at any time without on-chain governance or timelock. If the upgrade authority is a single keypair rather than a multisig or locked to None, a key compromise or insider action can replace the program binary, potentially draining all protocol funds or backdooring authentication logic.

## Detection Heuristics

**Single-Keypair Upgrade Authority**
- Program data account's upgrade authority is a single wallet address rather than a Squads multisig, governance program, or `None`
- No timelock between upgrade proposal and execution; an upgrade can be applied in a single transaction from the authority holder
- Protocol documentation does not mention the upgrade authority setup or its security model

**Upgrade Authority Not Revoked After Final Audit**
- Program intended to be immutable has not had its upgrade authority set to `None` post-audit
- `solana program set-upgrade-authority <program_id> --final` never executed; upgrade authority remains at initial deployer address
- Protocol's trust model claims immutability in documentation but on-chain state shows a live authority

**No Governance Gate**
- Upgrade authority is a DAO or governance program but upgrade proposals have no minimum voting period or quorum requirement, making it trivially executeable by a whale voter
- Emergency upgrade path bypasses the normal governance delay, creating a fast-track mechanism that could be abused

## False Positives

- Upgrade authority is explicitly set to `None` on-chain; program is immutable and cannot be upgraded
- Upgrade authority is a Squads multisig with a documented threshold and all signers are independent parties; upgrade path has a timelock of at least 48 hours
