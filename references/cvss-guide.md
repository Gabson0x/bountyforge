# CVSS 3.1 Scoring Guide

Use this guide to compute the CVSS 3.1 vector string and base score for each finding.

## Vector Format

`CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}`

---

## Metric Definitions

### Attack Vector (AV)
| Value | Code | When to use |
|-------|------|-------------|
| Network | N | Exploitable remotely over the internet / blockchain |
| Adjacent | A | Requires access to the same network segment |
| Local | L | Requires local access to the machine |
| Physical | P | Requires physical access |

**Default for most web/smart contract findings: N**

### Attack Complexity (AC)
| Value | Code | When to use |
|-------|------|-------------|
| Low | L | No special conditions; attack succeeds reliably |
| High | H | Requires specific configuration, race condition, or difficult-to-control state |

**If the attack needs a race window, specific token type, or flash loan: consider H**

### Privileges Required (PR)
| Value | Code | When to use |
|-------|------|-------------|
| None | N | No auth required |
| Low | L | Normal user account |
| High | H | Admin / privileged role required |

### User Interaction (UI)
| Value | Code | When to use |
|-------|------|-------------|
| None | N | No victim interaction needed |
| Required | R | Victim must click a link, approve a tx, etc. |

### Scope (S)
| Value | Code | When to use |
|-------|------|-------------|
| Unchanged | U | Impact stays within the vulnerable component |
| Changed | C | Impact extends beyond (e.g., compromised server affects other users, bridge affects other chains) |

**Cross-chain attacks, XSS, and SSRF to internal networks often qualify for C**

### Confidentiality (C)
| Value | Code | Description |
|-------|------|-------------|
| None | N | No confidentiality impact |
| Low | L | Limited info disclosure |
| High | H | Full disclosure of sensitive data |

### Integrity (I)
| Value | Code | Description |
|-------|------|-------------|
| None | N | No integrity impact |
| Low | L | Some data can be modified |
| High | H | Complete loss of integrity / funds drained |

### Availability (A)
| Value | Code | Description |
|-------|------|-------------|
| None | N | No availability impact |
| Low | L | Reduced performance, partial DoS |
| High | H | Complete DoS, contract bricked |

---

## Common Patterns

| Finding Type | Typical Vector | Score Range |
|---|---|---|
| Flash loan + fund drain | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` | 7.5 |
| Single attester compromise (bridge) | `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` | 9.1 |
| Upgrade bypass (no timelock) | `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` | 9.1 |
| Reentrancy fund drain | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` | 7.5 |
| Signature replay | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` | 7.5 |
| IDOR (non-financial) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 |
| IDOR (financial/ATO) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | 8.1 |
| Stored XSS (admin panel) | `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` | 8.7 |
| GraphQL introspection | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 |
| DoS (unbounded loop) | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | 7.5 |
| Race condition (web) | `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N` | 6.3 |
| Subdomain takeover | `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N` | 6.1 |
| Missing zero-address check | `AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H` | 5.8 |
| Unprotected initializer | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 |

---

## Scoring Instructions

1. Select each metric value from the definitions above.
2. Construct the vector string: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
3. Compute the base score using the CVSS 3.1 formula (or reference the common patterns table for well-known attack types).
4. In the report, show: vector string, numerical score, and a one-line justification for each metric selection.

**Example:**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0
AV:N — exploitable from the internet via any RPC node
AC:L — no race condition or special state required
PR:N — no authentication required, any address can call
UI:N — no victim interaction
S:C — compromise of the bridge affects all destination chains
C:H / I:H / A:H — attacker can drain all bridged assets and brick the contract
```
