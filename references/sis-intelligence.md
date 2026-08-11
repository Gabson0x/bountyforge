# SIS-MD — Passive Security Intelligence Integration

Integrated from [SIS-MD Security Intelligence SkillMD](https://github.com/prize22/SIS-MD-Security-Intelligence-SkillMD-) by prize22. A portable, model-agnostic Markdown skill for passive security analysis.

## Core Principle

**Passive analysis only.** No exploit generation, no active scanning, no brute-forcing, no credential testing. This module is for pre-hunt intelligence gathering — understanding what a target exposes before sending any active probes.

## Three Intelligence Modules

### Module 1: Metadata Intelligence
Extract embedded metadata from files before hunting:

| Target | What to Extract | Risk Signal |
|--------|----------------|-------------|
| Documents (PDF, DOCX, ODT) | Author names, usernames, org name | Social engineering surface, org chart inference |
| Images (JPG, PNG, TIFF) | GPS coordinates, camera model, timestamps | Physical location exposure, device fingerprinting |
| Office files | Revision history, tracked changes, deleted content | Credential leaks in revision history, internal comments |
| Code files | File paths (`/Users/jdoe/...`), IDE metadata | Internal directory structure, developer usernames |
| Archives | Original paths, timestamps, compression metadata | Timeline reconstruction, internal naming conventions |

**Method:** Read what's embedded — never guess. If AI lacks raw EXIF/tool access, state the limitation and suggest `exiftool` or `mat2`.

### Module 2: Secret & Sensitive Data Detection
Pattern-match exposed secrets in code, configs, and responses:

| Category | Patterns | Severity |
|----------|----------|----------|
| Cloud credentials | AWS AKIA, GCP service account JSON, Azure connection strings | Critical |
| API keys/tokens | GitHub (`ghp_`, `gho_`), Stripe (`sk_live_`), Slack (`xoxb-`), generic `api_key=` | High |
| Private keys | PEM blocks (`-----BEGIN PRIVATE KEY-----`), `.pem`/`.pfx` contents | Critical |
| Hardcoded credentials | `password=`, `passwd=`, DB connection strings with embedded auth | High |
| Internal contact info | Internal emails, RFC 1918 IPs, `.internal`/`.corp` domains | Medium |
| Session artifacts | JWTs, session tokens, OAuth refresh tokens | Medium-High |

**Masking rule:** Never reprint a live-looking secret in full. Show first 4-6 chars + last 4, mask middle with `*`. The report itself must not become a leak vector.

**Boundary:** Flag pattern matches as "potentially live" — never validate by making network calls. Let the user verify and rotate.

### Module 3: Technology & Infrastructure Fingerprinting
Passively identify the target's stack from headers, HTML, and manifests:

| Source | What to Extract |
|--------|----------------|
| HTTP response headers | Server, X-Powered-By, Set-Cookie conventions, security header presence/absence |
| HTML source | Generator meta tags, framework build artifacts, developer comments |
| Package manifests | `package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, `Gemfile` |
| CDN/WAF indicators | Cloudflare, Akamai, Fastly, CloudFront header signatures |
| Error pages | Framework-specific error templates (Laravel, Django, Rails, Spring) |
| Cloud storage URLs | S3, Azure Blob, GCP Storage bucket URL patterns |

**Confidence tiers:**
- **High** — explicit version string in generator tag or manifest
- **Medium** — inferred from structural/path patterns
- **Low** — weak circumstantial signal (generic header conventions)

**Version risk language:** When outdated versions are found, note "This version is N major releases behind current" without fabricating CVE IDs. Direct users to NVD or vendor advisories.

---

## Integration with BountyForge

### When to Use SIS-MD Modules

**Before active hunting (recon phase):**
1. Run Metadata Intelligence on any documents/images provided by the target
2. Run Secret Detection on all JS bundles, config files, and error responses
3. Run Fingerprinting on all HTTP responses to build the technology stack map

**During hunting:**
- Re-run Secret Detection on every new JS bundle, source map, or config file discovered
- Update Fingerprinting when new services/endpoints are discovered

**Before reporting:**
- Verify no live secrets are printed in full in the report (Masking Rule)
- Confirm all findings are from passive observation or authorized active testing
- Cross-reference technology versions against known-vulnerable ranges

### Boundary Enforcement (from SIS-MD)

These boundaries are non-negotiable and apply to all BountyForge agents:

1. **Passive analysis only** — no exploitation, brute-forcing, or credential testing without explicit authorization
2. **Redact, don't repeat** — mask live secrets in all output
3. **Authorization is the user's responsibility** — decline clearly unauthorized third-party targets
4. **No speculative CVEs** — only general version-based risk notes
5. **Severity is evidence-based** — not alarmist, not inflated

---

## Source & Credits

- **Repository:** [prize22/SIS-MD-Security-Intelligence-SkillMD](https://github.com/prize22/SIS-MD-Security-Intelligence-SkillMD-)
- **Main skill:** `SIS.md` — portable, model-agnostic security intelligence processor
- **Modules:** `modules/metadata.md`, `modules/secrets.md`, `modules/fingerprinting.md`
- **Example:** `examples/sample-report.md` — full worked example of structured security intelligence output
