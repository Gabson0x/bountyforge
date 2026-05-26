# Deepseek & Local Tool Setup

This reference file is included in BountyForge bundles so the skill can use Deepseek CLI setup and local tooling guidance, not just display it in the README.

## Deepseek Claude CLI setup (Mac/Linux)

Set these environment variables in your project shell or project file before starting Claude Code:

```bash
export ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic
export ANTHROPIC_MODEL=deepseek-v4-pro
export ANTHROPIC_DEFAULT_OPUS_MODEL=deepseek-v4-pro
export ANTHROPIC_DEFAULT_SONNET_MODEL=deepseek-v4-pro
export ANTHROPIC_DEFAULT_HAIKU_MODEL=deepseek-v4-flash
export CLAUDE_CODE_SUBAGENT_MODEL=deepseek-v4-flash
export CLAUDE_CODE_EFFORT_LEVEL=max
export ANTHROPIC_AUTH_TOKEN="your-deepseek-pro-token"
```

Then export the Deepseek project binding temporarily inside your repo:

```bash
deepseek export --project . --key "$ANTHROPIC_AUTH_TOKEN" --mode pro
```

If you want this to be project-local, add the same export block to a shell startup file inside the repo, such as `.env`, `project.env`, or your custom Claude project file.

## Deepseek setup (Windows PowerShell)

For Windows PowerShell, apply the variables to the current session and export the project:

```powershell
$env:ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"
$env:ANTHROPIC_MODEL = "deepseek-v4-pro"
$env:ANTHROPIC_DEFAULT_OPUS_MODEL = "deepseek-v4-pro"
$env:ANTHROPIC_DEFAULT_SONNET_MODEL = "deepseek-v4-pro"
$env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "deepseek-v4-flash"
$env:CLAUDE_CODE_SUBAGENT_MODEL = "deepseek-v4-flash"
$env:CLAUDE_CODE_EFFORT_LEVEL = "max"
$env:ANTHROPIC_AUTH_TOKEN = "your-deepseek-pro-token"

deepseek export --project . --key $env:ANTHROPIC_AUTH_TOKEN --mode pro
```

For persistence, add the same variables to your PowerShell profile.

## Local CLI tooling support

When Claude Code execution is enabled, BountyForge can orchestrate and call available local tools directly.

Recommended tools:

- `nmap`
- `ffuf`
- `amass`
- `sqlmap`
- `gobuster`
- `curl`
- `httpx`
- `wfuzz`
- `zap`
- `burpsuite`

Enable local execution and make sure the tools are on `PATH` so the skill can run discovery, fuzzing, payload generation, and verification steps.

## Coverage and payload strategy

BountyForge is designed to search for a broad range of web and API vulnerabilities with unlimited payload variation, including:

- open redirect
- CSV injection
- SQL injection
- XSS
- SSRF
- command injection
- template injection
- path traversal
- deserialization
- prototype pollution
- IDOR
- CSRF
- response splitting
- session fixation
- business logic abuse

The skill uses this reference setup to reason about environment configuration and local tooling availability while building reports.
