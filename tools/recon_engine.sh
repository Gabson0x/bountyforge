#!/usr/bin/env bash
#
# BountyForge Recon Engine v3.0.0
# Full pipeline: subdomains → resolve → live hosts → URLs → JS → secrets
#
# Usage:
#   ./tools/recon_engine.sh example.com
#   ./tools/recon_engine.sh example.com --fast        (skip slow steps)
#   ./tools/recon_engine.sh example.com --deep        (include port scanning, brute force)
#
# Output: recon/<target>/{subs.txt,resolved.txt,live-hosts.txt,urls.txt,jsfiles.txt,nuclei.txt,secrets.txt}

set -euo pipefail

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target-domain> [--fast|--deep]"
  exit 1
fi

MODE="${2:---normal}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RECON_DIR="${ROOT}/recon/${TARGET}"
mkdir -p "${RECON_DIR}"

TMPDIR="${TMPDIR:-/tmp}"
TMP="$(mktemp -d "${TMPDIR}/recon-XXXXXX")"
trap "rm -rf ${TMP}" EXIT

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ---------------------------------------------------------------------------
# Phase 1: Subdomain enumeration
# ---------------------------------------------------------------------------
log "Phase 1/7: Subdomain enumeration for *.${TARGET}"

# Subfinder
if command -v subfinder &>/dev/null; then
  subfinder -d "${TARGET}" -silent -all 2>/dev/null > "${TMP}/subfinder.txt" || true
  log "  subfinder: $(wc -l < "${TMP}/subfinder.txt") found"
fi

# Assetfinder
if command -v assetfinder &>/dev/null; then
  assetfinder --subs-only "${TARGET}" 2>/dev/null > "${TMP}/assetfinder.txt" || true
  log "  assetfinder: $(wc -l < "${TMP}/assetfinder.txt") found"
fi

# crt.sh (certificate transparency)
curl -sk "https://crt.sh/?q=%.${TARGET}&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | \
  sed 's/\*\.//g' | tr ',' '\n' | sort -u > "${TMP}/crtsh.txt" || true
log "  crt.sh: $(wc -l < "${TMP}/crtsh.txt") found"

# Chaos API (if key configured)
if [ -n "${CHAOS_API_KEY:-}" ]; then
  curl -sk "https://dns.projectdiscovery.io/dns/${TARGET}/subdomains" \
    -H "Authorization: ${CHAOS_API_KEY}" 2>/dev/null | \
    jq -r '.subdomains[]' 2>/dev/null | \
    sed "s/$/.${TARGET}/" > "${TMP}/chaos.txt" || true
  log "  chaos: $(wc -l < "${TMP}/chaos.txt") found"
fi

# Merge and deduplicate
cat "${TMP}"/subfinder.txt "${TMP}"/assetfinder.txt "${TMP}"/crtsh.txt "${TMP}"/chaos.txt 2>/dev/null | \
  grep -i "${TARGET}" | sort -u > "${RECON_DIR}/subs.txt"
log "  Total unique subdomains: $(wc -l < "${RECON_DIR}/subs.txt")"

# ---------------------------------------------------------------------------
# Phase 2: DNS resolution
# ---------------------------------------------------------------------------
log "Phase 2/7: DNS resolution"

if command -v dnsx &>/dev/null; then
  cat "${RECON_DIR}/subs.txt" | dnsx -silent -a -cname -resp-only -json > "${RECON_DIR}/dnsx.json" 2>/dev/null || true
  # Extract resolved IPs/hosts
  jq -r '.host + " [" + .a[0] + "]"' "${RECON_DIR}/dnsx.json" 2>/dev/null | sort -u > "${TMP}/resolved.txt" || true
  # Also extract CNAMEs for takeover checking
  jq -r 'select(.cname != null) | "\(.host) CNAME \(.cname[0])"' "${RECON_DIR}/dnsx.json" 2>/dev/null > "${RECON_DIR}/cnames.txt" || true
else
  # Fallback: use host/dig
  while read -r sub; do
    host "$sub" 2>/dev/null | grep "has address" | awk '{print $1" ["$NF"]"}' >> "${TMP}/resolved.txt" || true
  done < "${RECON_DIR}/subs.txt"
fi

grep -v '^$' "${TMP}/resolved.txt" | sort -u > "${RECON_DIR}/resolved.txt" || touch "${RECON_DIR}/resolved.txt"
log "  Resolved: $(wc -l < "${RECON_DIR}/resolved.txt") hosts"

# ---------------------------------------------------------------------------
# Phase 3: Live host discovery
# ---------------------------------------------------------------------------
log "Phase 3/7: Live host probing"

# Extract just the hostnames for httpx
awk '{print $1}' "${RECON_DIR}/resolved.txt" > "${TMP}/hosts-only.txt"

if command -v httpx &>/dev/null; then
  cat "${TMP}/hosts-only.txt" | httpx -silent -status-code -title -tech-detect -json \
    -o "${RECON_DIR}/httpx.json" 2>/dev/null || true

  # Extract live URLs
  jq -r 'select(.status_code != null) | "\(.url) [\(.status_code)] \(.title // "N/A")"' \
    "${RECON_DIR}/httpx.json" 2>/dev/null > "${RECON_DIR}/live-hosts.txt" || true
else
  # Fallback: curl each host
  while read -r host; do
    for proto in https http; do
      status=$(curl -sko /dev/null -w "%{http_code}" --max-time 5 "${proto}://${host}" 2>/dev/null || echo "000")
      if [ "$status" != "000" ]; then
        echo "${proto}://${host} [${status}]" >> "${RECON_DIR}/live-hosts.txt"
      fi
    done
  done < "${TMP}/hosts-only.txt"
fi

log "  Live hosts: $(wc -l < "${RECON_DIR}/live-hosts.txt")"

# ---------------------------------------------------------------------------
# Phase 4: URL collection
# ---------------------------------------------------------------------------
log "Phase 4/7: URL crawling"

# Extract just the base URLs
awk '{print $1}' "${RECON_DIR}/live-hosts.txt" > "${TMP}/live-urls.txt"

# Katana
if command -v katana &>/dev/null && [ "$MODE" != "--fast" ]; then
  cat "${TMP}/live-urls.txt" | katana -d 3 -silent -jc -kf all 2>/dev/null > "${TMP}/katana.txt" || true
  log "  katana: $(wc -l < "${TMP}/katana.txt") URLs"
fi

# Waybackurls
if command -v waybackurls &>/dev/null; then
  echo "${TARGET}" | waybackurls 2>/dev/null > "${TMP}/wayback.txt" || true
  log "  waybackurls: $(wc -l < "${TMP}/wayback.txt") URLs"
fi

# gau
if command -v gau &>/dev/null; then
  gau "${TARGET}" 2>/dev/null > "${TMP}/gau.txt" || true
  log "  gau: $(wc -l < "${TMP}/gau.txt") URLs"
fi

# Merge
cat "${TMP}"/katana.txt "${TMP}"/wayback.txt "${TMP}"/gau.txt 2>/dev/null | \
  grep -i "${TARGET}" | sort -u > "${RECON_DIR}/urls.txt"
log "  Total unique URLs: $(wc -l < "${RECON_DIR}/urls.txt")"

# ---------------------------------------------------------------------------
# Phase 5: JavaScript extraction
# ---------------------------------------------------------------------------
log "Phase 5/7: JavaScript file extraction"

grep '\.js' "${RECON_DIR}/urls.txt" | grep -v '\.json' | sort -u > "${RECON_DIR}/jsfiles.txt"
log "  JS files: $(wc -l < "${RECON_DIR}/jsfiles.txt")"

# Download JS files for analysis
if [ "$MODE" == "--deep" ]; then
  mkdir -p "${RECON_DIR}/js/"
  while read -r jsurl; do
    fname=$(echo "$jsurl" | sha256sum | cut -c1-16)
    curl -sk --max-time 10 "$jsurl" -o "${RECON_DIR}/js/${fname}.js" 2>/dev/null || true
  done < "${RECON_DIR}/jsfiles.txt"
  log "  Downloaded JS files to ${RECON_DIR}/js/"
fi

# ---------------------------------------------------------------------------
# Phase 6: Vulnerability scanning
# ---------------------------------------------------------------------------
log "Phase 6/7: Nuclei scanning"

if command -v nuclei &>/dev/null && [ "$MODE" != "--fast" ]; then
  nuclei -l "${TMP}/live-urls.txt" -severity critical,high,medium \
    -silent -stats -stats-interval 30 \
    -o "${RECON_DIR}/nuclei.txt" 2>/dev/null || true
  log "  Nuclei findings: $(wc -l < "${RECON_DIR}/nuclei.txt")"
else
  echo "# Nuclei scan skipped (not installed or --fast mode)" > "${RECON_DIR}/nuclei.txt"
fi

# ---------------------------------------------------------------------------
# Phase 7: Secret scanning
# ---------------------------------------------------------------------------
log "Phase 7/7: Secret scanning in JS files"

if command -v trufflehog &>/dev/null && [ "$MODE" != "--fast" ] && [ -d "${RECON_DIR}/js/" ]; then
  trufflehog filesystem "${RECON_DIR}/js/" --json --no-update 2>/dev/null > "${RECON_DIR}/secrets.json" || true
  log "  Secrets found: $(wc -l < "${RECON_DIR}/secrets.json")"
elif [ -f "${RECON_DIR}/urls.txt" ]; then
  # Quick grep for common secret patterns
  {
    grep -oE 'ghp_[A-Za-z0-9_]{36}' "${RECON_DIR}/urls.txt" 2>/dev/null || true
    grep -oE 'AKIA[0-9A-Z]{16}' "${RECON_DIR}/urls.txt" 2>/dev/null || true
    grep -oE 'sk_live_[0-9a-zA-Z]{24,}' "${RECON_DIR}/urls.txt" 2>/dev/null || true
    grep -oE 'hooks\.slack\.com/services/[A-Za-z0-9/]+' "${RECON_DIR}/urls.txt" 2>/dev/null || true
  } | sort -u > "${RECON_DIR}/secrets-quick.txt"
  log "  Quick secret scan: $(wc -l < "${RECON_DIR}/secrets-quick.txt") potential matches"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=============================================="
echo " BountyForge Recon Complete"
echo "=============================================="
echo " Target:         ${TARGET}"
echo " Subs:           $(wc -l < "${RECON_DIR}/subs.txt")"
echo " Resolved:       $(wc -l < "${RECON_DIR}/resolved.txt")"
echo " Live hosts:     $(wc -l < "${RECON_DIR}/live-hosts.txt")"
echo " URLs:           $(wc -l < "${RECON_DIR}/urls.txt")"
echo " JS files:       $(wc -l < "${RECON_DIR}/jsfiles.txt")"
echo " Output:         ${RECON_DIR}/"
echo "=============================================="

# Generate surface ranking if state module exists
if python3 -c "from tools.state import load_state" 2>/dev/null; then
  python3 -c "
from tools.state import load_state, save_state
s = load_state('${TARGET}')
s.endpoints_tested = 0
s.findings_count = 0
save_state('${TARGET}', s)
print('[+] State initialized for ${TARGET}')
" 2>/dev/null || true
fi
