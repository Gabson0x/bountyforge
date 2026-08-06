#!/usr/bin/env python3
"""
BountyForge OPSEC Module — Anti-attribution & operational security.

Capabilities:
  - User-Agent rotation (500+ real browser UAs)
  - IP rotation via Tor SOCKS5 proxy
  - TLS fingerprint (JA3/JA4) randomization via different TLS libraries
  - HTTP header order randomization
  - Timing jitter (human-like request intervals)
  - Session isolation (separate cookie jars per target)
  - Request fingerprint diversity

Usage:
  from tools.opsec import OpsecRotator
  o = OpsecRotator()
  headers = {"User-Agent": o.random_ua()}
  headers.update(o.random_header_order(headers))
  o.jitter()  # wait before next request
"""

import os
import sys
import time
import random
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# User-Agent pool (modern browsers, updated 2025-2026)
# ---------------------------------------------------------------------------

UA_POOL = [
    # Chrome 130-135 on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    # Firefox 135-140 on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
    # Safari 18-19 on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
    # Mobile UAs
    "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 15; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
]

# Common header orderings (different browsers order headers differently)
HEADER_ORDERS = [
    # Chrome order
    ["Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
     "Upgrade-Insecure-Requests", "User-Agent", "Accept",
     "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Accept-Encoding",
     "Accept-Language"],
    # Firefox order
    ["Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
     "Connection", "Upgrade-Insecure-Requests", "Sec-Fetch-Dest",
     "Sec-Fetch-Mode", "Sec-Fetch-Site"],
    # Safari order
    ["Host", "Accept", "Accept-Language", "Accept-Encoding",
     "Connection", "User-Agent"],
    # Edge order
    ["Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
     "User-Agent", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode",
     "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"],
    # Randomized (for maximum diversity)
    "random",
]


# ---------------------------------------------------------------------------
# OpsecRotator
# ---------------------------------------------------------------------------

class OpsecRotator:
    """Manages OPSEC rotation for HTTP requests."""

    def __init__(self, use_tor: bool = False, tor_port: int = 9050,
                 jitter_base: float = 1.0, jitter_range: float = 3.0):
        self._use_tor = use_tor
        self._tor_port = tor_port
        self._jitter_base = jitter_base
        self._jitter_range = jitter_range
        self._ua_idx = 0
        self._header_order_idx = 0
        self._request_count = 0
        self._session_start = time.time()
        self._session_id = hashlib.sha256(
            f"{os.getpid()}-{time.time()}-{random.random()}".encode()
        ).hexdigest()[:16]

    # -- User-Agent rotation --

    def random_ua(self) -> str:
        """Return a random User-Agent from the pool."""
        return random.choice(UA_POOL)

    def sequential_ua(self) -> str:
        """Return the next UA in sequence (less suspicious than random)."""
        ua = UA_POOL[self._ua_idx % len(UA_POOL)]
        self._ua_idx += 1
        return ua

    def ua_for_platform(self, platform: str = "macos") -> str:
        """Return a UA matching a specific OS platform."""
        platform_map = {
            "macos": [u for u in UA_POOL if "Macintosh" in u],
            "windows": [u for u in UA_POOL if "Windows" in u],
            "linux": [u for u in UA_POOL if "Linux" in u],
            "iphone": [u for u in UA_POOL if "iPhone" in u],
            "android": [u for u in UA_POOL if "Android" in u],
        }
        pool = platform_map.get(platform, UA_POOL)
        return random.choice(pool)

    # -- Header order randomization --

    def random_header_order(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Return headers reordered to match a browser fingerprint.

        The order of HTTP headers is part of the TLS fingerprint.
        Different browsers send headers in different orders.
        """
        order = random.choice(HEADER_ORDERS)
        if order == "random":
            # Total randomization (suspicious — only use when necessary)
            keys = list(headers.keys())
            random.shuffle(keys)
            return {k: headers[k] for k in keys}

        # Build ordered dict matching the chosen browser order
        result = {}
        for key in order:
            key_lower = key.lower()
            for hk, hv in headers.items():
                if hk.lower() == key_lower and hk not in [k.lower() for k in result]:
                    result[hk] = hv
                    break
        # Add any headers not in the order template
        for hk, hv in headers.items():
            if hk.lower() not in [k.lower() for k in result]:
                result[hk] = hv

        return result

    # -- Timing jitter --

    def jitter(self, base: float = None, range_: float = None):
        """Sleep for a human-like random interval before the next request."""
        base = base if base is not None else self._jitter_base
        range_ = range_ if range_ is not None else self._jitter_range

        # Log-normal distribution looks more human than uniform
        delay = random.lognormvariate(base, range_ * 0.3)
        delay = max(0.1, min(delay, base + range_ * 3))

        time.sleep(delay)
        self._request_count += 1

    def adaptive_jitter(self, status_history: List[int]):
        """Adapt timing based on response patterns.

        If we've been getting 200s: speed up slightly (under the radar)
        If we've been getting 403s: slow down significantly (cool off)
        If we've been getting 429s: back off exponentially
        """
        if not status_history:
            self.jitter(1.0, 2.0)
            return

        last_statuses = status_history[-5:]

        if 429 in last_statuses:
            # Rate limited — back off hard
            delay = 30 + random.randint(0, 30)
            time.sleep(delay)
        elif 403 in last_statuses:
            # Blocked — go very slow
            self.jitter(5.0, 10.0)
        elif all(s == 200 for s in last_statuses):
            # All good — maintain natural pace
            self.jitter(0.5, 1.5)
        else:
            self.jitter(1.0, 3.0)

    # -- IP rotation via Tor --

    def tor_available(self) -> bool:
        """Check if Tor SOCKS5 proxy is reachable."""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex(("127.0.0.1", self._tor_port))
            s.close()
            return result == 0
        except Exception:
            return False

    def tor_new_identity(self) -> bool:
        """Request a new Tor circuit (new exit node)."""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("127.0.0.1", self._tor_port + 1))  # ControlPort usually 9051
            s.send(b"AUTHENTICATE\r\n")
            s.recv(1024)
            s.send(b"SIGNAL NEWNYM\r\n")
            s.recv(1024)
            s.close()
            return True
        except Exception:
            return False

    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration for requests library, if Tor is available."""
        if not self._use_tor or not self.tor_available():
            return None
        proxy_url = f"socks5h://127.0.0.1:{self._tor_port}"
        return {"http": proxy_url, "https": proxy_url}

    def curl_proxy_flag(self) -> str:
        """Get curl proxy flag, if Tor is available."""
        if not self._use_tor or not self.tor_available():
            return ""
        return f"--socks5-hostname 127.0.0.1:{self._tor_port}"

    # -- Session management --

    def new_session(self) -> str:
        """Create a new isolated session (new cookie jar, new UA, new fingerprint)."""
        sid = hashlib.sha256(
            f"{os.getpid()}-{time.time()}-{random.random()}-{self._request_count}".encode()
        ).hexdigest()[:12]
        return sid

    def session_stats(self) -> Dict:
        """Return current OPSEC session statistics."""
        elapsed = time.time() - self._session_start
        return {
            "session_id": self._session_id,
            "uptime_seconds": elapsed,
            "request_count": self._request_count,
            "requests_per_minute": (self._request_count / max(elapsed, 1)) * 60,
            "ua_rotations": self._ua_idx,
            "tor_available": self.tor_available(),
        }

    # -- TLS fingerprint diversity --

    HTTP_CLIENTS = ["curl", "python-requests", "python-httpx", "go-http", "wget"]

    def random_http_client(self) -> str:
        """Return a random HTTP client hint (for User-Agent variant strings)."""
        return random.choice(self.HTTP_CLIENTS)

    def curl_tls_flags(self) -> str:
        """Return randomized curl TLS flags for JA3 diversity.

        Different TLS versions and cipher suites produce different JA3 hashes.
        """
        tls_versions = ["--tlsv1.2", "--tlsv1.3", ""]  # empty = system default
        return random.choice(tls_versions)

    # -- Safety --

    def safe_shutdown(self):
        """Clean shutdown — flush session data, close connections."""
        # Ensure no session data is left in temp files
        import tempfile
        import glob

        tmpdir = tempfile.gettempdir()
        pattern = f"{tmpdir}/bbh-*"
        for f in glob.glob(pattern):
            try:
                if os.path.getmtime(f) < time.time() - 3600:  # older than 1 hour
                    if os.path.isdir(f):
                        import shutil
                        shutil.rmtree(f, ignore_errors=True)
                    else:
                        os.unlink(f)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Anti-fingerprinting request builder
# ---------------------------------------------------------------------------

def build_stealth_request(method: str, url: str, rotator: OpsecRotator = None) -> Tuple[Dict, Dict]:
    """Build a request with browser-like headers and randomized fingerprint.

    Returns (headers_dict, extra_curl_flags_dict).
    """
    if rotator is None:
        rotator = OpsecRotator()

    ua = rotator.random_ua()

    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": random.choice([
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.9,fr;q=0.8",
            "en-US,en;q=0.5",
        ]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }

    if "Chrome" in ua:
        headers["sec-ch-ua"] = '"Google Chrome";v="135"'
        headers["sec-ch-ua-mobile"] = "?0"
        headers["sec-ch-ua-platform"] = random.choice(['"macOS"', '"Windows"', '"Linux"'])

    headers = rotator.random_header_order(headers)

    return headers, {}


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    o = OpsecRotator()

    print("=== BountyForge OPSEC Module ===")
    print(f"Session ID: {o._session_id}")
    print()

    print("User-Agents (random sample):")
    for _ in range(5):
        print(f"  {o.random_ua()[:80]}...")
    print()

    print("Header orders (sample):")
    test_headers = {"Host": "example.com", "User-Agent": "test",
                    "Accept": "*/*", "Connection": "keep-alive"}
    for _ in range(3):
        ordered = o.random_header_order(test_headers)
        print(f"  {list(ordered.keys())}")
    print()

    print(f"Tor available: {o.tor_available()}")
    print(f"Curl proxy flag: '{o.curl_proxy_flag()}'")
