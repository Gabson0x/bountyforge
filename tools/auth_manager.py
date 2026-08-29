#!/usr/bin/env python3
"""
BountyForge Auth Manager — Automated authentication for bug bounty testing.

Capabilities:
  - Create temporary email via Guerrilla Mail API
  - Auto-detect registration forms (tries common paths + field patterns)
  - Auto-register accounts with generated credentials
  - Wait for and extract verification links from emails
  - Auto-login and return authenticated session (cookies + tokens)
  - Multi-account creation for cross-user testing (IDOR, privilege escalation)

Usage:
  python3 tools/auth_manager.py --target example.com
  python3 tools/auth_manager.py --target example.com --create-two-users

Credentials are saved to state directory for reuse across sessions.
"""

import asyncio
import hashlib
import json
import os
import re
import secrets
import string
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from tools.http_pool import HTTPPool, HTTPResult
    HAS_HTTP = True
except ImportError:
    HAS_HTTP = False
    HTTPPool = None  # type: ignore
    HTTPResult = None  # type: ignore


# ── Data structures ────────────────────────────────────────

@dataclass
class AuthSession:
    """An authenticated session ready for vulnerability testing."""
    email: str
    password: str
    cookies: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)  # bearer, csrf, api_key, etc.
    headers: Dict[str, str] = field(default_factory=dict)
    logged_in: bool = False
    user_id: str = ""
    username: str = ""
    session_id: str = ""  # Internal reference, never the raw token

    def __post_init__(self):
        if not self.session_id:
            raw = f"{self.email}|{int(time.time())}"
            self.session_id = hashlib.sha256(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict:
        return {
            "email": self.email,
            "password": self.password,
            "cookies": self.cookies,
            "tokens": self.tokens,
            "headers": self.headers,
            "logged_in": self.logged_in,
            "user_id": self.user_id,
            "username": self.username,
            "session_id": self.session_id,
        }

    def get_cookie_string(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def get_auth_headers(self) -> Dict[str, str]:
        """Return headers for authenticated requests."""
        h = dict(self.headers)
        if self.tokens.get("bearer"):
            h["Authorization"] = f"Bearer {self.tokens['bearer']}"
        if self.tokens.get("csrf"):
            h["X-CSRF-Token"] = self.tokens["csrf"]
        return h


# ── AuthManager ────────────────────────────────────────────

class AuthManager:
    """
    Automated authentication manager.

    Creates temp email accounts, registers on target applications,
    verifies emails, and returns authenticated sessions for testing.
    """

    # Common registration endpoints to try
    SIGNUP_PATHS = [
        "/register", "/signup", "/auth/register", "/auth/signup",
        "/api/register", "/api/v1/register", "/api/auth/register",
        "/users/register", "/user/register", "/create-account",
        "/join", "/get-started", "/sign-up", "/new-account",
        "/api/auth/signup", "/api/v1/auth/register",
    ]

    # Common login endpoints
    LOGIN_PATHS = [
        "/login", "/signin", "/auth/login", "/auth/signin",
        "/api/login", "/api/v1/login", "/api/auth/login",
        "/users/login", "/user/login", "/sign-in",
    ]

    # Common field names for registration forms
    EMAIL_FIELDS = ["email", "mail", "e-mail", "email_address", "username"]
    PASSWORD_FIELDS = ["password", "pass", "pwd", "passwd", "secret"]
    NAME_FIELDS = ["name", "full_name", "fullname", "display_name", "first_name"]
    CSRF_FIELDS = ["csrf_token", "csrf", "_csrf", "_token", "authenticity_token",
                    "xsrf_token", "__RequestVerificationToken"]

    def __init__(self, http_pool: HTTPPool, state_dir: str = None):
        self.http_pool = http_pool
        self.state_dir = state_dir or os.path.join(
            os.environ.get("BF_STATE_DIR", str(ROOT / "state")), "auth"
        )
        self.guerrilla_sid: Optional[str] = None
        self.guerrilla_email: Optional[str] = None
        os.makedirs(self.state_dir, exist_ok=True)

    # ── Temp Email (Guerrilla Mail) ────────────────────────

    async def create_temp_email(self) -> str:
        """
        Create a disposable email address via Guerrilla Mail.

        Returns the email address string.
        """
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                # Get email address
                params = {
                    "f": "get_email_address",
                    "ip": "127.0.0.1",
                    "agent": "bountyforge_auth",
                }
                async with session.get(
                    "https://api.guerrillamail.com/ajax.php",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    data = await resp.json()

                if data.get("email_addr"):
                    self.guerrilla_email = data["email_addr"]
                    self.guerrilla_sid = data.get("sid_token", "")
                    print(f"[auth] Temp email created: {self.guerrilla_email}")
                    return self.guerrilla_email

                raise RuntimeError(f"Guerrilla Mail API error: {data}")

        except Exception as e:
            # Fallback: generate a random email on a public disposable domain
            fallback_user = secrets.token_hex(8)
            fallback_domain = secrets.choice([
                "mailinator.com", "guerrillamail.com", "sharklasers.com",
                "yopmail.com", "temp-mail.org",
            ])
            fallback = f"{fallback_user}@{fallback_domain}"
            print(f"[auth] Guerrilla Mail failed ({e}), using fallback: {fallback}")
            self.guerrilla_email = fallback
            return fallback

    async def wait_for_email(self, timeout: int = 60, poll_interval: float = 3.0) -> Optional[Dict]:
        """
        Poll Guerrilla Mail inbox until a new email arrives.
        Returns the email dict with mail_id, mail_from, mail_subject, mail_body, etc.
        """
        if not self.guerrilla_sid:
            print("[auth] No Guerrilla Mail session — cannot poll inbox")
            return None

        start = time.monotonic()
        seen_ids = set()

        try:
            import aiohttp
        except ImportError:
            return None

        async with aiohttp.ClientSession() as session:
            while (time.monotonic() - start) < timeout:
                try:
                    params = {
                        "f": "check_email",
                        "seq": "0",
                        "sid_token": self.guerrilla_sid,
                    }
                    async with session.get(
                        "https://api.guerrillamail.com/ajax.php",
                        params=params,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        data = await resp.json()

                    emails = data.get("list", [])
                    for email in emails:
                        mail_id = email.get("mail_id", "")
                        if mail_id and mail_id not in seen_ids:
                            seen_ids.add(mail_id)
                            # Fetch full email content
                            params2 = {
                                "f": "fetch_email",
                                "email_id": mail_id,
                                "sid_token": self.guerrilla_sid,
                            }
                            async with session.get(
                                "https://api.guerrillamail.com/ajax.php",
                                params=params2,
                                timeout=aiohttp.ClientTimeout(total=10),
                            ) as resp2:
                                full_email = await resp2.json()

                            print(f"[auth] Email received: {email.get('mail_subject', 'No subject')}")
                            return {
                                "mail_id": mail_id,
                                "from": email.get("mail_from", ""),
                                "subject": email.get("mail_subject", ""),
                                "body": full_email.get("mail_body", ""),
                                "timestamp": email.get("mail_timestamp", 0),
                            }

                except Exception as e:
                    print(f"[auth] Poll error: {e}")

                await asyncio.sleep(poll_interval)

        print(f"[auth] Timeout waiting for email ({timeout}s)")
        return None

    # ── Registration ───────────────────────────────────────

    async def register(
        self,
        target: str,
        email: str = None,
        password: str = None,
        signup_url: str = None,
        extra_fields: Dict[str, str] = None,
        name: str = None,
    ) -> Optional[AuthSession]:
        """
        Auto-detect registration form, fill in fields, submit.

        Tries common signup paths with common field patterns.
        Falls back gracefully if no registration form is found.
        """
        email = email or self.guerrilla_email or await self.create_temp_email()
        password = password or self._generate_password()
        name = name or f"Test{secrets.token_hex(4)[:8]}"

        base_url = target if target.startswith("http") else f"https://{target}"

        # Try to discover the signup endpoint
        discovered_url = signup_url
        if not discovered_url:
            discovered_url = await self._discover_endpoint(base_url, self.SIGNUP_PATHS)

        if not discovered_url:
            print(f"[auth] No registration endpoint found on {target}")
            return AuthSession(email=email, password=password, logged_in=False)

        # Get the registration page (for CSRF token extraction)
        get_result = await self.http_pool.request("GET", discovered_url)
        csrf_token = self._extract_csrf(get_result)

        # Build registration payload
        payload = self._build_registration_payload(
            get_result.body, email, password, name, extra_fields
        )
        if csrf_token:
            payload["csrf_token"] = csrf_token

        # Determine content type
        content_type = self._detect_content_type(get_result)

        # Send registration
        headers = {
            "Content-Type": content_type,
            "Accept": "application/json, text/html, */*",
            "Origin": base_url,
            "Referer": discovered_url,
        }
        if csrf_token:
            headers["X-CSRF-Token"] = csrf_token

        if content_type == "application/json":
            reg_result = await self.http_pool.request(
                "POST", discovered_url, headers=headers, json_data=payload
            )
        else:
            reg_result = await self.http_pool.request(
                "POST", discovered_url, headers=headers, data=self._encode_form(payload)
            )

        # Check if registration succeeded
        if reg_result.status in (200, 201, 302, 303):
            print(f"[auth] Registration successful — {email}")
        elif reg_result.status == 409:
            print(f"[auth] Email already registered — {email}")
        elif reg_result.status in (400, 422):
            print(f"[auth] Registration rejected ({reg_result.status}): {reg_result.body[:200]}")
            # Try alternate endpoint with different field names
            alt_result = await self._try_alternate_registration(
                base_url, email, password, name, extra_fields
            )
            if alt_result:
                return alt_result
        else:
            print(f"[auth] Registration returned {reg_result.status}")

        # Extract cookies from response
        cookies = self._extract_response_cookies(reg_result)

        return AuthSession(
            email=email,
            password=password,
            cookies=cookies,
            username=name,
            logged_in=reg_result.status in (200, 201, 302, 303),
        )

    async def _try_alternate_registration(
        self, base_url: str, email: str, password: str,
        name: str, extra_fields: Dict = None,
    ) -> Optional[AuthSession]:
        """Try alternate field names and content types for registration."""
        alt_paths = ["/api/v1/users", "/api/users", "/api/auth/register/json"]

        for alt_path in alt_paths:
            alt_url = urljoin(base_url, alt_path)
            payload = {
                "email": email,
                "password": password,
                "username": email.split("@")[0],
            }
            result = await self.http_pool.request(
                "POST", alt_url,
                headers={"Content-Type": "application/json"},
                json_data=payload,
            )
            if result.status in (200, 201):
                print(f"[auth] Alternate registration succeeded at {alt_path}")
                return AuthSession(
                    email=email, password=password,
                    cookies=self._extract_response_cookies(result),
                    logged_in=True,
                )

        return None

    # ── Email Verification ─────────────────────────────────

    async def verify_email(
        self,
        target: str,
        session: AuthSession,
        timeout: int = 60,
    ) -> bool:
        """
        Wait for verification email and click the verification link.

        Returns True if verification was successful.
        """
        print(f"[auth] Waiting for verification email to {session.email}...")
        email = await self.wait_for_email(timeout=timeout)

        if not email:
            print("[auth] No verification email received")
            return False

        # Extract verification link from email body
        verification_url = self._extract_verification_link(email["body"])
        if not verification_url:
            print("[auth] No verification link found in email body")
            print(f"  Body preview: {email['body'][:300]}")
            return False

        # Ensure URL is absolute
        base_url = target if target.startswith("http") else f"https://{target}"
        if not verification_url.startswith("http"):
            verification_url = urljoin(base_url, verification_url)

        # Click the verification link
        print(f"[auth] Clicking verification link: {verification_url[:100]}...")
        result = await self.http_pool.request(
            "GET", verification_url,
            headers={"User-Agent": self.http_pool.random_ua()},
            allow_redirects=True,
        )

        if result.status in (200, 302, 303):
            print(f"[auth] Email verified successfully — {session.email}")
            # Update session cookies with any new ones
            session.cookies.update(self._extract_response_cookies(result))
            return True

        print(f"[auth] Verification returned {result.status}")
        return False

    # ── Login ──────────────────────────────────────────────

    async def login(
        self,
        target: str,
        email: str,
        password: str,
        login_url: str = None,
    ) -> AuthSession:
        """
        Auto-detect login form, authenticate, extract cookies/tokens.
        """
        base_url = target if target.startswith("http") else f"https://{target}"

        # Discover login endpoint
        discovered_url = login_url
        if not discovered_url:
            discovered_url = await self._discover_endpoint(base_url, self.LOGIN_PATHS)

        if not discovered_url:
            print(f"[auth] No login endpoint found on {target}")
            return AuthSession(email=email, password=password, logged_in=False)

        # Get login page for CSRF token
        get_result = await self.http_pool.request("GET", discovered_url)
        csrf_token = self._extract_csrf(get_result)

        # Build login payload
        content_type = self._detect_content_type(get_result)
        payload = {
            "email": email,
            "password": password,
        }
        if csrf_token:
            payload["csrf_token"] = csrf_token

        headers = {
            "Content-Type": content_type,
            "Accept": "application/json, text/html, */*",
            "Origin": base_url,
            "Referer": discovered_url,
        }

        # Send login
        if content_type == "application/json":
            result = await self.http_pool.request(
                "POST", discovered_url, headers=headers, json_data=payload
            )
        else:
            result = await self.http_pool.request(
                "POST", discovered_url, headers=headers, data=self._encode_form(payload)
            )

        cookies = self._extract_response_cookies(result)
        tokens = self._extract_tokens(result)

        session = AuthSession(
            email=email,
            password=password,
            cookies=cookies,
            tokens=tokens,
            headers={"Authorization": f"Bearer {tokens['bearer']}"} if tokens.get("bearer") else {},
            logged_in=result.status in (200, 302, 303) or bool(cookies),
        )

        if session.logged_in:
            print(f"[auth] Login successful — {email}")
            # Test authenticated access
            if await self._test_auth(base_url, session):
                print(f"[auth] Authenticated access confirmed")
        else:
            print(f"[auth] Login failed ({result.status}): {result.body[:200]}")

        return session

    # ── Full Auto-Auth Pipeline ────────────────────────────

    async def auto_auth(
        self,
        target: str,
        verify_email: bool = True,
        create_two: bool = False,
    ) -> Dict[str, AuthSession]:
        """
        Full automated authentication pipeline:
        1. Create temp email(s)
        2. Register account(s)
        3. Verify email(s) (optional)
        4. Login and return authenticated session(s)

        Returns dict with keys 'user_a' and optionally 'user_b' (for IDOR testing).
        """
        print(f"[auth] Starting auto-auth for {target}")

        # User A
        email_a = await self.create_temp_email()
        password_a = self._generate_password()

        session_a = await self.register(target, email=email_a, password=password_a)
        if not session_a:
            print("[auth] Registration failed for user A")
            return {}

        if verify_email:
            await self.verify_email(target, session_a)

        # Login to get full session
        session_a = await self.login(target, email_a, password_a)

        # Save to state
        self._save_session(target, "user_a", session_a)

        result = {"user_a": session_a}

        if create_two:
            # User B (for cross-user testing)
            email_b = await self.create_temp_email()
            password_b = self._generate_password()

            session_b = await self.register(target, email=email_b, password=password_b)
            if session_b:
                if verify_email:
                    await self.verify_email(target, session_b)
                session_b = await self.login(target, email_b, password_b)
                self._save_session(target, "user_b", session_b)
                result["user_b"] = session_b

        print(f"[auth] Auto-auth complete — {len(result)} session(s) created")
        return result

    # ── Helpers ────────────────────────────────────────────

    async def _discover_endpoint(self, base_url: str, paths: List[str]) -> Optional[str]:
        """Try common paths, then crawl homepage for form actions before falling back."""
        # First, try the hardcoded paths
        for path in paths:
            url = urljoin(base_url, path)
            result = await self.http_pool.request("GET", url)
            if result.status not in (404, -3, -1):
                return url

        # Fall back: crawl homepage for form actions
        homepage = await self.http_pool.request("GET", base_url)
        if homepage.status == 200:
            discovered = self._extract_form_actions(homepage.body, base_url, paths)
            if discovered:
                print(f"[auth] Discovered endpoint from form action: {discovered}")
                return discovered

        return None

    def _extract_form_actions(self, html: str, base_url: str, target_paths: List[str]) -> Optional[str]:
        """
        Extract form action URLs from HTML that match known auth path patterns.
        Looks for <form action="..."> elements pointing to login/register pages.
        """
        # Find all form action URLs
        form_pattern = re.compile(
            r'<form\b[^>]*\saction\s*=\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        actions = form_pattern.findall(html)

        # Also check links with auth-related text
        link_pattern = re.compile(
            r'<a\b[^>]*\shref\s*=\s*["\']([^"\']+(?:login|signin|register|signup|sign-in|sign-up|log-in)[^"\']*)["\'][^>]*>',
            re.IGNORECASE,
        )
        link_actions = [m.group(1) if hasattr(m, 'group') else m for m in link_pattern.finditer(html)]

        all_actions = actions + link_actions

        # Score each action by its match to known auth patterns
        auth_keywords = [
            "login", "signin", "sign-in", "log-in", "sign_in",
            "register", "signup", "sign-up", "sign_up", "create-account",
            "auth", "oauth", "sso",
        ]

        for action in all_actions:
            # Make absolute
            full_url = urljoin(base_url, action)
            action_lower = action.lower()
            # Score: count how many auth keywords appear in the URL
            score = sum(1 for kw in auth_keywords if kw in action_lower)
            if score > 0:
                # Also parse the full URL for additional path segments
                parsed = urlparse(full_url)
                if parsed.path and len(parsed.path) > 1:
                    return full_url

        return None

    def _extract_csrf(self, result: HTTPResult) -> Optional[str]:
        """Extract CSRF token from HTML response."""
        body = result.body

        # Try meta tag
        m = re.search(r'<meta\s+name=["\']csrf[^"\']*["\']\s+content=["\']([^"\']+)["\']', body, re.I)
        if m:
            return m.group(1)

        # Try hidden input
        for field in self.CSRF_FIELDS:
            m = re.search(
                rf'<input[^>]*name=["\']{re.escape(field)}["\'][^>]*value=["\']([^"\']+)["\']',
                body, re.I,
            )
            if m:
                return m.group(1)
            # Also try reversed order (value before name)
            m = re.search(
                rf'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']{re.escape(field)}["\']',
                body, re.I,
            )
            if m:
                return m.group(1)

        # Try JS variable
        m = re.search(r'csrf[_\w]*\s*=\s*["\']([^"\']+)["\']', body, re.I)
        if m:
            return m.group(1)

        # Try cookie
        csrf_cookie_names = ["csrf_token", "csrf", "xsrf-token", "XSRF-TOKEN"]
        for name in csrf_cookie_names:
            if name in result.headers.get("set-cookie", "").lower():
                m = re.search(rf'{name}=([^;]+)', result.headers.get("set-cookie", ""), re.I)
                if m:
                    return m.group(1)

        return None

    def _build_registration_payload(
        self, body: str, email: str, password: str,
        name: str, extra_fields: Dict = None,
    ) -> Dict[str, str]:
        """Build registration payload by detecting form fields."""
        payload = {}

        # Detect which email field name to use
        for field in self.EMAIL_FIELDS:
            if field in body.lower() or f'name="{field}"' in body.lower():
                payload[field] = email
                break
        if not any(f in payload for f in self.EMAIL_FIELDS):
            payload["email"] = email

        # Detect which password field to use
        for field in self.PASSWORD_FIELDS:
            if field in body.lower() or f'name="{field}"' in body.lower():
                payload[field] = password
                break
        if not any(f in payload for f in self.PASSWORD_FIELDS):
            payload["password"] = password

        # Add name if the form has it
        for field in self.NAME_FIELDS:
            if field in body.lower():
                payload[field] = name
                break

        # Add confirm password if present
        if "confirm" in body.lower() or "password_confirmation" in body.lower():
            payload["password_confirmation"] = password

        # Add extra fields
        if extra_fields:
            payload.update(extra_fields)

        return payload

    def _detect_content_type(self, result: HTTPResult) -> str:
        """Detect whether the endpoint expects JSON or form data."""
        ct = result.headers.get("content-type", "")
        if "json" in ct.lower():
            return "application/json"
        return "application/x-www-form-urlencoded"

    def _encode_form(self, data: Dict) -> str:
        """URL-encode form data."""
        import urllib.parse
        return urllib.parse.urlencode(data)

    def _extract_response_cookies(self, result: HTTPResult) -> Dict[str, str]:
        """Extract cookies from Set-Cookie response headers."""
        cookies = {}
        set_cookie = result.headers.get("set-cookie", "")
        if set_cookie:
            for part in set_cookie.split(","):
                part = part.strip().split(";")[0]
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()
        return cookies

    def _extract_tokens(self, result: HTTPResult) -> Dict[str, str]:
        """Extract auth tokens from response body (JWT, API key, etc.)."""
        tokens = {}

        # JWT in body
        m = re.search(r'"token"\s*:\s*"([^"]+)"', result.body)
        if not m:
            m = re.search(r'"access_token"\s*:\s*"([^"]+)"', result.body)
        if not m:
            m = re.search(r'"(?:jwt|accessToken|auth_token)"\s*:\s*"([^"]+)"', result.body)
        if m:
            tokens["bearer"] = m.group(1)

        # API key
        m = re.search(r'"api_key"\s*:\s*"([^"]+)"', result.body)
        if m:
            tokens["api_key"] = m.group(1)

        return tokens

    def _extract_verification_link(self, body: str) -> Optional[str]:
        """Extract email verification link from email body."""
        # Common patterns in verification emails
        patterns = [
            r'https?://[^\s<>"\']*(?:verify|confirm|activate|validate)[^\s<>"\']*',
            r'https?://[^\s<>"\']*(?:email-verification|email_verification)[^\s<>"\']*',
            r'https?://[^\s<>"\']*token=[^\s<>"\']+',
            r'https?://[^\s<>"\']*hash=[^\s<>"\']+',
            r'<a\s+[^>]*href=["\']([^"\']*(?:verify|confirm|activate|token|hash)[^"\']*)["\']',
        ]

        for pattern in patterns:
            m = re.search(pattern, body, re.I)
            if m:
                link = m.group(1) if m.lastindex else m.group(0)
                # Clean up: remove trailing punctuation
                link = link.rstrip(".,;:)")
                return link

        return None

    async def _test_auth(self, base_url: str, session: AuthSession) -> bool:
        """Test if the session is actually authenticated."""
        # Try common authenticated endpoints
        auth_endpoints = [
            "/api/v1/users/me", "/api/me", "/api/user",
            "/settings", "/profile", "/dashboard",
            "/api/auth/me", "/api/v1/me",
        ]
        for path in auth_endpoints:
            url = urljoin(base_url, path)
            headers = session.get_auth_headers()
            if session.cookies:
                headers["Cookie"] = session.get_cookie_string()
            result = await self.http_pool.request("GET", url, headers=headers)
            if result.status == 200 and len(result.body) > 50:
                # Check if response looks like user data (not a redirect to login)
                if not any(phrase in result.body.lower() for phrase in
                          ["login", "sign in", "unauthorized", "unauthenticated",
                           "<title>Sign In", "<title>Log In"]):
                    return True

        return False

    def _save_session(self, target: str, role: str, session: AuthSession):
        """Save authenticated session to state directory."""
        safe_target = target.replace("/", "_").replace(":", "_")
        session_file = Path(self.state_dir) / f"{safe_target}_{role}.json"
        session_file.write_text(json.dumps(session.to_dict(), indent=2))
        print(f"[auth] Session saved: {session_file}")

    def load_session(self, target: str, role: str = "user_a") -> Optional[AuthSession]:
        """Load a previously saved session."""
        safe_target = target.replace("/", "_").replace(":", "_")
        session_file = Path(self.state_dir) / f"{safe_target}_{role}.json"
        if session_file.exists():
            data = json.loads(session_file.read_text())
            return AuthSession(**data)
        return None

    @staticmethod
    def _generate_password(length: int = 16) -> str:
        """Generate a strong random password."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))


# ── Self-test ──────────────────────────────────────────────

async def _self_test():
    """Quick self-test: create a temp email and verify the Guerrilla Mail API."""
    from tools.http_pool import HTTPPool

    pool = HTTPPool(max_connections=5, timeout=15)
    auth = AuthManager(pool)

    print("[*] Auth Manager self-test")

    # Test temp email creation
    email = await auth.create_temp_email()
    print(f"  Temp email: {email}")
    assert "@" in email, f"Invalid email: {email}"

    await pool.stop()
    print("[*] Self-test complete")


# ── CLI ────────────────────────────────────────────────────

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="BountyForge Auth Manager — automated account creation + login")
    parser.add_argument("--target", help="Target domain or URL")
    parser.add_argument("--two", action="store_true",
                        help="Create two accounts (for IDOR / cross-user testing)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip email verification step")
    parser.add_argument("--self-test", action="store_true", help="Run built-in self-test")
    args = parser.parse_args()

    if args.self_test or not args.target:
        await _self_test()
        return

    from tools.http_pool import HTTPPool

    pool = HTTPPool(max_connections=5, timeout=15)
    await pool.start()
    auth = AuthManager(pool)

    target = args.target if args.target.startswith("http") else f"https://{args.target}"

    print(f"[*] BountyForge Auth Manager")
    print(f"[*] Target: {target}")
    print(f"[*] Mode: {'dual-account (IDOR)' if args.two else 'single-account'}")

    sessions = await auth.auto_auth(
        target,
        verify_email=not args.no_verify,
        create_two=args.two,
    )

    print(f"\n[*] Sessions created: {len(sessions)}")
    for role, s in sessions.items():
        status = "LOGGED IN" if s.logged_in else "registered (login failed)"
        print(f"\n  [{role}] {s.email} — {status}")
        print(f"    cookies: {len(s.cookies)} | tokens: {list(s.tokens.keys())}")
        if s.user_id:
            print(f"    user_id: {s.user_id}")
        # Never print raw token values — only which keys exist

    if not sessions:
        print("  ✗ Could not register/login automatically.")
        print("    The target may use CAPTCHA, OAuth-only signup, or non-standard forms.")

    print(f"\n[*] Session files saved under: {auth.state_dir}")

    await pool.stop()


if __name__ == "__main__":
    if not HAS_HTTP:
        print("[!] http_pool.py required (put in same directory)")
        sys.exit(1)
    asyncio.run(main())
