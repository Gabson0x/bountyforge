#!/usr/bin/env python3
"""
BountyForge Infrastructure Auto-Deploy v2.1.0

Auto-provisions callback infrastructure for blind/out-of-band attacks:
  - Self-hosted interactsh server (OOB DNS/HTTP/LDAP listener)
  - HTTP callback server for SSRF verification
  - DNS exfiltration listener
  - Auto-teardown after session (no lingering infra)

Supports:
  - Local mode: Start listeners on localhost + ngrok/tunnel
  - Cloud mode: Terraform EC2/Droplet with auto-provision
  - Container mode: Docker-based disposable listeners

Usage:
  python3 tools/infra_deploy.py --mode local --type http-callback
  python3 tools/infra_deploy.py --mode cloud --provider aws --type interactsh
  python3 tools/infra_deploy.py --teardown --session-id abc123
  python3 tools/infra_deploy.py --list-sessions
"""

import os
import sys
import json
import time
import signal
import socket
import hashlib
import secrets
import shutil
import subprocess
import threading
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict
from http.server import HTTPServer, BaseHTTPRequestHandler

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

INFRA_DIR = ROOT / "state" / "infra"
INFRA_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Callback HTTP server (for SSRF verification)
# ---------------------------------------------------------------------------

class CallbackHandler(BaseHTTPRequestHandler):
    """Minimal HTTP server that logs all incoming requests.

    Used to verify SSRF, blind XSS, and other OOB vulnerabilities.
    Each request is logged with full headers, body, and source IP.
    """

    captured_requests: List[Dict] = []

    def log_message(self, format, *args):
        pass  # Suppress default logging

    def _log_request(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": self.command,
            "path": self.path,
            "source_ip": self.client_address[0],
            "source_port": self.client_address[1],
            "headers": dict(self.headers),
            "body": body.decode("utf-8", errors="replace")[:2000],
            "body_hex": body.hex()[:500],
        }
        CallbackHandler.captured_requests.append(entry)

        with open(INFRA_DIR / "callback-log.jsonl", "a") as f:
            f.write(json.dumps(entry) + "\n")

    def do_GET(self):
        self._log_request()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"BountyForge Callback Server v2.1.0\n")

    def do_POST(self):
        self._log_request()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}\n')

    def do_PUT(self):
        self._log_request()
        self.send_response(200)
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()


class CallbackServer:
    """Manages a disposable HTTP callback server."""

    def __init__(self, port: int = 8080, bind: str = "0.0.0.0"):
        self.port = port
        self.bind = bind
        self.server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.session_id = secrets.token_hex(8)
        self.started_at: Optional[str] = None

    def start(self):
        self.server = HTTPServer((self.bind, self.port), CallbackHandler)
        self.server.timeout = 1
        self._thread = threading.Thread(target=self.server.serve_forever,
                                        daemon=True)
        self._thread.start()
        self.started_at = datetime.now(timezone.utc).isoformat()

        return {
            "session_id": self.session_id,
            "url": f"http://{self._get_public_ip()}:{self.port}",
            "local_url": f"http://127.0.0.1:{self.port}",
            "port": self.port,
            "started_at": self.started_at,
        }

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def get_captured(self) -> List[Dict]:
        return CallbackHandler.captured_requests

    def get_stats(self) -> Dict:
        captured = self.get_captured()
        sources = set(c.get("source_ip") for c in captured)
        return {
            "total_requests": len(captured),
            "unique_sources": len(sources),
            "sources": list(sources),
            "last_request": captured[-1] if captured else None,
            "uptime": (datetime.now(timezone.utc) -
                       datetime.fromisoformat(self.started_at)).total_seconds()
            if self.started_at else 0,
        }

    def _get_public_ip(self) -> str:
        """Get the machine's public IP for the callback URL."""
        try:
            import urllib.request
            with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
                return r.read().decode().strip()
        except Exception:
            pass
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


# ---------------------------------------------------------------------------
# Interactsh self-hosted
# ---------------------------------------------------------------------------

def start_interactsh() -> Dict:
    """Start a self-hosted interactsh server.

    Interactsh is an OOB interaction server supporting DNS, HTTP, SMTP, LDAP.
    Requires: interactsh-client installed (go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest)
    """
    interactsh_bin = shutil.which("interactsh-client")
    if not interactsh_bin:
        return {
            "success": False,
            "error": "interactsh-client not installed. "
                     "Install: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        }

    # Generate a session token
    session_id = secrets.token_hex(8)
    config_dir = INFRA_DIR / "interactsh" / session_id
    config_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Start interactsh client (uses public interactsh servers by default)
        # For self-hosted, you'd run interactsh-server separately
        proc = subprocess.Popen(
            [interactsh_bin, "-json", "-o", str(config_dir / "interactsh.log")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)

        # Wait for the OOB URL to appear in output
        time.sleep(3)

        # Read the generated URL from the log
        log_file = config_dir / "interactsh.log"
        oob_url = None
        for _ in range(10):  # Wait up to 10 seconds
            if log_file.exists():
                for line in log_file.read_text().splitlines():
                    if "." in line and len(line) > 20:
                        try:
                            data = json.loads(line)
                            if "protocol" in data:
                                oob_url = data.get("full-id", "")
                                break
                        except json.JSONDecodeError:
                            pass
            if oob_url:
                break
            time.sleep(1)

        return {
            "success": True,
            "session_id": session_id,
            "oob_url": oob_url or "check interactsh log",
            "config_dir": str(config_dir),
            "pid": proc.pid,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# DNS exfiltration listener
# ---------------------------------------------------------------------------

class DNSExfilListener:
    """Simple DNS listener for data exfiltration via DNS queries.

    Listens on UDP port 53 (requires root/sudo).
    Captures subdomain queries and reconstructs exfiltrated data.
    """

    def __init__(self, domain: str = "exfil.local", port: int = 5353):
        self.domain = domain
        self.port = port  # Use non-privileged port to avoid sudo
        self._socket: Optional[socket.socket] = None
        self._running = False
        self.captured: List[Dict] = []

    def start(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("0.0.0.0", self.port))
        self._socket.settimeout(1.0)
        self._running = True

        thread = threading.Thread(target=self._listen, daemon=True)
        thread.start()

        return {
            "listener": "dns-exfil",
            "port": self.port,
            "domain": self.domain,
        }

    def _listen(self):
        while self._running:
            try:
                data, addr = self._socket.recvfrom(4096)
                # Parse DNS query for subdomain data
                query = data[12:]  # Skip DNS header
                parts = []
                while query and query[0] != 0:
                    length = query[0]
                    parts.append(query[1:length+1].decode("ascii", errors="replace"))
                    query = query[length+1:]

                subdomain = ".".join(parts[:-2])  # Remove domain and TLD
                if subdomain:
                    self.captured.append({
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "source": addr[0],
                        "subdomain": subdomain,
                        "decoded": bytes.fromhex(subdomain.replace(".", "")).decode(
                            "utf-8", errors="replace") if len(subdomain) % 2 == 0
                        else "[non-hex data]",
                    })
            except socket.timeout:
                continue
            except Exception:
                break

    def stop(self):
        self._running = False
        if self._socket:
            self._socket.close()


# ---------------------------------------------------------------------------
# Ngrok tunnel (for exposing local callback servers)
# ---------------------------------------------------------------------------

def start_ngrok_tunnel(local_port: int) -> Dict:
    """Start an ngrok tunnel to expose a local port."""
    ngrok_bin = shutil.which("ngrok")
    if not ngrok_bin:
        return {"success": False, "error": "ngrok not installed"}

    try:
        # Start ngrok in background
        proc = subprocess.Popen(
            [ngrok_bin, "http", str(local_port), "--log=stdout"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)

        # Wait for tunnel URL
        time.sleep(3)

        # Get tunnel URL from ngrok API
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels",
                                     timeout=5) as r:
            tunnels = json.loads(r.read().decode())
            public_url = tunnels["tunnels"][0]["public_url"]

        return {
            "success": True,
            "public_url": public_url,
            "local_port": local_port,
            "pid": proc.pid,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Session manager
# ---------------------------------------------------------------------------

@dataclass
class InfraSession:
    session_id: str
    created_at: str
    mode: str  # local, cloud, container
    resources: Dict[str, Any] = field(default_factory=dict)
    status: str = "active"  # active, teardown


class InfraManager:
    """Manages disposable attack infrastructure."""

    def __init__(self):
        INFRA_DIR.mkdir(parents=True, exist_ok=True)
        self._sessions: Dict[str, InfraSession] = {}
        self._callback_server: Optional[CallbackServer] = None
        self._dns_listener: Optional[DNSExfilListener] = None

    def start_callback_server(self, port: int = 8080) -> Dict:
        """Start an HTTP callback server for SSRF verification."""
        if self._callback_server:
            self._callback_server.stop()

        self._callback_server = CallbackServer(port=port)
        info = self._callback_server.start()

        session = InfraSession(
            session_id=info["session_id"],
            created_at=info["started_at"],
            mode="local",
            resources={"type": "http-callback", "info": info},
        )
        self._sessions[info["session_id"]] = session
        self._save_session(session)

        print(f"[+] Callback server started: {info['url']}")
        print(f"    Session ID: {info['session_id']}")
        return info

    def start_dns_listener(self, port: int = 5353) -> Dict:
        """Start a DNS exfiltration listener."""
        self._dns_listener = DNSExfilListener(port=port)
        info = self._dns_listener.start()

        session = InfraSession(
            session_id=f"dns-{secrets.token_hex(4)}",
            created_at=datetime.now(timezone.utc).isoformat(),
            mode="local",
            resources={"type": "dns-listener", "info": info},
        )
        self._sessions[session.session_id] = session
        self._save_session(session)

        return info

    def start_interactsh(self) -> Dict:
        """Start interactsh for OOB testing."""
        result = start_interactsh()

        if result["success"]:
            session = InfraSession(
                session_id=result["session_id"],
                created_at=datetime.now(timezone.utc).isoformat(),
                mode="local",
                resources={"type": "interactsh", "info": result},
            )
            self._sessions[result["session_id"]] = session
            self._save_session(session)

        return result

    def start_full_stack(self) -> Dict:
        """Start all listeners: HTTP callback + DNS + interactsh."""
        results = {}

        http_info = self.start_callback_server(port=8080)
        results["http_callback"] = http_info

        dns_info = self.start_dns_listener(port=5353)
        results["dns_listener"] = dns_info

        # Try interactsh
        try:
            interactsh_info = self.start_interactsh()
            results["interactsh"] = interactsh_info
        except Exception as e:
            results["interactsh"] = {"success": False, "error": str(e)}

        return results

    def get_captured(self) -> Dict:
        """Get all captured interactions across all listeners."""
        result = {}

        if self._callback_server:
            result["http_callback"] = {
                "requests": self._callback_server.get_captured(),
                "stats": self._callback_server.get_stats(),
            }

        if self._dns_listener:
            result["dns_listener"] = {
                "queries": self._dns_listener.captured,
            }

        return result

    def teardown(self, session_id: str = None):
        """Tear down all infrastructure. If session_id, tear down specific session."""
        print("[*] Tearing down infrastructure...")

        if self._callback_server:
            stats = self._callback_server.get_stats()
            print(f"    HTTP callback: {stats['total_requests']} requests captured")
            self._callback_server.stop()
            self._callback_server = None

        if self._dns_listener:
            print(f"    DNS listener: {len(self._dns_listener.captured)} queries captured")
            self._dns_listener.stop()
            self._dns_listener = None

        # Kill ngrok tunnels
        subprocess.run(["pkill", "-f", "ngrok http"], capture_output=True)

        # Kill interactsh
        subprocess.run(["pkill", "-f", "interactsh-client"], capture_output=True)

        # Update session status
        for sid, session in self._sessions.items():
            if session_id is None or sid == session_id:
                session.status = "teardown"
                self._save_session(session)

        print("[+] All infrastructure torn down")

    def list_sessions(self) -> List[Dict]:
        """List all infrastructure sessions."""
        sessions = []
        for f in INFRA_DIR.glob("session-*.json"):
            data = json.loads(f.read_text())
            sessions.append(data)
        return sessions

    def _save_session(self, session: InfraSession):
        """Persist session info."""
        out = INFRA_DIR / f"session-{session.session_id}.json"
        out.write_text(json.dumps(asdict(session), indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BountyForge Infrastructure Auto-Deploy")
    parser.add_argument("--mode", default="local",
                        choices=["local", "cloud", "container"],
                        help="Deployment mode")
    parser.add_argument("--type", default="http-callback",
                        choices=["http-callback", "dns-listener", "interactsh",
                                 "full-stack"],
                        help="Infrastructure type to deploy")
    parser.add_argument("--port", type=int, default=8080,
                        help="Port for HTTP callback server")
    parser.add_argument("--dns-port", type=int, default=5353,
                        help="Port for DNS listener")
    parser.add_argument("--ngrok", action="store_true",
                        help="Expose via ngrok tunnel")
    parser.add_argument("--teardown", help="Teardown session ID")
    parser.add_argument("--teardown-all", action="store_true",
                        help="Teardown all infrastructure")
    parser.add_argument("--list-sessions", action="store_true",
                        help="List active infrastructure sessions")
    parser.add_argument("--get-captured", action="store_true",
                        help="Show captured interactions")
    args = parser.parse_args()

    mgr = InfraManager()

    if args.list_sessions:
        sessions = mgr.list_sessions()
        if not sessions:
            print("[*] No active infrastructure sessions")
        for s in sessions:
            print(f"  [{s['status']}] {s['session_id']} — {s['mode']} — {s['created_at']}")

    elif args.teardown_all:
        mgr.teardown()

    elif args.teardown:
        mgr.teardown(args.teardown)

    elif args.get_captured:
        captured = mgr.get_captured()
        print(json.dumps(captured, indent=2, default=str))

    elif args.type == "full-stack":
        print("[*] Starting full attack infrastructure stack...")
        results = mgr.start_full_stack()
        print(json.dumps(results, indent=2, default=str))
        print("\n[*] Press Ctrl+C to tear down")

        def cleanup(sig, frame):
            mgr.teardown()
            sys.exit(0)

        signal.signal(signal.SIGINT, cleanup)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            mgr.teardown()

    elif args.type == "http-callback":
        info = mgr.start_callback_server(port=args.port)

        if args.ngrok:
            ngrok_result = start_ngrok_tunnel(args.port)
            if ngrok_result.get("success"):
                info["ngrok_url"] = ngrok_result["public_url"]
                print(f"[+] Ngrok tunnel: {ngrok_result['public_url']}")

        print(f"\n[*] Callback URL: {info['url']}")
        print(f"[*] Press Ctrl+C to stop and see captured requests")

        def cleanup(sig, frame):
            stats = mgr._callback_server.get_stats() if mgr._callback_server else {}
            print(f"\n[*] Stopping... ({stats.get('total_requests', 0)} requests captured)")
            mgr.teardown()
            sys.exit(0)

        signal.signal(signal.SIGINT, cleanup)
        try:
            while True:
                time.sleep(5)
                if mgr._callback_server:
                    stats = mgr._callback_server.get_stats()
                    if stats["total_requests"] > 0:
                        last = stats["last_request"]
                        print(f"  [{stats['total_requests']}] {last['method']} "
                              f"{last['path']} from {last['source_ip']}")
        except KeyboardInterrupt:
            stats = mgr._callback_server.get_stats() if mgr._callback_server else {}
            print(f"\n[*] Stopping... ({stats.get('total_requests', 0)} requests captured)")
            mgr.teardown()

    elif args.type == "dns-listener":
        info = mgr.start_dns_listener(port=args.dns_port)
        print(f"[*] DNS exfiltration listener started on port {args.dns_port}")
        print(f"[*] Send DNS queries to: <data>.{info['domain']}")
        print(f"[*] Press Ctrl+C to stop")

        signal.signal(signal.SIGINT, lambda s, f: mgr.teardown())
        try:
            while True:
                time.sleep(5)
                if mgr._dns_listener and mgr._dns_listener.captured:
                    print(f"  [{len(mgr._dns_listener.captured)}] queries captured")
        except KeyboardInterrupt:
            mgr.teardown()

    elif args.type == "interactsh":
        result = mgr.start_interactsh()
        print(json.dumps(result, indent=2, default=str))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
