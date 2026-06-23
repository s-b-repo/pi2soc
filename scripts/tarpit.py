#!/usr/bin/env python3
"""
SOC wall scanner-deception tarpit — stdlib HTTP server, port 80.

A passing port-scanner that touches admin.php / wp-login.php / .env / etc.
gets a `200 OK` with random-looking junk (4–32 KB) after a 0.5–2.0 s drip.
Everything else gets a `404`. Goal: make automated scanners waste real time
+ chew up false-positive triage cycles, without exposing anything real.

Design notes:
  * Stdlib only — no Flask, no FastAPI, runs anywhere the wall does.
  * Strips the `Server:` header so the response doesn't fingerprint Python /
    BaseHTTPServer / kernel version.
  * Per-source-IP rate limit (bounded LRU): a chatty scanner hits the same
    box from one or two IPs; we slow them down per-IP instead of globally so
    a single noisy scanner can't shoulder out a quiet one.
  * Picks a Content-Type that matches the path (PHP -> text/html, .env ->
    text/plain, /api/v1 -> application/json) so the body looks plausible.
  * The body is `os.urandom(N)` wrapped in the chosen MIME — for JSON we wrap
    in a string literal; for HTML in a comment; for env in `KEY=...` lines.
    Plausible enough to fool a header-only scanner; junk enough to be useless.
  * `Connection: close` after every response — never let a scanner pipeline.
  * Logs to stderr only (systemd journal).

Off by default. Opt-in via `SOC_TARPIT_ENABLE=1` in /etc/soc-display/soc.env,
or `systemctl enable --now soc-tarpit.service` after dropping the unit in.
"""
from __future__ import annotations

import base64
import collections
import http.server
import os
import random
import socketserver
import sys
import threading
import time

# Common scanner targets — keep this list updated; order doesn't matter (lookup
# is a set + a prefix walk). Mostly drawn from public scanner signatures
# (Nuclei, ZAP, dirbuster wordlists). Anything not in here returns 404.
EXACT_PATHS = {
    "/admin", "/admin.php", "/admin/", "/admin/login", "/admin/login.php",
    "/administrator", "/administrator/", "/administrator/index.php",
    "/wp-admin", "/wp-admin/", "/wp-admin/admin-ajax.php", "/wp-login.php",
    "/.env", "/.env.local", "/.env.production", "/.git/config", "/.git/HEAD",
    "/.aws/credentials", "/.ssh/id_rsa", "/.htpasswd", "/.htaccess",
    "/phpmyadmin/", "/phpmyadmin/index.php", "/pma/", "/myadmin/",
    "/server-status", "/server-info",
    "/manager/html", "/manager/status", "/host-manager/html",
    "/console/", "/jolokia/list", "/jmx-console",
    "/HNAP1/", "/HNAP1",
}
PREFIX_PATHS = (
    "/actuator/",            # spring-boot
    "/api/v1/",              # generic api fishing
    "/wp-content/",
    "/wp-includes/",
    "/cgi-bin/",
    "/vendor/",
    "/dbeaver/",
    "/.git/",
    "/owa/",                 # exchange
    "/Autodiscover/",
    "/ecp/",
)

# Bind defaults; overrideable from env so a non-80 deploy can also use this.
TARPIT_HOST = os.environ.get("SOC_TARPIT_HOST", "0.0.0.0")
TARPIT_PORT = int(os.environ.get("SOC_TARPIT_PORT", "80") or 80)
# Per-IP rate: at most BURST hits, then 1 hit per WINDOW seconds.
RL_BURST = int(os.environ.get("SOC_TARPIT_BURST", "8") or 8)
RL_WINDOW = float(os.environ.get("SOC_TARPIT_WINDOW", "2.0") or 2.0)
# Drip range: each matched request sleeps this long before answering.
DRIP_MIN = float(os.environ.get("SOC_TARPIT_DRIP_MIN", "0.5") or 0.5)
DRIP_MAX = float(os.environ.get("SOC_TARPIT_DRIP_MAX", "2.0") or 2.0)


def _matches(path: str) -> bool:
    """True if `path` looks like a known scanner target."""
    if path in EXACT_PATHS:
        return True
    return any(path.startswith(p) for p in PREFIX_PATHS)


def _mime_for(path: str) -> tuple[str, str]:
    """(Content-Type, body-generator-key) for a matched path. The body shape
    matches what a header-only scanner expects to see, so a Quick Look reads
    'yep, it's an env file' rather than 'random bytes' (which would tip them
    off that this is fake)."""
    if path.endswith((".env", ".env.local", ".env.production")):
        return "text/plain; charset=utf-8", "env"
    if path.endswith((".json",)) or path.startswith(("/api/", "/actuator/",
                                                      "/jolokia/")):
        return "application/json", "json"
    if path.startswith(("/.git/", "/.htpasswd", "/.htaccess",
                         "/.aws/", "/.ssh/")):
        return "text/plain; charset=utf-8", "text"
    return "text/html; charset=utf-8", "html"


def _junk_env(n: int) -> bytes:
    """Random `KEY=base64-junk` lines for a fake .env response."""
    lines = []
    keys = ["DATABASE_URL", "APP_KEY", "MAIL_PASSWORD", "S3_SECRET",
            "REDIS_URL", "JWT_SECRET", "API_TOKEN", "DEBUG_TOKEN"]
    while sum(len(x) + 1 for x in lines) < n:
        k = random.choice(keys)
        v = base64.urlsafe_b64encode(os.urandom(random.randint(16, 48))).decode().rstrip("=")
        lines.append(f"{k}={v}")
    return ("\n".join(lines) + "\n").encode()


def _junk_json(n: int) -> bytes:
    """A JSON blob shaped like an actuator or generic-API response."""
    keys = ["status", "data", "result", "token", "id", "name", "value"]
    pairs = []
    while sum(len(p) + 2 for p in pairs) < n:
        k = random.choice(keys)
        v = base64.urlsafe_b64encode(os.urandom(random.randint(8, 32))).decode().rstrip("=")
        pairs.append(f'"{k}_{len(pairs)}": "{v}"')
    return ("{" + ", ".join(pairs) + "}").encode()


def _junk_html(n: int) -> bytes:
    """A '<html>...random base64 in a comment...</html>' that looks like a
    real admin page on cursory inspection. Don't try to mimic specific apps —
    just enough HTML chrome that header-only scanners are satisfied."""
    body = base64.b64encode(os.urandom(max(64, n - 200))).decode()
    return (b"<!doctype html><html><head><title>Admin</title></head><body>"
            b"<h1>Login</h1><!-- "
            + body.encode()
            + b" --></body></html>")


def _junk_text(n: int) -> bytes:
    """Plain base64-looking bytes (for /.git/HEAD, /.htpasswd, ...)."""
    return base64.urlsafe_b64encode(os.urandom(max(48, n // 4 * 3))).decode().rstrip("=").encode()


_BODY_MAKERS = {
    "env": _junk_env,
    "json": _junk_json,
    "html": _junk_html,
    "text": _junk_text,
}


# Bounded per-IP rate limiter. We use an OrderedDict so eviction is O(1) — the
# worst case (a /16 worth of attackers) only ever keeps the most-recent 4096
# IPs, which is plenty for triage + bounds the memory footprint forever.
class RateLimiter:
    def __init__(self, burst: int, window: float, cap: int = 4096):
        self._buckets: collections.OrderedDict[str, tuple[float, int]] = \
            collections.OrderedDict()
        self.burst = burst
        self.window = window
        self.cap = cap
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.pop(ip, None)
            if bucket is None:
                self._buckets[ip] = (now, 1)
                self._evict_lru()
                return True
            last, count = bucket
            elapsed = now - last
            # Leak the bucket — refill at 1/window per second.
            refilled = max(0, count - int(elapsed / self.window))
            if refilled >= self.burst:
                # Re-insert without changing the window head, so they stay capped.
                self._buckets[ip] = (last, self.burst)
                self._evict_lru()
                return False
            self._buckets[ip] = (now, refilled + 1)
            self._evict_lru()
            return True

    def _evict_lru(self):
        while len(self._buckets) > self.cap:
            self._buckets.popitem(last=False)


_LIMITER = RateLimiter(RL_BURST, RL_WINDOW)


class _Handler(http.server.BaseHTTPRequestHandler):
    """The whole tarpit. Default `do_GET` / `do_HEAD` / `do_POST` all funnel
    to `_respond` so the path detection runs regardless of method."""
    # http.server is chatty by default — silence the line-per-request log;
    # systemd journal already records our explicit log_message() calls.
    def log_request(self, code="-", size="-"):
        return

    # Override the Server header to drop the BaseHTTPServer/Python fingerprint.
    server_version = ""
    sys_version = ""

    def _client_ip(self) -> str:
        # Trust X-Forwarded-For only if running behind a known proxy — for the
        # kiosk's default (port 80 directly exposed) the socket peer is truth.
        return self.client_address[0] if self.client_address else "0.0.0.0"

    def _respond(self):
        ip = self._client_ip()
        path = self.path.split("?", 1)[0]
        if not _matches(path):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        if not _LIMITER.allow(ip):
            # Don't even bother replying: close the socket. Bot operators
            # waiting on a response time out — much slower than a 429.
            return
        # Drip — eat real scanner wall-clock.
        time.sleep(random.uniform(DRIP_MIN, DRIP_MAX))
        ctype, kind = _mime_for(path)
        size = random.randint(4 * 1024, 32 * 1024)
        body = _BODY_MAKERS[kind](size)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        sys.stderr.write(f"[tarpit] {ip} {self.command} {path} -> 200 ({len(body)}B)\n")
        sys.stderr.flush()

    def do_GET(self):  return self._respond()
    def do_HEAD(self): return self._respond()
    def do_POST(self): return self._respond()
    def do_PUT(self):  return self._respond()


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    # `daemon_threads = True` so a worker stuck mid-drip dies with the parent.
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    # Refuse to start if not explicitly opted in — defense in depth against an
    # operator who installed the unit but didn't mean to expose port 80.
    if os.environ.get("SOC_TARPIT_ENABLE", "0") != "1":
        sys.stderr.write("[tarpit] SOC_TARPIT_ENABLE=1 not set — exiting.\n")
        return 0
    try:
        srv = _Server((TARPIT_HOST, TARPIT_PORT), _Handler)
    except PermissionError:
        sys.stderr.write(f"[tarpit] cannot bind {TARPIT_HOST}:{TARPIT_PORT} "
                         f"(needs CAP_NET_BIND_SERVICE for port <1024)\n")
        return 1
    except OSError as e:
        sys.stderr.write(f"[tarpit] bind failed: {e}\n")
        return 1
    sys.stderr.write(f"[tarpit] listening on {TARPIT_HOST}:{TARPIT_PORT} "
                     f"(burst={RL_BURST}/{RL_WINDOW}s, drip={DRIP_MIN}-{DRIP_MAX}s)\n")
    try:
        srv.serve_forever(poll_interval=1.0)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
