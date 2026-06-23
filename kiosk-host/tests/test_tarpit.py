"""Scanner-deception tarpit: pure-helper tests (no socket bind)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
import tarpit                                       # noqa: E402


def test_matches_known_paths():
    for p in ("/admin.php", "/wp-login.php", "/.env",
              "/phpmyadmin/", "/wp-admin/admin-ajax.php",
              "/actuator/health", "/api/v1/login", "/.git/HEAD"):
        assert tarpit._matches(p), f"should match: {p}"


def test_does_not_match_real_app_paths():
    for p in ("/", "/index.html", "/healthz", "/static/app.js",
              "/login", "/api"):
        assert not tarpit._matches(p), f"should NOT match: {p}"


def test_mime_picks_plausible_type():
    assert tarpit._mime_for("/.env")[0].startswith("text/plain")
    assert tarpit._mime_for("/api/v1/foo")[0] == "application/json"
    assert tarpit._mime_for("/actuator/env")[0] == "application/json"
    assert tarpit._mime_for("/admin.php")[0].startswith("text/html")
    assert tarpit._mime_for("/.git/HEAD")[0].startswith("text/plain")


def test_junk_bodies_have_plausible_shape():
    env = tarpit._junk_env(400)
    assert b"=" in env and env.count(b"\n") >= 1
    j = tarpit._junk_json(400)
    assert j.startswith(b"{") and j.endswith(b"}")
    h = tarpit._junk_html(400)
    assert h.startswith(b"<!doctype html") and b"</body></html>" in h
    t = tarpit._junk_text(400)
    assert len(t) > 0 and b" " not in t              # base64-ish, no whitespace


def test_ratelimiter_caps_burst_then_leaks():
    import time
    rl = tarpit.RateLimiter(burst=3, window=0.05)
    assert [rl.allow("9.9.9.9") for _ in range(5)] == [True, True, True, False, False]
    time.sleep(0.12)                                # window passes
    # leaked at least one token
    assert rl.allow("9.9.9.9") is True


def test_ratelimiter_per_ip_independent():
    rl = tarpit.RateLimiter(burst=2, window=1.0)
    assert [rl.allow("1.1.1.1") for _ in range(2)] == [True, True]
    assert rl.allow("1.1.1.1") is False              # 1.1.1.1 capped
    assert rl.allow("2.2.2.2") is True               # 2.2.2.2 unaffected


def test_ratelimiter_bounded_capacity():
    rl = tarpit.RateLimiter(burst=1, window=60.0, cap=4)
    for i in range(20):
        rl.allow(f"10.0.0.{i}")
    assert len(rl._buckets) <= 4                     # LRU evicted older IPs
