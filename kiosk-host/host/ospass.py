"""
Verify an operator's OPERATING-SYSTEM password — separate from the wall's
own PIN / TOTP gates.

Why this exists: the password-manager Edit flow (read+modify an existing
vault item) is more sensitive than Delete. Delete needs the wall PIN/TOTP
because the operator who set the PIN clearly has physical access. Edit
hands the operator a STORED CREDENTIAL — which is the worst possible
data class for a stolen PIN to leak.

So Edit is gated by the same authentication the box uses to grant root /
unlock the session: the operator's local UNIX password. A local-only
attacker with the PIN still gets nothing without that.

Three backends are tried in order:

  1. python3-pam — the cleanest path. Two import shapes are accepted:
     `import pam; pam.pam().authenticate(user, pw)`  (python3-pam, Debian)
     `import pam; pam.authenticate(user, pw)`        (python-pam < 1.8)
  2. `pamtester` CLI — a small standalone wrapper around pam_authenticate.
     `echo -n PASS | pamtester -v login USER authenticate`
  3. `su` subprocess — universal Unix fallback. `su -c true USER` with the
     password on stdin. Returns 0 on auth success.

Every backend returns ONLY a bool. We never store / log / display the
entered password; the variable goes out of scope at function return.
"""
from __future__ import annotations

import logging
import os
import pwd
import shutil
import subprocess
import time
from typing import Optional


_log = logging.getLogger("soc.ospass")


def operator_user() -> str:
    """The OS user whose password Edit should validate against.

    Resolution order:
      1. SOC_OPERATOR_USER env var (explicit operator config, recommended).
      2. SUDO_USER (set by sudo — the user who launched the wall).
      3. The kali / pi / debian conventional desktop users, if they exist.
      4. The wall's own running user (usually `soc`) — last resort, will
         only authenticate if that user has a password set.

    Never raises; always returns a non-empty string."""
    for var in ("SOC_OPERATOR_USER", "SUDO_USER"):
        v = os.environ.get(var, "").strip()
        if v and _user_exists(v):
            return v
    for guess in ("kali", "pi", "operator", "admin", "debian"):
        if _user_exists(guess):
            return guess
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return "root"


def _user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def verify_os_password(user: str, password: str,
                       *, timeout: float = 5.0) -> bool:
    """Returns True iff `password` is `user`'s current OS login password.

    Never raises. Constant-time wall-clock: every backend takes at least
    `_MIN_LATENCY_SEC` seconds so wrong-vs-right can't be distinguished by
    response timing (PAM modules vary, su is fast)."""
    if not user or not password:
        return False
    start = time.monotonic()
    try:
        for backend in (_verify_via_pam,
                        _verify_via_pamtester,
                        _verify_via_su):
            try:
                rv = backend(user, password, timeout=timeout)
            except Exception as e:                       # noqa: BLE001
                _log.debug("ospass backend %s raised: %s",
                           backend.__name__, e)
                rv = None
            if rv is None:
                continue                                 # backend unusable
            return bool(rv)
        _log.warning("no OS-password verifier available "
                     "(python3-pam, pamtester, or su)")
        return False
    finally:
        elapsed = time.monotonic() - start
        if elapsed < _MIN_LATENCY_SEC:
            time.sleep(_MIN_LATENCY_SEC - elapsed)


_MIN_LATENCY_SEC = 0.30


def _verify_via_pam(user: str, password: str, *, timeout: float):
    """python3-pam path. Returns True/False on a real attempt; None if the
    binding is unavailable."""
    try:
        import pam as _pam                              # type: ignore
    except ImportError:
        return None
    # Two API shapes exist; try both.
    if hasattr(_pam, "pam"):
        try:
            p = _pam.pam()
            return bool(p.authenticate(user, password, service="login"))
        except TypeError:
            return bool(p.authenticate(user, password))
    if hasattr(_pam, "authenticate"):
        try:
            return bool(_pam.authenticate(user, password, service="login"))
        except TypeError:
            return bool(_pam.authenticate(user, password))
    return None


def _verify_via_pamtester(user: str, password: str, *, timeout: float):
    """pamtester CLI. Returns True/False on a real attempt; None if the
    binary isn't installed."""
    if not shutil.which("pamtester"):
        return None
    try:
        r = subprocess.run(
            ["pamtester", "login", user, "authenticate"],
            input=password,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def _verify_via_su(user: str, password: str, *, timeout: float):
    """su subprocess fallback. Returns True/False on a real attempt; None
    if su itself can't be found (extremely unlikely on Linux)."""
    if not shutil.which("su"):
        return None
    # `su - <user> -c true` reads the password on stdin via PAM when no
    # tty is attached. Works on every Linux distro tested. Returns 0 on
    # success, non-zero on auth failure (and on other errors, which we
    # conservatively treat as auth failure).
    try:
        r = subprocess.run(
            ["su", "-", user, "-c", "true"],
            input=password + "\n",
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0
