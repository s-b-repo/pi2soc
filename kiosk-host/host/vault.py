"""
Credential access for the SOC kiosk host.

Reads logins from Vaultwarden via the `rbw` CLI. Unattended unlock uses a pinentry
wrapper that UNSEALS the host-bound master (scripts/pinentry-vault.py) — no
plaintext master password on disk.

Credentials are held only in a short-TTL in-RAM cache and never written to disk
by this process.
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from typing import Dict, Tuple


class VaultError(Exception):
    pass


def _tcp_reachable(url: str, timeout: float = 1.5) -> bool:
    """Cheap pre-flight: is something listening at `url`'s host:port? Used so
    `Vault.open()` can bail with 'Vaultwarden is not listening' instead of
    letting rbw produce an opaque 'connection refused' that obscures the cause."""
    import socket
    import urllib.parse
    try:
        u = urllib.parse.urlparse(url)
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if u.scheme == "https" else 8222)
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #
class RbwBackend:
    def __init__(self):
        self.email = os.environ.get("SOC_VAULT_EMAIL", "")
        self.url = os.environ.get("SOC_VAULT_URL", "")
        self.pinentry = os.environ.get("SOC_PINENTRY", "")
        self.interactive = os.environ.get("SOC_VAULT_INTERACTIVE", "0") == "1"

    def _rbw(self, *args, check=True, env=None) -> str:
        e = dict(os.environ)
        if env:
            e.update(env)
        try:
            r = subprocess.run(["rbw", *args], capture_output=True, text=True,
                               env=e, timeout=30)
        except FileNotFoundError:
            raise VaultError("rbw not found on PATH — install it (e.g. cargo install rbw)")
        except subprocess.TimeoutExpired:
            raise VaultError(f"rbw {' '.join(args)} timed out")
        if check and r.returncode != 0:
            raise VaultError(f"rbw {' '.join(args)} failed: {r.stderr.strip() or r.stdout.strip()}")
        return r.stdout.strip()

    def configure(self):
        """Idempotently point rbw at the right server / account / pinentry."""
        if self.email:
            self._rbw("config", "set", "email", self.email, check=False)
        if self.url:
            self._rbw("config", "set", "base_url", self.url, check=False)
        if self.pinentry:
            self._rbw("config", "set", "pinentry", self.pinentry, check=False)

    def unlock(self):
        # Bail early with an actionable error instead of letting rbw fail with
        # "invalid email" (when SOC_VAULT_EMAIL is empty) or "connection refused"
        # (when Vaultwarden is not listening). Both were silent prod-breakage
        # paths flagged by the audit: the wall booted, vault.open() failed, and
        # every panel just showed the unconfigured tile with no clue why.
        if not self.email:
            raise VaultError(
                "SOC_VAULT_EMAIL is empty — the wall cannot unlock the vault. "
                "Run 'sudo python3 setup.py wizard' (sets the email) followed "
                "by 'sudo python3 setup.py first-run' (seals the master + "
                "registers the Vaultwarden account).")
        if self.url and not _tcp_reachable(self.url):
            raise VaultError(
                f"Vaultwarden at {self.url} is not reachable — check "
                f"'systemctl status vaultwarden' (the wall needs the vault to "
                f"start, even with blank tiles, so the GUI can read/write "
                f"credentials at the glass).")
        self.configure()
        if self.interactive:
            # operator unlocks manually after boot; just make sure agent is up.
            self._rbw("unlocked", check=False)
            return
        # Non-interactive: pinentry wrapper supplies the master password.
        self._rbw("unlock")

    def sync(self):
        self._rbw("sync")

    def get(self, item: str) -> Tuple[str, str]:
        user = self._rbw("get", "--field", "username", item, check=False)
        password = self._rbw("get", item)
        if not password:
            raise VaultError(f"vault item '{item}' has no password (or not found)")
        return user, password

    def notes(self, item: str) -> str:
        """The item's Notes field (used to hold a VPN config — wg .conf / .ovpn —
        so its keys live in Vaultwarden instead of on disk). '' if empty.

        Callers that REQUIRE the notes (e.g. config_from_vault: true for the VPN)
        should call notes_required() instead — an empty Notes used as a config
        file silently fails downstream with a parser error that doesn't mention
        the vault."""
        out = self._rbw("get", "--field", "notes", item, check=False)
        if out:
            return out
        # secure-note items return the note as the main value
        return self._rbw("get", item, check=False)

    def notes_required(self, item: str, purpose: str = "") -> str:
        """notes() that RAISES on empty/missing — for callers that depend on the
        Notes field actually carrying content (e.g. openvpn/wireguard config
        from vault). `purpose` is interpolated into the error so the operator
        knows which feature is broken."""
        out = self.notes(item)
        if not out.strip():
            what = f" for {purpose}" if purpose else ""
            raise VaultError(
                f"vault item '{item}' has an empty Notes field{what} — "
                f"paste the .ovpn / .conf content into the Notes section of "
                f"that item in Vaultwarden (web UI or the ⚙ Credentials tab).")
        return out

    def delete(self, item: str) -> bool:
        """Delete a vault item via `rbw remove <item>`. Returns True on exit
        code 0; False otherwise. Used by the GUI's Remove buttons (VPN remove,
        Credentials-tab delete). Idempotent — a second call returns False
        because rbw exits non-zero when the item is already gone."""
        r = subprocess.run(["rbw", "remove", item], capture_output=True,
                           text=True, timeout=30)
        return r.returncode == 0

    def list_by_folder(self, folder: str) -> list:
        """Names of every item in the named folder (e.g. 'SOC Wall Auth').
        Returns [] if the folder is empty / does not exist / rbw fails — the
        Credentials tab uses this to discover items it doesn't track via
        panels.yaml. Uncached on purpose: the GUI calls it on demand."""
        # `rbw list --folder <name>` prints one item name per line.
        r = subprocess.run(["rbw", "list", "--folder", folder],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return []
        return [line.strip() for line in r.stdout.splitlines() if line.strip()]


def _make_backend():
    # Production-only: every credential comes from Vaultwarden via rbw. The legacy
    # JSON "dev" backend was removed; tests inject a fake backend onto Vault.backend.
    return RbwBackend()


# --------------------------------------------------------------------------- #
# Facade with TTL cache
# --------------------------------------------------------------------------- #
class Vault:
    def __init__(self, ttl: float = 30.0):
        self.backend = _make_backend()
        self.ttl = ttl
        self._cache: Dict[str, Tuple[float, Tuple[str, str]]] = {}
        self._lock = threading.Lock()      # creds()/prewarm run on worker threads
        self._ready = False

    def open(self):
        """Unlock + initial sync. Call once at startup."""
        self.backend.unlock()
        self.backend.sync()
        self._ready = True

    def ready(self) -> bool:
        return self._ready

    def _evict_expired_locked(self, now: float = None):
        """Drop expired entries so the cache can't grow unbounded over a 24/7 run
        and stale credentials don't linger in RAM past their TTL. Call under lock."""
        now = now if now is not None else time.time()
        for k in [k for k, (ts, _) in self._cache.items() if now - ts >= self.ttl]:
            self._cache.pop(k, None)

    def cached(self, item: str) -> bool:
        """True if a fresh credential is in the cache (no backend call needed)."""
        with self._lock:
            self._evict_expired_locked()
            hit = self._cache.get(item)
            return bool(hit and (time.time() - hit[0]) < self.ttl)

    def creds(self, item: str) -> dict:
        with self._lock:
            self._evict_expired_locked()
            hit = self._cache.get(item)
            if hit and (time.time() - hit[0]) < self.ttl:
                user, pw = hit[1]
                return {"user": user, "pass": pw}
        # fetch outside the lock — rbw is a subprocess; don't serialise all
        # callers (a duplicate fetch of the same item is harmless)
        user, pw = self.backend.get(item)
        with self._lock:
            self._cache[item] = (time.time(), (user, pw))
        return {"user": user, "pass": pw}

    def prewarm(self, items, log=None) -> int:
        """Fetch creds for many items in parallel (off the GTK thread) so each
        panel's first login is served from cache instead of blocking the UI on
        an rbw call. Per-item failures are logged, not raised."""
        from concurrent.futures import ThreadPoolExecutor
        uniq = [i for i in dict.fromkeys(items) if i]
        if not uniq:
            return 0

        def one(it):
            try:
                self.creds(it)
                return True
            except VaultError as e:
                if log:
                    log(f"prewarm '{it}': {e}")
                return False
        with ThreadPoolExecutor(max_workers=min(4, len(uniq))) as ex:
            return sum(1 for r in ex.map(one, uniq) if r)

    def notes(self, item: str) -> str:
        """Fetch the item's Notes field (not cached — read once at connect)."""
        return self.backend.notes(item)

    def invalidate(self, item: str = None):
        with self._lock:
            if item:
                self._cache.pop(item, None)
            else:
                self._cache.clear()

    def delete(self, item: str) -> bool:
        """Delete a vault item and invalidate its cache entry. Returns True
        on success; logs + returns False if the backend reports failure or
        raises (so callers can show a single 'delete failed' toast rather
        than a stack trace at the glass)."""
        try:
            ok = bool(self.backend.delete(item))
        except Exception as e:  # noqa: BLE001 — never crash the GUI on delete
            import logging
            logging.warning("vault.delete(%r) failed: %s", item, e)
            return False
        if ok:
            self.invalidate(item)
        return ok

    def list_by_folder(self, folder: str) -> list:
        """Names of every item in the named folder. Empty list on failure /
        unknown folder so the GUI can render an empty 'orphans' group."""
        try:
            return list(self.backend.list_by_folder(folder))
        except Exception as e:  # noqa: BLE001
            import logging
            logging.warning("vault.list_by_folder(%r) failed: %s", folder, e)
            return []
