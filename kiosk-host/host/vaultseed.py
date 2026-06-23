"""
Write a credential into Vaultwarden over its REST API.

So setup.py and the on-screen Settings can *store* usernames/passwords (and a
VPN config in Notes) in the vault — the kiosk still READS them via rbw. This is
the programmatic equivalent of adding a login in the web vault, generalised from
dev/seed-ciphers.py.

Needs the `cryptography` package (imported lazily). When it is absent, callers
get a VaultSeedError telling the operator to add the login in the web vault
instead — so this stays an optional convenience, never a hard dependency of the
running wall.

Supports PBKDF2 master-key KDF (Vaultwarden's default). An Argon2 vault raises a
clear error.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import urllib.parse
import urllib.request


class VaultSeedError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _ub64(s: str) -> bytes:
    return base64.b64decode(s)


def _hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def _aes():
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes)
        return Cipher, algorithms, modes
    except ImportError:
        raise VaultSeedError(
            "the 'cryptography' package is required to write into Vaultwarden — "
            "install it (pip install cryptography), or add the login in the "
            "Vaultwarden web vault instead")


def _enc(plaintext: bytes, ek: bytes, mk: bytes) -> str:
    Cipher, algorithms, modes = _aes()
    iv = os.urandom(16)
    pad = 16 - (len(plaintext) % 16)
    data = plaintext + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(ek), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    mac = hmac.new(mk, iv + ct, hashlib.sha256).digest()
    return f"2.{_b64(iv)}|{_b64(ct)}|{_b64(mac)}"


def _dec(s: str, ek: bytes, mk: bytes) -> bytes:
    Cipher, algorithms, modes = _aes()
    iv_b, ct_b, mac_b = s.split(".", 1)[1].split("|")
    iv, ct, mac = _ub64(iv_b), _ub64(ct_b), _ub64(mac_b)
    if not hmac.compare_digest(
            hmac.new(mk, iv + ct, hashlib.sha256).digest(), mac):
        raise VaultSeedError("MAC mismatch decrypting the account key")
    dec = Cipher(algorithms.AES(ek), modes.CBC(iv)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    return pt[:-pt[-1]]


def _req(url, headers=None, data=None, method="GET", form=False):
    h = dict(headers or {})
    body = None
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode()
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        raise VaultSeedError(f"{method} {url} -> HTTP {e.code}: "
                             f"{e.read().decode()[:200]}")
    except OSError as e:
        raise VaultSeedError(f"could not reach Vaultwarden at {url}: {e}")


class Session:
    """An authenticated Vaultwarden session that can create/update logins."""

    def __init__(self, url: str, email: str, master_password: str):
        self.base = url.rstrip("/")
        email = email.lower()
        pw = master_password.encode()

        pre = _req(self.base + "/identity/accounts/prelogin",
                   data={"email": email}, method="POST")
        kdf = int(pre.get("kdf", pre.get("Kdf", 0)) or 0)
        iters = int(pre.get("kdfIterations", pre.get("KdfIterations", 600000)) or 600000)
        if kdf != 0:
            raise VaultSeedError("this vault uses the Argon2 KDF — vaultseed "
                                 "supports PBKDF2 only; add the login in the web vault")

        master_key = hashlib.pbkdf2_hmac("sha256", pw, email.encode(), iters, 32)
        master_hash = _b64(hashlib.pbkdf2_hmac("sha256", master_key, pw, 1, 32))
        senc = _hkdf_expand(master_key, b"enc")
        smac = _hkdf_expand(master_key, b"mac")

        try:
            tok = _req(self.base + "/identity/connect/token", data={
                "grant_type": "password", "username": email, "password": master_hash,
                "scope": "api offline_access", "client_id": "cli", "deviceType": "8",
                "deviceIdentifier": "soc-setup-0001", "deviceName": "soc-setup",
            }, method="POST", form=True)
        except VaultSeedError as e:
            # Vaultwarden returns the same 400 invalid_grant for "no such account"
            # AND for "wrong password" (anti-enumeration). We can't tell from the
            # response which it is — so the operator gets BOTH options, including
            # the URL they need to register at if it's the missing-account case.
            if "HTTP 400" in str(e) or "HTTP 401" in str(e):
                raise VaultSeedError(
                    f"Vaultwarden rejected the login for '{email}'. Either the "
                    f"master password is wrong, or no account exists for that "
                    f"email — register at {self.base}/#/login (a kiosk install "
                    f"typically uses setup.py first-run, which can register the "
                    f"account for you).")
            raise
        if "Key" not in tok or "access_token" not in tok:
            raise VaultSeedError(
                f"Vaultwarden login for '{email}' returned an unexpected response. "
                f"If this is a fresh install with no account yet, register at "
                f"{self.base}/#/login or re-run setup.py first-run.")
        sym = _dec(tok["Key"], senc, smac)              # 64-byte account key
        self.ek, self.mk = sym[:32], sym[32:]
        self.auth = {"Authorization": f"Bearer {tok['access_token']}"}

    def _ciphers(self):
        r = _req(self.base + "/api/ciphers", headers=self.auth)
        return r.get("Data", r.get("data", []))

    def _find(self, name: str):
        for c in self._ciphers():
            enc_name = c.get("Name") or c.get("name")
            try:
                if enc_name and _dec(enc_name, self.ek, self.mk).decode() == name:
                    return c.get("Id") or c.get("id")
            except VaultSeedError:
                continue
        return None

    def upsert_login(self, name, username, password, notes=None, uri=None) -> str:
        """Create or update a login item named `name`. Returns 'created'|'updated'."""
        def e(s):
            return _enc(s.encode(), self.ek, self.mk)
        body = {
            "type": 1,
            "name": e(name),
            "favorite": False,
            "notes": e(notes) if notes else None,
            "login": {
                "username": e(username) if username else None,
                "password": e(password) if password else None,
                "uris": [{"uri": e(uri), "match": None}] if uri else None,
            },
        }
        cid = self._find(name)
        if cid:
            _req(self.base + f"/api/ciphers/{cid}", headers=self.auth,
                 data=body, method="PUT")
            return "updated"
        _req(self.base + "/api/ciphers", headers=self.auth, data=body, method="POST")
        return "created"

    def upsert_secure_note(self, name, notes, folder=None) -> str:
        """Create or update a Vaultwarden secure note (type=2). Used for items
        whose payload lives entirely in the Notes field — e.g. TOTP secrets,
        VPN config blocks parsed by fortivpn.py. Returns 'created'|'updated'.
        `folder` is ignored today (folder IDs need a separate folders API
        round-trip); planned for Phase 6 inventory grouping."""
        def e(s):
            return _enc(s.encode(), self.ek, self.mk)
        body = {
            "type": 2,
            "name": e(name),
            "favorite": False,
            "notes": e(notes) if notes else None,
            "secureNote": {"type": 0},
        }
        cid = self._find(name)
        if cid:
            _req(self.base + f"/api/ciphers/{cid}", headers=self.auth,
                 data=body, method="PUT")
            return "updated"
        _req(self.base + "/api/ciphers", headers=self.auth, data=body, method="POST")
        return "created"

    def delete_item(self, name) -> bool:
        """DELETE /api/ciphers/{id}. Returns True if a matching cipher was
        found + deleted, False if no item by that name. Raises on transport /
        auth errors (so a 5xx from Vaultwarden surfaces as a GUI 'delete
        failed; check journal')."""
        cid = self._find(name)
        if not cid:
            return False
        _req(self.base + f"/api/ciphers/{cid}", headers=self.auth,
             method="DELETE")
        return True


def upsert_login(url, email, master_password, name, username, password,
                 notes=None, uri=None) -> str:
    """One-shot: log in and create/update a Vaultwarden login. Returns the action."""
    return Session(url, email, master_password).upsert_login(
        name, username, password, notes=notes, uri=uri)


def upsert_secure_note(url, email, master_password, name, notes,
                       folder=None) -> str:
    """One-shot: log in and create/update a Vaultwarden secure note."""
    return Session(url, email, master_password).upsert_secure_note(
        name, notes, folder=folder)


def delete_login(url, email, master_password, name) -> bool:
    """One-shot: log in and delete a vault item by name. Returns True if
    deleted, False if nothing matched."""
    return Session(url, email, master_password).delete_item(name)


def account_exists(url: str, email: str, master_password: str) -> bool:
    """True if `email` + `master_password` opens a session against the vault at
    `url`. False on a 400/401 invalid_grant (no account OR wrong password — the
    API hides which). Other errors (vault unreachable, Argon2, network) propagate
    so the caller distinguishes 'no account' from 'cannot reach the vault'."""
    try:
        Session(url, email, master_password)
        return True
    except VaultSeedError as e:
        msg = str(e)
        # Session() wraps the invalid_grant into the long actionable message; the
        # token endpoint itself returns HTTP 400.
        if ("rejected the login" in msg or "no account exists" in msg
                or "HTTP 400" in msg or "HTTP 401" in msg):
            return False
        raise


def register_account(url: str, email: str, master_password: str,
                     kdf_iterations: int = 600000) -> None:
    """Create a Vaultwarden account at `url` for `email`/`master_password`.

    Requires `SIGNUPS_ALLOWED=true` to be set on the running Vaultwarden — the
    setup.py wrapper flips it on transiently via a systemd drop-in. Raises
    VaultSeedError on any failure; idempotent insofar as the caller should
    `account_exists()` first.

    Builds a minimal but spec-compliant Bitwarden registration payload:
      * sym key: 64 random bytes (32 enc + 32 mac), encrypted with the
        HKDF-stretched master_key — this is the user's account key.
      * RSA-2048 keypair for the org/share crypto, encrypted with sym.
      * masterPasswordHash: PBKDF2(master_key, password, 1).
    PBKDF2 KDF only (kdf=0) — Argon2 is not handled here.
    """
    Cipher, algorithms, modes = _aes()              # also raises if crypto missing
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    email = email.lower()
    pw = master_password.encode()
    master_key = hashlib.pbkdf2_hmac("sha256", pw, email.encode(), kdf_iterations, 32)
    master_hash = _b64(hashlib.pbkdf2_hmac("sha256", master_key, pw, 1, 32))
    senc = _hkdf_expand(master_key, b"enc")
    smac = _hkdf_expand(master_key, b"mac")

    sym = os.urandom(64)
    sym_enc = _enc(sym, senc, smac)

    rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = rk.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_der = rk.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    priv_enc = _enc(priv_der, sym[:32], sym[32:])

    body = {
        "email": email,
        "name": None,
        "masterPasswordHash": master_hash,
        "masterPasswordHint": None,
        "key": sym_enc,
        "kdf": 0,
        "kdfIterations": kdf_iterations,
        "keys": {
            "publicKey": _b64(pub_der),
            "encryptedPrivateKey": priv_enc,
        },
    }
    try:
        _req(url.rstrip("/") + "/identity/accounts/register",
             data=body, method="POST")
    except VaultSeedError as e:
        msg = str(e)
        if "HTTP 400" in msg and "Registration not allowed" in msg:
            raise VaultSeedError(
                "Vaultwarden refused registration — SIGNUPS_ALLOWED is not "
                "true. Drop in [Service] Environment=SIGNUPS_ALLOWED=true, "
                "restart vaultwarden, then retry. (setup.py first-run handles "
                "this automatically.)")
        if "HTTP 400" in msg and "already in use" in msg.lower():
            raise VaultSeedError(
                f"an account for '{email}' already exists in this vault — "
                f"use the existing master password, or remove the account.")
        raise


def available() -> bool:
    """True if the crypto backend needed to write is importable."""
    try:
        _aes()
        return True
    except VaultSeedError:
        return False
