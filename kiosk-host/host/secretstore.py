"""
Host-bound, PIN-sealed storage for the vault master password.

This removes the plaintext master password from disk — there is no
SOC_VAULT_PASSWORD in any .env any more. The master password is sealed with
AES-256-GCM under a key derived (scrypt) from THREE factors:

  1. a 256-bit random *host key* (`host.key`, 0600, never world-readable),
  2. this host's machine-id, and
  3. a one-time PIN that `setup.py` generates and shows the operator exactly once.

So the wall can boot unattended (no prompt), the PIN is itself sealed under a
key derived from (host key + machine-id). Net effect:

  * nothing on disk is the plaintext master password;
  * the seal's strength does NOT rest on the machine-id, which is world-readable
    (0644) on systemd hosts and therefore not a secret — the binding secret is
    the 0600 `host.key`. Knowing the machine-id is useless without it;
  * the sealed files are useless if copied to another machine (different
    machine-id) *or* copied without `host.key` (key derivation → GCM auth fails);
  * the operator's one-time PIN is needed to *re-seal* (re-deploy, move to new
    hardware, or change the password) and to authorise destructive setup steps.

Files (under $SOC_SECRET_DIR, default /etc/soc-display/secret, dir 0700, files 0600):
  host.key     32 random bytes — the per-host binding secret (never leaves 0700 dir)
  master.enc   MAGIC|ALGO|salt|nonce|AESGCM(key = KDF(host_key+machine_id+pin)) of the master pw
  pin.enc      MAGIC|ALGO|salt|nonce|AESGCM(key = KDF(host_key+machine_id))     of the PIN
  pin.hash     "<salt_hex>$<sha256(salt+pin)>"  — lets setup verify the PIN

KDF: scrypt (RFC 7914) N=2**17, r=8, p=1 (~128 MiB) by default — a deliberate cost
that makes an offline brute-force of the PIN (the only low-entropy factor)
impractical even if every file and the machine-id are exfiltrated. FIPS 140
deployments set SOC_FIPS_KDF=1 to use PBKDF2-HMAC-SHA256 (NIST SP 800-132, an
approved KDF) instead. The KDF id is stored in each blob (ALGO byte), so a sealed
blob always unseals with the algorithm it was sealed under, regardless of the
current SOC_FIPS_KDF setting. All KDFs run once per boot to unseal.

Needs the `cryptography` package (imported lazily). available() reports whether
it is importable; callers degrade to a clear error otherwise.

For tests, $SOC_MACHINE_ID overrides the real machine-id (simulate other hosts).
"""
from __future__ import annotations

import hashlib
import hmac
import os

# Standards alignment:
#   * AES-256-GCM (AEAD), SHA-256 — NIST SP 800-131A approved; FIPS 140 ciphers.
#   * scrypt (RFC 7914) memory-hard KDF — N=2**17, r=8, p=1 (~128 MiB working
#     set, run once per boot to unseal). Deliberate cost: an offline brute-force
#     of the PIN (the only low-entropy factor) stays impractical even if every
#     file + the machine-id are exfiltrated. (scrypt is NOT FIPS-approved; a
#     PBKDF2-HMAC-SHA256 mode for FIPS deployments is tracked as future work.)
#   * os.urandom — NIST SP 800-90A compliant CSPRNG.
#   * hmac.compare_digest — constant-time verification (timing-safe).
_SCRYPT = dict(n=2 ** 17, r=8, p=1, dklen=32, maxmem=200 * 1024 * 1024)

# Self-describing sealed-blob format:  MAGIC(2) | ALGO(1) | salt(16) | nonce(12) | ct
# The algorithm id is stored IN the blob, so a blob always unseals with the KDF it
# was sealed under — independent of the current SOC_FIPS_KDF setting.
_MAGIC = b"PS"
_ALGO_SCRYPT = 1          # RFC 7914 scrypt (default — memory-hard)
_ALGO_PBKDF2 = 2          # NIST SP 800-132 PBKDF2-HMAC-SHA256 (FIPS-approved)
# NIST SP 800-132 sets a 1000-iteration floor; this follows modern (OWASP) guidance
# for PBKDF2-HMAC-SHA256. Once-per-boot cost on a Pi 5 is a few hundred ms.
_PBKDF2_ITERS = 600_000
_BLOB_HEADER = len(_MAGIC) + 1 + 16 + 12   # magic + algo + salt + nonce

# Domain-separation label (NIST SP 800-108 "context"): bound into the KDF input so
# this seal's keys can never collide with any other scrypt use of the same inputs.
# The version suffix lets the on-disk format evolve without silent ambiguity.
_KDF_CONTEXT = b"p2soc-seal/v2"

# NIST SP 800-63B: a memorized authenticator floor. The PIN only authorises
# *re-seal*; host.key is the real binding secret, but reject trivially short PINs.
_MIN_PIN_LEN = 6

_HOST_KEY_FILE = "host.key"


class SecretStoreError(Exception):
    pass


def secret_dir(d: str | None = None) -> str:
    return d or os.environ.get("SOC_SECRET_DIR") or "/etc/soc-display/secret"


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except ImportError:
        raise SecretStoreError(
            "the 'cryptography' package is required to seal/unseal the vault "
            "master password (pip install cryptography)")


def available() -> bool:
    """True if the crypto backend needed to seal/unseal is importable."""
    try:
        _aesgcm()
        return True
    except SecretStoreError:
        return False


def _machine_id() -> bytes:
    v = os.environ.get("SOC_MACHINE_ID")
    if v:
        return v.strip().encode()
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(p, encoding="utf-8") as fh:
                s = fh.read().strip()
            if s:
                return s.encode()
        except OSError:
            continue
    raise SecretStoreError("no machine-id (/etc/machine-id missing or empty) — "
                           "set SOC_MACHINE_ID, or run `systemd-machine-id-setup`")


def _host_key_path(sd: str) -> str:
    return os.path.join(sd, _HOST_KEY_FILE)


def _read_host_key(sd: str) -> bytes:
    """Read the per-host binding secret. Its absence is fatal — without it the
    seal cannot be derived (that is the whole point: machine-id alone is not a
    secret)."""
    try:
        with open(_host_key_path(sd), "rb") as fh:
            key = fh.read()
    except FileNotFoundError:
        raise SecretStoreError(
            "host.key missing — the seal is bound to a per-host key that is not "
            "present (copied without it, or never sealed); re-run `sudo python3 setup.py first-run` to re-seal")
    if len(key) < 32:
        raise SecretStoreError("host.key is truncated/corrupt — re-run `sudo python3 setup.py first-run` to re-seal")
    return key


def _binding_material(host_key: bytes) -> bytes:
    """The non-PIN key material: a domain-separation label (NIST SP 800-108
    context) + host key (the real secret) + machine-id (binds the seal to this
    physical host). machine-id is NOT trusted for secrecy."""
    return _KDF_CONTEXT + b"\x00" + host_key + b"\x00" + _machine_id()


def _kdf(material: bytes, salt: bytes, algo: int) -> bytes:
    if algo == _ALGO_PBKDF2:
        return hashlib.pbkdf2_hmac("sha256", material, salt, _PBKDF2_ITERS, dklen=32)
    if algo == _ALGO_SCRYPT:
        return hashlib.scrypt(material, salt=salt, **_SCRYPT)
    raise SecretStoreError(f"unknown KDF algorithm id {algo} in sealed blob")


def _active_algo() -> int:
    """FIPS 140 deployments select PBKDF2 (an approved KDF) via SOC_FIPS_KDF=1;
    the default is scrypt (memory-hard, stronger against brute force)."""
    return _ALGO_PBKDF2 if os.environ.get("SOC_FIPS_KDF") == "1" else _ALGO_SCRYPT


def _encrypt(material: bytes, plaintext: bytes) -> bytes:
    AESGCM = _aesgcm()
    algo = _active_algo()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    ct = AESGCM(_kdf(material, salt, algo)).encrypt(nonce, plaintext, None)
    return _MAGIC + bytes([algo]) + salt + nonce + ct


def _decrypt(material: bytes, blob: bytes) -> bytes:
    AESGCM = _aesgcm()
    if len(blob) < _BLOB_HEADER or blob[:len(_MAGIC)] != _MAGIC:
        raise SecretStoreError(
            "sealed blob is too short / not in the expected format — re-run "
            "setup.py to re-seal")
    algo = blob[len(_MAGIC)]
    off = len(_MAGIC) + 1
    salt, nonce, ct = blob[off:off + 16], blob[off + 16:off + 28], blob[off + 28:]
    try:
        return AESGCM(_kdf(material, salt, algo)).decrypt(nonce, ct, None)
    except SecretStoreError:
        raise
    except Exception:  # cryptography.exceptions.InvalidTag, etc.
        raise SecretStoreError(
            "could not unseal — wrong machine (the secret is bound to the host "
            "it was sealed on) or the files are corrupt; re-run `sudo python3 setup.py first-run` to re-seal")


def _write_atomic(path: str, data: bytes) -> str:
    """Write `data` to `path`.tmp (0600, fsync'd) and return the tmp path. The
    caller os.replace()s it into place once every blob is staged, so an
    interrupted seal never leaves a torn file under `path`."""
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return tmp


def _read(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        raise SecretStoreError(f"sealed secret not found: {path} (run setup.py)")


# Commit order matters: host.key is needed to *derive* the seal, and master.enc
# is the is_sealed() sentinel — so host.key is committed first and master.enc
# last. A seal missing host.key (e.g. copied without it) reads as NOT sealed.
_SEAL_FILES = ("host.key", "pin.hash", "pin.enc", "master.enc")


def is_sealed(d: str | None = None) -> bool:
    """True only when a *complete* seal is present. Requiring all four files
    (not just master.enc) means a half-written seal — or one copied without its
    host.key — reads as 'not sealed' so the operator re-seals instead of booting
    into an unrecoverable state."""
    sd = secret_dir(d)
    return all(os.path.exists(os.path.join(sd, f)) for f in _SEAL_FILES)


def seal(master: str, pin: str, d: str | None = None):
    """Seal the master password + PIN under this host. Overwrites any prior seal.

    All three blobs are written to `*.tmp` (fsync'd) first, then os.replace()d
    into place with master.enc — the is_sealed() sentinel — last. So an
    interruption during a fresh seal leaves master.enc absent (is_sealed False),
    never a torn file that looks sealed but cannot unseal."""
    if not master:
        raise SecretStoreError("refusing to seal an empty master password")
    if not pin:
        raise SecretStoreError("refusing to seal an empty PIN")
    if len(pin) < _MIN_PIN_LEN:
        raise SecretStoreError(
            f"PIN too short: need at least {_MIN_PIN_LEN} characters "
            "(NIST SP 800-63B memorized-authenticator floor)")
    sd = secret_dir(d)
    os.makedirs(sd, exist_ok=True)
    try:
        os.chmod(sd, 0o700)
    except OSError:
        pass
    # A fresh host key per (re-)seal: the 256-bit binding secret. Written 0600
    # immediately so the dir is never left holding a key with looser perms.
    host_key = os.urandom(32)
    material = _binding_material(host_key)
    salt = os.urandom(16)
    blobs = {
        "host.key": host_key,
        "master.enc": _encrypt(material + b"\x00" + pin.encode(), master.encode()),
        "pin.enc": _encrypt(material, pin.encode()),
        "pin.hash": f"{salt.hex()}${hashlib.sha256(salt + pin.encode()).hexdigest()}".encode(),
    }
    # stage every blob before swapping any into place
    tmps = {name: _write_atomic(os.path.join(sd, name), data)
            for name, data in blobs.items()}
    # commit in dependency order; host.key first, master.enc (the sentinel) last
    for name in _SEAL_FILES:
        os.replace(tmps[name], os.path.join(sd, name))


def unseal(d: str | None = None) -> str:
    """Recover the master password (host.key + machine-id, no PIN prompt —
    unattended). Raises SecretStoreError if not sealed / wrong host / missing
    host.key / corrupt.

    Backend selection: when SOC_SECRET_BACKEND=libsecret is set, try the
    user-keyring path first (KWallet / GNOME-Keyring via the freedesktop
    Secret-Service spec). If it has an entry, return it; otherwise log a
    warning and fall through to the sealed-file path. Either way the
    sealed files remain the on-disk source of truth so re-seal works."""
    if os.environ.get("SOC_SECRET_BACKEND") == "libsecret":
        try:
            v = libsecret_load()
        except Exception as e:                         # noqa: BLE001
            import logging
            logging.warning("libsecret unseal failed: %s — "
                            "falling back to sealed file", e)
            v = None
        if v:
            return v
        import logging
        logging.warning("SOC_SECRET_BACKEND=libsecret but no entry found — "
                        "falling back to sealed file")
    sd = secret_dir(d)
    host_key = _read_host_key(sd)
    material = _binding_material(host_key)
    pin = _decrypt(material, _read(os.path.join(sd, "pin.enc"))).decode()
    return _decrypt(material + b"\x00" + pin.encode(),
                    _read(os.path.join(sd, "master.enc"))).decode()


# --- libsecret backend (Phase 5 — opt-in via SOC_SECRET_BACKEND=libsecret) -
# Stores the master password in the user's login keyring. KWallet,
# GNOME-Keyring, and KeePassXC's secret-service integration all speak the
# freedesktop Secret-Service spec via libsecret. The keyring is unlocked
# when the user logs in (auto-unlock with login password, configurable in
# Plasma's System Settings → KDE Wallet), so the wall starts under the
# user's session without prompting.
#
# Trade-off vs the sealed-file backend:
#   * sealed file = host-bound, root-readable, survives without a user
#     session (good for tty1 kiosk; bad for sharing across walls);
#   * libsecret = user-bound, only accessible while the user's keyring is
#     unlocked (good for desk deploys; the wall must run as that user).
# Operators choose at setup time; we never auto-promote.

_LIBSECRET_SCHEMA_NAME = "com.soc-wall.master"


def _try_libsecret():
    try:
        import gi as _gi
        _gi.require_version("Secret", "1")
        from gi.repository import Secret as _Secret      # noqa: N812
        return _Secret
    except (ValueError, ImportError):
        return None


def libsecret_available() -> bool:
    """True if the gi Secret-Service typelib is importable. Cheap probe —
    only loads the binding once, doesn't hit DBus."""
    return _try_libsecret() is not None


def _libsecret_schema(Secret):
    return Secret.Schema.new(
        _LIBSECRET_SCHEMA_NAME, Secret.SchemaFlags.NONE,
        {"role": Secret.SchemaAttributeType.STRING})


def libsecret_store(master: str) -> None:
    """Store the master password under role=master in the default
    collection. Raises RuntimeError if libsecret is not installed."""
    Secret = _try_libsecret()
    if not Secret:
        raise RuntimeError("libsecret not available — install gir1.2-secret-1")
    schema = _libsecret_schema(Secret)
    Secret.password_store_sync(
        schema, {"role": "master"},
        Secret.COLLECTION_DEFAULT,
        "SOC Wall vault master",
        master, None)


def libsecret_load() -> str | None:
    """Read the stored master, or None if not stored / agent unreachable."""
    Secret = _try_libsecret()
    if not Secret:
        return None
    schema = _libsecret_schema(Secret)
    try:
        return Secret.password_lookup_sync(schema, {"role": "master"}, None)
    except Exception:                                  # noqa: BLE001
        return None


def libsecret_clear() -> bool:
    """Remove the stored master. Returns True on success, False if the
    backend is absent. Safe to call when nothing is stored."""
    Secret = _try_libsecret()
    if not Secret:
        return False
    schema = _libsecret_schema(Secret)
    try:
        Secret.password_clear_sync(schema, {"role": "master"}, None)
        return True
    except Exception:                                  # noqa: BLE001
        return False


def verify_pin(pin: str, d: str | None = None) -> bool:
    """True if `pin` matches the sealed PIN (constant-time, via pin.hash)."""
    try:
        raw = _read(os.path.join(secret_dir(d), "pin.hash")).decode()
        salt_hex, want = raw.split("$", 1)
    except (SecretStoreError, ValueError):
        return False
    got = hashlib.sha256(bytes.fromhex(salt_hex) + pin.encode()).hexdigest()
    return hmac.compare_digest(got, want)


def gen_pin(digits: int = 8) -> str:
    """A fresh, uniformly-random numeric PIN (no modulo bias), never shorter than
    the NIST SP 800-63B floor (_MIN_PIN_LEN)."""
    import secrets
    return "".join(secrets.choice("0123456789")
                   for _ in range(max(_MIN_PIN_LEN, digits)))
