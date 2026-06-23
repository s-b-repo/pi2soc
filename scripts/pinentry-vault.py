#!/usr/bin/env python3
"""
Assuan pinentry for rbw that returns the vault master password by UNSEALING the
host-bound secret (host/secretstore.py). This is what lets the wall self-unlock
Vaultwarden with no plaintext master password anywhere on disk (no .env).

rbw is pointed at it with:
    rbw config set pinentry /opt/soc-display/scripts/pinentry-vault.py

Production unseals the host-bound secret — there is no plaintext master anywhere
on disk. Only when nothing is sealed (dev / local seeding) does it fall back to
an explicit $SOC_VAULT_PASSWORD from the environment (never from prod soc.env).
"""
import os
import sys


def _master() -> str:
    # Production: the host-bound sealed secret is authoritative. We try it FIRST
    # so a sealed wall never reads a master from the environment.
    here = os.path.dirname(os.path.abspath(__file__))
    for base in (os.environ.get("SOC_ROOT", "/opt/soc-display"),
                 os.path.dirname(here)):
        cand = os.path.join(base, "kiosk-host")
        if os.path.isdir(cand):
            sys.path.insert(0, cand)
    sealed = False
    try:
        from host import secretstore
        sealed = secretstore.is_sealed()
        if sealed:
            return secretstore.unseal()
    except Exception as e:  # noqa: BLE001 — surface to rbw's stderr, fall through
        sys.stderr.write(f"pinentry-vault: cannot unseal host-bound master "
                         f"({e}). If you re-imaged or moved the SD card, "
                         f"re-run: sudo python3 setup.py first-run\n")
    # Dev / seeding only: an explicit env-provided master (never in prod soc.env).
    env_master = os.environ.get("SOC_VAULT_PASSWORD", "")
    if not env_master and not sealed:
        # Empty return would make rbw fail with a generic decryption error that
        # gives the operator zero idea WHY. Write a loud, actionable line to
        # stderr — rbw forwards pinentry stderr to the journal, so this lands
        # in `journalctl -u soc-wall`.
        sd = os.environ.get("SOC_SECRET_DIR") or "/etc/soc-display/secret"
        sys.stderr.write(
            f"pinentry-vault: NO sealed master in {sd} and SOC_VAULT_PASSWORD "
            f"is unset — the vault cannot be unlocked. Run:\n"
            f"    sudo python3 setup.py first-run\n"
            f"to seal the master password host-bound (one-time setup).\n")
    return env_master


def _enc(s: str) -> str:
    return s.replace("%", "%25").replace("\n", "%0A").replace("\r", "%0D")


def main() -> int:
    out = sys.stdout
    out.write("OK Pleased to meet you\n")
    out.flush()
    secret = None
    for line in sys.stdin:
        cmd = line.strip().split(" ", 1)[0].upper()
        if cmd == "GETPIN":
            if secret is None:
                secret = _master()
            out.write(f"D {_enc(secret)}\n")
            out.write("OK\n")
            out.flush()
        elif cmd == "BYE":
            out.write("OK\n")
            out.flush()
            return 0
        else:
            out.write("OK\n")
            out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
