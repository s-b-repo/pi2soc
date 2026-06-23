# p2soc — SOC Video Wall (Raspberry Pi 5)

Raspberry Pi 5 (1 GB) kiosk that boots into a 2x2 grid of browser windows showing SOC panels (Wazuh, Zabbix, etc.). Auto-logs in from a local Vaultwarden, self-heals crashed panels, reconnects VPN/tunnels.

## Project layout

```
kiosk-host/host/     Python kiosk host (PyGObject/WebKitGTK + Chromium/CDP)
kiosk-host/tests/    Unit tests (pytest)
config/              Panel configs (panels.yaml variants)
scripts/             Session startup, VPN, tunnel, pinentry helpers
dev/                 Dev harness: verify.sh, dummy panels, seed-ciphers
docs/                Architecture, config, deploy, security docs
inject/              login.js.tmpl — injected login bootstrap
security/            sysctl, nftables, sshd hardening
systemd/             Service units (vaultwarden, autossh, forti-vpn, autologin)
setup.py             Install tool (install/firstboot/wizard/doctor/repair/deploy/creds/first-run)
install.sh           Multi-distro package installer (apt/dnf/pacman/zypper/apk/xbps); called by setup.py
launch.sh            App entrypoint — run / --repair / first-time setup page (once)
systemd/soc-firstboot.service   tty1 oneshot: runs the setup page once on first boot
```

## Two tools

- **Install** (`sudo python3 setup.py`): OS packages (via `install.sh`) + services +
  optional PIN seal. `install.sh` is an internal helper, not a separate user-facing tool.
- **App** (`./launch.sh`): runs the wall; `--repair` diagnoses/fixes; the **first-time setup
  page** (screen preset + panels + PIN-if-unsealed) runs **once**, gated by the marker
  `/etc/soc-display/.configured`, on first `launch.sh` and on first Pi boot (soc-firstboot.service).
  `setup.py firstboot` is that page; `launch.sh --reconfigure` re-runs it.

## Build / test commands

```bash
make venv            # create .venv (system-site-packages for PyGObject) — used by tests
make test            # unit tests (no display needed)
make lint            # shell + python syntax check
make install         # install on the Pi (sudo bash install.sh)
make clean           # remove Python caches   ·   make distclean also drops .venv
```

This is a **production-only** tree — there is no dev simulation / dummy-panel
harness. Tests run against a fake in-memory vault (`kiosk-host/tests/conftest.py`),
never a real rbw/Vaultwarden.

## Key architecture

- **Renderer:** WebKitGTK primary, Chromium opt-in per panel (`engine: chromium`)
- **Login injection:** host-side (WebKit socCreds handler, Chromium CDP) — no extensions/brokers
- **Secrets:** all in Vaultwarden, master password sealed host-bound (AES-256-GCM, scrypt)
- **Config source of truth:** Vaultwarden secure-note (`SOC_CONFIG_VAULT_ITEM`), panels.yaml fallback
- **VPN:** `vpn.type: fortinet|openvpn|wireguard` — supervised, log-classifying, auto-reconnect
- **Display:** X11 (Openbox) or Wayland (cage/labwc), `SOC_SESSION=auto` fallback chain
- **No .env secrets:** soc.env is non-secret; vault master sealed under `$SOC_SECRET_DIR`

## Conventions

- Pure stdlib for setup.py (runs before venv)
- `config/panels.yaml` is the reference config (the wall's config lives in the
  Vaultwarden `SOC Wall Config` note in production; the file is the fallback)
- `.env` / `vaultwarden.env` contain actual secrets — NEVER commit (gitignored)
- rbw is the only vault backend; tests inject a fake backend (see conftest.py)
- Multi-distro: install.sh detects package manager; `SOC_SKIP_PACKAGES=1` for unsupported
- Non-systemd graceful: deploys files, prints manual steps
