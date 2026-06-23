# Full setup guide

This is the single, start-to-finish walkthrough for bringing up the SOC video
wall on a **Raspberry Pi** (production). It ties together the `setup.py` installer,
the first-launch setup page, and the manual steps, and covers the autossh
**tunnel** and the Fortinet **VPN**.

For deep dives see [ARCHITECTURE](ARCHITECTURE.md), [CONFIGURATION](CONFIGURATION.md),
[INSTALL](INSTALL.md), and [SECURITY](SECURITY.md). This page is the map.

---

## 0. What you're building

Four browser windows in a 2×2 grid, each auto-logging into a different web panel
using credentials from a local **Vaultwarden** vault. Panels can be reached
directly, through an **SSH jump host** (autossh `-L`), or across a **Fortinet
SSL-VPN** (openfortivpn). Everything starts on boot and self-heals.

You will produce three files:

| File | Purpose | Where (Pi) |
|---|---|---|
| `panels.yaml` | the 4 panels + `tunnel` + `vpn` | `/etc/soc-display/panels.yaml` |
| `soc.env` | vault settings (email/url) + paths — **non-secret** | `/etc/soc-display/soc.env` |
| _(Vaultwarden)_ | server config inline in its systemd unit — **no `.env`** | `systemd/vaultwarden*.service` |

The **interactive wizard writes all three for you**. You can also write them by
hand from the `*.example` templates.

Two more things live outside these files: the vault **master password** is sealed
host-bound under `/etc/soc-display/secret/` (`setup.py first-run`, no plaintext
`.env`), and in production the wall **config is pushed into the Vaultwarden
`SOC Wall Config` note** (the source of truth; `panels.yaml` is the fallback).

---

## 1. The fast path: two tools

There are two tools. **`setup.py` installs** (OS packages + services, via `install.sh`,
plus an optional PIN seal). **`launch.sh` is the app** — it runs the wall, and the very
first run walks through a one-time **setup page** (screen preset + panels, and the vault
PIN if it was not sealed at install). After that the wall launches straight away; the page
is gated by the marker `/etc/soc-display/.configured` and re-run with `launch.sh --reconfigure`.

```bash
# Install (once, as root) — OS packages + services; the wall configures itself on first launch
sudo python3 setup.py             # the install tool (asks before doing anything)
sudo python3 setup.py --fresh     # force a full OS package reinstall

# Run the wall (the app)
./launch.sh                       # run; the FIRST run shows the setup page once, then launches
./launch.sh --setup               # run the first-time setup page now, then exit
./launch.sh --reconfigure         # re-run the setup page, then launch
./launch.sh --repair              # diagnose + fix this install (setup.py doctor/repair)

# setup.py subcommands (also via `python3 setup.py menu`)
python3 setup.py firstboot        # the once-only first-launch setup page (screen + panels + seal-if-needed)
python3 setup.py deploy           # all-in-one: install → configure → seal PIN → creds → check
python3 setup.py deploy --clean   # wipe generated config/state first, then deploy fresh
python3 setup.py wizard           # just the configuration wizard
python3 setup.py first-run        # generate the one-time PIN + seal the master password
python3 setup.py doctor           # diagnose            python3 setup.py repair   # fix what doctor flags
python3 setup.py --dry-run        # show what it would write, write nothing
python3 setup.py --defaults       # accept every default (non-interactive)
python3 setup.py --section vpn    # one section: display|panels|tunnel|vpn|proxy|vault|server
```

It writes to `/etc/soc-display` (needs root/sudo). Re-running
loads your previous answers as the defaults, and every file is backed up
(`*.bak.<timestamp>`) before it's overwritten.

The seven sections:

1. **Display** — screen size as a **preset** (1080p / 1440p / 4K / 720p), **auto**-detect
   at launch, or a **custom** width × height; the grid (cols × rows, gap); and the
   `layout` (auto/windows/single).
2. **Panels** — per panel: id, engine (`webkit`/`chromium`), grid cell, `direct`
   vs `tunnel`, URL or tunnel forward, `vault_item`, login **selectors**,
   `login_marker`, keep-alive. For `direct` panels the wizard **probes the URL
   and auto-detects the selectors + login type**, so you usually just confirm
   *“Use these detected selectors? [Y]”*. See the
   [wizard walkthrough](WIZARD.md) for every prompt, with examples.
3. **Tunnel** — autossh jump host + identity key (asked when any panel is tunneled).
4. **VPN** — Fortinet gateway, `vault_item`, cert pinning (can fetch the digest
   for you), routing/DNS, supervisor reconnect + liveness check, optional TOTP.
5. **Proxy** — optional outbound HTTP(S)/SOCKS proxy: URL, the vault login holding
   its credentials (in-memory auth), and hosts to bypass.
6. **Vault** — account email/URL, the secret dir + config-note name, and the
   session backend (rbw → Vaultwarden). The master password is **not**
   entered here — it is sealed later by `first-run` (one-time PIN).
7. **Server** — Vaultwarden bind + admin token (can generate the argon2 hash).

> **Selectors are not credentials.** The selector prompts ask *where* the login
> boxes are on the page (`#name`, `#password`) — **not** your username/password,
> which go into the Vaultwarden `vault_item` (stored with `setup.py creds`).
> The wizard auto-detects the selectors from the URL, so usually you just press
> Enter at *“Use these detected selectors?”*. `login_marker` is the wall's
> "logged out?" detector — a selector seen **only** on the login page (the
> password box is perfect, and the suggested default). Full prompt-by-prompt
> detail with examples: **[the wizard walkthrough](WIZARD.md)** (see also
> [CONFIGURATION.md](CONFIGURATION.md#finding-selectors)).

> **Don't have the panel details yet? Skip them.** Answer **n** to *“Configure
> panels now?”* (or per panel) to install with blank *click-to-configure* tiles,
> then set each tile's **URL, vault login _and_ credentials** — plus the
> **VPN**, **proxy**, **SSH tunnel jump host**, **grid size**, and
> **resolution** — from the running wall's **⚙ settings window** (corner gear /
> **Ctrl+Shift+C**). No SSH, no file editing. See
> [Configure at the glass](WIZARD.md#configure-at-the-glass-no-wizard-needed).

After it writes the files it runs a parse + geometry check, so you'll know
immediately if anything is off.

For production the order is: **`sudo python3 setup.py`** (install) → first boot (or
`./launch.sh`), which runs the **first-time setup page** once — the wizard, the one-time
PIN seal if it was not done at install, and the push of the config into the Vaultwarden
`SOC Wall Config` note (the boot source of truth). On the Pi the page runs automatically
on tty1 the first time (`soc-firstboot.service`) and never again. **`setup.py deploy`**
still chains the installer, wizard, sealing, and credential storage in one pass for a
hands-on, all-at-once install.

---

## 2. Testing the tooling (any Linux box)

The unit tests run anywhere — no Pi, no display, no Vaultwarden (they use a fake
in-memory vault, `kiosk-host/tests/conftest.py`):

```bash
make venv     # build .venv (PyYAML, websocket-client, pytest, cryptography)
make test     # unit tests (config, injection, vault facade, VPN supervisor, proxy, perf)
make lint     # shell + python syntax check
```

---

## 3. Raspberry Pi walkthrough (production)

Target: **Raspberry Pi 5 (1 GB+)**, Raspberry Pi OS 64-bit (Bookworm), HDMI
monitor. The installer keeps your card and just **disables the desktop session**
(reversible).

### 3.1 Prepare

1. Flash/boot Raspberry Pi OS 64-bit, enable SSH, connect to the network.
2. Copy this repo to the Pi (`scp -r p2soc pi@<ip>:` or `git clone`), then SSH in.

### 3.2 Configure, then install

You can configure **before or after** running the installer — the installer
preserves any `/etc/soc-display/*` you already wrote.

```bash
cd p2soc
sudo python3 setup.py deploy     # end-to-end: install → configure → seal PIN → push config → creds → doctor
# …or do the two main steps by hand:
sudo python3 setup.py            # menu → Configure (panels.yaml + soc.env)
sudo ./install.sh                # deps, users, /opt/soc-display, systemd units, zram, autologin
```

Installer knobs (env): `VW_MODE=docker|native`, `HARDEN=1` (nftables + key-only
sshd), `KIOSK_USER=soc`, `SVC_USER=socsvc`. It is **idempotent**.

The installer auto-enables `autossh-tunnel.service` only if a panel uses
`mode: tunnel`, and `forti-vpn.service` only if `vpn.enabled` has a gateway.

### 3.3 Create the vault account + add logins

```bash
sudo systemctl start vaultwarden
```

Open the web vault over an SSH tunnel for safety:

```bash
ssh -L 8222:127.0.0.1:8222 pi@<ip>     # then browse http://127.0.0.1:8222
```

Create the kiosk account (matching `SOC_VAULT_EMAIL`), then add **one login item
per panel, named exactly to match its `vault_item`**. If the VPN is enabled, also
add a login named to match **`vpn.vault_item`** holding the FortiGate username +
password. Turn signups back off afterwards (it's a systemd drop-in now — no `.env`).

Then seal the master password (skip if you ran `setup.py deploy`):

```bash
sudo python3 setup.py first-run   # one-time PIN + host-bound seal (no plaintext .env)
```

The wall config is stored in the Vaultwarden `SOC Wall Config` note — the source
of truth at boot; the local `panels.yaml` is only the offline fallback.

### 3.4 Tunnel key (if any panel uses `mode: tunnel`)

Generate a dedicated, restricted ed25519 key and authorize it on the jump host
with `restrict,permitopen="host:port",…`. Full steps in
[`security/tunnel_key.note`](../security/tunnel_key.note). Point `tunnel.identity`
at the key.

### 3.5 Fortinet VPN (if `vpn.enabled`)

Set the `vpn` section (the wizard does this). Pin the gateway certificate —
`setup.py` can fetch the digest, or:

```bash
openssl s_client -connect vpn.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 | sed 's/.*=//;s/://g' | tr A-Z a-z
```

On first start, `forti-vpn.service` unlocks root's `rbw` via the same host-bound
sealed secret + `pinentry-vault.py` as the kiosk host (no plaintext password) and
connects. The FortiGate password
is fed to openfortivpn via a pinentry helper — **never on the command line or
disk**. Watch it:

```bash
sudo systemctl status forti-vpn
journalctl -u forti-vpn -f          # should reach "connecting to <gateway>"
ip a show ppp0                      # has an address once connected
```

Routing note: accepting all gateway routes can pull your LAN/SSH path over the
VPN. Use `half_internet_routes: true` or `set_routes: false` to keep your own
default route, and `set_dns: false` to keep your resolver. See
[CONFIGURATION.md](CONFIGURATION.md#vpn-fortinet--fortigate-ssl-vpn).

### 3.6 Calibrate the monitor (if not 1920×1080)

```bash
sudo -u soc /opt/soc-display/.venv/bin/python \
  /opt/soc-display/scripts/gen-openbox-rc.py \
  --panels /etc/soc-display/panels.yaml \
  --template /opt/soc-display/openbox/rc.xml.tmpl \
  --out ~soc/.config/openbox/rc.xml --width <W> --height <H>
```

### 3.7 Reboot

```bash
sudo systemctl reboot
```

The wall comes up automatically: tty1 → `startx` → Openbox → four logged-in
panels, hands-free.

---

## 4. Bring-up checklist

- [ ] `systemctl status vaultwarden` active; `curl 127.0.0.1:8222/alive` → 200
- [ ] `journalctl _UID=$(id -u soc)` shows `[pN] injected login` for all panels
- [ ] `systemctl status autossh-tunnel` active (if tunnels) and `nc -z 127.0.0.1 191xx`
- [ ] `systemctl status forti-vpn` active (if VPN) and `ip a show ppp0` has an address
- [ ] each VPN-side panel host answers from the Pi (`nc -z <host> <port>`)
- [ ] `zramctl` shows an active zram swap device
- [ ] no credentials appear in `journalctl` (incl. `journalctl -u forti-vpn`)
- [ ] the master password is **sealed** (`setup.py first-run`); the one-time PIN is recorded off-device

---

## 5. Changing things later

Re-run the wizard (it loads your current answers as defaults):

```bash
python3 setup.py                 # all sections
python3 setup.py --section panels   # just edit the panels
python3 setup.py --section vpn      # just edit the VPN
```

> In production the wall reads its config from the Vaultwarden `SOC Wall Config`
> note, so after a local edit re-push it with `sudo python3 setup.py deploy` — or
> edit live from the on-screen ⚙ Settings, which writes changes back to the note
> automatically.

Then restart the host without rebooting (the launcher loop restarts it):

```bash
sudo pkill -f host.main
# tunnel / VPN service changes:
sudo systemctl restart autossh-tunnel forti-vpn
```

---

## 6. Troubleshooting

| Symptom | Where to look |
|---|---|
| A panel never logs in | `selectors`/`login_marker` vs the real page; `journalctl` for `[pN] injected login` |
| A panel renders blank in WebKit | set that panel's `engine: chromium` |
| Tunneled panel shows connection error | `systemctl status autossh-tunnel`; jump key/`permitopen`; `nc -z 127.0.0.1 191xx` |
| VPN won't connect | `journalctl -u forti-vpn`; check `vpn.trusted_cert`, gateway/port, vault item exists |
| VPN up but lost LAN/SSH | gateway pushed a default route — set `half_internet_routes: true` / `set_routes: false` |
| Windows not in 2×2 | re-run `gen-openbox-rc.py` with the real `--width/--height` |
| OOM / sluggish | confirm zram (`zramctl`); lower panel refresh; prefer `engine: webkit` |

More detail: [INSTALL.md](INSTALL.md) · [CONFIGURATION.md](CONFIGURATION.md) ·
[SECURITY.md](SECURITY.md) · [DEVELOPMENT.md](DEVELOPMENT.md).
