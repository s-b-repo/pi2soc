# Changelog

All notable changes to **p2soc** (the SOC video-wall kiosk). Format follows
[Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0.

## [Unreleased]

Production-hardening pass on top of the initial single-engine wall: multi-distro
+ multi-display-server install, a supervised multi-protocol VPN, an outbound
proxy, on-screen configuration, self-healing panels, and hardware auto-tuning.

### Kiosk-lock wiring · tarpit prod hardening · secrets-scrub hook (2026-06-23 later)

Roadmap phases 1, 2 and 10 from the PROMPT.txt handoff. Closes the gap
where shipped modules (`locker.py`, `tray.py`) had no runtime callers,
takes the tarpit from "works" to "survives", and automates the
secrets-cleanup-before-push that was done by hand for commit 4c328ad.

- **Tray + kiosk-lock wired into the wall runtime.** `WallWindow` gains
  `🔒 Lock` toolbar button next to `⚙ Settings`, a window-wide
  `Ctrl+Alt+L` accelerator (works even when a webview has the keyboard
  focus), and a `delete-event` handler that hides to tray instead of
  shutting down when a tray icon is active. `KioskHost.__init__` builds
  a `KioskLocker` pointed at `state_dir()` unconditionally; tray icon
  installs only in windowed mode (`SOC_WINDOWED=1` or
  `display.fullscreen: false`) AND when a backend
  (AyatanaAppIndicator3 / AppIndicator3 / `Gtk.StatusIcon`) responds.
  Tray menu: **Show wall · Lock panel · Open Settings · Restart wall ·
  Reboot machine · Quit**. Pure-kiosk-on-tty1 path unchanged.
- **⚙ Settings → Actions** gains a single-click `🔒 Lock the wall now`
  button — same effect as the toolbar / hotkey, for operators who
  prefer the menu surface.

- **Tarpit (`scripts/tarpit.py`) prod hardening:**
  - **Per-worker `BoundedSemaphore`** (`SOC_TARPIT_MAX_WORKERS`,
    default 64) with `try/finally` release. Over-cap requests are
    TCP-closed silently — slowloris flood can't exhaust the thread
    pool, and the scanner gets no signal that its strategy worked.
  - **Per-connection `socket.settimeout(5s)`** plus `rbufsize=0` so
    the timeout actually fires on a half-open scanner.
  - **`http.client._MAXLINE = 4096` / `_MAXHEADERS = 64`** pinned at
    module import — caps URL + header smear before the first byte.
  - **`SIGHUP` reloads `/etc/soc-display/tarpit-paths.list`** (one
    path per line, `/foo/*` for prefix). Built-in defaults survive +
    are the fallback on missing / unreadable / empty file.
  - **`SIGUSR1` dumps top-20 source IPs** by hit count + busy-worker
    count (bounded LRU counter, cap 4096) as a JSON line — drop-in
    journal triage during a spike.
  - **Structured JSON log line per response**
    (`ts/event/ip/method/path/status/bytes/drip_s`). Replaces the
    freeform stderr string.
  - **HEAD returns correct Content-Length, no body** per RFC 9110.
  - **Plausibility headers** — `ETag` (deterministic per
    path+ip+hour-bucket so replay can't say "all responses identical"),
    `Last-Modified` (random within 30 days), `Cache-Control: no-store`.
  - **IPv6** via `_address_family()`; `_Server.address_family` set in
    `main()`. `RestrictAddressFamilies=AF_INET AF_INET6` already in
    the unit.
  - `systemd/soc-tarpit.service` adds `LimitNOFILE=4096`.

- **Pre-commit secrets-scrub.** Native POSIX-sh hook at
  `.githooks/pre-commit` blocks staged content matching the operator's
  canary password / PEM private keys / `sk-…` / `ghp_…` / `ghs_…`
  tokens, AND staged paths matching `.env(.*)`, `secret/`, `PROMPT.txt`,
  `.claude/`, `MEMORY.md`, `*.key`, `*_ed25519`. `.env.example` is
  exempted to mirror `.gitignore`. Self-reference avoided by writing
  pattern literals with character-classes + skipping `.githooks/` +
  `.pre-commit-config.yaml` + `CONTRIBUTING.md` from the content scan.
  An `EXAMPLE-OK` per-line escape lets documented fixtures pass.
  Operators activate with `git config core.hooksPath .githooks`;
  `pre-commit`-framework users get the same via
  `.pre-commit-config.yaml`. `make secrets-scan` runs the hook on the
  staged set as a pre-push sanity check. `CONTRIBUTING.md` documents
  both activation paths.

### Setup auto-fix · vault-stored VPN cfg · scanner deception · windowed wall · multi-VPN (2026-06-23)

End-to-end pass after a real-install dogfooding session caught half a dozen
silent gaps and added the hardening + UX features they exposed.

- **Wall windowed-mode** — `display.fullscreen: false` (or `SOC_WINDOWED=1`)
  opens the wall as a normal desktop window sized to `display.width × height`
  with WM decorations, so it can live alongside KDE/Plasma without taking
  over the screen. Production fullscreen path unchanged. F11 still toggles.
  Added a `fullscreen` checkbox on the Display tab.
- **Multi-VPN** — `vpns: [...]` list (legacy `vpn:` mapping still parses),
  a new `forti-vpn@<name>.service` templated unit so each VPN runs in its
  own supervisor, one top-bar pill per VPN with a green/amber/red
  traffic-light (green=online, amber=connecting/probe-timeout, red=offline),
  GUI VPN tab now shows two sections side-by-side. The pill click only
  reconnects that one VPN.
- **VPN full config from vault (Fortinet/iNode)** — `config_from_vault: true`
  on a `fortinet`/`inode` VPN now overlays a KEY=VALUE block from the vault
  item's Notes onto the live vpn dict (`gateway=`, `port=`, `realm=`,
  `trusted_cert=`, `domain=`, etc.). Strict allowlist — unknown keys are
  logged and rejected. Never written to disk. Means you can rotate a
  gateway/cert from the web vault UI without touching `panels.yaml`.
- **Scanner-deception tarpit** — new `scripts/tarpit.py` + `soc-tarpit.service`
  (off by default, opt-in via `SOC_TARPIT_ENABLE=1`). Port 80; `/admin.php`,
  `/wp-login.php`, `/.env`, `/actuator/`, `/api/v1/`, `/phpmyadmin/`,
  `/.git/HEAD`, `/.aws/credentials` ... ~30 common scanner targets all
  return `200 OK` after a 0.5–2.0 s drip with a 4–32 KB body shaped to look
  like the requested file (JSON for `/api/`, KEY=VALUE for `.env`, HTML
  for `.php`). Per-IP rate-limited (bounded LRU). Strips `Server:` header.
  Runs as `nobody` with `CAP_NET_BIND_SERVICE` only.
- **Browser anti-fingerprinting** — both WebKit and Chromium panels now
  send a generic stable Chrome UA (`Chrome/124.0.0.0`) so a passing
  scanner / MITM reading wall traffic can't read the exact webkit2gtk
  version or kernel signature. Overrideable per deploy via `SOC_BROWSER_UA`.
- **Setup auto-fix (bakes this session's manual fix-ups)**:
  - `setup.py first-run` now chowns the sealed secret files to the wall user
    (`soc`) after sealing — previously left `root:root 0600`, which the wall
    couldn't read so it failed silently at `vault.open()`.
  - `setup.py first-run` materialises `~/.config/rbw/config.json` for BOTH
    root and the wall user (`sudo -u soc rbw config set …`), eliminating the
    "default pinentry, TTY error" trap.
  - `soc-wall.service` `ExecStartPre=+/bin/sh -c 'install -d -m 0700 -o soc
    -g soc /run/user/$(id -u soc)'` so cold boot has a runtime dir before
    rbw, pulse, WebKit need it.
  - `install.sh` setfacl now grants soc.env to BOTH `KIOSK_USER` and
    `SVC_USER` (was service-user-only — wall couldn't read its own env).
  - `install.sh` post-install sanity-check: `sudo -u <KIOSK_USER> cat
    soc.env` must succeed or it warns out loud.
- **Auto-register Vaultwarden account** — `setup.py first-run` probes for
  the account; if missing, transiently drops `[Service]
  Environment=SIGNUPS_ALLOWED=true`, restarts vaultwarden, registers via
  `vaultseed.register_account()` (RSA keypair + symmetric key + PBKDF2),
  then reverts. The only out-of-band manual web-UI step is gone.
- **Honest Apply messages** — VPN/Tunnel restart no longer silently
  no-ops when the wall lacks privilege; configwin's success message reads
  `Saved ✓ · ⚠ PENDING restart (sudo systemctl restart forti-vpn@<name>)`.
- **Vault note write-back is honest** — `_push_config_to_vault` returns
  `deferred:<reason>` on missing prereqs; the GUI surfaces *"your changes
  will be lost at next boot unless you fix this"*.
- **Vault.notes_required()** — new loud variant; `fortivpn.py` uses it for
  `config_from_vault` so empty Notes surfaces a useful error instead of an
  openvpn parser failure.
- **Doctor: config-vs-units drift detector** — flags `vpn.enabled` in
  config but `systemctl is-enabled forti-vpn` returning `disabled`,
  `static`, etc. Catches the install.sh-only-enables-units-at-install-time
  gap before reboot.
- **vpnstatus 4-state** — added `STATE_CONNECTING` (probe TCP timeout =
  amber, vs. refused = red); `_tcp_probe()` distinguishes timeout from
  refusal; `vpn_name()` for the pill label.
- **GUI gaps filled** — Panels tab Advanced now exposes per-panel
  `allow_insecure`, `allow_media`, global-proxy bypass (`proxy:`), and
  `keepalive` (strategy + interval). Display tab adds `fullscreen` toggle
  alongside layout/grid/resolution. Status tab now warns loudly when vault
  is unreachable, master is not sealed, panels have URLs but no creds,
  or login selectors look stale (auto-login attempts climbing without
  success).
- **Loud failure surfaces** — `start-session.sh` paints a red message on
  `/dev/tty1` when the firstboot marker is missing OR when no display
  stack is installed (instead of looping a black screen in the journal).
  `tunnel-args.py` exits non-zero with a clear "enabled but no forwards"
  error. `pinentry-vault.py` writes an actionable stderr line ("no sealed
  master in $SOC_SECRET_DIR — run `sudo python3 setup.py first-run`")
  instead of returning empty.
- **Tests** — 223 passing (+8 since last entry: tarpit handlers/rate-
  limiter, Fortinet KV from vault, plus the proxy/tunnel/display
  multi-VPN suites added earlier in this pass).

### Wizard: auto-detect panel login forms + clearer selector prompts (2026-06-23)

The configuration wizard now figures out the login selectors for you and makes
the "selectors are not credentials" distinction unmissable — the latter being a
real footgun (typing a username/password into a selector prompt breaks login and
writes the password into plain config).

- **Login-form auto-detection.** For a `direct` panel, `setup.py` fetches the
  login URL and derives the username/password/submit selectors + `login_marker`,
  then offers a single **"Use these detected selectors? [Y]"** instead of four
  prompts. Reads server-rendered forms from the DOM; fingerprints JS/SPA logins
  (Zabbix, Grafana, Wazuh/Kibana, Keycloak) and fills a known preset to verify;
  flags HTTP Basic auth. Pure stdlib (`urllib` + `html.parser`); fully graceful
  on unreachable hosts (still guesses from the URL path) and skipped under
  `--defaults`. Self-signed TLS is read only after an explicit prompt (the probe
  sends no credentials).
- **URL prompts accept a bare host.** `login URL` / `Vaultwarden URL` now
  normalize `10.14.0.2` or `host:port` to `http://…` instead of rejecting them;
  validation (scheme, port range) still applies.
- **Plain-language `login_marker`.** Inline help explains it's the wall's
  "logged out?" detector and that the suggested default (the password selector)
  is almost always right.
- **Panels are optional — configure at the glass.** The wizard can skip panel
  setup entirely (**"Configure panels now?" → n**) or per panel (**"Configure
  this panel now?"**), filling the grid with blank `{id, grid}`
  *click-to-configure* tiles. Point them at real tools — and store their logins —
  later from the running wall's **⚙ settings window** (Panels + Credentials tabs;
  already in `configwin.py`). The `panels.yaml` renderer and the review summary
  now handle blank tiles.
- **Everything else is now at the glass too.** The ⚙ window grows two new tabs
  and an expanded Display tab so the wizard is no longer the only path:
  - **Proxy tab** — enable, URL, vault login (proxy creds), ignore-hosts list.
  - **Tunnel tab** — SSH jump host, identity, `known_hosts`, host-key-check
    mode, and extra `bindaddr:port:host:port` forwards. Apply restarts
    `autossh-tunnel`.
  - **Display tab** — gains **grid size (cols × rows)** and **resolution
    (width × height + auto-detect)** alongside the existing layout / gap.
    Growing the grid auto-creates blank click-to-configure tiles for the new
    cells on restart, so the operator can add a 5th panel by bumping `rows`.
  Overrides round-trip through `to_yaml` back to the Vaultwarden config note,
  same write-back path the VPN tab uses. Tests:
  `test_proxy_settings.py`, `test_tunnel_settings.py`, `test_display_settings.py`
  (16 new, 215 total).
- **Docs.** New [`docs/WIZARD.md`](docs/WIZARD.md) — a prompt-by-prompt
  walkthrough with examples; `CONFIGURATION.md` / `SETUP.md` updated.
- Tests: selector derivation, product fingerprinting, SPA fallback, and URL
  normalization (`kiosk-host/tests/test_setup_commands.py`).

### Removed the dev simulation — production-only tooling (2026-06-23)

The tree is now production-only: there is no dev/dummy-panel mode. Unit suite still
192 green (rewritten onto an in-memory fake vault).

- **Deleted the `dev/` harness** entirely (dummy panels, `run-wall.sh`, `verify*.sh`,
  `seed-vault.sh`/`seed-ciphers.py`, `auth-proxy.py`, `tcp-forward.py`,
  `register-vaultwarden.py`) and `docs/DEVELOPMENT.md`.
- **Removed the JSON dev vault backend.** `kiosk-host/host/vault.py` is rbw-only —
  `_make_backend()` always returns `RbwBackend`; `DevFileBackend` /
  `SOC_VAULT_BACKEND=dev` / `SOC_DEV_VAULT` are gone.
- **`setup.py` is production-only:** no `--target dev`, no dev paths in
  `resolve_paths` (always `/etc/soc-display`, root required), no vault-backend
  choice (always rbw), and the dev branches/notes are gone.
- **`launch.sh` is production-only:** configure-once-then-run plus
  `--setup`/`--reconfigure`/`--repair`; the Xephyr dummy-panel simulation and the
  `SOC_VAULT_BACKEND:-dev` default are removed.
- **Makefile** drops the dev/verify/vault targets (`make dev`, `dev-vault`,
  `verify`, `verify-single`, `verify-proxy`, `verify-vpn`, `vpn-check`, `vault`);
  what remains is `venv` / `test` / `lint` / `install` / `clean` / `distclean`.
  Also deleted `config/panels.dev.yaml` and `config/panels.vpn-dev.yaml`.
- **Tests** no longer use the dev backend: a `kiosk-host/tests/conftest.py` provides
  an in-memory `FakeBackend` (`fake_vault` / `use_fake_backend` fixtures); the five
  vault tests and the two WM-generator tests were rewritten (the latter onto a new
  `kiosk-host/tests/data/panels.test.yaml`).
- Docs (`README`, `SETUP`, `DEPLOY`, `ARCHITECTURE`, `CONFIGURATION`, `CLAUDE.md`)
  updated to the production-only model; the VPN dry-run is now reached via
  `SOC_VPN_DRY_RUN=1` instead of the removed `make vpn-check`.

### Install/launch tooling split + first-boot setup page (2026-06-23)

Reworked the entry points into **two tools** and fixed two install-flow bugs hit on a
fresh Kali bring-up. Unit suite 186 → 192 green.

- **Fixed `PermissionError: './install.sh'`.** `install.sh` shipped without the exec bit
  (git `100644`), and `setup.py` invoked it as `./install.sh`, which needs that bit. The bit
  is now set, **and** all four `setup.py` call sites + `make install` invoke it as
  `bash <abs>/install.sh` — never dependent on the exec bit or cwd again (a downloaded/unzipped
  tree loses the bit).
- **Package-install failures now show the real error.** `pm_install()` ran the package manager
  with output hidden, so a held apt/dpkg lock, missing network, or a stale mirror all surfaced
  as the misleading "check the package names" with the whole core list. It now re-runs the
  failing set once with the manager's own error shown, and the message lists the real causes.
- **Two tools.** `setup.py` is the **installer** (OS packages via `install.sh` + services +
  optional PIN seal); `launch.sh` is the **app** (run / `--repair` / `--reconfigure`).
  `install.sh` is now an internal helper, not a third user-facing tool. Bare `setup.py` on a
  TTY runs the install flow; `setup.py menu` lists every action.
- **First-time setup page, used once.** A new `setup.py firstboot` (screen + panels, seal the
  vault PIN if not already sealed, push config/creds) runs on the first `./launch.sh` **and** on
  the first Pi boot via the new `systemd/soc-firstboot.service` (tty1 oneshot,
  `ConditionPathExists=!…/.configured`, ordered before autologin); it writes
  `/etc/soc-display/.configured` so every later boot launches straight to the wall.
  `start-session.sh` warns-and-continues if it ever arrives unconfigured (never a black screen).
  Re-run with `launch.sh --reconfigure`.
- **Screen presets.** The wizard's Display step offers `auto / 1920x1080 / 2560x1440 / 3840x2160
  / 1280x720 / custom` (auto-detect-at-launch remains the default).
- **PIN seal (both/fallback).** The installer seals if a master password is given at install
  time; otherwise the first-boot setup page seals it (skipped if already sealed).
- Docs (`SETUP`/`DEPLOY`/`INSTALL`/`CLAUDE.md`) updated to the two-tool model; tests added for
  the screen presets, the `.configured` marker, and `firstboot`'s seal-if-unsealed behaviour.

### Security & reliability audit pass (2026-06-23)

Four-domain read-only audit (secrets/crypto, kiosk runtime, VPN/RFC, installer/OS)
of the production merge, followed by fixes. Unit suite 136 → 186 green. Full
findings and deferred items: `docs/MERGE_AUDIT_REPORT.md`.

- **Memory (1 GB Pi, was a no-op):** WebKit `recycle()` now terminates the web
  process (and clears website data) so the kernel actually reclaims a leaking
  renderer's RSS instead of a plain reload; `mem_rss_kb()` reports the web-process
  RSS so the memory watchdog isn't blind. Feature-detected with a reload fallback.
- **Self-heal:** Chromium gained a respawn ceiling (`SOC_MAX_RESPAWNS`, default 20)
  + a parked terminal state so a permanently-broken panel stops respawning Chromium
  forever; WebKit retry timers are tracked and cancelled (no stale/stacked reloads);
  `WebKitPanel.stop()` tears down web process + timers on shutdown; CDP `rpc()` got a
  per-recv socket timeout so a wedged Chromium heals instead of stalling self-heal.
- **Credential injection origin gate:** host-side `socLogin()` refuses to fill unless
  `location.origin` matches the panel's configured origin — an open redirect or a
  compromised dashboard can no longer get SOC creds autofilled into an attacker page.
- **VPN/RFC:** OpenVPN management-socket username/password are CR/LF-sanitized
  (line-injection); materialized vault keys are cleaned via `try/finally` on every
  exit path; IPv6 `host:port` parsing is bracket-aware (RFC 3986).
- **iNode (H3C) SSL-VPN client updated to the audited upstream** (`vendor/iNode-VPN-Client`,
  clean-room backend only — no proprietary binaries). Fixes a **Critical pre-auth CAPTCHA
  BMP-decoder OOM** (`decode_bmp` now bounds attacker-declared dimensions before allocating —
  this was the `Killed`/137 crash), caps the tunnel frame-reassembly buffer (slow-OOM DoS),
  hardens `inode-svpn-helper` against root code-exec via an unvalidated `--backend`
  (rejects transient/world/group-writable dirs), and makes the cert-pin compare constant-time.
  The CAPTCHA solver needs far fewer retries (**15 → 3** live). See
  `vendor/iNode-VPN-Client/docs/SECURITY-FINDINGS.md`. Validated live: auth succeeds with a
  pinned self-signed cert; full tunnel comes up on `inode0` (split-tunnel preserves routing).
- **Config validation:** VPN/tunnel argv values (`gateway`/`remote_host`/`realm`/…)
  reject leading-dash/control/whitespace (argv option-injection); `remote_port` is
  range-checked; grid geometry clamps to ≥1 cell for an oversized `gap`; panel `id`
  is restricted to `[A-Za-z0-9_-]` and XML-escaped in the WM rc.xml generators.
- **Installer/OS:** dedicated `socenv` group scopes `soc.env` read (no over-broad
  kiosk-group grant); nftables pins NTP to `@ntp_servers` and rate-limits outbound
  ICMP echo; generated `soc-wall.service` is `0640` (no `SOC_VAULT_EMAIL` leak);
  `clean_state` rmtree is guarded by a path allowlist; ssh `-L` `extra_forwards` are
  shape-validated and a non-default `host_key_checking` now requires a `known_hosts`.
- **Live VPN validation (real gateways).** Fortinet (`openfortivpn`) and iNode (H3C SSL-VPN)
  both authenticated and brought up full tunnels — including **both at once in parallel**
  (`ppp0` 10.x + `inode0` 192.168.8.x), with the host default route/DNS left untouched
  (`--no-routes` / `--split-tunnel`) and clean teardown. Exercised the real project code paths
  (Fortinet via `forti-pinentry.sh`, password off argv; iNode via the `INodeDriver` + helper,
  cert pinned). Classifier patterns matched real gateway output. See `docs/MERGE_AUDIT_REPORT.md`.
- **Installer: vendored iNode backend permissions.** `install.sh` now clears group/other-write
  on `vendor/iNode-VPN-Client/backends` after deploy. The C3-hardened `inode-svpn-helper`
  refuses to load a group/other-writable backend as root, and `chown -R root:root` sets owner
  but not mode — so the dev repo's group-writable backend would otherwise trip the guard and
  break the iNode VPN on the Pi.
- **`launch.sh` no-arg interactive menu.** Bare `./launch.sh` in a terminal now prompts for the
  mode (Dev simulation / Configure / Production deploy) instead of silently running the dev
  simulation; flags (`--setup`/`--pi`/`--headless`) and piped/non-interactive runs are unchanged.
- **Deferred (needs on-hardware validation):** `forti-vpn.service` capability/syscall
  sandboxing (validate against all 3 VPN backends); on-device check of the WebKit
  web-process RSS-reclaim path (`make verify`); OpenVPN/WireGuard backends against real
  gateways. Single-use VPN OTP still on argv (documented residual).

### Added

- **Runtime memory watchdog (1 GB Pi).** The host periodically checks
  `MemAvailable` and, under sustained pressure (two low readings, with a
  cooldown so it can't thrash), recycles one panel to reclaim memory — the
  heaviest measurable panel (Chromium RSS) first, otherwise WebKit panels
  reloaded round-robin. Tunables: `SOC_MEM_MIN_AVAIL_MB` (default 96),
  `SOC_MEM_CHECK_SEC` (30), `SOC_MEM_RECYCLE_COOLDOWN` (120). The generated
  `soc-wall.service` also caps the session with `MemoryHigh=80%` / `MemoryMax=92%`
  so a leak throttles (or restarts the session) instead of OOM-killing the box.
- **Supervised, env-free kiosk session (`soc-wall.service`).** `setup.py` now
  generates the session as a systemd service with the non-secret config baked in
  as `Environment=` lines (no `soc.env` at runtime) and `Restart=always`, so a
  dead compositor/session recovers instead of leaving a black screen.
  `render_wall_unit()` emits it (the master is never baked in); `load_unit_env()`
  reads `SOC_*` back from a unit. Installed but not auto-enabled — flipping the
  boot from getty-autologin to the service is a documented on-Pi step.
- **`first-run` auto-migrates a plaintext master.** If `soc.env` still has a
  `SOC_VAULT_PASSWORD`, first-run seals it, verifies it unseals on this host,
  then scrubs the line (atomic `rewrite_env`) — never leaving the wall unable to
  unlock.
- **Vaultwarden has no `.env`.** Its server config is now inline in the systemd
  units (`systemd/vaultwarden*.service`) — non-secret (localhost-bound, signups
  off, websockets off) — and the `/admin` page is disabled by default (no
  `ADMIN_TOKEN`). `vaultwarden.env` is gone (install/setup no longer write it).
  First account: temporarily allow signups via a root-only drop-in; enable
  `/admin` later the same way.
- **Chromium kiosk anti-throttling.** Panels keep refreshing even when occluded or
  unfocused: added `--disable-background-timer-throttling`,
  `--disable-renderer-backgrounding`, `--disable-backgrounding-occluded-windows`
  (a 24/7 dashboard otherwise freezes its auto-refresh timers).
- **`doctor` handles `vpn.type: inode`.** It no longer KeyErrors on an iNode VPN
  (which mislabeled it as a config-parse failure); it now checks the iNode connect
  script is present/executable and warns if `tesseract` (the login CAPTCHA solver)
  is missing.
- **iNode client bundled.** The headless H3C iNode SSL-VPN client (the clean-room
  `h3csvpn` backend + `svpn-connect.sh` + helpers) ships in `vendor/iNode-VPN-Client`
  and installs to `/opt/soc-display/vendor/…`, so `vpn.type: inode` works out of the
  box — `vpn.config` is now optional (defaults to the bundled client; set it only to
  point elsewhere). The Qt GUI and large assets are not vendored.
- **iNode auto-reconnect.** The supervisor classifies iNode's keepalive heartbeat
  death ("going offline"), a forced log-off, and socket close as a disconnect and
  reconnects — the same liveness logic as the iNode client itself (which exits on
  a dead tunnel rather than reconnecting). The SSL-VPN self-heals with no
  `ready_probe` required; covered by a reconnect case in `make verify-vpn`.
- **VPN configurable from the on-screen ⚙ Settings.** A new **VPN** tab edits the
  supervised VPN (type incl. iNode, gateway, vault item, config, domain, cert pin,
  ready-probe); Apply persists it (overrides + the vault config note) and restarts
  the VPN service. The **Credentials** tab now also lists the VPN + proxy vault
  items, so their username/password go straight into Vaultwarden from the glass —
  every VPN is vault-backed for both config and credentials.
- **iNode (H3C SSL VPN) support** — new `vpn.type: inode`, driven headlessly by the
  bundled `svpn-connect.sh`; a process driver under the same supervisor (backoff,
  auth/cert holds, ready-probe health). Credentials come from the vault
  (`vault_item`) and reach the client only via `$H3C_SVPN_PASSWORD` (never argv);
  `config` points at the iNode-VPN-Client dir; `domain` + `trusted_cert`
  (`--pin-sha256`) / `insecure` cover the gateway. Wizard + `make verify-vpn`
  (fake client) cover it; install.sh adds tesseract for the login CAPTCHA.
- **Faster, idempotent deploy.** `install.sh` stamps `$ETC/.installed` on a
  successful run and **skips the slow OS-package step** on re-runs (the
  package-manager refresh + re-resolution) unless `--fresh` / `SOC_FRESH=1`.
  `setup.py deploy` detects an existing install and **skips it automatically**,
  offering a fresh reinstall (or force with `setup.py deploy --fresh`).
- **Performance + robustness pass (1 GB Pi tuning).** WebKit applies `WebKitMemoryPressureSettings` on low-memory boards (per web/network-process cap + GC thresholds; webkit2gtk-4.1, no-op on 4.0; `SOC_WEBKIT_MEM_LIMIT_MB`) and disables WebGL/WebAudio/media by default — opt back in per panel with `allow_media: true`. Chromium gains `--disable-dev-shm-usage`, `--renderer-process-limit=1` (low-mem) and `--disable-3d-apis` (unless `allow_media`). The vault config note is cached as last-known-good so a boot paints even if the note is briefly unreadable. On-screen ⚙ edits write the merged config **back** into the vault note (off-thread, via `config.to_yaml()`) so it stays the source of truth. `doctor` now test-unseals the secret (catches `machine-id` drift after a re-image) and `repair` converges the sealed-secret dir + rbw pinentry.
- **Secrets + config moved into Vaultwarden; no plaintext `.env`.** The wall
  config now lives in the vault as a `SOC Wall Config` secure-note (the source of
  truth, fetched after unlock; the local `panels.yaml` is the offline fallback),
  and the vault master password is **sealed host-bound** — AES-256-GCM under
  `scrypt(machine-id + a one-time PIN)` (`host/secretstore.py` +
  `scripts/pinentry-vault.py`), useless if copied off the box. `soc.env` holds no
  secret. `setup.py first-run` generates the one-time PIN and seals it; the new
  top-level **menu** (no-arg `setup.py`), `deploy` (end-to-end), `deploy --clean`
  (wipe generated state first), and an autossh-tunnel **doctor** check round it
  out. `cryptography` is now a required dependency.
- **`setup.py` is now an install/diagnose/repair tool**: `wizard` (config, with
  input validation on every field), **`doctor`** (diagnose deps/venv/config/vault/
  services/perms with fix hints), **`repair`** (install missing OS packages via
  `install.sh --deps-only`, recreate the venv, fix perms, generate the tunnel
  key), **`install`** (OS install → wizard → doctor), **`creds`** (store logins).
- **All secrets in Vaultwarden, writable** (`host/vaultseed.py`): setup.py
  (`creds`) and the on-screen Settings can store each panel/VPN/proxy
  username+password (and a VPN config in Notes) directly in Vaultwarden over its
  REST API — the wall still reads via rbw. Optional (`cryptography`); operator
  can still add logins in the web vault. The only on-disk secret is the
  unattended-unlock master password.
- **Tabbed on-screen ⚙ Settings**: Panels (URL/title/vault/engine + advanced
  selectors), Credentials (write to Vaultwarden), Display (layout/gap), Status.
- [**docs/DEPLOY.md**](docs/DEPLOY.md) — the production runbook.
- **On-screen configuration** (`host/configwin.py`): a floating, always-on-top
  panel opened by the corner **⚙** button or **Ctrl+Shift+C**. Set each tile's
  URL, title, and **Vaultwarden login** live; changes apply immediately and
  persist to `~/.config/soc-wall/overrides.json` (`SOC_STATE_DIR`), layered over
  `panels.yaml`. Optional **PIN lock** (salted SHA-256, `0600`) with brute-force
  cooldown. Disable entirely with `SOC_ONSCREEN_CONFIG=0`.
- **Display-first schema**: panels may ship unconfigured (no `url`) and
  display-only (no `vault_item`); a tile then shows a "not configured" card until
  set at the glass. New per-panel keys `title`, `allow_insecure` (accept
  self-signed TLS on a trusted LAN), and the universal `config/panels.live.yaml`.
- **Outbound proxy** (`proxy:` section): HTTP(S)/SOCKS for the panel browsers,
  per-panel opt-out. **Authenticated proxies** answer their `407` in memory —
  WebKit `authenticate` signal, Chromium CDP `Fetch.authRequired` — with
  credentials from `proxy.vault_item`; never on argv/disk. Loopback always
  bypassed. Dev harness: `dev/auth-proxy.py` + `make verify-proxy`.
- **Multi-protocol VPN** (`vpn.type: fortinet | openvpn | wireguard`,
  `host/vpndrivers.py`): one supervisor now drives all three. OpenVPN injects
  username/password over its **management socket** (in a `0700` dir); WireGuard
  is brought up via `wg-quick` with handshake/`ready_probe` health checks.
  Installer adds `openvpn` + `wireguard-tools`; the wizard asks the type.
  `make verify-vpn` behaviorally tests all three with fake clients.
- **VPN config in the vault** (`config_from_vault: true`): the OpenVPN `.ovpn` /
  WireGuard `.conf` (which hold the client key) can live in the Vaultwarden
  item's Notes; the supervisor materializes it to a transient `0600` file only
  while connecting and deletes it on disconnect. `Vault.notes()` added.
- **On-wall VPN status pill** (`host/vpnstatus.py`): top-of-wall indicator —
  online / offline / not configured — from `ready_probe` (or the tunnel
  interface), click to re-check / reconnect.
- **Smarter auto-login**: heuristic login-form detection (finds the password +
  username field when no `selectors` are set, so tiles set at the glass log in);
  **domain memory** (`host/loginmemory.py`) — a panel with a `vault_item`
  registers its origin (`host:port`), and other panels at the same origin reuse
  that login; an in-page **sign-in popup** when there's no saved login or
  auto-login keeps failing.
- **Always-reachable top bar**: the VPN pill + ⚙ Settings live in a real toolbar
  above the grid (a loaded WebKitWebView is a native window that painted over the
  old floating gear); plus a window-wide Ctrl+Shift+C accelerator.
- **Self-healing panels**: WebKit reloads on renderer crash and retries
  load failures with backoff; Chromium respawns and re-attaches CDP. Per-panel
  **status cards** (`host/style.py`) show connecting / offline / recovering.
- **Hardware auto-tuning** (`host/perf.py`): low-memory profile (lighter WebKit
  cache) auto-enabled ≤1.5 GB RAM; GPU compositing on ARM boards with a render
  node. Overrides: `SOC_LOW_MEMORY`, `SOC_WEBKIT_HWACCEL`. Chromium gets a capped
  disk cache and background networking/sync off.
- **Wayland support**: `single` layout (one fullscreen `GtkGrid`, `host/wall.py`)
  works on any compositor; `cage`/`labwc` session via `scripts/wayland-session.sh`
  with generated window rules (`scripts/gen-labwc-rc.py`); `SOC_COMPOSITOR`
  override; `SOC_SESSION=x11|wayland|auto` dispatcher.
- **More distros + display servers**: Alpine (`apk`) and Void (`xbps`) added to
  the installer (now apt/dnf/pacman/zypper/apk/xbps), plus `SOC_SKIP_PACKAGES=1`
  for anything else. Accepts X.Org **or XLibre**; degrades gracefully on
  non-systemd inits; ARM architecture detection.
- `F11` toggles fullscreen; `make verify-single` / `make verify-proxy` /
  `make gen-labwc` targets.

### Changed

- **VPN is supervised, not exec-once** (`host/fortivpn.py`): classifies the
  client's output, reconnects with exponential backoff, holds ~5 min on auth
  failure (avoids account lockout), speaks the systemd notify/watchdog protocol
  and reports state via `systemctl status`. `forti-vpn.service` is now generic.
- Config validation is collect-everything: one `ConfigError` lists every problem;
  unknown keys become warnings.
- Single-window wall tracks screen-size changes (refills on a resized
  Xephyr/cage, a monitor hotplug, or a mode switch) instead of leaving margins.

### Security

- **Production-hardening pass (military-grade).**
  - *Seal (SEC-3):* the host-bound vault master is now sealed under a **256-bit
    `0600` host key** + machine-id + PIN, with scrypt raised to **N=2¹⁷**. The
    world-readable `machine-id` is no longer the binding secret; a secret dir
    copied without `host.key` cannot unseal. Re-seal on hardware/restore.
  - *Firewall (SEC-1/SEC-2):* nftables is **fail-closed** — SSH defaults to
    loopback and the installer refuses to enable a `0.0.0.0/0` admin CIDR — and
    grows an **egress allowlist** (default-drop outbound; allow DNS/NTP/DHCP, the
    `vpn_gateways`/`jump_hosts` you list, and tunnel interfaces).
  - *Vaultwarden (SEC-4):* default install is the **hardened native systemd unit**
    (not the unsandboxed Docker one); Docker is installed from distro repos only —
    **no `get.docker.com | sh`** piped into root.
  - *VPN unit (SEC-5):* added no-cost sandboxing (`SystemCallArchitectures`,
    `RestrictSUIDSGID/Namespaces`, `ProtectHostname/Clock/KernelLogs`, `RemoveIPC`,
    `UMask`) that doesn't touch the device/netlink access the backends need.
  - *Tunnel (SEC-6):* jump-host key checking defaults to **strict** with a
    configured `known_hosts`; `accept-new` (TOFU) is opt-in for first bring-up.
  - *On-screen config (SEC-7):* off by default in production and, if enabled,
    **a PIN is mandatory** (no open-access fallback).
  - *Hardening misc:* Xwrapper `allowed_users=console` (SEC-9), `DenyUsers
    soc socsvc vaultwarden` in sshd (SEC-10), session sandbox knobs (SEC-11),
    `dev/` excluded from the production install (SEC-12).
  - *1 GB Pi (PERF-1/PERF-2):* dropped the hard `MemoryMax` from the session
    (it would OOM-bounce the whole wall before the in-host watchdog can recycle a
    single panel) and raised the watchdog floor to 150 MB; added a **journald
    size cap** (`100M`, batched fsyncs) so 24/7 log spam can't fill or wear the SD.
- On-screen config accepts **http(s) only** — `file://`, `javascript:`, `data:`
  URLs are rejected at the overlay, in `set_url`, and when merging saved
  overrides. `overrides.json` is `0600` (internal hostnames stay owner-only).
- Proxy/VPN credentials never reach a command line or disk: proxy auth answered
  in memory; the proxy URL may not embed `user:pass@` (validator rejects it);
  OpenVPN creds go over a `0700` management socket; Fortinet via pinentry.
- PIN stored only as a salted SHA-256 hash with a brute-force cooldown.
- `forti-vpn.service` keeps `/dev` open for `/dev/ppp` + `/dev/net/tun` without
  switching to device-whitelist mode (which could starve a backend).
- **Chromium CDP debugger locked to the host origin.** Replaced
  `--remote-allow-origins=*` with the exact `http://127.0.0.1:<port>` the host
  connects from. A rendered dashboard (or XSS on a panel) can no longer open the
  DevTools websocket — browsers forbid page JS from forging the `Origin` header —
  so it can't attach CDP and read every panel's injected credentials.
- **No plaintext vault master anywhere.** Removed every `SOC_VAULT_PASSWORD`
  code path (host write-back, on-screen config, `store_credentials`); the master
  comes only from the host-bound sealed store. `doctor` now **FAILs** (was a
  warning) on a leftover plaintext in `soc.env`; the legacy unsealed
  `pinentry-soc.sh` is retired (`pinentry-vault.py` tries the sealed store first).
- **Sealing is atomic.** `secretstore.seal()` stages `*.tmp` blobs + `os.replace`
  (master.enc last); `is_sealed()` requires all three files, so an interrupted
  seal reads as not-sealed instead of an unbootable half-state.
- `soc.env` is never world-readable: when `setfacl` is unavailable the installer
  grants the autossh user read via group membership at `0640` (was `chmod 0644`).

### Changed (display stack)

- `SOC_SESSION` is now a launch option with an automatic fallback chain
  (`auto`, the new default): at startup the wall tries **Wayland → XWayland →
  XLibre → Xorg**, falling through automatically (native Wayland drops to
  XWayland via the launcher; no compositor drops to X11; XLibre preferred over
  X.Org when present). Force a stage with `wayland`/`xwayland`/`xlibre`/`xorg`/
  `x11`; override the X server with `SOC_XSERVER`.

### Fixed

- **Settings unreachable after a panel loaded** — the gear + VPN pill moved from
  a GTK overlay (which a native-window WebKitWebView paints over) into a real top
  toolbar above the grid; plus a window-wide Ctrl+Shift+C accelerator.
- **Lost-update / clobber race** in the domain-login store (written from the GTK
  thread *and* Chromium control threads) — now a lock + unique temp file.
- **UI stall on login** — `need_login` ran `rbw` on the GTK thread; credentials
  are now prewarmed in parallel off-thread and the cache is thread-safe.
- **UI freeze** — the VPN pill's `systemctl restart` ran on the GTK thread; moved
  off-thread (and the credential write in Settings runs off-thread too).
- **Auto-login attempt counter crept to the popup threshold** over a long session
  for navigation-based logins; the bootstrap now reports the login state on every
  page, resetting it and recording the domain.
- WebKit error pages no longer flash over the status card: `load-failed` returns
  `TRUE` and a failed `FINISHED` no longer clears the card.
- Status cards render via a `Gtk.Stack` (not an overlay), which native-window
  WebKit views paint over.
- Chromium proxy-auth navigates from a dark placeholder (not `about:blank`, which
  demoted `--app` to a tabbed window) and settles before disabling interception.
- **Self-healing hardening for 24/7 unattended boards:** CDP `rpc()` now has an
  overall deadline so an event flood can't wedge a panel's control loop; Chromium
  children are `wait()`+`kill`ed on shutdown (no orphans / leaked CDP ports); a
  WebKit `web-process-terminated` reloads with exponential backoff instead of a
  fixed 3 s (which crash-OOM-looped on a 1 GB Pi); `effective_url` /
  `tunnel_local_port` are None-safe (no `KeyError` on the GTK thread when a live
  reconfigure nulls a panel's tunnel).
- **`first-run` honors `SOC_SECRET_DIR`** — it sealed to the hardcoded default
  even when a custom secret dir was set, so the wall couldn't self-unlock at boot.
- **`wait_for_tunnels` per-tunnel deadline** — the readiness budget was shared
  across all tunnels, so a slow first tunnel consumed it and the rest were
  declared down without ever being probed; each tunnel now gets its own budget
  (and a `None`/malformed local port is skipped instead of raising).
- **Defensive tunable parsing** — `SOC_*` numeric env vars are read via
  `config.env_int`/`env_float`, which warn + fall back to the default and clamp
  to a sane range on a missing/garbage value, instead of a `ValueError` that
  crashed the host at boot. Applied to every `int()/float(os.environ)` site.
- **`probe_tcp` validates `host:port`** and returns `False` on a malformed
  `ready_probe` instead of raising `ValueError` inside the VPN health loop
  (which silently killed it).
- **Vault TTL cache evicts on access** (was append-only) so it can't grow
  unbounded over a 24/7 run and stale credentials don't linger in RAM past TTL;
  `_poll_vpn` skips a tick if the previous probe is still running (no thread pileup).
