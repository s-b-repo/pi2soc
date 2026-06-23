# Security model

`p2soc` is an **unattended** appliance: it must boot and log into four panels with
no human present. That goal sets the security envelope — read this before
deploying anywhere sensitive.

## What protects the credentials

- **Vault on localhost.** Vaultwarden binds `127.0.0.1:8222`. Nothing SOC-related
  listens on the LAN.
- **No broker, no port, no page fetch.** The kiosk host reads creds via `rbw` and
  injects them into each view itself (WebKit `socCreds` message handler; Chromium
  CDP). Credentials never traverse a network socket or page-context `fetch`.
- **CDP debugger locked to the host.** The Chromium control channel binds
  `127.0.0.1` and `--remote-allow-origins` is pinned to the exact
  `http://127.0.0.1:<port>` the host connects from — never `*`. Because browsers
  forbid page JS from forging the `Origin` header, a rendered dashboard (or XSS
  on a panel) cannot open the DevTools websocket, attach CDP, and read the
  injected credentials of every panel.
- **RAM only.** Creds live in a short-TTL (~30 s) in-memory cache in the host
  process; the host never writes them to disk and never logs them. The host
  scrubs its copy right after injecting.

## The unattended-unlock model (read this)

There is **no plaintext master password on disk** and **no secret in any
`.env`**. The vault master password is sealed with AES-256-GCM under a key
derived (scrypt, **N=2¹⁷**) from **three** factors (`host/secretstore.py`):

1. a **256-bit random host key** (`host.key`, `0600`, never world-readable) —
   this is the real binding secret;
2. this host's `machine-id` — binds the seal to the physical host; and
3. a one-time PIN that `setup.py first-run` generates and shows you once.

The PIN is itself sealed under (host key + machine-id), so the wall self-unlocks
at boot with no prompt, while the sealed files (`/etc/soc-display/secret/*`,
`0600`, owned by the kiosk user) are **useless if copied to another machine** — a
different `machine-id` makes the GCM authentication fail — **and useless if
copied without `host.key`**. This matters because `machine-id` is *world-readable*
(`0644`) on systemd hosts and so is **not** a secret: the seal's strength rests on
the `0600` host key and the deliberately expensive KDF, not on the machine-id.
`rbw` gets the master password from `scripts/pinentry-vault.py`, which unseals it
in memory.

> **Re-seal on hardware/restore.** A restored backup or a move to new hardware
> will not unseal (different `machine-id`, and a backup that excludes the `0600`
> secret dir has no `host.key`). Re-run `setup.py first-run` with the one-time PIN
> to re-seal on the new host.

The wall **config** is the vault's too: a secure-note (`SOC Wall Config`) is the
source of truth, fetched after unlock; the local `panels.yaml` is only an offline
fallback. `soc.env` now holds **no secrets** — just the backend/email/URL, the
secret-dir and config-item names, paths and tuning.

**The residual tradeoff is unchanged in kind:** a local `root` on the *running*
Pi can still derive the key (machine-id + the sealed PIN are both on the box).
Host-binding defeats card/file theft, not local root — inherent to any
unattended appliance.

If even that is unacceptable:

- Do not seal: keep the wall attended and run `rbw unlock` once after each reboot
  (e.g. over SSH) within `SOC_READY_TIMEOUT` — the host retries opening the vault
  and logs in only once it is unlocked.
- Keep the one-time PIN off the device; you need it only to re-seal (re-deploy,
  new hardware, or changing the master password).
- Consider full-disk encryption (LUKS) with a remote unlock so a stolen card is
  inert.

## Residual exposure: form auto-fill

Auto-filling **any** login form necessarily places the password into the page DOM
at submit time — true of every password manager and every auto-login scheme. A
malicious panel that compromises its own renderer could read its own filled
fields. Mitigations in place: localhost-only everything, no shared broker, creds
delivered per-page and scrubbed, sessions isolated by origin. Only point the wall
at panels you trust.

## On-screen configuration (⚙ / Ctrl+Shift+C)

The wall can be repointed at the glass — convenient, but a surface to control:

- **PIN lock.** Set a PIN under "Security — lock PIN"; it then gates the config
  panel. It is stored only as a **salted SHA-256 digest** (`config.pin`, `0600`),
  never in clear text, with a brute-force **cooldown** after repeated misses. The
  PIN is casual physical-access protection, not a secret-grade barrier.
- **URL allow-list.** Only `http://` / `https://` URLs are accepted — at the
  overlay, in `set_url`, and when merging a (possibly hand-edited)
  `overrides.json`. `file://`, `javascript:`, `data:` etc. are refused, so the
  config cannot be turned into a local-file or script-injection vector.
- **Saved state is owner-only.** `overrides.json` is written `0600` because panel
  URLs can reveal internal hostnames.
- **Disable it entirely** for a locked-down deployment with
  `SOC_ONSCREEN_CONFIG=0` (the gear and hotkey then do nothing). Credentials are
  never entered here — only the *name* of the Vaultwarden login to use; the
  secrets stay in Vaultwarden.
- **Production defaults (SEC-7).** The generated `soc-wall.service` ships with
  `SOC_ONSCREEN_CONFIG=0` (surface off) **and** `SOC_CONFIG_REQUIRE_PIN=1`, so if
  you do re-enable the config surface it can **never open without a PIN** (no
  open-access fallback even when no PIN is set). Set a PIN before enabling it.

> **Trust boundary, stated plainly:** the sealed master protects against
> **offline media theft**, not against **local code execution as the `soc`
> user**. Anything running as `soc` (a compromised renderer, the on-screen
> config) can ask `pinentry-vault.py` to unseal, and can reach a panel's CDP
> port on loopback. Minimise what runs as `soc`, keep the console physically
> secured, and give each panel a **unique, least-privilege** vault login so one
> XSS-vulnerable dashboard cannot yield a reusable credential.

## Network hardening (`HARDEN=1`)

Installs:

- **nftables** (`security/nftables.conf`): default-deny **both directions**.
  - *Inbound:* loopback, established, ICMP, and rate-limited SSH from
    `ssh_admin_cidr`. **Fail-closed (SEC-1):** this defaults to **loopback only**
    and the installer **refuses to enable nftables while it is `0.0.0.0/0`** — set
    your real admin subnet (`SSH_ADMIN_CIDR=192.168.1.0/24 ./install.sh`, or edit
    the file).
  - *Outbound (SEC-2):* an **egress allowlist** — DNS/NTP/DHCP to bootstrap, the
    VPN gateway(s) and jump host(s) you list in the `vpn_gateways` / `jump_hosts`
    named sets, and anything inside the VPN/SSH tunnel interfaces. Everything else
    is dropped, so a compromised renderer cannot beacon to an arbitrary host.
- **sshd** (`security/sshd_hardening.conf`): key-only, no root, no forwarding,
  `MaxAuthTries 3`, and `DenyUsers soc socsvc vaultwarden` (SEC-10 — the kiosk and
  service accounts never accept an SSH login). **Ensure you have an authorized key
  before rebooting** or you can lock yourself out.

Neither is started automatically — review them (fill the egress sets) first, then
`systemctl start nftables` and `systemctl reload ssh`.

## Vault is localhost-only

The Vaultwarden listener is locked to loopback on both deploy paths:

- **Native** (`systemd/vaultwarden.service`): `Environment=ROCKET_ADDRESS=127.0.0.1`.
- **Docker** (`systemd/vaultwarden-docker.service`): the container is run with
  `-p 127.0.0.1:8222:8222` — the host's docker-proxy binds to `127.0.0.1` only,
  and the container's internal `ROCKET_ADDRESS=0.0.0.0` is correct (it must
  accept traffic from the docker bridge interface). The external blast radius
  is still loopback-only.

```
$ ss -tlnp | grep 8222
LISTEN  ...  127.0.0.1:8222  ...  users:(("docker-proxy",pid=...,fd=7))
```

If you need to reach the web vault from your workstation, use an SSH tunnel:

```
ssh -L 8222:127.0.0.1:8222 wall.lan
# then open http://localhost:8222 in your browser
```

`setup.py doctor` checks the listener bind and warns loudly if anything ever
exposes it to `0.0.0.0`.

## Tarpit (scanner deception, optional, port 80)

`scripts/tarpit.py` + `systemd/soc-tarpit.service`: a stdlib HTTP server that
answers `200 OK` with random-looking junk to ~30 common scanner targets
(`/admin.php`, `/wp-login.php`, `/.env`, `/.git/HEAD`, `/actuator/health`,
`/api/v1/*`, `/phpmyadmin/`, `/.aws/credentials`, etc.). Everything else
returns `404`. Each matched response sleeps 0.5–2.0 s (drip) and is rate-
limited per source IP (bounded LRU). The body shape matches what a header-
only scanner would expect to find (JSON for `/api/`, KEY=VALUE for `.env`,
HTML for `.php`) — plausible enough to register as a "hit", junk enough to
be useless.

**Off by default** — opt-in:

```
sudo bash -c 'echo SOC_TARPIT_ENABLE=1 > /etc/soc-display/tarpit.env'
sudo systemctl enable --now soc-tarpit
```

Hardening: `User=nobody`, `Group=nogroup`, `CapabilityBoundingSet=
CAP_NET_BIND_SERVICE` (for port 80) and nothing else, `ProtectSystem=strict`,
`MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service` minus
`@privileged @resources`. The `Server:` header is stripped from every response
so the tarpit doesn't itself fingerprint Python/BaseHTTPServer.

The tarpit doesn't add a real listening surface — port 80 was otherwise closed
on the kiosk by the nftables policy. The trade-off is one extra ~32 MB process
and a deliberate decoy for automated scanners; manual attackers are not
fooled by it.

## Browser anti-fingerprinting

Both panel engines (WebKitGTK and Chromium) ship with a pinned generic Chrome
User-Agent (`Chrome/124.0.0.0`) so a passing scanner / MITM reading wall
traffic can't read the exact `webkit2gtk` version or kernel signature. Override
per deploy via `SOC_BROWSER_UA` in `soc.env` if a dashboard needs a specific UA.

## Tunnel key hardening

The autossh tunnel uses a **dedicated, passphrase-less ed25519 key** that is
restricted on the jump host to *only* forward to the exact panels:

```
restrict,permitopen="10.20.0.7:8443",command="/usr/sbin/nologin" ssh-ed25519 AAAA… soc-wall-tunnel
```

So even if the Pi is compromised, that key cannot open a shell or forward
anywhere except the whitelisted panels. Full steps in
[`security/tunnel_key.note`](../security/tunnel_key.note).

**Jump-host key verification (SEC-6).** The tunnel now defaults to strict
`StrictHostKeyChecking=yes` with a configured `tunnel.known_hosts`, so a
man-in-the-middle at first connect cannot intercept the tunnel that carries the
dashboards and their logins. Provision the key out of band first
(`ssh-keyscan -t ed25519 <jump> >> <known_hosts>`, verify the fingerprint). Only
set `tunnel.host_key_checking: accept-new` (TOFU) for an explicit first bring-up.

## Fortinet VPN credentials

`forti-vpn.service` logs into the FortiGate with a username + password kept in the
**same vault** as the panels (`vpn.vault_item`). The password is read into memory
and handed to `openfortivpn` through a **pinentry helper** (`forti-pinentry.sh`) —
the identical mechanism that unlocks `rbw`. So the FortiGate password is **never
on the command line** (where `ps`/`/proc` would expose it) and **never written to
disk**; only the gateway, username, and routing flags appear in the process list.

Two caveats specific to the VPN unit:

- **It runs as root.** Unlike `autossh-tunnel` (unprivileged), openfortivpn must
  run `pppd` and rewrite the routing table, so the unit runs as root with only
  light sandboxing. Its rbw profile (under `/root`) is a second client of the same
  kiosk account.
- **OTP on argv (opt-in).** `otp_from_vault: true` passes a one-time `--otp=` code
  on the command line. It is single-use and short-lived, but briefly visible in
  the process list — leave it off unless your gateway requires TOTP.

**Account-lockout protection.** The supervisor classifies an auth failure and
then *stops trying* for `SOC_VPN_AUTH_RETRY_DELAY` (default 300 s) rather than
reconnecting in a tight loop — a misconfigured password must not lock the
FortiGate account. The same protection applies to the proxy (below). The unit is
`Type=notify` with a `WatchdogSec` so a hung connection is detected and restarted
rather than silently wedging the wall.

## Proxy credentials

If an outbound proxy needs authentication (`proxy.vault_item`), the username and
password are kept in the **same vault** and answered to the proxy's `407`
challenge **in memory** — WebKit via the `authenticate` signal, Chromium via the
CDP `Fetch.authRequired` event. Only `--proxy-server=host:port` (no userinfo)
ever reaches a command line; the validator **rejects** a proxy URL that embeds
`user:pass@`. Loopback always bypasses the proxy, so the tunnels, the Chromium
CDP channel, and the local Vaultwarden are never routed through it. A wrong proxy
password is retried a few times and then held, like the VPN.

## systemd sandboxing

The `vaultwarden` and `autossh-tunnel` units run with `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, restricted address families,
`MemoryDenyWriteExecute` (vault), and read-only access to the key directory.

The `forti-vpn` unit is deliberately lighter on the knobs that would break a VPN
backend (`ProtectSystem=true` not `strict`, no `DeviceAllow`, address families
incl. `AF_NETLINK`/`AF_PPPOX`) because `pppd` needs `/dev/ppp`, netlink, and write
access to `/etc/resolv.conf`. It still adds the **no-cost defense-in-depth** that
doesn't touch that access (SEC-5): `SystemCallArchitectures=native`,
`RestrictSUIDSGID`, `RestrictNamespaces`, `ProtectHostname/Clock/KernelLogs`,
`RemoveIPC`, `UMask=0077`. The vault master password is never in the unit nor in
`soc.env`: the wrapper unlocks `rbw` via the same host-bound sealed secret +
`pinentry-vault.py` as the kiosk host, so it never appears in `systemctl show`
or the process environment.

The kiosk session itself can run as a supervised unit (`soc-wall.service`,
generated by `setup.py`) with the non-secret config baked in as `Environment=`
lines instead of a sourced `soc.env`, and `Restart=always` so a dead compositor
recovers rather than leaving a black screen. The vault master is never among
those `Environment=` lines — it stays host-sealed. It also carries the
browser-safe sandbox knobs `ProtectClock/Hostname/KernelLogs`, `LockPersonality`,
`RestrictRealtime` (SEC-11). (Switching the boot from getty-autologin to this
service is validated per-deployment on the target Pi.)

**Known residual — CDP on loopback TCP (SEC-8).** Each Chromium panel exposes a
DevTools port bound to `127.0.0.1` with the origin pinned to the exact loopback
origin (never `*`), so a rendered page cannot hijack it. The port has **no auth**,
so any *local* process running as `soc` can still drive that browser. On a
single-user kiosk this is low risk, but the production-grade fix is to move CDP to
`--remote-debugging-pipe` (fd-based, no TCP). Tracked in
[`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) — not yet applied because it
reworks the attach path and must be validated against the live Chromium panels.

## Checklist before exposing anything

- [ ] `ss -ltnp` shows Vaultwarden on `127.0.0.1` only and **no** extra SOC ports
- [ ] `soc.env` (now **non-secret**) is `0640`; Vaultwarden has **no `.env`**;
      `/etc/soc-display/secret/` is `0700` (kiosk user), `*.enc` are `0600`
- [ ] `SIGNUPS_ALLOWED=false` after the kiosk account exists; `/admin` left off
- [ ] tunnel key is `permitopen`-restricted on the jump host
- [ ] if using the VPN: `vpn.trusted_cert` pins the gateway; consider
      `half_internet_routes`/`set_routes: false` so the VPN can't hijack your admin path
- [ ] if using a proxy: `proxy.url` has **no** embedded credentials; the proxy
      login lives in the vault (`proxy.vault_item`)
- [ ] no credentials appear in `journalctl` (incl. `journalctl -u forti-vpn`) or
      in `ps`/`/proc` for the VPN client or chromium
- [ ] decide on the on-screen config: set a PIN, or disable it with
      `SOC_ONSCREEN_CONFIG=0` for a locked-down wall
- [ ] the master password is **sealed** (`setup.py first-run`), not in any
      `.env`; the one-time PIN is recorded off-device; you accept the host-bound
      unattended-unlock tradeoff
