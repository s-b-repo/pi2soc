#!/usr/bin/env bash
# =============================================================================
# SOC video-wall kiosk installer
#
# Supported distros (package install is automatic):
#   * Debian / Raspberry Pi OS / Ubuntu / Kali   (apt)
#   * Fedora / RHEL / Rocky / Alma               (dnf)
#   * Arch / Manjaro / EndeavourOS               (pacman)
#   * openSUSE Leap / Tumbleweed                 (zypper)
#   * Alpine                                     (apk)
#   * Void                                       (xbps)
# Any other distro: run with SOC_SKIP_PACKAGES=1 after installing the deps from
# docs/INSTALL.md by hand — everything else (deploy, venv, config, services) is
# distro-agnostic.
#
# systemd is preferred (autologin + service supervision). On a non-systemd
# init (OpenRC/runit/...) the installer still deploys everything and prints the
# autostart + supervision snippets you need to wire up by hand.
#
# X11 sessions work with X.Org OR XLibre (the installer accepts whichever X
# server is present, and falls back to xlibre-* package names where needed).
#
# Idempotent: safe to re-run. Run as root:  sudo ./install.sh
#
# Knobs (env):
#   SESSION=auto|wayland|xwayland|xlibre|xorg|x11   stack to install + use
#                             (default: auto). auto = install both stacks and at
#                             runtime try Wayland -> XWayland -> XLibre -> Xorg.
#                             wayland/xwayland install the Wayland compositor;
#                             xlibre/xorg/x11 install the X11 server + openbox.
#   VW_MODE=native|docker     how to run Vaultwarden           (default: native, hardened unit)
#   SSH_ADMIN_CIDR=<cidr>      admin subnet for nftables SSH    (default: loopback only)
#   HARDEN=1                  apply nftables + sshd hardening  (default: off)
#   KIOSK_USER=soc            kiosk login user                 (default: soc)
#   SVC_USER=socsvc           service user (autossh)           (default: socsvc)
#   COMPOSITOR=labwc          Wayland compositor to install    (default: labwc)
#                             (e.g. sway/cage — runtime override is SOC_COMPOSITOR)
#   SOC_SKIP_PACKAGES=1       do not install any OS packages (deps already present)
#   --fresh | SOC_FRESH=1     reinstall OS packages even if already installed
#                             (a successful install stamps $ETC/.installed; re-runs
#                             and `setup.py deploy` skip the slow package step)
#   SOC_ROOT=/opt/soc-display
# =============================================================================
set -euo pipefail

SESSION_WAS_SET="${SESSION+yes}"
SESSION="${SESSION:-auto}"
VW_MODE="${VW_MODE:-native}"
HARDEN="${HARDEN:-0}"
SSH_ADMIN_CIDR="${SSH_ADMIN_CIDR:-}"
KIOSK_USER="${KIOSK_USER:-soc}"
SVC_USER="${SVC_USER:-socsvc}"
COMPOSITOR="${COMPOSITOR:-labwc}"
SKIP_PACKAGES="${SOC_SKIP_PACKAGES:-0}"
DEPS_ONLY=0
FRESH="${SOC_FRESH:-0}"
for _a in "$@"; do
  [ "$_a" = "--deps-only" ] && DEPS_ONLY=1
  [ "$_a" = "--fresh" ] && FRESH=1
done
SOC_ROOT="${SOC_ROOT:-/opt/soc-display}"
ETC="/etc/soc-display"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCH="$(uname -m)"

log(){ printf '\033[36m==>\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m!!\033[0m %s\n' "$*"; }
die(){ printf '\033[31mEE\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo ./install.sh)"
case "$SESSION" in auto|wayland|xwayland|xlibre|xorg|x11) ;; *)
  die "SESSION must be auto|wayland|xwayland|xlibre|xorg|x11 (got '$SESSION')";; esac

# systemd is preferred but not required — degrade gracefully without it.
HAS_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  HAS_SYSTEMD=1
else
  warn "no running systemd detected — will deploy files + scripts but NOT install"
  warn "services or tty autologin. See the end-of-run notes for the manual steps."
fi

# Architecture note (ARM boards are the primary target; x86 works too).
case "$ARCH" in
  aarch64|arm64)  log "CPU architecture: $ARCH (64-bit ARM — e.g. Raspberry Pi 5)" ;;
  armv7l|armv6l)  warn "CPU architecture: $ARCH (32-bit ARM). WebKitGTK is heavy here;"
                  warn "  a 64-bit OS is strongly recommended for the SOC wall." ;;
  x86_64|amd64)   log "CPU architecture: $ARCH (x86-64)" ;;
  *)              warn "CPU architecture: $ARCH (untested — proceeding anyway)" ;;
esac

# --------------------------------------------------------------------------- #
# Distro detection + package-manager abstraction
# --------------------------------------------------------------------------- #
FAMILY=""
. /etc/os-release 2>/dev/null || true
_ids="${ID:-} ${ID_LIKE:-}"
case " $_ids " in
  *" debian "*|*" ubuntu "*|*" raspbian "*|*" kali "*) FAMILY=debian ;;
  *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*) FAMILY=fedora ;;
  *" arch "*|*" manjaro "*|*" endeavouros "*) FAMILY=arch ;;
  *" suse "*|*" opensuse "*|*" opensuse-leap "*|*" opensuse-tumbleweed "*) FAMILY=suse ;;
  *" alpine "*) FAMILY=alpine ;;
  *" void "*) FAMILY=void ;;
esac
# Last-resort detection by package manager when os-release is unhelpful.
if [ -z "$FAMILY" ]; then
  if command -v apt-get >/dev/null 2>&1;   then FAMILY=debian
  elif command -v dnf >/dev/null 2>&1;     then FAMILY=fedora
  elif command -v pacman >/dev/null 2>&1;  then FAMILY=arch
  elif command -v zypper >/dev/null 2>&1;  then FAMILY=suse
  elif command -v apk >/dev/null 2>&1;     then FAMILY=alpine
  elif command -v xbps-install >/dev/null 2>&1; then FAMILY=void
  fi
fi
if [ -z "$FAMILY" ] && [ "$SKIP_PACKAGES" != "1" ]; then
  die "unsupported distro: ID='${ID:-?}' ID_LIKE='${ID_LIKE:-?}'.
   Auto-install supports apt/dnf/pacman/zypper/apk/xbps. Install the deps from
   docs/INSTALL.md by hand, then re-run with SOC_SKIP_PACKAGES=1."
fi
log "Distro: ${PRETTY_NAME:-${FAMILY:-unknown}} (family: ${FAMILY:-none}, packages: $([ "$SKIP_PACKAGES" = 1 ] && echo skip || echo auto))"

pm_refresh(){
  [ "$SKIP_PACKAGES" = "1" ] && return 0
  case "$FAMILY" in
    debian) export DEBIAN_FRONTEND=noninteractive; apt-get update -qq ;;
    fedora) : ;;                              # dnf resolves metadata on install
    arch)   pacman -Sy --noconfirm >/dev/null ;;
    suse)   zypper -n refresh >/dev/null ;;
    alpine) apk update >/dev/null ;;
    void)   xbps-install -S >/dev/null ;;
  esac
}

pm_install_cmd(){   # one transaction; returns non-zero on any failure
  case "$FAMILY" in
    debian) apt-get install -y -qq "$@" ;;
    fedora) dnf install -y -q "$@" ;;
    arch)   pacman -S --noconfirm --needed "$@" ;;
    suse)   zypper -n install --no-recommends "$@" ;;
    alpine) apk add "$@" ;;
    void)   xbps-install -y "$@" ;;
  esac
}

pkg_exists(){       # is a package name known to the active package manager?
  case "$FAMILY" in
    debian) apt-cache show "$1" >/dev/null 2>&1 ;;
    fedora) dnf info "$1" >/dev/null 2>&1 ;;
    arch)   pacman -Si "$1" >/dev/null 2>&1 ;;
    suse)   zypper -n info "$1" >/dev/null 2>&1 ;;
    alpine) apk info -e "$1" >/dev/null 2>&1 || apk search -x "$1" 2>/dev/null | grep -q . ;;
    void)   xbps-query -Rp pkgver "$1" >/dev/null 2>&1 ;;
    *)      return 1 ;;
  esac
}

pm_install(){       # required packages: try the set, then bisect to name culprits
  [ "$SKIP_PACKAGES" = "1" ] && return 0
  pm_install_cmd "$@" >/dev/null 2>&1 && return 0
  local failed=()
  for p in "$@"; do
    pm_install_cmd "$p" >/dev/null 2>&1 || failed+=("$p")
  done
  [ "${#failed[@]}" -eq 0 ] && return 0
  # Surface the package manager's OWN error. When the whole core set "fails"
  # (even python3/curl), the cause is almost never a wrong package name — it is
  # the package manager itself: a held dpkg/apt lock, no network/proxy, or a
  # stale/unreachable mirror. We install with output hidden (clean logs on the
  # happy path), so re-run the failing set ONCE with output shown before dying.
  warn "package install failed for: ${failed[*]}"
  warn "re-running it with the package manager's output shown:"
  pm_install_cmd "${failed[@]}" || true
  die "could not install required package(s): ${failed[*]}
   Likely causes (see the error just above): another apt/dpkg (or dnf/pacman/...)
   process holding the lock; no network / proxy; a stale or unreachable mirror;
   or a package name that differs on this distro. Fix that, then re-run
   ./install.sh (or set SOC_SKIP_PACKAGES=1 once the deps are present)."
}

pm_try(){           # optional packages: best effort, one by one, warn only
  [ "$SKIP_PACKAGES" = "1" ] && return 0
  for p in "$@"; do
    pm_install_cmd "$p" >/dev/null 2>&1 || warn "optional package '$p' not installed (skipping)"
  done
}

# --------------------------------------------------------------------------- #
# Package sets per family
# --------------------------------------------------------------------------- #
# Per family:
#   PK_CORE       python/GTK/WebKit + autossh/openfortivpn (required)
#   PK_XSRV       the X server package (skipped if an X server is already present,
#                 which is also how an existing XLibre install is honoured)
#   PK_XSRV_ALT   XLibre server package name(s) to try if PK_XSRV is unavailable
#   PK_X11        the rest of the X session (xinit + openbox), server excluded
#   PK_WAYLAND    Wayland compositor(s); $COMPOSITOR is appended below
#   PK_TOOLS      optional niceties (cursor hider, fonts, pinentry, jq)
#   PK_ZRAM       zram swap generator (optional)
#   PK_RBW        rbw (Vaultwarden CLI); cargo fallback if unpackaged
PK_XSRV_ALT=()
case "$FAMILY" in
  debian)
    PK_CORE=(python3 python3-venv python3-gi gir1.2-gtk-3.0
             curl ca-certificates autossh openfortivpn ppp)
    PK_XSRV=(xserver-xorg xserver-xorg-legacy)
    PK_X11=(xinit x11-xserver-utils openbox)
    PK_WAYLAND=(cage)
    PK_TOOLS=(wmctrl xdotool unclutter fonts-dejavu-core pinentry-tty jq)
    PK_ZRAM=(systemd-zram-generator)
    PK_RBW=(rbw)
    # WebKit2 typelib: prefer 4.1 (Bookworm+), fall back to 4.0
    if pkg_exists gir1.2-webkit2-4.1; then
      PK_CORE+=(gir1.2-webkit2-4.1)
    else
      PK_CORE+=(gir1.2-webkit2-4.0)
    fi
    ;;
  fedora)
    PK_CORE=(python3 python3-gobject gtk3 webkit2gtk4.1
             curl ca-certificates autossh openfortivpn ppp)
    PK_XSRV=(xorg-x11-server-Xorg)
    PK_X11=(xorg-x11-xinit openbox)
    PK_WAYLAND=(cage)
    PK_TOOLS=(xorg-x11-server-utils xsetroot wmctrl xdotool unclutter
              dejavu-sans-fonts pinentry jq)
    PK_ZRAM=(zram-generator zram-generator-defaults)
    PK_RBW=(rbw)
    ;;
  arch)
    PK_CORE=(python python-gobject gtk3 webkit2gtk-4.1
             curl ca-certificates autossh openfortivpn ppp)
    PK_XSRV=(xorg-server)
    PK_XSRV_ALT=(xlibre-xserver)   # AUR / Artix; honoured if already installed
    PK_X11=(xorg-xinit openbox)
    PK_WAYLAND=(cage)
    PK_TOOLS=(xorg-xset xorg-xsetroot xorg-xrandr wmctrl xdotool unclutter
              ttf-dejavu pinentry jq)
    PK_ZRAM=(zram-generator)
    PK_RBW=(rbw)
    ;;
  suse)
    PK_CORE=(python3 python3-gobject typelib-1_0-Gtk-3_0 typelib-1_0-WebKit2-4_1
             curl ca-certificates autossh openfortivpn ppp)
    PK_XSRV=(xorg-x11-server)
    PK_X11=(xinit openbox)
    PK_WAYLAND=(cage)
    PK_TOOLS=(wmctrl xdotool unclutter dejavu-fonts pinentry jq)
    PK_ZRAM=()
    PK_RBW=(rbw)
    ;;
  alpine)
    PK_CORE=(python3 py3-gobject3 gtk+3.0 webkit2gtk-4.1
             curl ca-certificates autossh openfortivpn ppp)
    PK_XSRV=(xorg-server)
    PK_X11=(xinit openbox)
    PK_WAYLAND=(cage)
    PK_TOOLS=(xrandr xset wmctrl xdotool font-dejavu pinentry jq)
    PK_ZRAM=()
    PK_RBW=(rbw)
    ;;
  void)
    PK_CORE=(python3 python3-gobject gtk+3 webkit2gtk
             curl ca-certificates autossh openfortivpn ppp)
    PK_XSRV=(xorg-server)
    PK_X11=(xinit openbox)
    PK_WAYLAND=(cage)
    PK_TOOLS=(xrandr xset wmctrl xdotool dejavu-fonts-ttf pinentry jq)
    PK_ZRAM=()
    PK_RBW=(rbw)
    ;;
  *)   # SOC_SKIP_PACKAGES=1 with an unknown distro — arrays just stay empty
    PK_CORE=(); PK_XSRV=(); PK_X11=(); PK_WAYLAND=(); PK_TOOLS=(); PK_ZRAM=(); PK_RBW=()
    ;;
esac
# The chosen compositor (default labwc) leads the Wayland set unless skipping.
[ -n "$COMPOSITOR" ] && PK_WAYLAND=("$COMPOSITOR" "${PK_WAYLAND[@]}")

x_server_present(){ command -v Xorg >/dev/null 2>&1 || command -v X >/dev/null 2>&1; }

install_x_server(){   # honour an existing X.Org/XLibre; else install one
  if x_server_present; then
    log "X server already present ($(command -v Xorg || command -v X)) — keeping it"
    return 0
  fi
  [ "${#PK_XSRV[@]}" -gt 0 ] || return 0
  if pm_install_cmd "${PK_XSRV[@]}" >/dev/null 2>&1; then return 0; fi
  # xorg package missing/failed — try a XLibre package name before giving up
  for alt in "${PK_XSRV_ALT[@]}"; do
    if pkg_exists "$alt" && pm_install_cmd "$alt" >/dev/null 2>&1; then
      log "installed XLibre server ($alt)"; return 0
    fi
  done
  die "could not install an X server (${PK_XSRV[*]}).
   Install X.Org or XLibre for your distro by hand, then re-run with
   SOC_SKIP_PACKAGES=1 — or use SESSION=wayland to skip X entirely."
}

# Fast re-runs: an existing install (the install stamp is present) skips the OS
# package step unless --fresh / SOC_FRESH=1. The slow part is the package-manager
# metadata refresh + re-resolution; the deploy/config/service steps below still
# run (they are idempotent and pick up code changes).
if [ "$FRESH" != "1" ] && [ "$SKIP_PACKAGES" != "1" ] && [ "$DEPS_ONLY" != "1" ] \
   && [ -f "$ETC/.installed" ]; then
  log "Existing install detected ($ETC/.installed) — skipping OS package install"
  log "  (pass --fresh or SOC_FRESH=1 to reinstall/upgrade packages)"
  SKIP_PACKAGES=1
fi

log "Refreshing package metadata"
pm_refresh

log "Installing core dependencies (python/GTK/WebKit, autossh, openfortivpn)"
pm_install "${PK_CORE[@]}"

case "$SESSION" in
  xlibre|xorg|x11)
           log "Installing X11 session (X server + openbox)"
           install_x_server; pm_install "${PK_X11[@]}" ;;
  wayland|xwayland)
           log "Installing Wayland session ($COMPOSITOR + cage)"
           pm_install "${PK_WAYLAND[@]}" ;;
  auto)    log "Installing X11 + Wayland sessions (runtime: Wayland→XWayland→XLibre→Xorg)"
           install_x_server; pm_install "${PK_X11[@]}"; pm_try "${PK_WAYLAND[@]}" ;;
esac

log "Installing optional tools"
pm_try "${PK_TOOLS[@]}"
[ "${#PK_ZRAM[@]}" -gt 0 ] && pm_try "${PK_ZRAM[@]}"
[ "$HARDEN" = "1" ] && pm_install nftables

# Optional VPN clients (only the one matching vpn.type is actually used).
# openfortivpn is in PK_CORE; add OpenVPN + WireGuard so any vpn.type works.
log "Installing optional VPN clients (openvpn, wireguard-tools; tesseract for iNode)"
pm_try openvpn wireguard-tools
# iNode SSL-VPN solves the gateway's login CAPTCHA with tesseract (pkg name varies)
pm_try tesseract-ocr tesseract

# rbw is how the kiosk reads Vaultwarden — the wall cannot read logins without it
if ! command -v rbw >/dev/null 2>&1; then
  if [ "$SKIP_PACKAGES" != "1" ] && [ "${#PK_RBW[@]}" -gt 0 ]; then
    pm_install_cmd "${PK_RBW[@]}" >/dev/null 2>&1 || true
  fi
  if ! command -v rbw >/dev/null 2>&1; then
    warn "rbw is not on PATH / not packaged on this distro release. Install it with:"
    warn "    cargo install rbw     (as the kiosk + root users; needs rust/cargo)"
    warn "The wall cannot read Vaultwarden until rbw is on PATH."
  fi
fi

# Chromium (only needed for engine: chromium panels) — names differ
if ! command -v chromium >/dev/null 2>&1 && ! command -v chromium-browser >/dev/null 2>&1; then
  pm_try chromium chromium-browser
  command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 || \
    warn "chromium not installed (only needed for engine: chromium panels)"
fi

# --deps-only: stop here (used by `setup.py repair` to install missing packages)
if [ "$DEPS_ONLY" = "1" ]; then
  log "dependencies installed (--deps-only) — done."
  exit 0
fi

# --------------------------------------------------------------------------- #
log "Creating users ($KIOSK_USER kiosk, $SVC_USER service)"
if ! id "$KIOSK_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$KIOSK_USER"
fi
# kiosk user needs access to video/render/input/tty for the display + GPU
for grp in video render input tty audio seat; do
  getent group "$grp" >/dev/null 2>&1 && usermod -aG "$grp" "$KIOSK_USER" || true
done
if ! id "$SVC_USER" >/dev/null 2>&1; then
  useradd -r -m -s "$(command -v nologin || echo /usr/sbin/nologin)" "$SVC_USER"
fi

# Debian's Xorg wrapper restricts who may start X. The kiosk starts X from the
# console VT (tty1 autologin / soc-wall.service), so `console` is sufficient —
# SEC-9: do NOT widen to `anybody`, which would let any user spawn an X server.
if [ "$FAMILY" = "debian" ]; then
  if [ -f /etc/X11/Xwrapper.config ]; then
    sed -i 's/^allowed_users=.*/allowed_users=console/' /etc/X11/Xwrapper.config || true
    grep -q '^needs_root_rights' /etc/X11/Xwrapper.config || \
      echo "needs_root_rights=yes" >>/etc/X11/Xwrapper.config
  else
    printf 'allowed_users=console\nneeds_root_rights=yes\n' >/etc/X11/Xwrapper.config
  fi
fi

# --------------------------------------------------------------------------- #
log "Installing project to $SOC_ROOT"
mkdir -p "$SOC_ROOT"
# copy everything except the venv / git / caches. (--exclude='dev' is kept as a
# belt-and-suspenders guard; the dev harness has been removed from the tree.)
tar -C "$SRC_DIR" \
    --exclude='.git' --exclude='.venv' --exclude='dev' --exclude='__pycache__' \
    -cf - . | tar -C "$SOC_ROOT" -xf -
chown -R root:root "$SOC_ROOT"
chmod +x "$SOC_ROOT"/scripts/*.sh "$SOC_ROOT"/scripts/*.py 2>/dev/null || true
# the bundled iNode SSL-VPN client (vendor/) — its connect script + helpers
chmod +x "$SOC_ROOT"/vendor/iNode-VPN-Client/svpn-connect.sh \
         "$SOC_ROOT"/vendor/iNode-VPN-Client/scripts/* 2>/dev/null || true
# SEC: inode-svpn-helper (run as root by the VPN supervisor) refuses to load a
# group/other-writable backend (root code-exec guard). The source repo's dev
# umask leaves the clean-room backend group-writable; clear those bits so the
# helper will load it on the Pi (the chown above only sets owner, not the mode).
chmod -R go-w "$SOC_ROOT"/vendor/iNode-VPN-Client/backends 2>/dev/null || true

log "Creating Python venv"
if [ ! -x "$SOC_ROOT/.venv/bin/python" ]; then
  python3 -m venv --system-site-packages "$SOC_ROOT/.venv" || \
    die "python3 -m venv failed (on Debian: apt install python3-venv)"
fi
"$SOC_ROOT/.venv/bin/pip" install -q --upgrade pip
# PyYAML + websocket-client + cryptography are all REQUIRED: cryptography seals/
# unseals the host-bound vault master password (no plaintext .env) and writes the
# logins + config into Vaultwarden.
"$SOC_ROOT/.venv/bin/pip" install -q PyYAML websocket-client cryptography \
  || die "pip install failed (PyYAML, websocket-client and cryptography are required)"

# --------------------------------------------------------------------------- #
log "Setting up $ETC (config + secrets)"
mkdir -p "$ETC" "$ETC/keys"
install_template(){  # src dst mode owner
  if [ -f "$2" ]; then warn "keep existing $2"; else
    cp "$1" "$2"; chmod "$3" "$2"; chown "$4" "$2"; log "created $2"; fi
}
install_template "$SOC_ROOT/config/panels.yaml"          "$ETC/panels.yaml"      0644 "root:root"
install_template "$SOC_ROOT/config/soc.env.example"      "$ETC/soc.env"          0640 "root:$KIOSK_USER"
# Vaultwarden config is inline in its systemd unit (no .env) — nothing to install.
chmod 0750 "$ETC/keys"; chown "$SVC_USER:$SVC_USER" "$ETC/keys"
# Host-bound sealed vault secret (master.enc / pin.enc) — owned by the kiosk user
# (it unlocks the vault at boot), 0700. setup.py first-run/deploy seals it here.
mkdir -p "$ETC/secret"; chmod 0700 "$ETC/secret"; chown "$KIOSK_USER:$KIOSK_USER" "$ETC/secret"
# soc.env must be readable by BOTH the kiosk user (the wall sources it at
# session start) AND the autossh service user — but NEVER world-readable (it
# holds the vault email/URL, secret-dir path and config-item name). Prefer an
# ACL; if ACLs are unavailable, fall back to a shared group. The sealed-secret
# dir stays 0700, so this grants soc.env only.
#
# Audit HIGH #27: a previous version only added the ACL for SVC_USER, leaving
# the wall (which runs as KIOSK_USER) unable to read soc.env. The wall would
# boot, fail to source the env, and silently die at vault.open(). Both users
# now get an ACL entry, AND ownership is normalised to root:KIOSK_USER 0640 so
# even on filesystems without ACL the wall can still read by group.
chown "root:$KIOSK_USER" "$ETC/soc.env"; chmod 0640 "$ETC/soc.env"
ACL_OK=1
setfacl -m "u:$KIOSK_USER:r" "$ETC/soc.env" 2>/dev/null || ACL_OK=0
setfacl -m "u:$SVC_USER:r"  "$ETC/soc.env" 2>/dev/null || ACL_OK=0
if [ "$ACL_OK" = 0 ]; then
  warn "setfacl unavailable — granting $SVC_USER read on soc.env via a dedicated group"
  # The KIOSK_USER already has read via group ownership (root:$KIOSK_USER 0640).
  # SVC_USER needs a separate single-purpose group so it doesn't get blanket
  # access to other files KIOSK_USER might own.
  getent group socenv >/dev/null 2>&1 || groupadd -r socenv 2>/dev/null \
    || warn "could not create group socenv"
  usermod -aG socenv "$SVC_USER" 2>/dev/null \
    || warn "could not add $SVC_USER to group socenv; autossh may not read soc.env"
  # When falling back to socenv group, KIOSK_USER must also be in it (since the
  # file's group becomes socenv, not KIOSK_USER's primary group).
  usermod -aG socenv "$KIOSK_USER" 2>/dev/null || true
  chown "root:socenv" "$ETC/soc.env"; chmod 0640 "$ETC/soc.env"
fi

# record the chosen session in soc.env — only override a manual edit when the
# operator explicitly passed SESSION= to this run
if ! grep -q '^SOC_SESSION=' "$ETC/soc.env"; then
  printf '\n# session backend: x11 | wayland | auto (see docs/INSTALL.md)\nSOC_SESSION=%s\n' \
    "$SESSION" >> "$ETC/soc.env"
elif [ -n "$SESSION_WAS_SET" ]; then
  sed -i "s/^SOC_SESSION=.*/SOC_SESSION=$SESSION/" "$ETC/soc.env"
fi

# --------------------------------------------------------------------------- #
log "Vaultwarden ($VW_MODE)"
mkdir -p /var/lib/vaultwarden
if [ "$VW_MODE" = "docker" ]; then
  warn "VW_MODE=docker: the docker unit is NOT systemd-sandboxed; prefer VW_MODE=native for production."
  if ! command -v docker >/dev/null 2>&1; then
    log "installing Docker from the distro repos"
    # SEC-4: install from the signed distro repo only. Never pipe a remote
    # bootstrap script into a root shell (get.docker.com | sh).
    case "$FAMILY" in
      arch)        pm_install docker ;;
      suse)        pm_install docker ;;
      debian)      pm_install docker.io ;;
      fedora)      pm_install docker || pm_install podman-docker ;;
      *)           pm_install docker || pm_install docker.io || true ;;
    esac
    command -v docker >/dev/null 2>&1 || \
      die "could not install Docker from the distro repos. Install docker/podman yourself, or use VW_MODE=native (recommended). Refusing to fetch an unverified install script."
  fi
  [ "$HAS_SYSTEMD" = "1" ] && systemctl enable --now docker >/dev/null 2>&1 || true
  docker pull vaultwarden/server:latest
  cp "$SOC_ROOT/systemd/vaultwarden-docker.service" /etc/systemd/system/vaultwarden.service
else
  if [ ! -x /usr/local/bin/vaultwarden ]; then
    warn "native mode: place the vaultwarden binary at /usr/local/bin/vaultwarden"
    warn "(see https://github.com/dani-garcia/vaultwarden — build or fetch a static build)"
  fi
  id vaultwarden >/dev/null 2>&1 || \
    useradd -r -s "$(command -v nologin || echo /usr/sbin/nologin)" vaultwarden
  chown -R vaultwarden:vaultwarden /var/lib/vaultwarden
  cp "$SOC_ROOT/systemd/vaultwarden.service" /etc/systemd/system/vaultwarden.service
fi

# --------------------------------------------------------------------------- #
# has panels.yaml configured tunnels / a VPN? (used to enable services)
want_tunnel(){ "$SOC_ROOT/.venv/bin/python" -c "import sys;sys.path.insert(0,'$SOC_ROOT/kiosk-host');from host import config;c=config.load('$ETC/panels.yaml');sys.exit(0 if any(p.mode=='tunnel' for p in c.panels) and c.tunnel.get('enabled',True) else 1)"; }
want_vpn(){ "$SOC_ROOT/.venv/bin/python" -c "import sys;sys.path.insert(0,'$SOC_ROOT/kiosk-host');from host import config;v=config.load('$ETC/panels.yaml').vpn or {};k=config.vpn_kind(v);ok=bool(v.get('enabled')) and ((k=='fortinet' and v.get('gateway')) or (k in ('openvpn','wireguard') and v.get('config')));sys.exit(0 if ok else 1)"; }

if [ "$HAS_SYSTEMD" = "1" ]; then
  log "Installing systemd services (vaultwarden, autossh-tunnel, forti-vpn, soc-wall, soc-firstboot, soc-tarpit)"
  cp "$SOC_ROOT/systemd/autossh-tunnel.service" /etc/systemd/system/
  cp "$SOC_ROOT/systemd/forti-vpn.service" /etc/systemd/system/
  cp "$SOC_ROOT/systemd/forti-vpn@.service" /etc/systemd/system/
  # Scanner-deception tarpit on port 80. Installed but NEVER auto-enabled —
  # opt-in with: SOC_TARPIT_ENABLE=1 in $ETC/tarpit.env, then
  # `systemctl enable --now soc-tarpit`. See docs/SECURITY.md.
  cp "$SOC_ROOT/systemd/soc-tarpit.service" /etc/systemd/system/
  # Supervised kiosk session (env baked in, no soc.env) — setup.py regenerates it
  # with the wizard's values. Installed but NOT enabled: switching the boot from
  # getty-autologin to this service must be validated on the target display (see
  # the end-of-run notes), so we don't flip it automatically.
  [ -f /etc/systemd/system/soc-wall.service ] || \
    cp "$SOC_ROOT/systemd/soc-wall.service" /etc/systemd/system/
  # First-boot setup page: a tty1 oneshot that runs the interactive configuration
  # (setup.py firstboot) BEFORE the kiosk session, but only while unconfigured. It
  # self-skips once $ETC/.configured exists, so every later boot goes straight to
  # the wall. Templated for the chosen SOC_ROOT/ETC.
  sed -e "s#@SOC_ROOT@#$SOC_ROOT#g" -e "s#@ETC@#$ETC#g" \
      "$SOC_ROOT/systemd/soc-firstboot.service" \
      > /etc/systemd/system/soc-firstboot.service
  # PERF-2: bound the journal so 24/7 self-healing log spam can't fill the SD
  # card or burn its write endurance.
  install -d /etc/systemd/journald.conf.d
  cp "$SOC_ROOT/security/journald-soc.conf" /etc/systemd/journald.conf.d/10-soc.conf
  systemctl restart systemd-journald 2>/dev/null || true
  systemctl daemon-reload
  systemctl enable vaultwarden.service
  # First-boot setup runs once on tty1 (Condition skips it once configured).
  systemctl enable soc-firstboot.service 2>/dev/null \
    || warn "could not enable soc-firstboot.service — run setup on first boot with ./launch.sh"
  if want_tunnel; then
    systemctl enable autossh-tunnel.service
    log "autossh-tunnel enabled (tunnels configured)"
  else
    systemctl disable autossh-tunnel.service 2>/dev/null || true
    warn "no tunnels in panels.yaml — autossh-tunnel left disabled"
  fi
  if want_vpn; then
    systemctl enable forti-vpn.service
    log "VPN service enabled (forti-vpn.service supervises Fortinet/OpenVPN/WireGuard)"
  else
    systemctl disable forti-vpn.service 2>/dev/null || true
    warn "no vpn in panels.yaml — VPN service left disabled"
  fi
else
  warn "no systemd — skipping service installation. Supervise these by hand"
  warn "with your init (OpenRC/runit/sysvinit), all simple long-running commands:"
  warn "  vaultwarden : $SOC_ROOT/systemd/vaultwarden*.service shows the command"
  warn "  autossh     : $SOC_ROOT/scripts/launcher.sh-style restart loop around autossh"
  warn "  forti-vpn   : $SOC_ROOT/.venv/bin/python $SOC_ROOT/scripts/forti-vpn-connect.py"
  warn "                (self-supervising: reconnect/backoff built in; run as root)"
fi

# --------------------------------------------------------------------------- #
log "Configuring zram + sysctl"
if [ "$HAS_SYSTEMD" = "1" ] && [ "${#PK_ZRAM[@]}" -gt 0 ]; then
  cp "$SOC_ROOT/security/zram.conf" /etc/systemd/zram-generator.conf
fi
cp "$SOC_ROOT/security/99-soc-sysctl.conf" /etc/sysctl.d/99-soc.conf
sysctl --system >/dev/null 2>&1 || true
[ "$HAS_SYSTEMD" = "1" ] && systemctl daemon-reload

# --------------------------------------------------------------------------- #
log "Configuring kiosk session for $KIOSK_USER (SESSION=$SESSION)"
HOME_DIR="$(getent passwd "$KIOSK_USER" | cut -d: -f6)"
install -d -o "$KIOSK_USER" -g "$KIOSK_USER" "$HOME_DIR/.config/openbox"
# rc.xml with the grid placement rules from panels.yaml. 1920x1080 is only the
# install-time default: xinitrc regenerates it from xrandr at every X session
# start (display.auto), and wayland-session.sh does the same for labwc.
RES_W=1920; RES_H=1080
cp "$SOC_ROOT/openbox/menu.xml"  "$HOME_DIR/.config/openbox/menu.xml"
cp "$SOC_ROOT/openbox/autostart" "$HOME_DIR/.config/openbox/autostart"
"$SOC_ROOT/.venv/bin/python" "$SOC_ROOT/scripts/gen-openbox-rc.py" \
  --panels "$ETC/panels.yaml" --template "$SOC_ROOT/openbox/rc.xml.tmpl" \
  --out "$HOME_DIR/.config/openbox/rc.xml" --width "$RES_W" --height "$RES_H"
cp "$SOC_ROOT/scripts/xinitrc" "$HOME_DIR/.xinitrc"
# session dispatcher on tty1 login (picks X11/Wayland per SOC_SESSION)
cat > "$HOME_DIR/.bash_profile" <<EOF
export SOC_ROOT=$SOC_ROOT
if [ -z "\$DISPLAY" ] && [ -z "\$WAYLAND_DISPLAY" ] && [ "\$(tty)" = "/dev/tty1" ]; then
  exec $SOC_ROOT/scripts/start-session.sh
fi
EOF
chown -R "$KIOSK_USER:$KIOSK_USER" "$HOME_DIR/.config" "$HOME_DIR/.xinitrc" "$HOME_DIR/.bash_profile"

if [ "$HAS_SYSTEMD" = "1" ]; then
  log "Enabling tty1 autologin"
  mkdir -p /etc/systemd/system/getty@tty1.service.d
  sed "s/--autologin soc /--autologin $KIOSK_USER /" \
    "$SOC_ROOT/systemd/getty-autologin.conf" > /etc/systemd/system/getty@tty1.service.d/override.conf
  systemctl set-default multi-user.target    # no desktop env; we run our own session
  systemctl daemon-reload
else
  warn "no systemd — set up tty1 autologin for '$KIOSK_USER' with your init."
  warn "  agetty:  agetty --autologin $KIOSK_USER --noclear tty1 (in inittab/respawn)"
  warn "  Its login runs ~$KIOSK_USER/.bash_profile, which execs the SOC session."
fi

# kernel console blanking off (Raspberry Pi). cmdline.txt is a single boot line;
# append only to line 1 ('1 s') so a stray trailing newline can't spawn a second,
# malformed boot line (a plain 's' would append to every line).
if [ -f /boot/firmware/cmdline.txt ] && ! grep -q consoleblank /boot/firmware/cmdline.txt; then
  sed -i '1 s/$/ consoleblank=0/' /boot/firmware/cmdline.txt
fi

# --------------------------------------------------------------------------- #
if [ "$HARDEN" = "1" ]; then
  log "Applying hardening (nftables + sshd)"
  cp "$SOC_ROOT/security/nftables.conf" /etc/nftables.conf

  # Optionally bake the admin subnet in from SSH_ADMIN_CIDR= (e.g. 192.168.1.0/24).
  if [ -n "$SSH_ADMIN_CIDR" ]; then
    sed -i "s|^define ssh_admin_cidr =.*|define ssh_admin_cidr = $SSH_ADMIN_CIDR    # set by installer|" \
      /etc/nftables.conf
  fi

  # FAIL-CLOSED (SEC-1): never enable a ruleset that accepts SSH from the whole
  # internet. Default is loopback-only; the operator must pick a real subnet.
  eff_cidr="$(awk '/^define ssh_admin_cidr =/{print $4}' /etc/nftables.conf)"
  if [ "$eff_cidr" = "0.0.0.0/0" ]; then
    die "refusing to enable nftables: ssh_admin_cidr is 0.0.0.0/0 (SSH open to the world). Set a real admin subnet: SSH_ADMIN_CIDR=192.168.1.0/24 ./install.sh  (or edit /etc/nftables.conf)."
  fi

  [ "$HAS_SYSTEMD" = "1" ] && systemctl enable nftables.service || \
    warn "no systemd — enable nftables with your init (e.g. rc-update add nftables)"
  log "nftables admin SSH source: $eff_cidr (egress is allowlisted — set vpn_gateways/jump_hosts in /etc/nftables.conf)"
  warn "review /etc/nftables.conf egress sets (vpn_gateways, jump_hosts, dns_servers) before 'systemctl start nftables'"
  install -d /etc/ssh/sshd_config.d
  cp "$SOC_ROOT/security/sshd_hardening.conf" /etc/ssh/sshd_config.d/10-soc-hardening.conf
  warn "sshd hardening installed (key-only). Ensure you have an authorized key before reboot!"
fi

# --------------------------------------------------------------------------- #
# Stamp a successful full install so re-runs + `setup.py deploy` can fast-path
# the package step (skip unless --fresh).
printf 'installed=%s arch=%s session=%s\n' \
  "$(date -Is 2>/dev/null || date 2>/dev/null || echo unknown)" "$ARCH" "$SESSION" \
  > "$ETC/.installed" 2>/dev/null || true

cat <<EOF

$(printf '\033[32mInstall complete.\033[0m')  Next steps:

  0. The wall configures itself ONCE on first boot: a setup page runs on tty1
     (screen preset + panels, and the vault PIN if not sealed here), writes
     $ETC/.configured, then the wall launches; every later boot goes straight in.
     Configure now instead of at boot:  $SOC_ROOT/launch.sh --setup
     Diagnose / fix any time:           $SOC_ROOT/launch.sh --repair
  1. Edit $ETC/panels.yaml         -> your panels (IPs, ports, selectors, vault_item, tunnel, vpn)
     (or let the wizard write it; the config is then pushed into Vaultwarden as
      the 'SOC Wall Config' note — the wall's source of truth at boot)
  2. Edit $ETC/soc.env             -> email/url + SOC_SESSION (NON-SECRET; the
     master password is NOT here — it is sealed at first-run, step 3).
  3. First-time setup: python3 $SOC_ROOT/setup.py first-run
     -> generates a ONE-TIME PIN + seals the master password host-bound (no
        plaintext .env), and points rbw at pinentry-vault.py. Record the PIN.
  3. Vaultwarden config is in its systemd unit (no .env). /admin is off; to create
     the account, temporarily allow signups (systemctl edit vaultwarden ->
     Environment=SIGNUPS_ALLOWED=true), restart, create it, then revert.
  4. Start the vault:   $([ "$HAS_SYSTEMD" = 1 ] && echo "systemctl start vaultwarden" || echo "(start vaultwarden via your init)")
     Create the kiosk account in the web vault (http://<host>:8222 via SSH tunnel
     or temporarily on the LAN), add your logins named to match vault_item.
     If using the Fortinet VPN, also add a login named to match vpn.vault_item
     (FortiGate username + password) — see docs/CONFIGURATION.md (vpn section).
     If using a proxy with auth, add a login for it and set proxy.vault_item.
  5. Tunnel key (if used): see $SOC_ROOT/security/tunnel_key.note
  6. Reboot:  $([ "$HAS_SYSTEMD" = 1 ] && echo "systemctl reboot" || echo "reboot")
$([ "$HAS_SYSTEMD" = 1 ] || printf '%s\n' "  NOTE: no systemd here — see the warnings above for service supervision +")
$([ "$HAS_SYSTEMD" = 1 ] || printf '%s\n' "        tty1 autologin you must wire into your init before the wall starts.")

The wall comes up automatically on tty1 -> $([ "$SESSION" = x11 ] && echo "startx -> Openbox" || echo "cage/labwc (Wayland)") -> logged-in panels.
Debugging: $([ "$HAS_SYSTEMD" = 1 ] && echo "journalctl -t soc-kiosk -f (host)  journalctl -u forti-vpn -f (VPN)" || echo "the launcher logs to stdout/syslog; run forti-vpn-connect.py in the foreground to watch it")
EOF

# Sanity self-check: confirm the wall user can actually read soc.env. This used
# to silently break (install only ACL'd the SERVICE user, not the KIOSK user)
# and the wall would boot, fail to source soc.env, then silently die at
# vault.open(). Caught at install-time, fixable on the spot.
if [ "$HAS_SYSTEMD" = "1" ] && id "$KIOSK_USER" >/dev/null 2>&1; then
  if ! sudo -u "$KIOSK_USER" cat "$ETC/soc.env" >/dev/null 2>&1; then
    warn "POST-INSTALL CHECK FAILED: $KIOSK_USER cannot read $ETC/soc.env"
    warn "Fix with:  setfacl -m u:$KIOSK_USER:r $ETC/soc.env"
    warn "(or:  chown root:$KIOSK_USER $ETC/soc.env  ;  chmod 0640 $ETC/soc.env)"
  else
    log "post-install: $KIOSK_USER can read $ETC/soc.env ✓"
  fi
fi
