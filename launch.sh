#!/usr/bin/env bash
# =============================================================================
# launch.sh — run / configure / repair the SOC video wall.
#
# This is the APP. The very first run on a host walks through a one-time setup
# page (screen preset + panels, and the vault PIN if it was not sealed at
# install); after that it launches straight to the wall. Installing the OS
# packages is a separate one-time step:  sudo python3 setup.py
#
#   ./launch.sh                 # run the wall (first run configures it once)
#   ./launch.sh --skip-setup    # run the wall without ever opening the setup
#                               # page — marks the install as configured (wall
#                               # shows 'click to configure' tiles for any
#                               # blank panel; vault/sealed master must exist)
#   ./launch.sh --setup         # run the first-time setup page now, then exit
#   ./launch.sh --reconfigure   # re-run the setup page, then run
#   ./launch.sh --repair        # diagnose + fix this install (setup.py doctor/repair)
#   ./launch.sh --help
#
# Configuring the wall writes to /etc/soc-display, so --setup/--reconfigure (and
# the first-run configure) need root — re-run with sudo when asked.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"

log(){  printf '\033[36m==>\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m!!\033[0m %s\n' "$*"; }
usage(){ sed -n '4,17p' "$0" | sed 's/^# \{0,1\}//'; }

MODE="run"
SKIP_SETUP=0
for a in "$@"; do
  case "$a" in
    --setup)        MODE="setup" ;;
    --reconfigure)  MODE="reconfigure" ;;
    --repair)       MODE="repair" ;;
    --skip-setup)   SKIP_SETUP=1 ;;
    -h|--help)      usage; exit 0 ;;
    *) echo "unknown option: $a (try --help)" >&2; exit 2 ;;
  esac
done

# ---- bare TTY chooser (no flags) -------------------------------------------
if [ $# -eq 0 ] && [ -t 0 ] && [ -t 1 ]; then
  printf '\n\033[36mSOC video wall\033[0m — choose:\n'
  printf '  1) Launch       (run the wall; the first run configures it)\n'
  printf '  2) Configure    (run the first-time setup page now)\n'
  printf '  3) Repair       (diagnose + fix this install)\n'
  printf 'Selection [1]: '
  read -r _c || _c=1
  case "${_c:-1}" in
    1|"") MODE="run" ;;
    2)    MODE="setup" ;;
    3)    MODE="repair" ;;
    *)    warn "invalid selection '${_c}' — launching"; MODE="run" ;;
  esac
fi

# Prefer the deployed venv python (has cryptography/PyYAML for sealing + config);
# fall back to system python3 (setup.py itself is pure stdlib).
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="python3"

MARKER="/etc/soc-display/.configured"

require_root(){      # $1 = how to re-invoke (for the hint)
  if [ "$(id -u)" -ne 0 ]; then
    warn "configuring the wall writes to /etc/soc-display — re-run with sudo:"
    warn "    sudo $0 ${1:-}"
    exit 1
  fi
}

# ---- repair ----------------------------------------------------------------
if [ "$MODE" = "repair" ]; then
  log "Diagnose + repair (setup.py)"
  "$PY" setup.py repair || true
  exec "$PY" setup.py doctor
fi

# ---- explicit (re)configure ------------------------------------------------
if [ "$MODE" = "setup" ]; then
  require_root --setup
  log "First-time setup page (setup.py firstboot)"
  exec "$PY" setup.py firstboot
fi
if [ "$MODE" = "reconfigure" ]; then
  require_root --reconfigure
  log "Re-running the setup page"
  rm -f "$MARKER" 2>/dev/null || true
  "$PY" setup.py firstboot                         # then fall through to launch
fi

# ---- run: configure once if needed, then hand off to the boot session ------
if [ ! -e "$MARKER" ]; then
  if [ "$SKIP_SETUP" = "1" ]; then
    # Operator chose to launch without ever opening the wizard. Mark the
    # install configured + warn loudly: the wall WILL come up, but any
    # unconfigured panel shows the 'click to configure' card until the
    # operator pins it via the ⚙ Settings window at the glass. The vault
    # + sealed master MUST already exist (no fresh-install bootstrap
    # here — for that, run `sudo python3 setup.py` once).
    require_root
    install -m 0644 /dev/null "$MARKER"
    warn "--skip-setup: marked $MARKER without running the wizard."
    warn "  Unconfigured panels will show 'click to configure' tiles."
    warn "  Use ⚙ Settings at the glass to set URLs + vault items."
  else
    require_root
    log "First run on this host — opening the setup page"
    "$PY" setup.py firstboot
  fi
fi

# Decide HOW to launch:
#   tty1 / kiosk path  → start-session.sh starts a fresh compositor (cage/labwc
#                         or X11) and runs the wall under it. Requires
#                         XDG_RUNTIME_DIR for the kiosk user.
#   desktop-session    → DISPLAY / WAYLAND_DISPLAY already point at the user's
#                         existing compositor; we run the wall as a windowed
#                         app on top of it via wall-windowed.sh (which handles
#                         XDG_RUNTIME_DIR, XAUTHORITY discovery, safe env
#                         source, and the respawn loop).
#
# The bug we fix here: running `sudo launch.sh` from a desktop terminal
# kept DISPLAY=:1 in root's env (sudo's default env_keep). That made the
# old code take the "Starting the wall session" path, which tried to
# spawn cage as ROOT — cage immediately died because XDG_RUNTIME_DIR
# isn't set for root. The right move when we're root in someone else's
# desktop session is to drop to the kiosk user + use wall-windowed.sh.
KIOSK_USER="$(awk -F= '/^SOC_WALL_USER=/ {gsub(/^"|"$/, "", $2); print $2}' \
                /etc/soc-display/soc.env 2>/dev/null)"
[ -z "${KIOSK_USER:-}" ] && KIOSK_USER="soc"

# Is this an existing desktop session (X11 or Wayland) belonging to a
# DIFFERENT user? If so, root running cage is wrong — delegate.
if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] \
    && [ "$(id -u)" = "0" ] \
    && [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "$KIOSK_USER" ]; then
  log "Detected an existing desktop session (DISPLAY=${DISPLAY:-?},"
  log "  WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-?}) belonging to ${SUDO_USER}."
  log "  Running the wall as a windowed app via $KIOSK_USER's launcher."
  log "  (For the tty1 kiosk path instead, run as the kiosk user on tty1.)"
  # Make sure $KIOSK_USER can open windows on the existing display. xhost
  # is per-session + per-user; we run it as the desktop user via sudo so
  # it targets THEIR display state.
  if command -v xhost >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then
    sudo -u "$SUDO_USER" \
      env DISPLAY="${DISPLAY}" \
          XAUTHORITY="${XAUTHORITY:-/run/user/$(id -u "$SUDO_USER")/xauth_*}" \
      xhost "+SI:localuser:$KIOSK_USER" >/dev/null 2>&1 \
      || warn "could not run xhost as $SUDO_USER — if the wall fails on"
    [ $? = 0 ] || warn "  X auth, run: scripts/grant-soc-x-display.sh"
  fi
  # Make sure XDG_RUNTIME_DIR exists for the kiosk user (the launcher
  # tries again, but it can't always escalate; we have root here, so do
  # it now).
  install -d -m 0700 -o "$KIOSK_USER" -g "$KIOSK_USER" \
    "/run/user/$(id -u "$KIOSK_USER")" 2>/dev/null || true
  # Hand off — exec replaces this shell so we don't fall through.
  KIOSK_HOME="$(getent passwd "$KIOSK_USER" | cut -d: -f6)"
  LAUNCHER="${KIOSK_HOME}/wall-launcher.sh"
  [ -x "$LAUNCHER" ] || LAUNCHER="$ROOT/scripts/wall-windowed.sh"
  exec sudo -u "$KIOSK_USER" \
    env DISPLAY="${DISPLAY:-:0}" \
        WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-wayland-0}" \
    bash "$LAUNCHER"
fi

if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
  log "Starting the wall session"
  exec "$ROOT/scripts/start-session.sh"
fi
log "Configured. The wall starts automatically on tty1 — reboot, or start it on"
log "the console. Health check any time:  ./launch.sh --repair"
