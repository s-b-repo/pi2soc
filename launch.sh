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

if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
  log "Starting the wall session"
  exec "$ROOT/scripts/start-session.sh"
fi
log "Configured. The wall starts automatically on tty1 — reboot, or start it on"
log "the console. Health check any time:  ./launch.sh --repair"
