#!/usr/bin/env bash
# =============================================================================
# launch.sh — first-time bring-up + launch of the SOC video wall.
#
# One command from a fresh checkout to a running wall. Idempotent: it sets up
# only what is missing (Python venv, dev vault), then launches. Safe to re-run.
#
#   ./launch.sh              # in a terminal: menu -> Dev sim / Configure / Production deploy.
#                            #   piped/non-interactive: DEV wall (Xephyr) or headless check.
#   ./launch.sh --headless   # DEV: set up + headless end-to-end check (Xvfb + screenshot)
#   ./launch.sh --setup      # run the guided setup.py menu, then exit (no launch)
#   ./launch.sh --pi         # PRODUCTION: hand off to `sudo python3 setup.py deploy`
#                            #      (OS install -> configure -> seal PIN -> creds -> doctor)
#   ./launch.sh --help
#
# Dev uses the bundled dummy panels + the JSON "dev" vault backend, so it runs
# with no Vaultwarden and no root. To use the real rbw -> Vaultwarden vault in
# dev, run:  SOC_VAULT_BACKEND=rbw ./launch.sh   (rbw must be configured). For a
# real install, use --pi.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"

MODE="dev-window"
for a in "$@"; do
  case "$a" in
    --headless)               MODE="headless" ;;
    --setup)                  MODE="setup" ;;
    --pi|--prod|--production)  MODE="pi" ;;
    -h|--help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a (try --help)" >&2; exit 2 ;;
  esac
done

log(){  printf '\033[36m==>\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m!!\033[0m %s\n' "$*"; }

# ---- no-arg interactive chooser (terminal only) ----------------------------
# Bare `./launch.sh` in a TTY asks which mode to run, so the dev simulation is
# never a surprise. Piped/non-interactive runs keep the dev default; any flag
# skips the menu entirely.
if [ $# -eq 0 ] && [ -t 0 ] && [ -t 1 ]; then
  printf '\n\033[36mSOC video wall\033[0m — choose a mode:\n'
  printf '  1) Dev simulation    (dummy panels + JSON dev vault, no root)\n'
  printf '  2) Configure         (setup.py menu: panels, VPN, proxy, display, vault)\n'
  printf '  3) Production deploy  (sudo setup.py deploy: install -> configure -> seal -> doctor)\n'
  printf 'Selection [1]: '
  read -r _choice || _choice=1
  case "${_choice:-1}" in
    1|"") MODE="dev-window" ;;
    2)    MODE="setup" ;;
    3)    MODE="pi" ;;
    *)    warn "invalid selection '${_choice}' — using Dev simulation"; MODE="dev-window" ;;
  esac
fi

# ---- production: delegate to the full deploy flow --------------------------
if [ "$MODE" = "pi" ]; then
  log "Production first-time deploy -> setup.py deploy"
  if [ "$(id -u)" -eq 0 ]; then exec python3 setup.py deploy
  else exec sudo python3 setup.py deploy; fi
fi

# ---- 1. Python venv (created on first run) ---------------------------------
PY="$ROOT/.venv/bin/python"
if [ ! -x "$PY" ]; then
  log "Creating the Python venv (.venv) + installing deps"
  python3 -m venv --system-site-packages "$ROOT/.venv" \
    || { warn "python3 -m venv failed — on Debian: apt install python3-venv"; exit 1; }
  "$PY" -m pip install -q --upgrade pip
  "$PY" -m pip install -q PyYAML websocket-client cryptography \
    || warn "pip install had problems (PyYAML/websocket-client/cryptography)"
else
  log "venv present (.venv)"
fi

# ---- guided setup only -----------------------------------------------------
if [ "$MODE" = "setup" ]; then
  log "Opening the setup.py menu"
  exec python3 setup.py
fi

# ---- 2. dev vault (JSON backend; no Vaultwarden needed) --------------------
if [ "${SOC_VAULT_BACKEND:-dev}" = "dev" ] && [ ! -f "$ROOT/dev/run/dev-vault.json" ]; then
  log "Seeding the dev vault (dev/run/dev-vault.json)"
  make dev-vault >/dev/null
fi

# ---- 3. launch -------------------------------------------------------------
have_display(){ [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; }

if [ "$MODE" = "headless" ] || ! have_display; then
  [ "$MODE" = "headless" ] || warn "no display detected — running the headless check instead"
  log "Headless end-to-end check (Xvfb + screenshot) -> make verify"
  exec make verify
fi

log "Launching the wall in a window (Xephyr). Ctrl-C to stop."
exec bash dev/run-wall.sh
