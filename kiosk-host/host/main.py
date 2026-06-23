"""
SOC kiosk host — entry point.

Boot sequence:
  1. load + validate config (panels.yaml) — a broken config fails loudly with
     every problem listed
  2. open the vault (rbw unlock + sync)  [required]
  3. wait for the VPN (if any) + each tunnel's local port to answer  [best-effort]
  4. create the panel views, staggered:
       layout windows : one GTK window per panel (Openbox/labwc places them)
       layout single  : every WebKit panel in one fullscreen grid window
     (resolved from display.layout + the running backend, see config.resolve_layout)
  5. run the GTK main loop; inject logins on demand; keep sessions alive

Runs natively on X11 and Wayland (GTK picks the backend; we only adapt layout).

Run:  SOC_PANELS_FILE=config/panels.yaml python3 -m host.main
"""
from __future__ import annotations

import os
import signal
import socket
import sys
import time

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib  # noqa: E402

from . import config as cfg  # noqa: E402
from . import perf  # noqa: E402
from .vault import Vault, VaultError  # noqa: E402


def log(msg: str):
    t = time.strftime("%H:%M:%S")
    print(f"{t} [soc-kiosk] {msg}", flush=True)


def detect_backend() -> str:
    """'wayland' or 'x11', from the GDK display GTK actually connected to."""
    disp = Gdk.Display.get_default()
    name = type(disp).__name__ if disp else ""
    return "wayland" if "Wayland" in name else "x11"


def detect_resolution():
    """(width, height) of the primary monitor, or None if it can't be read."""
    try:
        disp = Gdk.Display.get_default()
        mon = disp.get_primary_monitor() or disp.get_monitor(0)
        geo = mon.get_geometry()
        if geo.width > 0 and geo.height > 0:
            return geo.width, geo.height
    except Exception:  # noqa: BLE001
        pass
    return None


def _port_open(host: str, port: int, timeout=1.0) -> bool:
    """Best-effort TCP-connect probe. NEVER raises — every conceivable
    failure (socket.gaierror, socket.timeout, ConnectionRefusedError, no
    route, blocked, ValueError on a bad arg, even SSL on the rare
    connect-then-close path) is caught + returned as False. The wall's
    startup gates (`wait_for_vpn`, `wait_for_tunnels`) loop on this; a
    transient network failure must NEVER bubble up and kill the wall
    before the GTK loop even starts. This used to catch OSError only,
    which left a hole for str/int boundary errors caught only by
    Exception (host=None from a malformed override, for instance)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:                                  # noqa: BLE001
        return False


def wait_for_tunnels(panels, timeout: float):
    tunneled = [p for p in panels if p.mode == "tunnel"]
    for p in tunneled:
        port = p.tunnel_local_port
        if not port:                       # malformed/None tunnel — nothing to wait on
            continue
        log(f"[{p.id}] waiting for tunnel port 127.0.0.1:{port} ...")
        deadline = time.time() + timeout   # per-tunnel budget — a slow first tunnel
        while time.time() < deadline:      # must not starve the rest of the deadline
            if _port_open("127.0.0.1", port):
                log(f"[{p.id}] tunnel up")
                break
            time.sleep(1)
        else:
            log(f"[{p.id}] WARNING tunnel port {port} never came up; "
                f"window will show a connection error")


def heaviest_panel(views):
    """The panel view with the largest measurable RSS, or None if none can be
    measured. Pure (testable) — the memory watchdog uses it to pick a recycle
    target under pressure."""
    best, best_rss = None, -1
    for v in views:
        try:
            rss = v.mem_rss_kb()
        except Exception:                  # noqa: BLE001 — never crash the watchdog
            rss = None
        if rss is not None and rss > best_rss:
            best, best_rss = v, rss
    return best


def wait_for_vpn(vpn: dict, timeout: float):
    """Best-effort gate: if a VPN is enabled with a `ready_probe`
    (host:port reachable only once the VPN is up), wait for it before opening
    VPN-side panels. The VPN itself is brought up by forti-vpn.service; this
    only avoids loading those panels into a dead route. Non-fatal — wrapped
    in a top-level catch so a probe error CANNOT kill the wall during startup
    (a transient gaierror / DNS hiccup / KeyboardInterrupt on a long sleep
    would otherwise propagate out and tear down the host before GTK ran)."""
    try:
        vpn = vpn or {}
        if not vpn.get("enabled"):
            return
        probe = (vpn.get("ready_probe") or "").strip()
        if not probe:
            return
        host, _, port = probe.rpartition(":")
        if not host or not port.isdigit():
            log(f"[vpn] ignoring malformed ready_probe '{probe}' "
                "(want host:port)")
            return
        port = int(port)
        log(f"[vpn] waiting for VPN reachability {host}:{port} ...")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if _port_open(host, port):
                log("[vpn] VPN up")
                return
            time.sleep(1)
        log(f"[vpn] WARNING {host}:{port} never became reachable; "
            f"VPN-side panels may show a connection error "
            f"(check: systemctl status forti-vpn / journalctl -u forti-vpn)")
    except Exception as e:                             # noqa: BLE001
        # The wait is purely advisory — if its own machinery breaks,
        # log loudly + continue. Never let it abort the boot.
        log(f"[vpn] WARNING wait_for_vpn aborted ({e.__class__.__name__}: "
            f"{e}); proceeding without the readiness gate")


class KioskHost:
    def __init__(self, conf: cfg.Config, vault: "Vault | None" = None):
        self.conf = conf
        self.vault = vault or Vault(ttl=cfg.env_float("SOC_CRED_TTL", 30.0, lo=1.0))
        self.panels_view = []          # live panel objects (WebKit/Chromium)
        self.wall = None               # WallWindow in single-window layout
        self._config_win = None        # the on-screen config window, when open
        # Kiosk lock overlay (PIN/TOTP). Constructed unconditionally — `lock()`
        # is cheap and idempotent, so wiring it from the toolbar / tray /
        # Ctrl+Alt+L stays simple. Lock state files live under state_dir().
        from . import locker as _locker
        from . import configwin as _cw
        self._locker = _locker.KioskLocker(_cw.state_dir())
        # Tray is best-effort + only when running windowed (a tty1 kiosk has
        # nowhere for a tray icon to live). Populated in build_and_show().
        self._tray = None

    # creds callback handed to each panel
    def need_login(self, panel):
        # use the panel's vault_item, or a login remembered for this domain
        # (so a domain logged-in-before auto-logs-in on any panel)
        from . import loginmemory
        item = panel.vault_item or loginmemory.vault_item_for(panel.effective_url)
        panel._resolved_vault = item
        if not item:
            return None                   # no creds known -> panel shows the popup
        # a panel with its own vault_item registers its domain immediately, so
        # other panels at the same domain reuse it (login often navigates away,
        # so we can't wait for an in-page "logged in" signal to record it)
        if panel.vault_item:
            loginmemory.remember(panel.effective_url, panel.vault_item)
        try:
            return self.vault.creds(item)
        except VaultError as e:
            log(f"[{panel.id}] vault: {e}")
            return None

    # called by a panel when a login succeeds — remember the domain -> vault item
    def login_success(self, panel):
        from . import loginmemory
        item = getattr(panel, "_resolved_vault", "") or panel.vault_item
        if item:
            loginmemory.remember(panel.effective_url, item)
            log(f"[{panel.id}] login OK — remembered "
                f"{loginmemory.domain_of(panel.effective_url)} -> '{item}'")

    # proxy-credential callback (proxy.vault_item) handed to each panel
    def proxy_creds(self):
        item = self.conf.proxy.vault_item
        if not item:
            return None
        try:
            return self.vault.creds(item)
        except VaultError as e:
            log(f"[proxy] vault: {e}")
            return None

    def open_vault(self):
        backend = os.environ.get("SOC_VAULT_BACKEND", "rbw")
        log(f"opening vault (backend={backend}) ...")
        self.vault.open()
        log("vault unlocked + synced")

    def prewarm_creds(self):
        """Fetch every panel/proxy/remembered login into the cache in the
        background, so the first login of each panel is served from cache and
        never blocks the GTK thread on an rbw call."""
        import threading
        from . import loginmemory
        items = [p.vault_item for p in self.conf.panels if p.vault_item]
        if self.conf.proxy.vault_item:
            items.append(self.conf.proxy.vault_item)
        items += list(loginmemory.load().values())
        if not items:
            return

        def work():
            n = self.vault.prewarm(items, log)
            log(f"prewarmed {n} vault credential(s)")
        threading.Thread(target=work, daemon=True).start()

    def _autosize(self):
        """display.auto: recompute the grid from the real screen size."""
        if not self.conf.display.auto:
            return
        res = detect_resolution()
        if not res:
            return
        d = self.conf.display
        if (d.width, d.height) != res:
            log(f"display auto-detect: {res[0]}x{res[1]} "
                f"(config said {d.width}x{d.height})")
            d.width, d.height = res
            for p in self.conf.panels:
                p.geometry = cfg.compute_geometry(d, p.grid)

    def build_and_show(self):
        backend = detect_backend()
        layout = cfg.resolve_layout(self.conf, backend)
        env_layout = os.environ.get("SOC_LAYOUT", "")
        if env_layout in ("windows", "single"):
            layout = env_layout       # session script override (e.g. under cage)
        log(f"backend={backend} layout={layout}")
        self._autosize()

        # the on-screen config (gear + Ctrl+Shift+C) can be disabled for a
        # locked-down wall: SOC_ONSCREEN_CONFIG=0
        config_cb = (self.open_config
                     if os.environ.get("SOC_ONSCREEN_CONFIG", "1") != "0" else None)
        if config_cb is None:
            log("on-screen config disabled (SOC_ONSCREEN_CONFIG=0)")

        if layout == "single":
            from .wall import WallWindow
            # Tray sits in the system-tray of the desktop session. Pure-kiosk
            # mode on tty1 has no tray surface, so we only construct it when
            # running windowed AND the tray backend probe succeeds.
            windowed = (os.environ.get("SOC_WINDOWED") == "1"
                        or not getattr(self.conf.display, "fullscreen", True))
            if windowed:
                self._install_tray()
            self.wall = WallWindow(
                self.conf, log,
                on_destroy=self.shutdown,
                on_config=config_cb,
                on_vpn=self.vpn_action,
                on_lock=self._lock_wall,
                on_hide_to_tray=(self._hide_to_tray
                                 if self._tray is not None else None),
            )

        stagger = cfg.env_float("SOC_LAUNCH_STAGGER", 1.5, lo=0.0, hi=60.0)
        cdp_base = cfg.env_int("SOC_CDP_BASE_PORT", 9222, lo=1024, hi=65535)
        delay = 0.0
        for idx, panel in enumerate(self.conf.panels):
            if panel.engine == "chromium":
                from .chromium_panel import ChromiumPanel
                view = ChromiumPanel(panel, self.need_login, log,
                                     cdp_port=cdp_base + idx,
                                     proxy=self.conf.proxy,
                                     proxy_creds=self.proxy_creds,
                                     on_login_success=self.login_success)
            else:
                from .webkit_panel import WebKitPanel
                view = WebKitPanel(panel, self.need_login, log,
                                   embedded=self.wall is not None,
                                   proxy=self.conf.proxy,
                                   proxy_creds=self.proxy_creds,
                                   on_config=config_cb,
                                   on_login_success=self.login_success)
                if self.wall is not None:
                    self.wall.attach(panel, view.widget)
            self.panels_view.append(view)
            GLib.timeout_add(int(delay * 1000), self._show_one, view)
            delay += stagger

        if self.wall is not None:
            self.wall.show()
            self._start_vpn_monitor()
            self._check_deploy_drift()
        self._start_mem_watch()

    # ---- memory watchdog ---------------------------------------------------
    def _start_mem_watch(self):
        """On a 1 GB Pi a single leaking dashboard can OOM the box. Periodically
        check MemAvailable and, under sustained pressure, recycle one panel
        (heaviest measurable first) to reclaim memory — with hysteresis and a
        cooldown so it can't thrash."""
        if perf.mem_available_mb() is None:
            return                          # not Linux/proc — nothing to watch
        self._mem_min_mb = cfg.env_int("SOC_MEM_MIN_AVAIL_MB", 96, lo=16, hi=8192)
        self._mem_check_sec = cfg.env_int("SOC_MEM_CHECK_SEC", 30, lo=5, hi=3600)
        self._mem_cooldown = cfg.env_int("SOC_MEM_RECYCLE_COOLDOWN", 120, lo=10)
        self._mem_low_streak = 0
        self._mem_last_recycle = 0.0
        self._mem_rr = 0
        log(f"memory watchdog on: recycle a panel when MemAvailable < "
            f"{self._mem_min_mb} MB (every {self._mem_check_sec}s)")
        GLib.timeout_add_seconds(self._mem_check_sec, self._check_memory)

    def _check_memory(self):
        avail = perf.mem_available_mb()
        if not perf.under_pressure(avail, self._mem_min_mb):
            self._mem_low_streak = 0
            return True
        self._mem_low_streak += 1
        now = time.time()
        # need two consecutive low readings (ignore a transient dip) and respect
        # the cooldown since the last recycle
        if self._mem_low_streak < 2 or (now - self._mem_last_recycle) < self._mem_cooldown:
            return True
        view = self._pick_recycle_target()
        if view is not None:
            log(f"[mem] MemAvailable {avail} MB < {self._mem_min_mb} MB — "
                f"recycling panel {view.panel.id}")
            try:
                view.recycle()
            except Exception as e:          # noqa: BLE001
                log(f"[mem] recycle of {view.panel.id} failed: {e}")
            self._mem_last_recycle = now
            self._mem_low_streak = 0
        return True

    def _pick_recycle_target(self):
        """The heaviest panel with a measurable RSS (Chromium); otherwise reload
        WebKit panels round-robin (their RSS isn't separable)."""
        heaviest = heaviest_panel(self.panels_view)
        if heaviest is not None:
            return heaviest
        if self.panels_view:
            v = self.panels_view[self._mem_rr % len(self.panels_view)]
            self._mem_rr += 1
            return v
        return None

    # ---- VPN status pill ---------------------------------------------------
    def _start_vpn_monitor(self):
        """Poll the VPN state in the background and keep the wall pill current."""
        if self.wall is None:
            return
        interval = cfg.env_int("SOC_VPN_STATUS_INTERVAL", 10, lo=1, hi=3600)
        self._poll_vpn()                              # immediate first reading
        GLib.timeout_add_seconds(max(3, interval), self._poll_vpn_periodic)

    def _poll_vpn_periodic(self):
        self._poll_vpn()
        return True                                   # keep the timeout alive

    def _poll_vpn(self):
        # the probe can block (TCP connect), so compute off the GTK thread
        import threading
        from . import vpnstatus

        # Skip this tick if the previous probe is still running, so a slow/hung
        # connect near the poll interval can't pile up daemon threads. But a
        # daemon thread that is killed (interpreter teardown) or wedges before
        # its finally: would clear the flag never — wedging the pill forever — so
        # force-clear it once the in-flight probe is grossly overdue (> interval*3
        # since it started) and proceed with a fresh probe.
        interval = cfg.env_int("SOC_VPN_STATUS_INTERVAL", 10, lo=1, hi=3600)
        if getattr(self, "_vpn_poll_busy", False):
            started = getattr(self, "_vpn_poll_started", 0.0)
            if time.time() - started < interval * 3:
                return False
            log("[vpn] previous status probe overdue — force-clearing the busy "
                "flag (probe thread may have died)")
        self._vpn_poll_busy = True
        self._vpn_poll_started = time.time()

        def work():
            # Multi-VPN: probe each entry independently and push per-pill
            # updates. A failing probe on one VPN doesn't mask the status of
            # the others.
            results = []
            for idx, v in enumerate(self.conf.vpns or []):
                try:
                    state = vpnstatus.vpn_state(v)
                except Exception:                      # never let the pill crash us
                    state = vpnstatus.STATE_OFFLINE
                name = vpnstatus.vpn_name(v, idx)
                label_state = {"not_configured": "unconfigured",
                               "connecting": "connecting"}.get(state, state)
                short = {"online": "online", "offline": "offline",
                         "connecting": "connecting",
                         "not_configured": "off"}.get(state, state)
                results.append((name, label_state, f"{name}: {short}"))
            GLib.idle_add(self._clear_vpn_busy)
            GLib.idle_add(self._set_pills, results)
        threading.Thread(target=work, daemon=True).start()
        return False

    def _clear_vpn_busy(self):
        self._vpn_poll_busy = False
        return False

    def _set_pills(self, results):
        """Apply per-VPN pill updates: results is a list of (name, css, label)."""
        if self.wall is not None:
            for name, css, label in results:
                self.wall.set_vpn_status(css, label, name=name)
        return False

    def vpn_action(self, name: str = ""):
        """Pill click: show 'checking', best-effort reconnect the named VPN's
        service, then re-poll. With `name` empty (legacy), restarts the first."""
        target_unit = f"forti-vpn@{name}" if name else "forti-vpn"
        if self.wall is not None:
            self.wall.set_vpn_status("checking", f"{name or 'VPN'}: checking…",
                                     name=name)
        # Don't bother restarting a disabled VPN — just re-poll
        target_vpn = next((v for v in (self.conf.vpns or [])
                           if v.get("name") == name), {}) if name else (
            self.conf.vpn or {})
        if not target_vpn.get("enabled"):
            self._poll_vpn()
            return
        import subprocess
        import threading

        def work():
            try:                                       # best-effort; needs privilege
                subprocess.run(["systemctl", "restart", target_unit],
                               timeout=10, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                log(f"VPN reconnect requested (systemctl restart {target_unit})")
            except Exception as e:  # noqa: BLE001
                log(f"VPN reconnect not permitted from the wall ({e}); re-checking")
            GLib.timeout_add_seconds(2, self._poll_vpn)
        threading.Thread(target=work, daemon=True).start()

    # ---- on-screen configuration ------------------------------------------
    def open_config(self):
        """Open the floating, PIN-lockable config window (gear / Ctrl+Shift+C)."""
        if getattr(self, "_config_win", None) is not None:
            self._config_win.present()
            return
        try:
            from .configwin import ConfigWindow
            win = ConfigWindow(self.conf.panels, self.apply_config,
                               on_close=self._config_closed,
                               display=self.conf.display,
                               vpns=self.conf.vpns,
                               proxy=self.conf.proxy,
                               tunnel=self.conf.tunnel,
                               proxy_vault_item=self.conf.proxy.vault_item,
                               login_stats=self.login_stats,
                               vault=self.vault,
                               actions={
                                   "restart_wall": self.restart_wall,
                                   "reload_panels": self.reload_all_panels,
                                   "lock_wall": self._lock_wall,
                                   "calibrate_panel": self.calibrate_panel,
                               })
            self._config_win = win
            win.show_all()
            win.present()
        except Exception as e:  # noqa: BLE001 — never let the config UI kill the wall
            self._config_win = None
            log(f"config window failed to open: {e}")

    # ---- tray + locker -----------------------------------------------------
    def _install_tray(self):
        """Best-effort: install a tray icon with Show / Lock / Settings /
        Restart / Reboot / Quit. Returns silently if no tray backend is
        available (AyatanaAppIndicator3 / AppIndicator3 / Gtk.StatusIcon)."""
        try:
            from . import tray as _tray
        except Exception as e:  # noqa: BLE001
            log(f"tray module import failed: {e}")
            return
        if not _tray.available():
            log("no tray backend available — close button will quit")
            return
        t = _tray.Tray(app_id="soc-wall", icon_name="video-display",
                       title="SOC wall")
        ok = t.install([
            ("Show wall",         lambda: self.wall and self.wall.window.present()),
            ("Lock panel",        self._lock_wall),
            None,
            ("Open Settings",     self.open_config),
            ("Restart wall",      self.restart_wall),
            None,
            ("Reboot machine",    self._tray_reboot),
            None,
            ("Quit",              self.shutdown),
        ])
        if ok:
            self._tray = t
            log(f"tray installed (backend={t.backend})")
        else:
            log("tray install failed")

    def _lock_wall(self):
        """Show the kiosk-lock overlay. Panels keep rendering underneath;
        keyboard + mouse are inert until the operator enters PIN/TOTP."""
        try:
            self._locker.lock(on_unlock=None)
        except Exception as e:  # noqa: BLE001
            log(f"lock failed: {e}")

    def _hide_to_tray(self):
        """delete-event callback when tray is active — hide the window. The
        wall keeps running; clicking the tray's "Show wall" brings it back."""
        if self.wall is not None and self.wall.window is not None:
            self.wall.window.hide()

    def _tray_reboot(self):
        """systemd reboot — needs root. Falls back to a journal note if not."""
        import subprocess
        log("tray: reboot requested")
        try:
            subprocess.run(["systemctl", "reboot"], timeout=10,
                           stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True)
        except Exception as e:  # noqa: BLE001
            log(f"tray: reboot needs root ({e}) — run sudo systemctl reboot")

    def _check_deploy_drift(self):
        """Compare on-disk file hashes against the deploy-time manifest;
        paint a top-bar warning if anything has drifted.
        Best-effort + non-fatal: missing manifest, unreadable manifest, or
        any other error is logged at INFO and skipped — the warning only
        appears when we positively find drift."""
        try:
            from . import manifest as _mf
        except Exception as e:                         # noqa: BLE001
            log(f"manifest check skipped: import failed ({e})")
            return
        deploy_root = os.environ.get("SOC_DEPLOY_ROOT", "/opt/soc-display")
        try:
            drift = _mf.check_drift(deploy_root)
        except FileNotFoundError:
            log(f"manifest check skipped: no manifest at "
                f"{_mf.MANIFEST_PATH} (re-run install.sh to enable)")
            return
        except (OSError, ValueError, KeyError) as e:
            log(f"manifest check skipped: {e}")
            return
        msg = _mf.format_drift_summary(drift)
        if msg and self.wall is not None:
            # Pass the full drift dict so wall.py can open a detail modal
            # listing changed / missing / extras + a clickable URL to the
            # deployed commit on GitHub.
            self.wall.show_top_bar_warning(msg, detail=drift)
            log(f"file drift detected: {len(drift['changed'])} changed, "
                f"{len(drift['missing'])} missing, "
                f"{len(drift['extras'])} extras (commit "
                f"{(drift.get('commit') or 'unknown')[:12]})")
        else:
            log("manifest check ok — no drift")

    def _config_closed(self):
        self._config_win = None

    def calibrate_panel(self, panel_id: str, on_done):
        """Phase 8: start click-zone calibration on the panel matching
        `panel_id`. Routes to webkit_panel.calibrate or chromium_panel.
        calibrate. on_done(zones_dict_or_None) fires once the operator
        finishes (zones dict) or cancels / timeout (None).

        On success we ALSO persist the captured zones into the panel's
        override + the panel.login_zones attribute so the next injected
        JS picks it up without a restart. Save is best-effort — a write
        failure is logged and the override-save is skipped, but the
        in-memory panel.login_zones still has the value so the operator
        can verify the new fallback works before re-applying."""
        # Find the panel + its view.
        view = None
        panel = None
        for v in self.panels_view:
            pid = getattr(getattr(v, "panel", None), "id", None)
            if pid == panel_id:
                view = v
                panel = v.panel
                break
        if view is None or panel is None:
            log(f"calibrate_panel: no view for id={panel_id!r}")
            on_done(None)
            return
        if not hasattr(view, "calibrate"):
            log(f"calibrate_panel: {panel_id} engine has no calibrate() "
                "(needs WebKit or Chromium renderer)")
            on_done(None)
            return

        def _on_zones(zones):
            if zones is not None:
                try:
                    panel.login_zones = dict(zones)
                    self._save_login_zones_override(panel_id, zones)
                except Exception as e:                    # noqa: BLE001
                    log(f"calibrate_panel: persist failed for "
                        f"{panel_id}: {e}")
            try:
                on_done(zones)
            except Exception as e:                        # noqa: BLE001
                log(f"calibrate_panel: on_done raised: {e}")

        try:
            view.calibrate(_on_zones)
        except Exception as e:                            # noqa: BLE001
            log(f"calibrate_panel: view.calibrate raised: {e}")
            on_done(None)

    def _apply_display_live(self, changes: dict, current: dict) -> bool:
        """In-place display update — width/height/fullscreen/cols/rows.

        Mutates `self.conf.display`, then nudges the live WallWindow:
          width/height → window.resize + re-fit (homogeneous grid auto-
            recomputes cell size)
          fullscreen   → window.fullscreen / unfullscreen
          cols/rows    → re-attach every panel widget at its (col, row)
            with set_column_homogeneous / set_row_homogeneous (the new
            cell count picks up automatically from the next paint).

        Returns True on success, False on any unhandled exception (caller
        then falls back to soft-restart). Never raises out — the wall
        must keep running even if a live apply turns out to be a no-op."""
        try:
            wall = self.wall
            if wall is None or wall.window is None:
                return False
            d = self.conf.display
            # Mutate the config first so other paths (override save, status
            # tab) see the new values immediately.
            if "width" in changes:
                d.width = int(changes["width"])
            if "height" in changes:
                d.height = int(changes["height"])
            if "cols" in changes:
                d.cols = int(changes["cols"])
            if "rows" in changes:
                d.rows = int(changes["rows"])
            if "fullscreen" in changes:
                d.fullscreen = bool(changes["fullscreen"])

            # Width / height — resize the window. In fullscreen mode the WM
            # owns the size, so we still update _fit_to_screen for the
            # next size-changed signal.
            if "width" in changes or "height" in changes:
                try:
                    wall.window.resize(d.width, d.height)
                    wall._fit_to_screen()
                except Exception:                        # noqa: BLE001
                    pass

            # Fullscreen toggle — match the new desired state.
            if "fullscreen" in changes:
                want_full = bool(d.fullscreen)
                have_full = bool(getattr(wall, "_fullscreen", True))
                if want_full != have_full:
                    wall._toggle_fullscreen()

            # cols/rows — recompute each panel's geometry, then re-attach
            # widgets to the grid. The Gtk.Grid is homogeneous so cell
            # size follows the grid's own size automatically.
            if "cols" in changes or "rows" in changes:
                from . import config as _cfg
                # Re-derive each panel.geometry from the new cols/rows.
                for p in self.conf.panels:
                    p.geometry = _cfg.compute_geometry(d, p.grid)
                # Detach + reattach so Gtk.Grid recomputes its layout from
                # scratch. Each panel's widget is the existing webview —
                # no reload, no flicker, just a different cell position.
                grid = wall.grid
                widgets = []
                for v in self.panels_view:
                    w = getattr(v, "widget", None)
                    if w is not None:
                        widgets.append((v.panel, w))
                for _p, w in widgets:
                    try:
                        grid.remove(w)
                    except Exception:                    # noqa: BLE001
                        pass
                grid.set_row_homogeneous(True)
                grid.set_column_homogeneous(True)
                for p, w in widgets:
                    try:
                        wall.attach(p, w)
                    except Exception:                    # noqa: BLE001
                        pass
                grid.show_all()
            log(f"display: applied live {sorted(changes)} "
                f"(now {d.cols}x{d.rows} @ {d.width}x{d.height}, "
                f"fullscreen={getattr(d, 'fullscreen', True)})")
            return True
        except Exception as e:                           # noqa: BLE001
            log(f"display: live apply failed ({e}); falling back to "
                "soft-restart")
            return False

    def _save_login_zones_override(self, panel_id: str, zones: dict):
        """Merge {panel_id: {login_zones: zones}} into the overrides file
        so the calibration survives a restart. Reuses configwin's
        save_overrides path to keep the file format consistent."""
        from . import configwin
        ov = configwin.load_overrides()
        per = dict(ov.get(panel_id) or {})
        per["login_zones"] = {k: dict(v) for k, v in zones.items()}
        ov[panel_id] = per
        configwin.save_overrides(ov)
        log(f"saved login_zones override for {panel_id} ({sorted(zones)})")

    def reload_all_panels(self):
        """Reload every panel view in place — no teardown, no exit. Used by
        the Actions tab "Reload panels" button when something has wedged and
        a fresh page should fix it (without paying the 3 s systemd respawn)."""
        n = 0
        for v in self.panels_view:
            try:
                if hasattr(v, "set_url"):
                    v.set_url(v.panel.url or "")
                    n += 1
            except Exception as e:  # noqa: BLE001
                log(f"[{getattr(v.panel, 'id', '?')}] reload failed: {e}")
        log(f"reload_all_panels: refreshed {n}/{len(self.panels_view)} panel(s)")
        return n

    def restart_wall(self):
        """Soft restart: hand the runtime back to whoever launched us so they
        respawn with the current config. Two paths, chosen automatically:

          - systemd-supervised (INVOCATION_ID is set by systemd):
            sys.exit(0). The unit's Restart=always RestartSec=3 brings us
            back within ~3 s.
          - standalone (wall-windowed.sh's while-loop OR a direct python -m
            host.main with no supervisor): sys.exit(0) still works under the
            launcher loop; for the no-launcher case we ALSO arm an os.execv
            fallback that replaces the current process with the same argv
            so the wall comes back regardless of how it was started.

        Scheduled ~500 ms in the future so the GUI paints the 'restarting…'
        message first.

        Used by the Actions-tab Restart button AND by apply_config when a
        change can't be applied in-place (layout backend switch)."""
        in_systemd = bool(os.environ.get("INVOCATION_ID"))
        if in_systemd:
            log("restart_wall: scheduling self-exit (systemd will respawn in ~3s)")
        else:
            log("restart_wall: scheduling self-restart (launcher loop or execv "
                "fallback will respawn)")

        def _restart():
            log("restart_wall: tearing down panel views")
            for v in self.panels_view:
                if hasattr(v, "stop"):
                    try:
                        v.stop()
                    except Exception:                    # noqa: BLE001
                        pass
            if in_systemd:
                log("restart_wall: exiting (systemd will respawn)")
                import sys as _sys
                _sys.exit(0)
                return False
            # Standalone: prefer exit(0) so a wall-windowed.sh launcher
            # loop respawns us; if there IS no launcher (a bare `python -m
            # host.main`), the process would just die — so we ALSO try
            # os.execv as a last-ditch self-replace. Order matters: exit
            # would unwind cleanly; execv replaces immediately.
            try:
                log("restart_wall: re-execing via os.execv")
                import sys as _sys
                os.execv(_sys.executable,
                          [_sys.executable, "-m", "host.main"])
            except OSError as e:                         # noqa: BLE001
                log(f"restart_wall: os.execv failed ({e}); exiting cleanly "
                    "and trusting the launcher loop")
                import sys as _sys
                _sys.exit(0)
            return False
        GLib.timeout_add(500, _restart)

    def login_stats(self) -> dict:
        """Per-panel auto-login retry stats for the ⚙ Status tab. A panel whose
        attempts climbed near the cap without ever firing on_login_success
        likely has a stale login_marker / wrong selectors after the dashboard
        was redesigned — the form fills but the marker never goes away. Audit
        MED #9. Returns {panel_id: {'attempts': int, 'stale': bool}}."""
        out = {}
        for v in self.panels_view:
            try:
                pid = v.panel.id
                attempts = int(getattr(v, "_login_attempts", 0))
            except Exception:                # noqa: BLE001 — be defensive
                continue
            # 'stale' = burnt half the budget without success. MAX_LOGIN_ATTEMPTS
            # caps at 3 today, so threshold is 2.
            out[pid] = {"attempts": attempts, "stale": attempts >= 2}
        return out

    def apply_config(self, changes: dict):
        """Live-apply URL/title/vault edits from the config window to the panels.

        Returns a dict the on-screen Apply button uses to tell the truth about
        what actually went live vs what is queued for the next reboot:
          {"pending_restarts": [...], "write_back": "ok"|"deferred"|"failed"}
        Used to be void — silently lying about VPN/tunnel restarts was the
        cause of the audit finding 'Apply silently fails when wall lacks
        privilege'.
        """
        result = {"pending_restarts": [], "write_back": "ok",
                  "self_restart": False}
        can_restart = self._can_systemctl_restart()
        disp = changes.pop("_display", None)
        if disp and self.wall is not None and "gap" in disp:
            try:                                        # gap applies live
                self.wall.grid.set_row_spacing(disp["gap"])
                self.wall.grid.set_column_spacing(disp["gap"])
            except Exception:  # noqa: BLE001
                pass
        # Display changes — try to apply LIVE first; soft-restart only when
        # we genuinely cannot (the layout windowing model changed, or cells
        # shrunk and existing panels would be orphaned).
        #
        # Live-apply scope (no flicker, no exit):
        #   gap         already applied above (in-place row/col spacing)
        #   width       window.resize() — homogeneous grid auto-resizes
        #   height      same
        #   fullscreen  use the existing _toggle_fullscreen path
        #   cols/rows   reflow the grid in-place IF new cells >= existing
        #               panels (no panel gets orphaned)
        #
        # Soft-restart (exit → launcher / systemd respawn):
        #   layout      single ↔ windows is a windowing-model swap; the
        #               WallWindow type differs. Restart is the clean path.
        #   cols/rows shrinking that would orphan a configured panel —
        #               surfaces a restart so the operator can confirm.
        if disp and self.wall is not None:
            current = {"layout": self.conf.display.layout,
                       "cols": self.conf.display.cols,
                       "rows": self.conf.display.rows,
                       "width": self.conf.display.width,
                       "height": self.conf.display.height,
                       "fullscreen": getattr(self.conf.display,
                                              "fullscreen", True)}
            live_keys = ("width", "height", "fullscreen", "cols", "rows")
            live_changes = {k: disp[k] for k in live_keys
                            if k in disp and disp[k] != current.get(k)}
            layout_change = ("layout" in disp
                             and disp["layout"] != current["layout"])
            # cols/rows shrinkage check — if the new grid is smaller than
            # any existing panel's (col, row), live-reflow would orphan it.
            shrink_orphans = []
            if "cols" in live_changes or "rows" in live_changes:
                new_cols = int(live_changes.get("cols", current["cols"]))
                new_rows = int(live_changes.get("rows", current["rows"]))
                for p in self.conf.panels:
                    col, row = p.grid
                    if col >= new_cols or row >= new_rows:
                        shrink_orphans.append(p.id)
            if layout_change or shrink_orphans:
                result["self_restart"] = True
                if shrink_orphans:
                    result["pending_restarts"].append(
                        f"grid shrink would orphan {shrink_orphans} — "
                        "restart to confirm")
            elif live_changes:
                applied = self._apply_display_live(live_changes, current)
                if applied:
                    result["applied_live"] = sorted(live_changes)
                else:
                    # Live apply errored out — fall back to soft-restart.
                    result["self_restart"] = True
        # Multi-VPN: _vpns is the canonical list; _vpn (legacy) is kept for
        # back-compat callers that still only know about a single VPN.
        vpns_ch = changes.pop("_vpns", None)
        vpn_ch = changes.pop("_vpn", None)
        if vpns_ch is not None:
            self.conf.vpns = list(vpns_ch)
            if can_restart:
                for v in vpns_ch:
                    self._restart_vpn_async(v.get("name") or "")
            else:
                for v in vpns_ch:
                    name = v.get("name") or ""
                    result["pending_restarts"].append(
                        f"forti-vpn@{name}" if name else "forti-vpn")
        elif vpn_ch is not None:
            self.conf.vpn = vpn_ch
            if can_restart:
                self._restart_vpn_async("")
            else:
                result["pending_restarts"].append("forti-vpn")
        proxy_ch = changes.pop("_proxy", None)
        if proxy_ch is not None:
            # ProxyCfg is a dataclass; the panel browsers read it at WebView
            # creation time, so this takes effect on the next launch. We still
            # update the live conf so the vault write-back is current.
            from . import config as _cfg
            self.conf.proxy = _cfg.ProxyCfg(
                enabled=bool(proxy_ch.get("enabled")),
                url=str(proxy_ch.get("url") or ""),
                vault_item=str(proxy_ch.get("vault_item") or ""),
                ignore_hosts=tuple(proxy_ch.get("ignore_hosts") or ()),
            )
            result["pending_restarts"].append("soc-wall (proxy applies on next boot)")
        tunnel_ch = changes.pop("_tunnel", None)
        if tunnel_ch is not None:
            # tunnel section is a free-form dict; merge so advanced keys set in
            # panels.yaml (and not exposed by the form) survive a glass edit
            (self.conf.tunnel or {}).update(tunnel_ch)
            if not self.conf.tunnel:
                self.conf.tunnel = dict(tunnel_ch)
            if can_restart:
                self._restart_tunnel_async()
            else:
                result["pending_restarts"].append("autossh-tunnel")
        by_id = {v.panel.id: v for v in self.panels_view}
        for pid, ch in changes.items():
            view = by_id.get(pid)
            if view is None:
                continue
            if "title" in ch:
                view.panel.title = ch["title"]
            vault_changed = ("vault_item" in ch
                             and ch["vault_item"] != (view.panel.vault_item or ""))
            if vault_changed:
                view.panel.vault_item = ch["vault_item"]
            url_changed = "url" in ch and ch["url"] != (view.panel.url or "")
            if url_changed:
                view.set_url(ch["url"])      # reload (also re-triggers login)
            elif vault_changed and hasattr(view, "set_url"):
                # vault item changed but URL didn't — reload to re-trigger login
                view.set_url(view.panel.url or "")
        result["write_back"] = self._push_config_to_vault()
        if result.get("self_restart"):
            # Soft restart so the new layout/grid/resolution takes effect
            # without an external reboot. systemd respawns us in 3 s.
            self.restart_wall()
        return result

    def _can_systemctl_restart(self) -> bool:
        """True iff this process can `systemctl restart` a unit. The wall runs
        as user `soc` with NoNewPrivileges=yes, so the answer is almost always
        False in production — but it can be True in dev (run as root) or once
        a polkit rule for `org.freedesktop.systemd1.manage-units` is added."""
        import os as _os
        if _os.geteuid() == 0:
            return True
        # polkit rule path — pkexec without a TTY agent fails fast, which is
        # the right signal (no rule installed). We DON'T actually run it here;
        # we just check the system has the agent. Conservative: return False.
        return False

    def _restart_vpn_async(self, name: str = ""):
        """A VPN-tab change — restart the VPN service so it re-reads the config
        (off the GTK thread; best-effort, needs privilege). When `name` is
        non-empty, restarts the templated instance forti-vpn@<name>; otherwise
        the legacy single-VPN unit."""
        import threading
        import subprocess
        unit = f"forti-vpn@{name}" if name else "forti-vpn"

        def work():
            try:
                subprocess.run(["systemctl", "restart", unit], timeout=10,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                log(f"VPN config changed — restarted {unit}")
            except Exception as e:  # noqa: BLE001
                log(f"VPN restart not permitted from the wall ({e})")
        threading.Thread(target=work, daemon=True).start()

    def _restart_tunnel_async(self):
        """A Tunnel-tab change — restart autossh-tunnel so the new jump host /
        identity / forwards come up. Same caveats as _restart_vpn_async."""
        import threading
        import subprocess

        def work():
            try:
                subprocess.run(["systemctl", "restart", "autossh-tunnel"], timeout=10,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                log("tunnel config changed — restarted autossh-tunnel")
            except Exception as e:  # noqa: BLE001
                log(f"tunnel restart not permitted from the wall ({e})")
        threading.Thread(target=work, daemon=True).start()

    def _push_config_to_vault(self) -> str:
        """After an on-screen edit, write the merged config back to the vault note
        (the source of truth) so it does not drift. Off the GTK thread, best-effort
        — the local overrides remain the durable record if this fails.

        Returns a synchronous status:
          'ok'        — write-back scheduled (the async upload may still fail
                        but the prereqs are met)
          'deferred:<reason>'  — write-back skipped; overrides.json is the only
                                 record until the operator resolves <reason>.
                                 At next boot the stale vault note wins, so
                                 surface this loudly to the operator.
        """
        item = os.environ.get("SOC_CONFIG_VAULT_ITEM", "SOC Wall Config")
        if not item:
            return "deferred:SOC_CONFIG_VAULT_ITEM is empty"
        from . import secretstore
        sd = os.environ.get("SOC_SECRET_DIR")
        url = os.environ.get("SOC_VAULT_URL", "")
        email = os.environ.get("SOC_VAULT_EMAIL", "")
        if not url:
            return "deferred:SOC_VAULT_URL is empty"
        if not email:
            return "deferred:SOC_VAULT_EMAIL is empty"
        if not secretstore.is_sealed(sd):
            return "deferred:master password is not host-sealed"
        try:
            master = secretstore.unseal(sd)
        except Exception as e:  # noqa: BLE001
            return f"deferred:cannot unseal master ({e})"
        import threading

        def work():
            try:
                from . import vaultseed
                yaml_text = cfg.to_yaml(self.conf)
                vaultseed.upsert_login(url, email, master, item, "", "",
                                       notes=yaml_text)
                log(f"config written back to vault note '{item}'")
            except Exception as e:  # noqa: BLE001
                log(f"config write-back FAILED (local overrides kept, will be "
                    f"OVERWRITTEN by stale vault note at next boot): {e}")
        threading.Thread(target=work, daemon=True).start()
        return "ok"

    def _show_one(self, view):
        try:
            view.show()
        except Exception as e:  # noqa: BLE001
            log(f"[{view.panel.id}] show failed: {e}")
        return False  # one-shot timeout

    def shutdown(self, *_):
        log("shutting down ...")
        for v in self.panels_view:
            if hasattr(v, "stop"):
                try:
                    v.stop()
                except Exception:
                    pass
        Gtk.main_quit()
        return False


def _config_cache_path() -> str:
    base = os.environ.get("SOC_STATE_DIR") or os.path.expanduser("~/.config/soc-wall")
    return os.path.join(base, "config-cache.yaml")


def _cache_config(text: str):
    """Best-effort: remember the last-known-good vault config so a later boot can
    paint from it if the vault note is briefly unreadable."""
    try:
        p = _config_cache_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(p, 0o600)
    except OSError:
        pass


def _read_cached_config() -> str:
    try:
        with open(_config_cache_path(), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def load_config(vault: Vault) -> cfg.Config:
    """Load the wall config. With the rbw backend the config is the vault's — a
    Vaultwarden secure-note (SOC_CONFIG_VAULT_ITEM, default 'SOC Wall Config') is
    the source of truth, and a local panels.yaml is only an offline fallback. The
    dev backend always reads the file. SOC_CONFIG_FROM_VAULT=0 forces the file."""
    backend = os.environ.get("SOC_VAULT_BACKEND", "rbw")
    item = os.environ.get("SOC_CONFIG_VAULT_ITEM", "SOC Wall Config")
    if backend == "rbw" and item and os.environ.get("SOC_CONFIG_FROM_VAULT", "1") != "0":
        try:
            text = vault.notes(item)
        except VaultError as e:
            log(f"config note '{item}' unreadable ({e}); falling back to the file")
            text = ""
        if text and text.strip():
            _cache_config(text)                  # remember last-known-good
            log(f"config source: vault note '{item}'")
            return cfg.load_str(text, f"vault:{item}")
        cached = _read_cached_config()
        if cached.strip():
            try:
                conf = cfg.load_str(cached, "cache:config-cache.yaml")
                log("config source: last-known-good cache (vault note unavailable)")
                return conf
            except cfg.ConfigError:
                pass
        log(f"config note '{item}' empty/absent; using the local file")
    panels_file = os.environ.get("SOC_PANELS_FILE", "config/panels.yaml")
    log(f"config source: {panels_file}")
    return cfg.load(panels_file)


def main():
    # Geometry preview (no display, no vault needed) — read the local file.
    if os.environ.get("SOC_DRY_RUN") == "1":
        panels_file = os.environ.get("SOC_PANELS_FILE", "config/panels.yaml")
        try:
            conf = cfg.load(panels_file)
        except cfg.ConfigError as e:
            log(f"FATAL config error:\n{e}")
            return 2
        for p in conf.panels:
            g = p.geometry
            log(f"  {p.id:4s} {p.engine:8s} {p.mode:6s} -> {p.effective_url}  "
                f"@ {g.w}x{g.h}+{g.x}+{g.y}")
        return 0

    # 1. open the vault FIRST — with the rbw backend the wall config itself lives
    #    in the vault, so it must be unlocked before we can read the config.
    #    Required: fail loudly if it will not open within the timeout.
    vault = Vault(ttl=cfg.env_float("SOC_CRED_TTL", 30.0, lo=1.0))
    backend = os.environ.get("SOC_VAULT_BACKEND", "rbw")
    log(f"opening vault (backend={backend}) ...")
    ready_timeout = cfg.env_float("SOC_READY_TIMEOUT", 120.0, lo=0.0, hi=3600.0)
    deadline = time.time() + ready_timeout
    while True:
        try:
            vault.open()
            break
        except VaultError as e:
            if time.time() > deadline:
                log(f"FATAL: vault did not open within {ready_timeout}s: {e}")
                return 2
            log(f"vault not ready ({e}); retrying ...")
            time.sleep(3)
    log("vault unlocked + synced")

    # 2. config — from the vault note (rbw) or the local file
    try:
        conf = load_config(vault)
    except cfg.ConfigError as e:
        log(f"FATAL config error:\n{e}")
        return 2
    for w in conf.warnings:
        log(f"WARNING {w}")

    # apply any settings set previously from the on-screen config
    try:
        from .configwin import (load_overrides, apply_overrides_to_panels,
                                 apply_display_override, apply_vpn_override,
                                 apply_vpns_override,
                                 apply_proxy_override, apply_tunnel_override)
        ov = load_overrides()
        if ov:
            apply_display_override(conf.display, ov)
            # Try multi-VPN merge first; if not present, fall back to single.
            if "_vpns" in ov:
                conf.vpns = apply_vpns_override(conf.vpns, ov)
            else:
                apply_vpn_override(conf.vpn, ov)
            apply_proxy_override(conf.proxy, ov)
            apply_tunnel_override(conf.tunnel, ov)
            apply_overrides_to_panels(conf.panels, ov)
            # Grow blank tiles if the operator expanded the grid at the glass —
            # cols*rows is the cap, but if panels < cap there are empty slots
            # waiting for click-to-configure tiles.
            cap = conf.display.cols * conf.display.rows
            existing = {p.id for p in conf.panels}
            for i in range(len(conf.panels), cap):
                pid = f"p{i+1}"
                n = 1
                while pid in existing:
                    n += 1
                    pid = f"p{i+1}_{n}"
                existing.add(pid)
                conf.panels.append(cfg.Panel(
                    id=pid, engine="webkit",
                    grid=(i % conf.display.cols, i // conf.display.cols),
                    mode="direct", vault_item="", selectors={},
                    login_marker="", keepalive=cfg.KeepAlive(strategy="none"),
                ))
            for p in conf.panels:                        # geometry may have moved
                p.geometry = cfg.compute_geometry(conf.display, p.grid)
            log(f"applied {len(ov)} saved override(s) from the on-screen config")
    except Exception as e:  # noqa: BLE001
        log(f"WARNING could not load config overrides: {e}")

    log(f"{len(conf.panels)} panels, grid {conf.display.cols}x{conf.display.rows} "
        f"@ {conf.display.width}x{conf.display.height}")
    if conf.proxy.enabled:
        auth = (f"auth via vault item '{conf.proxy.vault_item}'"
                if conf.proxy.vault_item else "no auth")
        log(f"proxy: {conf.proxy.url} ({auth})")
    if not conf.panels:
        log("FATAL: no panels defined — nothing to show (edit the config)")
        return 2

    host = KioskHost(conf, vault=vault)

    # warm the credential cache off-thread while we wait for VPN/tunnels, so
    # the first login of each panel never blocks the GTK loop on an rbw call
    host.prewarm_creds()

    # 3. VPN + tunnels (best-effort). VPN first: its routes may be what makes a
    #    tunnel's jump host (or a direct VPN-side panel) reachable at all.
    wait_for_vpn(conf.vpn, timeout=ready_timeout)
    wait_for_tunnels(conf.panels, timeout=ready_timeout)

    # 4. windows
    host.build_and_show()

    # 5. signals + main loop
    # GLib's signal helper moved namespaces between PyGObject versions:
    #   * 3.46+   gi.repository.GLibUnix.signal_add (preferred)
    #   * pre-3.46 GLib.unix_signal_add (deprecated but still callable)
    # Try the new module first to silence the deprecation warning on
    # modern systems, fall back transparently on older ones.
    try:
        gi.require_version("GLibUnix", "2.0")
        from gi.repository import GLibUnix as _GLibUnix  # noqa: E402
        _add_signal = lambda s: _GLibUnix.signal_add(  # noqa: E731
            GLib.PRIORITY_DEFAULT, s, host.shutdown)
    except (ValueError, ImportError):
        _add_signal = lambda s: GLib.unix_signal_add(  # noqa: E731
            GLib.PRIORITY_DEFAULT, s, host.shutdown)
    for sig in (signal.SIGINT, signal.SIGTERM):
        _add_signal(sig)
    log("entering GTK main loop")
    Gtk.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
