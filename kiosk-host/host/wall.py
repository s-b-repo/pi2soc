"""
Single-window layout (display.layout: single): one fullscreen top-level window
holding every WebKit panel in a homogeneous GtkGrid.

This is the native Wayland path — Wayland clients cannot position their own
windows, but a grid inside ONE fullscreen window needs no window management at
all, so it works identically under cage, labwc, sway, Openbox or a bare Xvfb.
Cells track the real screen size automatically (no resolution detection), and
`display.gap` becomes the grid spacing.

Chromium panels cannot be embedded (they are separate OS processes); config
validation rejects layout: single with engine: chromium.
"""
from __future__ import annotations

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk  # noqa: E402

from . import style  # noqa: E402


def _delete_event_action(on_hide_to_tray):
    """Pure logic for delete-event handling — extracted so tests can exercise
    it without constructing a GTK window. Returns True to *swallow* the close
    (tray hide path), False to let GTK propagate to destroy (legacy path)."""
    if on_hide_to_tray is None:
        return False
    try:
        on_hide_to_tray()
    except Exception:                                  # noqa: BLE001
        # If hide-to-tray bombs, fall back to letting the window close
        # rather than leaving an unresponsive zombie on screen.
        return False
    return True


class WallWindow:
    def __init__(self, conf, log, on_destroy=None, on_config=None, on_vpn=None,
                 on_lock=None, on_hide_to_tray=None):
        self.conf = conf
        self.log = log
        self.on_config = on_config        # callable() -> open the config window
        self.on_vpn = on_vpn              # callable(name) -> reconnect VPN named
        self.on_lock = on_lock            # callable() -> show kiosk-lock overlay
        # If on_hide_to_tray is set (i.e. main constructed a tray icon), the
        # close button hides instead of destroys. Without it, close behaves as
        # before — the destroy handler fires and the host shuts down.
        self.on_hide_to_tray = on_hide_to_tray
        # Multi-VPN: one pill per entry in conf.vpns (name + traffic-light
        # colour). Falls back to a single "VPN: not configured" pill when
        # vpns is empty so the toolbar isn't visually empty.
        self.vpn_pills = []
        self.vpn_pill = None              # back-compat alias = pills[0]
        win = Gtk.Window()
        win.set_title("soc-wall")
        try:
            win.set_wmclass("soc-wall", "soc-wall")       # X11 only; harmless on Wayland
        except Exception:
            pass

        grid = Gtk.Grid()
        grid.set_row_homogeneous(True)
        grid.set_column_homogeneous(True)
        grid.set_row_spacing(conf.display.gap)
        grid.set_column_spacing(conf.display.gap)

        style.apply_css()

        # A real top toolbar (NOT an overlay): a loaded WebKitWebView is a native
        # window that paints over GTK overlay siblings, which would hide a
        # floating gear once a panel shows a page. Putting the controls in their
        # own region above the grid keeps them always visible + clickable.
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        toolbar.get_style_context().add_class("soc-toolbar")
        # One pill per configured VPN
        from . import vpnstatus as _vs
        vpns = conf.vpns or []
        if not vpns:
            vpns = [{}]                   # show a single "not configured" pill
        for idx, v in enumerate(vpns):
            name = _vs.vpn_name(v, idx)
            pill = Gtk.Button(label=f"{name}: …")
            pill.get_style_context().add_class("soc-vpn-pill")
            pill.get_style_context().add_class("unconfigured")
            pill.set_tooltip_text(f"VPN '{name}' status — click to re-check / reconnect")
            # closure-by-default: capture name per pill
            pill.connect("clicked", (lambda _b, n=name:
                                     self.on_vpn and self.on_vpn(n)))
            self.vpn_pills.append({"button": pill, "name": name})
            toolbar.pack_start(pill, False, False, 0)
        if self.vpn_pills:
            self.vpn_pill = self.vpn_pills[0]["button"]   # back-compat
        toolbar.pack_start(Gtk.Box(), True, True, 0)        # spacer
        if on_config is not None:
            gear = Gtk.Button(label="⚙ Settings")
            gear.get_style_context().add_class("soc-gear")
            gear.set_tooltip_text("Configure panels (Ctrl+Shift+C)")
            gear.connect("clicked", lambda *_: self.on_config and self.on_config())
            # pack_end pushes right; this lands *right* of the lock button below.
            toolbar.pack_end(gear, False, False, 0)
        if on_lock is not None:
            # pack_end in reverse-visual order: gear is already on the right,
            # pack_end the lock NEXT so it sits to gear's LEFT.
            lock = Gtk.Button(label="🔒 Lock")
            lock.get_style_context().add_class("soc-toolbar-action")
            lock.set_tooltip_text("Lock the wall — unlock with PIN or TOTP "
                                  "(Ctrl+Alt+L). Panels stay visible.")
            lock.connect("clicked", lambda *_: self.on_lock and self.on_lock())
            toolbar.pack_end(lock, False, False, 0)

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        vbox.pack_start(toolbar, False, False, 0)
        vbox.pack_start(grid, True, True, 0)
        win.add(vbox)

        win.connect("key-press-event", self._on_key)
        # window-wide accelerators so the hotkeys still work when a webview has
        # focus: Ctrl+Shift+C opens settings, Ctrl+Alt+L locks the wall.
        accel = Gtk.AccelGroup()
        win.add_accel_group(accel)
        if on_config is not None:
            key, mod = Gtk.accelerator_parse("<Control><Shift>c")
            if key:
                accel.connect(key, mod, 0, self._accel_config)
        if on_lock is not None:
            key, mod = Gtk.accelerator_parse("<Control><Alt>l")
            if key:
                accel.connect(key, mod, 0, self._accel_lock)

        # delete-event fires when the user clicks the close button. With a tray
        # callback installed, we swallow it (window hides, host stays alive).
        # Without one, we let it propagate to destroy, which fires on_destroy
        # exactly as before.
        win.connect("delete-event", lambda *_: _delete_event_action(
            self.on_hide_to_tray))

        if on_destroy:
            # losing the wall window (e.g. the compositor killed it) leaves
            # nothing on screen — exit so the launcher restarts the host
            win.connect("destroy", lambda *_: on_destroy())

        self.window = win
        self.grid = grid

    def _accel_config(self, *_):
        if self.on_config:
            self.on_config()
        return True

    def _accel_lock(self, *_):
        if self.on_lock:
            self.on_lock()
        return True

    def _on_key(self, _w, event):
        ctrl = event.state & Gdk.ModifierType.CONTROL_MASK
        shift = event.state & Gdk.ModifierType.SHIFT_MASK
        # Ctrl+Shift+C opens the on-screen config
        if ctrl and shift and event.keyval in (Gdk.KEY_c, Gdk.KEY_C):
            if self.on_config:
                self.on_config()
            return True
        # F11 toggles fullscreen (handy when running windowed/in dev)
        if event.keyval == Gdk.KEY_F11:
            self._toggle_fullscreen()
            return True
        return False

    def _toggle_fullscreen(self):
        self._fullscreen = not getattr(self, "_fullscreen", True)
        if self._fullscreen:
            self.window.fullscreen()
            self._fit_to_screen()
        else:
            self.window.unfullscreen()

    def show_top_bar_warning(self, text: str):
        """Surface a banner above the toolbar — used for the file-hash
        drift warning at boot. Idempotent: replaces an existing banner
        if any. Click to dismiss for this session (warning re-paints on
        next boot if the drift persists)."""
        # Late-built helper: dismantle previous banner first.
        prev = getattr(self, "_warn_bar", None)
        if prev is not None:
            try:
                prev.destroy()
            except Exception:                          # noqa: BLE001
                pass
            self._warn_bar = None
        if not text:
            return
        bar = Gtk.EventBox()
        bar.get_style_context().add_class("soc-warn-bar")
        lbl = Gtk.Label(label=text)
        lbl.set_xalign(0.0)
        lbl.set_line_wrap(True)
        lbl.set_margin_start(12); lbl.set_margin_end(12)
        lbl.set_margin_top(6);   lbl.set_margin_bottom(6)
        bar.add(lbl)
        bar.set_tooltip_text("Click to dismiss for this session. The "
                             "warning re-paints on next boot if drift "
                             "persists.")

        def _dismiss(*_):
            try:
                bar.destroy()
            except Exception:                          # noqa: BLE001
                pass
            self._warn_bar = None
            return True

        bar.connect("button-press-event", _dismiss)
        # Inject at the very top of the vbox (above the toolbar).
        vbox = self.window.get_child()
        if vbox is not None and hasattr(vbox, "pack_start"):
            vbox.pack_start(bar, False, False, 0)
            vbox.reorder_child(bar, 0)
            bar.show_all()
        self._warn_bar = bar

    def set_vpn_status(self, state: str, label: str, name: str = ""):
        """Update a pill. With `name` empty, updates the first pill (back-compat
        — what the old single-pill code calls). With `name` set, finds the pill
        for that VPN. `state` in online|offline|unconfigured|checking|connecting."""
        target = None
        if name:
            for p in self.vpn_pills:
                if p["name"] == name:
                    target = p["button"]
                    break
        elif self.vpn_pills:
            target = self.vpn_pills[0]["button"]
        if target is None:
            return
        ctx = target.get_style_context()
        for c in ("online", "offline", "unconfigured", "checking", "connecting"):
            ctx.remove_class(c)
        ctx.add_class(state)
        dot = {"online": "● ", "offline": "● ", "checking": "… ",
               "connecting": "◐ "}.get(state, "○ ")
        target.set_label(f"{dot}{label}")

    def attach(self, panel, widget):
        col, row = panel.grid
        widget.set_hexpand(True)
        widget.set_vexpand(True)
        self.grid.attach(widget, col, row, 1, 1)

    def _screen_size(self):
        w, h = self.conf.display.width, self.conf.display.height
        try:
            disp = Gdk.Display.get_default()
            mon = disp.get_primary_monitor() or disp.get_monitor(0)
            geo = mon.get_geometry()
            if geo.width > 0 and geo.height > 0:
                w, h = geo.width, geo.height
        except Exception:  # noqa: BLE001
            pass
        return w, h

    def _fit_to_screen(self, *_):
        """Resize the window to fill the current screen. Needed when there is no
        window manager to maximise us (a resized Xephyr, a bare Xvfb, or a
        resolution/monitor change), where fullscreen() alone is a no-op."""
        w, h = self._screen_size()
        try:
            self.window.move(0, 0)
            self.window.resize(w, h)
        except Exception:  # noqa: BLE001
            pass
        return False

    def show(self):
        # Windowed mode: opt-in via SOC_WINDOWED=1 OR display.fullscreen=false.
        # Opens as a regular WM-managed window sized to display.width/height —
        # the wall lives ON your desktop instead of taking over the screen.
        # F11 still toggles fullscreen at runtime. Defaults to fullscreen so
        # the production kiosk path on a Pi 5 is unchanged.
        import os as _os
        env_windowed = _os.environ.get("SOC_WINDOWED") == "1"
        cfg_fullscreen = getattr(self.conf.display, "fullscreen", True)
        self._fullscreen = not (env_windowed or not cfg_fullscreen)
        w, h = (self.conf.display.width, self.conf.display.height) \
            if not self._fullscreen else self._screen_size()
        self.window.set_default_size(w, h)
        if self._fullscreen:
            self.window.fullscreen()
        else:
            # Stay decorated + resizable so the user can move/close it. Don't
            # set keep-above; the wall is just another app.
            try:
                self.window.set_decorated(True)
                self.window.set_resizable(True)
            except Exception:  # noqa: BLE001
                pass
        self.window.show_all()
        if self._fullscreen:
            self._fit_to_screen()
            # keep filling the screen when it changes size under us: a resized
            # nested window (Xephyr/cage), a monitor hotplug, or a mode switch.
            scr = Gdk.Screen.get_default()
            if scr is not None:
                scr.connect("size-changed", self._fit_to_screen)
                scr.connect("monitors-changed", self._fit_to_screen)
            # also re-fit shortly after first map (some compositors settle late)
            from gi.repository import GLib
            GLib.timeout_add(400, self._fit_to_screen)
        self.log(f"wall window shown ({'fullscreen' if self._fullscreen else 'windowed'}"
                 f"; {w}x{h}; F11 toggles)")
