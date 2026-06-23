"""
Live VPN log viewer — a small Gtk.Window with one tab per VPN that streams
`journalctl -u forti-vpn[@<name>].service -f` line-by-line, plus a
Reconnect button per tab. Pops up when:
  * the operator clicks a VPN pill in the toolbar,
  * the tray menu's "Show VPN log" item fires,
  * ⚙ Settings → Actions → "Show VPN log" fires,
  * any time the operator triggers a manual reconnect.

The user's exact ask was: "when iNode reconnect it should open up a
small box printing every step and error for all VPNs". This is that
box — every supervisor + driver log line ([soc-vpn] ..., openfortivpn's
own output, the h3csvpn backend's stderr) lands here verbatim. The
journal-stream subprocess runs read-only via the NOPASSWD sudoers
drop-in (soc → sudo -n journalctl).

Design:
  * One Gtk.Window, one Gtk.Notebook tab per VPN entry in conf.vpns.
    Tab labels are the VPN name; titles update with the live state
    (online / connecting / offline) when set_state() is called.
  * Per-tab: Gtk.TextView (read-only, monospace, auto-scroll) +
    Reconnect button (kicks `systemctl restart forti-vpn@<name>` via
    the existing _privileged_systemctl path) + Clear button.
  * Streaming uses subprocess.Popen + GLib.io_add_watch on the
    process's stdout fd — pure event-driven, no polling. On window
    close, all tail processes are SIGTERM'd.
  * The window is single-instance (one viewer per KioskHost); a second
    "open" just present()s the existing window.
"""
from __future__ import annotations

import os
import subprocess
import sys
from typing import Optional

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib, Gdk     # noqa: E402


_MAX_LINES = 5_000          # ring-buffer cap per tab; older trimmed first


def _have_nopasswd_journalctl() -> bool:
    """Cheap probe: can we run `sudo -n journalctl -u <unit>` without
    a prompt? Used at window-build time so the fallback path can warn
    the operator (instead of the subprocess silently hanging on a
    sudo prompt that has no TTY).

    Important: the sudoers drop-in allows a SPECIFIC command shape —
    `journalctl -u <unit> *`, NOT bare `journalctl --version`. The
    probe must use a command that matches the same shape we'll run
    for real, otherwise the warning fires even when journalctl is
    perfectly fine."""
    try:
        r = subprocess.run(
            # `-n 0 --no-pager -u soc-vpn.service` matches the sudoers
            # pattern `journalctl -u soc-vpn.service *`. Returns 0 even
            # when there are no journal entries (the unit may never
            # have run on this box).
            ["sudo", "-n", "/usr/bin/journalctl", "-u", "soc-vpn.service",
             "-n", "0", "--no-pager"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class _VpnTab:
    """One per VPN. Owns its tail subprocess, its TextView buffer, the
    auto-scroll mark, and a Reconnect callback."""

    def __init__(self, name: str, *, on_reconnect, sudo: bool):
        self.name = name or "default"
        self.unit = (f"soc-vpn@{name}.service"
                     if name else "soc-vpn.service")
        self._on_reconnect = on_reconnect
        self._sudo = sudo
        self._proc: Optional[subprocess.Popen] = None
        self._io_tag: Optional[int] = None

        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.box.set_border_width(6)

        # Header — unit name + Reconnect / Clear buttons.
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        unit_lbl = Gtk.Label()
        unit_lbl.set_xalign(0.0)
        unit_lbl.set_markup(f"<tt>{GLib.markup_escape_text(self.unit)}</tt>")
        head.pack_start(unit_lbl, True, True, 0)
        reconn = Gtk.Button(label="Reconnect")
        reconn.set_tooltip_text("systemctl restart this VPN supervisor; "
                                "the log below shows each step + error.")
        reconn.connect("clicked", lambda *_: self._reconnect())
        clr = Gtk.Button(label="Clear")
        clr.set_tooltip_text("Clear the log view (the actual journal "
                             "is untouched; re-open the window to see "
                             "the trimmed history again).")
        clr.connect("clicked", lambda *_: self._clear())
        head.pack_start(reconn, False, False, 0)
        head.pack_start(clr, False, False, 0)
        self.box.pack_start(head, False, False, 0)

        # Body — monospace, read-only, scrolling text view.
        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC,
                       Gtk.PolicyType.AUTOMATIC)
        sw.set_min_content_height(280)
        self._buf = Gtk.TextBuffer()
        self._view = Gtk.TextView(buffer=self._buf)
        self._view.set_editable(False)
        self._view.set_cursor_visible(False)
        self._view.set_monospace(True)
        self._view.set_left_margin(6)
        self._view.set_right_margin(6)
        self._view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        sw.add(self._view)
        self.box.pack_start(sw, True, True, 0)

        # An "end" mark we keep on the last char + scroll to after every
        # append, so the operator always sees the freshest line without
        # losing the ability to scroll up.
        self._end_mark = self._buf.create_mark(
            "_soc_end", self._buf.get_end_iter(), False)

    # ---- streaming ----------------------------------------------------- #
    def start_stream(self):
        if self._proc is not None:
            return                                     # already streaming
        # `journalctl -u <unit> -f --no-pager -n 100 -o cat` =
        #   -f       follow (live)
        #   --no-pager  don't pipe through less
        #   -n 100   prime with last 100 lines so the operator sees context
        #   -o cat   one log message per line, NO timestamps/host/unit
        #            (the unit label is already in the tab header)
        cmd = ["/usr/bin/journalctl",
               "-u", self.unit, "-f", "--no-pager",
               "-n", "100", "-o", "cat"]
        if self._sudo:
            cmd = ["sudo", "-n"] + cmd
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,                             # line-buffered
                text=True,
                # New session so SIGTERM on close doesn't get raced by
                # the operator's parent shell.
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError) as e:
            self._append(
                f"[viewer] could not start journalctl for {self.unit}:\n"
                f"  {e}\n"
                f"[viewer] If you see 'sudo: a password is required', the\n"
                f"  sudoers drop-in /etc/sudoers.d/soc-wall-restart isn't\n"
                f"  installed. Re-run install.sh OR install manually:\n"
                f"  sudo install -m 0440 -o root -g root \\\n"
                f"    /opt/soc-display/security/soc-wall-restart.sudoers \\\n"
                f"    /etc/sudoers.d/soc-wall-restart\n")
            return
        # Watch the subprocess's stdout fd for new data. GLib invokes
        # _on_io on the GTK thread, so we can append safely without
        # locks.
        fd = self._proc.stdout.fileno()
        # `IO_IN | IO_HUP` — readable OR end-of-pipe (subprocess died).
        self._io_tag = GLib.io_add_watch(
            fd, GLib.IO_IN | GLib.IO_HUP, self._on_io)

    def _on_io(self, _source, condition):
        if condition & GLib.IO_HUP:
            self._append(f"[viewer] journalctl exited for {self.unit}\n")
            return False
        try:
            line = self._proc.stdout.readline()
        except (OSError, ValueError):
            return False
        if not line:
            return False                               # EOF → unregister
        self._append(line)
        return True                                    # keep watching

    def _append(self, text: str):
        # Trim the buffer to _MAX_LINES from the bottom so 24/7 wall
        # operation can't pin memory on a chatty VPN. Cheap: count
        # newlines in the buffer + delete from the start.
        end = self._buf.get_end_iter()
        self._buf.insert(end, text)
        # Newline count → trim oldest lines.
        line_count = self._buf.get_line_count()
        if line_count > _MAX_LINES:
            extra = line_count - _MAX_LINES
            start = self._buf.get_start_iter()
            cut_to = self._buf.get_iter_at_line(extra)
            self._buf.delete(start, cut_to)
        # Auto-scroll. scroll_mark_onscreen is the documented "keep
        # this mark visible" call; doesn't fight an operator who
        # has scrolled up to read history (because they're moving
        # the mark via interaction).
        self._view.scroll_mark_onscreen(self._end_mark)

    def _clear(self):
        self._buf.set_text("")

    def _reconnect(self):
        self._append(f"[viewer] reconnect requested for {self.unit}\n")
        try:
            self._on_reconnect(self.name)
        except Exception as e:                         # noqa: BLE001
            self._append(f"[viewer] reconnect raised: {e}\n")

    # ---- lifecycle ----------------------------------------------------- #
    def stop(self):
        if self._io_tag is not None:
            try:
                GLib.source_remove(self._io_tag)
            except (AttributeError, ValueError, TypeError):
                pass
            self._io_tag = None
        p = self._proc
        if p is not None:
            try:
                p.terminate()
                p.wait(timeout=2)
            except (OSError, subprocess.SubprocessError,
                    subprocess.TimeoutExpired):
                try:
                    p.kill()
                except OSError:
                    pass
            self._proc = None


class VpnLogViewer:
    """Single-instance window. Open with .show(focus_name=...). Close
    with .close() — re-show() reuses the same window if alive."""

    def __init__(self, *, on_reconnect, on_close=None):
        self._on_reconnect = on_reconnect
        self._on_close = on_close
        self._win: Optional[Gtk.Window] = None
        self._notebook: Optional[Gtk.Notebook] = None
        self._tabs: dict = {}                          # name → _VpnTab
        self._sudo = _have_nopasswd_journalctl()

    @property
    def is_open(self) -> bool:
        return self._win is not None

    def show(self, vpns, *, focus_name: Optional[str] = None):
        """Open (or present) the viewer. `vpns` is the conf.vpns list
        (each a dict with a `name`). Adds tabs for any VPN not already
        shown; never removes tabs (operator may want to keep watching
        a removed VPN until the window closes)."""
        if self._win is None:
            self._build()
        # Add any missing tabs.
        for v in (vpns or []):
            name = (v.get("name") or "").strip()
            if name in self._tabs:
                continue
            self._add_tab(name)
        # If no VPNs at all, show a synthetic "default" tab so the
        # viewer isn't empty (covers the legacy single-VPN setup).
        if not self._tabs:
            self._add_tab("")
        if focus_name is not None and focus_name in self._tabs:
            # Focus the right tab so a pill-click opens straight to it.
            idx = list(self._tabs.keys()).index(focus_name)
            self._notebook.set_current_page(idx)
        self._win.present()

    def close(self):
        if self._win is None:
            return
        for tab in self._tabs.values():
            tab.stop()
        self._tabs = {}
        try:
            self._win.destroy()
        except Exception:                              # noqa: BLE001
            pass
        self._win = None
        self._notebook = None
        if self._on_close:
            try:
                self._on_close()
            except Exception:                          # noqa: BLE001
                pass

    # ---- internals ---------------------------------------------------- #
    def _build(self):
        self._win = Gtk.Window(type=Gtk.WindowType.TOPLEVEL)
        self._win.set_title("SOC wall — VPN log")
        self._expanded_size = (720, 460)
        self._collapsed_size = (320, 1)                # height clamps to bar
        self._win.set_default_size(*self._expanded_size)
        self._win.set_keep_above(False)                # operator may want it bg
        self._win.connect("delete-event", lambda *_: (self.close(), True)[1])
        # Esc closes.
        self._win.connect("key-press-event", self._on_key)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        outer.set_border_width(8)

        # Top bar: collapse/expand toggle + status summary. Always
        # visible — even in collapsed mode this is what stays on screen.
        self._bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self._collapse_btn = Gtk.Button(label="▾ Collapse")
        self._collapse_btn.set_tooltip_text(
            "Shrink to a thin bar — keeps streaming in the background, "
            "tap Expand to see the log again. Esc closes the window.")
        self._collapse_btn.connect("clicked", lambda *_: self.toggle_collapsed())
        self._summary = Gtk.Label(label="VPN log — streaming")
        self._summary.set_xalign(0.0)
        self._summary.set_hexpand(True)
        # Esc closes; small "Close" too so the bar is self-contained
        # when collapsed (no need to expand-then-X).
        close_btn = Gtk.Button(label="✕")
        close_btn.set_tooltip_text("Close (Esc)")
        close_btn.connect("clicked", lambda *_: self.close())
        self._bar.pack_start(self._collapse_btn, False, False, 0)
        self._bar.pack_start(self._summary, True, True, 0)
        self._bar.pack_start(close_btn, False, False, 0)
        outer.pack_start(self._bar, False, False, 0)

        if not self._sudo:
            warn = Gtk.Label()
            warn.set_xalign(0.0); warn.set_line_wrap(True)
            warn.set_markup(
                "<b>Warning:</b> sudo NOPASSWD for journalctl isn't "
                "available. The log tail subprocess will fail with "
                "'a password is required'. Install the sudoers drop-in "
                "<tt>/etc/sudoers.d/soc-wall-restart</tt> "
                "(re-run install.sh).")
            outer.pack_start(warn, False, False, 0)

        # The body — notebook of per-VPN tabs. Hidden when collapsed.
        self._body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self._notebook = Gtk.Notebook()
        self._notebook.set_scrollable(True)
        self._body.pack_start(self._notebook, True, True, 0)
        outer.pack_start(self._body, True, True, 0)

        self._collapsed = False
        self._win.add(outer)
        self._win.show_all()

    # ---- collapse / expand -------------------------------------------- #
    def toggle_collapsed(self):
        """Operator clicked the Collapse/Expand button. When collapsed,
        the body hides + the window shrinks to JUST the top bar; the
        journalctl tail keeps running in the background so logs land
        the moment the operator expands again. Mirrors what an IDE's
        bottom-panel collapse does."""
        if self._collapsed:
            self._body.show()
            self._collapse_btn.set_label("▾ Collapse")
            try:
                self._win.resize(*self._expanded_size)
            except Exception:                          # noqa: BLE001
                pass
            self._collapsed = False
        else:
            self._body.hide()
            self._collapse_btn.set_label("▸ Expand")
            try:
                # Resize asks the WM; the bar's own natural height
                # dictates the actual collapsed height (≈ 40 px).
                self._win.resize(self._expanded_size[0], 1)
            except Exception:                          # noqa: BLE001
                pass
            self._collapsed = True

    def _on_key(self, _w, event):
        if event.keyval == Gdk.KEY_Escape:
            self.close()
            return True
        return False

    def _add_tab(self, name: str):
        tab = _VpnTab(name, on_reconnect=self._on_reconnect,
                       sudo=self._sudo)
        tab.start_stream()
        label = Gtk.Label(label=(name or "default"))
        self._notebook.append_page(tab.box, label)
        self._notebook.show_all()
        self._tabs[name] = tab
