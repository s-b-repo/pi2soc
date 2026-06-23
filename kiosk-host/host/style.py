"""
Shared look & feel for the wall.

apply_css()  — installs the application CSS once (dark background, status
               card styling). Safe to call multiple times.
PanelFrame   — wraps a panel's webview in a Gtk.Stack with a branded status
               page: "connecting…" while the first load runs, a clear
               offline/recovering card when the panel fails. The webview is
               crossfaded back in the moment a load finishes, so a dark cell
               on the wall always says *why* and what happens next (and the
               stock white WebKit error page is never shown).

A Gtk.Stack is used instead of a Gtk.Overlay on purpose: WebKitWebView renders
through its own native subwindow and paints OVER overlay siblings, so floating
cards above a live webview are not reliable across backends.

Chromium panels run in their own OS process and cannot carry GTK widgets;
their state goes to the journal instead.
"""
from __future__ import annotations

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk  # noqa: E402

BACKGROUND = "#0b1020"

# --- Colour tokens (single source of truth for the wall palette) ---------- #
# Every hex code in the CSS below should be one of these. Keeping the palette
# small + named means future re-skins are one-line changes; ad-hoc inline
# colours rot out of sync with the rest of the surface.
TOKENS = {
    "bg":            "#0b1020",   # primary background (wall + config)
    "bg-toolbar":    "#0a0f1f",   # toolbar / headerbar
    "bg-elev":       "#131a31",   # entries, raised cells
    "bg-elev-2":     "#1b2b4a",   # buttons (idle)
    "border-soft":   "rgba(126,150,255,0.18)",
    "border":        "rgba(126,150,255,0.30)",
    "border-strong": "rgba(126,150,255,0.35)",
    "fg":            "#e7ecff",   # primary text on dark
    "fg-muted":      "#aeb9e6",   # toolbar buttons, less-prominent text
    "fg-soft":       "#c9d3f2",   # body text
    "fg-dim":        "#8694c4",   # captions / sub-labels
    "accent":        "#2f4fd0",   # primary action
    "accent-text":   "#7e96ff",   # accent foreground (links, tags)
    "ok":            "#57d9a3",   # online / success
    "warn":          "#ffb450",   # connecting / amber
    "warn-deep":     "#d9c66a",   # checking
    "err":           "#ff8f80",   # offline / destructive
    "err-text":      "#ff9c8f",   # error-state ids
    "warn-bg":       "rgba(255,180,80,0.18)",  # drift-warning banner
}


def _css() -> bytes:
    t = TOKENS
    src = f"""
window, grid, stack {{ background-color: {t['bg']}; }}

.soc-status {{
  background-color: rgba(10, 15, 32, 0.92);
  border: 1px solid rgba(126, 150, 255, 0.28);
  border-radius: 10px;
  padding: 18px 28px;
}}
.soc-status.error {{ border-color: rgba(255, 120, 110, 0.55); }}

.soc-status-id {{
  color: {t['accent-text']};
  font-weight: bold;
  font-size: 12px;
  letter-spacing: 2px;
}}
.soc-status.error .soc-status-id {{ color: {t['err-text']}; }}

.soc-status-msg {{ color: {t['fg-soft']}; font-size: 15px; }}
.soc-status.error .soc-status-msg {{ color: #ffc2b8; }}

.soc-status spinner {{ color: {t['accent-text']}; min-width: 22px; min-height: 22px; }}

/* on-screen config window + corner gear */
.soc-config {{ background-color: {t['bg']}; }}
.soc-config-title {{ color: {t['fg']}; font-size: 18px; font-weight: bold; }}
.soc-config-sub  {{ color: {t['fg-dim']}; font-size: 12px; }}
.soc-config-tag  {{ color: {t['accent-text']}; font-weight: bold; }}
.soc-config-ok    {{ color: {t['ok']}; font-size: 12px; }}
.soc-config-error {{ color: {t['err']}; font-size: 12px; }}
.soc-config entry {{
  background-color: {t['bg-elev']}; color: {t['fg']};
  border: 1px solid {t['border']}; border-radius: 6px; padding: 6px 8px;
}}
.soc-config entry:focus {{ border-color: {t['accent-text']}; }}
.soc-config button {{
  background-image: none; background-color: {t['bg-elev-2']}; color: {t['fg-soft']};
  border: 1px solid {t['border']}; border-radius: 6px; padding: 6px 12px;
}}
.soc-config-primary {{
  background-color: {t['accent']}; color: #ffffff; border-color: {t['accent']};
}}
.soc-config-sec {{ color: {t['fg-dim']}; }}

/* Destructive buttons (Remove VPN, Delete vault item, Clear PIN).
 * Subtle red outline + label so the destructive intent is visible at a
 * glance without screaming. Honoured by both GtkButton (.destructive-
 * action is the GTK convention) and the new soc- variant. */
.soc-config button.destructive-action,
.destructive-action {{
  background-color: {t['bg-elev-2']};
  color: {t['err']};
  border-color: {t['err']};
}}
.soc-config button.destructive-action:hover,
.destructive-action:hover {{
  background-color: {t['err']};
  color: #ffffff;
}}

.soc-gear, .soc-toolbar-action {{
  background-color: rgba(20,28,54,0.72);
  border: 1px solid {t['border-strong']};
  border-radius: 8px; padding: 3px 12px; margin: 0 2px;
  color: {t['fg-muted']}; font-size: 13px; font-weight: bold;
}}
.soc-gear:hover, .soc-toolbar-action:hover {{
  background-color: {t['accent']}; color: #ffffff;
}}

/* top toolbar (always-visible controls; webviews can't paint over it) */
.soc-toolbar {{
  background-color: {t['bg-toolbar']};
  border-bottom: 1px solid {t['border-soft']};
  padding: 4px 8px;
}}

/* File-hash drift warning bar (Phase 9 — shown above the toolbar when
 * on-disk files don't match the deploy-time manifest). Subtle amber so
 * it reads as "look at me" without being alarming. */
.soc-warn-bar {{
  background-color: {t['warn-bg']};
  border-bottom: 1px solid {t['warn']};
}}
.soc-warn-bar label {{
  color: {t['warn']};
  font-weight: bold;
  font-size: 13px;
}}

/* VPN status pill (top of the wall) */
.soc-vpn-pill {{
  background-image: none;
  background-color: rgba(20,28,54,0.82);
  border: 1px solid {t['border']};
  border-radius: 12px; padding: 3px 14px; margin: 0 2px;
  color: {t['fg-soft']}; font-size: 13px; font-weight: bold;
}}
/* Traffic-light pill colours: green=online, amber=connecting (probe timed
 * out, still mid-handshake), red=offline (refused / iface gone). */
.soc-vpn-pill.online       {{ border-color: rgba(87,217,163,0.7);  color: {t['ok']}; }}
.soc-vpn-pill.connecting   {{ border-color: rgba(255,180,80,0.75); color: {t['warn']}; }}
.soc-vpn-pill.offline      {{ border-color: rgba(255,120,110,0.7); color: {t['err']}; }}
.soc-vpn-pill.checking     {{ color: {t['warn-deep']}; }}
.soc-vpn-pill.unconfigured {{ color: {t['fg-dim']}; }}
"""
    return src.encode("utf-8")


_CSS = _css()

_applied = False


def apply_css():
    """Install the wall CSS for the whole screen (idempotent)."""
    global _applied
    if _applied:
        return
    screen = Gdk.Screen.get_default()
    if screen is None:
        return
    provider = Gtk.CssProvider()
    provider.load_from_data(_CSS)
    Gtk.StyleContext.add_provider_for_screen(
        screen, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    _applied = True


class _StatusCard(Gtk.Box):
    """Centered card: panel name, spinner, one-line message."""

    def __init__(self, panel_id: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.set_halign(Gtk.Align.CENTER)
        self.set_valign(Gtk.Align.CENTER)
        self.get_style_context().add_class("soc-status")

        self._id = Gtk.Label(label=panel_id.upper())
        self._id.get_style_context().add_class("soc-status-id")
        self._spinner = Gtk.Spinner()
        self._msg = Gtk.Label(label="")
        self._msg.get_style_context().add_class("soc-status-msg")
        self._msg.set_line_wrap(True)
        self._msg.set_max_width_chars(46)
        self._msg.set_justify(Gtk.Justification.CENTER)

        self.pack_start(self._id, False, False, 0)
        self.pack_start(self._spinner, False, False, 0)
        self.pack_start(self._msg, False, False, 0)

    def set_state(self, message: str, error: bool, busy: bool):
        ctx = self.get_style_context()
        if error:
            ctx.add_class("error")
        else:
            ctx.remove_class("error")
        self._msg.set_text(message)
        if busy:
            self._spinner.start()
        else:
            self._spinner.stop()
        self._spinner.set_visible(busy)


class PanelFrame(Gtk.Stack):
    """content page (the webview) + status page, crossfaded."""

    def __init__(self, panel_id: str, widget):
        super().__init__()
        apply_css()
        # NONE, not CROSSFADE: a crossfade snapshots the outgoing child to an
        # offscreen surface; a WebKitWebView renders through its own (often
        # native-window) pipeline that doesn't always snapshot cleanly. A plain
        # map/unmap switch shows the card reliably on every backend.
        self.set_transition_type(Gtk.StackTransitionType.NONE)
        self._content = widget
        self._card = _StatusCard(panel_id)
        self.add_named(widget, "content")
        self.add_named(self._card, "status")

    def update(self, message: str, error: bool = False, busy: bool = True):
        """Show the status page with this message."""
        self._card.set_state(message, error, busy)
        self.set_visible_child_name("status")

    def clear(self):
        """Back to the live panel."""
        self._card.set_state("", False, False)
        self.set_visible_child_name("content")
