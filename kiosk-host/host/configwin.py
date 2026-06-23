"""
On-screen configuration for the SOC wall.

A floating, always-on-top hovering panel an operator opens *at the glass* — via
the corner gear button or Ctrl+Shift+C — to set each tile's URL, vault login,
selectors, VPN/proxy/tunnel/display settings, and Vaultwarden credentials live,
with no SSH and no YAML editing. Changes apply immediately and are written to an
overrides file so they survive a restart.

The window is deliberately **non-modal** and tagged as a UTILITY window: it
hovers above the wall without blocking the panels behind it, and a stray click
elsewhere on the screen does not dismiss it. The only ways to close it are the
title-bar × button or the Close button next to Apply. A focus-out handler
re-presents the window so it cannot be visually buried by the kiosk.

Optional PIN lock: once a PIN is set, the window demands it before showing the
form, so a passer-by can't repoint the wall. The PIN is stored only as a salted
SHA-256 digest (never clear text); it can be set, changed, or removed from
inside the form.

State lives under $SOC_STATE_DIR (default ~/.config/soc-wall):
  overrides.json   {panel_id: {"url": "...", "title": "..."}}
  config.pin       "<salt_hex>$<digest_hex>"   (mode 0600)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib  # noqa: E402

from . import config  # noqa: E402
from . import style  # noqa: E402


# --------------------------------------------------------------------------- #
# State directory + overrides + PIN store (pure, no GTK — unit-testable)
# --------------------------------------------------------------------------- #
# Sentinels for _fetch_creds_with_recovery — distinct singleton objects so
# `is` comparison reliably distinguishes "no such item" / "operator
# cancelled" from a real result dict. Using a plain object() (not a string
# or None) avoids any accidental aliasing.
_NOT_FOUND = object()
_CANCELLED = object()


def state_dir() -> str:
    d = os.environ.get("SOC_STATE_DIR") or os.path.join(
        os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
        "soc-wall")
    os.makedirs(d, exist_ok=True)
    return d


def _overrides_path() -> str:
    return os.path.join(state_dir(), "overrides.json")


def load_overrides() -> dict:
    try:
        with open(_overrides_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def valid_url(url: str) -> bool:
    """A panel URL must be empty (unconfigured) or a valid http(s) URL. Delegates
    to the canonical RFC 3986-aware validator (config.valid_http_url), so the
    glass and the loader agree: file://, javascript:, data:, embedded creds,
    control-char smuggling, and host-less URLs are all rejected here too."""
    return config.valid_http_url(url, allow_empty=True)


def save_overrides(d: dict):
    path = _overrides_path()
    tmp = path + ".tmp"
    # 0600: panel URLs can reveal internal hostnames; keep them owner-only
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def _pin_path() -> str:
    return os.path.join(state_dir(), "config.pin")


def pin_is_set() -> bool:
    return os.path.exists(_pin_path())


def set_pin(pin: str):
    """Store a salted SHA-256 digest of the PIN (0600). Empty pin clears it."""
    if not pin:
        clear_pin()
        return
    salt = os.urandom(16)
    digest = hashlib.sha256(salt + pin.encode("utf-8")).hexdigest()
    path = _pin_path()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(f"{salt.hex()}${digest}")


def clear_pin():
    try:
        os.remove(_pin_path())
    except OSError:
        pass


def verify_pin(pin: str) -> bool:
    try:
        with open(_pin_path(), "r", encoding="utf-8") as fh:
            salt_hex, _, digest = fh.read().strip().partition("$")
        want = hashlib.sha256(bytes.fromhex(salt_hex) + pin.encode("utf-8")).hexdigest()
        return hmac.compare_digest(want, digest)
    except (OSError, ValueError):
        return False


def _totp_path() -> str:
    return os.path.join(state_dir(), "config.totp")


def totp_is_set() -> bool:
    return os.path.exists(_totp_path())


def verify_pin_or_totp(code: str) -> bool:
    """Settings-gate verify: accepts either the saved PIN OR a current TOTP
    code from the enrolled secret. Both paths use hmac.compare_digest /
    constant-time comparisons internally."""
    if not code or not code.strip():
        return False
    code = code.strip()
    if pin_is_set() and verify_pin(code):
        return True
    if totp_is_set():
        from . import totp as _t
        secret = _t.load(_totp_path())
        if secret and _t.verify(secret, code):
            return True
    return False


def require_pin() -> bool:
    """SEC-7: in production the on-screen config must never open without a PIN.
    soc-wall.service bakes SOC_CONFIG_REQUIRE_PIN=1; dev leaves it unset."""
    return os.environ.get("SOC_CONFIG_REQUIRE_PIN", "0") == "1"


def _reauth_verify(code: str) -> bool:
    """Pure verifier shared by every destructive surface in the GUI: PIN
    OR TOTP. Falls back to True (no auth required) ONLY when neither a
    PIN nor a TOTP is enrolled AND the Settings gate is also unconfigured
    (a brand-new install). Phase 6 contract: a destructive action without
    *any* auth path returns False from _require_reauth — operators must
    enrol a PIN / TOTP first."""
    if not code or not code.strip():
        return False
    return verify_pin_or_totp(code)


def _reauth_required() -> bool:
    """True when at least one auth method is enrolled. When False, the
    GUI tells the operator to enrol a PIN/TOTP before destructive
    operations rather than letting deletes happen unauthenticated."""
    return pin_is_set() or totp_is_set()


def gate_unlocked(require_pin_: bool, pin_set: bool) -> bool:
    """Decide whether the config form opens WITHOUT entering a PIN. Pure, so it
    is unit-testable without a display.

      * dev, no PIN set        -> open (convenience)
      * a PIN is set           -> always gated (must enter it)
      * production (require)    -> always gated, even with no PIN set, so a box at
                                   the glass cannot reach the config surface.
    """
    return (not require_pin_) and (not pin_set)


def apply_overrides_to_panels(panels, overrides: dict):
    """Merge a loaded overrides dict onto the panel objects at startup."""
    for p in panels:
        o = overrides.get(p.id)
        if not isinstance(o, dict):
            continue
        if "url" in o and valid_url(o.get("url")):
            p.url = o["url"] or None
            if o.get("url"):
                p.mode = "direct"          # a set URL implies a direct panel
        if o.get("title"):
            p.title = o["title"]
        if "vault_item" in o:
            p.vault_item = o["vault_item"] or ""
        if o.get("engine") in ("webkit", "chromium"):
            p.engine = o["engine"]
        if isinstance(o.get("selectors"), dict):
            p.selectors = {k: v for k, v in o["selectors"].items() if v}
        if "login_marker" in o:
            p.login_marker = o["login_marker"] or p.selectors.get("pass", "")
        if isinstance(o.get("allow_insecure"), bool):
            p.allow_insecure = o["allow_insecure"]
        if isinstance(o.get("allow_media"), bool):
            p.allow_media = o["allow_media"]
        if isinstance(o.get("proxy"), bool):
            p.proxy = o["proxy"]
        if isinstance(o.get("keepalive"), dict):
            ka = o["keepalive"]
            strat = ka.get("strategy")
            if strat in ("none", "reload", "click", "xhr", "mouse"):
                p.keepalive.strategy = strat
            iv = ka.get("intervalSec")
            if isinstance(iv, int) and iv >= 0:
                p.keepalive.intervalSec = iv
        if "relogin_url" in o:
            # Empty string -> clear; non-empty must look like an http URL,
            # else silently drop (don't fight the operator's typo).
            v = o["relogin_url"]
            if not v:
                p.relogin_url = None
            elif valid_url(v) and v.startswith(("http://", "https://")):
                p.relogin_url = v
        if isinstance(o.get("blocked_url_patterns"), list):
            p.blocked_url_patterns = [str(x) for x in o["blocked_url_patterns"]
                                       if isinstance(x, str) and x.strip()]


def apply_vpn_override(vpn: dict, overrides: dict):
    """Merge a saved VPN override (set from the on-screen VPN tab) onto the loaded
    vpn dict at startup. The override is what the operator entered at the glass;
    it merges over the config note/file so advanced fields not on the form
    (set_routes, etc.) are preserved."""
    o = overrides.get("_vpn")
    if isinstance(o, dict):
        vpn.update(o)
    return vpn


def apply_vpns_override(vpns: list, overrides: dict) -> list:
    """Multi-VPN startup merge. The _vpns override is a list of dicts; each is
    merged by name into the corresponding loaded VPN (preserving advanced fields
    set in panels.yaml that the form doesn't expose). Entries in the override
    that don't match any loaded VPN are appended. Returns the updated list."""
    o = overrides.get("_vpns")
    if not isinstance(o, list):
        return vpns
    by_name = {v.get("name"): i for i, v in enumerate(vpns) if v.get("name")}
    for entry in o:
        if not isinstance(entry, dict):
            continue
        n = entry.get("name")
        if n and n in by_name:
            vpns[by_name[n]].update(entry)
        else:
            # New VPN added at the glass that wasn't in the source config.
            vpns.append(dict(entry))
            if n:
                by_name[n] = len(vpns) - 1
    return vpns


def vpn_form_to_dict(v: dict) -> dict:
    """Build a clean vpn config dict from flat on-screen form values: always sets
    enabled+type, keeps only non-empty strings, coerces port/health to int. The
    VPN service re-validates on restart and surfaces problems via its status."""
    out = {"enabled": bool(v.get("enabled")), "type": (v.get("type") or "fortinet")}
    for k in ("gateway", "vault_item", "config", "domain", "realm",
              "trusted_cert", "ready_probe"):
        val = str(v.get(k) or "").strip()
        if val:
            out[k] = val
    if v.get("insecure"):
        out["insecure"] = True
    if v.get("config_from_vault"):
        out["config_from_vault"] = True
    for k in ("port", "health_check_interval"):
        try:
            n = int(v.get(k) or 0)
        except (TypeError, ValueError):
            n = 0
        if n > 0:
            out[k] = n
    return out


def apply_display_override(display, overrides: dict):
    """Apply a saved display override to the DisplayCfg at startup. Covers
    layout/gap (live-applied after the user clicks Apply) AND the grid+resolution
    (cols/rows/width/height/auto, which take effect on next restart — changing
    them while panels are mapped would require destroying and rebuilding the
    whole wall)."""
    o = overrides.get("_display")
    if not isinstance(o, dict):
        return
    if o.get("layout") in ("auto", "windows", "single"):
        display.layout = o["layout"]
    if isinstance(o.get("gap"), int) and o["gap"] >= 0:
        display.gap = o["gap"]
    if isinstance(o.get("auto"), bool):
        display.auto = o["auto"]
    if isinstance(o.get("fullscreen"), bool):
        display.fullscreen = o["fullscreen"]
    for k in ("cols", "rows"):
        v = o.get(k)
        if isinstance(v, int) and 1 <= v <= 8:
            setattr(display, k, v)
    for k in ("width", "height"):
        v = o.get(k)
        if isinstance(v, int) and 320 <= v <= 16384:
            setattr(display, k, v)


def proxy_form_to_dict(p: dict) -> dict:
    """Build a clean proxy override dict from on-screen form values: drops empty
    strings, coerces ignore_hosts (comma- or whitespace-separated) to a clean
    list. The renderer re-validates the URL on next startup; an invalid URL
    becomes 'proxy disabled' rather than crashing the wall."""
    out = {"enabled": bool(p.get("enabled"))}
    url = str(p.get("url") or "").strip()
    if url:
        out["url"] = url
    vi = str(p.get("vault_item") or "").strip()
    if vi:
        out["vault_item"] = vi
    raw = p.get("ignore_hosts")
    if isinstance(raw, str):
        items = [h.strip() for h in raw.replace("\n", ",").split(",")]
    else:
        items = list(raw or [])
    items = [h for h in items if h]
    if items:
        out["ignore_hosts"] = items
    return out


def apply_proxy_override(proxy, overrides: dict):
    """Merge a saved proxy override onto the loaded ProxyCfg at startup."""
    o = overrides.get("_proxy")
    if not isinstance(o, dict):
        return
    if isinstance(o.get("enabled"), bool):
        proxy.enabled = o["enabled"]
    if "url" in o:
        proxy.url = str(o.get("url") or "")
    if "vault_item" in o:
        proxy.vault_item = str(o.get("vault_item") or "")
    if "ignore_hosts" in o:
        v = o.get("ignore_hosts") or []
        proxy.ignore_hosts = tuple(str(h) for h in v if h)


def tunnel_form_to_dict(t: dict) -> dict:
    """Build a clean tunnel-section dict from on-screen form values. extra_forwards
    is split per-line; host_key_checking is constrained to the values autossh
    actually understands. Empty values are dropped so the override stays minimal."""
    out = {"enabled": bool(t.get("enabled", True))}
    for k in ("jump_host", "identity", "known_hosts"):
        v = str(t.get(k) or "").strip()
        if v:
            out[k] = v
    hkc = str(t.get("host_key_checking") or "").strip().lower()
    if hkc in ("yes", "no", "accept-new"):
        out["host_key_checking"] = hkc
    raw = t.get("extra_forwards")
    if isinstance(raw, str):
        items = [ln.strip() for ln in raw.splitlines()]
    else:
        items = list(raw or [])
    items = [ln for ln in items if ln]
    if items:
        out["extra_forwards"] = items
    return out


def apply_tunnel_override(tunnel: dict, overrides: dict):
    """Merge a saved tunnel override onto the loaded tunnel dict at startup. As
    with apply_vpn_override, advanced keys not exposed by the form (e.g. fields
    the operator added by hand to panels.yaml) are preserved through update()."""
    o = overrides.get("_tunnel")
    if isinstance(o, dict):
        tunnel.update(o)
    return tunnel


def _vw_reachable(url: str, timeout: float = 1.0) -> bool:
    """Cheap TCP probe for the Vaultwarden listener — used by the Status tab to
    flag a dead vault before the operator clicks Save on the Credentials tab
    and gets a confusing 'login failed' error. Does NOT speak HTTP; a process
    bound to the port (even if it's not Vaultwarden) reads as 'reachable',
    which is good enough for the tab's purpose."""
    import socket
    import urllib.parse
    try:
        u = urllib.parse.urlparse(url)
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if u.scheme == "https" else 8222)
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


# --------------------------------------------------------------------------- #
# The window
# --------------------------------------------------------------------------- #
class ConfigWindow(Gtk.Window):
    """on_apply(changes: {id: {"url","title"}}) is called when Apply is pressed,
    after the overrides file has been saved; the host applies them live."""

    def __init__(self, panels, on_apply, on_close=None, display=None, vpn=None,
                 proxy=None, tunnel=None, proxy_vault_item="",
                 login_stats=None, vpns=None, actions=None, vault=None):
        super().__init__(title="SOC wall — settings")
        style.apply_css()
        self.panels = panels
        self.on_apply = on_apply
        self.on_close_cb = on_close
        self.display = display          # config.DisplayCfg | None (Display tab)
        # Multi-VPN: `vpns` is the canonical list; `vpn` is the legacy single
        # alias. Either gives us a VPN tab. Internally we always work with a
        # list, padded to 2 entries so the GUI shows a placeholder "VPN 2"
        # section on single-VPN configs — that's the operator's discovery
        # surface for the new multi-VPN feature.
        if vpns is not None:
            self._vpns = [dict(v) for v in vpns]
        elif vpn:
            self._vpns = [dict(vpn)]
        else:
            self._vpns = []
        while len(self._vpns) < 2:
            i = len(self._vpns) + 1
            self._vpns.append({"name": f"vpn-{i}", "enabled": False,
                               "type": "fortinet"})
        self._vpn = self._vpns[0] if (vpn or vpns) else None
        self._proxy = proxy             # config.ProxyCfg | None (Proxy tab)
        self._tunnel = tunnel           # conf.tunnel dict | None (Tunnel tab)
        self._login_stats = login_stats # callable() -> {pid: {attempts, stale}}
        self._actions = actions or {}   # {restart_wall, reload_panels, ...}
        # Vault handle (rbw / Fake backend) so the Credentials tab can
        # list_by_folder + delete items. Optional — Phase 6 inventory
        # degrades to "panels.yaml-derived only" when absent.
        self._vault = vault
        # Back-compat: callers that still pass only proxy_vault_item get a
        # Credentials-tab row but no Proxy tab.
        self._proxy_vault_item = (getattr(proxy, "vault_item", None)
                                  or proxy_vault_item or "")
        self._vpn_ws = []               # list of widget dicts, one per VPN
        self._proxy_w = None
        self._tunnel_w = None
        self._rows = {}
        # "Has any credential enrolled" = PIN OR TOTP (either gates the form).
        self._unlocked = gate_unlocked(require_pin(),
                                        pin_is_set() or totp_is_set())

        self.set_keep_above(True)
        # A floating, always-on-top utility panel — NOT modal. On a full-screen
        # kiosk the modal grab gets released by a stray click on a panel behind
        # the window (some WMs treat the lost grab as a dismiss), which looked
        # like the window had vanished. As a non-modal utility window it just
        # hovers above the wall and the only way out is the title-bar × button
        # (or the Close button next to Apply).
        self.set_modal(False)
        self.set_type_hint(Gdk.WindowTypeHint.UTILITY)
        self.set_skip_taskbar_hint(True)
        self.set_skip_pager_hint(True)
        self.set_deletable(True)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.set_default_size(820, 600)
        self.set_resizable(True)
        self.get_style_context().add_class("soc-config")
        # Re-assert always-on-top whenever focus is stolen, so clicking through
        # to a panel underneath cannot bury the settings window. Cheap (no
        # geometry change), only fires on focus changes.
        self.connect("focus-out-event", self._on_focus_out)
        # No Escape-closes-window — the operator must press × so the panel
        # cannot be dismissed by reflex while typing into a URL field.
        self.connect("destroy", lambda *_: self.on_close_cb and self.on_close_cb())

        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self.add(self._stack)
        self._stack.add_named(self._build_pin_page(), "pin")
        self._stack.add_named(self._build_form_page(), "form")
        self._stack.set_visible_child_name("form" if self._unlocked else "pin")
        # show_all() reverts a Stack to its first child until it is mapped, so
        # re-assert the intended page once the window actually appears.
        self.connect("map", lambda *_: self._stack.set_visible_child_name(
            "form" if self._unlocked else "pin"))

    # ---- PIN gate ----------------------------------------------------------
    def _build_pin_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_border_width(28)
        title = Gtk.Label(label="🔒  Enter PIN")
        title.get_style_context().add_class("soc-config-title")
        self._pin_entry = Gtk.Entry()
        self._pin_entry.set_visibility(False)
        self._pin_entry.set_input_purpose(Gtk.InputPurpose.DIGITS)
        self._pin_entry.set_alignment(0.5)
        self._pin_entry.set_placeholder_text("PIN")
        self._pin_entry.connect("activate", lambda *_: self._try_unlock())
        self._pin_err = Gtk.Label(label="")
        self._pin_err.get_style_context().add_class("soc-config-error")
        self._pin_btn = Gtk.Button(label="Unlock")
        self._pin_btn.get_style_context().add_class("soc-config-primary")
        self._pin_btn.connect("clicked", lambda *_: self._try_unlock())
        self._pin_fails = 0
        for w in (title, self._pin_entry, self._pin_err, self._pin_btn):
            box.pack_start(w, False, False, 0)
        return box

    def _try_unlock(self):
        if verify_pin_or_totp(self._pin_entry.get_text()):
            self._unlocked = True
            self._pin_fails = 0
            self._pin_err.set_text("")
            self._stack.set_visible_child_name("form")
            return
        self._pin_entry.set_text("")
        self._pin_fails += 1
        # rate-limit brute force: lock the input for a growing cooldown
        if self._pin_fails >= 3:
            wait = min(5 * (self._pin_fails - 2), 60)
            self._pin_err.set_text(f"Incorrect PIN — locked for {wait}s "
                                   f"({self._pin_fails} attempts)")
            self._pin_entry.set_sensitive(False)
            self._pin_btn.set_sensitive(False)

            def _unlock_input():
                self._pin_entry.set_sensitive(True)
                self._pin_btn.set_sensitive(True)
                self._pin_err.set_text("")
                return False
            GLib.timeout_add_seconds(wait, _unlock_input)
        else:
            self._pin_err.set_text("Incorrect PIN")

    # ---- config form (tabbed) ----------------------------------------------
    def _build_form_page(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        outer.set_border_width(16)
        head = Gtk.Label(label="SOC wall — settings")
        head.get_style_context().add_class("soc-config-title")
        head.set_xalign(0.0)
        outer.pack_start(head, False, False, 0)

        nb = Gtk.Notebook()
        nb.append_page(self._tab_panels(), Gtk.Label(label="Panels"))
        nb.append_page(self._tab_credentials(), Gtk.Label(label="Credentials"))
        if self.display is not None:
            nb.append_page(self._tab_display(), Gtk.Label(label="Display"))
        if self._vpn is not None:
            nb.append_page(self._tab_vpn(), Gtk.Label(label="VPN"))
        if self._proxy is not None:
            nb.append_page(self._tab_proxy(), Gtk.Label(label="Proxy"))
        if self._tunnel is not None:
            nb.append_page(self._tab_tunnel(), Gtk.Label(label="Tunnel"))
        nb.append_page(self._tab_actions(), Gtk.Label(label="Actions"))
        nb.append_page(self._tab_security(), Gtk.Label(label="Security"))
        nb.append_page(self._tab_status(), Gtk.Label(label="Status"))
        outer.pack_start(nb, True, True, 0)

        self._form_msg = Gtk.Label(label="")
        self._form_msg.get_style_context().add_class("soc-config-ok")
        self._form_msg.set_xalign(0.0)
        self._form_msg.set_line_wrap(True)
        outer.pack_start(self._form_msg, False, False, 0)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.set_halign(Gtk.Align.END)
        close_b = Gtk.Button(label="Close")
        close_b.connect("clicked", lambda *_: self.close())
        apply_b = Gtk.Button(label="Apply")
        apply_b.get_style_context().add_class("soc-config-primary")
        apply_b.connect("clicked", lambda *_: self._apply())
        actions.pack_start(close_b, False, False, 0)
        actions.pack_start(apply_b, False, False, 0)
        outer.pack_start(actions, False, False, 4)
        return outer

    def _tab_panels(self):
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_min_content_height(340)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(8)
        for p in self.panels:
            box.pack_start(self._panel_group(p), False, False, 0)
        scroll.add(box)
        return scroll

    def _panel_group(self, p):
        frame = Gtk.Frame(label=f"  {p.display_name}  ")
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        inner.set_border_width(8)
        g = Gtk.Grid()
        g.set_column_spacing(8)
        g.set_row_spacing(4)
        title_e = Gtk.Entry()
        title_e.set_text(p.title or "")
        title_e.set_placeholder_text("title")
        title_e.set_width_chars(12)
        url_e = Gtk.Entry()
        url_e.set_text(p.url or "")
        url_e.set_hexpand(True)
        url_e.set_placeholder_text("https://host/…  (blank = not configured)")
        url_e.set_input_purpose(Gtk.InputPurpose.URL)
        url_e.connect("activate", lambda *_: self._apply())
        vault_e = Gtk.Entry()
        vault_e.set_text(p.vault_item or "")
        vault_e.set_placeholder_text("vault item")
        vault_e.set_width_chars(13)
        engine_c = Gtk.ComboBoxText()
        for opt in ("webkit", "chromium"):
            engine_c.append_text(opt)
        engine_c.set_active(1 if p.engine == "chromium" else 0)
        for col, (lbl, w) in enumerate((("title", title_e), ("URL", url_e),
                                        ("vault login", vault_e), ("engine", engine_c))):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            g.attach(h, col, 0, 1, 1)
            g.attach(w, col, 1, 1, 1)
        inner.pack_start(g, False, False, 0)

        exp = Gtk.Expander(label="Advanced — selectors + per-panel toggles (apply on restart)")
        adv = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        adv.set_border_width(6)
        ag = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        sel = p.selectors or {}
        user_e = Gtk.Entry(); user_e.set_text(sel.get("user", "")); user_e.set_placeholder_text("user CSS")
        pass_e = Gtk.Entry(); pass_e.set_text(sel.get("pass", "")); pass_e.set_placeholder_text("pass CSS")
        sub_e = Gtk.Entry(); sub_e.set_text(sel.get("submit", "")); sub_e.set_placeholder_text("submit CSS")
        mark_e = Gtk.Entry(); mark_e.set_text(p.login_marker or ""); mark_e.set_placeholder_text("login marker")
        for w in (user_e, pass_e, sub_e, mark_e):
            w.set_width_chars(13)
            ag.pack_start(w, True, True, 0)
        adv.pack_start(ag, False, False, 0)

        # Per-panel toggles that used to be YAML-only. Each is a real correctness
        # / RAM / security knob the operator may need at the glass — exposing
        # them removes "edit panels.yaml + restart" round-trips for the common
        # cases (a panel with self-signed TLS, one that needs WebGL, or one that
        # must bypass the global proxy).
        tg = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        ai_c = Gtk.CheckButton(label="allow self-signed TLS")
        ai_c.set_active(bool(getattr(p, "allow_insecure", False)))
        ai_c.set_tooltip_text("Accept self-signed certs on this panel only "
                              "(trusted LAN). Off by default — system CAs are "
                              "enforced.")
        am_c = Gtk.CheckButton(label="allow media (WebGL/audio/video)")
        am_c.set_active(bool(getattr(p, "allow_media", False)))
        am_c.set_tooltip_text("Re-enables WebGL/WebAudio/<video>. Off by "
                              "default to save RAM/GPU on 1 GB boards. Enable "
                              "if the dashboard uses WebGL Grafana or shows "
                              "video.")
        px_c = Gtk.CheckButton(label="use global proxy (if any)")
        px_c.set_active(bool(getattr(p, "proxy", True)))
        px_c.set_tooltip_text("Off = this panel ALWAYS hits the URL directly, "
                              "bypassing the corporate proxy. Useful for an "
                              "internal dashboard the proxy can't reach.")
        for c in (ai_c, am_c, px_c):
            tg.pack_start(c, False, False, 0)
        adv.pack_start(tg, False, False, 0)

        # Keepalive controls (strategy + interval). The wall's panel reloader
        # nudges idle dashboards so they don't log themselves out / silently
        # break their websockets — exposed here so an operator can change the
        # cadence on a per-panel basis without editing YAML.
        ka = (p.keepalive.__dict__
              if hasattr(getattr(p, "keepalive", None), "__dict__")
              else {})
        kg = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        kg.pack_start(Gtk.Label(label="keepalive:"), False, False, 0)
        ka_strat = Gtk.ComboBoxText()
        # `mouse` = invisible synthetic in-DOM mousemove every interval —
        # resets the dashboard's idle timer without disturbing the operator.
        strats = ["none", "reload", "click", "xhr", "mouse"]
        for s in strats:
            ka_strat.append_text(s)
        cur_strat = ka.get("strategy", "none")
        ka_strat.set_active(strats.index(cur_strat) if cur_strat in strats else 0)
        ka_int = Gtk.SpinButton.new_with_range(0, 86400, 30)
        ka_int.set_value(int(ka.get("intervalSec", 600) or 600))
        kg.pack_start(ka_strat, False, False, 0)
        kg.pack_start(Gtk.Label(label="every (sec):"), False, False, 0)
        kg.pack_start(ka_int, False, False, 0)
        adv.pack_start(kg, False, False, 0)

        # Post-login landing URL — wall navigates here ONCE after auto-login
        # succeeds, so dashboards that log in to /login then need /dashboard
        # don't sit on the login page forever. Validation: must be http(s)
        # if non-empty; an empty entry just keeps the panel on `url`.
        rg = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        rg.pack_start(Gtk.Label(label="relogin URL:"), False, False, 0)
        relogin_e = Gtk.Entry()
        relogin_e.set_text(getattr(p, "relogin_url", "") or "")
        relogin_e.set_placeholder_text("https://host/dashboard  (after login)")
        relogin_e.set_hexpand(True)
        relogin_e.set_tooltip_text("Optional. After auto-login succeeds the "
                                    "wall navigates here once (per page "
                                    "load). Leave empty to stay on the URL.")
        rg.pack_start(relogin_e, True, True, 0)
        adv.pack_start(rg, False, False, 0)

        # Blocked URL patterns — fnmatch-style, one per line. WebKit
        # decide-policy + Chromium Fetch.requestPaused both enforce. Keeps
        # the operator out of dashboard account-settings / change-password
        # pages from the wall without hiding the dashboard itself.
        bg_lbl = Gtk.Label(label="blocked URLs  (fnmatch, one per line — "
                                  "e.g. */account/* or *change-password*)")
        bg_lbl.get_style_context().add_class("soc-config-sub")
        bg_lbl.set_xalign(0.0)
        adv.pack_start(bg_lbl, False, False, 0)
        blocked_tv = Gtk.TextView()
        blocked_tv.set_monospace(True)
        blocked_tv.set_wrap_mode(Gtk.WrapMode.NONE)
        bbuf = blocked_tv.get_buffer()
        bbuf.set_text("\n".join(getattr(p, "blocked_url_patterns", []) or []))
        bsw = Gtk.ScrolledWindow()
        bsw.set_min_content_height(54)
        bsw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        bsw.add(blocked_tv)
        adv.pack_start(bsw, False, False, 0)

        # --- Phase 8: click-zone calibration --------------------------------
        # Last-resort login fallback: when the CSS selectors AND the text-
        # pattern heuristic both miss, the operator can click the three
        # zones (user / pass / submit) on the rendered page; ratios are
        # stored so a resize keeps the calibration accurate.
        cz_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        cz_lbl = Gtk.Label()
        cz_lbl.set_xalign(0.0); cz_lbl.set_line_wrap(True); cz_lbl.set_hexpand(True)
        cz_lbl.get_style_context().add_class("soc-config-sub")
        cz_lbl.set_markup(self._login_zones_status(p))
        cz_btn = Gtk.Button(label="Calibrate login zones")
        cz_btn.set_tooltip_text("Overlay a crosshair on the panel; click "
                                "the username, password, and submit "
                                "elements. Ratios are stored — a resize "
                                "keeps the calibration accurate.")
        cz_clr_btn = Gtk.Button(label="Clear zones")
        cz_clr_btn.set_tooltip_text("Drop the saved zones from this panel. "
                                    "The wall falls back to selectors + "
                                    "text-pattern heuristics.")
        cz_clr_btn.get_style_context().add_class("destructive-action")
        cz_btn.connect("clicked",
                       lambda _b, pid=p.id, lbl=cz_lbl:
                            self._on_calibrate_panel(pid, lbl))
        cz_clr_btn.connect("clicked",
                           lambda _b, pid=p.id, lbl=cz_lbl:
                                self._on_clear_login_zones(pid, lbl))
        cz_box.pack_start(cz_lbl, True, True, 0)
        cz_box.pack_start(cz_btn, False, False, 0)
        cz_box.pack_start(cz_clr_btn, False, False, 0)
        adv.pack_start(cz_box, False, False, 0)

        exp.add(adv)
        inner.pack_start(exp, False, False, 0)
        frame.add(inner)
        self._rows[p.id] = {"url": url_e, "title": title_e, "vault": vault_e,
                            "engine": engine_c, "user": user_e, "pass": pass_e,
                            "submit": sub_e, "marker": mark_e,
                            "allow_insecure": ai_c, "allow_media": am_c,
                            "proxy": px_c, "ka_strat": ka_strat,
                            "ka_int": ka_int,
                            "relogin": relogin_e, "blocked": blocked_tv,
                            "zones_lbl": cz_lbl}
        return frame

    def _login_zones_status(self, p) -> str:
        """Markup string for the per-panel "zones: …" status label.
        Names the captured zones (or notes the absence) so the operator
        sees calibration state at a glance without expanding the panel."""
        zones = getattr(p, "login_zones", None) or {}
        if not zones:
            return ("<b>login zones:</b> none — selectors + heuristics only")
        names = sorted(zones.keys())
        return f"<b>login zones:</b> calibrated ✓  ({', '.join(names)})"

    def _on_calibrate_panel(self, panel_id: str, status_lbl):
        """Wire the per-panel Calibrate button → host.calibrate_panel().
        Updates the status label when the operator finishes."""
        action = self._actions.get("calibrate_panel")
        if action is None:
            self._alert("Calibrate is unavailable in this session — the "
                        "wall wasn't launched with a calibrate-capable "
                        "host (the action wasn't wired by main.py).",
                        error=True, title="Calibrate unavailable")
            return
        # Update the in-memory Panel + the status label once the host
        # writes the override; the operator sees confirmation immediately.
        p = next((pp for pp in self.panels if pp.id == panel_id), None)

        def _on_done(zones):
            if zones is None:
                self._toast(f"{panel_id}: calibration cancelled / timed out")
                return
            if p is not None:
                p.login_zones = dict(zones)
            try:
                status_lbl.set_markup(self._login_zones_status(p
                    if p is not None else type("P", (), {"login_zones": zones})))
            except Exception:                            # noqa: BLE001
                pass
            self._toast(f"{panel_id}: calibrated ✓ ({len(zones)} zones)")
        self._toast(f"{panel_id}: click USER → PASS → SUBMIT on the panel "
                    "(Esc cancels)")
        try:
            action(panel_id, _on_done)
        except Exception as e:                            # noqa: BLE001
            self._alert(f"Calibrate failed to start for '{panel_id}':\n\n{e}",
                        error=True, title="Calibrate failed")

    def _on_clear_login_zones(self, panel_id: str, status_lbl):
        """Drop the panel's saved zones from the override file and the
        live Panel object. Gated by re-auth — same policy as Remove VPN."""
        if not self._require_reauth(f"clearing login zones on '{panel_id}'"):
            return
        ov = load_overrides()
        per = dict(ov.get(panel_id) or {})
        had = bool(per.get("login_zones"))
        per.pop("login_zones", None)
        if not per:
            ov.pop(panel_id, None)
        else:
            ov[panel_id] = per
        save_overrides(ov)
        p = next((pp for pp in self.panels if pp.id == panel_id), None)
        if p is not None:
            p.login_zones = {}
        try:
            status_lbl.set_markup(self._login_zones_status(
                p if p is not None else type("P", (), {"login_zones": {}})))
        except Exception:                                # noqa: BLE001
            pass
        self._toast(f"{panel_id}: login zones cleared"
                    if had else f"{panel_id}: no zones to clear")

    def _tab_credentials(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_border_width(12)
        note = Gtk.Label(label="Top: inventory of vault items the wall "
                               "touches (names only — values are never "
                               "shown here). Delete requires PIN/TOTP "
                               "re-auth. Bottom: write a fresh login into "
                               "Vaultwarden for a panel/VPN/proxy that "
                               "needs one.")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)

        # --- Inventory + delete (Phase 6 central manager). Listed by source:
        #     panels' vault_items, VPNs' vault_items, proxy, tunnel, plus
        #     items in the 'SOC Wall Auth' folder (system TOTPs / future
        #     panel-lock PIN). Deduplicated by item name.
        inv_frame = Gtk.Frame(label="  Vault items in use  ")
        inv_outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        inv_outer.set_border_width(8)
        # Refresh + Sync row at the TOP of the section — the buttons used
        # to be at the BOTTOM, which scrolled off-screen as soon as the
        # inventory grew past the tab height (user-reported: "Refresh
        # from vault — you can't click it"). Top is always visible.
        action_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        refresh_btn = Gtk.Button(label="Refresh from vault")
        refresh_btn.set_tooltip_text("Re-scan panels.yaml + vault folder "
                                     "'SOC Wall Auth' for items.")
        refresh_btn.connect("clicked", lambda *_: self._refresh_cred_inventory())
        sync_btn = Gtk.Button(label="Sync vault (rbw sync)")
        sync_btn.set_tooltip_text("Force rbw to fetch the latest from "
                                  "Vaultwarden. Use when an item you "
                                  "added in the web vault doesn't show up.")
        sync_btn.connect("clicked", lambda *_: self._rbw_sync_now())
        action_row.pack_start(refresh_btn, False, False, 0)
        action_row.pack_start(sync_btn, False, False, 0)
        inv_outer.pack_start(action_row, False, False, 0)
        # The list is in a ScrolledWindow so even hundreds of vault items
        # stay self-contained inside the inventory frame instead of
        # pushing the rest of the tab off the bottom.
        list_scroll = Gtk.ScrolledWindow()
        list_scroll.set_policy(Gtk.PolicyType.NEVER,
                                Gtk.PolicyType.AUTOMATIC)
        list_scroll.set_min_content_height(200)
        list_scroll.set_max_content_height(360)
        self._inv_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        list_scroll.add(self._inv_list)
        inv_outer.pack_start(list_scroll, True, True, 0)
        inv_frame.add(inv_outer)
        box.pack_start(inv_frame, False, False, 0)
        self._refresh_cred_inventory()

        grid = Gtk.Grid()
        grid.set_column_spacing(8)
        grid.set_row_spacing(8)
        for col, t in enumerate(("vault item", "username", "password", "")):
            h = Gtk.Label(label=t)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            grid.attach(h, col, 0, 1, 1)
        seen = set()
        self._cred_r = 1

        def add_row(name, uri):
            name = (name or "").strip()
            if not name or name in seen:
                return
            seen.add(name)
            r = self._cred_r
            nm = Gtk.Label(label=name)
            nm.get_style_context().add_class("soc-config-tag")
            nm.set_xalign(0.0)
            u = Gtk.Entry(); u.set_width_chars(15); u.set_placeholder_text("username")
            pw = Gtk.Entry(); pw.set_visibility(False); pw.set_width_chars(15)
            pw.set_placeholder_text("password")
            btn = Gtk.Button(label="Save to vault")
            btn.connect("clicked", (lambda b, n=name, ue=u, pe=pw, ur=uri:
                                    self._save_cred(n, ue, pe, ur)))
            grid.attach(nm, 0, r, 1, 1)
            grid.attach(u, 1, r, 1, 1)
            grid.attach(pw, 2, r, 1, 1)
            grid.attach(btn, 3, r, 1, 1)
            self._cred_r += 1

        for p in self.panels:
            add_row(p.vault_item, p.effective_url)
        add_row((self._vpn or {}).get("vault_item", ""), "")   # VPN login -> vault
        add_row(self._proxy_vault_item, "")                    # proxy login -> vault
        if self._cred_r == 1:
            box.pack_start(Gtk.Label(label="No vault logins to set yet (give a "
                                           "panel/VPN/proxy a vault item first)."),
                           False, False, 0)
        else:
            box.pack_start(grid, False, False, 0)

        self._cred_master = None
        # Only ask for the master at the glass when it isn't sealed on this host;
        # a sealed wall unseals it itself (no plaintext SOC_VAULT_PASSWORD).
        from . import secretstore
        if not secretstore.is_sealed(os.environ.get("SOC_SECRET_DIR")):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            lbl = Gtk.Label(label="vault master password:")
            lbl.get_style_context().add_class("soc-config-sub")
            self._cred_master = Gtk.Entry()
            self._cred_master.set_visibility(False)
            self._cred_master.set_hexpand(True)
            row.pack_start(lbl, False, False, 0)
            row.pack_start(self._cred_master, True, True, 0)
            box.pack_start(row, False, False, 0)
        self._cred_msg = Gtk.Label(label="")
        self._cred_msg.get_style_context().add_class("soc-config-ok")
        self._cred_msg.set_xalign(0.0)
        box.pack_start(self._cred_msg, False, False, 0)
        # Wrap the whole tab in a ScrolledWindow so a long Save grid (one
        # row per panel + every VPN + proxy + tunnel) plus the inventory
        # plus the master-password field never push interactive widgets
        # off the bottom of the tab (user-reported: Refresh button was
        # unreachable). Vertical scroll only — horizontal stays clean.
        outer = Gtk.ScrolledWindow()
        outer.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        outer.add(box)
        return outer

    def _rbw_sync_now(self):
        """Force rbw to fetch the latest from Vaultwarden + refresh the
        inventory. Drops the in-process TTL cache. Threaded so the GUI
        stays responsive."""
        self._toast("syncing vault ...")

        def work():
            import subprocess
            try:
                r = subprocess.run(["rbw", "sync"], timeout=15,
                                    stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True)
                ok = (r.returncode == 0)
                err = (r.stderr or r.stdout or "").strip()
            except (OSError, subprocess.SubprocessError) as e:
                ok, err = False, str(e)
            v = getattr(self, "_vault", None)
            if v is not None and hasattr(v, "invalidate"):
                try:
                    v.invalidate()                     # drop the TTL cache
                except Exception:                      # noqa: BLE001
                    pass
            GLib.idle_add(self._rbw_sync_done, ok, err)
        import threading
        threading.Thread(target=work, daemon=True).start()

    def _rbw_sync_done(self, ok: bool, err: str):
        if ok:
            self._toast("vault synced ✓")
        else:
            self._alert(f"Vault sync failed:\n\n{err or 'unknown error'}\n\n"
                        "Common causes: Vaultwarden unreachable (check "
                        "`systemctl status vaultwarden`), the vault is "
                        "locked (check `rbw unlocked`), or rbw isn't "
                        "configured for this user (re-run "
                        "`sudo python3 setup.py first-run`).",
                        error=True, title="Vault sync failed")
        try:
            self._refresh_cred_inventory()
        except Exception:                              # noqa: BLE001
            pass
        return False

    def _collect_inventory(self) -> list:
        """Pure helper: every vault item name the wall touches, deduped,
        each as a dict {name, origin}. Unit-testable without GTK.

        Sources (in priority order; first wins for the 'origin' label):
          1. Panels: panel.vault_item.
          2. VPNs: vpns[i].vault_item.
          3. Proxy.vault_item.
          4. Tunnel.vault_item (if present).
          5. 'SOC Wall Auth' folder items (Phase 5 TOTP secure notes).

        Items found ONLY via #5 are tagged origin='SOC Wall Auth folder'
        — implicitly known to the wall, not pinned by a panels.yaml field.
        """
        seen = {}                                # name -> origin
        for p in (self.panels or []):
            n = (getattr(p, "vault_item", None) or "").strip()
            if n and n not in seen:
                seen[n] = f"panel:{p.id}"
        for v in (self._vpns or []):
            if not v:                            # nullified entry from remove
                continue
            n = (v.get("vault_item") or "").strip()
            if n and n not in seen:
                seen[n] = f"vpn:{v.get('name','?')}"
        prx = (self._proxy_vault_item or "").strip()
        if prx and prx not in seen:
            seen[prx] = "proxy"
        if self._tunnel and isinstance(self._tunnel, dict):
            tn = (self._tunnel.get("vault_item") or "").strip()
            if tn and tn not in seen:
                seen[tn] = "tunnel"
        # Pull folder items via the vault (only when one is attached to
        # this ConfigWindow). Skip silently if not present — the tab still
        # renders the panels/VPN-derived entries.
        v_handle = getattr(self, "_vault", None)
        if v_handle is not None and hasattr(v_handle, "list_by_folder"):
            try:
                folder_items = v_handle.list_by_folder("SOC Wall Auth")
            except Exception:                    # noqa: BLE001
                folder_items = []
            for n in folder_items:
                n = (n or "").strip()
                if n and n not in seen:
                    seen[n] = "SOC Wall Auth folder"
        return [{"name": n, "origin": o} for n, o in seen.items()]

    def _refresh_cred_inventory(self):
        """Rebuild the inventory rows. Idempotent: clears + re-adds."""
        if not hasattr(self, "_inv_list") or self._inv_list is None:
            return
        for child in list(self._inv_list.get_children()):
            self._inv_list.remove(child)
        items = self._collect_inventory()
        if not items:
            empty = Gtk.Label(label="(no vault items pinned yet — give a "
                                    "panel/VPN/proxy a vault item first)")
            empty.set_xalign(0.0)
            empty.get_style_context().add_class("soc-config-sub")
            self._inv_list.pack_start(empty, False, False, 0)
            self._inv_list.show_all()
            return
        for it in items:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            name = Gtk.Label(label=it["name"])
            name.set_xalign(0.0)
            name.get_style_context().add_class("soc-config-tag")
            origin = Gtk.Label(label=f"({it['origin']})")
            origin.set_xalign(0.0)
            origin.get_style_context().add_class("soc-config-sub")
            # Edit — fetches the current user/pass from the vault, gated
            # by the OPERATING SYSTEM password (not the wall PIN). Higher
            # bar than Delete because Edit reveals the stored secret.
            edit = Gtk.Button(label="Edit")
            edit.set_tooltip_text("Reveal + change the username/password for "
                                  "this vault item. Requires your OS login "
                                  "password (NOT the wall PIN).")
            edit.connect("clicked",
                         lambda _b, n=it["name"]: self._on_cred_edit(n))
            # Delete — re-auth via wall PIN/TOTP. Doesn't reveal anything.
            delete = Gtk.Button(label="Delete")
            delete.get_style_context().add_class("destructive-action")
            delete.set_tooltip_text("Permanent. PIN/TOTP required.")
            delete.connect("clicked",
                           lambda _b, n=it["name"]: self._on_cred_delete(n))
            row.pack_start(name, True, True, 0)
            row.pack_start(origin, False, False, 0)
            row.pack_start(edit, False, False, 0)
            row.pack_start(delete, False, False, 0)
            self._inv_list.pack_start(row, False, False, 0)
        self._inv_list.show_all()

    def _prompt_os_password(self, what: str) -> "tuple[bool, str]":
        """Modal that asks for the operator's OS login password and
        verifies via host.ospass.verify_os_password.

        Returns (ok, user). `ok` is True iff the operator provided a
        valid password; `user` is the user that was checked (useful
        for the next-step modal title).

        The username field is OPERATOR-EDITABLE — auto-detection guesses
        the most likely human user (uid >= 1000, real shell), but the
        operator can override (e.g. on a multi-user box, or when the
        wall was launched via a sudo chain that confused the
        auto-detect).

        The password string is held only inside this scope — never
        returned, logged, or stored. Rejection raises a loud error
        dialog so the operator can't miss it."""
        from . import ospass as _osp
        auto_user = _osp.operator_user()
        d = Gtk.Dialog(transient_for=self, modal=True,
                        title=f"OS password required — {what}")
        d.add_buttons("Cancel", Gtk.ResponseType.CANCEL,
                       "Verify", Gtk.ResponseType.OK)
        d.set_default_response(Gtk.ResponseType.OK)
        d.set_default_size(440, 0)
        box = d.get_content_area()
        box.set_spacing(8)
        box.set_margin_start(14); box.set_margin_end(14)
        box.set_margin_top(10);  box.set_margin_bottom(10)
        hint = Gtk.Label()
        hint.set_xalign(0.0); hint.set_line_wrap(True)
        hint.set_markup(
            "This action reveals + changes a stored credential. Enter "
            "your OS login username + password to continue.  "
            "Wall PIN/TOTP is <i>not</i> sufficient for reveal operations.")
        # Username (editable — pre-filled with the auto-detected operator).
        u_lbl = Gtk.Label(label="username")
        u_lbl.set_xalign(0.0)
        u_lbl.get_style_context().add_class("soc-config-sub")
        u_entry = Gtk.Entry()
        u_entry.set_text(auto_user)
        u_entry.set_tooltip_text("Default is the first uid≥1000 with a "
                                  "real shell. Override if the wall guessed "
                                  "wrong (or you set SOC_OPERATOR_USER).")
        # Password.
        p_lbl = Gtk.Label(label="password")
        p_lbl.set_xalign(0.0)
        p_lbl.get_style_context().add_class("soc-config-sub")
        p_entry = Gtk.Entry()
        p_entry.set_visibility(False)
        p_entry.set_activates_default(True)
        p_entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        box.pack_start(hint, False, False, 0)
        for w in (u_lbl, u_entry, p_lbl, p_entry):
            box.pack_start(w, False, False, 0)
        d.show_all()
        p_entry.grab_focus()
        rc = d.run()
        user = (u_entry.get_text() or "").strip() or auto_user
        pw = p_entry.get_text()
        d.destroy()
        if rc != Gtk.ResponseType.OK:
            return False, user
        try:
            ok = _osp.verify_os_password(user, pw)
        except Exception as e:                          # noqa: BLE001
            ok = False
            err_msg = f"OS password verification crashed: {e}"
        else:
            err_msg = None
        finally:
            pw = "x" * len(pw)                          # scrub
            del pw
        if not ok:
            # Loud error dialog (toast was missable). Surface the
            # username we tried so the operator can correct it.
            msg = err_msg or (
                f"OS password rejected for user '{user}'.\n\n"
                "Common causes:\n"
                "  • Wrong username — the wall auto-detected this one;\n"
                "    override it in the field if your desktop user is\n"
                "    different (e.g. 'kali', 'pi', or whatever you log\n"
                "    in as).\n"
                "  • Wrong password — the wall checks your LOCAL OS\n"
                "    login password, NOT the wall PIN, vault master,\n"
                "    or anything stored in Vaultwarden.\n"
                "  • Account has no password (e.g. Kali root by default).\n"
                "    Set one with: sudo passwd <user>, OR set\n"
                "    SOC_OPERATOR_USER=<real-user> in /etc/soc-display/\n"
                "    soc.env and restart the wall.")
            err = Gtk.MessageDialog(transient_for=self, modal=True,
                                     message_type=Gtk.MessageType.ERROR,
                                     buttons=Gtk.ButtonsType.OK,
                                     text="OS password rejected")
            err.format_secondary_text(msg)
            err.run(); err.destroy()
        return ok, user

    def _on_cred_edit(self, name: str):
        """Edit flow: OS password → fetch via vault → modal with user +
        pass entries → vaultseed.upsert_login. The current password is
        the only operator-side disclosure path for stored secrets, so
        it's gated by the same authentication root would need."""
        ok, _user = self._prompt_os_password(f"edit '{name}'")
        if not ok:
            return
        # Now read the current user+pass from vault.
        v_handle = getattr(self, "_vault", None)
        if v_handle is None or not hasattr(v_handle, "creds"):
            self._alert(f"Cannot edit '{name}': no vault handle attached to "
                        "this Settings window. The wall must be launched "
                        "with a vault for Edit to work; check the journal "
                        "for vault.open() errors.",
                        error=True, title="Vault unavailable")
            return
        # `creds()` raises VaultError on "no such item" AND on
        # transport errors. The user-facing difference is huge: a
        # missing item is the OPERATOR's normal first-time path (they
        # added a VPN, never saved its creds, now clicking Edit
        # to set them) — that's a CREATE flow, not an error.
        # A transport error is something to surface loudly + offers a
        # one-click "Sync + retry" inside the dialog (the operator was
        # blocked because the previous version told them to click the
        # Refresh button under the modal, which the modal itself was
        # covering).
        item_missing = False
        creds = self._fetch_creds_with_recovery(v_handle, name)
        if creds is _CANCELLED:
            return
        if creds is _NOT_FOUND:
            item_missing = True
            creds = {}
        current_user = creds.get("user", "") or ""
        current_pass = creds.get("pass", "") or ""
        if item_missing:
            # Promote the Edit modal into a Create modal — fields are
            # empty, title makes the intent explicit, Save upserts
            # (vaultseed.upsert_login creates on miss). One tap, no
            # extra prompt — the operator already authed with their OS
            # password, that's enough auth to create.
            self.log_msg = (f"Vault item '{name}' does not exist yet — "
                             "creating a new entry. Fill in the username "
                             "and password, then Save.")
            d_pre = Gtk.MessageDialog(transient_for=self, modal=True,
                                       message_type=Gtk.MessageType.INFO,
                                       buttons=Gtk.ButtonsType.OK,
                                       text=f"Create vault item '{name}'?")
            d_pre.format_secondary_text(
                "This vault item doesn't exist yet — that's normal for a "
                "first-time setup (a panel or VPN that hasn't had creds "
                "saved). The next dialog lets you fill in the username + "
                "password; Save will CREATE the item in Vaultwarden.")
            d_pre.run(); d_pre.destroy()

        # Edit modal with prefilled values.
        d = Gtk.Dialog(transient_for=self, modal=True,
                        title=f"Edit vault item — {name}")
        d.add_buttons("Cancel", Gtk.ResponseType.CANCEL,
                       "Save to vault", Gtk.ResponseType.OK)
        d.set_default_response(Gtk.ResponseType.OK)
        d.set_default_size(440, 0)
        body = d.get_content_area()
        body.set_spacing(6); body.set_margin_start(14); body.set_margin_end(14)
        body.set_margin_top(10); body.set_margin_bottom(10)
        u_e = Gtk.Entry()
        u_e.set_text(current_user)
        u_e.set_placeholder_text("username")
        u_e.set_activates_default(True)        # Enter → Save
        p_e = Gtk.Entry()
        p_e.set_text(current_pass)
        p_e.set_visibility(False)
        p_e.set_placeholder_text("password")
        p_e.set_activates_default(True)        # Enter → Save
        show_pass = Gtk.CheckButton(label="show password")
        show_pass.connect("toggled",
                           lambda b: p_e.set_visibility(b.get_active()))
        for label, w in (("username", u_e), ("password", p_e)):
            l = Gtk.Label(label=label)
            l.set_xalign(0.0)
            l.get_style_context().add_class("soc-config-sub")
            body.pack_start(l, False, False, 0)
            body.pack_start(w, False, False, 0)
        body.pack_start(show_pass, False, False, 0)
        d.show_all()
        # Focus the password (assume the username is correct from the
        # pre-fill — operator usually edits the password).
        p_e.grab_focus()
        rc = d.run()
        new_user = u_e.get_text().strip()
        new_pass = p_e.get_text()
        d.destroy()
        # Scrub the in-memory copies BEFORE doing anything else.
        current_pass = "x" * len(current_pass)
        del current_pass
        if rc != Gtk.ResponseType.OK:
            new_pass = "x" * len(new_pass); del new_pass
            return
        if not new_user and not new_pass:
            self._alert("Both username AND password are empty — nothing to "
                        "save. Cancel the Edit dialog if you didn't mean "
                        "to change anything, otherwise type the new values.",
                        title="Nothing to save")
            return
        # Hand off to vaultseed.upsert_login (threaded so the GUI stays
        # responsive). _do_vault_upsert raises a loud MessageDialog on
        # completion — success OR failure — so the operator sees feedback
        # even when the apply_msg label isn't on screen.
        self._do_vault_upsert(name, new_user, new_pass)
        new_pass = "x" * len(new_pass); del new_pass

    def _do_vault_upsert(self, name: str, user: str, password: str):
        """Inline upsert — used by the Edit modal. Threaded so the GUI
        doesn't freeze while vaultseed talks to Vaultwarden."""
        url = os.environ.get("SOC_VAULT_URL", "http://127.0.0.1:8222")
        email = os.environ.get("SOC_VAULT_EMAIL", "")
        from . import secretstore
        sd = os.environ.get("SOC_SECRET_DIR")
        try:
            master = secretstore.unseal(sd) if secretstore.is_sealed(sd) else ""
        except Exception:                                # noqa: BLE001
            master = ""
        if not master and getattr(self, "_cred_master", None):
            master = self._cred_master.get_text()
        if not email:
            self._alert("SOC_VAULT_EMAIL is empty in /etc/soc-display/soc.env "
                        "— cannot write to Vaultwarden. Set it via `sudo "
                        "python3 setup.py wizard` then restart the wall.",
                        error=True, title="Vault email missing")
            return
        if not master:
            self._alert("No vault master password available for the Edit.\n\n"
                        "Either the wall isn't sealed (run `sudo python3 "
                        "setup.py first-run` to seal the master host-bound), "
                        "or the Credentials tab's master-password field is "
                        "empty — type it there first, then retry Edit.",
                        error=True, title="Vault master missing")
            return
        import threading
        from . import vaultseed

        def work():
            try:
                rc = vaultseed.upsert_login(url, email, master, name, user,
                                              password)
                msg = f"edited '{name}' in Vaultwarden ✓ ({rc})"
                err = False
            except Exception as e:                       # noqa: BLE001
                msg = f"edit failed for '{name}': {e}"
                err = True
            GLib.idle_add(self._post_edit_done, msg, err)
        threading.Thread(target=work, daemon=True).start()

    def _post_edit_done(self, msg: str, err: bool = False):
        # Loud MessageDialog so the operator can't miss the result. The
        # old toast was only visible in the apply_msg label at the bottom
        # of the Panels tab — invisible from the Credentials tab where
        # Edit lives.
        self._toast(msg)                               # keep the toast too
        try:
            mt = (Gtk.MessageType.ERROR if err
                  else Gtk.MessageType.INFO)
            d = Gtk.MessageDialog(transient_for=self, modal=True,
                                   message_type=mt,
                                   buttons=Gtk.ButtonsType.OK,
                                   text=("Vault edit failed" if err
                                         else "Vault edit succeeded"))
            d.format_secondary_text(msg)
            d.run(); d.destroy()
        except Exception:                              # noqa: BLE001
            pass
        self._refresh_cred_inventory()
        return False

    def _on_cred_delete(self, name: str):
        """Delete a vault item from the inventory list.
        Two-step: re-auth, then confirm, then vault.delete + refresh."""
        if not self._require_reauth(f"delete of vault item '{name}'"):
            return
        d = Gtk.MessageDialog(transient_for=self, modal=True,
                              message_type=Gtk.MessageType.QUESTION,
                              buttons=Gtk.ButtonsType.OK_CANCEL,
                              text=f"Delete vault item '{name}'?")
        d.format_secondary_text(
            "This is permanent. Any panel / VPN / proxy referencing this "
            "item will fail to auto-login until the item is recreated or "
            "the field is re-pointed at a different vault item.")
        rc = d.run(); d.destroy()
        if rc != Gtk.ResponseType.OK:
            return
        v_handle = getattr(self, "_vault", None)
        if v_handle is None or not hasattr(v_handle, "delete"):
            self._alert(f"Cannot delete '{name}': no vault handle attached "
                        "to this Settings window. The wall must be launched "
                        "with a vault for Delete to work.",
                        error=True, title="Vault unavailable")
            return
        ok = v_handle.delete(name)
        if ok:
            self._alert(f"Vault item '{name}' deleted ✓\n\n"
                        "Any panel / VPN / proxy referencing this item will "
                        "fail to auto-login until the item is recreated or "
                        "the field is re-pointed at a different vault item.",
                        title="Deleted")
            self._refresh_cred_inventory()
        else:
            self._alert(f"Delete failed for '{name}'.\n\n"
                        "rbw returned non-zero. Check `journalctl -u "
                        "soc-wall -n 30` for details. The item may already "
                        "be gone (in which case clicking Refresh should "
                        "remove the row from the list).",
                        error=True, title="Delete failed")

    def _save_cred(self, name, user_e, pass_e, uri):
        user = user_e.get_text().strip()
        secret = pass_e.get_text()
        if not user:
            self._cred_msg.set_text(f"{name}: enter a username first")
            return
        url = os.environ.get("SOC_VAULT_URL", "http://127.0.0.1:8222")
        email = os.environ.get("SOC_VAULT_EMAIL", "")
        # Prefer the host-bound sealed master; fall back to the at-the-glass entry
        # only when the wall isn't sealed. Never read a plaintext SOC_VAULT_PASSWORD.
        from . import secretstore
        sd = os.environ.get("SOC_SECRET_DIR")
        try:
            master = secretstore.unseal(sd) if secretstore.is_sealed(sd) else ""
        except Exception:  # noqa: BLE001 — fall back to the manual entry below
            master = ""
        if not master and self._cred_master:
            master = self._cred_master.get_text()
        if not (email and master):
            self._cred_msg.set_text("need the vault email + master password to write")
            return
        self._cred_msg.set_text(f"writing '{name}' …")
        import threading

        def work():
            try:
                from . import vaultseed
                if not vaultseed.available():
                    msg = "'cryptography' not installed — add the login in the web vault"
                else:
                    action = vaultseed.upsert_login(url, email, master, name, user,
                                                    secret, uri=uri or None)
                    msg = f"{action} '{name}' in Vaultwarden ✓"
            except Exception as e:  # noqa: BLE001
                msg = f"{name}: {e}"
            GLib.idle_add(self._cred_done, msg, pass_e)
        threading.Thread(target=work, daemon=True).start()

    def _cred_done(self, msg, pass_e):
        self._cred_msg.set_text(msg)
        if "✓" in msg:
            pass_e.set_text("")
        else:
            # Failed write — surface a loud dialog instead of leaving
            # the operator squinting at the bottom-of-tab label.
            self._alert(msg, error=True, title="Vault save failed")
        return False

    def _tab_display(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(12)
        note = Gtk.Label(label="Layout, spacing, grid size, and resolution. Gap "
                               "applies live; layout, grid size, and resolution "
                               "take effect on the next restart. Growing the grid "
                               "adds blank click-to-configure tiles for the new "
                               "cells.")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)
        g = Gtk.Grid()
        g.set_column_spacing(10)
        g.set_row_spacing(10)
        self._layout_c = Gtk.ComboBoxText()
        opts = ["auto", "windows", "single"]
        for o in opts:
            self._layout_c.append_text(o)
        cur = getattr(self.display, "layout", "auto")
        self._layout_c.set_active(opts.index(cur) if cur in opts else 0)
        self._gap_s = Gtk.SpinButton.new_with_range(0, 64, 1)
        self._gap_s.set_value(getattr(self.display, "gap", 0))
        self._cols_s = Gtk.SpinButton.new_with_range(1, 8, 1)
        self._cols_s.set_value(int(getattr(self.display, "cols", 2)))
        self._rows_s = Gtk.SpinButton.new_with_range(1, 8, 1)
        self._rows_s.set_value(int(getattr(self.display, "rows", 2)))
        self._disp_auto = Gtk.CheckButton(label="auto-detect from the screen")
        self._disp_auto.set_active(bool(getattr(self.display, "auto", True)))
        self._w_s = Gtk.SpinButton.new_with_range(320, 16384, 16)
        self._w_s.set_value(int(getattr(self.display, "width", 1920)))
        self._h_s = Gtk.SpinButton.new_with_range(320, 16384, 16)
        self._h_s.set_value(int(getattr(self.display, "height", 1080)))
        # disable explicit width/height while auto-detect is on, so the UI matches
        # the actual behaviour (width/height are only read when auto is False)
        self._w_s.set_sensitive(not self._disp_auto.get_active())
        self._h_s.set_sensitive(not self._disp_auto.get_active())
        self._disp_auto.connect("toggled", lambda b: (
            self._w_s.set_sensitive(not b.get_active()),
            self._h_s.set_sensitive(not b.get_active())))
        # Windowed-vs-fullscreen toggle (defaults fullscreen for kiosk; flip
        # off to run as a normal desktop window — useful on a dev box or when
        # the wall coexists with other apps on the operator's display).
        self._fullscreen_c = Gtk.CheckButton(
            label="fullscreen on start  (off = open as a windowed desktop app, "
                  "F11 toggles)")
        self._fullscreen_c.set_active(bool(getattr(self.display, "fullscreen",
                                                    True)))
        rows = [("layout", self._layout_c), ("gap (px)", self._gap_s),
                ("cols", self._cols_s), ("rows", self._rows_s),
                ("resolution", self._disp_auto),
                ("width", self._w_s), ("height", self._h_s),
                ("window", self._fullscreen_c)]
        for r, (lbl, w) in enumerate(rows):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            g.attach(h, 0, r, 1, 1)
            g.attach(w, 1, r, 1, 1)
        box.pack_start(g, False, False, 0)
        return box

    def _tab_proxy(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(12)
        note = Gtk.Label(label="Outbound HTTP(S)/SOCKS proxy for the panel browsers. "
                               "Credentials live in the vault (set username + "
                               "password on the Credentials tab for this proxy's "
                               "vault item). Changes apply on the next restart.")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)

        p = self._proxy
        w = {}
        w["enabled"] = Gtk.CheckButton(label="Proxy enabled")
        w["enabled"].set_active(bool(getattr(p, "enabled", False)))
        box.pack_start(w["enabled"], False, False, 0)

        g = Gtk.Grid()
        g.set_column_spacing(8)
        g.set_row_spacing(6)

        def entry(val, hint, purpose=None):
            e = Gtk.Entry()
            e.set_text(str(val or ""))
            e.set_hexpand(True)
            e.set_placeholder_text(hint)
            if purpose is not None:
                e.set_input_purpose(purpose)
            return e

        w["url"] = entry(getattr(p, "url", ""),
                         "http://host:port  (no embedded user:pass)",
                         Gtk.InputPurpose.URL)
        w["vault_item"] = entry(getattr(p, "vault_item", ""),
                                "vault login holding the proxy creds (optional)")
        ignore = ", ".join(getattr(p, "ignore_hosts", ()) or ())
        w["ignore_hosts"] = entry(ignore,
                                  "host1, host2  (loopback is always bypassed)")
        rows = [("url", w["url"]), ("vault login", w["vault_item"]),
                ("ignore hosts", w["ignore_hosts"])]
        for r, (lbl, widget) in enumerate(rows, start=1):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            g.attach(h, 0, r, 1, 1)
            g.attach(widget, 1, r, 1, 1)
        box.pack_start(g, False, False, 0)
        self._proxy_w = w
        return box

    def _tab_tunnel(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(12)
        note = Gtk.Label(label="SSH jump host used by panels in 'tunnel' mode. The "
                               "SSH key sits in the host's filesystem (the jump "
                               "host trusts its public half). Apply pushes the "
                               "change and restarts autossh-tunnel.")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)

        t = self._tunnel or {}
        w = {}
        w["enabled"] = Gtk.CheckButton(label="Tunnel enabled")
        w["enabled"].set_active(bool(t.get("enabled", True)))
        box.pack_start(w["enabled"], False, False, 0)

        g = Gtk.Grid()
        g.set_column_spacing(8)
        g.set_row_spacing(6)

        def entry(val, hint):
            e = Gtk.Entry()
            e.set_text(str(val or ""))
            e.set_hexpand(True)
            e.set_placeholder_text(hint)
            return e

        w["jump_host"] = entry(t.get("jump_host"), "user@host  (the SSH jump box)")
        w["identity"] = entry(t.get("identity"), "private key path on the wall")
        w["known_hosts"] = entry(t.get("known_hosts"),
                                 "known_hosts file pinning the jump box's key")
        w["host_key_checking"] = Gtk.ComboBoxText()
        hkc_opts = ["yes", "accept-new", "no"]
        for o in hkc_opts:
            w["host_key_checking"].append_text(o)
        cur = str(t.get("host_key_checking", "yes"))
        w["host_key_checking"].set_active(hkc_opts.index(cur) if cur in hkc_opts else 0)
        rows = [("jump host", w["jump_host"]),
                ("identity (key)", w["identity"]),
                ("known_hosts", w["known_hosts"]),
                ("host key check", w["host_key_checking"])]
        for r, (lbl, widget) in enumerate(rows, start=1):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            g.attach(h, 0, r, 1, 1)
            g.attach(widget, 1, r, 1, 1)
        box.pack_start(g, False, False, 0)

        ef_lbl = Gtk.Label(label="extra forwards  (one per line, "
                                 "bindaddr:port:host:port)")
        ef_lbl.get_style_context().add_class("soc-config-sub")
        ef_lbl.set_xalign(0.0)
        box.pack_start(ef_lbl, False, False, 0)
        self._tunnel_ef = Gtk.TextView()
        self._tunnel_ef.set_monospace(True)
        self._tunnel_ef.set_wrap_mode(Gtk.WrapMode.NONE)
        buf = self._tunnel_ef.get_buffer()
        buf.set_text("\n".join(t.get("extra_forwards") or []))
        sw = Gtk.ScrolledWindow()
        sw.set_min_content_height(70)
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.add(self._tunnel_ef)
        box.pack_start(sw, False, False, 0)

        self._tunnel_w = w
        return box

    def _tab_vpn(self):
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        outer.set_border_width(12)
        note = Gtk.Label(label="Supervised VPNs. Each gets its own systemd "
                               "service (forti-vpn@<name>) and its own top-bar "
                               "pill (green=online · amber=connecting · "
                               "red=offline). Inline username/password saves "
                               "straight to the vault item; cert / config "
                               "fields stay in the panels config. Apply pushes "
                               "the config back to the vault note and restarts "
                               "the VPN service(s).")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        outer.pack_start(note, False, False, 0)

        # Header row: "+ Add VPN" button. Operator can add as many VPN sections
        # as they want; the layout no longer hardcodes 2.
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        header.get_style_context().add_class("soc-config-sub")
        add_btn = Gtk.Button(label="+ Add VPN")
        add_btn.set_tooltip_text("Add a new collapsible VPN section. The new "
                                 "entry starts disabled — fill in name + "
                                 "gateway + vault item, then enable it.")
        add_btn.connect("clicked", self._on_add_vpn)
        header.pack_end(add_btn, False, False, 0)
        outer.pack_start(header, False, False, 0)

        # Re-buildable expander list. Cache the (outer container, header) so
        # _on_add_vpn can append + show without rebuilding the whole tab.
        self._vpn_ws = []
        self._vpn_expanders_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                          spacing=8)
        outer.pack_start(self._vpn_expanders_box, False, False, 0)

        for idx, v in enumerate(self._vpns):
            exp = self._vpn_section(v, idx)
            self._vpn_expanders_box.pack_start(exp, False, False, 0)
            # Only the first section is expanded by default — operators usually
            # only edit one VPN at a time and the open-by-default sprawl was
            # too tall on small displays.
            exp.set_expanded(idx == 0)

        scroll.add(outer)
        return scroll

    def _on_add_vpn(self, _btn):
        """+ Add VPN — append a blank entry, build its expander, show it."""
        idx = len(self._vpns)
        v = {"name": f"vpn-{idx+1}", "enabled": False, "type": "fortinet"}
        self._vpns.append(v)
        exp = self._vpn_section(v, idx)
        self._vpn_expanders_box.pack_start(exp, False, False, 0)
        exp.set_expanded(True)
        exp.show_all()

    def _on_remove_vpn(self, idx: int, expander):
        """Remove this VPN — re-auth, then dialog confirm, then drop from
        _vpns + UI. The vault credential item is intentionally NOT
        auto-deleted (Credentials tab handles that with its own re-auth)."""
        name = (self._vpns[idx].get("name") if idx < len(self._vpns)
                and self._vpns[idx] else "") or f"vpn-{idx+1}"
        if not self._require_reauth(f"removal of VPN '{name}'"):
            return
        d = Gtk.MessageDialog(transient_for=self,
                              modal=True,
                              message_type=Gtk.MessageType.QUESTION,
                              buttons=Gtk.ButtonsType.OK_CANCEL,
                              text=f"Remove VPN '{name}'?")
        d.format_secondary_text(
            f"VPN '{name}' will be removed from the config on next Apply. "
            "The vault credential item is NOT deleted by this action — "
            "use the Credentials tab to delete it explicitly.")
        rc = d.run()
        d.destroy()
        if rc != Gtk.ResponseType.OK:
            return
        # Stop + disable the templated supervisor for THIS VPN before we
        # drop the entry from the config. Without this, the VPN's
        # forti-vpn@<name>.service would keep running on the box —
        # silently auto-reconnecting against a deleted config until
        # something else stops it. Uses the sudoers-allowed `sudo -n`
        # path (the privilege we already arranged for "Save VPN edits
        # live"); falls back to a clear log line if not allowed.
        stop_action = self._actions.get("stop_vpn_unit")
        if stop_action is not None and name:
            try:
                stop_action(name)
            except Exception as e:                      # noqa: BLE001
                self._alert(f"Could not stop forti-vpn@{name}.service:"
                            f"\n\n{e}\n\nThe config is being removed, but "
                            f"the supervisor is still running. Stop it "
                            f"manually with:\n"
                            f"    sudo systemctl disable --now "
                            f"soc-vpn@{name}.service",
                            error=True, title="VPN supervisor still running")
        # Remove the dict entry; we leave self._vpn_ws[idx] in place but
        # marked dead so apply_overrides skips it (lighter than re-indexing
        # every expander's name-rename closure).
        if 0 <= idx < len(self._vpns):
            self._vpns[idx] = None
        if 0 <= idx < len(self._vpn_ws):
            self._vpn_ws[idx] = None
        if expander is not None:
            expander.destroy()

    def _save_vpn_creds(self, idx: int, user: str, password: str,
                         vault_item_entry):
        """Save inline VPN user/password to the vault item named by the
        section's `vault_item` entry. If the operator has not chosen a
        vault item name, default to 'SOC VPN <name>' so saving Just Works
        for first-time setup. Reuses the same secretstore-unseal + manual-
        master fallback as the Credentials tab Save grid so a sealed
        prod install needs no extra inputs and a dev install can paste
        the master into the Credentials tab once."""
        from . import vaultseed
        from . import secretstore
        import os as _os
        if not vault_item_entry.get_text().strip():
            vname = (self._vpns[idx].get("name")
                     if 0 <= idx < len(self._vpns) and self._vpns[idx]
                     else "") or f"vpn-{idx+1}"
            vault_item_entry.set_text(f"SOC VPN {vname}")
        item = vault_item_entry.get_text().strip()
        if not user and not password:
            self._alert("Set a username AND a password before saving inline "
                        "VPN credentials.", error=True,
                        title="Nothing to save")
            return
        url = _os.environ.get("SOC_VAULT_URL", "http://127.0.0.1:8222")
        email = _os.environ.get("SOC_VAULT_EMAIL", "")
        # FIX: the old code read `self._master_pw` which is never set,
        # so VPN inline Save ALWAYS hit the "vault credentials needed"
        # toast. Match the working pattern from _save_cred: prefer the
        # sealed master, fall back to the master-password entry the
        # Credentials tab shows when the wall isn't sealed.
        sd = _os.environ.get("SOC_SECRET_DIR")
        try:
            master = secretstore.unseal(sd) if secretstore.is_sealed(sd) else ""
        except Exception:                              # noqa: BLE001
            master = ""
        if not master and getattr(self, "_cred_master", None):
            master = self._cred_master.get_text()
        if not email:
            self._alert("SOC_VAULT_EMAIL is empty in /etc/soc-display/soc.env "
                        "— the wall doesn't know which Vaultwarden account "
                        "to write to. Set it via `sudo python3 setup.py "
                        "wizard` then restart the wall.",
                        error=True, title="Vault email missing")
            return
        if not master:
            self._alert("No vault master password available.\n\n"
                        "Either the wall isn't sealed (run `sudo python3 "
                        "setup.py first-run` to seal the master host-bound), "
                        "or the Credentials tab's master-password field is "
                        "empty — type the master password there first.",
                        error=True, title="Vault master missing")
            return
        try:
            rc = vaultseed.upsert_login(url, email, master,
                                        name=item, username=user,
                                        password=password)
            self._alert(f"VPN credential '{item}' {rc} in Vaultwarden ✓\n\n"
                        "The wall will pick up the new credential on the "
                        "next auto-login attempt.",
                        error=False, title="Vault save succeeded")
        except Exception as e:  # noqa: BLE001
            self._alert(f"Failed to write '{item}' to Vaultwarden:\n\n{e}\n\n"
                        "Common causes: vault unreachable (check `systemctl "
                        "status vaultwarden`), wrong master password, the "
                        "'cryptography' package not installed.",
                        error=True, title="Vault save failed")

    def _toast(self, msg: str):
        """Lightweight non-modal message — uses the existing status label
        slot if present, falls back to a transient label at the bottom of
        the active page. Idempotent: no-op if neither surface is built yet.

        NOT for error reporting — use `_alert(msg, error=True)` for
        anything an operator MUST see (auth failure, vault write failure,
        ...). The Settings tab label this writes to is invisible from
        every other tab, so quiet failures got missed all session."""
        lbl = getattr(self, "_apply_msg", None)
        if lbl is not None:
            try:
                lbl.set_text(msg)
            except Exception:  # noqa: BLE001
                pass
        # Also write to the Credentials tab message slot if present, so
        # toast(...) from the Edit / Save / Delete flow lands somewhere
        # the operator is actually looking.
        cm = getattr(self, "_cred_msg", None)
        if cm is not None and cm is not lbl:
            try:
                cm.set_text(msg)
            except Exception:  # noqa: BLE001
                pass

    def _fetch_creds_with_recovery(self, v_handle, name):  # noqa: D401
        # Sentinels are defined at module bottom; they're singletons so
        # `is` works for the dispatcher. See _NOT_FOUND / _CANCELLED.
        """Read vault.creds(name); on a transport error, surface a
        dialog with a 'Sync + retry' button so the operator can recover
        without dismissing the modal (the previous version told them
        to click 'Refresh from vault' which was COVERED by the modal —
        unreachable). Returns either:
          dict   — success (may be empty if item missing)
          _NOT_FOUND — vault definitively says no such item (caller
                       promotes to a Create flow)
          _CANCELLED — operator cancelled the error dialog."""
        from . import vault as _vault
        attempts = 0
        while True:
            attempts += 1
            try:
                return v_handle.creds(name) or {}
            except Exception as e:                       # noqa: BLE001
                err_text = str(e).lower()
                # rbw says "Error: no entry found" — match that, plus the
                # variants other backends may use.
                if ("no entry found" in err_text
                        or "not found" in err_text
                        or "no vault item" in err_text
                        or "no password" in err_text):
                    return _NOT_FOUND
                # Transport / lock error — offer Sync + Retry inside
                # the dialog. Avoid infinite-retry: after 2 attempts,
                # fall through to a Cancel-only dialog so a perma-down
                # vault can't loop here forever.
                if attempts >= 3:
                    self._alert(
                        f"Vault read still failing for '{name}' after "
                        f"sync retry:\n\n{e}\n\n"
                        "Check `systemctl status vaultwarden` + "
                        "`rbw unlocked` from a terminal, then retry "
                        "Edit. The wall's vault cache may need a full "
                        "restart (⚙ Settings → Actions → Restart wall).",
                        error=True, title="Vault read keeps failing")
                    return _CANCELLED
                # First / second failure — offer Sync + Retry.
                d = Gtk.MessageDialog(
                    transient_for=self, modal=True,
                    message_type=Gtk.MessageType.WARNING,
                    text=f"Vault read failed for '{name}'")
                d.format_secondary_text(
                    f"{e}\n\n"
                    "This usually means rbw's cache is stale (the item "
                    "was added / renamed / deleted directly in the web "
                    "vault). Click 'Sync + retry' to refresh the cache "
                    "and try again. If the vault is unreachable, Sync "
                    "will also fail loudly.")
                d.add_buttons("Cancel", Gtk.ResponseType.CANCEL,
                               "Sync + retry", Gtk.ResponseType.OK)
                d.set_default_response(Gtk.ResponseType.OK)
                rc = d.run(); d.destroy()
                if rc != Gtk.ResponseType.OK:
                    return _CANCELLED
                # Run rbw sync in a small subprocess (the vault.facade
                # has no public sync; we use the rbw CLI directly).
                try:
                    import subprocess
                    subprocess.run(["rbw", "sync"], timeout=15,
                                    stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
                except Exception:                        # noqa: BLE001
                    pass
                # Also drop the in-process TTL cache for this item so
                # the next creds() call REALLY hits rbw.
                try:
                    v_handle.invalidate(name)
                except Exception:                        # noqa: BLE001
                    pass
                # Refresh the inventory list in the background so the
                # operator sees the row updated even if the retry fails.
                try:
                    self._refresh_cred_inventory()
                except Exception:                        # noqa: BLE001
                    pass
                # Loop — one more attempt against rbw.

    def _alert(self, msg: str, *, error: bool = False,
                title: "str | None" = None):
        """Modal MessageDialog — for things the operator MUST see. Use
        this instead of `_toast()` for auth failures, vault errors,
        post-action confirmations, anything the operator can't recover
        from without knowing what happened.

        `error=True` paints the red-cross icon + ERROR class; otherwise
        an INFO icon. Always blocks until the operator acknowledges, so
        the next destructive step can never race ahead of an error the
        user hasn't seen."""
        try:
            mt = (Gtk.MessageType.ERROR if error else Gtk.MessageType.INFO)
            d = Gtk.MessageDialog(transient_for=self, modal=True,
                                   message_type=mt,
                                   buttons=Gtk.ButtonsType.OK,
                                   text=title or ("Error" if error
                                                  else "Notice"))
            d.format_secondary_text(msg)
            d.run(); d.destroy()
        except Exception:                              # noqa: BLE001
            # GUI tear-down race or no transient_for — at least record
            # to the toast surface so the message isn't lost entirely.
            self._toast(msg)

    def _require_reauth(self, what: str = "this action") -> bool:
        """Modal PIN/TOTP prompt before a destructive action. Returns True
        only after the operator types a code that matches the Settings PIN
        OR the Settings TOTP. Fail-closed when no auth is enrolled — the
        Settings tab needs a credential before anything destructive can
        happen at the glass.

        Used to gate Clear PIN / Clear TOTP / Remove VPN / Delete
        credential. Re-auth failure is NOT counted toward the existing
        locker.py back-off — that one is for the wall-lock surface; this
        one has its own counter `_reauth_fails`."""
        if not _reauth_required():
            d = Gtk.MessageDialog(transient_for=self, modal=True,
                                   message_type=Gtk.MessageType.WARNING,
                                   buttons=Gtk.ButtonsType.OK,
                                   text="No PIN or TOTP enrolled")
            d.format_secondary_text(
                "Destructive actions need a credential. Enrol a PIN or "
                "TOTP under the Security tab first, then retry "
                f"{what}.")
            d.run(); d.destroy()
            return False
        # Back-off after repeated wrong codes: 3+ fails → 5 s, capped at 60 s.
        # Mirrors the locker.py back-off so behaviour is consistent.
        import time as _time
        fails = getattr(self, "_reauth_fails", 0)
        wait_until = getattr(self, "_reauth_blocked_until", 0)
        if _time.monotonic() < wait_until:
            remaining = int(wait_until - _time.monotonic()) + 1
            d = Gtk.MessageDialog(transient_for=self, modal=True,
                                   message_type=Gtk.MessageType.INFO,
                                   buttons=Gtk.ButtonsType.OK,
                                   text="Too many wrong attempts")
            d.format_secondary_text(
                f"Wait {remaining} s before trying again.")
            d.run(); d.destroy()
            return False

        d = Gtk.Dialog(transient_for=self, modal=True,
                        title=f"Confirm {what} — enter PIN or TOTP")
        d.add_buttons("Cancel", Gtk.ResponseType.CANCEL,
                       "Confirm", Gtk.ResponseType.OK)
        d.set_default_response(Gtk.ResponseType.OK)
        box = d.get_content_area()
        lbl = Gtk.Label(label=f"Enter PIN or TOTP code to confirm {what}.")
        lbl.set_xalign(0.0); lbl.set_margin_top(6); lbl.set_margin_start(12)
        lbl.set_margin_end(12)
        entry = Gtk.Entry()
        entry.set_visibility(False)
        entry.set_activates_default(True)
        entry.set_margin_top(6); entry.set_margin_start(12)
        entry.set_margin_end(12); entry.set_margin_bottom(6)
        box.pack_start(lbl, False, False, 0)
        box.pack_start(entry, False, False, 0)
        d.show_all()
        rc = d.run()
        code = entry.get_text()
        d.destroy()
        if rc != Gtk.ResponseType.OK:
            return False
        ok = _reauth_verify(code)
        if not ok:
            fails += 1
            self._reauth_fails = fails
            if fails >= 3:
                cooldown = min(60, 5 * (2 ** (fails - 3)))
                self._reauth_blocked_until = _time.monotonic() + cooldown
                self._toast(f"wrong code ({fails} consecutive) — "
                            f"cooling down for {cooldown}s")
            else:
                self._toast("wrong code")
        else:
            self._reauth_fails = 0
            self._reauth_blocked_until = 0
        return ok

    def _vpn_section(self, v: dict, idx: int):
        """Build the collapsible per-VPN section. Returns a `Gtk.Expander`
        (not the old `Gtk.Frame`) so multiple VPNs don't sprawl the tab,
        and only the first one is open by default."""
        default_name = v.get("name") or f"vpn-{idx+1}"
        # Custom label widget so we can set_markup live as the operator
        # types in the name entry — keeps the header in sync.
        header_lbl = Gtk.Label()
        header_lbl.set_markup(self._vpn_header_markup(default_name, idx,
                                                       v.get("type")))
        header_lbl.set_xalign(0.0)

        exp = Gtk.Expander()
        exp.set_label_widget(header_lbl)
        exp.set_resize_toplevel(True)

        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        inner.set_border_width(8)
        w = {}
        w["enabled"] = Gtk.CheckButton(label=f"enabled  (systemd unit: soc-vpn@{default_name})")
        w["enabled"].set_active(bool(v.get("enabled")))
        inner.pack_start(w["enabled"], False, False, 0)

        g = Gtk.Grid()
        g.set_column_spacing(8)
        g.set_row_spacing(6)
        w["type"] = Gtk.ComboBoxText()
        types = ["fortinet", "openvpn", "wireguard", "inode"]
        for t in types:
            w["type"].append_text(t)
        cur = str(v.get("type", "fortinet"))
        w["type"].set_active(types.index(cur) if cur in types else 0)

        def entry(val, hint):
            e = Gtk.Entry()
            e.set_text(str(val or ""))
            e.set_hexpand(True)
            e.set_placeholder_text(hint)
            return e

        w["name"] = entry(default_name, "name (top-bar pill label, systemd instance)")
        # Live rename — the expander header updates as the operator types so
        # the section reflects the chosen VPN identity (not stuck on
        # "VPN 1" / "VPN 2"). Pass idx + the combo box for live type info too.
        def _on_name_change(e, i=idx, hdr=header_lbl, type_combo=w["type"]):
            hdr.set_markup(self._vpn_header_markup(
                e.get_text().strip() or f"vpn-{i+1}", i,
                type_combo.get_active_text()))
        w["name"].connect("changed", _on_name_change)
        w["type"].connect("changed", lambda _c: _on_name_change(w["name"]))

        w["gateway"] = entry(v.get("gateway"), "gateway host (fortinet / inode)")
        w["port"] = Gtk.SpinButton.new_with_range(0, 65535, 1)
        w["port"].set_value(int(v.get("port", 443) or 0))
        w["vault_item"] = entry(v.get("vault_item"),
                                 "vault login item (auto-named 'SOC VPN <name>' if blank)")
        w["config"] = entry(v.get("config"), ".ovpn/.conf path, or the iNode client dir")
        w["domain"] = entry(v.get("domain"), "auth domain (inode)")
        w["realm"] = entry(v.get("realm"), "realm (fortinet)")
        w["trusted_cert"] = entry(v.get("trusted_cert"), "gateway cert sha256 pin")
        w["ready_probe"] = entry(v.get("ready_probe"),
                                 "host:port reachable only over the VPN (drives the pill)")
        rows = [("name", w["name"]), ("type", w["type"]),
                ("gateway", w["gateway"]), ("port", w["port"]),
                ("vault login", w["vault_item"]), ("config", w["config"]),
                ("domain", w["domain"]), ("realm", w["realm"]),
                ("trusted_cert", w["trusted_cert"]), ("ready_probe", w["ready_probe"])]
        for r, (lbl, widget) in enumerate(rows, start=1):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            g.attach(h, 0, r, 1, 1)
            g.attach(widget, 1, r, 1, 1)
        inner.pack_start(g, False, False, 0)

        w["insecure"] = Gtk.CheckButton(label="skip TLS verify (inode — trusted LAN only)")
        w["insecure"].set_active(bool(v.get("insecure")))
        w["config_from_vault"] = Gtk.CheckButton(
            label="config from the vault item's Notes (openvpn / wireguard)")
        w["config_from_vault"].set_active(bool(v.get("config_from_vault")))
        inner.pack_start(w["insecure"], False, False, 0)
        inner.pack_start(w["config_from_vault"], False, False, 0)

        # --- inline credentials (Phase 4 — write straight to the vault item).
        # Read is intentionally NOT shown (no re-display of stored secrets).
        cred_frame = Gtk.Frame(label="  inline credentials → vault  ")
        cred_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        cred_box.set_border_width(6)
        w["user"] = entry("", "VPN username (saved to the vault item; never read back)")
        w["pass"] = Gtk.Entry()
        w["pass"].set_visibility(False)
        w["pass"].set_placeholder_text("VPN password (write-only)")
        w["pass"].set_hexpand(True)
        cred_box.pack_start(w["user"], False, False, 0)
        cred_box.pack_start(w["pass"], False, False, 0)
        save_btn = Gtk.Button(label="Save inline creds to vault")
        save_btn.set_tooltip_text("Writes to the vault item named in 'vault "
                                  "login'; auto-names it 'SOC VPN <name>' if "
                                  "blank. Inputs are scrubbed after a "
                                  "successful save.")
        save_btn.connect(
            "clicked",
            lambda _b, i=idx, u=w["user"], p=w["pass"], vi=w["vault_item"]:
                self._save_and_clear_vpn_creds(i, u, p, vi))
        cred_box.pack_start(save_btn, False, False, 0)
        cred_frame.add(cred_box)
        inner.pack_start(cred_frame, False, False, 0)

        # --- destructive: Remove this VPN.
        rm = Gtk.Button(label="Remove this VPN")
        rm.get_style_context().add_class("destructive-action")
        rm.set_tooltip_text("Removes the section from the config (next Apply "
                            "drops it). The vault credential item is left "
                            "alone — delete it explicitly in Credentials.")
        rm.connect("clicked", lambda _b, i=idx, e=exp: self._on_remove_vpn(i, e))
        inner.pack_start(rm, False, False, 0)

        exp.add(inner)
        # Pad self._vpn_ws so indexing matches self._vpns.
        while len(self._vpn_ws) <= idx:
            self._vpn_ws.append(None)
        self._vpn_ws[idx] = w
        return exp

    def _vpn_header_markup(self, name: str, idx: int, typ):
        """Header label shown next to the expander arrow. Bold name, then
        a small grey "(type)" suffix so the operator sees the choice
        without expanding the section."""
        name = name or f"vpn-{idx+1}"
        t = (typ or "").strip() or "?"
        return f"<b>VPN {idx+1}: {GLib.markup_escape_text(name)}</b>  " \
               f"<span color='#888'>({GLib.markup_escape_text(t)})</span>"

    def _save_and_clear_vpn_creds(self, idx, user_entry, pass_entry,
                                   vault_item_entry):
        """Wrapper: call _save_vpn_creds, then scrub the entries on success
        so the password doesn't sit in a GTK Entry forever."""
        self._save_vpn_creds(idx, user_entry.get_text(),
                             pass_entry.get_text(), vault_item_entry)
        # Scrub regardless — even on failure we don't want the password
        # lingering; the operator can retype.
        pass_entry.set_text("")

    def _tab_security(self):
        """PIN + TOTP enrollment for the Settings gate AND the panel lock.
        Real-time complexity check on PIN entry."""
        from . import totp as _totp
        from . import complexity as _cx
        from . import locker as _lk
        sd = state_dir()

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(12)
        note = Gtk.Label(label="PIN + TOTP gates: 'Settings' protects this "
                               "configuration window; 'Panel lock' freezes "
                               "the wall's input so a passer-by can't click "
                               "around (display stays visible). Either or both "
                               "may be enrolled; either unlocks.")
        note.set_xalign(0.0); note.set_line_wrap(True)
        note.get_style_context().add_class("soc-config-sub")
        box.pack_start(note, False, False, 0)

        def _section(title, on_set_pin, on_clr_pin, on_enroll_totp,
                      on_clr_totp, has_pin, has_totp):
            frame = Gtk.Frame(label=f"  {title}  ")
            inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            inner.set_border_width(8)
            status = Gtk.Label(label="")
            status.set_xalign(0.0); status.set_line_wrap(True)
            status.get_style_context().add_class("soc-config-sub")
            inner.pack_start(status, False, False, 0)

            def _refresh():
                bits = []
                bits.append("PIN: SET ✓" if has_pin() else "PIN: (none)")
                bits.append("TOTP: SET ✓" if has_totp() else "TOTP: (none)")
                status.set_text("  ·  ".join(bits))
            _refresh()

            # PIN row + live complexity hint
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            pin_e = Gtk.Entry()
            pin_e.set_visibility(False)
            pin_e.set_input_purpose(Gtk.InputPurpose.PIN)
            pin_e.set_placeholder_text("new PIN")
            pin_e.set_hexpand(True)
            cx_lbl = Gtk.Label(label="")
            cx_lbl.set_xalign(0.0); cx_lbl.set_line_wrap(True)

            def _on_change(_e):
                v = pin_e.get_text()
                if not v:
                    cx_lbl.set_text("")
                    return
                r = _cx.check(v, kind="pin")
                ctx = cx_lbl.get_style_context()
                ctx.remove_class("soc-config-ok"); ctx.remove_class("soc-config-error")
                ctx.add_class("soc-config-ok" if r.ok else "soc-config-error")
                cx_lbl.set_text("✓ meets PIN policy" if r.ok
                                else "✗ " + "; ".join(r.issues))
            pin_e.connect("changed", _on_change)
            set_b = Gtk.Button(label="Set PIN")
            clr_b = Gtk.Button(label="Remove PIN")

            def _set(_w):
                v = pin_e.get_text()
                r = _cx.check(v, kind="pin")
                if not r.ok:
                    status.set_text("PIN rejected — " + "; ".join(r.issues))
                    return
                try:
                    on_set_pin(v)
                    pin_e.set_text("")
                    _refresh()
                except Exception as e:                # noqa: BLE001
                    status.set_text(f"could not set PIN: {e}")

            def _clr(_w):
                if has_pin() and not self._require_reauth(
                        f"removal of the {title} PIN"):
                    return
                try:
                    on_clr_pin()
                    _refresh()
                except Exception as e:                # noqa: BLE001
                    status.set_text(f"could not remove PIN: {e}")
            set_b.connect("clicked", _set)
            clr_b.connect("clicked", _clr)
            row.pack_start(pin_e, True, True, 0)
            row.pack_start(set_b, False, False, 0)
            row.pack_start(clr_b, False, False, 0)
            inner.pack_start(row, False, False, 0)
            inner.pack_start(cx_lbl, False, False, 0)

            # TOTP row — Enroll generates a fresh secret, shows the otpauth://
            # URI (which the operator pastes into their authenticator OR scans
            # via a separate qr-render tool; we don't pull qrencode in to keep
            # this stdlib).
            trow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            enroll_b = Gtk.Button(label="Enroll TOTP")
            unenroll_b = Gtk.Button(label="Remove TOTP")
            uri_e = Gtk.Entry()
            uri_e.set_editable(False)
            uri_e.set_hexpand(True)
            uri_e.set_placeholder_text("otpauth://... (appears after Enroll)")

            def _enroll(_w):
                try:
                    s = _totp.generate_secret()
                    on_enroll_totp(s)
                    uri = _totp.provision_uri(s, "kiosk@soc.local",
                                                issuer=f"SOC Wall — {title}")
                    uri_e.set_text(uri)
                    _refresh()
                    status.set_text("TOTP enrolled — paste the URI into your "
                                     "authenticator app (or scan after `qrencode "
                                     "-t ANSIUTF8 '<uri>'`).")
                except Exception as e:                # noqa: BLE001
                    status.set_text(f"could not enroll TOTP: {e}")

            def _unenroll(_w):
                if has_totp() and not self._require_reauth(
                        f"removal of the {title} TOTP"):
                    return
                try:
                    on_clr_totp()
                    uri_e.set_text("")
                    _refresh()
                except Exception as e:                # noqa: BLE001
                    status.set_text(f"could not remove TOTP: {e}")
            enroll_b.connect("clicked", _enroll)
            unenroll_b.connect("clicked", _unenroll)
            trow.pack_start(uri_e, True, True, 0)
            trow.pack_start(enroll_b, False, False, 0)
            trow.pack_start(unenroll_b, False, False, 0)
            inner.pack_start(trow, False, False, 0)
            frame.add(inner)
            return frame

        # ⚙ Settings PIN/TOTP (the gate that opens this very window)
        box.pack_start(_section(
            title="Settings access (this window)",
            on_set_pin=set_pin, on_clr_pin=clear_pin,
            on_enroll_totp=lambda s: _totp.save(_totp_path(), s),
            on_clr_totp=lambda: _totp.clear(_totp_path()),
            has_pin=pin_is_set, has_totp=totp_is_set,
        ), False, False, 0)

        # Panel-lock PIN/TOTP (the input-firewall over the wall)
        box.pack_start(_section(
            title="Panel lock (input firewall over the wall)",
            on_set_pin=lambda v: _lk.set_pin(sd, v),
            on_clr_pin=lambda: _lk.clear_pin(sd),
            on_enroll_totp=lambda s: _totp.save(_lk._totp_path(sd), s),
            on_clr_totp=lambda: _totp.clear(_lk._totp_path(sd)),
            has_pin=lambda: _lk.pin_is_set(sd),
            has_totp=lambda: _lk.totp_is_set(sd),
        ), False, False, 0)
        return box

    def _tab_actions(self):
        """Operator actions that aren't config edits — recover from a wedged
        panel, soft-restart the wall to pick up new layout/grid/resolution,
        reboot the box, or run setup.py repair without a shell."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(12)
        note = Gtk.Label(label="Operator actions. The wall service has "
                               "Restart=always (RestartSec=3), so 'Restart "
                               "wall' is a 3-second blip — used to apply "
                               "layout / grid / resolution changes live.")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)

        msg = Gtk.Label(label="")
        msg.get_style_context().add_class("soc-config-ok")
        msg.set_xalign(0.0)
        msg.set_line_wrap(True)

        def _confirm_and_run(label, callable_):
            # Two-click confirmation: first click changes button text, second
            # actually fires. Prevents an accidental "Reboot" from a fat-finger.
            state = {"armed": False}

            def cb(btn):
                if not state["armed"]:
                    state["armed"] = True
                    btn.set_label(f"Confirm: {label}")
                    GLib.timeout_add_seconds(4, _disarm, btn)
                    return
                state["armed"] = False
                btn.set_label(label)
                try:
                    callable_()
                    msg.set_text(f"{label} ✓")
                except Exception as e:  # noqa: BLE001
                    msg.set_text(f"{label} failed: {e}")

            def _disarm(btn):
                if state["armed"]:
                    state["armed"] = False
                    btn.set_label(label)
                return False
            return cb

        def _reboot_machine():
            import subprocess
            try:
                subprocess.run(["systemctl", "reboot"], timeout=10,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=True)
            except Exception:                          # noqa: BLE001
                raise RuntimeError(
                    "needs root — run: sudo systemctl reboot")

        def _repair_install():
            import subprocess
            try:
                subprocess.Popen(
                    ["sudo", "-n", "/opt/soc-display/.venv/bin/python",
                     "/opt/soc-display/setup.py", "repair"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:                          # noqa: BLE001
                raise RuntimeError(
                    "needs root — run: sudo python3 /opt/soc-display/setup.py repair")

        grid = Gtk.Grid()
        grid.set_column_spacing(10)
        grid.set_row_spacing(10)
        rows = []

        if self._actions.get("reload_panels"):
            b = Gtk.Button(label="Reload panels")
            b.set_tooltip_text("Refresh every panel in place (no restart). "
                               "Use when a panel is stuck or a dashboard "
                               "rotation is needed.")
            b.connect("clicked", _confirm_and_run(
                "Reload panels", self._actions["reload_panels"]))
            rows.append(("Reload panels (in-place)", b))

        if self._actions.get("restart_wall"):
            b = Gtk.Button(label="Restart wall")
            b.get_style_context().add_class("soc-config-primary")
            b.set_tooltip_text("Soft-restart the wall process — systemd "
                               "respawns it in ~3 s. Use this to apply "
                               "layout / grid / resolution / SOC_SESSION "
                               "changes without rebooting the box.")
            b.connect("clicked", _confirm_and_run(
                "Restart wall", self._actions["restart_wall"]))
            rows.append(("Restart wall (systemd respawn)", b))

        if self._actions.get("lock_wall"):
            b = Gtk.Button(label="🔒 Lock the wall now")
            b.set_tooltip_text("Same as the toolbar 🔒 Lock and Ctrl+Alt+L. "
                               "Panels stay visible; keyboard + mouse are "
                               "inert until PIN or TOTP is entered.")
            # Single-click (no confirm) — locking is reversible and the
            # operator may need to lock fast.
            b.connect("clicked", lambda _b: self._actions["lock_wall"]())
            rows.append(("Lock the wall now", b))

        if self._actions.get("show_vpn_log"):
            b = Gtk.Button(label="Show VPN log (live)")
            b.set_tooltip_text("Opens the live VPN log viewer — one tab per "
                               "VPN streaming journalctl. Reconnect button "
                               "per tab. Collapse-to-bar mode for keeping "
                               "an eye on it while you work.")
            b.connect("clicked",
                       lambda _b: self._actions["show_vpn_log"]())
            rows.append(("Show VPN log (live)", b))

        b = Gtk.Button(label="Repair install")
        b.set_tooltip_text("Run setup.py repair as root. Fixes perms, "
                           "re-seeds rbw config, re-ensures /run/user/<soc>.")
        b.connect("clicked", _confirm_and_run("Repair install", _repair_install))
        rows.append(("Repair install (setup.py repair)", b))

        b = Gtk.Button(label="Reboot machine")
        b.set_tooltip_text("systemctl reboot — needs root.")
        b.connect("clicked", _confirm_and_run("Reboot", _reboot_machine))
        rows.append(("Reboot machine", b))

        for r, (lbl, w) in enumerate(rows):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            grid.attach(h, 0, r, 1, 1)
            grid.attach(w, 1, r, 1, 1)
        box.pack_start(grid, False, False, 0)
        box.pack_start(msg, False, False, 0)
        return box

    def _tab_status(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.set_border_width(12)
        panels_total = len(self.panels)
        configured = sum(1 for p in self.panels if getattr(p, "configured", False))
        with_creds = sum(1 for p in self.panels if p.vault_item)
        vw_url = os.environ.get("SOC_VAULT_URL", "http://127.0.0.1:8222")
        vw_email = os.environ.get("SOC_VAULT_EMAIL", "")
        vw_reachable = _vw_reachable(vw_url)
        from . import secretstore
        sealed = secretstore.is_sealed(os.environ.get("SOC_SECRET_DIR"))

        lines = [
            f"vault backend  : {os.environ.get('SOC_VAULT_BACKEND', 'rbw')}",
            f"vault server   : {vw_url}  "
            f"({'reachable ✓' if vw_reachable else 'NOT REACHABLE ✗'})",
            f"vault account  : {vw_email or '(SOC_VAULT_EMAIL is empty)'}",
            f"master sealed  : "
            f"{'yes ✓' if sealed else 'NO ✗ — run sudo python3 setup.py first-run'}",
            f"panels         : {configured}/{panels_total} configured "
            f"({panels_total - configured} blank click-to-configure)",
            f"auto-login     : {with_creds}/{panels_total} panel(s) have a vault item set",
            "VPN status     : shown in the top bar (click the pill to re-check)",
        ]
        for ln in lines:
            lbl = Gtk.Label(label=ln)
            lbl.get_style_context().add_class("soc-config-sub")
            lbl.set_xalign(0.0)
            box.pack_start(lbl, False, False, 0)

        # Loud warnings — what the audit asked for. The operator opens this tab
        # when something feels off, so each warning is a one-line "you have a
        # silent failure waiting for you" with the fix hint inline.
        warnings = []
        if not vw_reachable:
            warnings.append(f"⚠ Vaultwarden at {vw_url} is NOT reachable — "
                            f"auto-login and the Credentials tab will fail. "
                            f"Check 'systemctl status vaultwarden'.")
        if not sealed:
            warnings.append("⚠ Master password is NOT host-sealed — the wall "
                            "cannot self-unlock the vault at boot, so "
                            "auto-login is dead until you run "
                            "'sudo python3 setup.py first-run'.")
        if vw_reachable and not vw_email:
            warnings.append("⚠ SOC_VAULT_EMAIL is empty in soc.env — register "
                            "an account and set the email via setup.py "
                            "wizard, then re-run first-run.")
        if configured > 0 and with_creds == 0:
            warnings.append(f"⚠ {configured} panel(s) have a URL but NO vault "
                            f"item — those panels will show the login page "
                            f"without auto-filling. Set a vault item on the "
                            f"Panels tab and store the login on Credentials.")
        if with_creds > 0 and not vw_reachable:
            warnings.append(f"⚠ {with_creds} panel(s) depend on the vault for "
                            f"auto-login but the vault is unreachable — fix "
                            f"vaultwarden first.")
        # Selector-staleness — a panel that has burnt most of its login retry
        # budget without ever firing on_login_success usually means the
        # dashboard was redesigned and the selectors / login_marker no longer
        # match. Audit MED #9.
        if callable(self._login_stats):
            try:
                stats = self._login_stats() or {}
            except Exception:                # noqa: BLE001
                stats = {}
            stale = [pid for pid, s in stats.items()
                     if isinstance(s, dict) and s.get("stale")]
            if stale:
                warnings.append(
                    f"⚠ selectors may be stale on {len(stale)} panel(s): "
                    f"{', '.join(sorted(stale))}. The dashboard probably "
                    f"changed; update the user/pass/submit selectors and "
                    f"login_marker on the Panels tab > Advanced.")
        for w in warnings:
            lbl = Gtk.Label(label=w)
            lbl.get_style_context().add_class("soc-config-error")
            lbl.set_xalign(0.0)
            lbl.set_line_wrap(True)
            box.pack_start(lbl, False, False, 0)
        return box

    def _build_security(self):
        exp = Gtk.Expander(label="Security — lock PIN")
        exp.get_style_context().add_class("soc-config-sec")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_border_width(8)
        state = ("A PIN is set — it is required to open this window."
                 if pin_is_set() else
                 "No PIN set — anyone can open this window. Set one to lock it.")
        self._sec_state = Gtk.Label(label=state)
        self._sec_state.get_style_context().add_class("soc-config-sub")
        self._sec_state.set_xalign(0.0)
        self._sec_state.set_line_wrap(True)
        box.pack_start(self._sec_state, False, False, 0)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._newpin = Gtk.Entry()
        self._newpin.set_visibility(False)
        self._newpin.set_input_purpose(Gtk.InputPurpose.DIGITS)
        self._newpin.set_placeholder_text("new PIN")
        self._newpin.set_hexpand(True)
        set_b = Gtk.Button(label="Set / change PIN")
        set_b.connect("clicked", lambda *_: self._set_pin())
        clr_b = Gtk.Button(label="Remove PIN")
        clr_b.connect("clicked", lambda *_: self._clear_pin())
        row.pack_start(self._newpin, True, True, 0)
        row.pack_start(set_b, False, False, 0)
        row.pack_start(clr_b, False, False, 0)
        box.pack_start(row, False, False, 0)
        exp.add(box)
        return exp

    def _set_pin(self):
        pin = self._newpin.get_text().strip()
        if len(pin) < 4:
            self._sec_state.set_text("PIN must be at least 4 digits.")
            return
        set_pin(pin)
        self._newpin.set_text("")
        self._sec_state.set_text("PIN updated — it will be required next time.")

    def _clear_pin(self):
        # Gate Remove PIN with the same re-auth policy Phase 6 added to
        # the Security tab's clear buttons. Without this, anyone who can
        # already open the Settings window (because a PIN unlocked it)
        # could trivially remove the PIN — which the wall now warns is
        # exactly the action we want gated.
        if pin_is_set() and not self._require_reauth(
                "removal of the Settings PIN (legacy expander)"):
            return
        clear_pin()
        self._newpin.set_text("")
        self._sec_state.set_text("PIN removed — the window now opens without one.")

    # ---- apply -------------------------------------------------------------
    def _msg(self, text, error=False):
        ctx = self._form_msg.get_style_context()
        ctx.remove_class("soc-config-error" if not error else "soc-config-ok")
        ctx.add_class("soc-config-error" if error else "soc-config-ok")
        self._form_msg.set_text(text)

    def _apply(self):
        if not self._unlocked:
            return
        bad = [pid for pid, w in self._rows.items() if not valid_url(w["url"].get_text())]
        if bad:
            self._msg(f"only http:// or https:// URLs are allowed (check: {', '.join(bad)})",
                      error=True)
            return

        changes, overrides = {}, load_overrides()
        for pid, w in self._rows.items():
            url = w["url"].get_text().strip()
            title = w["title"].get_text().strip()
            vault_item = w["vault"].get_text().strip()
            engine = w["engine"].get_active_text() or "webkit"
            sel = {k: w[k].get_text().strip() for k in ("user", "pass", "submit")}
            sel = {k: v for k, v in sel.items() if v}
            marker = w["marker"].get_text().strip()
            # only url/title/vault apply live; the rest persist for next restart
            changes[pid] = {"url": url, "title": title, "vault_item": vault_item}
            entry = overrides.get(pid, {}) if isinstance(overrides.get(pid), dict) else {}
            relogin = w["relogin"].get_text().strip()
            bbuf = w["blocked"].get_buffer()
            blocked = [ln.strip() for ln in bbuf.get_text(
                bbuf.get_start_iter(), bbuf.get_end_iter(), False).splitlines()
                if ln.strip()]
            entry.update({"url": url, "title": title, "vault_item": vault_item,
                          "engine": engine, "selectors": sel, "login_marker": marker,
                          "allow_insecure": bool(w["allow_insecure"].get_active()),
                          "allow_media": bool(w["allow_media"].get_active()),
                          "proxy": bool(w["proxy"].get_active()),
                          "keepalive": {
                              "strategy": w["ka_strat"].get_active_text() or "none",
                              "intervalSec": int(w["ka_int"].get_value())},
                          "relogin_url": relogin,
                          "blocked_url_patterns": blocked})
            overrides[pid] = entry

        if self.display is not None:
            disp = {"layout": self._layout_c.get_active_text() or "auto",
                    "gap": int(self._gap_s.get_value()),
                    "cols": int(self._cols_s.get_value()),
                    "rows": int(self._rows_s.get_value()),
                    "auto": bool(self._disp_auto.get_active()),
                    "width": int(self._w_s.get_value()),
                    "height": int(self._h_s.get_value()),
                    "fullscreen": bool(self._fullscreen_c.get_active())}
            overrides["_display"] = disp
            changes["_display"] = disp

        if self._vpn is not None and self._vpn_ws:
            vpns_out = []
            for idx, w in enumerate(self._vpn_ws):
                cfg = vpn_form_to_dict({
                    "enabled": w["enabled"].get_active(),
                    "type": w["type"].get_active_text() or "fortinet",
                    "gateway": w["gateway"].get_text(),
                    "port": int(w["port"].get_value()),
                    "vault_item": w["vault_item"].get_text(),
                    "config": w["config"].get_text(),
                    "domain": w["domain"].get_text(),
                    "realm": w["realm"].get_text(),
                    "trusted_cert": w["trusted_cert"].get_text(),
                    "ready_probe": w["ready_probe"].get_text(),
                    "insecure": w["insecure"].get_active(),
                    "config_from_vault": w["config_from_vault"].get_active(),
                })
                cfg["name"] = (w["name"].get_text().strip()
                               or f"vpn-{idx+1}")
                vpns_out.append(cfg)
            overrides["_vpns"] = vpns_out
            changes["_vpns"] = vpns_out
            # back-compat: first entry under the legacy key
            overrides["_vpn"] = vpns_out[0] if vpns_out else {}
            changes["_vpn"] = vpns_out[0] if vpns_out else {}

        if self._proxy is not None and self._proxy_w:
            w = self._proxy_w
            pcfg = proxy_form_to_dict({
                "enabled": w["enabled"].get_active(),
                "url": w["url"].get_text(),
                "vault_item": w["vault_item"].get_text(),
                "ignore_hosts": w["ignore_hosts"].get_text(),
            })
            overrides["_proxy"] = pcfg
            changes["_proxy"] = pcfg

        if self._tunnel is not None and self._tunnel_w:
            w = self._tunnel_w
            buf = self._tunnel_ef.get_buffer()
            ef = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
            tcfg = tunnel_form_to_dict({
                "enabled": w["enabled"].get_active(),
                "jump_host": w["jump_host"].get_text(),
                "identity": w["identity"].get_text(),
                "known_hosts": w["known_hosts"].get_text(),
                "host_key_checking": w["host_key_checking"].get_active_text() or "yes",
                "extra_forwards": ef,
            })
            overrides["_tunnel"] = tcfg
            changes["_tunnel"] = tcfg

        save_overrides(overrides)
        try:
            result = self.on_apply(changes) or {}
        except Exception as e:  # noqa: BLE001 — never let a bad apply kill the window
            self._msg(f"apply error: {e}", error=True)
            return
        # Tell the truth: pending_restarts (the wall can't restart units when it
        # runs as `soc` with NoNewPrivileges) and write_back ('deferred:<reason>'
        # when overrides.json was saved but the vault note can't be updated —
        # next boot's stale vault note will silently win otherwise).
        pending = result.get("pending_restarts") or []
        write_back = result.get("write_back", "ok")
        self_restart = bool(result.get("self_restart"))
        applied_live = result.get("applied_live") or []
        bits = ["Saved ✓ — overrides.json updated"]
        if applied_live:
            # Width / height / fullscreen / cols / rows applied without a
            # restart — surface what changed in-place so the operator
            # doesn't think the wall ignored their edit.
            bits.append(f"applied live ✓ ({', '.join(applied_live)} — "
                        "no restart)")
        if self_restart:
            bits.append("restarting wall to apply layout change "
                        "(launcher/systemd respawns in ~3s)")
        if pending:
            bits.append("⚠ PENDING restart (reboot the wall, or `sudo "
                        f"systemctl restart {' '.join(pending)}` as root): "
                        f"{', '.join(pending)}")
        if isinstance(write_back, str) and write_back.startswith("deferred:"):
            bits.append(f"⚠ vault config-note NOT written ({write_back[9:]}) — "
                        "your changes will be lost at the next boot unless you "
                        "fix this. Local overrides remain in effect for now.")
        elif write_back == "ok":
            bits.append("vault note write-back scheduled")
        self._msg("  ·  ".join(bits), error=bool(pending) or (
                  isinstance(write_back, str) and write_back.startswith("deferred:")))

    def _on_focus_out(self, *_):
        # Pull the window back to the front whenever the kiosk steals focus.
        # set_keep_above() handles stacking, present() re-marks it as the
        # active window so a click on a panel underneath doesn't visually
        # bury us. Returning False lets other handlers run normally.
        try:
            self.present()
        except Exception:  # noqa: BLE001 — never let UX polish kill the wall
            pass
        return False
