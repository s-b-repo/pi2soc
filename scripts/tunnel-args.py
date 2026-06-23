#!/usr/bin/env python3
"""
Emit the autossh argument list (one arg per line) from config/panels.yaml.

Builds an -L local forward for every panel with mode: tunnel, so each remote
panel becomes http://127.0.0.1:<local_port>/... Prints nothing if there are no
tunnels (the wrapper then idles).

  autossh $(this script) ==> persistent jump-host tunnel
"""
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "kiosk-host"))
from host import config as cfg  # noqa: E402

# A user-supplied extra_forward is spliced straight into ssh's `-L` argument. It
# MUST be a plain bindaddr:port:host:port spec — never an option-looking token
# ("-D ...", "-o ...") or anything with whitespace, which ssh could mis-parse as
# a second option (e.g. -L "x -o ProxyCommand=...").
_FWD_RE = re.compile(
    r"^[A-Za-z0-9_.:\[\]-]+:[0-9]+:[A-Za-z0-9_.:\[\]-]+:[0-9]+$")


def _validate_extra_forward(entry):
    """Return a vetted bindaddr:port:host:port forward, or raise ValueError.

    Rejects option injection into ssh's -L: any leading '-', embedded
    whitespace, or anything not matching the strict forward shape.
    """
    s = str(entry)
    if s != s.strip() or any(c.isspace() for c in s):
        raise ValueError(f"extra_forward contains whitespace: {entry!r}")
    if s.startswith("-"):
        raise ValueError(f"extra_forward looks like an option: {entry!r}")
    if not _FWD_RE.match(s):
        raise ValueError(
            f"extra_forward must be bindaddr:port:host:port, got: {entry!r}")
    return s


def main():
    panels = os.environ.get("SOC_PANELS_FILE", "config/panels.yaml")
    conf = cfg.load(panels)
    t = conf.tunnel or {}

    forwards = []
    for p in conf.panels:
        if p.mode == "tunnel" and p.tunnel:
            tn = p.tunnel
            forwards.append(
                f"127.0.0.1:{tn['local_port']}:{tn['remote_host']}:{tn['remote_port']}")
    forwards += [_validate_extra_forward(f)
                 for f in (t.get("extra_forwards", []) or [])]

    # A disabled tunnel section, or one explicitly empty, is a legitimate no-op
    # — print nothing and let autossh-tunnel.sh sleep. But an ENABLED tunnel
    # section with a jump_host yet zero forwards is a misconfiguration: the
    # operator clearly intended to tunnel something, but no panel uses
    # mode: tunnel and no extra_forwards is set. autossh-tunnel.sh would
    # silently fall through to `sleep infinity`, looking identical to "no
    # tunnels intended". Surface the mistake to the journal so it isn't
    # silently swallowed.
    if not t.get("enabled", True):
        return
    if not t.get("jump_host"):
        return                              # nothing to point ssh at
    if not forwards:
        sys.stderr.write(
            "tunnel-args: tunnel.enabled=true and jump_host is set, but NO "
            "panels use mode: tunnel and tunnel.extra_forwards is empty — "
            "there is nothing for autossh to forward. Either disable the "
            "tunnel section, or give a panel mode: tunnel (Panels tab) / "
            "add an extra_forward (Tunnel tab).\n")
        sys.exit(2)

    # SEC-6: verify the jump host's key. Default is strict 'yes' — the operator
    # provisions the key into known_hosts (verifying the fingerprint out of band)
    # so a MITM at first connect cannot intercept the tunnel that carries the
    # SOC dashboards + their logins. 'accept-new' (TOFU) is allowed only as an
    # explicit opt-in for first bring-up; anything else falls back to 'yes'.
    hkc = str(t.get("host_key_checking", "yes")).strip().lower()
    if hkc not in ("yes", "accept-new"):
        hkc = "yes"

    # With anything weaker than strict 'yes' (e.g. 'accept-new' TOFU), require an
    # explicit known_hosts path. Otherwise ssh would write trust-on-first-use
    # keys into a default/ambient file we don't control — a silent MITM window.
    # The operator must pin a dedicated, provisioned known_hosts in that mode.
    known = t.get("known_hosts")
    if hkc != "yes" and not known:
        raise ValueError(
            "host_key_checking={!r} requires an explicit 'known_hosts' path "
            "(set tunnel.known_hosts) so first-connect keys are pinned to a "
            "controlled file; refusing to weaken host-key verification without "
            "it.".format(t.get("host_key_checking")))

    args = ["-M", "0", "-N",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-o", "ExitOnForwardFailure=yes",
            "-o", f"StrictHostKeyChecking={hkc}",
            "-o", "BatchMode=yes"]
    if known:
        args += ["-o", f"UserKnownHostsFile={os.path.expanduser(known)}"]
    ident = t.get("identity")
    if ident:
        args += ["-i", os.path.expanduser(ident)]
    for f in forwards:
        args += ["-L", f]
    args.append(t["jump_host"])
    sys.stdout.write("\n".join(args) + "\n")


if __name__ == "__main__":
    main()
