"""SEC-6 regression: the autossh arg builder must verify the jump-host key."""
import importlib.util
import io
import os
from contextlib import redirect_stdout


def _run(panels_path):
    """Import scripts/tunnel-args.py fresh and run main() against a panels file,
    returning the emitted args as a list of lines."""
    path = os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "tunnel-args.py")
    spec = importlib.util.spec_from_file_location("tunnel_args", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    os.environ["SOC_PANELS_FILE"] = str(panels_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        m.main()
    return buf.getvalue().splitlines()


_PANELS = """\
display: {grid: "2x2"}
panels:
  - id: p1
    grid: [0, 0]
    mode: tunnel
    tunnel: {local_port: 19101, remote_host: 10.0.0.5, remote_port: 8443}
tunnel:
  enabled: true
  jump_host: "u@jump"
  __EXTRA__
"""


def _write(tmp_path, extra=""):
    p = tmp_path / "panels.yaml"
    p.write_text(_PANELS.replace("__EXTRA__", extra))
    return p


def test_default_is_strict_host_key_checking(tmp_path):
    args = _run(_write(tmp_path))
    assert "StrictHostKeyChecking=yes" in args
    assert "StrictHostKeyChecking=accept-new" not in args


def test_accept_new_is_explicit_optin(tmp_path):
    args = _run(_write(tmp_path, extra='host_key_checking: "accept-new"'))
    assert "StrictHostKeyChecking=accept-new" in args


def test_unknown_value_falls_back_to_strict(tmp_path):
    # A bogus / unsafe value must NOT silently weaken verification.
    args = _run(_write(tmp_path, extra='host_key_checking: "no"'))
    assert "StrictHostKeyChecking=yes" in args
    assert "StrictHostKeyChecking=no" not in args


def test_known_hosts_is_passed_through(tmp_path):
    args = _run(_write(tmp_path, extra='known_hosts: "/etc/soc-display/keys/known_hosts"'))
    assert "UserKnownHostsFile=/etc/soc-display/keys/known_hosts" in args
