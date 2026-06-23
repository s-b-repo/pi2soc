"""
Deploy-time file-hash manifest + boot-time drift detection.

At install time (after install.sh's tar-pipe copies the git checkout into
$SOC_ROOT), we hash every shipped file and record the (relative_path →
sha256) map together with the source commit's `HEAD` sha. The manifest is
written to /etc/soc-display/manifest.json (one directory above $SOC_ROOT
so it isn't itself hashed).

At boot, `check_drift(deploy_root)` hashes the on-disk files in
$SOC_ROOT and compares to the manifest. Anything that differs is in
`changed`; anything in the manifest but missing on disk is in `missing`.
Empty `changed` + empty `missing` → no drift.

Used by `KioskHost.build_and_show` to paint a top-bar warning when files
drift — useful to spot a tampered install or an unrecorded local edit
that snuck onto the box outside of `install.sh`.

This module is stdlib-only and side-effect-free apart from the explicit
write_manifest call, so the unit tests can exercise it without touching
the real `/etc/soc-display`.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from typing import Iterable

MANIFEST_PATH = "/etc/soc-display/manifest.json"
REPO_URL = "https://github.com/s-b-repo/pi2soc"

# Directories whose contents are noise — bytecode caches, audit dumps, the
# venv, the .git itself. The deploy tree should not contain any of these,
# but we exclude defensively so a re-run on a dev checkout doesn't crash
# with "git/foo doesn't exist".
_SKIP_DIRS = frozenset({
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".audit", ".claude", "secret",
})

# File suffixes worth excluding — generated, transient, or per-host.
_SKIP_SUFFIXES: tuple[str, ...] = (".pyc", ".pyo", ".log")

# Concrete filenames to exclude. PROMPT.txt / MEMORY.md are operator
# scratchpads (gitignored); manifest.json itself sits outside the deploy
# tree but exclude defensively in case someone moves it later.
_SKIP_NAMES = frozenset({
    "PROMPT.txt", "MEMORY.md", "manifest.json",
})


def hash_file(path: str) -> str:
    """SHA-256 of `path`, computed in 64 KiB chunks so a 100 MB binary
    doesn't blow up memory. Reads in binary mode — works for source
    code, vendored binaries, anything."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _walk_tracked(root: str) -> Iterable[str]:
    """Yield every file under `root` worth hashing, as absolute paths. Skips
    the directories and suffixes above. Stable order (sorted) so the same
    tree produces the same manifest byte-for-byte across runs."""
    root = os.path.abspath(root)
    for d, dirs, fs in os.walk(root):
        dirs[:] = sorted([x for x in dirs if x not in _SKIP_DIRS])
        for f in sorted(fs):
            if f in _SKIP_NAMES or f.endswith(_SKIP_SUFFIXES):
                continue
            yield os.path.join(d, f)


def build_manifest(root: str, commit_sha: str = "") -> dict:
    """Build a manifest dict from `root`. `commit_sha` is opaque to us — we
    just record it for the drift warning to link back to the right commit."""
    files = {}
    root_abs = os.path.abspath(root)
    for p in _walk_tracked(root_abs):
        rel = os.path.relpath(p, root_abs)
        files[rel] = hash_file(p)
    return {
        "version": 1,
        "commit": commit_sha or "",
        "repo": REPO_URL,
        "files": files,
    }


def _current_commit(root: str) -> str:
    """`git -C root rev-parse HEAD`. Returns '' on failure (not a checkout,
    git missing, detached state without a rev) — that's the manifest's
    'unknown commit' state and the drift warning degrades gracefully."""
    try:
        r = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def write_manifest(root: str, dest: str = MANIFEST_PATH) -> str:
    """Hash `root` + read `root`'s git HEAD, write JSON to `dest`. The
    enclosing directory is created with mode 0755 if absent; the manifest
    itself is written 0644 (world-readable — its contents are not secret,
    only the *integrity guarantee* they encode is interesting)."""
    sha = _current_commit(root)
    m = build_manifest(root, sha)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2, sort_keys=True)
    os.chmod(dest, 0o644)
    return dest


def check_drift(deploy_root: str,
                manifest_path: str = MANIFEST_PATH) -> dict:
    """Compare `deploy_root` on-disk hashes to the recorded manifest.
    Returns a dict:

        {
          "commit": <recorded commit sha>,
          "repo":   <github url>,
          "changed":[<rel-path>, ...],   # file present, hash differs
          "missing":[<rel-path>, ...],   # file in manifest, gone on disk
          "extras": [<rel-path>, ...],   # file on disk, not in manifest
        }

    Empty changed+missing+extras → no drift. Raises FileNotFoundError
    if the manifest itself is missing (call site decides whether absence
    is a soft-skip or a loud failure)."""
    with open(manifest_path, encoding="utf-8") as f:
        m = json.load(f)
    expected = m.get("files", {})
    changed: list[str] = []
    missing: list[str] = []
    seen: set[str] = set()
    root_abs = os.path.abspath(deploy_root)
    for rel, want in expected.items():
        p = os.path.join(root_abs, rel)
        if not os.path.exists(p):
            missing.append(rel)
            continue
        if hash_file(p) != want:
            changed.append(rel)
        seen.add(rel)
    # Discover extras — files on disk that the manifest doesn't know about.
    # Useful to catch a covert add ("did anyone drop a sketchy .py into
    # /opt/soc-display?"). Bounded by the same walk filter.
    extras: list[str] = []
    for p in _walk_tracked(root_abs):
        rel = os.path.relpath(p, root_abs)
        if rel not in expected:
            extras.append(rel)
    return {
        "commit": m.get("commit", ""),
        "repo":   m.get("repo", REPO_URL),
        "changed": sorted(changed),
        "missing": sorted(missing),
        "extras":  sorted(extras),
    }


def format_drift_summary(drift: dict, *, max_files: int = 5) -> str:
    """Compose a one-line warning suitable for the wall's top-bar.

    Returns '' when there's no drift, so the caller can `if msg: ...`."""
    n_chg = len(drift.get("changed", []))
    n_miss = len(drift.get("missing", []))
    n_xtra = len(drift.get("extras", []))
    if not (n_chg or n_miss or n_xtra):
        return ""
    commit = (drift.get("commit") or "").strip()
    sha_short = commit[:12] if commit else "unknown"
    parts = []
    if n_chg:  parts.append(f"{n_chg} changed")
    if n_miss: parts.append(f"{n_miss} missing")
    if n_xtra: parts.append(f"{n_xtra} extra")
    summary = ", ".join(parts)
    return (f"⚠ files drift from deployed commit {sha_short} "
            f"({summary}). Run `git diff {sha_short}` against the "
            f"repo to investigate.")
