"""Seal the plugin's security-relevant files and check them before starting or unlocking.

`qr-launch seal` (run by you, in your own terminal) records SHA-256 hashes of every
file in the plugin folder in ~/.qr/seal.json; added or removed files count as changes.
The bin scripts load this module by file path, before anything else in lib/, and run
with `python3 -I`, so nothing in the plugin folder or the current folder can shadow it. qr-launch start, qr-approve and qr-reject refuse to proceed if
any sealed file changed, so a session that rewrote the gate cannot quietly get
its tools back. This is a tripwire, not a boundary: anything running as your
user could also rewrite the seal.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

IGNORED_DIRS = {"__pycache__", ".git"}
IGNORED_FILES = {".DS_Store"}


def files(root: Path) -> list[str]:
    """Every file in the plugin folder, relative and sorted (caches excluded)."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
        for name in filenames:
            if name in IGNORED_FILES or name.endswith(".pyc"):
                continue
            out.append(os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/"))
    return sorted(out)


def digest(root: Path) -> dict:
    out = {}
    for rel in files(root):
        p = root / rel
        out[rel] = "symlink" if p.is_symlink() else hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def seal(root: Path, home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / "seal.json").write_text(json.dumps(digest(root), indent=2) + "\n", encoding="utf-8")


def changed(root: Path, home: Path) -> list[str] | None:
    """Files that differ from the seal. None means there is no seal yet."""
    try:
        sealed = json.loads((home / "seal.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return None
    now = digest(root)
    return sorted(k for k in set(sealed) | set(now) if sealed.get(k) != now.get(k))


def hooks_disabled(user_home: Path, project_dirs: list[Path] = ()) -> list[str]:
    """Claude settings files that turn all hooks off (which would disable the gate)."""
    found = []
    candidates = [user_home / ".claude" / "settings.json", user_home / ".claude" / "settings.local.json"]
    for d in project_dirs:
        candidates += [d / ".claude" / "settings.json", d / ".claude" / "settings.local.json"]
    for p in candidates:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and data.get("disableAllHooks") is True:
            found.append(str(p))
    return found
