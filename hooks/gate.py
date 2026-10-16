#!/usr/bin/env python3
"""PreToolUse gate for your main Claude Code session (all tools, including inside subagents).

While a report is pending (~/.qr/TAINTED exists or ~/.qr/inbox is not empty):
  - only Read, Grep and Glob run, and only on paths inside ~/.qr/inbox or ~/.qr/approved;
  - sessions that read a pending report are recorded, so a reject can keep them locked.
In a session that read a report you rejected: the same read-only rules apply for good.
Otherwise, as a backstop:
  - no tool may touch the token, raw job folders, flag or bookkeeping in ~/.qr;
  - no edits inside ~/.qr, this plugin's folder, or Claude settings files;
  - shell commands may not mention ~/.qr, this plugin, podman or the approve/reject
    scripts, except the exact launcher forms used by /research.

Fails closed: any error denies the call. Exit code 2 = deny (reason on stderr).
Path checks are lexical first, so untrusted paths are never touched on disk unless
they already sit inside ~/.qr.
"""
from __future__ import annotations

import json
import os
import re
import sys

READ_ONLY_TOOLS = {"Read", "Grep", "Glob", "LS"}
EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
SHELL_TOOLS = {"Bash", "BashOutput", "PowerShell"}
SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
JOB_ID = r"[0-9]{8}-[0-9]{6}-[0-9a-f]{6}"
PROTECTED_MARKERS = ("oauth_token", "find-generic-password", "qr-approve", "qr-reject", "set-token",
                     "disableallhooks")
SHELL_MARKERS = ("quarantined-research", "qr-launch", "hooks.json", "gate.py", ".claude/settings",
                 "podman", "claude_plugin_root")
QR_DIR = re.compile(r"(?:^|[/\\~\s\"'=:])\.qr(?:$|[/\\\s\"'*?\[{])")

AWAITING = "Report awaiting approval: only the report folder can be read. Run qr-approve or qr-reject in your own terminal."
LOCKED = "This session read a report that was rejected. Start a new Claude session."
PROTECTED = "Protected by the quarantined-research plugin."


def absolute(path: str, cwd: str, user_home: str) -> str:
    """Absolute, normalized path without touching the disk (original case)."""
    p = path
    if p == "~" or p.startswith("~/"):
        p = user_home + p[1:]
    if not os.path.isabs(p):
        p = os.path.join(cwd, p)
    return os.path.normpath(p)


def lexical(path: str, cwd: str, user_home: str) -> str:
    """Like absolute(), lowercased for comparison (macOS file names are case-insensitive)."""
    return absolute(path, cwd, user_home).lower()


def under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def path_fields(tool: str, ti: dict, cwd: str) -> list[str] | None:
    """Paths a read-only tool will touch. None means the input is not understood."""
    if tool == "Read":
        p = ti.get("file_path")
        return [p] if isinstance(p, str) and p else None
    if tool in ("Grep", "Glob", "LS"):
        p = ti.get("path")
        if p is None:
            p = cwd
        if not isinstance(p, str) or not p:
            return None
        out = [p]
        pattern = ti.get("pattern") if tool == "Glob" else ti.get("glob")
        if pattern is not None:
            if not isinstance(pattern, str) or ".." in pattern or pattern.startswith(("/", "~")):
                return None
        return out
    return None


def is_tainted(home: str) -> bool:
    if os.path.lexists(os.path.join(home, "TAINTED")):
        return True
    inbox = os.path.join(home, "inbox")
    try:
        return any(not n.startswith(".") for n in os.listdir(inbox))
    except FileNotFoundError:
        return False
    except OSError:
        return True


def touch(path: str) -> None:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    with open(path, "a", encoding="utf-8"):
        pass


def launcher_pattern(plugin_root: str) -> re.Pattern:
    root = re.escape(plugin_root.lower().rstrip("/"))
    exe = r'(?:"?(?:%s|\$\{?claude_plugin_root\}?)/bin/qr-launch"?|qr-launch)' % root
    heredoc = r"\s*<<\s*'qr_brief'\n(?:(?!\nqr_brief\n).)*\nqr_brief"
    return re.compile(r"^\s*%s\s+(?:status(?:\s+%s)?|start(?:%s)?)\s*$" % (exe, JOB_ID, heredoc), re.S)


def decide(payload: dict, home: str, plugin_root: str, user_home: str) -> str | None:
    tool = payload.get("tool_name")
    if not isinstance(tool, str) or not tool:
        return "malformed hook input"
    ti = payload.get("tool_input")
    if ti is None:
        ti = {}
    if not isinstance(ti, dict):
        return "malformed hook input"
    cwd = payload.get("cwd")
    if not isinstance(cwd, str) or not os.path.isabs(cwd):
        cwd = os.getcwd()
    sid = payload.get("session_id")
    sid = sid if isinstance(sid, str) and SESSION_ID.match(sid) else None

    home_l = lexical(home, "/", user_home)
    roots = [home_l + "/inbox", home_l + "/approved"]

    tainted = is_tainted(home)
    locked = bool(sid) and os.path.lexists(os.path.join(home, "locked_sessions", sid))
    if tainted or locked:
        reason = LOCKED if locked else AWAITING
        if tool not in READ_ONLY_TOOLS:
            return reason
        paths = path_fields(tool, ti, cwd)
        if not paths:
            return reason
        reads_inbox = False
        for p in paths:
            lp = lexical(p, cwd, user_home)
            if not any(under(lp, r) for r in roots):
                return reason
            # Inside ~/.qr now, so resolving symlinks is safe; it must still land in a report folder.
            rp = os.path.realpath(absolute(p, cwd, user_home)).lower()
            real_roots = [os.path.realpath(os.path.join(home, sub)).lower() for sub in ("inbox", "approved")]
            if not any(under(rp, r) for r in real_roots):
                return reason
            reads_inbox = reads_inbox or under(lp, roots[0])
        if reads_inbox and sid and tainted:
            touch(os.path.join(home, "readers", sid))
        return None

    # ---- backstops for an unflagged session ----
    blob = json.dumps(ti, ensure_ascii=False).lower()
    blob = blob.replace("\\\\", "\\").replace("\\/", "/")
    for marker in PROTECTED_MARKERS:
        if marker in blob:
            return PROTECTED

    for key in ("file_path", "notebook_path", "path"):
        p = ti.get(key)
        if isinstance(p, str) and p:
            lp = lexical(p, cwd, user_home)
            if under(lp, home_l) and not any(under(lp, r) for r in roots):
                return PROTECTED
            if tool in EDIT_TOOLS:
                if under(lp, home_l) or under(lp, lexical(plugin_root, "/", user_home)):
                    return PROTECTED
                # Follow symlinks in the parent folder (skipping network mounts, which could hang).
                ap = absolute(p, cwd, user_home)
                if not ap.startswith(("/net/", "/Network/", "//")):
                    rp = os.path.join(os.path.realpath(os.path.dirname(ap)), os.path.basename(ap)).lower()
                    if (under(rp, os.path.realpath(home).lower()) or
                            under(rp, os.path.realpath(plugin_root).lower())):
                        return PROTECTED
                if re.search(r"/\.claude/settings[^/]*\.json$", lp):
                    return PROTECTED
    if tool in EDIT_TOOLS and not any(isinstance(ti.get(k), str) and ti.get(k)
                                      for k in ("file_path", "notebook_path")):
        return "malformed hook input"

    if tool in SHELL_TOOLS:
        command = ti.get("command", "")
        if not isinstance(command, str):
            return "malformed hook input"
        cmd = command.lower()
        expanded = cmd.replace("${home}", user_home.lower()).replace("$home", user_home.lower())
        expanded = re.sub(r"(^|[\s\"'=:(])~(?=/|$|\s)", lambda m: m.group(1) + user_home.lower(), expanded)
        if QR_DIR.search(expanded) or home_l in expanded:
            return PROTECTED
        if launcher_pattern(plugin_root).match(cmd):
            return None
        root_l = lexical(plugin_root, "/", user_home)
        # The folder's own name is a marker too, so a rename cannot drop this backstop, and
        # quotes and backslashes are ignored so "My Drive" or My\ Drive in the path still match.
        name_l = os.path.basename(root_l)
        unquoted = re.sub(r"[\\\"']", "", expanded)
        if (root_l in expanded or root_l in unquoted or (name_l and name_l in unquoted)
                or any(m in expanded for m in SHELL_MARKERS)):
            return PROTECTED
    return None


def main() -> int:
    user_home = os.environ.get("HOME") or os.path.expanduser("~")
    home = os.environ.get("QR_HOME") or os.path.join(user_home, ".qr")
    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        payload = json.loads(sys.stdin.read())
        if not isinstance(payload, dict):
            raise ValueError
        reason = decide(payload, home, plugin_root, user_home)
    except Exception:
        reason = "quarantined-research gate could not check this tool call"
    if reason:
        sys.stderr.write(reason + "\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
