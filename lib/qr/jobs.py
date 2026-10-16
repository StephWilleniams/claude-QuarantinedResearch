"""Job lifecycle: create, run the worker container, finalize, approve, reject.

Layout under QR_HOME (default ~/.qr):
  TAINTED              flag: present while any report awaits approval
  secrets/oauth_token  subscription token for the worker (mode 600)
  jobs/<id>/           job state; io/ is the only folder mounted into the container
  inbox/<id>/report.md reports awaiting approval
  approved/<id>/       approved reports
  decisions.log        one line per approve/reject
  readers/<session>    sessions that read a pending report (written by the gate)
  locked_sessions/<s>  sessions that read a rejected report: they stay read-only
  lock                 file lock serializing finalize, approve and reject
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import secrets as pysecrets
import shutil
import subprocess
import time
from pathlib import Path

from . import render, validate

IMAGE = "qr-worker:latest"
JOB_ID = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$")
STATUSES = {"queued", "running", "awaiting-approval", "approved", "rejected"}


# ---------- paths ----------

def qr_home() -> Path:
    return Path(os.environ.get("QR_HOME") or (Path.home() / ".qr"))


def flag_path(home: Path) -> Path:
    return home / "TAINTED"


def token_path(home: Path) -> Path:
    return home / "secrets" / "oauth_token"


def ensure_layout(home: Path) -> None:
    for sub in ("jobs", "inbox", "approved", "secrets"):
        (home / sub).mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    os.chmod(home / "secrets", 0o700)


@contextlib.contextmanager
def locked(home: Path):
    """Serialize every change to the flag and inbox, so approve cannot race finalize."""
    home.mkdir(parents=True, exist_ok=True)
    with open(home / "lock", "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def check_job_id(job_id: str) -> str:
    if not isinstance(job_id, str) or not JOB_ID.match(job_id):
        raise ValueError("invalid job id")
    return job_id


def new_job_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + "-" + pysecrets.token_hex(3)


def set_status(home: Path, job_id: str, status: str) -> None:
    assert status in STATUSES
    p = home / "jobs" / job_id / "status"
    p.write_text(status + "\n", encoding="utf-8")


def get_status(home: Path, job_id: str) -> str:
    try:
        return (home / "jobs" / check_job_id(job_id) / "status").read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return "unknown"


def list_jobs(home: Path) -> list[tuple[str, str]]:
    jobs_dir = home / "jobs"
    if not jobs_dir.is_dir():
        return []
    return [(p.name, get_status(home, p.name)) for p in sorted(jobs_dir.iterdir()) if JOB_ID.match(p.name)]


def pending(home: Path) -> list[str]:
    inbox = home / "inbox"
    if not inbox.is_dir():
        return []
    return sorted(p.name for p in inbox.iterdir() if JOB_ID.match(p.name))


# ---------- token ----------

def save_token(home: Path, token: str) -> None:
    token = token.strip()
    if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,4096}", token):
        raise ValueError("that does not look like a token")
    ensure_layout(home)
    p = token_path(home)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token)
    os.chmod(p, 0o600)


def load_token(home: Path) -> str:
    p = token_path(home)
    if not p.is_file():
        raise RuntimeError("no token saved; run `qr-launch set-token` in your own terminal")
    if p.stat().st_mode & 0o077:
        raise RuntimeError("token file permissions are too open; expected 600")
    return p.read_text(encoding="utf-8").strip()


# ---------- create and run ----------

def create_job(home: Path, brief: str) -> str:
    ensure_layout(home)
    job_id = new_job_id()
    job_dir = home / "jobs" / job_id
    (job_dir / "io").mkdir(parents=True)
    (job_dir / "brief.txt").write_text(brief, encoding="utf-8")
    (job_dir / "io" / "brief.txt").write_text(brief, encoding="utf-8")
    (job_dir / "canary").write_text("QR-" + pysecrets.token_hex(16), encoding="utf-8")
    set_status(home, job_id, "queued")
    return job_id


def podman_command(job_id: str, io_dir: Path, canary: str, limits: dict) -> list[str]:
    """The exact container invocation. Only io_dir is mounted; the token is passed by name only."""
    return [
        "podman", "run", "--rm", "--name", "qr-" + job_id,
        "--cap-drop=ALL",
        "--cap-add=NET_ADMIN", "--cap-add=NET_RAW",
        "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=SETPCAP",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=64m,mode=1777",
        # Podman's --tmpfs rejects uid=/gid=, and the root-only entrypoint has no CAP_CHOWN,
        # so the worker's home is world-writable; the worker creates and owns what is inside.
        "--tmpfs", "/home/worker:rw,size=512m,mode=1777",
        "--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
        "--sysctl", "net.ipv6.conf.default.disable_ipv6=1",
        "--pids-limit=512", "--memory=2g", "--cpus=2",
        "-v", str(io_dir) + ":/job:rw",
        "-e", "CLAUDE_CODE_OAUTH_TOKEN",
        "-e", "QR_CANARY=" + canary,
        "-e", "QR_MAX_TURNS=" + str(limits["max_turns"]),
        "-e", "QR_MAX_FETCHES=" + str(limits["max_fetches"]),
        "-e", "QR_MAX_SEARCHES=" + str(limits["max_searches"]),
        IMAGE,
    ]


def default_limits() -> dict:
    return {
        "max_turns": int(os.environ.get("QR_MAX_TURNS", "60")),
        "max_fetches": int(os.environ.get("QR_MAX_FETCHES", "40")),
        "max_searches": int(os.environ.get("QR_MAX_SEARCHES", "20")),
        "timeout_s": int(os.environ.get("QR_TIMEOUT_S", "1800")),
    }


def run_worker(home: Path, job_id: str) -> None:
    check_job_id(job_id)
    job_dir = home / "jobs" / job_id
    limits = default_limits()
    canary = (job_dir / "canary").read_text(encoding="utf-8").strip()
    env = {k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")}
    env["CLAUDE_CODE_OAUTH_TOKEN"] = load_token(home)
    set_status(home, job_id, "running")
    cmd = podman_command(job_id, job_dir / "io", canary, limits)
    try:
        subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=limits["timeout_s"], check=False)
    except subprocess.TimeoutExpired:
        subprocess.run(["podman", "kill", "qr-" + job_id], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)
        (job_dir / "io" / "error.txt").write_text("timed out\n", encoding="utf-8")


# ---------- finalize ----------

def _read(path: Path, limit: int = 4_000_000) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except FileNotFoundError:
        return ""


ENTRYPOINT_ERRORS = {
    "missing brief", "missing or malformed canary", "missing subscription token",
    "firewall setup failed", "worker setup failed", "timed out",
}


def _build_report(home: Path, job_id: str) -> str:
    job_dir = home / "jobs" / job_id
    io = job_dir / "io"
    brief = _read(job_dir / "brief.txt")
    records = validate.read_fetch_log(_read(io / "fetch.log"))

    error = None
    result = None
    entry_err = _read(io / "error.txt").strip()
    if entry_err:
        error = entry_err if (entry_err in ENTRYPOINT_ERRORS or entry_err.startswith("Claude Code in the image lacks --")) else "container error"
        error = re.sub(r"[^A-Za-z0-9 ;:,.()_-]", "", error)[:200]
    else:
        try:
            final_message = validate.extract_result(_read(io / "stdout.json"))
            doc = validate.parse_claims(final_message)
            result = validate.check_document(doc, validate.fetched_urls(records))
        except validate.WorkerOutputError as exc:
            error = str(exc)
        except Exception:
            error = "worker output could not be checked"
    try:
        return render.render(job_id, brief, result, error, records)
    except Exception:
        # Last resort: a report with no worker text at all.
        return render.render(job_id, brief, None, "report could not be built", [])


def finalize(home: Path, job_id: str) -> Path:
    """Turn the worker's raw output into a report in the inbox. Sets the flag first.

    Always produces a report and always sets the flag, whatever the worker returned.
    """
    check_job_id(job_id)
    io = home / "jobs" / job_id / "io"
    try:
        report = _build_report(home, job_id)
    except Exception:
        report = "# Research report " + job_id + "\n\n## Review summary\n\n- **Status: failed** (internal error). No worker text is included.\n"

    ensure_layout(home)
    with locked(home):
        flag_path(home).write_text(job_id + "\n", encoding="utf-8")   # flag before the report lands
        out_dir = home / "inbox" / job_id
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "report.md").write_text(report, encoding="utf-8")
        set_status(home, job_id, "awaiting-approval")

    # Raw worker output is not kept: only the sanitized report leaves the job.
    for name in ("stdout.json", "stderr.log"):
        try:
            (io / name).unlink()
        except FileNotFoundError:
            pass
    return out_dir / "report.md"


# ---------- approve / reject ----------

def _log_decision(home: Path, job_id: str, decision: str) -> None:
    with open(home / "decisions.log", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "job": job_id,
                             "decision": decision}) + "\n")


def _clear_flag_if_idle(home: Path) -> bool:
    if pending(home):
        return False
    try:
        flag_path(home).unlink()
    except FileNotFoundError:
        pass
    return True


def _move_readers(home: Path, lock_them: bool) -> None:
    readers = home / "readers"
    if not readers.is_dir():
        return
    if lock_them:
        (home / "locked_sessions").mkdir(parents=True, exist_ok=True)
    for p in readers.iterdir():
        if lock_them and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", p.name):
            (home / "locked_sessions" / p.name).touch()
        p.unlink()


def approve(home: Path, job_id: str) -> bool:
    """Move the report to approved/. Returns True if the flag was cleared."""
    check_job_id(job_id)
    with locked(home):
        src = home / "inbox" / job_id
        if not src.is_dir():
            raise RuntimeError("no pending report with that id")
        dst = home / "approved" / job_id
        if dst.exists():
            raise RuntimeError("that job was already approved")
        (home / "approved").mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        set_status(home, job_id, "approved")
        _log_decision(home, job_id, "approved")
        cleared = _clear_flag_if_idle(home)
        if cleared:
            _move_readers(home, lock_them=False)
        return cleared


def reject(home: Path, job_id: str) -> bool:
    """Delete the pending report and lock every session that read a pending report.

    Returns True if the flag was cleared.
    """
    check_job_id(job_id)
    with locked(home):
        src = home / "inbox" / job_id
        if not src.is_dir():
            raise RuntimeError("no pending report with that id")
        shutil.rmtree(src)
        set_status(home, job_id, "rejected")
        _log_decision(home, job_id, "rejected")
        _move_readers(home, lock_them=True)
        return _clear_flag_if_idle(home)
