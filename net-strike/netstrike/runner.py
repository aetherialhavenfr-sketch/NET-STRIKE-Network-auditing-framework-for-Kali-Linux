"""Safe subprocess execution and external tool detection.

Commands are always passed as argument lists (never through a shell), so user-supplied
values can never be interpreted as shell syntax.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .config import TOOLS


@dataclass
class CmdResult:
    cmd: list
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False
    cancelled: bool = False
    error: str = ""
    lines: list = field(default_factory=list, repr=False)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.cancelled and not self.error

    @property
    def combined(self) -> str:
        return (self.stdout + "\n" + self.stderr).strip()


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def find_tool(name: str) -> str | None:
    return shutil.which(name)


def tool_version(name: str, path: str) -> str:
    args = TOOLS.get(name, {}).get("version_args", ["--version"])
    try:
        res = run_command([path, *args], timeout=8)
    except Exception:  # noqa: BLE001
        return ""
    for line in res.combined.splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        if name == "netdiscover" and "netdiscover" not in low:
            continue
        return line[:90]
    return ""


def detect_tools() -> dict:
    """Return {tool: {available, path, version, role, needs_root}}."""
    found = {}
    for name, meta in TOOLS.items():
        path = find_tool(name)
        found[name] = {
            "available": bool(path),
            "path": path or "",
            "version": tool_version(name, path) if path else "",
            "role": meta["role"],
            "needs_root": meta["root"],
        }
    return found


def _terminate(proc: subprocess.Popen) -> None:
    """Terminate the whole process group, escalating to SIGKILL if needed."""
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        return
    for sig, wait in ((signal.SIGTERM, 4.0), (signal.SIGKILL, 2.0)):
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            return
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def run_command(
    cmd: list[str],
    timeout: float | None = None,
    on_line: Callable[[str, str], None] | None = None,
    cancel: threading.Event | None = None,
    store: bool = True,
    env: dict | None = None,
) -> CmdResult:
    """Run *cmd*, streaming output lines to *on_line(stream, line)* while it executes."""
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
            text=True, errors="replace", bufsize=1, start_new_session=True, env=env,
        )
    except FileNotFoundError:
        return CmdResult(cmd, 127, error=f"command not found: {cmd[0]}")
    except PermissionError:
        return CmdResult(cmd, 126, error=f"permission denied: {cmd[0]}")
    except OSError as exc:
        return CmdResult(cmd, 1, error=f"cannot start {cmd[0]}: {exc}")

    out_buf: list[str] = []
    err_buf: list[str] = []

    def pump(stream, name: str, buf: list[str]) -> None:
        try:
            for raw in iter(stream.readline, ""):
                line = raw.rstrip("\r\n")
                if store:
                    buf.append(line)
                if on_line is not None:
                    try:
                        on_line(name, line)
                    except Exception:  # noqa: BLE001 - a UI callback must never kill the reader
                        pass
        except (ValueError, OSError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    threads = [
        threading.Thread(target=pump, args=(proc.stdout, "out", out_buf), daemon=True),
        threading.Thread(target=pump, args=(proc.stderr, "err", err_buf), daemon=True),
    ]
    for t in threads:
        t.start()

    timed_out = cancelled = False
    try:
        while True:
            try:
                proc.wait(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                pass
            if cancel is not None and cancel.is_set():
                cancelled = True
                _terminate(proc)
                break
            if timeout and (time.monotonic() - started) > timeout:
                timed_out = True
                _terminate(proc)
                break
    except BaseException:  # includes KeyboardInterrupt - never leave children running
        _terminate(proc)
        raise
    finally:
        for t in threads:
            t.join(timeout=2)

    return CmdResult(
        cmd=cmd, returncode=proc.returncode if proc.returncode is not None else -1,
        stdout="\n".join(out_buf), stderr="\n".join(err_buf),
        duration=time.monotonic() - started, timed_out=timed_out, cancelled=cancelled,
    )


def fix_owner(path: Path) -> None:
    """When started via sudo, hand output files back to the invoking user."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not (uid and gid and is_root()):
        return
    try:
        targets = [path]
        if path.is_dir():
            targets += list(path.rglob("*"))
        for p in targets:
            os.chown(p, int(uid), int(gid))
    except (OSError, ValueError):
        pass


def write_private(path: Path, text: str) -> None:
    """Write a report file readable only by its owner (reports contain sensitive data)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
