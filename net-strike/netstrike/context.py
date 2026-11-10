"""Execution context shared by all modules (kept separate from the engine to avoid import cycles)."""

from __future__ import annotations

import ipaddress
import shlex
import threading
from pathlib import Path

from .models import HostInfo, ScanOptions, ScanSession, ip_sort_key
from .runner import CmdResult, is_root, run_command
from .ui import UI


class ModuleSkipped(Exception):
    """The module cannot run (missing tool/privilege/prerequisite). Not an error."""


class ModuleError(Exception):
    """The module ran but failed."""


class Context:
    def __init__(self, session: ScanSession, ui: UI, opts: ScanOptions, networks: list,
                 workdir: Path, tools: dict):
        self.session = session
        self.ui = ui
        self.opts = opts
        self.networks = list(networks)
        self.workdir = workdir
        self.tools = tools
        self.cancel = threading.Event()
        self.is_root = is_root()
        self.no_live_hosts = False           # set by discovery when nothing answered
        self._warned_oos: set[str] = set()
        self._lock = threading.RLock()

    # -- environment ------------------------------------------------------------
    def has(self, tool: str) -> bool:
        return bool(self.tools.get(tool, {}).get("available"))

    def in_scope(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self.networks)

    def artifact(self, name: str) -> Path:
        return self.workdir / name

    # -- command execution -------------------------------------------------------
    def run(self, cmd: list[str], timeout: float | None = None, source: str | None = None,
            quiet: bool = False) -> CmdResult:
        """Run a tool, mirroring its command line and output into the live log."""
        src = source or Path(cmd[0]).name
        self.ui.log("cmd", " ".join(shlex.quote(c) for c in cmd), src)

        def on_line(stream: str, line: str) -> None:
            if line.strip() and not quiet:
                self.ui.log("out", line, src)

        return run_command(cmd, timeout=timeout, on_line=on_line, cancel=self.cancel)

    # -- host bookkeeping ----------------------------------------------------------
    def add_host(self, ip: str, source: str = "", mac: str = "", vendor: str = "",
                 hostname: str = "") -> HostInfo | None:
        """Register a host, refusing anything outside the authorized scope."""
        with self._lock:
            if self.networks and not self.in_scope(ip):
                if ip not in self._warned_oos:
                    self._warned_oos.add(ip)
                    self.ui.warn(f"ignoring out-of-scope host {ip}", "scope")
                return None
            if not self.networks:
                return None
            host = self.session.host(ip)
            if mac and not host.mac:
                host.mac = mac.lower()
            if vendor and not host.vendor:
                host.vendor = vendor
            if hostname and not host.hostname:
                host.hostname = hostname
            host.add_source(source)
            return host

    def live_hosts(self) -> list[str]:
        return sorted(self.session.hosts, key=ip_sort_key)

    def write_target_file(self, name: str, entries: list[str]) -> Path:
        path = self.artifact(name)
        path.write_text("\n".join(entries) + "\n", encoding="utf-8")
        return path

    def scan_targets(self) -> list[str]:
        """Known live hosts if discovery ran, otherwise the authorized target networks."""
        hosts = self.live_hosts()
        return hosts if hosts else [str(n) for n in self.networks]
