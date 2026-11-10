"""Scope enforcement: NET-STRIKE only scans authorized networks and lab environments.

Policy
------
* Private / lab address space (RFC 1918, loopback, link-local) is allowed by default.
* Anything else must be listed explicitly in the scope file (default ~/.netstrike/scope.txt).
* A single run may not cover more than a /16 (65,536 addresses).
* The operator must confirm authorization before every run and each run is written to an audit log.
* Every host found during a run is re-checked against the scope before any tool touches it.
"""

from __future__ import annotations

import getpass
import ipaddress
import json
import os
import re
import socket
from pathlib import Path

from .config import AUDIT_LOG, AUTH_PHRASE, CONFIG_DIR, MAX_TARGET_ADDRESSES
from .models import now_iso

PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
)]
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


class ScopeError(Exception):
    """Raised when a target is invalid or outside the authorized scope."""


def parse_target(raw: str) -> list[ipaddress.IPv4Network]:
    """Parse a single target (IP, CIDR, range, or hostname) into IPv4 networks."""
    raw = raw.strip()
    if not raw:
        raise ScopeError("empty target")

    if ":" in raw and "/" not in raw and raw.count(":") > 1:
        raise ScopeError(f"{raw}: IPv6 targets are not supported")

    try:
        if "/" in raw:
            try:
                net = ipaddress.ip_network(raw, strict=True)
            except ValueError:
                fixed = ipaddress.ip_network(raw, strict=False)
                raise ScopeError(f"{raw}: host bits set - did you mean {fixed}?") from None
            nets = [net]
        elif "-" in raw and re.match(r"^\d+\.\d+\.\d+\.\d+-\S+$", raw):
            start_s, end_s = raw.split("-", 1)
            start = ipaddress.ip_address(start_s)
            if end_s.isdigit():                          # 192.168.1.10-50
                end = ipaddress.ip_address(".".join(start_s.split(".")[:3] + [end_s]))
            else:
                end = ipaddress.ip_address(end_s)
            if start.version != 4 or end.version != 4:
                raise ScopeError(f"{raw}: only IPv4 ranges are supported")
            if end < start:
                raise ScopeError(f"{raw}: range end is before range start")
            nets = list(ipaddress.summarize_address_range(start, end))
        else:
            try:
                nets = [ipaddress.ip_network(ipaddress.ip_address(raw))]
            except ValueError:
                nets = _resolve_hostname(raw)
    except ValueError as exc:
        raise ScopeError(f"{raw}: {exc}") from None

    for n in nets:
        if n.version != 4:
            raise ScopeError(f"{raw}: IPv6 targets are not supported")
        if n.network_address.is_unspecified or n.network_address.is_multicast or n.network_address.is_reserved:
            raise ScopeError(f"{raw}: unspecified, multicast and reserved ranges are not valid targets")
        if str(n.broadcast_address) == "255.255.255.255":
            raise ScopeError(f"{raw}: broadcast address is not a valid target")
    return nets


def _resolve_hostname(name: str) -> list[ipaddress.IPv4Network]:
    if not _HOST_RE.match(name):
        raise ScopeError(f"{name}: not a valid IP, CIDR, range or hostname")
    try:
        infos = socket.getaddrinfo(name, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError(f"{name}: cannot resolve hostname ({exc.strerror or exc})") from None
    ips = sorted({i[4][0] for i in infos})
    if not ips:
        raise ScopeError(f"{name}: hostname did not resolve")
    return [ipaddress.ip_network(ip) for ip in ips]


def load_scope_file(path: Path | str) -> list[ipaddress.IPv4Network]:
    """Read authorized networks from a scope file (one IP/CIDR/range per line, # comments)."""
    p = Path(path).expanduser()
    if not p.is_file():
        return []
    nets: list[ipaddress.IPv4Network] = []
    for lineno, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            nets.extend(parse_target(line))
        except ScopeError as exc:
            raise ScopeError(f"scope file {p}:{lineno}: {exc}") from None
    return nets


class Scope:
    def __init__(self, authorized: list[ipaddress.IPv4Network] | None = None):
        self.authorized = list(authorized or [])
        self.networks: list[ipaddress.IPv4Network] = []   # validated run targets

    @classmethod
    def from_file(cls, path: Path | str | None) -> "Scope":
        return cls(load_scope_file(path) if path else [])

    def _allowed(self, net: ipaddress.IPv4Network) -> bool:
        return any(net.subnet_of(p) for p in PRIVATE_NETS + self.authorized)

    def validate(self, raw_targets: list[str]) -> list[ipaddress.IPv4Network]:
        if not raw_targets:
            raise ScopeError("no targets given")
        nets: list[ipaddress.IPv4Network] = []
        problems: list[str] = []
        for raw in raw_targets:
            try:
                nets.extend(parse_target(raw))
            except ScopeError as exc:
                problems.append(str(exc))
        if problems:
            raise ScopeError("\n".join(problems))

        nets = list(ipaddress.collapse_addresses(nets))
        for n in nets:
            if not self._allowed(n):
                problems.append(
                    f"{n}: outside authorized scope (private/lab ranges only unless listed in the scope file)")
        total = sum(n.num_addresses for n in nets)
        if total > MAX_TARGET_ADDRESSES:
            problems.append(f"target space too large ({total:,} addresses, maximum {MAX_TARGET_ADDRESSES:,} = /16)")
        if problems:
            raise ScopeError("\n".join(problems))
        self.networks = nets
        return nets

    def contains(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self.networks)


def validate_iface(name: str) -> str:
    """Interface names go straight into tool command lines - validate strictly."""
    if not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,32}", name or ""):
        raise ScopeError(f"invalid interface name: {name!r}")
    if os.path.isdir("/sys/class/net") and not os.path.exists(f"/sys/class/net/{name}"):
        raise ScopeError(f"interface not found: {name}")
    return name


def default_iface() -> str:
    """First non-loopback interface that is up (best effort)."""
    base = "/sys/class/net"
    try:
        for name in sorted(os.listdir(base)):
            if name == "lo":
                continue
            try:
                with open(f"{base}/{name}/operstate", encoding="utf-8") as fh:
                    if fh.read().strip() in ("up", "unknown"):
                        return name
            except OSError:
                continue
    except OSError:
        pass
    return ""


def write_audit(event: dict) -> None:
    """Append a JSON line to the audit log (created 0600)."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        entry = {"time": now_iso(), "user": _user(), **event}
        fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        _chown_to_sudo_user(CONFIG_DIR)
        _chown_to_sudo_user(AUDIT_LOG)
    except OSError:
        pass  # auditing must never crash the run


def _user() -> str:
    try:
        return os.environ.get("SUDO_USER") or getpass.getuser()
    except Exception:  # noqa: BLE001 - getpass can raise several things
        return "unknown"


def _chown_to_sudo_user(path: Path) -> None:
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid and hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            os.chown(path, int(uid), int(gid))
        except (OSError, ValueError):
            pass


def confirm_authorization(ui, networks, accepted: bool) -> dict:
    """Require explicit operator confirmation. Returns the authorization record."""
    targets = ", ".join(str(n) for n in networks) or "offline analysis"
    if accepted:
        return {"method": "flag", "phrase": AUTH_PHRASE, "targets": targets}

    if not ui.interactive():
        raise ScopeError(
            "authorization not confirmed. Re-run interactively, or pass --i-am-authorized "
            "to confirm you have written permission to audit these targets.")

    ui.notice_box("AUTHORIZATION REQUIRED", [
        f"Targets : {targets}",
        "",
        "NET-STRIKE sends active probes (ARP, SYN, service and SMB queries).",
        "Only continue if you own these systems or hold WRITTEN permission to test them.",
        "Unauthorized scanning may be illegal.",
    ])
    answer = ui.ask(f"Type '{AUTH_PHRASE}' to continue")
    if answer.strip() != AUTH_PHRASE:
        raise ScopeError("authorization not confirmed - aborting")
    return {"method": "interactive", "phrase": AUTH_PHRASE, "targets": targets}
