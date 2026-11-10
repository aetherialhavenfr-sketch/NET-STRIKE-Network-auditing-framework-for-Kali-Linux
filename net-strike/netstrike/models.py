"""Data models shared by every module."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def ip_sort_key(ip: str):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


@dataclass
class ScanOptions:
    targets: list[str] = field(default_factory=list)
    iface: str = ""
    profile: str = "standard"
    modules: list[str] = field(default_factory=list)
    ports: str = ""
    rate: int = 1000
    traffic_duration: int = 20
    threads: int = 3
    timing: int = 4
    scripts: bool = True
    out_dir: str = "reports"
    formats: list[str] = field(default_factory=lambda: ["html", "json"])
    pcap: str = ""


@dataclass
class PortInfo:
    port: int
    proto: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    scripts: dict = field(default_factory=dict)
    sources: list = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.port}/{self.proto}"

    @property
    def label(self) -> str:
        parts = [self.service, self.product, self.version]
        text = " ".join(p for p in parts if p)
        return f"{text} ({self.extrainfo})" if self.extrainfo else text

    def merge(self, other: "PortInfo") -> None:
        for attr in ("service", "product", "version", "extrainfo"):
            val = getattr(other, attr)
            if val:
                setattr(self, attr, val)
        if other.state:
            self.state = other.state
        self.scripts.update(other.scripts)
        for s in other.sources:
            if s not in self.sources:
                self.sources.append(s)

    def to_dict(self) -> dict:
        return {
            "port": self.port, "proto": self.proto, "state": self.state, "service": self.service,
            "product": self.product, "version": self.version, "extrainfo": self.extrainfo,
            "scripts": dict(self.scripts), "sources": list(self.sources),
        }


@dataclass
class HostInfo:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    os_guess: str = ""
    os_accuracy: int = 0
    device_type: str = ""
    ttl: int = 0
    status: str = "up"
    ports: dict = field(default_factory=dict)       # "80/tcp" -> PortInfo
    sources: list = field(default_factory=list)
    smb: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    def add_port(self, p: PortInfo) -> PortInfo:
        existing = self.ports.get(p.key)
        if existing:
            existing.merge(p)
            return existing
        self.ports[p.key] = p
        return p

    def add_source(self, src: str) -> None:
        if src and src not in self.sources:
            self.sources.append(src)

    def open_ports(self) -> list[PortInfo]:
        return sorted((p for p in self.ports.values() if p.state.startswith("open")),
                      key=lambda p: (p.proto, p.port))

    def has_port(self, port: int, proto: str = "tcp") -> bool:
        p = self.ports.get(f"{port}/{proto}")
        return bool(p and p.state.startswith("open"))

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "mac": self.mac, "vendor": self.vendor, "hostname": self.hostname,
            "os_guess": self.os_guess, "os_accuracy": self.os_accuracy, "device_type": self.device_type,
            "ttl": self.ttl, "status": self.status, "sources": list(self.sources),
            "ports": [p.to_dict() for p in sorted(self.ports.values(), key=lambda x: (x.proto, x.port))],
            "smb": self.smb, "notes": list(self.notes),
        }


@dataclass
class Finding:
    severity: str
    title: str
    detail: str = ""
    host: str = ""
    port: str = ""
    recommendation: str = ""
    source: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity, "title": self.title, "detail": self.detail, "host": self.host,
            "port": self.port, "recommendation": self.recommendation, "source": self.source,
        }


@dataclass
class TrafficSummary:
    source: str = ""                 # "live" | "pcap"
    pcap_file: str = ""
    interface: str = ""
    capture_filter: str = ""
    duration: int = 0
    packets: int = 0
    bytes: int = 0
    protocols: list = field(default_factory=list)       # [{"name":..., "packets":...}]
    top_talkers: list = field(default_factory=list)     # [{"ip":..., "bytes":..., "packets":...}]
    conversations: list = field(default_factory=list)   # [{"a":..., "b":..., "packets":..., "bytes":...}]
    top_ports: list = field(default_factory=list)       # [{"port":..., "proto":..., "service":..., "packets":...}]
    dns_queries: list = field(default_factory=list)
    http_hosts: list = field(default_factory=list)
    tls_sni: list = field(default_factory=list)
    cleartext: list = field(default_factory=list)       # [{"protocol":..., "packets":...}]
    arp_anomalies: list = field(default_factory=list)   # [{"ip":..., "macs":[...]}]
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class ScanSession:
    id: str
    started: str
    targets: list = field(default_factory=list)
    interface: str = ""
    profile: str = ""
    modules: list = field(default_factory=list)
    operator: str = ""
    hostname: str = ""
    authorization: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)
    tools: dict = field(default_factory=dict)
    finished: str = ""
    hosts: dict = field(default_factory=dict)
    traffic: TrafficSummary | None = None
    findings: list = field(default_factory=list)
    phases: list = field(default_factory=list)
    events: list = field(default_factory=list)
    artifacts: list = field(default_factory=list)
    duration: float = 0.0

    MAX_EVENTS = 3000

    def host(self, ip: str) -> HostInfo:
        if ip not in self.hosts:
            self.hosts[ip] = HostInfo(ip=ip)
        return self.hosts[ip]

    def add_event(self, level: str, source: str, msg: str) -> None:
        if level == "out" or len(self.events) >= self.MAX_EVENTS:
            return
        self.events.append({"time": now_iso(), "level": level, "source": source, "message": msg})

    def add_finding(self, f: Finding) -> None:
        key = (f.host, f.port, f.title)
        if any((x.host, x.port, x.title) == key for x in self.findings):
            return
        self.findings.append(f)

    def sorted_hosts(self) -> list[HostInfo]:
        return [self.hosts[k] for k in sorted(self.hosts, key=ip_sort_key)]

    def summary(self) -> dict:
        sev = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        ports = sum(len(h.open_ports()) for h in self.hosts.values())
        services = sum(1 for h in self.hosts.values() for p in h.open_ports() if p.service)
        return {
            "hosts_up": len(self.hosts), "open_ports": ports, "services_identified": services,
            "smb_hosts": sum(1 for h in self.hosts.values() if h.smb),
            "findings": sev, "findings_total": len(self.findings),
            "packets_captured": self.traffic.packets if self.traffic else 0,
        }

    def to_dict(self) -> dict:
        return {
            "schema": "netstrike-report/1",
            "id": self.id, "started": self.started, "finished": self.finished,
            "duration_seconds": round(self.duration, 1),
            "targets": list(self.targets), "interface": self.interface, "profile": self.profile,
            "modules": list(self.modules), "operator": self.operator, "hostname": self.hostname,
            "authorization": self.authorization, "options": self.options, "tools": self.tools,
            "summary": self.summary(),
            "hosts": [h.to_dict() for h in self.sorted_hosts()],
            "traffic": self.traffic.to_dict() if self.traffic else None,
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda f: SEV_ORDER.get(f.severity, 9))],
            "phases": self.phases, "artifacts": self.artifacts, "events": self.events,
        }
