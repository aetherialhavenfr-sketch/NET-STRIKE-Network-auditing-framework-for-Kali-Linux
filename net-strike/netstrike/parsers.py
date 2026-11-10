"""Parsers for tool output. Everything here is pure Python and unit-tested without the tools."""

from __future__ import annotations

import re
import socket
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

from .models import TrafficSummary

# --------------------------------------------------------------------------- ports


def count_ports(spec: str) -> int:
    """Number of ports in a spec like '1-1024,3306,8000-8100'."""
    total = 0
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            total += int(b) - int(a) + 1
        else:
            total += 1
    return total


def validate_port_spec(spec: str) -> str:
    spec = spec.replace(" ", "")
    if not re.fullmatch(r"\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*", spec):
        raise ValueError(f"invalid port specification: {spec!r} (use e.g. 22,80,443 or 1-1024)")
    for part in spec.split(","):
        nums = [int(x) for x in part.split("-")]
        if any(n < 1 or n > 65535 for n in nums) or (len(nums) == 2 and nums[0] > nums[1]):
            raise ValueError(f"port out of range in {part!r}")
    return spec


def port_list(ports: list[int]) -> str:
    return ",".join(str(p) for p in sorted(set(ports)))


# --------------------------------------------------------------------------- nmap XML


def parse_nmap_xml(path) -> list[dict]:
    """Parse an nmap -oX file into plain dicts. Returns [] for missing/invalid/empty files."""
    try:
        root = ET.parse(str(path)).getroot()
    except (ET.ParseError, OSError, FileNotFoundError):
        return []

    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        ip = mac = vendor = ""
        for a in h.findall("address"):
            kind = a.get("addrtype")
            if kind == "ipv4":
                ip = a.get("addr", "")
            elif kind == "mac":
                mac, vendor = a.get("addr", ""), a.get("vendor", "")
        if not ip:
            continue
        names = [n.get("name", "") for n in h.findall("hostnames/hostname") if n.get("name")]

        ports = []
        for p in h.findall("ports/port"):
            st, svc = p.find("state"), p.find("service")
            name = svc.get("name", "") if svc is not None else ""
            if svc is not None and svc.get("tunnel") == "ssl" and name and not name.endswith("s"):
                name = "ssl/" + name
            ports.append({
                "port": int(p.get("portid", "0")),
                "proto": p.get("protocol", "tcp"),
                "state": st.get("state", "") if st is not None else "",
                "service": name,
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
                "scripts": {s.get("id", ""): s.get("output", "") for s in p.findall("script")},
            })

        os_info = {}
        best = h.find("os/osmatch")
        if best is not None:
            os_info = {"name": best.get("name", ""), "accuracy": int(best.get("accuracy", "0") or 0)}
            cls = best.find("osclass")
            if cls is not None:
                os_info["type"] = cls.get("type", "")
                os_info["family"] = cls.get("osfamily", "")

        hosts.append({
            "ip": ip, "mac": mac, "vendor": vendor, "hostnames": names,
            "state": status.get("state", "up") if status is not None else "up",
            "ports": ports, "os": os_info,
            "hostscripts": {s.get("id", ""): s.get("output", "") for s in h.findall("hostscript/script")},
        })
    return hosts


# --------------------------------------------------------------------------- masscan / netdiscover

_MASSCAN_RE = re.compile(r"^open\s+(tcp|udp)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+\d+")


def parse_masscan_list(text: str) -> list[tuple[str, int, str]]:
    """Parse `masscan -oL` output into (ip, port, proto) tuples."""
    results = []
    for line in text.splitlines():
        m = _MASSCAN_RE.match(line.strip())
        if m:
            results.append((m.group(3), int(m.group(2)), m.group(1)))
    return results


_NETDISCOVER_RE = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+(\d+)\s+(\d+)\s*(.*)$")


def parse_netdiscover(text: str) -> list[dict]:
    """Parse `netdiscover -P -N` output lines: IP  MAC  count  len  vendor."""
    seen, out = set(), []
    for line in text.splitlines():
        m = _NETDISCOVER_RE.match(line)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            out.append({"ip": m.group(1), "mac": m.group(2).lower(), "vendor": m.group(5).strip()})
    return out


# --------------------------------------------------------------------------- TTL / device hints


def parse_ttl(text: str) -> int:
    m = re.search(r"ttl[=:\s]+(\d+)", text, re.IGNORECASE)
    return int(m.group(1)) if m else 0


def ttl_guess(ttl: int) -> str:
    if ttl <= 0:
        return ""
    if ttl <= 64:
        return "Linux / Unix / macOS (TTL~64)"
    if ttl <= 128:
        return "Windows (TTL~128)"
    return "Network device / Solaris (TTL~255)"


_VENDOR_HINTS = (
    ("vmware", "Virtual machine (VMware)"), ("virtualbox", "Virtual machine (VirtualBox)"),
    ("qemu", "Virtual machine (QEMU/KVM)"), ("xen", "Virtual machine (Xen)"),
    ("microsoft", "Microsoft / Hyper-V"), ("raspberry", "Raspberry Pi"),
    ("cisco", "Network device (Cisco)"), ("ubiquiti", "Network device (Ubiquiti)"),
    ("tp-link", "Network device (TP-Link)"), ("netgear", "Network device (Netgear)"),
    ("d-link", "Network device (D-Link)"), ("mikrotik", "Network device (MikroTik)"),
    ("juniper", "Network device (Juniper)"), ("apple", "Apple device"),
    ("hewlett", "HP / HPE device"), ("dell", "Dell device"), ("intel", "PC / server (Intel NIC)"),
    ("synology", "NAS (Synology)"), ("qnap", "NAS (QNAP)"),
)


def device_from_vendor(vendor: str) -> str:
    low = vendor.lower()
    for key, label in _VENDOR_HINTS:
        if key in low:
            return label
    return ""


# --------------------------------------------------------------------------- enum4linux-ng


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def summarize_enum4linux(data: dict) -> dict:
    """Condense enum4linux-ng JSON into a small, stable structure (defensive about missing keys)."""
    data = _as_dict(data)
    summary: dict = {"null_session": None, "smb1_enabled": None, "signing_required": None,
                     "os": "", "domain": "", "users": [], "groups": [], "shares": []}

    sessions = data.get("sessions_possible")
    if isinstance(sessions, bool):
        summary["null_session"] = sessions

    dialects = _as_dict(data.get("smb_dialects"))
    for key, val in dialects.items():
        k = str(key).lower().replace(" ", "")
        if k.startswith("smb1") and isinstance(val, bool) and "only" not in k:
            summary["smb1_enabled"] = bool(val) or bool(summary["smb1_enabled"])
        if "signing" in k and isinstance(val, bool):
            summary["signing_required"] = val
    if dialects.get("SMB1 only") is True:
        summary["smb1_enabled"] = True

    os_info = _as_dict(data.get("os_info"))
    summary["os"] = " ".join(str(v) for k, v in os_info.items()
                             if v and str(k).lower() in ("os", "os version", "os_version") and isinstance(v, (str, int, float)))
    domain = _as_dict(data.get("smb_domain_info")) or _as_dict(data.get("rpc_domain_info"))
    summary["domain"] = str(domain.get("Domain") or domain.get("NetBIOS domain name") or "")

    for _rid, u in _as_dict(data.get("users")).items():
        name = u.get("username") if isinstance(u, dict) else None
        if name:
            summary["users"].append(str(name))
    for _rid, g in _as_dict(data.get("groups")).items():
        name = g.get("groupname") if isinstance(g, dict) else None
        if name:
            summary["groups"].append(str(name))
    for name, s in _as_dict(data.get("shares")).items():
        access = _as_dict(s.get("access")) if isinstance(s, dict) else {}
        summary["shares"].append({
            "name": str(name),
            "comment": str(s.get("comment", "")) if isinstance(s, dict) else "",
            "mapping": str(access.get("mapping", "")),
            "listing": str(access.get("listing", "")),
            "writing": str(access.get("writing", "")),
        })
    return summary


# --------------------------------------------------------------------------- tshark traffic

TSHARK_FIELDS = [
    "frame.len", "frame.protocols", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.dstport", "udp.dstport", "dns.qry.name", "http.host",
    "tls.handshake.extensions_server_name", "arp.src.proto_ipv4", "arp.src.hw_mac",
]
TSHARK_FIELDS_MIN = ["frame.len", "frame.protocols", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
                     "tcp.dstport", "udp.dstport", "dns.qry.name", "http.host"]

_BASE_PROTOS = {"eth", "ethertype", "ip", "ipv6", "frame", "sll", "vlan", "raw", "null", "loop", "data", "llc"}
CLEARTEXT = {
    "ftp": "FTP", "telnet": "Telnet", "http": "HTTP", "pop": "POP3", "imap": "IMAP", "smtp": "SMTP",
    "snmp": "SNMP v1/v2c", "tftp": "TFTP", "nntp": "NNTP", "rlogin": "rlogin", "ldap": "LDAP",
}


def _service_name(port: int, proto: str) -> str:
    try:
        return socket.getservbyport(port, proto)
    except (OSError, OverflowError):
        return ""


class TrafficAggregator:
    """Aggregates `tshark -T fields` output line by line (constant memory)."""

    def __init__(self, fields: list[str] | None = None):
        self.fields = fields or TSHARK_FIELDS
        self.idx = {f: i for i, f in enumerate(self.fields)}
        self.packets = 0
        self.bytes = 0
        self.protos: Counter = Counter()
        self.talker_bytes: Counter = Counter()
        self.talker_pkts: Counter = Counter()
        self.conv_bytes: Counter = Counter()
        self.conv_pkts: Counter = Counter()
        self.ports: Counter = Counter()
        self.dns: Counter = Counter()
        self.http: Counter = Counter()
        self.sni: Counter = Counter()
        self.arp: dict = defaultdict(set)

    def _get(self, cols: list[str], name: str) -> str:
        i = self.idx.get(name)
        return cols[i].strip() if i is not None and i < len(cols) else ""

    def feed(self, line: str) -> None:
        if not line.strip():
            return
        cols = line.split("\t")
        try:
            length = int(self._get(cols, "frame.len") or 0)
        except ValueError:
            length = 0
        self.packets += 1
        self.bytes += length

        for proto in {p for p in self._get(cols, "frame.protocols").split(":") if p and p not in _BASE_PROTOS}:
            self.protos[proto] += 1

        src = self._get(cols, "ip.src") or self._get(cols, "ipv6.src")
        dst = self._get(cols, "ip.dst") or self._get(cols, "ipv6.dst")
        if src:
            self.talker_bytes[src] += length
            self.talker_pkts[src] += 1
        if src and dst:
            pair = tuple(sorted((src, dst)))
            self.conv_bytes[pair] += length
            self.conv_pkts[pair] += 1

        tcp, udp = self._get(cols, "tcp.dstport"), self._get(cols, "udp.dstport")
        if tcp.isdigit():
            self.ports[(int(tcp), "tcp")] += 1
        elif udp.isdigit():
            self.ports[(int(udp), "udp")] += 1

        for name, counter in (("dns.qry.name", self.dns), ("http.host", self.http),
                              ("tls.handshake.extensions_server_name", self.sni)):
            val = self._get(cols, name)
            if val:
                counter[val[:120]] += 1

        arp_ip, arp_mac = self._get(cols, "arp.src.proto_ipv4"), self._get(cols, "arp.src.hw_mac")
        if arp_ip and arp_mac:
            self.arp[arp_ip].add(arp_mac.lower())

    def summary(self, top: int = 10) -> TrafficSummary:
        ts = TrafficSummary()
        ts.packets, ts.bytes = self.packets, self.bytes
        ts.protocols = [{"name": n, "packets": c} for n, c in self.protos.most_common(15)]
        ts.top_talkers = [{"ip": ip, "bytes": b, "packets": self.talker_pkts[ip]}
                          for ip, b in self.talker_bytes.most_common(top)]
        ts.conversations = [{"a": a, "b": b, "packets": self.conv_pkts[(a, b)], "bytes": nbytes}
                            for (a, b), nbytes in self.conv_bytes.most_common(top)]
        ts.top_ports = [{"port": p, "proto": pr, "service": _service_name(p, pr), "packets": c}
                        for (p, pr), c in self.ports.most_common(top)]
        ts.dns_queries = [{"name": n, "count": c} for n, c in self.dns.most_common(15)]
        ts.http_hosts = [{"name": n, "count": c} for n, c in self.http.most_common(15)]
        ts.tls_sni = [{"name": n, "count": c} for n, c in self.sni.most_common(15)]
        ts.cleartext = [{"protocol": label, "packets": self.protos[key]}
                        for key, label in CLEARTEXT.items() if self.protos.get(key)]
        ts.arp_anomalies = [{"ip": ip, "macs": sorted(macs)} for ip, macs in sorted(self.arp.items()) if len(macs) > 1]
        return ts
