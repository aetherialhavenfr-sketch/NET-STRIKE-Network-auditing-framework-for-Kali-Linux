"""Port scanning: masscan for speed (root), nmap as fallback or when masscan is unavailable."""

from __future__ import annotations

from ..config import QUICK_PORTS
from ..context import Context, ModuleError, ModuleSkipped
from ..models import PortInfo
from ..parsers import count_ports, parse_masscan_list, parse_nmap_xml


def _all_loopback(ctx: Context) -> bool:
    return bool(ctx.networks) and all(n.is_loopback for n in ctx.networks)


def _record(ctx: Context, ip: str, port: PortInfo, source: str) -> None:
    host = ctx.add_host(ip, source=source)
    if host:
        port.sources = [source]
        host.add_port(port)


def _masscan(ctx: Context, targets_file, ports: str) -> bool:
    out = ctx.artifact("masscan.lst")
    cmd = ["masscan", "-iL", str(targets_file), "-p", ports, "--rate", str(ctx.opts.rate),
           "--wait", "3", "-oL", str(out)]
    if ctx.opts.iface:
        cmd += ["-e", ctx.opts.iface]
    with open(targets_file, encoding="utf-8") as fh:
        n_targets = sum(1 for _ in fh)
    eta = n_targets * count_ports(ports) / max(1, ctx.opts.rate)
    ctx.ui.info(f"masscan: ~{count_ports(ports):,} ports/target at {ctx.opts.rate} pps (rough floor {eta:,.0f}s)",
                "portscan")
    res = ctx.run(cmd, timeout=7200, source="masscan")
    if res.error or (res.returncode != 0 and not out.exists()):
        ctx.ui.warn(res.error or f"masscan exited with {res.returncode}", "portscan")
        return False
    try:
        text = out.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    count = 0
    for ip, port, proto in parse_masscan_list(text):
        _record(ctx, ip, PortInfo(port=port, proto=proto, state="open"), "masscan")
        count += 1
    ctx.ui.ok(f"masscan found {count} open port(s)", "portscan")
    return True


def _nmap(ctx: Context, targets_file, ports: str) -> None:
    xml = ctx.artifact("portscan.xml")
    cmd = ["nmap", "-Pn", "-n", f"-T{ctx.opts.timing}", "-p", ports, "--open", "--max-retries", "2",
           "--min-rate", str(ctx.opts.rate), "--stats-every", "5s", "-iL", str(targets_file), "-oX", str(xml)]
    if ctx.opts.iface:
        cmd += ["-e", ctx.opts.iface]
    res = ctx.run(cmd, timeout=7200, source="nmap")
    if res.error:
        raise ModuleError(res.error)
    if res.timed_out:
        ctx.ui.warn("nmap port scan timed out - using partial results", "portscan")
    entries = parse_nmap_xml(xml)
    if not entries and not res.cancelled:
        ctx.ui.warn("nmap produced no parsable XML result (no open ports, or the scan failed)", "portscan")
    for entry in entries:
        for p in entry["ports"]:
            if not p["state"].startswith("open"):
                continue
            _record(ctx, entry["ip"], PortInfo(
                port=p["port"], proto=p["proto"], state="open", service=p["service"], product=p["product"],
                version=p["version"], extrainfo=p["extrainfo"]), "nmap")


def run(ctx: Context) -> tuple[str, str]:
    if not (ctx.has("masscan") or ctx.has("nmap")):
        raise ModuleSkipped("neither masscan nor nmap is installed")
    if ctx.no_live_hosts:
        raise ModuleSkipped("no live hosts (run without discovery to scan blindly)")

    ports = ctx.opts.ports or QUICK_PORTS
    targets = ctx.scan_targets()
    targets_file = ctx.write_target_file("portscan-targets.txt", targets)
    ctx.ui.set_phase("portscan", "running", f"{len(targets)} target(s), {count_ports(ports):,} ports")

    done = False
    if ctx.has("masscan") and ctx.is_root and not _all_loopback(ctx):
        ctx.ui.set_phase("portscan", "running", "masscan sweep")
        done = _masscan(ctx, targets_file, ports)
    elif ctx.has("masscan"):
        why = "needs root" if not ctx.is_root else "cannot scan loopback"
        ctx.ui.warn(f"masscan {why} - falling back to nmap", "portscan")

    if not done:
        if not ctx.has("nmap"):
            raise ModuleError("masscan failed and nmap is not available")
        ctx.ui.set_phase("portscan", "running", "nmap port scan")
        _nmap(ctx, targets_file, ports)

    total = sum(len(h.open_ports()) for h in ctx.session.hosts.values())
    ctx.ui.set_stat("hosts", len(ctx.session.hosts))
    ctx.ui.set_stat("ports", total)
    for ip in ctx.live_hosts():
        ports_open = ctx.session.hosts[ip].open_ports()
        if ports_open:
            ctx.ui.ok(f"{ip}: " + ",".join(f"{p.port}/{p.proto}" for p in ports_open[:12])
                      + (f" (+{len(ports_open) - 12})" if len(ports_open) > 12 else ""), "portscan")
    if total == 0:
        return "warn", "no open ports found"
    return "done", f"{total} open port(s) on {sum(1 for h in ctx.session.hosts.values() if h.open_ports())} host(s)"
