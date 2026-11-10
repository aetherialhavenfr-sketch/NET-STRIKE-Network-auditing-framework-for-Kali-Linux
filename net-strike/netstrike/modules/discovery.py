"""Network discovery: netdiscover (ARP) and nmap ping sweep, restricted to the authorized scope."""

from __future__ import annotations

from ..context import Context, ModuleError, ModuleSkipped
from ..parsers import parse_netdiscover, parse_nmap_xml


def _netdiscover(ctx: Context) -> int:
    """ARP sweep. netdiscover only understands /8, /16, /24 ranges, so only exact matches are used -
    widening a range would probe addresses outside the authorized scope."""
    if not ctx.has("netdiscover"):
        return 0
    if not ctx.is_root:
        ctx.ui.warn("netdiscover needs root - skipping ARP sweep", "discovery")
        return 0

    found = 0
    for net in ctx.networks:
        if net.prefixlen not in (16, 24):
            ctx.ui.info(f"netdiscover supports /16 and /24 only - using nmap for {net}", "discovery")
            continue
        cmd = ["netdiscover", "-r", str(net), "-P", "-N", "-c", "2", "-f"]
        if ctx.opts.iface:
            cmd[1:1] = ["-i", ctx.opts.iface]
        res = ctx.run(cmd, timeout=900 if net.prefixlen == 16 else 150, source="netdiscover")
        if res.error:
            ctx.ui.warn(res.error, "discovery")
            continue
        for entry in parse_netdiscover(res.stdout):
            if ctx.add_host(entry["ip"], source="netdiscover", mac=entry["mac"], vendor=entry["vendor"]):
                found += 1
        ctx.ui.set_stat("hosts", len(ctx.session.hosts))
    return found


def _nmap_sweep(ctx: Context) -> int:
    if not ctx.has("nmap"):
        return 0
    xml = ctx.artifact("discovery.xml")
    cmd = ["nmap", "-sn", f"-T{ctx.opts.timing}", "-PS22,80,443,445,3389,8080",
           "--stats-every", "5s", "-oX", str(xml)]
    if ctx.opts.iface:
        cmd += ["-e", ctx.opts.iface]
    cmd += [str(n) for n in ctx.networks]
    res = ctx.run(cmd, timeout=3600, source="nmap")
    if res.error:
        raise ModuleError(res.error)
    if res.timed_out:
        ctx.ui.warn("nmap sweep timed out - using partial results", "discovery")
    if res.cancelled:
        return 0

    entries = parse_nmap_xml(xml)
    if not entries:
        ctx.ui.info("nmap sweep reported no live hosts", "discovery")
    found = 0
    for entry in entries:
        if entry["state"] != "up":
            continue
        host = ctx.add_host(entry["ip"], source="nmap-sweep", mac=entry["mac"], vendor=entry["vendor"],
                            hostname=entry["hostnames"][0] if entry["hostnames"] else "")
        if host:
            found += 1
    return found


def run(ctx: Context) -> tuple[str, str]:
    if not (ctx.has("netdiscover") or ctx.has("nmap")):
        raise ModuleSkipped("neither netdiscover nor nmap is installed")
    if not ctx.networks:
        raise ModuleSkipped("no target networks")

    ctx.ui.set_phase("discovery", "running", "ARP sweep" if ctx.has("netdiscover") else "ping sweep")
    _netdiscover(ctx)
    ctx.ui.set_phase("discovery", "running", "nmap host sweep")
    _nmap_sweep(ctx)

    total = len(ctx.session.hosts)
    ctx.ui.set_stat("hosts", total)
    for ip in ctx.live_hosts():
        h = ctx.session.hosts[ip]
        ctx.ui.ok(f"host up: {ip}" + (f"  {h.mac}" if h.mac else "") + (f"  ({h.vendor})" if h.vendor else ""),
                  "discovery")
    if total == 0:
        ctx.no_live_hosts = True
        ctx.ui.warn("no live hosts found - dependent phases will be skipped", "discovery")
        return "warn", "no live hosts"
    return "done", f"{total} host(s) up"
