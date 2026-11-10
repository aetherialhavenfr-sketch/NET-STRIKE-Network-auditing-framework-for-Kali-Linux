"""Host identification: MAC vendor hints, TTL fingerprinting and nmap OS detection."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from ..context import Context, ModuleSkipped
from ..parsers import device_from_vendor, parse_nmap_xml, parse_ttl, ttl_guess
from ..runner import find_tool


def _ping_ttl(ctx: Context, ip: str) -> tuple[str, int]:
    if not find_tool("ping") or ctx.cancel.is_set():
        return ip, 0
    res = ctx.run(["ping", "-c", "1", "-W", "1", ip], timeout=5, source="ping", quiet=True)
    return ip, parse_ttl(res.stdout)


def _os_detection(ctx: Context, hosts: list[str]) -> int:
    xml = ctx.artifact("hostid-os.xml")
    targets = ctx.write_target_file("hostid-targets.txt", hosts)
    cmd = ["nmap", "-O", "--osscan-guess", "-Pn", "-n", f"-T{ctx.opts.timing}", "--max-os-tries", "2",
           "--stats-every", "5s", "-iL", str(targets), "-oX", str(xml)]
    res = ctx.run(cmd, timeout=3600, source="nmap")
    if res.error:
        ctx.ui.warn(res.error, "hostid")
        return 0
    identified = 0
    for entry in parse_nmap_xml(xml):
        host = ctx.session.hosts.get(entry["ip"])
        if not host:
            continue
        if entry["os"].get("name"):
            host.os_guess = entry["os"]["name"]
            host.os_accuracy = entry["os"].get("accuracy", 0)
            host.device_type = entry["os"].get("type", "") or host.device_type
            host.add_source("nmap-os")
            identified += 1
        if entry["hostnames"] and not host.hostname:
            host.hostname = entry["hostnames"][0]
    return identified


def run(ctx: Context) -> tuple[str, str]:
    hosts = ctx.live_hosts()
    if not hosts:
        raise ModuleSkipped("no live hosts to identify")

    # 1. vendor hints from MAC OUI
    for ip in hosts:
        h = ctx.session.hosts[ip]
        hint = device_from_vendor(h.vendor)
        if hint and not h.device_type:
            h.device_type = hint

    # 2. TTL fingerprint (cheap, works without root)
    ctx.ui.set_phase("hostid", "running", f"TTL fingerprint ({len(hosts)} hosts)")
    with ThreadPoolExecutor(max_workers=min(16, len(hosts))) as pool:
        for ip, ttl in pool.map(lambda x: _ping_ttl(ctx, x), hosts):
            if ttl:
                h = ctx.session.hosts[ip]
                h.ttl = ttl
                if not h.os_guess:
                    h.os_guess = ttl_guess(ttl)
                    h.add_source("ttl")
                ctx.ui.info(f"{ip}: ttl={ttl} -> {ttl_guess(ttl)}", "hostid")

    # 3. nmap OS detection (needs root)
    identified = 0
    if ctx.has("nmap") and ctx.is_root:
        ctx.ui.set_phase("hostid", "running", "nmap OS detection")
        identified = _os_detection(ctx, hosts)
    elif ctx.has("nmap"):
        ctx.ui.warn("nmap OS detection needs root - using TTL/vendor heuristics only", "hostid")

    for ip in hosts:
        h = ctx.session.hosts[ip]
        ctx.ui.ok(f"{ip}: {h.os_guess or 'unknown OS'}"
                  + (f" [{h.os_accuracy}%]" if h.os_accuracy else "")
                  + (f" | {h.device_type}" if h.device_type else "")
                  + (f" | {h.hostname}" if h.hostname else ""), "hostid")
    status = "done" if identified or any(ctx.session.hosts[i].os_guess for i in hosts) else "warn"
    return status, f"{identified} OS match(es), {len(hosts)} host(s)"
