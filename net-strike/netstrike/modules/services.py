"""Service enumeration: nmap -sV (+ default safe scripts) per host, in a small thread pool."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..context import Context, ModuleSkipped
from ..models import PortInfo
from ..parsers import parse_nmap_xml, port_list


def _scan_host(ctx: Context, ip: str, tcp_ports: list[int]) -> int:
    xml = ctx.artifact(f"services-{ip}.xml")
    cmd = ["nmap", "-sV", "--version-intensity", "5", "-Pn", "-n", f"-T{ctx.opts.timing}",
           "--host-timeout", "15m", "-oX", str(xml)]
    if ctx.opts.scripts:
        cmd += ["-sC", "--script-timeout", "30s"]
    cmd += ["-p", port_list(tcp_ports)] if tcp_ports else ["--top-ports", "100"]
    if ctx.opts.iface:
        cmd += ["-e", ctx.opts.iface]
    cmd.append(ip)

    res = ctx.run(cmd, timeout=1500, source="nmap:" + ip.split(".")[-1])
    if res.error:
        ctx.ui.warn(f"{ip}: {res.error}", "services")
        return 0

    entries = parse_nmap_xml(xml)
    if not entries and not res.cancelled:
        ctx.ui.warn(f"{ip}: nmap produced no parsable XML result", "services")
    updated = 0
    for entry in entries:
        host = ctx.session.hosts.get(entry["ip"])
        if not host:
            continue
        for p in entry["ports"]:
            if not p["state"].startswith("open"):
                continue
            host.add_port(PortInfo(
                port=p["port"], proto=p["proto"], state="open", service=p["service"], product=p["product"],
                version=p["version"], extrainfo=p["extrainfo"], scripts=p["scripts"], sources=["nmap-sv"]))
            updated += 1
        if entry["hostnames"] and not host.hostname:
            host.hostname = entry["hostnames"][0]
        for sid, out in entry["hostscripts"].items():
            host.notes.append(f"{sid}: {out.strip()[:300]}")
    return updated


def run(ctx: Context) -> tuple[str, str]:
    if not ctx.has("nmap"):
        raise ModuleSkipped("nmap is not installed")
    if ctx.no_live_hosts:
        raise ModuleSkipped("no live hosts")
    hosts = ctx.live_hosts()
    if not hosts:
        raise ModuleSkipped("no hosts to enumerate (run discovery or port scan first)")

    # hosts that already have port data are scanned on exactly those ports; others get top-100
    plan = {}
    for ip in hosts:
        tcp = [p.port for p in ctx.session.hosts[ip].open_ports() if p.proto == "tcp"]
        if tcp or not any(h.ports for h in ctx.session.hosts.values()):
            plan[ip] = tcp
    if not plan:
        raise ModuleSkipped("no open TCP ports to enumerate")

    total = len(plan)
    done = 0
    counter_lock = threading.Lock()
    ctx.ui.set_phase("services", "running", f"0/{total} hosts")
    pool = ThreadPoolExecutor(max_workers=max(1, min(ctx.opts.threads, total)))
    try:
        futures = {pool.submit(_scan_host, ctx, ip, ports): ip for ip, ports in plan.items()}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                fut.result()
            except Exception as exc:  # noqa: BLE001 - one bad host must not abort the phase
                ctx.ui.err(f"{ip}: service scan failed: {exc}", "services")
            with counter_lock:
                done += 1
                ctx.ui.set_phase("services", "running", f"{done}/{total} hosts")
            h = ctx.session.hosts[ip]
            for p in h.open_ports():
                if p.service:
                    ctx.ui.ok(f"{ip}:{p.port}/{p.proto}  {p.label}", "services")
            ctx.ui.set_stat("services", sum(1 for x in ctx.session.hosts.values() for p in x.open_ports() if p.service))
            ctx.ui.set_stat("ports", sum(len(x.open_ports()) for x in ctx.session.hosts.values()))
    except KeyboardInterrupt:
        ctx.cancel.set()
        raise
    finally:
        pool.shutdown(wait=True, cancel_futures=True)

    identified = sum(1 for x in ctx.session.hosts.values() for p in x.open_ports() if p.service)
    return "done", f"{identified} service(s) on {total} host(s)"
