"""Traffic analysis with tshark.

* Live mode: passive capture on an interface, limited by a BPF filter built from the authorized scope.
* Offline mode: analyse an existing pcap/pcapng (`netstrike.py analyze file.pcap`).

The module reports protocol mix, top talkers, conversations, DNS/HTTP/TLS names, clear-text protocol use
and ARP anomalies. It deliberately does NOT extract credentials or payloads.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from ..context import Context, ModuleError, ModuleSkipped
from ..models import TrafficSummary
from ..parsers import TSHARK_FIELDS, TSHARK_FIELDS_MIN, TrafficAggregator
from ..runner import run_command
from ..scope import default_iface


def _capture_filter(ctx: Context) -> str:
    parts = []
    for n in ctx.networks:
        parts.append(f"host {n.network_address}" if n.prefixlen == 32 else f"net {n}")
    return " or ".join(f"({p})" for p in parts)


def _capture(ctx: Context, duration: int) -> tuple[Path, str, str]:
    iface = ctx.opts.iface or default_iface()
    if not iface:
        raise ModuleError("no network interface available for capture (use --iface)")
    pcap = ctx.artifact("capture.pcapng")
    bpf = _capture_filter(ctx)
    cmd = ["tshark", "-i", iface, "-n", "-q", "-a", f"duration:{duration}", "-w", str(pcap)]
    if bpf:
        cmd += ["-f", bpf]

    stop = threading.Event()

    def ticker() -> None:
        t0 = time.time()
        while not stop.is_set():
            ctx.ui.set_phase("traffic", "running", f"capturing on {iface}: {int(time.time() - t0)}/{duration}s")
            stop.wait(0.5)

    th = threading.Thread(target=ticker, daemon=True)
    th.start()
    try:
        res = ctx.run(cmd, timeout=duration + 30, source="tshark")
    finally:
        stop.set()
        th.join(timeout=1)

    if res.error:
        raise ModuleError(res.error)
    if not pcap.exists() or pcap.stat().st_size == 0:
        hint = "tshark needs root or dumpcap capabilities (sudo dpkg-reconfigure wireshark-common)"
        raise ModuleError(f"capture produced no data. {hint}. {res.stderr.strip()[-160:]}")
    return pcap, iface, bpf


def _analyze(ctx: Context, pcap: Path) -> TrafficAggregator:
    for fields in (TSHARK_FIELDS, TSHARK_FIELDS_MIN):     # older tshark may lack some fields
        agg = TrafficAggregator(fields)
        cmd = ["tshark", "-r", str(pcap), "-n", "-T", "fields", "-E", "occurrence=f"]
        for f in fields:
            cmd += ["-e", f]
        ctx.ui.set_phase("traffic", "running", "analysing packets")
        ctx.ui.log("cmd", " ".join(cmd[:6]) + " ...", "tshark")
        res = run_command(cmd, timeout=900, on_line=lambda s, line, a=agg: a.feed(line) if s == "out" else None,
                          cancel=ctx.cancel, store=False)
        if res.error:
            raise ModuleError(res.error)
        if agg.packets or res.returncode == 0:
            return agg
        ctx.ui.warn("tshark rejected some fields - retrying with a reduced field set", "traffic")
    return agg


def run(ctx: Context) -> tuple[str, str]:
    if not ctx.has("tshark"):
        raise ModuleSkipped("tshark is not installed")

    offline = Path(ctx.opts.pcap).expanduser() if ctx.opts.pcap else None
    summary_meta = {"source": "pcap", "interface": "", "bpf": "", "duration": 0}

    if offline:
        if not offline.is_file():
            raise ModuleError(f"pcap not found: {offline}")
        pcap = offline
        summary_meta["pcap"] = str(offline)
    else:
        duration = ctx.opts.traffic_duration
        if duration <= 0:
            raise ModuleSkipped("capture duration is 0")
        if not ctx.is_root:
            ctx.ui.warn("live capture usually needs root (or wireshark group membership)", "traffic")
        pcap, iface, bpf = _capture(ctx, duration)
        summary_meta.update({"source": "live", "interface": iface, "bpf": bpf, "duration": duration,
                             "pcap": str(pcap)})

    agg = _analyze(ctx, pcap)
    ts: TrafficSummary = agg.summary()
    ts.source = summary_meta["source"]
    ts.pcap_file = summary_meta.get("pcap", "")
    ts.interface = summary_meta["interface"]
    ts.capture_filter = summary_meta["bpf"]
    ts.duration = summary_meta["duration"]
    if not agg.packets:
        ts.notes.append("No packets matched - the segment may be quiet or the filter too narrow.")
    ctx.session.traffic = ts

    ctx.ui.ok(f"{ts.packets:,} packets / {ts.bytes:,} bytes analysed", "traffic")
    for item in ts.protocols[:6]:
        ctx.ui.info(f"protocol {item['name']}: {item['packets']:,} pkts", "traffic")
    for item in ts.cleartext:
        ctx.ui.warn(f"clear-text protocol seen: {item['protocol']} ({item['packets']} pkts)", "traffic")
    for item in ts.arp_anomalies:
        ctx.ui.warn(f"ARP anomaly: {item['ip']} claimed by {', '.join(item['macs'])}", "traffic")

    if not ts.packets:
        return "warn", "no packets captured"
    flags = len(ts.cleartext) + len(ts.arp_anomalies)
    return ("warn" if flags else "done"), f"{ts.packets:,} pkts, {flags} flag(s)"
