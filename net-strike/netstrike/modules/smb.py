"""SMB / Windows enumeration via enum4linux-ng (anonymous, read-only enumeration - no brute forcing)."""

from __future__ import annotations

import json
from pathlib import Path

from ..context import Context, ModuleSkipped
from ..parsers import summarize_enum4linux


def _candidates(ctx: Context) -> list[str]:
    hosts = ctx.live_hosts()
    have_port_data = any(h.ports for h in ctx.session.hosts.values())
    if not have_port_data:
        return hosts            # no port scan ran - let the tool probe every live host
    return [ip for ip in hosts if ctx.session.hosts[ip].has_port(445) or ctx.session.hosts[ip].has_port(139)]


def _load_json(prefix: Path) -> dict | None:
    for candidate in (Path(str(prefix) + ".json"), prefix):
        if candidate.is_file():
            try:
                data = json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            return data if isinstance(data, dict) else None
    return None


def run(ctx: Context) -> tuple[str, str]:
    if not ctx.has("enum4linux-ng"):
        raise ModuleSkipped("enum4linux-ng is not installed")
    if ctx.no_live_hosts:
        raise ModuleSkipped("no live hosts")
    targets = _candidates(ctx)
    if not targets:
        raise ModuleSkipped("no hosts with SMB (139/445) open")

    ok = 0
    for i, ip in enumerate(targets, 1):
        if ctx.cancel.is_set():
            break
        ctx.ui.set_phase("smb", "running", f"{ip} ({i}/{len(targets)})")
        prefix = ctx.artifact(f"enum4linux-{ip}")
        res = ctx.run(["enum4linux-ng", "-A", ip, "-oJ", str(prefix)], timeout=600, source="enum4linux")
        if res.error:
            ctx.ui.warn(f"{ip}: {res.error}", "smb")
            continue
        data = _load_json(prefix)
        if data is None:
            ctx.ui.warn(f"{ip}: no enum4linux-ng result (host may not run SMB)", "smb")
            continue
        summary = summarize_enum4linux(data)
        host = ctx.session.hosts[ip]
        host.smb = summary
        host.add_source("enum4linux-ng")
        if summary["os"] and not host.os_guess:
            host.os_guess = summary["os"]
        ok += 1
        ctx.ui.ok(f"{ip}: null-session={summary['null_session']} users={len(summary['users'])} "
                  f"groups={len(summary['groups'])} shares={len(summary['shares'])}", "smb")
        ctx.ui.set_stat("smb", ok)

    if ok == 0:
        return "warn", "no SMB data collected"
    return "done", f"{ok}/{len(targets)} host(s) enumerated"
