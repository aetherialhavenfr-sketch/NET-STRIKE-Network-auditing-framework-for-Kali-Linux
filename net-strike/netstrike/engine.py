"""Audit orchestration: runs the selected modules in a fixed order with full error isolation."""

from __future__ import annotations

import getpass
import os
import socket
import time
import traceback
from pathlib import Path

from . import findings
from .config import MODULE_ORDER, MODULE_TITLES, MODULE_TOOLS
from .context import Context, ModuleError, ModuleSkipped
from .models import ScanOptions, ScanSession, now_iso
from .modules import discovery, hostid, portscan, services, smb, traffic
from .reporting.html_report import write_html
from .reporting.json_report import write_json
from .runner import detect_tools, fix_owner, is_root
from .scope import Scope
from .ui import UI

MODULES = {
    "discovery": discovery.run, "hostid": hostid.run, "portscan": portscan.run,
    "services": services.run, "smb": smb.run, "traffic": traffic.run,
}
# hostid always has a ping/TTL fallback, so it never needs an external tool to be usable
ANY_TOOL_OK = {"hostid"}


def _operator() -> str:
    try:
        return os.environ.get("SUDO_USER") or getpass.getuser()
    except Exception:  # noqa: BLE001
        return "unknown"


def _refresh_stats(ctx: Context) -> None:
    s = ctx.session
    ctx.ui.set_stat("hosts", len(s.hosts))
    ctx.ui.set_stat("ports", sum(len(h.open_ports()) for h in s.hosts.values()))
    ctx.ui.set_stat("services", sum(1 for h in s.hosts.values() for p in h.open_ports() if p.service))
    ctx.ui.set_stat("findings", len(s.findings))


def run_audit(opts: ScanOptions, ui: UI, scope: Scope, auth: dict,
              tools: dict | None = None) -> tuple[ScanSession, dict]:
    """Execute an audit. Always returns (session, report_paths), even after Ctrl+C or module failures."""
    sid = time.strftime("%Y%m%d-%H%M%S")
    workdir = Path(opts.out_dir).expanduser() / f"netstrike-{sid}"
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        workdir.chmod(0o700)
    except OSError:
        pass

    session = ScanSession(
        id=sid, started=now_iso(),
        targets=[str(n) for n in scope.networks] or [f"pcap:{opts.pcap}" if opts.pcap else "-"],
        interface=opts.iface, profile=opts.profile, modules=list(opts.modules),
        operator=_operator(), hostname=socket.gethostname(), authorization=auth,
        options={k: (str(v) if isinstance(v, Path) else v) for k, v in vars(opts).items()},
    )
    ui.open_logfile(workdir / "netstrike.log")
    ui.sink = session.add_event

    tools = tools or detect_tools()
    session.tools = tools
    ctx = Context(session, ui, opts, scope.networks, workdir, tools)

    order = [m for m in MODULE_ORDER if m in opts.modules]
    for key in order:
        ui.add_phase(key, MODULE_TITLES[key])
    ui.add_phase("analysis", MODULE_TITLES["analysis"])
    ui.add_phase("report", MODULE_TITLES["report"])
    ui.set_meta(target=", ".join(session.targets), iface=opts.iface or "auto", profile=opts.profile,
                privilege="root" if is_root() else "user")

    t_start = time.time()
    paths: dict = {}
    ui.start_dashboard()
    interrupted = False
    try:
        ui.info(f"session {sid} started - output: {workdir}", "core")
        if not is_root():
            ui.warn("not running as root: ARP discovery, masscan, OS detection and live capture are limited", "core")
        for name, info in tools.items():
            if not info["available"]:
                ui.warn(f"{name} not found ({info['role']})", "core")

        for key in order:
            if interrupted:
                ui.set_phase(key, "skipped", "aborted")
                continue
            usable = key in ANY_TOOL_OK or any(ctx.has(t) for t in MODULE_TOOLS[key])
            if not usable:
                missing = " / ".join(MODULE_TOOLS[key])
                ui.set_phase(key, "skipped", f"missing: {missing}")
                ui.warn(f"{MODULE_TITLES[key]} skipped - install {missing}", "core")
                session.phases.append({"key": key, "title": MODULE_TITLES[key], "status": "skipped",
                                      "detail": f"missing: {missing}", "seconds": 0})
                continue

            ui.set_phase(key, "running", "starting")
            ui.info(f">> {MODULE_TITLES[key]}", "core")
            t0 = time.time()
            status, detail = "done", ""
            try:
                status, detail = MODULES[key](ctx)
            except ModuleSkipped as exc:
                status, detail = "skipped", str(exc)
                ui.warn(f"{MODULE_TITLES[key]} skipped: {exc}", "core")
            except ModuleError as exc:
                status, detail = "failed", str(exc)
                ui.err(f"{MODULE_TITLES[key]} failed: {exc}", "core")
            except KeyboardInterrupt:
                interrupted = True
                ctx.cancel.set()
                status, detail = "warn", "aborted by user"
                ui.warn("Ctrl+C received - stopping and saving partial results", "core")
            except Exception as exc:  # noqa: BLE001 - isolate module bugs from the rest of the audit
                status, detail = "failed", f"{type(exc).__name__}: {exc}"
                ui.err(f"{MODULE_TITLES[key]} crashed: {type(exc).__name__}: {exc}", "core")
                ui.log("dbg", traceback.format_exc(), "core")
            ui.set_phase(key, status, detail)
            session.phases.append({"key": key, "title": MODULE_TITLES[key], "status": status,
                                   "detail": detail, "seconds": round(time.time() - t0, 1)})
            _refresh_stats(ctx)

        # ---- analysis ----------------------------------------------------------
        ui.set_phase("analysis", "running", "evaluating results")
        try:
            n = findings.analyze(session)
            ui.set_phase("analysis", "done", f"{n} finding(s)")
            session.phases.append({"key": "analysis", "title": MODULE_TITLES["analysis"], "status": "done",
                                   "detail": f"{n} finding(s)", "seconds": 0})
        except Exception as exc:  # noqa: BLE001
            ui.set_phase("analysis", "failed", str(exc))
            ui.err(f"analysis failed: {exc}", "core")
        _refresh_stats(ctx)

        # ---- report ------------------------------------------------------------
        ui.set_phase("report", "running", "writing reports")
        session.finished = now_iso()
        session.duration = time.time() - t_start
        try:
            data = session.to_dict()
            if "json" in opts.formats:
                paths["json"] = write_json(data, workdir / "report.json")
            if "html" in opts.formats:
                paths["html"] = write_html(data, workdir / "report.html")
            session.artifacts = sorted(p.name for p in workdir.iterdir() if p.is_file())
            if "json" in opts.formats:           # rewrite so the JSON lists its sibling artifacts
                paths["json"] = write_json(session.to_dict(), workdir / "report.json")
            ui.set_phase("report", "done", ", ".join(p.name for p in paths.values()))
            for label, p in paths.items():
                ui.ok(f"{label.upper()} report written: {p}", "report")
        except OSError as exc:
            ui.set_phase("report", "failed", str(exc))
            ui.err(f"could not write report: {exc}", "report")
    finally:
        ui.stop_dashboard()
        ui.close_logfile()
        ui.sink = None
        fix_owner(workdir)

    paths["workdir"] = workdir
    return session, paths
