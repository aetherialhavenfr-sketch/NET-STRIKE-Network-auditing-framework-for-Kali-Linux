#!/usr/bin/env python3
"""NET-STRIKE - network auditing framework for authorized networks and lab environments.

Usage:
    sudo ./netstrike.py                                  interactive console
    sudo ./netstrike.py scan 192.168.56.0/24             standard audit
    sudo ./netstrike.py scan 10.0.0.5 -p quick           fast triage of one host
    ./netstrike.py analyze capture.pcapng                offline traffic analysis
    ./netstrike.py report reports/netstrike-.../report.json
    ./netstrike.py check                                 toolchain / privilege check
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from netstrike import APP_NAME, VERSION
from netstrike.banner import show_banner
from netstrike.config import (AUDIT_LOG, DEFAULT_OUTPUT_DIR, DEFAULT_RATE, DEFAULT_SCOPE_FILE, MAX_RATE,
                              MODULE_ORDER, PROFILES)
from netstrike.engine import run_audit
from netstrike.models import ScanOptions
from netstrike.parsers import validate_port_spec
from netstrike.reporting.html_report import write_html
from netstrike.runner import detect_tools, fix_owner, is_root
from netstrike.scope import (Scope, ScopeError, confirm_authorization, default_iface, validate_iface,
                             write_audit)
from netstrike.term import AMBER, DIM, GREEN, ORANGE, RED, Term
from netstrike.ui import UI, print_summary


# ------------------------------------------------------------------------- argument parsing
def _rate(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("rate must be an integer") from None
    if not 1 <= n <= MAX_RATE:
        raise argparse.ArgumentTypeError(f"rate must be between 1 and {MAX_RATE}")
    return n


def _bounded(lo: int, hi: int):
    def conv(value: str) -> int:
        try:
            n = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError("must be an integer") from None
        if not lo <= n <= hi:
            raise argparse.ArgumentTypeError(f"must be between {lo} and {hi}")
        return n
    return conv


def _common(p: argparse.ArgumentParser, suppress: bool) -> None:
    d = argparse.SUPPRESS if suppress else False
    p.add_argument("--no-anim", action="store_true", default=d, help="disable animations / live dashboard")
    p.add_argument("--no-banner", action="store_true", default=d, help="skip the startup banner")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netstrike", description=f"{APP_NAME} v{VERSION} - network auditing framework "
        "(authorized networks and lab environments only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run without a command for the interactive console.")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    _common(p, suppress=False)
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="run an audit against authorized targets")
    _common(s, suppress=True)
    s.add_argument("targets", nargs="+", help="IP, CIDR (max /16), range (a.b.c.1-50) or hostname")
    s.add_argument("-i", "--iface", default="", help="network interface (default: auto)")
    s.add_argument("-p", "--profile", choices=sorted(PROFILES), default="standard",
                   help="quick | standard | full (default: standard)")
    s.add_argument("-m", "--modules", help=f"comma list overriding the profile: {','.join(MODULE_ORDER)}")
    s.add_argument("--ports", help="port spec for the sweep, e.g. 22,80,443 or 1-10000")
    s.add_argument("--rate", type=_rate, default=DEFAULT_RATE, help=f"packets/sec for masscan/nmap (max {MAX_RATE})")
    s.add_argument("--duration", type=_bounded(0, 3600), default=None, help="traffic capture seconds")
    s.add_argument("--threads", type=_bounded(1, 16), default=3, help="parallel service scans (default 3)")
    s.add_argument("--timing", type=_bounded(1, 5), default=4, help="nmap timing template 1-5 (default 4)")
    s.add_argument("--no-scripts", action="store_true", help="do not run nmap default scripts (-sC)")
    s.add_argument("-o", "--out", default=DEFAULT_OUTPUT_DIR, help="output directory (default ./reports)")
    s.add_argument("-f", "--format", default="html,json", help="report formats: html,json")
    s.add_argument("--scope-file", default=str(DEFAULT_SCOPE_FILE),
                   help="file listing extra authorized networks (default ~/.netstrike/scope.txt)")
    s.add_argument("--i-am-authorized", action="store_true",
                   help="confirm you hold written permission to audit the targets (non-interactive)")

    a = sub.add_parser("analyze", help="offline traffic analysis of an existing pcap/pcapng")
    _common(a, suppress=True)
    a.add_argument("pcap")
    a.add_argument("-o", "--out", default=DEFAULT_OUTPUT_DIR)
    a.add_argument("-f", "--format", default="html,json")

    r = sub.add_parser("report", help="re-render the HTML report from a report.json")
    _common(r, suppress=True)
    r.add_argument("json_file")

    c = sub.add_parser("check", help="show toolchain, privileges and scope policy")
    _common(c, suppress=True)
    return p


def parse_formats(value: str) -> list[str]:
    fmts = [f.strip().lower() for f in value.split(",") if f.strip()]
    bad = [f for f in fmts if f not in ("html", "json")]
    if bad or not fmts:
        raise ScopeError(f"unknown report format(s): {', '.join(bad) or '(none)'} - use html,json")
    return fmts


def resolve_options(args) -> ScanOptions:
    prof = PROFILES[args.profile]
    explicit = bool(args.modules)
    if explicit:
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
        bad = [m for m in modules if m not in MODULE_ORDER]
        if bad:
            raise ScopeError(f"unknown module(s): {', '.join(bad)} (choose from {', '.join(MODULE_ORDER)})")
    else:
        modules = list(prof["modules"])
    try:
        ports = validate_port_spec(args.ports) if args.ports else prof["ports"]
    except ValueError as exc:
        raise ScopeError(str(exc)) from None
    duration = args.duration
    if duration is None:
        duration = prof["traffic_duration"] or (20 if explicit and "traffic" in modules else 0)
    iface = validate_iface(args.iface) if args.iface else ""
    return ScanOptions(
        targets=list(args.targets), iface=iface, profile=args.profile, modules=modules, ports=ports,
        rate=args.rate, traffic_duration=duration, threads=args.threads, timing=args.timing,
        scripts=not args.no_scripts, out_dir=args.out, formats=parse_formats(args.format))


# ------------------------------------------------------------------------- UI flow
def boot_sequence(ui: UI, tools: dict) -> None:
    ui.boot_line("OK", "scope guard armed " + ui.t.paint("(private/lab ranges + scope file)", DIM))
    ui.boot_line("OK", f"audit log {ui.t.paint(str(AUDIT_LOG), DIM)}")
    ui.progress_fill("probing toolchain")
    for name, info in tools.items():
        if info["available"]:
            ver = (info["version"] or "installed")[:48]
            ui.boot_line("OK", f"{name:<14}{ui.t.paint(ver, DIM)}", 0.06)
        else:
            ui.boot_line("!!", f"{name:<14}{ui.t.paint('not found - ' + info['role'], AMBER)}", 0.06)
    root = is_root()
    ui.boot_line("OK" if root else "!!", "privileges   " + ui.t.paint(
        "root" if root else "unprivileged (ARP, masscan, OS detection, capture limited) - use sudo",
        GREEN if root else AMBER))
    ui.t.print()


def show_check(ui: UI, tools: dict) -> None:
    ui.section("TOOLCHAIN")
    rows = []
    for name, info in tools.items():
        rows.append([ui.t.paint(name, ORANGE),
                     ui.t.paint("installed", GREEN) if info["available"] else ui.t.paint("missing", RED),
                     info["version"] or "-", info["role"], "yes" if info["needs_root"] else "no"])
    ui.table(["TOOL", "STATUS", "VERSION", "ROLE", "ROOT"], rows)
    missing = [n for n, i in tools.items() if not i["available"]]
    if missing:
        ui.t.print(ui.t.paint("  install: ", DIM) + f"sudo apt install {' '.join(missing)}")
    ui.section("ENVIRONMENT")
    ui.kv("privileges", "root" if is_root() else "unprivileged", GREEN if is_root() else AMBER)
    ui.kv("interface", default_iface() or "none detected")
    ui.kv("scope file", f"{DEFAULT_SCOPE_FILE} ({'present' if Path(DEFAULT_SCOPE_FILE).is_file() else 'absent'})")
    ui.kv("audit log", str(AUDIT_LOG))
    ui.kv("scope policy", "private/lab ranges allowed; others only if listed in scope file; max /16")
    ui.t.print()


def do_scan(ui: UI, opts: ScanOptions, scope_file: str, accepted: bool, tools: dict) -> int:
    scope = Scope.from_file(scope_file)
    scope.validate(opts.targets)                         # raises ScopeError when out of scope
    auth = confirm_authorization(ui, scope.networks, accepted)
    write_audit({"event": "scan_start", "targets": [str(n) for n in scope.networks], "modules": opts.modules,
                 "profile": opts.profile, "iface": opts.iface or "auto", "authorization": auth["method"]})
    session, paths = run_audit(opts, ui, scope, auth, tools)
    write_audit({"event": "scan_end", "session": session.id, "hosts": len(session.hosts),
                 "findings": len(session.findings)})
    print_summary(ui, session, {k: v for k, v in paths.items()})
    return 0


def do_analyze(ui: UI, args, tools: dict) -> int:
    pcap = Path(args.pcap).expanduser()
    if not pcap.is_file():
        raise ScopeError(f"pcap not found: {pcap}")
    opts = ScanOptions(profile="offline", modules=["traffic"], out_dir=args.out, pcap=str(pcap),
                       formats=parse_formats(args.format))
    auth = {"method": "offline", "note": "analysis of an existing capture; no packets are sent"}
    write_audit({"event": "analyze_pcap", "pcap": str(pcap)})
    session, paths = run_audit(opts, ui, Scope(), auth, tools)
    print_summary(ui, session, paths)
    return 0


def do_report(ui: UI, args) -> int:
    src = Path(args.json_file).expanduser()
    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ScopeError(f"cannot read report json: {exc}") from None
    if not isinstance(data, dict) or data.get("schema", "").split("/")[0] != "netstrike-report":
        raise ScopeError("not a NET-STRIKE report.json")
    out = write_html(data, src.with_suffix(".html"))
    fix_owner(out)
    ui.ok(f"HTML report written: {out}", "report")
    return 0


def interactive(ui: UI, tools: dict) -> int:
    state = {"targets": [], "profile": "standard", "iface": "", "scope_file": str(DEFAULT_SCOPE_FILE)}
    while True:
        ui.section("CONSOLE")
        ui.kv("targets", ", ".join(state["targets"]) or "(not set)", ORANGE if state["targets"] else AMBER)
        ui.kv("profile", f"{state['profile']} - {PROFILES[state['profile']]['description']}")
        ui.kv("interface", state["iface"] or f"auto ({default_iface() or 'none'})")
        choice = ui.menu("MAIN MENU", [
            ("1", "set target(s)"), ("2", "select profile"), ("3", "choose interface"),
            ("4", "launch audit"), ("5", "analyze a pcap file"), ("6", "toolchain check"), ("0", "exit")])
        try:
            if choice == "1":
                raw = ui.ask("targets (space or comma separated)")
                targets = [t for t in raw.replace(",", " ").split() if t]
                Scope.from_file(state["scope_file"]).validate(targets)
                state["targets"] = targets
                ui.ok("targets accepted", "scope")
            elif choice == "2":
                state["profile"] = ui.ask("profile (quick / standard / full)", state["profile"]).lower()
                if state["profile"] not in PROFILES:
                    state["profile"] = "standard"
                    ui.warn("unknown profile - using standard", "console")
            elif choice == "3":
                name = ui.ask("interface name (blank = auto)", "")
                state["iface"] = validate_iface(name) if name else ""
            elif choice == "4":
                if not state["targets"]:
                    ui.warn("set a target first", "console")
                    continue
                ns = argparse.Namespace(
                    targets=state["targets"], iface=state["iface"], profile=state["profile"], modules=None,
                    ports=None, rate=DEFAULT_RATE, duration=None, threads=3, timing=4, no_scripts=False,
                    out=DEFAULT_OUTPUT_DIR, format="html,json")
                do_scan(ui, resolve_options(ns), state["scope_file"], False, tools)
            elif choice == "5":
                path = ui.ask("path to pcap/pcapng")
                if path:
                    do_analyze(ui, argparse.Namespace(pcap=path, out=DEFAULT_OUTPUT_DIR, format="html,json"), tools)
            elif choice == "6":
                show_check(ui, tools)
            elif choice in ("0", "q", "exit", "quit"):
                ui.t.print(ui.t.paint("  session closed.", DIM))
                return 0
            else:
                ui.warn("invalid selection", "console")
        except ScopeError as exc:
            for line in str(exc).splitlines():
                ui.err(line, "scope")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    term = Term()
    ui = UI(term, animate=not args.no_anim)
    cmd = args.cmd

    try:
        if cmd == "report":
            return do_report(ui, args)

        if not args.no_banner:
            show_banner(term, animate=ui.animate)
        tools = detect_tools()
        if not args.no_banner:
            boot_sequence(ui, tools)

        if cmd == "check":
            show_check(ui, tools)
            return 0
        if cmd == "scan":
            return do_scan(ui, resolve_options(args), args.scope_file, args.i_am_authorized, tools)
        if cmd == "analyze":
            return do_analyze(ui, args, tools)
        if not ui.interactive():
            ui.err("no command given and no interactive terminal - see --help", "cli")
            return 2
        return interactive(ui, tools)

    except ScopeError as exc:
        term.show_cursor()
        term.print()
        for line in str(exc).splitlines():
            term.print(term.paint("[-] ", RED, bold=True) + term.paint(line, RED))
        return 2
    except KeyboardInterrupt:
        term.show_cursor()
        term.print("\n" + term.paint("[!] interrupted", AMBER, bold=True))
        return 130
    except BrokenPipeError:
        return 0
    finally:
        term.show_cursor()


if __name__ == "__main__":
    sys.exit(main())
