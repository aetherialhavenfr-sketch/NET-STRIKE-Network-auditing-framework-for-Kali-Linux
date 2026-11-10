"""Standalone HTML report (no external resources). Every value is HTML-escaped: scan data comes from
remote hosts and must never be trusted."""

from __future__ import annotations

import html
import time
from pathlib import Path

from ..banner import art_lines
from ..config import APP_NAME, VERSION
from ..runner import write_private

SEVERITIES = ("critical", "high", "medium", "low", "info")

CSS = """
:root{--bg:#0b0b0e;--panel:#14141a;--panel2:#1b1b23;--line:#2a2a35;--text:#d8d8de;--dim:#8a8a96;
--orange:#ff8c00;--amber:#ffb000;--ember:#cc5500;--green:#50fa7b;--red:#ff5555;--cyan:#66d9ef}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
header{padding:28px 24px 8px;border-bottom:1px solid var(--line);
background:radial-gradient(ellipse at top,#241405 0%,var(--bg) 70%)}
pre.banner{margin:0;font-size:clamp(6px,1.15vw,15px);line-height:1.05;font-weight:700;overflow:hidden;
color:var(--orange);background:linear-gradient(180deg,#ffb000 0%,#ff8c00 45%,#cc4800 100%);
-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.sub{color:var(--dim);margin:10px 0 6px}.sub b{color:var(--amber)}
nav{display:flex;gap:16px;flex-wrap:wrap;padding:10px 24px;border-bottom:1px solid var(--line);
position:sticky;top:0;background:#0b0b0ef2;z-index:5}
nav a{color:var(--orange);text-decoration:none}nav a:hover{text-decoration:underline}
main{padding:20px 24px;max-width:1280px;margin:auto}
h2{color:var(--amber);font-size:16px;letter-spacing:.12em;text-transform:uppercase;margin:34px 0 12px;
border-bottom:1px solid var(--line);padding-bottom:6px}
h2:before{content:"// ";color:var(--ember)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--orange);padding:12px 14px}
.card .n{font-size:26px;color:var(--orange);font-weight:700}.card .l{color:var(--dim);font-size:12px;text-transform:uppercase}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line)}
th,td{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;word-break:break-word}
th{color:var(--amber);font-size:12px;text-transform:uppercase;background:var(--panel2)}
tr:hover td{background:#1a1a22}.wrap{overflow-x:auto}
.sev{display:inline-block;padding:1px 8px;font-size:11px;font-weight:700;text-transform:uppercase;border:1px solid}
.sev.critical,.sev.high{color:var(--red);border-color:var(--red)}.sev.medium{color:var(--amber);border-color:var(--amber)}
.sev.low{color:var(--cyan);border-color:var(--cyan)}.sev.info{color:var(--dim);border-color:var(--dim)}
.ok{color:var(--green)}.bad{color:var(--red)}.warn{color:var(--amber)}.dim{color:var(--dim)}
details{background:var(--panel);border:1px solid var(--line);margin:8px 0}
summary{cursor:pointer;padding:9px 12px;color:var(--orange)}summary:hover{background:var(--panel2)}
details>div{padding:4px 12px 12px}
pre{background:#0e0e12;border:1px solid var(--line);padding:8px;overflow-x:auto;white-space:pre-wrap;margin:6px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}
.bar{background:#0e0e12;border:1px solid var(--line);height:10px;min-width:80px}
.bar span{display:block;height:100%;background:linear-gradient(90deg,var(--amber),var(--ember))}
input#q{width:100%;padding:8px 10px;margin:0 0 10px;background:var(--panel);border:1px solid var(--line);
color:var(--text);font:inherit}input#q:focus{outline:1px solid var(--orange)}
footer{color:var(--dim);text-align:center;padding:28px;border-top:1px solid var(--line);margin-top:40px}
.pill{display:inline-block;background:var(--panel2);border:1px solid var(--line);padding:0 7px;margin:1px 3px 1px 0}
"""

JS = ("document.getElementById('q').addEventListener('input',function(e){var v=e.target.value.toLowerCase();"
      "document.querySelectorAll('#hosttable tbody tr').forEach(function(r){"
      "r.style.display=r.textContent.toLowerCase().indexOf(v)>-1?'':'none';});});")


def E(x) -> str:
    return html.escape("" if x is None else str(x), quote=True)


def _sev(s: str) -> str:
    s = s if s in SEVERITIES else "info"
    return f'<span class="sev {s}">{E(s)}</span>'


def _bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _secs(n) -> str:
    n = int(n or 0)
    return f"{n // 60}m{n % 60:02d}s" if n >= 60 else f"{n}s"


def _bars(items: list, label: str, value: str, extra: str = "") -> str:
    if not items:
        return '<p class="dim">no data</p>'
    top = max((i.get(value, 0) for i in items), default=1) or 1
    rows = []
    for i in items:
        pct = max(1.0, 100.0 * (i.get(value, 0) or 0) / top)
        rows.append(f"<tr><td>{E(i.get(label, ''))}{E(' ' + str(i.get(extra, '')) if extra and i.get(extra) else '')}</td>"
                    f'<td style="width:45%"><div class="bar"><span style="width:{pct:.1f}%"></span></div></td>'
                    f"<td>{E(i.get(value, 0)):}</td></tr>")
    return f'<div class="wrap"><table><tbody>{"".join(rows)}</tbody></table></div>'


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return '<p class="dim">no data</p>'
    head = "".join(f"<th>{E(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _cards(d: dict) -> str:
    s = d.get("summary", {})
    f = s.get("findings", {})
    items = [
        (s.get("hosts_up", 0), "hosts up"), (s.get("open_ports", 0), "open ports"),
        (s.get("services_identified", 0), "services"), (s.get("smb_hosts", 0), "smb hosts"),
        (s.get("packets_captured", 0), "packets"), (s.get("findings_total", 0), "findings"),
        (f.get("critical", 0) + f.get("high", 0), "high / critical"), (_secs(d.get("duration_seconds", 0)), "duration"),
    ]
    return '<div class="cards">' + "".join(
        f'<div class="card"><div class="n">{E(n)}</div><div class="l">{E(l)}</div></div>' for n, l in items) + "</div>"


def _findings(d: dict) -> str:
    rows = []
    for f in d.get("findings", []):
        where = E(f.get("host", "")) + (f":{E(f.get('port'))}" if f.get("port") else "")
        rows.append([_sev(f.get("severity", "info")), where or "-", f"<b>{E(f.get('title'))}</b><br>"
                     f"<span class='dim'>{E(f.get('detail'))}</span>", E(f.get("recommendation")), E(f.get("source"))])
    return _table(["Severity", "Where", "Finding", "Recommendation", "Source"], rows)


def _hosts(d: dict) -> str:
    rows = []
    for h in d.get("hosts", []):
        open_ports = [p for p in h.get("ports", []) if str(p.get("state", "")).startswith("open")]
        pills = "".join(f'<span class="pill">{E(p.get("port"))}/{E(p.get("proto"))}</span>' for p in open_ports[:14])
        if len(open_ports) > 14:
            pills += f'<span class="dim">+{len(open_ports) - 14}</span>'
        mac = E(h.get("mac")) + (f" <span class='dim'>({E(h.get('vendor'))})</span>" if h.get("vendor") else "")
        rows.append([f"<b class='ok'>{E(h.get('ip'))}</b>", E(h.get("hostname")) or "-", mac or "-",
                     E(h.get("os_guess") or h.get("device_type")) or "-", pills or "-"])
    table = _table(["IP", "Hostname", "MAC / Vendor", "OS / Device", "Open ports"], rows)
    return table.replace("<table>", '<table id="hosttable">', 1)


def _host_details(d: dict) -> str:
    out = []
    for h in d.get("hosts", []):
        ports = h.get("ports", [])
        port_rows = []
        for p in ports:
            scripts = "".join(f"<details><summary>{E(k)}</summary><pre>{E(v)}</pre></details>"
                              for k, v in (p.get("scripts") or {}).items())
            svc = " ".join(x for x in (p.get("product"), p.get("version")) if x)
            port_rows.append([E(p.get("port")), E(p.get("proto")), E(p.get("state")), E(p.get("service")),
                              E(svc) + (f" <span class='dim'>{E(p.get('extrainfo'))}</span>" if p.get("extrainfo") else ""),
                              scripts or "-"])
        smb = h.get("smb") or {}
        smb_html = ""
        if smb:
            def flag(v, bad_when):
                if v is None:
                    return '<span class="dim">unknown</span>'
                return f'<span class="{"bad" if v == bad_when else "ok"}">{E(v)}</span>'
            shares = _table(["Share", "Comment", "Map", "List", "Write"],
                            [[E(s.get("name")), E(s.get("comment")), E(s.get("mapping")), E(s.get("listing")),
                              E(s.get("writing"))] for s in smb.get("shares", [])])
            smb_html = (
                "<h3 class='warn'>SMB / Windows enumeration</h3>"
                f"<p>Null session: {flag(smb.get('null_session'), True)} &nbsp; SMBv1: {flag(smb.get('smb1_enabled'), True)}"
                f" &nbsp; Signing required: {flag(smb.get('signing_required'), False)}"
                f" &nbsp; Domain: {E(smb.get('domain')) or '-'} &nbsp; OS: {E(smb.get('os')) or '-'}</p>"
                f"<p>Users ({len(smb.get('users', []))}): {', '.join(E(u) for u in smb.get('users', [])[:60]) or '-'}</p>"
                f"<p>Groups ({len(smb.get('groups', []))}): {', '.join(E(g) for g in smb.get('groups', [])[:40]) or '-'}</p>"
                + shares)
        notes = "".join(f"<pre>{E(n)}</pre>" for n in h.get("notes", []))
        out.append(
            f"<details><summary><b>{E(h.get('ip'))}</b> &nbsp;{E(h.get('hostname'))} &nbsp;"
            f"<span class='dim'>{E(h.get('os_guess'))} &middot; {len([p for p in ports if str(p.get('state')).startswith('open')])} open</span>"
            f"</summary><div><p class='dim'>MAC {E(h.get('mac')) or '-'} &middot; vendor {E(h.get('vendor')) or '-'} &middot; "
            f"TTL {E(h.get('ttl')) or '-'} &middot; sources {E(', '.join(h.get('sources', [])))}</p>"
            + _table(["Port", "Proto", "State", "Service", "Product / Version", "Script output"], port_rows)
            + smb_html + notes + "</div></details>")
    return "".join(out) or '<p class="dim">no hosts</p>'


def _traffic(d: dict) -> str:
    t = d.get("traffic")
    if not t:
        return '<p class="dim">Traffic analysis was not run.</p>'
    flags = "".join(f"<li class='warn'>Clear-text protocol: <b>{E(c.get('protocol'))}</b> ({E(c.get('packets'))} packets)</li>"
                    for c in t.get("cleartext", []))
    flags += "".join(f"<li class='bad'>ARP anomaly: <b>{E(a.get('ip'))}</b> claimed by {E(', '.join(a.get('macs', [])))}</li>"
                     for a in t.get("arp_anomalies", []))
    names = lambda items: _bars(items, "name", "count")  # noqa: E731
    return (
        f"<p>Source: <b>{E(t.get('source'))}</b> &middot; interface {E(t.get('interface')) or '-'} &middot; "
        f"filter <code>{E(t.get('capture_filter')) or '-'}</code> &middot; {E(t.get('packets'))} packets &middot; "
        f"{_bytes(t.get('bytes'))}</p>"
        + (f"<ul>{flags}</ul>" if flags else "<p class='ok'>No clear-text protocols or ARP anomalies observed.</p>")
        + "<div class='grid'><div><h3>Protocols</h3>" + _bars(t.get("protocols", []), "name", "packets") + "</div>"
        "<div><h3>Top talkers</h3>" + _table(["IP", "Bytes", "Packets"], [[E(x.get("ip")), _bytes(x.get("bytes")), E(x.get("packets"))] for x in t.get("top_talkers", [])]) + "</div>"
        "<div><h3>Top destination ports</h3>" + _table(["Port", "Proto", "Service", "Packets"], [[E(x.get("port")), E(x.get("proto")), E(x.get("service")), E(x.get("packets"))] for x in t.get("top_ports", [])]) + "</div></div>"
        "<h3>Conversations</h3>" + _table(["A", "B", "Packets", "Bytes"], [[E(x.get("a")), E(x.get("b")), E(x.get("packets")), _bytes(x.get("bytes"))] for x in t.get("conversations", [])])
        + "<div class='grid'><div><h3>DNS queries</h3>" + names(t.get("dns_queries", [])) + "</div>"
        "<div><h3>HTTP hosts</h3>" + names(t.get("http_hosts", [])) + "</div>"
        "<div><h3>TLS server names (SNI)</h3>" + names(t.get("tls_sni", [])) + "</div></div>"
        + "".join(f"<p class='dim'>{E(n)}</p>" for n in t.get("notes", [])))


def _pipeline(d: dict) -> str:
    cls = {"done": "ok", "failed": "bad", "warn": "warn"}
    phases = _table(["Phase", "Status", "Detail", "Time"], [
        [E(p.get("title")), f"<span class='{cls.get(p.get('status'), 'dim')}'>{E(p.get('status'))}</span>",
         E(p.get("detail")), _secs(p.get("seconds"))] for p in d.get("phases", [])])
    tools = _table(["Tool", "Available", "Version", "Path"], [
        [E(n), "<span class='ok'>yes</span>" if t.get("available") else "<span class='bad'>no</span>",
         E(t.get("version")), E(t.get("path"))] for n, t in (d.get("tools") or {}).items()])
    return f"<h3>Phases</h3>{phases}<h3>Toolchain</h3>{tools}"


def _events(d: dict) -> str:
    cls = {"ok": "ok", "warn": "warn", "err": "bad"}
    rows = [[E(e.get("time", "")[11:19]), f"<span class='{cls.get(e.get('level'), 'dim')}'>{E(e.get('level'))}</span>",
             E(e.get("source")), E(e.get("message"))] for e in d.get("events", [])[-500:]]
    return _table(["Time", "Level", "Source", "Message"], rows)


def render_html(d: dict) -> str:
    banner = E("\n".join(art_lines()))
    auth = d.get("authorization") or {}
    meta = (f"session <b>{E(d.get('id'))}</b> &middot; targets <b>{E(', '.join(d.get('targets', [])))}</b> &middot; "
            f"profile {E(d.get('profile'))} &middot; interface {E(d.get('interface')) or '-'}<br>"
            f"operator {E(d.get('operator'))}@{E(d.get('hostname'))} &middot; started {E(d.get('started'))} &middot; "
            f"finished {E(d.get('finished')) or '-'} &middot; authorization: {E(auth.get('method')) or 'n/a'}")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>{E(APP_NAME)} report {E(d.get('id'))}</title><style>{CSS}</style></head><body>
<header><pre class="banner">{banner}</pre><div class="sub">{E(APP_NAME)} v{E(VERSION)} &middot; network audit report</div>
<div class="sub">{meta}</div></header>
<nav><a href="#summary">summary</a><a href="#findings">findings</a><a href="#hosts">hosts</a>
<a href="#details">host details</a><a href="#traffic">traffic</a><a href="#pipeline">pipeline</a><a href="#log">log</a></nav>
<main>
<h2 id="summary">Summary</h2>{_cards(d)}
<h2 id="findings">Findings</h2>{_findings(d)}
<h2 id="hosts">Hosts</h2><input id="q" placeholder="filter hosts (ip, os, port, vendor)..." autocomplete="off">{_hosts(d)}
<h2 id="details">Host details</h2>{_host_details(d)}
<h2 id="traffic">Traffic analysis</h2>{_traffic(d)}
<h2 id="pipeline">Pipeline &amp; toolchain</h2>{_pipeline(d)}
<h2 id="log">Event log</h2>{_events(d)}
</main>
<footer>Generated by {E(APP_NAME)} v{E(VERSION)} on {E(time.strftime('%Y-%m-%d %H:%M:%S'))}.
Findings reflect exposure and configuration evidence only - no exploitation or CVE matching was performed.
Authorized use only. This file contains sensitive network data: handle accordingly.</footer>
<script>{JS}</script></body></html>
"""


def write_html(data: dict, path: Path) -> Path:
    write_private(path, render_html(data))
    return path
