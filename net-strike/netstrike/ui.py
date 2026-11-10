"""Hacker-style terminal UI: animated live dashboard, log stream, status indicators, tables."""

from __future__ import annotations

import re
import sys
import threading
import time
from collections import OrderedDict, deque

try:  # line editing for prompts (Linux/macOS)
    import readline  # noqa: F401
except ImportError:  # pragma: no cover
    pass

from .banner import typewriter
from .config import APP_NAME
from .term import (AMBER, CYAN, DIM, EMBER, GREEN, GREY, ORANGE, RED, WHITE, Term, fmt_dur, gradient,
                   pad, sanitize, truncate, visible_len)

LEVELS = {
    "ok": ("+", GREEN), "info": ("*", CYAN), "warn": ("!", AMBER),
    "err": ("-", RED), "cmd": (">", ORANGE), "dbg": ("~", DIM),
}
SEV_COLORS = {"critical": RED, "high": RED, "medium": AMBER, "low": CYAN, "info": GREY}
_SGR_RE = re.compile(r"(\x1b\[[0-9;]*m)")


class Phase:
    __slots__ = ("key", "title", "status", "detail", "t0", "t1")

    def __init__(self, key: str, title: str):
        self.key, self.title = key, title
        self.status, self.detail = "pending", ""
        self.t0 = self.t1 = 0.0

    def elapsed(self) -> float:
        if not self.t0:
            return 0.0
        return (self.t1 or time.time()) - self.t0


class UI:
    def __init__(self, term: Term, animate: bool = True):
        self.t = term
        self.animate = animate and term.is_tty
        self.lock = threading.RLock()
        self.phases: "OrderedDict[str, Phase]" = OrderedDict()
        self.logs: deque = deque(maxlen=600)
        self.stats: dict = {}
        self.meta: dict = {}
        self.sink = None                     # callable(level, source, msg) -> session events
        self._logfile = None
        self._live = False
        self._finished = False
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._prev = 0
        self._t_start = time.time()

    # ------------------------------------------------------------------ logging
    def open_logfile(self, path) -> None:
        try:
            self._logfile = open(path, "a", encoding="utf-8")
        except OSError:
            self._logfile = None

    def close_logfile(self) -> None:
        if self._logfile:
            try:
                self._logfile.close()
            finally:
                self._logfile = None

    def log(self, level: str, msg: str, source: str = "") -> None:
        msg = sanitize(msg)
        entry = (time.time(), level, source, msg)
        with self.lock:
            self.logs.append(entry)
            if self._logfile:
                try:
                    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry[0]))
                    self._logfile.write(f"{stamp} {level.upper():5} [{source}] {msg}\n")
                    self._logfile.flush()
                except (OSError, ValueError):
                    pass
            if not self._live:
                self.t.print(self.format_entry(entry, self.t.size()[0] - 1))
        if self.sink and level != "out":
            try:
                self.sink(level, source, msg)
            except Exception:  # noqa: BLE001
                pass

    def info(self, msg, source=""): self.log("info", msg, source)
    def ok(self, msg, source=""): self.log("ok", msg, source)
    def warn(self, msg, source=""): self.log("warn", msg, source)
    def err(self, msg, source=""): self.log("err", msg, source)

    def format_entry(self, entry, width: int = 0) -> str:
        t = self.t
        ts, level, source, msg = entry
        stamp = t.paint(time.strftime("%H:%M:%S", time.localtime(ts)), DIM)
        if level == "out":
            line = f"{stamp} {t.paint(t.sym['out'], DIM)} {t.paint(source[:9].ljust(9), DIM)} {t.paint(msg, GREY)}"
        else:
            sym, col = LEVELS.get(level, ("*", CYAN))
            tag = t.paint(f"[{sym}]", col, bold=True)
            if level in ("cmd", "warn", "err", "ok"):
                body = t.paint(msg, col)
            elif level == "dbg":
                body = t.paint(msg, DIM)
            else:
                body = msg
            line = f"{stamp} {tag} {body}"
        return truncate(line, width, ellipsis=True) if width else line

    # ------------------------------------------------------------------ state
    def interactive(self) -> bool:
        return bool(sys.stdin and sys.stdin.isatty() and self.t.is_tty)

    def add_phase(self, key: str, title: str) -> None:
        with self.lock:
            self.phases[key] = Phase(key, title)

    def set_phase(self, key: str, status: str, detail: str = "") -> None:
        with self.lock:
            ph = self.phases.get(key)
            if not ph:
                return
            if status == "running" and not ph.t0:
                ph.t0 = time.time()
            if status in ("done", "failed", "skipped", "warn"):
                ph.t1 = time.time()
                if not ph.t0:
                    ph.t0 = ph.t1
            ph.status = status
            if detail or status != "running":
                ph.detail = sanitize(detail)
        if not self._live:
            colors = {"running": CYAN, "done": GREEN, "failed": RED, "skipped": GREY, "warn": AMBER}
            if status in colors and status != "running":
                self.t.print(self.t.paint(f"    {ph.title}: {status}" + (f" - {ph.detail}" if ph.detail else ""),
                                          colors[status]))

    def set_stat(self, name: str, value) -> None:
        with self.lock:
            self.stats[name] = value

    def set_meta(self, **kw) -> None:
        with self.lock:
            self.meta.update({k: sanitize(v) for k, v in kw.items()})

    # ------------------------------------------------------------------ dashboard
    def start_dashboard(self) -> None:
        self._t_start = time.time()
        self._finished = False
        if not self.animate:
            return
        self._live = True
        self._prev = 0
        self._stop.clear()
        self.t.hide_cursor()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop_dashboard(self) -> None:
        if not self._live:
            return
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        with self.lock:
            self._finished = True
            self._draw()
            self._live = False
        self.t.show_cursor()
        self.t.print()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                with self.lock:
                    self._draw()
            except Exception:  # noqa: BLE001 - never let a render glitch kill the audit
                pass
            self._stop.wait(1 / 12)

    def _draw(self) -> None:
        lines = self._compose()
        out = []
        if self._prev:
            out.append(f"\x1b[{self._prev}A")
        out.append("\r")
        for ln in lines:
            out.append("\x1b[2K" + ln + "\n")
        self.t.write("".join(out))
        self._prev = len(lines)

    # -- composition helpers ---------------------------------------------------
    def _bp(self, s: str) -> str:
        return self.t.paint(s, ORANGE)

    def _row(self, content: str, W: int) -> str:
        v, inner = self.t.box["v"], W - 4
        return f"{self._bp(v)} {pad(truncate(content, inner), inner)} {self._bp(v)}"

    def _rule(self, W: int, title: str = "", right: str = "", top: bool = False, bottom: bool = False) -> str:
        b = self.t.box
        left_c, right_c = (b["tl"], b["tr"]) if top else (b["bl"], b["br"]) if bottom else (b["lj"], b["rj"])
        h = b["h"]
        vt, vr = visible_len(title), visible_len(right)
        if not title and not right:
            return self._bp(left_c + h * (W - 2) + right_c)
        if right:
            fill = max(1, W - 8 - vt - vr)
            return (self._bp(left_c + h + " ") + title + self._bp(" " + h * fill + " ") + right
                    + self._bp(" " + h + right_c))
        fill = max(1, W - 5 - vt)
        return self._bp(left_c + h + " ") + title + self._bp(" " + h * fill + right_c)

    def _indicator(self, ph: Phase) -> str:
        t, sym = self.t, self.t.sym
        if ph.status == "running":
            frames = sym["spin"]
            return t.paint(frames[int(time.time() * 10) % len(frames)], ORANGE, bold=True)
        mapping = {"done": ("ok", GREEN), "failed": ("fail", RED), "skipped": ("skip", DIM),
                   "warn": ("warn", AMBER), "pending": ("pending", DIM)}
        key, col = mapping.get(ph.status, ("pending", DIM))
        return t.paint(sym[key], col, bold=True)

    def _progress(self, width: int) -> str:
        t = self.t
        total = max(1, len(self.phases))
        finished = sum(1 for p in self.phases.values() if p.status in ("done", "failed", "skipped", "warn"))
        running = any(p.status == "running" for p in self.phases.values())
        frac = min(1.0, (finished + (0.5 if running else 0)) / total)
        filled = int(frac * width)
        bar = "".join(
            t.paint(t.sym["full"], gradient([AMBER, ORANGE, EMBER], i / max(1, width - 1))) for i in range(filled)
        ) + t.paint(t.sym["empty"] * (width - filled), DIM)
        pct = t.paint(f"{int(frac * 100):3d}%", ORANGE, bold=True)
        return f"{bar} {pct}  {t.paint(f'{finished}/{total} phases', GREY)}"

    def _compose(self) -> list[str]:
        t = self.t
        cols, rows = t.size()
        W = max(64, min(cols - 1, 112))
        P = len(self.phases)
        L = max(5, min(14, rows - (P + 7) - 2))
        sep = t.paint(t.sym["sep"], DIM)
        elapsed = time.time() - self._t_start

        pulse = GREEN if (int(time.time() * 2) % 2 == 0 or self._finished) else DIM
        state = "DONE" if self._finished else "LIVE"
        right = (t.paint(t.sym["dot"], pulse, bold=True) + " " + t.paint(state, GREEN if self._finished else ORANGE, bold=True)
                 + " " + t.paint(fmt_dur(elapsed, clock=True), WHITE))
        lines = [self._rule(W, t.paint(APP_NAME, AMBER, bold=True), right, top=True)]

        m = self.meta
        meta = f" {sep} ".join(
            t.paint(k, DIM) + " " + t.paint(str(m.get(k, "-")), ORANGE)
            for k in ("target", "iface", "profile", "privilege") if k in m or k == "target"
        )
        lines.append(self._row(meta, W))
        lines.append(self._rule(W, t.paint("PIPELINE", AMBER, bold=True)))

        inner = W - 4
        title_w, el_w = 24, 7
        detail_w = max(8, inner - 2 - title_w - 1 - el_w - 1)
        for ph in self.phases.values():
            title_col = {"running": WHITE, "done": GREY, "failed": RED, "warn": AMBER}.get(ph.status, DIM)
            det_col = {"running": CYAN, "failed": RED, "warn": AMBER}.get(ph.status, DIM)
            el = fmt_dur(ph.elapsed()) if ph.t0 else ""
            row = (f"{self._indicator(ph)} "
                   f"{t.paint(ph.title[:title_w].ljust(title_w), title_col, bold=ph.status == 'running')} "
                   f"{t.paint(truncate(ph.detail, detail_w, ellipsis=True).ljust(detail_w), det_col)} "
                   f"{t.paint(el.rjust(el_w), DIM)}")
            lines.append(self._row(row, W))
        lines.append(self._row(self._progress(30), W))

        s = self.stats
        stat_txt = f" {sep} ".join(
            t.paint(label, DIM) + " " + t.paint(str(s.get(key, 0)), ORANGE, bold=True)
            for label, key in (("hosts", "hosts"), ("open ports", "ports"), ("services", "services"), ("findings", "findings"))
        )
        lines.append(self._rule(W, t.paint("LIVE LOG", AMBER, bold=True), stat_txt))

        recent = list(self.logs)[-L:]
        for _ in range(L - len(recent)):
            lines.append(self._row("", W))
        for entry in recent:
            lines.append(self._row(self.format_entry(entry), W))

        hint = t.paint("Ctrl+C aborts and saves a partial report", DIM)
        lines.append(self._rule(W, hint, bottom=True))
        return lines

    # ------------------------------------------------------------------ static output
    def section(self, title: str) -> None:
        t = self.t
        cols = min(t.size()[0] - 1, 100)
        fill = max(2, cols - visible_len(title) - 6)
        t.print()
        t.print(t.paint(f"{t.box['h'] * 2} ", ORANGE) + t.paint(title, AMBER, bold=True)
                + t.paint(f" {t.box['h'] * fill}", ORANGE))

    def kv(self, label: str, value: str, color=ORANGE) -> None:
        self.t.print(f"  {self.t.paint(label.ljust(16), DIM)} {self.t.paint(str(value), color)}")

    def type_out(self, text: str, delay: float = 0.004) -> None:
        typewriter(self.t, text, self.animate, delay)

    def boot_line(self, tag: str, text: str, delay: float = 0.04) -> None:
        colors = {"OK": GREEN, "..": CYAN, "!!": AMBER, "XX": RED}
        label = self.t.paint(f"[ {tag} ]", colors.get(tag, GREY), bold=True)
        self.t.print(f"  {label} {text}")
        if self.animate:
            time.sleep(delay)

    def progress_fill(self, label: str, seconds: float = 0.7, width: int = 28) -> None:
        t = self.t
        if not self.animate:
            return
        steps = 24
        for i in range(steps + 1):
            n = int(width * i / steps)
            bar = "".join(t.paint(t.sym["full"], gradient([AMBER, ORANGE, EMBER], k / max(1, width - 1))) for k in range(n))
            t.write("\r\x1b[2K  " + t.paint(label.ljust(22), GREY) + bar + t.paint(t.sym["empty"] * (width - n), DIM)
                    + " " + t.paint(f"{int(100 * i / steps):3d}%", ORANGE, bold=True))
            time.sleep(seconds / steps)
        t.write("\n")

    def notice_box(self, title: str, lines: list[str]) -> None:
        t, b = self.t, self.t.box
        width = min(t.size()[0] - 1, 78)
        inner = width - 4
        t.print()
        t.print(t.paint(b["tl"] + b["h"] + " ", RED) + t.paint(title, RED, bold=True)
                + t.paint(" " + b["h"] * max(1, width - 5 - len(title)) + b["tr"], RED))
        for ln in lines:
            t.print(t.paint(b["v"], RED) + " " + pad(truncate(sanitize(ln), inner), inner) + " " + t.paint(b["v"], RED))
        t.print(t.paint(b["bl"] + b["h"] * (width - 2) + b["br"], RED))

    def table(self, headers: list[str], rows: list[list[str]], limit: int = 0) -> None:
        """Print a bordered table. Cells may contain ANSI colour; they are width-measured correctly."""
        t, b = self.t, self.t.box
        if limit and len(rows) > limit:
            extra = len(rows) - limit
            rows = rows[:limit] + [[t.paint(f"... {extra} more (see report)", DIM)] + [""] * (len(headers) - 1)]
        widths = [max(visible_len(h), *(visible_len(r[i]) for r in rows)) if rows else visible_len(h)
                  for i, h in enumerate(headers)]
        avail = max(40, t.size()[0] - 1) - (3 * len(headers) + 1)
        while sum(widths) > avail:
            i = widths.index(max(widths))
            if widths[i] <= 8:
                break
            widths[i] -= 1
        line = lambda l, m, r: self._bp(l + m.join(b["h"] * (w + 2) for w in widths) + r)  # noqa: E731
        t.print(line(b["tl"], b["tj"], b["tr"]))
        t.print(self._bp(b["v"]) + self._bp(b["v"]).join(
            " " + pad(t.paint(h, AMBER, bold=True), w) + " " for h, w in zip(headers, widths)) + self._bp(b["v"]))
        t.print(line(b["lj"], b["x"], b["rj"]))
        for r in rows:
            cells = [" " + pad(truncate(c, w, ellipsis=True), w) + " " for c, w in zip(r, widths)]
            t.print(self._bp(b["v"]) + self._bp(b["v"]).join(cells) + self._bp(b["v"]))
        t.print(line(b["bl"], b["bj"], b["br"]))

    # ------------------------------------------------------------------ input
    @staticmethod
    def _rl(prompt: str) -> str:
        """Wrap SGR sequences so readline measures the prompt width correctly."""
        return _SGR_RE.sub("\x01\\1\x02", prompt)

    def ask(self, label: str, default: str | None = None) -> str:
        t = self.t
        hint = f" [{default}]" if default else ""
        t.print(t.paint(f" {t.box['tl']}{t.box['h'] * 2}(", ORANGE) + t.paint("net-strike", AMBER, bold=True)
                + t.paint(")-[", ORANGE) + t.paint(label + hint, WHITE) + t.paint("]", ORANGE))
        try:
            ans = input(self._rl(t.paint(f" {t.box['bl']}{t.box['h']}{t.sym['arrow']} ", ORANGE, bold=True)))
        except EOFError:
            raise KeyboardInterrupt from None
        ans = ans.strip()
        return ans if ans else (default or "")

    def menu(self, title: str, items: list[tuple[str, str]]) -> str:
        t = self.t
        self.section(title)
        for key, text in items:
            t.print(f"  {t.paint('[' + key + ']', ORANGE, bold=True)} {text}")
        t.print()
        return self.ask("select")


# ---------------------------------------------------------------------- results summary


def print_summary(ui: UI, session, paths: dict) -> None:
    t = ui.t
    sm = session.summary()
    ui.section("AUDIT COMPLETE")
    ui.kv("session", session.id)
    ui.kv("duration", fmt_dur(session.duration))
    ui.kv("hosts up", sm["hosts_up"], GREEN if sm["hosts_up"] else AMBER)
    ui.kv("open ports", sm["open_ports"])
    ui.kv("services", sm["services_identified"])
    if session.traffic:
        ui.kv("packets", f"{session.traffic.packets:,}")
    sev = sm["findings"]
    ui.kv("findings", "  ".join(f"{k}:{v}" for k, v in sev.items() if v) or "none",
          RED if sev.get("high") or sev.get("critical") else AMBER if sm["findings_total"] else GREEN)

    hosts = session.sorted_hosts()
    if hosts:
        ui.section("HOSTS")
        rows = []
        for h in hosts:
            ports = [str(p.port) for p in h.open_ports()]
            shown = ",".join(ports[:8]) + (f" +{len(ports) - 8}" if len(ports) > 8 else "")
            rows.append([t.paint(h.ip, ORANGE), h.hostname or "-", (h.os_guess or h.device_type or "-"),
                         shown or "-"])
        ui.table(["IP", "HOSTNAME", "OS / DEVICE", "OPEN PORTS"], rows, limit=20)

    if session.findings:
        ui.section("FINDINGS")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        rows = []
        for f in sorted(session.findings, key=lambda x: order.get(x.severity, 9)):
            col = SEV_COLORS.get(f.severity, GREY)
            where = f.host + (f":{f.port}" if f.port else "")
            rows.append([t.paint(f.severity.upper(), col, bold=True), where or "-", f.title])
        ui.table(["SEVERITY", "WHERE", "FINDING"], rows, limit=15)

    ui.section("OUTPUT")
    for label, path in paths.items():
        ui.kv(label, str(path), GREEN)
    t.print()
