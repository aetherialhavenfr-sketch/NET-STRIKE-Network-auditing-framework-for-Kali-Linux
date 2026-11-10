"""Dependency-free ANSI terminal helpers (truecolor with 256-colour fallback)."""

from __future__ import annotations

import os
import re
import shutil
import sys

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

# Palette -----------------------------------------------------------------------
ORANGE = (255, 140, 0)
AMBER = (255, 176, 0)
EMBER = (204, 85, 0)
GREEN = (80, 250, 123)
RED = (255, 85, 85)
CYAN = (102, 217, 239)
GREY = (150, 150, 150)
DIM = (100, 100, 100)
WHITE = (235, 235, 235)

RESET = "\x1b[0m"
HIDE_CURSOR = "\x1b[?25l"
SHOW_CURSOR = "\x1b[?25h"

BOX_UNI = {"tl": "┌", "tr": "┐", "bl": "└", "br": "┘", "h": "─", "v": "│", "lj": "├", "rj": "┤", "tj": "┬", "bj": "┴", "x": "┼"}
BOX_ASCII = {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|", "lj": "+", "rj": "+", "tj": "+", "bj": "+", "x": "+"}

SYM_UNI = {
    "spin": "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏", "ok": "✔", "fail": "✖", "pending": "○", "skip": "◌", "warn": "▲",
    "full": "█", "empty": "░", "dot": "●", "sep": "·", "out": "│", "arrow": "➜",
}
SYM_ASCII = {
    "spin": "|/-\\", "ok": "+", "fail": "x", "pending": "o", "skip": "-", "warn": "!",
    "full": "#", "empty": ".", "dot": "*", "sep": "|", "out": "|", "arrow": ">",
}


def sanitize(text: object) -> str:
    """Strip escape sequences / control characters from untrusted text before display."""
    s = ANSI_RE.sub("", str(text)).replace("\t", "    ")
    return CTRL_RE.sub("", s)


def visible_len(s: str) -> int:
    return len(ANSI_RE.sub("", s))


def truncate(s: str, width: int, ellipsis: bool = False) -> str:
    """Truncate to *width* visible characters, keeping ANSI sequences intact."""
    if width <= 0:
        return ""
    if visible_len(s) <= width:
        return s
    limit = width - 1 if ellipsis else width
    out, n, i = [], 0, 0
    while i < len(s) and n < limit:
        m = ANSI_RE.match(s, i)
        if m:
            out.append(m.group())
            i = m.end()
            continue
        out.append(s[i])
        n += 1
        i += 1
    if ellipsis:
        out.append("…")
    out.append(RESET)
    return "".join(out)


def pad(s: str, width: int) -> str:
    return s + " " * max(0, width - visible_len(s))


def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def mix(c1, c2, t: float):
    return tuple(int(lerp(x, y, t)) for x, y in zip(c1, c2))


def scale(c, k: float):
    return tuple(max(0, min(255, int(v * k))) for v in c)


def gradient(stops, t: float):
    """Sample a multi-stop gradient at position t in [0, 1]."""
    t = max(0.0, min(1.0, t))
    if len(stops) == 1:
        return stops[0]
    pos = t * (len(stops) - 1)
    i = min(int(pos), len(stops) - 2)
    return mix(stops[i], stops[i + 1], pos - i)


def _to256(r: int, g: int, b: int) -> int:
    if r == g == b:
        if r < 8:
            return 16
        if r > 248:
            return 231
        return round((r - 8) / 247 * 24) + 232
    return 16 + 36 * round(r / 255 * 5) + 6 * round(g / 255 * 5) + round(b / 255 * 5)


def fmt_dur(seconds: float, clock: bool = False) -> str:
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if clock:
        return f"{h:02d}:{m:02d}:{s:02d}"
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


class Term:
    """Thin wrapper around an output stream that knows what it can render."""

    def __init__(self, stream=None, color: bool | None = None):
        self.stream = stream or sys.stdout
        self.is_tty = bool(getattr(self.stream, "isatty", lambda: False)())
        if color is None:
            color = self.is_tty and "NO_COLOR" not in os.environ and os.environ.get("TERM", "") != "dumb"
        self.color = color
        ct = os.environ.get("COLORTERM", "").lower()
        self.truecolor = self.color and ct in ("truecolor", "24bit")
        enc = (getattr(self.stream, "encoding", None) or "").lower()
        self.utf8 = "utf" in enc
        self.box = BOX_UNI if self.utf8 else BOX_ASCII
        self.sym = SYM_UNI if self.utf8 else SYM_ASCII

    # -- geometry ------------------------------------------------------------
    def size(self) -> tuple[int, int]:
        sz = shutil.get_terminal_size((100, 30))
        return sz.columns, sz.lines

    # -- output --------------------------------------------------------------
    def write(self, s: str) -> None:
        try:
            self.stream.write(s)
            self.stream.flush()
        except (BrokenPipeError, ValueError):
            pass

    def print(self, s: str = "") -> None:
        self.write(s + "\n")

    # -- colour --------------------------------------------------------------
    def fg(self, rgb) -> str:
        if not self.color:
            return ""
        r, g, b = (int(max(0, min(255, v))) for v in rgb)
        if self.truecolor:
            return f"\x1b[38;2;{r};{g};{b}m"
        return f"\x1b[38;5;{_to256(r, g, b)}m"

    def paint(self, text: str, rgb=None, bold: bool = False, dim: bool = False) -> str:
        if not self.color:
            return text
        pre = ("\x1b[1m" if bold else "") + ("\x1b[2m" if dim else "") + (self.fg(rgb) if rgb else "")
        return f"{pre}{text}{RESET}" if pre else text

    def asciify(self, text: str) -> str:
        if self.utf8:
            return text
        table = str.maketrans({"█": "#", "╗": "+", "╔": "+", "╝": "+", "╚": "+", "═": "=", "║": "|",
                               "•": "*", "▀": "^", "▄": "_", "⚠": "!", "·": "|", "─": "-", "│": "|"})
        return text.translate(table)

    def hide_cursor(self) -> None:
        if self.is_tty:
            self.write(HIDE_CURSOR)

    def show_cursor(self) -> None:
        if self.is_tty:
            self.write(SHOW_CURSOR)
