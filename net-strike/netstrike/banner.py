"""Startup banner: MSTFAXNAF in huge, bold block letters with an orange -> dark-orange gradient."""

from __future__ import annotations

import time

from .config import APP_NAME, VERSION
from .term import AMBER, DIM, GREY, ORANGE, RED, Term, gradient, mix, scale

_GLYPHS = {
    "M": ["███╗   ███╗", "████╗ ████║", "██╔████╔██║", "██║╚██╔╝██║", "██║ ╚═╝ ██║", "╚═╝     ╚═╝"],
    "S": ["███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"],
    "T": ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
    "F": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "██║     ", "╚═╝     "],
    "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "X": ["██╗  ██╗", "╚██╗██╔╝", " ╚███╔╝ ", " ██╔██╗ ", "██╔╝ ██╗", "╚═╝  ╚═╝"],
    "N": ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
}
_WORD = "MSTFAXNAF"


def _build() -> list[str]:
    rows = []
    for r in range(6):
        rows.append("".join(_GLYPHS[ch][r].ljust(len(_GLYPHS[ch][0])) for ch in _WORD))
    return rows


ART = _build()
ART_H = len(ART)
ART_W = max(len(r) for r in ART)

# orange -> dark orange -> burnt orange
STOPS = [(255, 176, 0), (255, 140, 0), (255, 106, 0), (204, 72, 0)]
GLOW = (255, 236, 190)


def art_lines() -> list[str]:
    """Plain (uncoloured) art lines - used by the HTML report."""
    return list(ART)


def _cell_color(row: int, col: int, ch: str, shimmer: float | None):
    t = 0.80 * row / (ART_H - 1) + 0.20 * col / max(1, ART_W - 1)
    rgb = gradient(STOPS, t)
    if ch != "█":                       # box-drawing "shadow" is darker => 3D look
        rgb = scale(rgb, 0.60)
    if shimmer is not None:
        d = abs((col + row * 3) - shimmer)
        if d < 9:
            rgb = mix(rgb, GLOW, (1 - d / 9) * 0.85)
    return rgb


def _render_row(term: Term, row: int, shimmer: float | None = None) -> str:
    text = ART[row]
    if not term.color:
        return term.asciify(text)
    out = []
    for col, ch in enumerate(text):
        if ch == " ":
            out.append(" ")
        else:
            out.append(f"{term.fg(_cell_color(row, col, ch, shimmer))}\x1b[1m{ch}")
    out.append("\x1b[0m")
    return "".join(out)


def typewriter(term: Term, text: str, animate: bool, delay: float = 0.004) -> None:
    if not animate:
        term.print(text)
        return
    # text may carry ANSI escapes: emit escapes whole, delay only on visible characters
    from .term import ANSI_RE

    i = 0
    while i < len(text):
        m = ANSI_RE.match(text, i)
        if m:
            term.stream.write(m.group())
            i = m.end()
            continue
        term.stream.write(text[i])
        term.stream.flush()
        time.sleep(delay)
        i += 1
    term.stream.write("\n")
    term.stream.flush()


def compact_banner(term: Term) -> None:
    text = "[ " + " ".join(_WORD) + " ]"
    term.print(term.paint(text, ORANGE, bold=True))


def show_banner(term: Term, animate: bool = True) -> None:
    """Print the startup banner, with a reveal + shimmer animation on capable terminals."""
    cols, _ = term.size()
    animate = animate and term.is_tty and term.color
    term.print()

    if cols < ART_W + 2:
        compact_banner(term)
    elif not animate:
        for r in range(ART_H):
            term.print(_render_row(term, r))
    else:
        term.hide_cursor()
        try:
            for r in range(ART_H):                       # reveal row by row
                term.print(_render_row(term, r))
                time.sleep(0.055)
            span = ART_W + ART_H * 3 + 12
            for pos in range(-10, span, 3):              # one shimmer sweep
                frame = "\n".join(_render_row(term, r, pos) for r in range(ART_H))
                term.write(f"\x1b[{ART_H}A\r" + frame + "\n")
                time.sleep(0.012)
            term.write(f"\x1b[{ART_H}A\r" + "\n".join(_render_row(term, r) for r in range(ART_H)) + "\n")
        finally:
            term.show_cursor()

    sub_a = (
        term.paint("  ▀▄▀▄ ", ORANGE) + term.paint(f"{APP_NAME}", AMBER, bold=True)
        + term.paint(" ▄▀▄▀", ORANGE) + term.paint("  //  network auditing framework  ", GREY)
        + term.paint(f"v{VERSION}", ORANGE, bold=True)
    )
    sub_b = term.paint("  [ discover • identify • enumerate • analyze • report ]", DIM)
    sub_c = term.paint("  ⚠  authorized networks & lab environments only", RED, bold=True)
    for line in (sub_a, sub_b, sub_c):
        typewriter(term, term.asciify(line) if not term.utf8 else line, animate)
    term.print()
