"""Integration tests: run the real CLI against fake nmap/masscan/tshark/... executables in tests/fake_bin."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAKE_BIN = ROOT / "tests" / "fake_bin"


def setUpModule() -> None:
    """Copy the fake tools to a temp dir with the executable bit set (zip/download/mounts may drop it)."""
    global FAKE_BIN
    tmp = Path(tempfile.mkdtemp(prefix="fakebin-"))
    for src in (ROOT / "tests" / "fake_bin").iterdir():
        shutil.copy(src, tmp / src.name)
        (tmp / src.name).chmod(0o755)
    FAKE_BIN = tmp


def run_cli(*args: str, path: str | None = None, stdin: str | None = None):
    home = tempfile.mkdtemp(prefix="nshome-")
    env = dict(os.environ, HOME=home, PATH=path if path is not None else f"{FAKE_BIN}:{os.environ['PATH']}",
               NO_COLOR="1", PYTHONIOENCODING="utf-8")
    env.pop("SUDO_USER", None)
    return subprocess.run([sys.executable, str(ROOT / "netstrike.py"), "--no-anim", "--no-banner", *args],
                          capture_output=True, text=True, env=env, input=stdin or "", timeout=120, cwd=ROOT)


def load_report(out: str) -> dict:
    return json.loads(next(Path(out).glob("netstrike-*/report.json")).read_text(encoding="utf-8"))


class TestPipeline(unittest.TestCase):
    def test_full_scan(self):
        with tempfile.TemporaryDirectory() as out:
            r = run_cli("scan", "192.168.56.0/24", "--i-am-authorized", "--duration", "1", "-o", out)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            d = load_report(out)
            self.assertEqual({h["ip"] for h in d["hosts"]}, {"192.168.56.10", "192.168.56.20"})   # 10.9.9.9 dropped
            titles = {f["title"] for f in d["findings"]}
            for expected in ("Anonymous FTP login allowed", "SMB null session allowed", "RDP exposed",
                             "Clear-text protocol observed: FTP"):
                self.assertIn(expected, titles)
            self.assertEqual(d["summary"]["open_ports"], 7)
            html = next(Path(out).glob("netstrike-*/report.html")).read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", html)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)

    def test_missing_tools_degrade_gracefully(self):
        with tempfile.TemporaryDirectory() as out:
            r = run_cli("scan", "192.168.56.0/24", "--i-am-authorized", "-o", out, path="/nonexistent")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            d = load_report(out)
            statuses = {p["key"]: p["status"] for p in d["phases"]}
            self.assertEqual(statuses["discovery"], "skipped")
            self.assertEqual(statuses["portscan"], "skipped")
            self.assertEqual(d["hosts"], [])

    def test_offline_pcap_analysis(self):
        with tempfile.TemporaryDirectory() as out:
            pcap = Path(out) / "x.pcapng"
            pcap.write_bytes(b"fake")
            r = run_cli("analyze", str(pcap), "-o", out)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            d = load_report(out)
            self.assertEqual(d["traffic"]["source"], "pcap")
            self.assertEqual(d["traffic"]["packets"], 7)

    def test_report_regeneration(self):
        with tempfile.TemporaryDirectory() as out:
            run_cli("scan", "192.168.56.0/24", "--i-am-authorized", "-m", "discovery", "-o", out)
            js = next(Path(out).glob("netstrike-*/report.json"))
            html = js.with_suffix(".html")
            html.unlink()
            r = run_cli("report", str(js))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue(html.exists())


class TestSafety(unittest.TestCase):
    def test_out_of_scope_target_refused(self):
        r = run_cli("scan", "8.8.8.8", "--i-am-authorized")
        self.assertEqual(r.returncode, 2)
        self.assertIn("outside authorized scope", r.stdout + r.stderr)

    def test_authorization_required_non_interactive(self):
        r = run_cli("scan", "192.168.56.0/24")
        self.assertEqual(r.returncode, 2)
        self.assertIn("authorization not confirmed", r.stdout + r.stderr)

    def test_bad_arguments_rejected(self):
        self.assertEqual(run_cli("scan", "10.0.0.1", "--i-am-authorized", "--ports", "22;id").returncode, 2)
        self.assertEqual(run_cli("scan", "10.0.0.1", "--i-am-authorized", "-m", "exploit").returncode, 2)
        self.assertNotEqual(run_cli("scan", "10.0.0.1", "--rate", "99999999").returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
