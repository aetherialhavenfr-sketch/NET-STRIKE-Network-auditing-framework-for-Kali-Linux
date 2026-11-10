"""Unit tests (stdlib unittest): run with  python3 -m unittest discover -s tests -v"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from netstrike import banner, findings, parsers  # noqa: E402
from netstrike.models import HostInfo, PortInfo, ScanSession, TrafficSummary  # noqa: E402
from netstrike.reporting.html_report import render_html  # noqa: E402
from netstrike.scope import Scope, ScopeError, parse_target  # noqa: E402
from netstrike.term import Term, sanitize, truncate, visible_len  # noqa: E402
from netstrike.ui import UI  # noqa: E402


class TestScope(unittest.TestCase):
    def test_private_ranges_allowed(self):
        for t in ("192.168.56.0/24", "10.1.2.3", "172.16.0.0/16", "127.0.0.1", "192.168.1.10-20"):
            self.assertTrue(Scope().validate([t]), t)

    def test_public_rejected_unless_in_scope_file(self):
        with self.assertRaises(ScopeError):
            Scope().validate(["8.8.8.8"])
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# authorised\n203.0.113.0/28\n")
        scope = Scope.from_file(fh.name)
        self.assertEqual(str(scope.validate(["203.0.113.5"])[0]), "203.0.113.5/32")
        with self.assertRaises(ScopeError):
            scope.validate(["203.0.113.0/24"])           # wider than the authorised /28

    def test_mixed_targets_fail_closed(self):
        with self.assertRaises(ScopeError) as cm:
            Scope().validate(["192.168.1.1", "8.8.8.8"])
        self.assertIn("8.8.8.8", str(cm.exception))

    def test_size_limit(self):
        with self.assertRaises(ScopeError):
            Scope().validate(["10.0.0.0/8"])
        self.assertTrue(Scope().validate(["10.0.0.0/16"]))

    def test_invalid_inputs(self):
        for bad in ("", "::1", "224.0.0.1", "0.0.0.0/8", "192.168.1.5/24", "bad host!", "192.168.1.9-5"):
            with self.assertRaises(ScopeError, msg=bad):
                parse_target(bad)

    def test_contains_rechecks_discovered_hosts(self):
        s = Scope()
        s.validate(["192.168.56.0/24"])
        self.assertTrue(s.contains("192.168.56.7"))
        self.assertFalse(s.contains("192.168.57.7"))
        self.assertFalse(s.contains("not-an-ip"))


NMAP_XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="VMware, Inc."/><hostnames><hostname name="srv.lab"/></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open"/><service name="http" product="nginx" version="1.24" tunnel="ssl"/>
<script id="ssl-enum-ciphers" output="TLSv1.0: weak"/></port></ports>
<os><osmatch name="Linux 5.x" accuracy="95"><osclass type="general purpose" osfamily="Linux"/></osmatch></os></host></nmaprun>"""


class TestParsers(unittest.TestCase):
    def test_nmap_xml(self):
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as fh:
            fh.write(NMAP_XML)
        host = parsers.parse_nmap_xml(fh.name)[0]
        self.assertEqual(host["ip"], "10.0.0.5")
        self.assertEqual(host["vendor"], "VMware, Inc.")
        self.assertEqual(host["ports"][0]["service"], "ssl/http")
        self.assertEqual(host["os"]["accuracy"], 95)

    def test_nmap_xml_invalid_or_missing(self):
        self.assertEqual(parsers.parse_nmap_xml("/nonexistent.xml"), [])
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as fh:
            fh.write("<nmaprun><host>")
        self.assertEqual(parsers.parse_nmap_xml(fh.name), [])

    def test_masscan_list(self):
        text = "#masscan\nopen tcp 80 10.0.0.1 1700000000\nopen udp 53 10.0.0.2 1700000001\n# end\ngarbage\n"
        self.assertEqual(parsers.parse_masscan_list(text), [("10.0.0.1", 80, "tcp"), ("10.0.0.2", 53, "udp")])

    def test_netdiscover(self):
        text = "192.168.1.1   aa:bb:cc:dd:ee:ff   2   120  Vendor Inc\nnoise line\n192.168.1.1   aa:bb:cc:dd:ee:ff 1 60 dup\n"
        out = parsers.parse_netdiscover(text)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["vendor"], "Vendor Inc")

    def test_ports(self):
        self.assertEqual(parsers.count_ports("1-10,80,443"), 12)
        self.assertEqual(parsers.validate_port_spec("22, 80,1-1024"), "22,80,1-1024")
        for bad in ("0", "70000", "80-20", "abc", "22;rm -rf /"):
            with self.assertRaises(ValueError, msg=bad):
                parsers.validate_port_spec(bad)

    def test_ttl(self):
        self.assertEqual(parsers.parse_ttl("64 bytes from x: icmp_seq=1 ttl=117 time=1 ms"), 117)
        self.assertIn("Windows", parsers.ttl_guess(117))
        self.assertIn("Linux", parsers.ttl_guess(62))

    def test_enum4linux_defensive(self):
        self.assertEqual(parsers.summarize_enum4linux({})["users"], [])
        self.assertEqual(parsers.summarize_enum4linux(None)["shares"], [])
        s = parsers.summarize_enum4linux({
            "sessions_possible": True, "smb_dialects": {"SMB 1.0": True, "Signing required": False},
            "users": {"1": {"username": "bob"}}, "shares": {"x": {"access": {"writing": "ok"}}}})
        self.assertTrue(s["null_session"] and s["smb1_enabled"])
        self.assertIs(s["signing_required"], False)
        self.assertEqual(s["shares"][0]["writing"], "ok")

    def test_traffic_aggregator(self):
        agg = parsers.TrafficAggregator(parsers.TSHARK_FIELDS_MIN)
        f = parsers.TSHARK_FIELDS_MIN
        def row(**kw):
            return "\t".join(kw.get(name.replace(".", "_"), "") for name in f)
        agg.feed(row(frame_len="100", frame_protocols="eth:ethertype:ip:tcp:http", ip_src="10.0.0.1",
                     ip_dst="10.0.0.2", tcp_dstport="80", http_host="a.test"))
        agg.feed(row(frame_len="50", frame_protocols="eth:ethertype:ip:udp:dns", ip_src="10.0.0.2",
                     ip_dst="10.0.0.9", udp_dstport="53", dns_qry_name="b.test"))
        agg.feed("")
        s = agg.summary()
        self.assertEqual((s.packets, s.bytes), (2, 150))
        self.assertEqual(s.cleartext[0]["protocol"], "HTTP")
        self.assertEqual(s.http_hosts[0]["name"], "a.test")
        self.assertEqual(s.conversations[0]["a"], "10.0.0.1")

    def test_arp_anomaly(self):
        fields = parsers.TSHARK_FIELDS
        agg = parsers.TrafficAggregator(fields)
        for mac in ("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"):
            vals = {"frame.len": "60", "frame.protocols": "eth:arp", "arp.src.proto_ipv4": "10.0.0.1", "arp.src.hw_mac": mac}
            agg.feed("\t".join(vals.get(x, "") for x in fields))
        self.assertEqual(agg.summary().arp_anomalies[0]["ip"], "10.0.0.1")


class TestTerm(unittest.TestCase):
    def test_sanitize_strips_escapes(self):
        evil = "ok\x1b[2J\x1b]0;pwned\x07\x00text"
        clean = sanitize(evil)
        self.assertNotIn("\x1b", clean)
        self.assertNotIn("\x07", clean)

    def test_truncate_keeps_ansi(self):
        s = "\x1b[31m" + "x" * 50 + "\x1b[0m"
        t = truncate(s, 10)
        self.assertEqual(visible_len(t), 10)
        self.assertTrue(t.endswith("\x1b[0m"))
        self.assertEqual(visible_len(truncate(s, 10, ellipsis=True)), 10)

    def test_banner_art(self):
        art = banner.art_lines()
        self.assertEqual(len(art), 6)
        self.assertEqual(len({len(r) for r in art}), 1)       # rectangular
        self.assertLessEqual(len(art[0]), 80)


class TestFindings(unittest.TestCase):
    def test_rules(self):
        s = ScanSession(id="t", started="x")
        h = s.host("10.0.0.5")
        h.add_port(PortInfo(23, service="telnet"))
        h.add_port(PortInfo(21, service="ftp", scripts={"ftp-anon": "Anonymous FTP login allowed (FTP code 230)"}))
        h.add_port(PortInfo(445, service="microsoft-ds"))
        h.smb = {"null_session": True, "shares": [{"name": "data", "writing": "ok"}], "users": ["a"]}
        s.traffic = TrafficSummary(cleartext=[{"protocol": "FTP", "packets": 3}])
        findings.analyze(s)
        titles = {f.title for f in s.findings}
        for expected in ("Telnet service exposed", "Anonymous FTP login allowed", "SMB null session allowed",
                         "Writable SMB share 'data' (anonymous)", "Clear-text protocol observed: FTP"):
            self.assertIn(expected, titles)
        n = len(s.findings)
        findings.analyze(s)                                    # idempotent
        self.assertEqual(len(s.findings), n)


class TestUIAndReport(unittest.TestCase):
    def test_dashboard_lines_are_aligned(self):
        ui = UI(Term(io.StringIO()), animate=False)
        for k in ("discovery", "portscan", "report"):
            ui.add_phase(k, k.title())
        ui.set_meta(target="10.0.0.0/24", iface="eth0", profile="quick", privilege="root")
        ui.set_phase("discovery", "done", "3 hosts")
        ui.set_phase("portscan", "running", "masscan sweep")
        for i in range(30):
            ui.log("out", f"line {i} " + "x" * 300, "nmap")
        lines = ui._compose()
        self.assertEqual(len({visible_len(l) for l in lines}), 1, "every dashboard line must be the same width")
        self.assertIn("NET-STRIKE", lines[0])

    def test_html_report_escapes_untrusted_data(self):
        s = ScanSession(id="t", started="x", targets=["10.0.0.0/24"])
        h = HostInfo(ip="10.0.0.5", hostname="<img src=x onerror=alert(1)>")
        h.add_port(PortInfo(80, service="http", product="<script>alert(1)</script>",
                            scripts={"http-title": "</pre><script>steal()</script>"}))
        s.hosts["10.0.0.5"] = h
        s.add_event("warn", "core", "<b>boom</b>")
        out = render_html(s.to_dict())
        for payload in ("<script>alert(1)", "<img src=x", "<script>steal()", "<b>boom</b>"):
            self.assertNotIn(payload, out)
        self.assertEqual(out.count("<script"), 1)               # only the built-in filter script
        self.assertNotIn("http://", out.replace("http://www.w3.org", ""))
        json.dumps(s.to_dict())                                 # serialisable


if __name__ == "__main__":
    unittest.main(verbosity=2)
