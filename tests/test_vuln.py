"""Tests for the vulnerability module: parsing, ranking, and safe validation."""
import unittest
from pathlib import Path

from packetwatch.vuln.model import Prioritiser
from packetwatch.vuln.openvas import parse_report, summarise
from packetwatch.vuln.validate import Check, is_local_target, validate

REPORT = Path(__file__).parent / "fixtures" / "openvas_report.xml"


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.findings = parse_report(REPORT)

    def test_reads_every_result(self):
        self.assertEqual(len(self.findings), 4)

    def test_extracts_fields_and_cves(self):
        smb = self.findings[0]
        self.assertEqual(smb.host, "192.168.0.50")
        self.assertEqual(smb.port_number, 445)
        self.assertEqual(smb.protocol, "tcp")
        self.assertEqual(smb.severity, 9.3)
        self.assertIn("CVE-2017-0144", smb.cves)

    def test_finds_cve_mentioned_only_in_text(self):
        ssh = self.findings[1]
        self.assertIn("CVE-2023-38408", ssh.cves)

    def test_portless_finding_has_no_number(self):
        self.assertIsNone(self.findings[2].port_number)

    def test_summary_counts(self):
        info = summarise(self.findings)
        self.assertEqual(info["findings"], 4)
        self.assertEqual(info["threats"]["High"], 2)
        self.assertEqual(info["unique_cves"], 3)


class RankingTests(unittest.TestCase):
    def setUp(self):
        self.findings = parse_report(REPORT)
        # fixed feeds so the test does not depend on downloaded data
        self.p = Prioritiser(tree=None,
                             kev={"CVE-2017-0144": "2022-03-03"},
                             epss={"CVE-2021-41773": 0.94, "CVE-2023-38408": 0.02})

    def test_kev_outranks_everything(self):
        ranked = self.p.rank(self.findings)
        top, finding = ranked[0]
        self.assertEqual(top.cve, "CVE-2017-0144")
        self.assertEqual(top.basis, "kev")
        self.assertEqual(top.band, "CRITICAL")
        self.assertEqual(finding.port_number, 445)

    def test_high_epss_outranks_low_epss(self):
        order = [p.cve for p, _ in self.p.rank(self.findings)]
        self.assertLess(order.index("CVE-2021-41773"), order.index("CVE-2023-38408"))

    def test_every_item_explains_itself(self):
        for priority, _ in self.p.rank(self.findings):
            self.assertTrue(priority.reason)
            self.assertIn(priority.basis, {"kev", "epss", "tree", "cvss", "scanner"})

    def test_finding_without_cve_falls_back_to_scanner_severity(self):
        ranked = dict((f.name, p) for p, f in self.p.rank(self.findings))
        info = ranked["TCP Timestamps Information Disclosure"]
        self.assertEqual(info.basis, "scanner")
        self.assertEqual(info.band, "LOW")

    def test_epss_reason_quotes_the_probability(self):
        for priority, _ in self.p.rank(self.findings):
            if priority.cve == "CVE-2021-41773":
                self.assertIn("94", priority.reason)


class ValidationTests(unittest.TestCase):
    def test_private_addresses_are_local(self):
        self.assertTrue(is_local_target("192.168.0.50"))
        self.assertTrue(is_local_target("127.0.0.1"))
        self.assertFalse(is_local_target("203.0.113.10"))
        self.assertFalse(is_local_target("scanme.example.com"))

    def test_external_hosts_are_skipped_by_default(self):
        findings = parse_report(REPORT)
        p = Prioritiser(tree=None, kev={}, epss={"CVE-2021-41773": 0.94})
        results = validate(p.rank(findings), limit=5)
        external = [c for c, _, _ in results if c.host == "203.0.113.10"]
        self.assertTrue(external)
        self.assertFalse(external[0].reachable)
        self.assertIn("not a private address", external[0].detail)

    def test_closed_port_reports_unreachable(self):
        from packetwatch.vuln.validate import check_port

        check = check_port("127.0.0.1", 9, timeout=0.5)   # discard port, closed
        self.assertIsInstance(check, Check)
        self.assertFalse(check.reachable)

    def test_open_port_is_detected(self):
        import socket
        import threading

        from packetwatch.vuln.validate import check_port

        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        threading.Thread(target=lambda: srv.accept(), daemon=True).start()
        try:
            check = check_port("127.0.0.1", port, timeout=1.0)
            self.assertTrue(check.reachable)
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()
