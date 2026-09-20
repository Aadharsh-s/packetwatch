import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP

from packetwatch import config
from packetwatch.features import FEATURE_NAMES, SourceWindow
from packetwatch.model import ATTACK_PROFILES, BENIGN_PROFILES, Detector, train
from packetwatch.pipeline import Pipeline
from packetwatch.response import Alerter, FirewallBlocker
from packetwatch.verify import Correlator, verify

ATTACKER = "192.168.1.66"
HOST = "192.168.1.10"


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")


class FixedDetector:
    """Detector stub with a constant verdict, matching the real interface."""

    verdict = {}

    def predict(self, vec):
        return dict(self.verdict)

    def predict_many(self, vecs):
        return [dict(self.verdict) for _ in vecs]


class StubDetector(FixedDetector):
    """Always flags, to test that verification alone gates blocking."""

    verdict = {"dt": True, "nb": False, "dt_proba": 1.0, "nb_proba": 0.0,
               "flagged": True}


class BlindDetector(FixedDetector):
    """Never flags, to test the independent rule trigger."""

    verdict = {"dt": False, "nb": False, "dt_proba": 0.0, "nb_proba": 0.0,
               "flagged": False}


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dt, nb = train(verbose=False)
        cls.detector = Detector(dt, nb)

    def setUp(self):
        self.clock = FakeClock()
        self.runner = FakeRunner()
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "alerts.log"
        self.blocker = FirewallBlocker(runner=self.runner, ttl_min=0,
                                       whitelist={"192.168.1.1"})
        self.pipe = Pipeline(self.detector, self.blocker, Alerter(self.log),
                             own_addresses={HOST}, clock=self.clock)

    def tearDown(self):
        self.tmp.cleanup()

    def feed(self, pkts, spacing):
        for p in pkts:
            self.pipe.handle(p)
            self.clock.t += spacing
        self.pipe.sweep(force=True)  # what the ticker / shutdown does

    def alerts(self):
        if not self.log.exists():
            return []
        return [json.loads(l) for l in self.log.read_text().splitlines()]

    def test_port_scan_is_blocked_with_netsh(self):
        self.feed([IP(src=ATTACKER, dst=HOST) / TCP(dport=p, flags="S")
                   for p in range(1, 60)], spacing=0.05)
        self.assertIn(ATTACKER, self.blocker.blocked)
        self.assertEqual(self.runner.calls[0], [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=PacketWatch_Block_{ATTACKER}_in", "dir=in", "action=block",
            f"remoteip={ATTACKER}", "enable=yes"])
        self.assertIn("dir=out", self.runner.calls[1])
        alert = self.alerts()[0]
        self.assertIn("port_scan", [h["rule"] for h in alert["rule_hits"]])
        self.assertEqual(alert["action"], "blocked")

    def test_flood_is_blocked(self):
        self.feed([IP(src=ATTACKER, dst=HOST) / UDP(dport=53) for _ in range(400)],
                  spacing=0.004)
        self.assertIn(ATTACKER, self.blocker.blocked)
        self.assertIn("packet_flood", [h["rule"] for h in self.alerts()[0]["rule_hits"]])

    def test_icmp_flood_is_blocked(self):
        self.feed([IP(src=ATTACKER, dst=HOST) / ICMP() for _ in range(400)], spacing=0.004)
        self.assertIn(ATTACKER, self.blocker.blocked)

    def test_benign_browsing_not_blocked(self):
        pkts = [IP(src="142.250.1.1", dst=HOST) / TCP(sport=443, dport=443, flags="A")
                / (b"x" * 900) for _ in range(150)]
        self.feed(pkts, spacing=0.05)
        self.assertEqual(self.blocker.blocked, set())
        self.assertEqual(self.runner.calls, [])

    def test_ml_flag_without_rule_hit_is_not_blocked(self):
        pipe = Pipeline(StubDetector(), self.blocker, Alerter(self.log),
                        own_addresses={HOST}, clock=self.clock)
        for p in range(1, 6):  # 5 ports: below every rule threshold
            pipe.handle(IP(src=ATTACKER, dst=HOST) / TCP(dport=8000 + p, flags="S"))
            self.clock.t += 1.1
        self.assertGreater(pipe.stats["ml_flagged"], 0)
        self.assertEqual(pipe.stats["confirmed"], 0)
        self.assertEqual(self.runner.calls, [])

    def test_two_rules_block_even_when_ml_misses(self):
        """An unseen attack type the classifiers miss is still blocked on 2+ rules."""
        pipe = Pipeline(BlindDetector(), self.blocker, Alerter(self.log),
                        own_addresses={HOST}, clock=self.clock)
        ports = sorted(config.SUSPICIOUS_PORTS) + list(range(3000, 3200))
        for p in ports:  # port_scan + suspicious_port + flood
            pipe.handle(IP(src=ATTACKER, dst=HOST) / TCP(dport=p, flags="S"))
            self.clock.t += 0.004
        pipe.sweep(force=True)
        self.assertIn(ATTACKER, self.blocker.blocked)
        alert = self.alerts()[0]
        self.assertEqual(alert["trigger"], "rules-only")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(pipe.stats["rule_triggered"], 1)

    def test_single_rule_without_ml_does_not_block(self):
        """One rule alone is not enough: the ML must agree."""
        pipe = Pipeline(BlindDetector(), self.blocker, Alerter(self.log),
                        own_addresses={HOST}, clock=self.clock)
        for p in range(4000, 4060):  # port_scan only
            pipe.handle(IP(src=ATTACKER, dst=HOST) / TCP(dport=p, flags="S"))
            self.clock.t += 0.05
        pipe.sweep(force=True)
        self.assertEqual(self.blocker.blocked, set())
        self.assertEqual(self.runner.calls, [])

    def test_trigger_recorded_for_ml_confirmed_block(self):
        self.feed([IP(src=ATTACKER, dst=HOST) / TCP(dport=p, flags="S")
                   for p in range(5000, 5060)], spacing=0.05)
        self.assertEqual(self.alerts()[0]["trigger"], "ml+rule")

    def test_two_rules_block_even_when_ml_misses(self):
        """An unseen attack type the classifiers miss is still blocked on 2+ rules."""
        pipe = Pipeline(BlindDetector(), self.blocker, Alerter(self.log),
                        own_addresses={HOST}, clock=self.clock)
        ports = sorted(config.SUSPICIOUS_PORTS) + list(range(3000, 3200))
        for p in ports:  # port_scan + suspicious_port + flood
            pipe.handle(IP(src=ATTACKER, dst=HOST) / TCP(dport=p, flags="S"))
            self.clock.t += 0.004
        pipe.sweep(force=True)
        self.assertIn(ATTACKER, self.blocker.blocked)
        alert = self.alerts()[0]
        self.assertEqual(alert["trigger"], "rules-only")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(pipe.stats["rule_triggered"], 1)

    def test_single_rule_without_ml_does_not_block(self):
        """One rule alone is not enough: the classifiers must agree."""
        pipe = Pipeline(BlindDetector(), self.blocker, Alerter(self.log),
                        own_addresses={HOST}, clock=self.clock)
        for p in range(4000, 4060):  # port_scan only, spread out so no flood
            pipe.handle(IP(src=ATTACKER, dst=HOST) / TCP(dport=p, flags="S"))
            self.clock.t += 0.05
        pipe.sweep(force=True)
        self.assertEqual(self.blocker.blocked, set())
        self.assertEqual(self.runner.calls, [])

    def test_trigger_recorded_for_ml_confirmed_block(self):
        self.feed([IP(src=ATTACKER, dst=HOST) / TCP(dport=p, flags="S")
                   for p in range(5000, 5060)], spacing=0.05)
        self.assertEqual(self.alerts()[0]["trigger"], "ml+rule")

    def test_own_and_whitelisted_ips_never_blocked(self):
        for src in (HOST, "192.168.1.1", "127.0.0.1"):
            self.feed([IP(src=src, dst="10.0.0.5") / TCP(dport=p, flags="S")
                       for p in range(1, 60)], spacing=0.05)
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(self.blocker.block("192.168.1.1"), "skipped (whitelisted)")

    def test_multiple_rules_escalate_to_critical(self):
        # fast scan across suspicious ports: port_scan + suspicious_port + flood
        ports = sorted(config.SUSPICIOUS_PORTS) + list(range(1000, 1200))
        self.feed([IP(src=ATTACKER, dst=HOST) / TCP(dport=p, flags="S") for p in ports],
                  spacing=0.004)
        alert = self.alerts()[0]
        self.assertGreaterEqual(len(alert["rule_hits"]), 2)
        self.assertEqual(alert["severity"], "CRITICAL")

    def test_dry_run_does_not_execute(self):
        blocker = FirewallBlocker(dry_run=True, runner=self.runner, ttl_min=0)
        self.assertEqual(blocker.block("203.0.113.50"), "dry-run block")
        self.assertEqual(self.runner.calls, [])

    def test_invalid_ip_rejected(self):
        with self.assertRaises(ValueError):
            self.blocker.block("1.2.3.4 & calc.exe")

    def test_unblock_all_parses_netsh_output(self):
        out = ("Rule Name:   PacketWatch_Block_1.2.3.4_in\n----\n"
               "Rule Name:   Some Other Rule\n"
               "Rule Name:   PacketWatch_Block_1.2.3.4_out\n")

        def runner(cmd, **kw):
            self.runner.calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, out, "")

        blocker = FirewallBlocker(runner=runner, ttl_min=0)
        removed = blocker.unblock_all()
        self.assertEqual(removed, ["PacketWatch_Block_1.2.3.4_in",
                                   "PacketWatch_Block_1.2.3.4_out"])


class ModelTests(unittest.TestCase):
    def test_both_classifiers_separate_profiles(self):
        import random

        dt, nb = train(verbose=False)
        det = Detector(dt, nb)
        r = random.Random(7)
        attacks = [det.predict(p(r)) for p in ATTACK_PROFILES for _ in range(50)]
        benign = [det.predict(p(r)) for p in BENIGN_PROFILES for _ in range(50)]
        self.assertGreater(sum(a["dt"] for a in attacks) / len(attacks), 0.95)
        self.assertLess(sum(b["dt"] for b in benign) / len(benign), 0.05)
        self.assertGreater(sum(a["flagged"] for a in attacks) / len(attacks), 0.95)
        for res in attacks + benign:
            self.assertEqual(res["flagged"], res["dt"] or res["nb"])

    def test_batched_prediction_matches_single(self):
        import random

        dt, nb = train(verbose=False)
        det = Detector(dt, nb)
        r = random.Random(11)
        vecs = [p(r) for p in ATTACK_PROFILES + BENIGN_PROFILES for _ in range(20)]
        self.assertEqual(det.predict_many(vecs), [det.predict(v) for v in vecs])


class PacketLengthTests(unittest.TestCase):
    def test_uses_ip_header_length_for_sniffed_packets(self):
        from packetwatch.pipeline import packet_length

        wire = bytes(IP(src=ATTACKER, dst=HOST) / TCP(dport=80) / (b"x" * 200))
        sniffed = IP(wire)                       # as Scapy hands it to the handler
        self.assertEqual(packet_length(sniffed, sniffed), len(wire))

    def test_falls_back_for_crafted_packets(self):
        from packetwatch.pipeline import packet_length

        pkt = IP(src=ATTACKER, dst=HOST) / TCP(dport=80) / (b"y" * 50)
        self.assertEqual(packet_length(pkt, pkt[IP]), len(bytes(pkt)))

    def test_length_reaches_the_feature_vector(self):
        wire = bytes(IP(src=ATTACKER, dst=HOST) / TCP(dport=80) / (b"z" * 500))
        for _ in range(3):
            self.pipe_for_length().handle(IP(wire))

    def pipe_for_length(self):
        blocker = FirewallBlocker(runner=FakeRunner(), ttl_min=0)
        return Pipeline(StubDetector(), blocker, Alerter(None, console=False),
                        own_addresses={HOST})


class RiskMapTests(unittest.TestCase):
    """Module 1 feeding Module 2: scan findings change how traffic is judged."""

    def setUp(self):
        from packetwatch.riskmap import RiskMap

        self.clock = FakeClock()
        self.runner = FakeRunner()
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "alerts.log"
        self.blocker = FirewallBlocker(runner=self.runner, ttl_min=0)
        self.risk = RiskMap({445: {"band": "CRITICAL", "cve": "CVE-2017-0144",
                                   "reason": "listed in CISA KEV", "host": HOST,
                                   "score": 100.0}})

    def tearDown(self):
        self.tmp.cleanup()

    def pipe(self, detector, risk):
        return Pipeline(detector, self.blocker, Alerter(self.log, console=False),
                        own_addresses={HOST}, clock=self.clock, risk_map=risk)

    def scan_one_port(self, pipe, port, n=60):
        """A port scan whose only rule hit is port_scan, aimed at one service."""
        for i in range(n):
            pipe.handle(IP(src=ATTACKER, dst=HOST) / TCP(dport=port, flags="S"))
            pipe.handle(IP(src=ATTACKER, dst=HOST) / TCP(dport=9000 + i, flags="S"))
            self.clock.t += 0.05
        pipe.sweep(force=True)

    def alerts(self):
        if not self.log.exists():
            return []
        return [json.loads(l) for l in self.log.read_text().splitlines()]

    def test_single_rule_blocks_when_target_is_known_vulnerable(self):
        pipe = self.pipe(BlindDetector(), self.risk)   # classifiers miss it entirely
        self.scan_one_port(pipe, 445)
        self.assertIn(ATTACKER, self.blocker.blocked)
        alert = self.alerts()[0]
        self.assertEqual(alert["trigger"], "rules-only")
        self.assertEqual(alert["targets_known_vulnerability"]["cve"], "CVE-2017-0144")

    def test_same_traffic_elsewhere_needs_two_rules(self):
        from packetwatch.riskmap import RiskMap

        pipe = self.pipe(BlindDetector(), RiskMap())
        self.scan_one_port(pipe, 8123)
        self.assertEqual(self.blocker.blocked, set())
        self.assertEqual(self.runner.calls, [])

    def test_severity_is_escalated_for_at_risk_ports(self):
        pipe = self.pipe(StubDetector(), self.risk)
        self.scan_one_port(pipe, 445)
        self.assertEqual(self.alerts()[0]["severity"], "CRITICAL")
        self.assertEqual(pipe.stats["risk_escalated"], 1)

    def test_ordinary_ports_keep_their_severity(self):
        from packetwatch.riskmap import RiskMap

        pipe = self.pipe(StubDetector(), RiskMap())
        self.scan_one_port(pipe, 8123)
        self.assertEqual(self.alerts()[0]["severity"], "HIGH")
        self.assertEqual(pipe.stats["risk_escalated"], 0)

    def test_map_is_built_from_the_vuln_module_output(self):
        from packetwatch.riskmap import RiskMap

        payload = {"ranking": [
            {"cve": "CVE-2017-0144", "band": "CRITICAL", "score": 100.0,
             "port": "445/tcp", "host": HOST, "reason": "KEV"},
            {"cve": "CVE-2023-1111", "band": "MEDIUM", "score": 30.0,
             "port": "8080/tcp", "host": HOST, "reason": "tree"},
            {"cve": "", "band": "LOW", "score": 2.6, "port": "general/tcp",
             "host": HOST, "reason": "scanner"},
        ]}
        path = Path(self.tmp.name) / "risk.json"
        path.write_text(json.dumps(payload))
        rm = RiskMap.from_json(path)
        self.assertEqual(set(rm.ports), {445})       # MEDIUM and portless are ignored
        self.assertEqual(rm.lookup({445, 80})["cve"], "CVE-2017-0144")
        self.assertIsNone(rm.lookup({80, 443}))

    def test_worst_finding_wins_for_a_port(self):
        from packetwatch.riskmap import RiskMap

        payload = {"ranking": [
            {"cve": "CVE-A", "band": "HIGH", "score": 60.0, "port": "445/tcp"},
            {"cve": "CVE-B", "band": "CRITICAL", "score": 100.0, "port": "445/tcp"},
        ]}
        path = Path(self.tmp.name) / "risk2.json"
        path.write_text(json.dumps(payload))
        self.assertEqual(RiskMap.from_json(path).ports[445]["cve"], "CVE-B")


class CalibrationTests(unittest.TestCase):
    def samples(self, ports, pps, susp, n=1000):
        """n feature vectors whose three rule columns hold the given values."""
        from packetwatch.features import FEATURE_NAMES

        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        out = []
        for i in range(n):
            vec = [0] * len(FEATURE_NAMES)
            vec[idx["unique_dst_ports"]] = ports[i % len(ports)]
            vec[idx["pkts_per_sec"]] = pps[i % len(pps)]
            vec[idx["suspicious_port_hits"]] = susp[i % len(susp)]
            out.append(vec)
        return out

    def test_thresholds_follow_the_observed_traffic(self):
        from packetwatch.calibrate import thresholds_from_samples

        busy = thresholds_from_samples(self.samples([20, 30, 40], [300, 500], [10, 20]))
        quiet = thresholds_from_samples(self.samples([1, 2], [3, 5], [0, 0]))
        self.assertGreater(busy["flood_pps"], quiet["flood_pps"])
        self.assertGreater(busy["port_scan"], quiet["port_scan"])

    def test_floors_and_ceilings_are_respected(self):
        from packetwatch.calibrate import CEILINGS, FLOORS, thresholds_from_samples

        quiet = thresholds_from_samples(self.samples([0], [0], [0]))
        self.assertEqual(quiet, FLOORS)
        wild = thresholds_from_samples(self.samples([9999], [99999], [9999]))
        self.assertEqual(wild, CEILINGS)

    def test_empty_baseline_is_rejected(self):
        from packetwatch.calibrate import thresholds_from_samples

        with self.assertRaises(ValueError):
            thresholds_from_samples([])

    def test_saved_file_round_trips(self):
        import json

        from packetwatch.calibrate import save, thresholds_from_samples

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "thresholds.json"
            th = thresholds_from_samples(self.samples([12], [200], [4]))
            save(th, path)
            loaded = json.loads(path.read_text())
            for key, value in th.items():
                self.assertEqual(loaded[key], value)
            self.assertIn("calibrated_at", loaded)


class VerifyTests(unittest.TestCase):
    def test_thresholds_are_inclusive(self):
        w = SourceWindow()
        for p in range(config.PORT_SCAN_THRESHOLD):
            w.add(100.0 + p * 0.5, p + 2000, HOST, 6, True, 60)
        self.assertEqual([h.rule for h in verify(w)], ["port_scan"])

    def test_vector_and_batch_rules_agree(self):
        """The offline evaluations must test exactly the live thresholds."""
        import random

        from packetwatch.verify import rule_counts, verify_vector

        r = random.Random(5)
        rows = [[r.randint(0, 300) for _ in FEATURE_NAMES] for _ in range(200)]
        counts = rule_counts(rows)
        for row, n in zip(rows, counts):
            self.assertEqual(len(verify_vector(row)), n)

    def test_rules_follow_calibrated_thresholds(self):
        from packetwatch import config
        from packetwatch.verify import verify_vector

        idx = FEATURE_NAMES.index("unique_dst_ports")
        vec = [0] * len(FEATURE_NAMES)
        vec[idx] = config.PORT_SCAN_THRESHOLD
        self.assertEqual([h.rule for h in verify_vector(vec)], ["port_scan"])
        original = config.PORT_SCAN_THRESHOLD
        try:
            config.PORT_SCAN_THRESHOLD = original + 5      # as --calibrate would
            self.assertEqual(verify_vector(vec), [])
        finally:
            config.PORT_SCAN_THRESHOLD = original

    def test_correlation_expires(self):
        clock = FakeClock()
        c = Correlator(clock=clock)
        w = SourceWindow()
        for p in range(12):
            w.add(0.0, p + 2000, HOST, 6, True, 60)
        self.assertEqual(c.severity("1.1.1.1", verify(w)), "HIGH")
        clock.t += 120
        from packetwatch.verify import RuleHit
        self.assertEqual(c.severity("1.1.1.1", [RuleHit("packet_flood", 150, 100, "pps")]),
                         "HIGH")
        self.assertEqual(c.severity("1.1.1.1", [RuleHit("port_scan", 20, 10, "p")]),
                         "CRITICAL")


if __name__ == "__main__":
    unittest.main()
