"""Tests for the optional dashboard (packetwatch/dashboard.py).

Two things are worth testing here beyond "does it render": that the dashboard
cannot grow without bound, since that would undo the guarantee the rest of the
system makes, and that a page in the user's browser cannot use it to lift a
block.
"""
import json
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from scapy.layers.inet import IP, TCP

from packetwatch import config
from packetwatch.dashboard import CONTROL_HEADER, Dashboard, DashboardState
from packetwatch.features import FEATURE_NAMES
from packetwatch.pipeline import Pipeline
from packetwatch.response import Alerter, FirewallBlocker
from packetwatch.verify import nearest_rule

ATTACKER = "192.168.1.66"
HOST = "192.168.1.10"


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeRunner:
    def __call__(self, cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, "", "")


class AlwaysFlags:
    verdict = {"dt": True, "nb": True, "dt_proba": 1.0, "nb_proba": 1.0,
               "flagged": True}

    def predict(self, vec):
        return dict(self.verdict)

    def predict_many(self, vecs):
        return [dict(self.verdict) for _ in vecs]


class DashboardTestCase(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.tmp = tempfile.TemporaryDirectory()
        self.blocker = FirewallBlocker(runner=FakeRunner(), ttl_min=30)
        self.pipe = Pipeline(AlwaysFlags(), self.blocker,
                             Alerter(Path(self.tmp.name) / "alerts.log", console=False),
                             own_addresses={HOST}, clock=self.clock)
        self.state = DashboardState(self.pipe, self.blocker, iface="test",
                                    clock=self.clock)
        self.pipe.observer = self.state

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, ports=60):
        for p in range(1, ports):
            self.pipe.handle(IP(src=ATTACKER, dst=HOST) / TCP(dport=p, flags="S"))
            self.clock.t += 0.05
        self.pipe.sweep(force=True)


class BlockTtlTests(DashboardTestCase):
    def test_blocks_report_remaining_ttl(self):
        self.scan()
        self.assertIn(ATTACKER, self.blocker.blocked)
        row = self.blocker.blocks()[0]
        self.assertEqual(row["ip"], ATTACKER)
        self.assertIsNotNone(row["blocked_at"])
        # 30 minute TTL, just set: most of it should remain
        self.assertGreater(row["remaining"], 29 * 60)
        self.assertLessEqual(row["remaining"], 30 * 60)

    def test_unblock_clears_the_timestamp(self):
        self.scan()
        self.blocker.unblock(ATTACKER)
        self.assertEqual(self.blocker.blocks(), [])
        self.assertNotIn(ATTACKER, self.blocker.block_times)

    def test_no_ttl_means_no_expiry(self):
        blocker = FirewallBlocker(runner=FakeRunner(), ttl_min=0)
        blocker.block("10.0.0.5")
        self.assertIsNone(blocker.blocks()[0]["expires_at"])


class BoundedMemoryTests(DashboardTestCase):
    """The dashboard must not become the thing that grows under attack."""

    def test_alert_history_is_capped(self):
        for i in range(config.DASHBOARD_ALERTS * 3):
            self.state.on_alert({"src_ip": f"10.0.0.{i % 250}", "severity": "HIGH"})
        self.assertEqual(len(self.state.alerts), config.DASHBOARD_ALERTS)

    def test_unverified_history_is_capped(self):
        vec = [0] * len(FEATURE_NAMES)
        ml = dict(AlwaysFlags.verdict)
        for i in range(config.DASHBOARD_UNVERIFIED * 3):
            self.state.on_unverified(f"10.0.0.{i % 250}", vec, ml)
        self.assertEqual(len(self.state.unverified), config.DASHBOARD_UNVERIFIED)

    def test_traffic_history_is_capped(self):
        for _ in range(config.DASHBOARD_TRAFFIC_SAMPLES * 2):
            self.clock.t += 1
            self.state.sample()
        self.assertEqual(len(self.state.traffic), config.DASHBOARD_TRAFFIC_SAMPLES)


class SnapshotTests(DashboardTestCase):
    def test_snapshot_has_every_panel(self):
        self.scan()
        snap = self.state.snapshot()
        for key in ("status", "funnel", "blocks", "alerts", "unverified",
                    "traffic", "sources"):
            self.assertIn(key, snap)
        self.assertTrue(json.dumps(snap))            # must survive the API

    def test_funnel_matches_pipeline_stats(self):
        self.scan()
        snap = self.state.snapshot()
        self.assertEqual(snap["funnel"]["judged"], self.pipe.stats["judged"])
        self.assertEqual(snap["funnel"]["confirmed"], self.pipe.stats["confirmed"])
        self.assertGreaterEqual(snap["funnel"]["confirmed"], 1)

    def test_blocks_carry_the_reason_from_the_alert(self):
        self.scan()
        block = self.state.snapshot()["blocks"][0]
        self.assertEqual(block["ip"], ATTACKER)
        self.assertIsNotNone(block["reason"])
        self.assertTrue(any("port_scan" in line
                            for line in block["reason"]["explanation"]))

    def test_sources_carry_features_and_hits(self):
        self.scan()
        src = next(s for s in self.state.snapshot()["sources"] if s["ip"] == ATTACKER)
        self.assertGreater(src["features"]["unique_dst_ports"],
                           config.PORT_SCAN_THRESHOLD)
        self.assertIn("port_scan", [h["rule"] for h in src["hits"]])
        self.assertTrue(src["blocked"])

    def test_snapshot_does_not_disturb_detection(self):
        """Reading the dashboard must not change what the pipeline would do."""
        self.scan()
        before = dict(self.pipe.stats)
        for _ in range(5):
            self.state.snapshot()
        self.assertEqual(dict(self.pipe.stats), before)


class NearestRuleTests(unittest.TestCase):
    def test_reports_the_closest_rule(self):
        vec = [0] * len(FEATURE_NAMES)
        vec[FEATURE_NAMES.index("unique_dst_ports")] = config.PORT_SCAN_THRESHOLD - 1
        near = nearest_rule(vec)
        self.assertEqual(near["rule"], "port_scan")
        self.assertEqual(near["observed"], config.PORT_SCAN_THRESHOLD - 1)
        self.assertLess(near["fraction"], 1.0)

    def test_prefers_the_rule_nearest_its_threshold(self):
        vec = [0] * len(FEATURE_NAMES)
        vec[FEATURE_NAMES.index("unique_dst_ports")] = 1        # 1 of 10
        vec[FEATURE_NAMES.index("suspicious_port_hits")] = 2    # 2 of 3
        self.assertEqual(nearest_rule(vec)["rule"], "suspicious_port")


class HttpTests(DashboardTestCase):
    """The server is a control surface, so its refusals are part of the design."""

    def setUp(self):
        super().setUp()
        self.dash = Dashboard(self.pipe, self.blocker, iface="test", port=0)
        self.assertTrue(self.dash.start())
        self.dash.state = self.state          # share the state the tests feed
        self.base = f"http://127.0.0.1:{self.dash.port}"

    def tearDown(self):
        self.dash.stop()
        super().tearDown()

    def get(self, path, headers=None):
        req = urllib.request.Request(self.base + path, headers=headers or {})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()

    def post(self, path, body=None, headers=None):
        req = urllib.request.Request(
            self.base + path, method="POST",
            data=json.dumps(body or {}).encode(),
            headers={"Content-Type": "application/json", **(headers or {})})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())

    def test_page_is_served(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"PacketWatch", body)

    def test_status_api_returns_every_panel(self):
        status, body = self.get("/api/status")
        self.assertEqual(status, 200)
        self.assertIn("funnel", json.loads(body))

    def test_post_without_the_control_header_is_refused(self):
        """A cross-origin form POST cannot set a custom header. This is why."""
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.post("/api/unblock", {"ip": ATTACKER})
        self.assertEqual(cm.exception.code, 403)

    def test_non_loopback_host_header_is_refused(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.get("/api/status", {"Host": "packetwatch.example.com"})
        self.assertEqual(cm.exception.code, 403)

    def test_invalid_ip_is_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.post("/api/unblock", {"ip": "; del *"}, {CONTROL_HEADER: "1"})
        self.assertEqual(cm.exception.code, 400)

    def test_unblock_lifts_a_real_block(self):
        self.scan()
        self.assertIn(ATTACKER, self.blocker.blocked)
        status, body = self.post("/api/unblock", {"ip": ATTACKER},
                                 {CONTROL_HEADER: "1"})
        self.assertEqual(status, 200)
        self.assertEqual(body["unblocked"], [ATTACKER])
        self.assertNotIn(ATTACKER, self.blocker.blocked)

    def test_unblock_all_clears_everything(self):
        self.scan()
        self.blocker.block("10.0.0.5")
        status, body = self.post("/api/unblock-all", {}, {CONTROL_HEADER: "1"})
        self.assertEqual(status, 200)
        self.assertEqual(self.blocker.blocked, set())

    def test_unknown_route_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.get("/api/secrets")
        self.assertEqual(cm.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
