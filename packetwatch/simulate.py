"""Offline demo: replay crafted traffic through the full pipeline (no admin/Npcap).

Firewall commands are only logged (dry-run); timestamps come from a virtual clock.
Every scenario here is one the shipped models recognise, so each block shows
trigger=ml+rule. The rules-only path (2+ rules blocking when the classifiers miss)
is exercised in tests/test_pipeline.py with a detector that never flags.
"""
from scapy.layers.inet import ICMP, IP, TCP, UDP

from . import config

HOST = "192.168.50.10"

SCENARIOS = [
    ("Normal HTTPS browsing", "142.250.10.10",
     lambda: [IP(src="142.250.10.10", dst=HOST) / TCP(sport=443, dport=50000, flags="A")
              / (b"x" * 900) for _ in range(150)], 0.05),
    ("Normal DNS replies", "8.8.8.8",
     lambda: [IP(src="8.8.8.8", dst=HOST) / UDP(sport=53, dport=53000) / (b"d" * 80)
              for _ in range(20)], 0.3),
    ("SYN port scan", "10.0.0.66",
     lambda: [IP(src="10.0.0.66", dst=HOST) / TCP(dport=p, flags="S")
              for p in range(1, 120)], 0.02),
    ("UDP flood", "10.0.0.77",
     lambda: [IP(src="10.0.0.77", dst=HOST) / UDP(dport=9999) / (b"f" * 512)
              for _ in range(600)], 0.003),
    ("ICMP flood", "10.0.0.88",
     lambda: [IP(src="10.0.0.88", dst=HOST) / ICMP() for _ in range(600)], 0.003),
    ("RDP/SMB brute force", "10.0.0.99",
     lambda: [IP(src="10.0.0.99", dst=HOST) / TCP(dport=(3389, 445)[i % 2], flags="S")
              for i in range(12)], 0.4),
    ("Slow sweep of suspicious ports", "10.0.0.44",
     lambda: [IP(src="10.0.0.44", dst=HOST) / TCP(dport=p, flags="S")
              for p in sorted(config.SUSPICIOUS_PORTS) * 3], 0.004),
    ("Aggressive scan of suspicious ports", "10.0.0.55",
     lambda: [IP(src="10.0.0.55", dst=HOST) / TCP(dport=p, flags="S")
              for p in sorted(config.SUSPICIOUS_PORTS) + list(range(2000, 2200))], 0.004),
]


class VirtualClock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def run(risk_map=None):
    from .model import Detector
    from .pipeline import Pipeline
    from .response import Alerter, FirewallBlocker
    from .riskmap import RiskMap

    clock = VirtualClock()
    blocker = FirewallBlocker(dry_run=True, ttl_min=0)
    risk = risk_map or RiskMap()
    pipeline = Pipeline(Detector(), blocker, Alerter(), own_addresses={HOST},
                        clock=clock, risk_map=risk)

    print("PacketWatch simulation (DRY RUN - firewall commands are only logged)\n")
    for name, src, build, spacing in SCENARIOS:
        print(f"--- {name} from {src}")
        for pkt in build():
            pipeline.handle(pkt)
            clock.t += spacing
        pipeline.sweep(force=True)
        verdict = "BLOCKED" if src in blocker.blocked else "allowed"
        print(f"    result: {verdict}\n")
        clock.t += config.WINDOW_SECONDS + 1  # let windows age out between scenarios

    s = pipeline.stats
    print(f"Summary: packets={s['packets']} judged={s['judged']} "
          f"ml_flagged={s['ml_flagged']} unverified={s['unverified']} "
          f"confirmed={s['confirmed']} rules_only={s['rule_triggered']} "
          f"risk_escalated={s['risk_escalated']} blocked={sorted(blocker.blocked)}")
