"""REQ 3: deterministic rule-based verification (stands in for VPID's Snort step).

No ML here: a flagged source is only confirmed if it crosses a fixed threshold.
"""
import time
from collections import defaultdict
from dataclasses import dataclass

from . import config
from .features import FEATURE_NAMES


@dataclass(frozen=True)
class RuleHit:
    rule: str
    observed: int
    threshold: int
    unit: str

    def explain(self):
        return f"{self.rule}: observed {self.observed} {self.unit} >= threshold {self.threshold}"

    def as_dict(self):
        return {"rule": self.rule, "observed": self.observed, "threshold": self.threshold,
                "unit": self.unit}


@dataclass(frozen=True)
class RuleSpec:
    """One threshold rule, defined once and used everywhere.

    The threshold is read through a callable rather than copied, so a value
    loaded from thresholds.json by --calibrate takes effect without this table
    knowing about calibration.
    """

    name: str
    feature: str                 # which entry of FEATURE_NAMES it tests
    unit: str

    @property
    def threshold(self):
        return getattr(config, {
            "port_scan": "PORT_SCAN_THRESHOLD",
            "packet_flood": "FLOOD_PPS_THRESHOLD",
            "suspicious_port": "SUSPICIOUS_PORT_THRESHOLD",
        }[self.name])


RULES = (
    RuleSpec("port_scan", "unique_dst_ports", "unique dst ports"),
    RuleSpec("packet_flood", "pkts_per_sec", "pkts/sec"),
    RuleSpec("suspicious_port", "suspicious_port_hits", "suspicious-port packets"),
)
_INDEX = {name: i for i, name in enumerate(FEATURE_NAMES)}


def verify_vector(vec):
    """Rules violated by one feature vector (empty list = not confirmed)."""
    hits = []
    for rule in RULES:
        observed = vec[_INDEX[rule.feature]]
        limit = rule.threshold
        if observed >= limit:
            hits.append(RuleHit(rule.name, int(observed), int(limit), rule.unit))
    return hits


def verify(window):
    """Rules violated by a source's window."""
    return verify_vector(window.extract())


def rule_counts(rows):
    """How many distinct rules fire per row, for a 2-D array of feature vectors.

    The offline evaluations use this so they test the same thresholds the live
    system does, instead of restating them.
    """
    import numpy as np

    rows = np.asarray(rows)
    total = np.zeros(len(rows), dtype=int)
    for rule in RULES:
        total += (rows[:, _INDEX[rule.feature]] >= rule.threshold).astype(int)
    return total


class Correlator:
    """Escalates severity when one IP trips several distinct rules within 60 s."""

    def __init__(self, window=config.CORRELATION_WINDOW,
                 min_rules=config.CORRELATION_MIN_RULES, clock=time.time,
                 max_ips=config.MAX_CORRELATED_IPS):
        self.window = window
        self.min_rules = min_rules
        self.clock = clock
        self.max_ips = max_ips
        self.seen = defaultdict(dict)  # ip -> {rule: last_ts}
        self._last_sweep = float("-inf")

    def severity(self, ip, hits):
        now = self.clock()
        rules = self.seen[ip]
        for h in hits:
            rules[h.rule] = now
        for rule in [r for r, ts in rules.items() if now - ts > self.window]:
            del rules[rule]
        verdict = "CRITICAL" if len(rules) >= self.min_rules else "HIGH"
        self._forget_stale(now)
        return verdict

    def _forget_stale(self, now):
        """Drop IPs whose alerts have all expired.

        Without this the correlator keeps a dictionary entry for every address
        that ever tripped a rule, which on a busy or spoofed-source network is a
        slow leak for no benefit: an expired entry can never change a verdict.
        """
        if now - self._last_sweep < self.window and len(self.seen) <= self.max_ips:
            return
        self._last_sweep = now
        cutoff = now - self.window
        for ip in [ip for ip, rules in self.seen.items()
                   if not rules or max(rules.values()) < cutoff]:
            del self.seen[ip]
        if len(self.seen) > self.max_ips:      # pathological case: keep the freshest
            keep = sorted(self.seen.items(), key=lambda kv: -max(kv[1].values()))
            self.seen = defaultdict(dict, dict(keep[:self.max_ips]))
