"""Learn this host's rule thresholds from its own quiet traffic.

The three thresholds are fixed numbers chosen for a home or small-office link.
Measured on two public datasets, that assumption is the weakest part of the rule
layer: on UNSW-NB15, whose benign traffic is machine-generated at high rate, the
stock thresholds fire on 21.8% of benign windows. Deriving them from a baseline
of the host's own traffic drops that to 0.38%, and on CIC-IDS2017 from 1.64% to
0.37% with no loss of detection.

Calibration watches traffic for a while, takes a high percentile of what it saw
per source window, and writes thresholds.json next to the models. Floors keep a
busy or hostile baseline from raising a threshold so far that the rule goes
blind, and the baseline must be quiet: traffic captured during an attack teaches
the host that the attack is normal.
"""
import json
import time

import numpy as np

from . import config
from .features import FEATURE_NAMES, SourceWindow

THRESHOLD_FILE = config.MODEL_DIR / "thresholds.json"

# A calibrated threshold may never fall below these, so a quiet baseline cannot
# make the rules trigger-happy, nor a busy one make them useless.
FLOORS = {"port_scan": 5, "flood_pps": 20, "suspicious_port": 3}
CEILINGS = {"port_scan": 200, "flood_pps": 5000, "suspicious_port": 100}
PERCENTILE = 99.9


def thresholds_from_samples(samples, percentile=PERCENTILE):
    """Percentile of observed per-window values, clamped to the safe range."""
    if not samples:
        raise ValueError("no traffic observed; cannot calibrate")
    cols = {name: np.array([s[i] for s in samples], dtype=float)
            for i, name in enumerate(FEATURE_NAMES)}
    raw = {
        "port_scan": np.percentile(cols["unique_dst_ports"], percentile),
        "flood_pps": np.percentile(cols["pkts_per_sec"], percentile),
        "suspicious_port": np.percentile(cols["suspicious_port_hits"], percentile),
    }
    return {k: int(min(CEILINGS[k], max(FLOORS[k], np.ceil(v))))
            for k, v in raw.items()}


class Collector:
    """Snapshots each active source's feature window once a second."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self.windows = {}
        self.samples = []
        self._last = float("-inf")

    def handle(self, pkt):
        from scapy.layers.inet import IP, TCP, UDP

        if IP not in pkt:
            return
        from .pipeline import packet_length

        ip = pkt[IP]
        dport, syn_only = None, False
        if TCP in pkt:
            dport = int(pkt[TCP].dport)
            flags = int(pkt[TCP].flags)
            syn_only = bool(flags & 0x02) and not flags & 0x10
        elif UDP in pkt:
            dport = int(pkt[UDP].dport)
        now = self.clock()
        win = self.windows.get(ip.src)
        if win is None:
            win = self.windows[ip.src] = SourceWindow()
        win.add(now, dport, ip.dst, int(ip.proto), syn_only, packet_length(pkt, ip))
        if now - self._last >= config.EVAL_INTERVAL:
            self._last = now
            for w in self.windows.values():
                w.prune(now)
                if w.entries:
                    self.samples.append(w.extract())


def save(thresholds, path=THRESHOLD_FILE):
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(thresholds, calibrated_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
                   percentile=PERCENTILE)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def run(iface=None, seconds=300):
    """Capture a baseline and write thresholds.json. Needs Administrator."""
    from . import capture

    capture.preflight()
    collector = Collector()
    print(f"Calibrating on {seconds}s of traffic. Use the machine normally, and do "
          "NOT run scans or floods: whatever happens now is learned as normal.")
    capture.start_capture(collector.handle, iface=iface, timeout=seconds)
    if not collector.samples:
        raise SystemExit("No traffic seen; nothing to calibrate.")
    new = thresholds_from_samples(collector.samples)
    old = {"port_scan": config.PORT_SCAN_THRESHOLD,
           "flood_pps": config.FLOOD_PPS_THRESHOLD,
           "suspicious_port": config.SUSPICIOUS_PORT_THRESHOLD}
    path = save(new)
    print(f"\nObserved {len(collector.samples):,} source-windows from "
          f"{len(collector.windows):,} sources.")
    for k in old:
        mark = "unchanged" if old[k] == new[k] else f"was {old[k]}"
        print(f"  {k:16} {new[k]:>6}   ({mark})")
    print(f"Written to {path}. Delete that file to return to the stock thresholds.")
