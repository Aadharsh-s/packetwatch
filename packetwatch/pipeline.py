"""Glue: packet -> features -> ML (DT + NB) -> rule verification -> block + alert."""
import csv
import logging
import threading
import time
from collections import OrderedDict

from . import config
from .features import FEATURE_NAMES, SourceWindow
from .riskmap import RiskMap, escalate
from .verify import Correlator, verify_vector

log = logging.getLogger("packetwatch.pipeline")


def packet_length(pkt, ip):
    """Byte length of a packet without making Scapy rebuild it.

    len(pkt) re-serialises the whole packet and recomputes checksums, which
    profiling showed to be ~88% of per-packet cost. Sniffed packets already
    carry the IP header's total-length field and their raw bytes, so both are
    used first; the rebuild is only a fallback for hand-crafted packets.
    """
    n = ip.len
    if n:
        return int(n)
    raw = getattr(pkt, "original", None)
    if raw:
        return len(raw)
    return len(bytes(pkt))


class Pipeline:
    def __init__(self, detector, blocker, alerter, own_addresses=(), record_path=None,
                 clock=time.time, risk_map=None):
        self.detector = detector
        self.blocker = blocker
        self.alerter = alerter
        self.own = set(own_addresses)
        self.risk = risk_map or RiskMap()
        self.clock = clock
        self.correlator = Correlator(clock=clock)
        # OrderedDict as an LRU: a flood with spoofed source addresses would
        # otherwise create one window per packet and never release any of them.
        self.windows = OrderedDict()
        self.evicted = 0
        self.lock = threading.Lock()
        self.stats = {"packets": 0, "judged": 0, "ml_flagged": 0, "unverified": 0,
                      "confirmed": 0, "rule_triggered": 0, "risk_escalated": 0}
        self._last_stats = clock()
        self._last_sweep = float("-inf")
        self._record = self._record_file = None
        if record_path:
            # kept on the instance and flushed per row: a recording run usually
            # ends with Ctrl+C, which would otherwise lose whatever is buffered
            self._record_file = open(record_path, "a", newline="", encoding="utf-8")
            self._record = csv.writer(self._record_file)
            if self._record_file.tell() == 0:
                self._record.writerow(FEATURE_NAMES + ["label"])

    def handle(self, pkt):
        """Scapy sniff() callback."""
        from scapy.layers.inet import IP, TCP, UDP

        if IP not in pkt:
            return
        ip = pkt[IP]
        src = ip.src
        self.stats["packets"] += 1
        if src in self.own or self.blocker.is_protected(src):
            return  # only judge traffic arriving from other hosts

        dport, syn_only = None, False
        if TCP in pkt:
            dport = int(pkt[TCP].dport)
            flags = int(pkt[TCP].flags)
            syn_only = bool(flags & 0x02) and not flags & 0x10
        elif UDP in pkt:
            dport = int(pkt[UDP].dport)

        now = self.clock()
        with self.lock:
            win = self.windows.get(src)
            if win is None:
                win = self.windows[src] = SourceWindow()
                if len(self.windows) > config.MAX_SOURCES:
                    self.windows.popitem(last=False)   # drop the stalest source
                    self.evicted += 1
            else:
                self.windows.move_to_end(src)
            win.add(now, dport, ip.dst, int(ip.proto), syn_only,
                    packet_length(pkt, ip))
            win.dirty = True
        self.sweep()
        self._maybe_stats(now)

    def sweep(self, force=False):
        """Judge every source that sent packets since it was last judged.

        Runs at most once per EVAL_INTERVAL; called on each packet and by the
        ticker thread, so short bursts are judged even if the source goes quiet.
        """
        now = self.clock()
        with self.lock:
            if not force and now - self._last_sweep < config.EVAL_INTERVAL:
                return []
            self._last_sweep = now
            self._evict_idle(now)
            pending = []
            for src, win in self.windows.items():
                if not win.dirty or src in self.blocker.blocked:
                    continue
                win.dirty = False
                win.prune(now)
                vec = win.extract()
                pending.append((src, vec, verify_vector(vec),
                                self.risk.lookup(win.dst_ports())))
        if not pending:
            return []
        mls = self.detector.predict_many([vec for _, vec, _, _ in pending])
        return [r for r in (self.evaluate(src, vec, hits, ml, risk)
                            for (src, vec, hits, risk), ml in zip(pending, mls)) if r]

    def _evict_idle(self, now):
        """Forget sources that have gone quiet. Caller holds the lock.

        Runs from the sweep, so it happens on the ticker too: a host that goes
        silent after a burst is released without waiting for new traffic.
        """
        cutoff = now - config.IDLE_EVICT_SECONDS
        for ip in [ip for ip, w in self.windows.items() if w.last_seen < cutoff]:
            del self.windows[ip]

    def evaluate(self, src, vec, hits, ml=None, risk=None):
        self.stats["judged"] += 1
        if self._record:
            self._record.writerow(vec + [""])
            self._record_file.flush()

        if ml is None:
            ml = self.detector.predict(vec)
        if ml["flagged"]:
            self.stats["ml_flagged"] += 1

        # A source is acted on when the classifiers flag it AND a rule confirms
        # (the paper's detect -> verify chain), or when enough distinct rules fire
        # at once to stand on their own, as Snort's alerts do in VPID.
        distinct = len({h.rule for h in hits})
        # Traffic aimed at a service the scanner flagged as known-vulnerable is
        # blocked on a single rule, rather than the usual two.
        needed = 1 if risk else config.INDEPENDENT_RULE_TRIGGER
        rules_alone = bool(needed) and distinct >= needed
        if not ((ml["flagged"] and hits) or rules_alone):
            if ml["flagged"]:
                self.stats["unverified"] += 1
                log.info("ML-flagged, not verified: %s %s (DT=%s NB=%s)", src,
                         dict(zip(FEATURE_NAMES, vec)), ml["dt_proba"], ml["nb_proba"])
            return None

        trigger = "ml+rule" if (ml["flagged"] and hits) else "rules-only"
        if trigger == "rules-only":
            self.stats["rule_triggered"] += 1
        self.stats["confirmed"] += 1
        severity = self.correlator.severity(src, hits)
        if risk:
            severity = escalate(severity)
            self.stats["risk_escalated"] += 1
        action = self.blocker.block(src)
        return self.alerter.alert(src, severity, ml, hits, action, trigger=trigger,
                                  risk=risk)

    def close(self):
        """Flush and close the --record file, if one is open."""
        if self._record_file:
            self._record_file.close()
            self._record = self._record_file = None

    def run_ticker(self, stop_event):
        """Background sweeps so a quiet network still gets judged on time."""
        while not stop_event.wait(config.EVAL_INTERVAL):
            try:
                self.sweep()
            except Exception:
                log.exception("sweep failed")

    def _maybe_stats(self, now):
        if now - self._last_stats < config.STATS_INTERVAL:
            return
        self._last_stats = now
        with self.lock:
            self._evict_idle(now)
            active = len(self.windows)
        s = self.stats
        print(f"[stats] packets={s['packets']} active_sources={active} "
              f"ml_flagged={s['ml_flagged']} unverified={s['unverified']} "
              f"confirmed={s['confirmed']} rules_only={s['rule_triggered']} "
              f"risk_escalated={s['risk_escalated']} "
              f"blocked={len(self.blocker.blocked)}"
              + (f" evicted={self.evicted}" if self.evicted else ""), flush=True)
