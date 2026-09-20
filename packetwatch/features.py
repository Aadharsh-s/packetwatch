"""Per-source-IP sliding window and feature extraction.

Memory is the design constraint here. The obvious implementation keeps every
packet of the last WINDOW_SECONDS and derives the features from that list, but
then memory grows with the *packet rate*: a 20,000 packet/second flood parks
200,000 objects in memory for a single attacker, which is exactly when the
machine can least afford it. An attacker could force that deliberately.

So nothing per-packet is kept. Each source owns a fixed ring of one counter set
per second in the window, updated in place and recycled as the window slides.
The cost of a source is therefore the same whether it sends one packet a second
or a million, and the only things that grow with traffic variety - the sets of
distinct ports and destinations - are capped well above any threshold that could
fire, so hitting the cap still triggers the rule it should.
"""
from . import config

FEATURE_NAMES = [
    "pkt_count",
    "pkts_per_sec",
    "unique_dst_ports",
    "unique_dst_ips",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "syn_only_count",
    "suspicious_port_hits",
    "avg_len_bucket",
]

PROTO_TCP, PROTO_UDP, PROTO_ICMP = 6, 17, 1

# Distinct-value caps. Both sit far above any threshold that can fire (the
# port-scan threshold tops out at 200 even when calibrated), so capping cannot
# hide an attack; it only stops a scan of every port from being remembered in
# full. A saturated counter reports the cap, which still exceeds the rule.
PORT_CAP = config.PORT_TRACK_CAP
DST_CAP = config.DST_TRACK_CAP


class SourceWindow:
    """One source IP's activity over the last WINDOW_SECONDS, in constant space."""

    __slots__ = ("window", "dirty", "last_seen", "_sec", "_pkts", "_bytes", "_tcp",
                 "_udp", "_icmp", "_syn", "_susp", "_ports", "_dsts",
                 "_ports_full", "_dsts_full")

    def __init__(self, window=config.WINDOW_SECONDS):
        self.window = window
        self.dirty = False
        self.last_seen = 0.0
        size = window
        # one slot per second, addressed by second % window
        self._sec = [-1] * size          # which second each slot currently holds
        self._pkts = [0] * size
        self._bytes = [0] * size
        self._tcp = [0] * size
        self._udp = [0] * size
        self._icmp = [0] * size
        self._syn = [0] * size
        self._susp = [0] * size
        self._ports = [set() for _ in range(size)]
        self._dsts = [set() for _ in range(size)]
        self._ports_full = False
        self._dsts_full = False

    def _slot(self, second):
        """Index of the slot for this second, cleared if it holds an older one."""
        i = second % self.window
        if self._sec[i] != second:
            self._sec[i] = second
            self._pkts[i] = self._bytes[i] = 0
            self._tcp[i] = self._udp[i] = self._icmp[i] = 0
            self._syn[i] = self._susp[i] = 0
            self._ports[i].clear()
            self._dsts[i].clear()
            self._ports_full = self._dsts_full = False
        return i

    def add(self, ts, dport, dst, proto, syn_only, length):
        second = int(ts)
        i = self._slot(second)
        self.last_seen = ts
        self._pkts[i] += 1
        self._bytes[i] += length
        if proto == PROTO_TCP:
            self._tcp[i] += 1
        elif proto == PROTO_UDP:
            self._udp[i] += 1
        elif proto == PROTO_ICMP:
            self._icmp[i] += 1
        if syn_only:
            self._syn[i] += 1
        if dport is not None:
            if dport in config.SUSPICIOUS_PORTS:
                self._susp[i] += 1
            if not self._ports_full:
                self._ports[i].add(dport)
                if self._live_count(self._ports) >= PORT_CAP:
                    self._ports_full = True
        if dst is not None and not self._dsts_full:
            self._dsts[i].add(dst)
            if self._live_count(self._dsts) >= DST_CAP:
                self._dsts_full = True

    def _live_slots(self, now=None):
        """Slots still inside the window, newest second first."""
        if now is None:
            now = self.last_seen
        cutoff = int(now) - self.window + 1
        return [i for i, sec in enumerate(self._sec) if sec >= cutoff and sec >= 0]

    def _live_count(self, sets):
        return sum(len(sets[i]) for i in self._live_slots())

    def prune(self, now):
        """Drop slots that have fallen out of the window.

        Slots are recycled on write, so this only matters for a source that went
        quiet: without it, stale counters would still be reported.
        """
        cutoff = int(now) - self.window + 1
        for i, sec in enumerate(self._sec):
            if 0 <= sec < cutoff:
                self._sec[i] = -1
                self._pkts[i] = self._bytes[i] = 0
                self._tcp[i] = self._udp[i] = self._icmp[i] = 0
                self._syn[i] = self._susp[i] = 0
                self._ports[i].clear()
                self._dsts[i].clear()

    @property
    def active(self):
        """True while any slot still holds data."""
        return any(sec >= 0 for sec in self._sec)

    def pkt_count(self, live=None):
        live = self._live_slots() if live is None else live
        return sum(self._pkts[i] for i in live)

    def pkts_per_sec(self):
        """Packets in the busiest single second of the window."""
        live = self._live_slots()
        return max((self._pkts[i] for i in live), default=0)

    def unique_dst_ports(self):
        live = self._live_slots()
        if self._ports_full:
            return PORT_CAP
        return len(set().union(*(self._ports[i] for i in live)) if live else ())

    def suspicious_port_hits(self):
        return sum(self._susp[i] for i in self._live_slots())

    def dst_ports(self):
        live = self._live_slots()
        return set().union(*(self._ports[i] for i in live)) if live else set()

    def extract(self):
        """Feature vector of non-negative ints (required by MultinomialNB)."""
        live = self._live_slots()
        n = sum(self._pkts[i] for i in live)
        total_bytes = sum(self._bytes[i] for i in live)
        dsts = (DST_CAP if self._dsts_full
                else len(set().union(*(self._dsts[i] for i in live)) if live else ()))
        return [
            n,
            max((self._pkts[i] for i in live), default=0),
            self.unique_dst_ports(),
            dsts,
            sum(self._tcp[i] for i in live),
            sum(self._udp[i] for i in live),
            sum(self._icmp[i] for i in live),
            sum(self._syn[i] for i in live),
            sum(self._susp[i] for i in live),
            int((total_bytes / n) // 100) if n else 0,
        ]
