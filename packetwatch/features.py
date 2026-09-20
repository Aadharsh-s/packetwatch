"""Per-source-IP sliding window and feature extraction."""
from collections import deque, namedtuple

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

Entry = namedtuple("Entry", "ts dport dst proto syn_only length")


class SourceWindow:
    """Rolling record of one source IP's packets over the last WINDOW_SECONDS."""

    def __init__(self, window=config.WINDOW_SECONDS):
        self.window = window
        self.entries = deque()
        self.dirty = False

    def add(self, ts, dport, dst, proto, syn_only, length):
        self.entries.append(Entry(ts, dport, dst, proto, syn_only, length))
        self.prune(ts)

    def prune(self, now):
        cutoff = now - self.window
        while self.entries and self.entries[0].ts < cutoff:
            self.entries.popleft()

    def pkts_per_sec(self):
        """Peak rate over the most recent second, so a short burst isn't diluted."""
        if not self.entries:
            return 0
        latest = self.entries[-1].ts
        return sum(1 for e in self.entries if e.ts > latest - 1.0)

    def unique_dst_ports(self):
        return len({e.dport for e in self.entries if e.dport is not None})

    def suspicious_port_hits(self):
        return sum(1 for e in self.entries if e.dport in config.SUSPICIOUS_PORTS)

    def dst_ports(self):
        return {e.dport for e in self.entries if e.dport is not None}

    def extract(self):
        """Feature vector of non-negative ints (required by MultinomialNB)."""
        n = len(self.entries)
        avg_len = sum(e.length for e in self.entries) / n if n else 0
        return [
            n,
            self.pkts_per_sec(),
            self.unique_dst_ports(),
            len({e.dst for e in self.entries}),
            sum(1 for e in self.entries if e.proto == PROTO_TCP),
            sum(1 for e in self.entries if e.proto == PROTO_UDP),
            sum(1 for e in self.entries if e.proto == PROTO_ICMP),
            sum(1 for e in self.entries if e.syn_only),
            self.suspicious_port_hits(),
            int(avg_len // 100),
        ]
