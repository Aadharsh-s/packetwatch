"""Let what the scanner found change how the detector reacts.

VPID is an *integrated* framework: the point of prioritising vulnerabilities is
that the intrusion side then knows which services are worth defending hardest.
Until now PacketWatch's two modules ran independently.

A risk map is the link. It is built from the vulnerability module's JSON output
(`python -m packetwatch.vuln --report scan.xml --json risk.json`) and says, for
each local port, the worst thing known about the service behind it. While
capturing, traffic aimed at one of those ports is judged less forgivingly:

  * severity is raised a level, so an alert against a known-exploited service
    reads CRITICAL rather than HIGH;
  * one rule is enough to block, instead of the usual two, because the target
    is known to be vulnerable rather than merely noisy;
  * the alert names the CVE, so the person reading it knows why.

Nothing here lowers a threshold for ports that are not in the map, and an empty
or missing map leaves the detector exactly as it was.
"""
import json
from pathlib import Path

# Only these bands harden the response. MEDIUM and LOW findings are recorded for
# the alert text but do not change a decision.
ACTIONABLE = {"CRITICAL", "HIGH"}


class RiskMap:
    def __init__(self, entries=None):
        # {port: {"band": ..., "cve": ..., "reason": ..., "host": ...}}
        self.ports = entries or {}

    def __bool__(self):
        return bool(self.ports)

    def __len__(self):
        return len(self.ports)

    @classmethod
    def from_json(cls, path):
        """Read the vulnerability module's --json output."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = {}
        for item in data.get("ranking", []):
            port = _port_number(item.get("port", ""))
            if port is None or item.get("band") not in ACTIONABLE:
                continue
            current = entries.get(port)
            if current is None or item.get("score", 0) > current["score"]:
                entries[port] = {"band": item["band"], "cve": item.get("cve", ""),
                                 "reason": item.get("reason", ""),
                                 "host": item.get("host", ""),
                                 "score": item.get("score", 0)}
        return cls(entries)

    def lookup(self, ports):
        """Worst known finding among the destination ports a source touched."""
        hits = [self.ports[p] for p in ports if p in self.ports]
        return max(hits, key=lambda h: h["score"]) if hits else None

    def summary(self):
        if not self.ports:
            return "no risk map loaded"
        worst = sorted(self.ports.items(), key=lambda kv: -kv[1]["score"])[:3]
        listed = ", ".join(f"{p} ({e['cve'] or e['band']})" for p, e in worst)
        return f"{len(self.ports)} at-risk port(s): {listed}"


def _port_number(port_field):
    """"445/tcp" -> 445. Returns None for "general/tcp" and other non-ports."""
    head = str(port_field).split("/", 1)[0].strip()
    return int(head) if head.isdigit() else None


def escalate(severity):
    return "CRITICAL" if severity == "HIGH" else severity
