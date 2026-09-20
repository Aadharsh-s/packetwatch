"""Read an OpenVAS / Greenbone (GVM) XML report into plain finding records.

VPID's first module uses OpenVAS for asset mapping and vulnerability discovery.
OpenVAS is Linux-only, so PacketWatch does not run the scanner; it consumes the
report a scanner produces. That keeps the Windows host free of a scanner
dependency and makes the prioritisation stage testable against a saved file.

The parser accepts the report format GVM exports (`<report><results><result>`),
and is tolerant about missing fields, because real reports vary by version and
by the plugin that produced each result.
"""
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


@dataclass
class Finding:
    """One vulnerability reported against one host and port."""

    host: str
    port: str
    name: str
    severity: float                     # CVSS as the scanner reported it
    threat: str                         # scanner's own wording: High, Medium, ...
    cves: list = field(default_factory=list)
    oid: str = ""
    description: str = ""

    @property
    def port_number(self):
        """Numeric port from OpenVAS's "443/tcp" style, or None."""
        m = re.match(r"^(\d+)", self.port or "")
        return int(m.group(1)) if m else None

    @property
    def protocol(self):
        return "udp" if "/udp" in (self.port or "").lower() else "tcp"


def _text(node, path, default=""):
    found = node.find(path)
    return (found.text or default).strip() if found is not None and found.text else default


def _cves(node):
    """CVE ids from wherever this report version happens to put them."""
    ids = set()
    for path in ("nvt/refs/ref", "nvt/cve", "refs/ref"):
        for ref in node.findall(path):
            value = (ref.get("id") or ref.text or "")
            ids.update(m.group(0).upper() for m in CVE_RE.finditer(value))
    blob = " ".join(filter(None, [_text(node, "nvt/tags"), _text(node, "description")]))
    ids.update(m.group(0).upper() for m in CVE_RE.finditer(blob))
    return sorted(ids)


def parse_report(path):
    """Parse a GVM XML report file into Finding objects."""
    root = ET.parse(path).getroot()
    results = root.findall(".//results/result") or root.findall(".//result")
    findings = []
    for node in results:
        host = _text(node, "host") or (node.findtext("host/asset/@asset_id") or "")
        try:
            severity = float(_text(node, "severity", "0") or 0)
        except ValueError:
            severity = 0.0
        findings.append(Finding(
            host=host,
            port=_text(node, "port"),
            name=_text(node, "name") or _text(node, "nvt/name"),
            severity=severity,
            threat=_text(node, "threat"),
            cves=_cves(node),
            oid=(node.find("nvt").get("oid") if node.find("nvt") is not None else ""),
            description=_text(node, "description"),
        ))
    return findings


def summarise(findings):
    """Counts by host and by threat level, for the report header."""
    hosts, threats, cves = {}, {}, set()
    for f in findings:
        hosts[f.host] = hosts.get(f.host, 0) + 1
        threats[f.threat or "Unknown"] = threats.get(f.threat or "Unknown", 0) + 1
        cves.update(f.cves)
    return {"findings": len(findings), "hosts": hosts, "threats": threats,
            "unique_cves": len(cves)}
