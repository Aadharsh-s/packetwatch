"""Turn an NVD CVE record into the feature vector the prioritiser ranks on.

Used both when training (over NVD year feeds) and at runtime (over the CVEs an
OpenVAS report mentions), so a vulnerability is described identically in both
places. Everything here comes from the CVE record itself: severity, how the
vulnerability is reached, what it costs the attacker, what it grants, and how
the world has reacted to it (patches, exploit write-ups, how many products are
affected).
"""
from datetime import datetime, timezone

FEATURE_NAMES = [
    "base_score",            # CVSS v3 base score x10, kept as an int
    "exploitability",        # CVSS exploitability sub-score x10
    "impact",                # CVSS impact sub-score x10
    "attack_vector",         # 3 network .. 0 physical
    "attack_complexity",     # 1 low, 0 high
    "privileges_required",   # 2 none, 1 low, 0 high
    "user_interaction",      # 1 none, 0 required
    "scope_changed",
    "conf_impact",           # 2 high, 1 low, 0 none
    "integ_impact",
    "avail_impact",
    "has_exploit_ref",       # a reference NVD tagged "Exploit"
    "has_patch_ref",
    "n_references",
    "n_products",            # affected CPE entries
    "age_days",
]

_AV = {"NETWORK": 3, "ADJACENT_NETWORK": 2, "LOCAL": 1, "PHYSICAL": 0}
_PR = {"NONE": 2, "LOW": 1, "HIGH": 0}
_IMPACT = {"HIGH": 2, "LOW": 1, "NONE": 0}


def _cvss_v3(item):
    for key in ("cvssMetricV31", "cvssMetricV30"):
        metrics = item.get("metrics", {}).get(key) or []
        for m in metrics:
            if m.get("type") == "Primary" or len(metrics) == 1:
                return m
    return None


def _count_products(item):
    n = 0
    for conf in item.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            n += len(node.get("cpeMatch", []) or [])
    return n


def extract(item, now=None):
    """Feature vector for one NVD CVE record, or None if it has no CVSS v3."""
    metric = _cvss_v3(item)
    if not metric:
        return None
    data = metric.get("cvssData", {})
    refs = item.get("references", []) or []
    tags = {t for r in refs for t in (r.get("tags") or [])}

    published = item.get("published", "")
    try:
        pub = datetime.fromisoformat(published.replace("Z", "+00:00"))
        if pub.tzinfo is None:
            pub = pub.replace(tzinfo=timezone.utc)
        age = ((now or datetime.now(timezone.utc)) - pub).days
    except ValueError:
        age = 0

    return [
        int(round(float(data.get("baseScore", 0)) * 10)),
        int(round(float(metric.get("exploitabilityScore", 0)) * 10)),
        int(round(float(metric.get("impactScore", 0)) * 10)),
        _AV.get(data.get("attackVector", ""), 0),
        1 if data.get("attackComplexity") == "LOW" else 0,
        _PR.get(data.get("privilegesRequired", ""), 0),
        1 if data.get("userInteraction") == "NONE" else 0,
        1 if data.get("scope") == "CHANGED" else 0,
        _IMPACT.get(data.get("confidentialityImpact", ""), 0),
        _IMPACT.get(data.get("integrityImpact", ""), 0),
        _IMPACT.get(data.get("availabilityImpact", ""), 0),
        1 if "Exploit" in tags else 0,
        1 if ("Patch" in tags or "Vendor Advisory" in tags) else 0,
        min(len(refs), 100),
        min(_count_products(item), 1000),
        max(age, 0),
    ]


def describe(vec):
    """Feature vector as a readable dict, for explaining a ranking."""
    return dict(zip(FEATURE_NAMES, vec))
