"""Rank vulnerabilities, and say why each one ranks where it does.

VPID prioritises with a decision tree. Measured against CISA's known-exploited
catalogue, a decision tree over CVE-record fields turns out to rank *worse* than
the CVSS base score it is built from (AUC 0.71 vs 0.77), while EPSS - a model
trained on observed exploitation rather than on the CVE text - reaches 0.97.
See VULN_EVALUATION.md.

So the ranking is a cascade rather than a single model, most trustworthy signal
first:

  1. listed in CISA KEV        - attackers are known to use it, patch first
  2. EPSS probability          - the strong public predictor, when available
  3. decision tree             - the paper's algorithm, over CVE fields only,
                                 used where EPSS has no score yet
  4. CVSS base score           - last resort, and the tie-breaker throughout

Every item carries the reason it was ranked, because an admin acting on the list
needs to know whether "high" means "seen in the wild" or "the tree guessed".
"""
import json
from dataclasses import dataclass, field

import joblib

from .. import config
from .features import FEATURE_NAMES, extract

MODEL_PATH = config.MODEL_DIR / "vuln_priority.joblib"
KEV_PATH = config.MODEL_DIR / "kev.json"
EPSS_PATH = config.MODEL_DIR / "epss.csv.gz"

# Bands keep the four signals on one 0-100 scale without letting a weaker
# signal outrank a stronger one.
BAND_KEV = 90
BAND_EPSS = 50
BAND_TREE = 20
BAND_CVSS = 0


@dataclass
class Priority:
    cve: str
    score: float
    basis: str                      # which signal decided it
    reason: str                     # one line an admin can act on
    details: dict = field(default_factory=dict)

    @property
    def band(self):
        if self.score >= BAND_KEV:
            return "CRITICAL"
        if self.score >= BAND_EPSS:
            return "HIGH"
        if self.score >= BAND_TREE:
            return "MEDIUM"
        return "LOW"


def load_kev(path=KEV_PATH):
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {v["cveID"].upper(): v.get("dateAdded", "")
            for v in data.get("vulnerabilities", [])}


def load_epss(path=EPSS_PATH):
    if not path.exists():
        return {}
    import csv
    import gzip

    out = {}
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) == 3 and row[0].upper().startswith("CVE-"):
                try:
                    out[row[0].upper()] = float(row[1])
                except ValueError:
                    pass
    return out


class Prioritiser:
    def __init__(self, tree=None, kev=None, epss=None):
        self.tree = tree if tree is not None else (
            joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None)
        self.kev = load_kev() if kev is None else kev
        self.epss = load_epss() if epss is None else epss

    def score_cve(self, cve, nvd_item=None):
        """Priority for one CVE, using the best signal available for it."""
        cve = cve.upper()
        vec = extract(nvd_item) if nvd_item else None
        cvss = (vec[0] / 10) if vec else 0.0
        details = {"cvss": cvss}

        if cve in self.kev:
            return Priority(cve, 100.0, "kev",
                            f"listed in CISA KEV on {self.kev[cve] or 'unknown date'}: "
                            "known to be exploited in the wild",
                            dict(details, kev_date=self.kev[cve]))

        if cve in self.epss:
            p = self.epss[cve]
            details["epss"] = p
            return Priority(cve, BAND_EPSS + min(p, 1.0) * 39.9, "epss",
                            f"EPSS puts the chance of exploitation in the next 30 days "
                            f"at {p*100:.1f}%", details)

        if self.tree is not None and vec:
            proba = float(self.tree.predict_proba([vec])[0][
                list(self.tree.classes_).index(1)])
            details["tree_proba"] = round(proba, 3)
            return Priority(cve, BAND_TREE + proba * 29.9, "tree",
                            f"no EPSS score yet; the decision tree rates it "
                            f"{proba*100:.0f}% likely to be exploited, from CVSS "
                            f"{cvss:.1f} and its CVE record", details)

        return Priority(cve, BAND_CVSS + cvss, "cvss",
                        f"no exploitation data available; CVSS {cvss:.1f} only", details)

    def rank(self, findings, nvd_lookup=None):
        """Attach the best CVE priority to each OpenVAS finding, highest first.

        nvd_lookup maps a CVE id to its NVD record, when one is on hand; without
        it the cascade falls back to KEV and EPSS, which need no NVD data.
        """
        nvd_lookup = nvd_lookup or {}
        ranked = []
        for f in findings:
            priorities = [self.score_cve(c, nvd_lookup.get(c.upper()))
                          for c in f.cves]
            if priorities:
                best = max(priorities, key=lambda p: p.score)
            else:
                best = Priority("", f.severity, "scanner",
                                f"no CVE attached; scanner severity {f.severity:.1f}",
                                {"cvss": f.severity})
            ranked.append((best, f))
        ranked.sort(key=lambda pair: (-pair[0].score, -pair[1].severity))
        return ranked


def feature_names():
    return list(FEATURE_NAMES)
