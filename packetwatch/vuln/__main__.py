"""PacketWatch vulnerability module: python -m packetwatch.vuln --help

Reads an OpenVAS / Greenbone XML report, ranks what it found by how likely each
vulnerability is to be used against you, and optionally checks whether the
affected services are actually exposed.
"""
import argparse
import json
import sys
from pathlib import Path

from .. import config
from .model import EPSS_PATH, KEV_PATH, Prioritiser
from .openvas import parse_report, summarise

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def update_feeds():
    """Fetch the CISA KEV catalogue and current EPSS scores."""
    import urllib.request

    config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    for url, path in ((KEV_URL, KEV_PATH), (EPSS_URL, EPSS_PATH)):
        print(f"downloading {url}")
        urllib.request.urlretrieve(url, path)
        print(f"  -> {path} ({path.stat().st_size / 1e6:.1f} MB)")


def print_ranking(ranked, top):
    print(f"{'BAND':9} {'SCORE':>6}  {'HOST':15} {'PORT':9} CVE / FINDING")
    for priority, finding in ranked[:top]:
        label = priority.cve or finding.name[:40]
        print(f"{priority.band:9} {priority.score:6.1f}  {finding.host:15} "
              f"{finding.port:9} {label}")
        print(f"{'':9} {'':6}  -> {priority.reason}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="packetwatch.vuln",
                                description="Rank an OpenVAS report by exploitation "
                                            "risk, and check exposure safely")
    p.add_argument("--report", help="OpenVAS / GVM XML report to read")
    p.add_argument("--top", type=int, default=20, help="how many findings to show")
    p.add_argument("--validate", action="store_true",
                   help="check whether the top findings' ports are actually open")
    p.add_argument("--allow-external", action="store_true",
                   help="permit checks against non-private addresses")
    p.add_argument("--json", metavar="FILE", help="write the ranking as JSON")
    p.add_argument("--update-feeds", action="store_true",
                   help="download the CISA KEV catalogue and EPSS scores, then exit")
    args = p.parse_args(argv)

    if args.update_feeds:
        update_feeds()
        return
    if not args.report:
        p.error("--report is required (or use --update-feeds)")

    findings = parse_report(args.report)
    info = summarise(findings)
    print(f"{info['findings']} findings, {len(info['hosts'])} host(s), "
          f"{info['unique_cves']} unique CVEs: "
          + ", ".join(f"{k} {v}" for k, v in sorted(info["threats"].items())))

    prioritiser = Prioritiser()
    if not prioritiser.kev and not prioritiser.epss:
        print("\nWARNING: no KEV or EPSS data found. Ranking falls back to the "
              "decision tree and CVSS alone.\n"
              "Run: python -m packetwatch.vuln --update-feeds\n", file=sys.stderr)
    ranked = prioritiser.rank(findings)
    print()
    print_ranking(ranked, args.top)

    checks = []
    if args.validate:
        from .validate import validate

        print("\nExposure checks (connect and identify only; nothing is exploited):")
        for check, priority, finding in validate(ranked, limit=args.top,
                                                 allow_external=args.allow_external):
            print("  " + check.line())
            checks.append({"host": check.host, "port": check.port,
                           "reachable": check.reachable, "detail": check.detail,
                           "cve": priority.cve})

    if args.json:
        payload = {
            "summary": info,
            "ranking": [{"cve": pr.cve, "score": round(pr.score, 1), "band": pr.band,
                         "basis": pr.basis, "reason": pr.reason, "details": pr.details,
                         "host": f.host, "port": f.port, "name": f.name,
                         "scanner_severity": f.severity}
                        for pr, f in ranked],
            "checks": checks,
        }
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nWrote {args.json}")


if __name__ == "__main__":
    main()
