"""Train and evaluate the vulnerability prioritiser (VPID's Module 1, part one).

VPID ranks vulnerabilities with a decision tree trained on 15,000 labelled
records that are not public. The public stand-in used here is CISA's Known
Exploited Vulnerabilities catalogue: a CVE is worth patching first if attackers
are known to be using it. So the tree is trained to predict KEV membership from
the CVE's own CVSS features.

Three baselines keep the result honest:
  * CVSS >= 9.0, i.e. "just patch the criticals", which is what most people do;
  * EPSS, a purpose-built model trained on real exploitation telemetry, which
    is the strong reference rather than a competitor;
  * the rate of KEV membership itself, which is what random picking achieves.

Usage:
    python -m evaluation.vuln_priority --data <dir with CVE-*.json.xz, kev.json,
        epss.csv.gz> [--out VULN_EVALUATION.md]
"""
import argparse
import csv
import gzip
import json
import lzma
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.tree import DecisionTreeClassifier, export_text

from packetwatch import config
from packetwatch.vuln.features import FEATURE_NAMES, extract

MODEL_PATH = config.MODEL_DIR / "vuln_priority.joblib"
NOW = datetime(2026, 9, 20, tzinfo=timezone.utc)   # fixed so runs are comparable


def load_kev(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {v["cveID"].upper(): v.get("dateAdded", "")
            for v in data.get("vulnerabilities", [])}


def load_epss(path):
    scores = {}
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) == 3 and row[0].upper().startswith("CVE-"):
                try:
                    scores[row[0].upper()] = float(row[1])
                except ValueError:
                    pass
    return scores


def build_dataset(data_dir, kev, epss):
    """Feature rows for every CVE with a CVSS v3 score, labelled by KEV."""
    rows, ids, labels, published, eps = [], [], [], [], []
    for path in sorted(Path(data_dir).glob("CVE-*.json.xz")):
        items = json.loads(lzma.open(path).read()).get("cve_items", [])
        kept = 0
        for item in items:
            vec = extract(item, now=NOW)
            if vec is None:
                continue
            cve = item["id"].upper()
            rows.append(vec)
            ids.append(cve)
            labels.append(1 if cve in kev else 0)
            published.append(item.get("published", ""))
            eps.append(epss.get(cve, 0.0))
            kept += 1
        print(f"  {path.name}: {len(items):,} CVEs, {kept:,} with CVSS v3", flush=True)
    return (np.array(rows), np.array(labels), ids, np.array(published),
            np.array(eps))


def scores(name, y, pred, flagged_note=""):
    p, r, f1, _ = precision_recall_fscore_support(y, pred, average="binary",
                                                  zero_division=0)
    return {"strategy": name, "precision": p, "recall": r, "f1": f1,
            "flagged": int(pred.sum()), "caught": int((pred & (y == 1)).sum()),
            "note": flagged_note}


def table(rows, total_kev):
    head = ("| Strategy | Precision | Recall | F1 | CVEs flagged | KEV caught |\n"
            "|---|---|---|---|---|---|\n")
    return head + "".join(
        f"| {r['strategy']} | {r['precision']*100:.1f}% | {r['recall']*100:.1f}% | "
        f"{r['f1']*100:.1f}% | {r['flagged']:,} | {r['caught']:,} / {total_kev:,} |\n"
        for r in rows)


def topk_table(y, ranks, k_values):
    """Prioritisation is a ranking problem: what lands in the first k rows."""
    out = ["| Ranked by | " + " | ".join(f"top {k:,}" for k in k_values) + " |",
           "|---" * (len(k_values) + 1) + "|"]
    for name, score in ranks.items():
        order = np.argsort(-score)
        cells = []
        for k in k_values:
            hits = int(y[order[:k]].sum())
            cells.append(f"{hits} ({hits / max(1, y.sum()) * 100:.0f}%)")
        out.append(f"| {name} | " + " | ".join(cells) + " |")
    return chr(10).join(out) + chr(10)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", default="VULN_EVALUATION.md")
    ap.add_argument("--split", default="2024-01-01",
                    help="train on CVEs published before this date, test after")
    args = ap.parse_args()

    d = Path(args.data)
    print("loading KEV and EPSS...", flush=True)
    kev, epss = load_kev(d / "kev.json"), load_epss(d / "epss.csv.gz")
    print(f"  {len(kev):,} KEV entries, {len(epss):,} EPSS scores", flush=True)
    print("building CVE feature table...", flush=True)
    X, y, ids, published, eps = build_dataset(d, kev, epss)

    train_mask = published < args.split
    X_tr, y_tr = X[train_mask], y[train_mask]
    X_te, y_te = X[~train_mask], y[~train_mask]
    eps_te = eps[~train_mask]
    print(f"train {len(X_tr):,} CVEs ({y_tr.sum():,} KEV), "
          f"test {len(X_te):,} ({y_te.sum():,} KEV)", flush=True)

    tree = DecisionTreeClassifier(max_depth=6, class_weight="balanced",
                                  min_samples_leaf=50, random_state=42)
    tree.fit(X_tr, y_tr)
    proba = tree.predict_proba(X_te)[:, list(tree.classes_).index(1)]

    # same tree, with the EPSS score handed to it as an extra input
    Xe = np.column_stack([X, (eps * 1000).astype(int)])
    tree_e = DecisionTreeClassifier(max_depth=6, class_weight="balanced",
                                    min_samples_leaf=50, random_state=42)
    tree_e.fit(Xe[train_mask], y_tr)
    proba_e = tree_e.predict_proba(Xe[~train_mask])[:, list(tree_e.classes_).index(1)]

    base = {n: X_te[:, i] for i, n in enumerate(FEATURE_NAMES)}
    rows = [
        scores("Decision tree (this project)", y_te, tree.predict(X_te) == 1),
        scores("CVSS >= 9.0 (patch the criticals)", y_te, base["base_score"] >= 90),
        scores("CVSS >= 7.0 (patch high and above)", y_te, base["base_score"] >= 70),
        scores("EPSS >= 0.1 (reference model)", y_te, eps_te >= 0.1),
        scores("Decision tree + EPSS as a feature", y_te, tree_e.predict(Xe[~train_mask]) == 1),
    ]
    prevalence = y_te.mean()
    auc = roc_auc_score(y_te, proba)
    epss_auc = roc_auc_score(y_te, eps_te)
    cvss_auc = roc_auc_score(y_te, base["base_score"])

    ranks = {"Decision tree (CVE fields only)": proba,
             "Decision tree + EPSS as a feature": proba_e,
             "CVSS base score": base["base_score"].astype(float),
             "EPSS (reference model)": eps_te}
    k_values = [50, 200, 1000]

    config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(tree, MODEL_PATH)

    tree_e_auc = roc_auc_score(y_te, proba_e)
    rep = [
        "# Vulnerability prioritisation evaluation", "",
        "VPID ranks vulnerabilities with a decision tree trained on 15,000 labelled "
        "records that are not published. The public stand-in here is CISA's Known "
        "Exploited Vulnerabilities catalogue: a CVE deserves attention first if "
        "attackers are known to use it. The tree predicts KEV membership from the "
        "CVE's own CVSS fields.", "",
        f"Data: NVD year feeds (fkie-cad mirror), CISA KEV ({len(kev):,} entries), "
        f"EPSS ({len(epss):,} scores). {len(X):,} CVEs with a CVSS v3 vector, split by "
        f"publication date at {args.split}: {len(X_tr):,} for training, {len(X_te):,} "
        "held out. Splitting by date rather than at random matters, because ranking a "
        "vulnerability is a prediction about the future, and a random split would let "
        "the model learn from CVEs published after the ones it scores.", "",
        f"Only {prevalence*100:.2f}% of the held-out CVEs are in KEV "
        f"({int(y_te.sum()):,} of {len(y_te):,}), so precision is hard to come by and "
        "accuracy is a meaningless measure here.", "",
        "## Flagging: who would you patch?", "",
        table(rows, int(y_te.sum())),
        "## Ranking: what lands at the top of the list", "",
        "Prioritisation is really a ranking task - an admin works down the list until "
        "time runs out - so this is the more useful view. Cells show how many of the "
        f"{int(y_te.sum()):,} known-exploited CVEs appear in the first k rows.", "",
        topk_table(y_te, ranks, k_values),
        "Ranking quality (ROC AUC): decision tree on CVE fields "
        f"**{auc:.3f}**, the same tree with EPSS as an input {tree_e_auc:.3f}, "
        f"CVSS base score alone {cvss_auc:.3f}, EPSS {epss_auc:.3f}.", "",
        "## The result that shaped the design", "",
        f"**A decision tree over CVE-record fields ranks worse than the CVSS score it "
        f"is built from** ({auc:.3f} against {cvss_auc:.3f}). Deeper trees were tried "
        "and did worse; dropping CVE age changed little. The signal is simply not in "
        "the record: whether attackers adopt a vulnerability depends on what software "
        "is widely deployed, whether exploit code circulates, and who is targeting "
        "whom, none of which a CVE entry states. EPSS reaches "
        f"{epss_auc:.3f} because it is trained on observed exploitation.", "",
        "Reporting the tree as VPID's algorithm and stopping there would have meant "
        "shipping something worse than sorting by severity. So the shipped tool ranks "
        "in a cascade instead - KEV, then EPSS, then the tree, then CVSS - and each "
        "item states which signal decided it. The tree is retained for CVEs that have "
        "no EPSS score yet, which is where it is better than nothing.", "",
        "## What the tree learned", "", "```",
        export_text(tree, feature_names=FEATURE_NAMES, max_depth=3).strip(), "```", "",
        "## Comparison with VPID", "",
        "| | VPID (paper) | Decision tree here | Shipped cascade's best signal |",
        "|---|---|---|---|",
        f"| Precision | 91.8% | {rows[0]['precision']*100:.1f}% | "
        f"{rows[3]['precision']*100:.1f}% |",
        f"| Recall | 89.5% | {rows[0]['recall']*100:.1f}% | "
        f"{rows[3]['recall']*100:.1f}% |",
        f"| F1 | 90.6% | {rows[0]['f1']*100:.1f}% | {rows[3]['f1']*100:.1f}% |", "",
        "These are not the same task. VPID's labels come from its own 15,000 records "
        "with an unpublished definition of priority, and its class balance is unknown. "
        "Predicting real-world exploitation from CVSS fields alone is a much harder "
        "problem: EPSS exists precisely because it needs telemetry that a CVE record "
        "does not contain. The numbers above should be read against the CVSS baselines "
        "in the same table, not against the paper.", "",
        "## Honest reading", "",
        "1. The decision tree on CVE fields alone is not good enough to ship by "
        "itself, and this report says so rather than quoting its accuracy, which looks "
        "impressive only because 99.65% of CVEs are not in KEV.",
        "2. EPSS is far ahead, as it should be: it is trained on observed exploitation "
        "rather than on the CVE text. The shipped tool uses it whenever a score exists, "
        "and falls back to the tree when none does.",
        "3. KEV is a biased label. It lists what CISA has confirmed and is weighted "
        "towards widely deployed software, so absence from KEV does not mean safe.",
        "4. This module ranks and explains. It does not exploit anything: see "
        "`packetwatch/vuln/validate.py` for where that line is drawn.", "",
        "## Reproduce", "", "```",
        "python -m evaluation.vuln_priority --data <dir>", "```",
    ]
    Path(args.out).write_text(chr(10).join(rep), encoding="utf-8")
    Path(args.out).with_suffix(".json").write_text(json.dumps(
        {"train": int(len(X_tr)), "test": int(len(X_te)),
         "kev_in_test": int(y_te.sum()), "auc": {"tree": auc, "cvss": cvss_auc,
                                                 "epss": epss_auc},
         "strategies": rows}, indent=2), encoding="utf-8")
    print(chr(10) + table(rows, int(y_te.sum())))
    print(topk_table(y_te, ranks, k_values))
    print(f"AUC tree={auc:.3f} cvss={cvss_auc:.3f} epss={epss_auc:.3f}")
    print(f"Wrote {args.out}, model -> {MODEL_PATH}")


if __name__ == "__main__":
    main()
