"""Compare lightweight ML models the way the base paper does, on our features.

Base paper: S. Ismail, S. Dandan, A. Qushou, "Intrusion Detection in IoT and
IIoT: Comparing Lightweight Machine Learning Techniques Using TON_IoT,
WUSTL-IIOT-2021, and EdgeIIoTset Datasets," IEEE Access, vol. 13, 2025.

It compares Decision Tree, Random Forest, Bagging, Stacking and LightGBM on
precision, recall, micro-F1, model size and training time, selects features
with Mutual Information, and studies class imbalance. This script repeats that
protocol on the feature windows PacketWatch actually uses, adds the two models
PacketWatch ships (Multinomial Naive Bayes, and the verified DT + NB pipeline),
and reports prediction cost, since a live IPS pays that on every sweep.

Usage:
    python -m evaluation.model_comparison --cic <dir of CIC-IDS2017 parquet>
        --unsw <dir with UNSW_Flow.parquet> [--out MODEL_COMPARISON.md]
"""
import argparse
import json
import pickle
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import BaggingClassifier, RandomForestClassifier, StackingClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.tree import DecisionTreeClassifier

from packetwatch import config
from packetwatch.features import FEATURE_NAMES
from packetwatch.model import make_tree
from packetwatch.verify import rule_counts

warnings.filterwarnings("ignore")
SEED = 42
RARE = 30          # attack types with fewer test+train windows are pooled as "Other"


def models():
    """The base paper's five models, plus the two PacketWatch ships."""
    from lightgbm import LGBMClassifier

    # Every model is trained the same way - no class weighting - so rows differ by
    # algorithm alone. Weighting is examined separately in the imbalance section:
    # on these windows it changes F1 far more than the choice of algorithm does,
    # so mixing weighted and unweighted models would compare the wrong thing.
    return {
        "Decision Tree": DecisionTreeClassifier(max_depth=6, random_state=SEED),
        "Multinomial NB": MultinomialNB(),
        "Random Forest": RandomForestClassifier(n_estimators=100, n_jobs=-1,
                                                random_state=SEED),
        "Bagging": BaggingClassifier(DecisionTreeClassifier(random_state=SEED),
                                     n_estimators=50, n_jobs=-1, random_state=SEED),
        "Stacking": StackingClassifier(
            estimators=[("dt", DecisionTreeClassifier(max_depth=6, random_state=SEED)),
                        ("rf", RandomForestClassifier(n_estimators=50, n_jobs=-1,
                                                      random_state=SEED)),
                        ("nb", MultinomialNB())],
            final_estimator=LogisticRegression(max_iter=1000), cv=3, n_jobs=-1),
        # learning rate 0.02 (with more rounds), not the default 0.1: multi-class
        # training diverges at higher rates on this imbalanced data. On TON_IoT at
        # 0.1 the validation log-loss fell to 0.08 by round 50, then blew up to 19.5
        # and the model collapsed to 0.43 micro-F1 on its own training data; on
        # UNSW-NB15 even 0.05 diverged after round 27. At 0.02 it is stable on all
        # three datasets and level with Random Forest. The Decision Tree needed no
        # such tuning, which is itself a point in its favour for a deployed IPS.
        "LightGBM": LGBMClassifier(n_estimators=400, learning_rate=0.02,
                                   random_state=SEED, verbose=-1),
    }


def size_kb(model):
    return len(pickle.dumps(model)) / 1024


def timed_fit(model, X, y):
    t0 = time.perf_counter()
    model.fit(X, y)
    return time.perf_counter() - t0


def predict_us(model, X):
    """Microseconds per sample for a batch prediction, as a sweep does it."""
    t0 = time.perf_counter()
    model.predict(X)
    return (time.perf_counter() - t0) / len(X) * 1e6


def binary_row(name, y, pred, fit_s=None, kb=None, us=None):
    p, r, f1, _ = precision_recall_fscore_support(y, pred, average="binary",
                                                  zero_division=0)
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    return {"model": name, "precision": p, "recall": r, "f1": f1,
            "micro_f1": f1_score(y, pred, average="micro"),
            "fpr": fp / (fp + tn) if fp + tn else 0.0,
            "train_s": fit_s, "size_kb": kb, "predict_us": us}


def pool_rare(labels):
    counts = labels.value_counts()
    rare = set(counts[counts < RARE].index)
    return labels.where(~labels.isin(rare), "Other")


def compare(data, name):
    """Binary and multi-class comparison of every model on one dataset."""
    X = data[FEATURE_NAMES].to_numpy()
    y_bin = data["label"].to_numpy().astype(int)
    y_multi = pool_rare(data["attack_label"].replace("", "Benign").fillna("Benign")
                        .astype(str).str.strip())
    idx_tr, idx_te = train_test_split(np.arange(len(data)), test_size=0.3,
                                      random_state=SEED, stratify=y_bin)
    Xtr, Xte = X[idx_tr], X[idx_te]
    ytr, yte = y_bin[idx_tr], y_bin[idx_te]
    mtr, mte = y_multi.to_numpy()[idx_tr], y_multi.to_numpy()[idx_te]

    binary, multi, fitted = [], [], {}
    for mname, model in models().items():
        print(f"  [{name}] {mname}: binary...", flush=True)
        fit_s = timed_fit(model, Xtr, ytr)
        pred = model.predict(Xte)
        binary.append(binary_row(mname, yte, pred, fit_s, size_kb(model),
                                 predict_us(model, Xte)))
        fitted[mname] = model

        print(f"  [{name}] {mname}: multi-class...", flush=True)
        mmodel = models()[mname]
        mfit = timed_fit(mmodel, Xtr, mtr)
        mpred = mmodel.predict(Xte)
        multi.append({"model": mname,
                      "micro_f1": f1_score(mte, mpred, average="micro"),
                      "macro_f1": f1_score(mte, mpred, average="macro", zero_division=0),
                      "weighted_f1": f1_score(mte, mpred, average="weighted",
                                              zero_division=0),
                      "train_s": mfit, "size_kb": size_kb(mmodel)})

    # the shipped configuration: make_tree() DT, NB, OR fusion, rule verification
    shipped_dt = fitted["Decision Tree"]          # identical to make_tree()
    fused = (shipped_dt.predict(Xte) == 1) | \
            (fitted["Multinomial NB"].predict(Xte) == 1)
    counts = rule_counts(Xte)
    trigger = config.INDEPENDENT_RULE_TRIGGER
    shipped = (fused & (counts >= 1)) | ((counts >= trigger) if trigger else False)
    binary.append(binary_row("PacketWatch (DT or NB + rule verification)", yte,
                             shipped.astype(int),
                             binary[0]["train_s"] + binary[1]["train_s"],
                             binary[0]["size_kb"] + binary[1]["size_kb"],
                             binary[0]["predict_us"] + binary[1]["predict_us"]))

    classes = pd.Series(y_multi).value_counts()
    return {"dataset": name, "n": len(data), "attack_share": float(y_bin.mean()),
            "classes": classes.to_dict(), "binary": binary, "multi": multi,
            "train": (Xtr, ytr), "test": (Xte, yte)}


def mutual_information(result, sample=150_000):
    """MI of each feature with the attack label, and DT accuracy on top-k."""
    Xtr, ytr = result["train"]
    Xte, yte = result["test"]
    rng = np.random.default_rng(SEED)
    pick = rng.choice(len(Xtr), size=min(sample, len(Xtr)), replace=False)
    # discrete estimator: every feature is an integer count. The continuous (kNN)
    # estimator was tried first and scored a constant column at 0.03, an artefact.
    mi = mutual_info_classif(Xtr[pick], ytr[pick], discrete_features=True,
                             random_state=SEED)
    order = np.argsort(-mi)
    ranking = [{"feature": FEATURE_NAMES[i], "mi": float(mi[i])} for i in order]

    subsets = []
    for k in (2, 3, 5, 7, 10):
        cols = order[:k]
        dt = make_tree()
        dt.fit(Xtr[:, cols], ytr)
        pred = dt.predict(Xte[:, cols])
        p, r, f1, _ = precision_recall_fscore_support(yte, pred, average="binary",
                                                      zero_division=0)
        subsets.append({"k": k, "features": [FEATURE_NAMES[i] for i in cols],
                        "precision": p, "recall": r, "f1": f1})
    return ranking, subsets


def imbalance(result):
    """Decision Tree with and without class weighting, as the paper examines."""
    Xtr, ytr = result["train"]
    Xte, yte = result["test"]
    rows = []
    for label, weight in (("unweighted", None), ("class-balanced", "balanced")):
        dt = DecisionTreeClassifier(max_depth=6, class_weight=weight, random_state=SEED)
        dt.fit(Xtr, ytr)
        rows.append(binary_row(f"Decision Tree, {label}", yte, dt.predict(Xte)))
    return rows


# ---- report -------------------------------------------------------------------------

def _fmt(value, spec, unit=""):
    return "-" if value is None else f"{value:{spec}}{unit}"


def binary_table(rows, costs=True):
    head = "| Model | Precision | Recall | F1 | FPR |"
    rule = "|---|---|---|---|---|"
    if costs:
        head += " Train time | Model size | Predict / sample |"
        rule += "---|---|---|"
    out = [head, rule]
    for r in rows:
        line = (f"| {r['model']} | {r['precision']:.3f} | {r['recall']:.3f} | "
                f"{r['f1']:.3f} | {r['fpr']*100:.2f}% |")
        if costs:
            line += (f" {_fmt(r['train_s'], '.1f', ' s')} | "
                     f"{_fmt(r['size_kb'], ',.0f', ' KB')} | "
                     f"{_fmt(r['predict_us'], '.2f', ' us')} |")
        out.append(line)
    return "\n".join(out) + "\n"


def multi_table(rows):
    out = ["| Model | Micro-F1 | Macro-F1 | Weighted-F1 | Train time | Model size |",
           "|---|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['model']} | {r['micro_f1']:.4f} | {r['macro_f1']:.3f} | "
                   f"{r['weighted_f1']:.4f} | {r['train_s']:.1f} s | "
                   f"{r['size_kb']:,.0f} KB |")
    return "\n".join(out) + "\n"


def mi_table(ranking):
    top = ranking[0]["mi"] or 1
    out = ["| Rank | Feature | Mutual Information | Relative |", "|---|---|---|---|"]
    for i, r in enumerate(ranking, 1):
        out.append(f"| {i} | `{r['feature']}` | {r['mi']:.4f} | "
                   f"{'#' * max(1, round(r['mi'] / top * 20))} |")
    return "\n".join(out) + "\n"


def subset_table(rows):
    out = ["| Top-k features by MI | Precision | Recall | F1 |", "|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['k']} ({', '.join(r['features'][:3])}"
                   f"{', ...' if r['k'] > 3 else ''}) | {r['precision']:.3f} | "
                   f"{r['recall']:.3f} | {r['f1']:.3f} |")
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cic", required=True)
    ap.add_argument("--unsw", required=True)
    ap.add_argument("--out", default="MODEL_COMPARISON.md")
    args = ap.parse_args()

    from evaluation import cicids2017, unsw_nb15

    print("building CIC-IDS2017 windows (60 s)...", flush=True)
    cic = pd.concat([cicids2017.build_windows(cicids2017.load_flows(f, 60), 60)
                     for f in sorted(Path(args.cic).glob("*.parquet"))], ignore_index=True)
    print("building UNSW-NB15 windows (10 s)...", flush=True)
    unsw = unsw_nb15.build_windows(pd.read_parquet(
        Path(args.unsw) / "UNSW_Flow.parquet", columns=unsw_nb15.COLS))

    results = []
    for name, data in (("UNSW-NB15", unsw), ("CIC-IDS2017", cic)):
        res = compare(data, name)
        res["mi"], res["subsets"] = mutual_information(res)
        res["imbalance"] = imbalance(res)
        results.append(res)

    rep = [
        "# Lightweight model comparison", "",
        "Protocol follows the base paper: S. Ismail, S. Dandan and A. Qushou, "
        "\"Intrusion Detection in IoT and IIoT: Comparing Lightweight Machine Learning "
        "Techniques Using TON_IoT, WUSTL-IIOT-2021, and EdgeIIoTset Datasets,\" *IEEE "
        "Access*, vol. 13, pp. 73468-73485, 2025. Its five models (Decision Tree, Random "
        "Forest, Bagging, Stacking, LightGBM) are compared on precision, recall, "
        "micro-F1, model size and training time, with Mutual Information feature "
        "ranking and a class-imbalance check. Two rows are added: Multinomial Naive "
        "Bayes, which PacketWatch ships, and the full PacketWatch pipeline, where either "
        "model's flag must be confirmed by a rule. Prediction time per sample is also "
        "reported, because a live system pays it on every sweep.", "",
        "Every model sees the same 10 features PacketWatch extracts from live traffic, "
        "computed per (source, destination host, window), with a stratified 70/30 split. "
        "All models are trained without class weighting, so they differ by algorithm "
        "alone. The Decision Tree row is exactly the configuration PacketWatch ships "
        "(`packetwatch.model.make_tree`), and weighting is examined in its own section. "
        "Because "
        "windows are per destination host, `unique_dst_ips` is always 1 here and carries "
        "no information by construction.",
        "",
    ]
    for res in results:
        cls = ", ".join(f"{k} ({v:,})" for k, v in list(res["classes"].items())[:8])
        rep += [
            f"## {res['dataset']}", "",
            f"{res['n']:,} windows, {res['attack_share']*100:.2f}% containing attack "
            f"traffic. Classes: {cls}.", "",
            "### Binary: attack vs. normal", "", binary_table(res["binary"]),
            "### Multi-class: which attack", "",
            "Micro-F1 is dominated by the majority class on imbalanced data, which is "
            "why macro-F1 (every class weighted equally) is shown beside it.", "",
            multi_table(res["multi"]),
            "### Mutual Information feature ranking", "", mi_table(res["mi"]),
            "Decision Tree using only the top-k features by MI:", "",
            subset_table(res["subsets"]),
            "### Class imbalance", "",
            "The same Decision Tree trained with and without class weighting. Attack "
            "windows are the minority, so an unweighted tree can score well by "
            "favouring the normal class.", "",
            binary_table(res["imbalance"], costs=False),
        ]
    rep += ["## Reproduce", "", "```",
            "python -m evaluation.model_comparison --cic <dir> --unsw <dir>", "```"]

    text = "\n".join(rep).replace("| None s |", "| - |")
    Path(args.out).write_text(text, encoding="utf-8")
    slim = [{k: v for k, v in r.items() if k not in ("train", "test")} for r in results]
    Path(args.out).with_suffix(".json").write_text(json.dumps(slim, indent=2, default=str),
                                                   encoding="utf-8")
    for res in results:
        print(f"\n{res['dataset']}\n" + binary_table(res["binary"]))
        print(multi_table(res["multi"]))
        print(mi_table(res["mi"]))
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
