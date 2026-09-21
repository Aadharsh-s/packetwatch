"""Replicate the base paper's protocol on TON_IoT, its own primary dataset.

Base paper: S. Ismail, S. Dandan, A. Qushou, "Intrusion Detection in IoT and
IIoT: Comparing Lightweight Machine Learning Techniques Using TON_IoT,
WUSTL-IIOT-2021, and EdgeIIoTset Datasets," IEEE Access, vol. 13, 2025.

Why this differs from the CIC-IDS2017 and UNSW-NB15 evaluations: the TON_IoT
network train/test file has no timestamp column, so PacketWatch's per-source
time windows cannot be built from it without inventing time. The base paper
classifies TON_IoT record by record on the dataset's own features, so that is
what is done here - it is the closer replication anyway:

  1. drop identifiers and free-text fields, encode categorical fields;
  2. rank features by Mutual Information and pick a subset, as the paper does;
  3. compare Decision Tree, Random Forest, Bagging, Stacking, LightGBM and
     Multinomial NB on precision, recall, micro/macro-F1, model size, training
     time and prediction cost, binary and multi-class;
  4. check class imbalance;
  5. cross-dataset transfer: train on TON_IoT, test on UNSW-NB15 (and back) on
     the fields both datasets share, mirroring the paper's TON_IoT -> WUSTL test.

Usage:
    python -m evaluation.ton_iot --data <dir with train_test_network.csv>
        --unsw <dir with UNSW_Flow.parquet> [--out TON_IOT_EVALUATION.md]
"""
import argparse
import json
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_selection import mutual_info_classif
from sklearn.metrics import f1_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

from evaluation.model_comparison import (binary_row, binary_table, models, multi_table,
                                         predict_us, size_kb, timed_fit)
from packetwatch.model import make_tree

warnings.filterwarnings("ignore")
SEED = 42

# identifiers would let a model memorise hosts rather than learn behaviour, and
# free-text fields (URIs, user agents, certificate subjects) are not features
DROP = ["src_ip", "dst_ip", "src_port", "dns_query", "ssl_subject", "ssl_issuer",
        "http_uri", "http_user_agent", "label", "type"]
CATEGORICAL = ["proto", "service", "conn_state", "dns_AA", "dns_RD", "dns_RA",
               "dns_rejected", "ssl_version", "ssl_cipher", "ssl_resumed",
               "ssl_established", "http_trans_depth", "http_method", "http_version",
               "http_orig_mime_types", "http_resp_mime_types", "weird_name",
               "weird_addl", "weird_notice"]

# fields TON_IoT (Zeek) and UNSW-NB15 (Argus) both record, for the transfer test
SHARED = {  # common name: (TON_IoT column, UNSW-NB15 column)
    "duration": ("duration", "dur"),
    "src_bytes": ("src_bytes", "sbytes"),
    "dst_bytes": ("dst_bytes", "dbytes"),
    "src_pkts": ("src_pkts", "spkts"),
    "dst_pkts": ("dst_pkts", "dpkts"),
    "dst_port": ("dst_port", "destination_port"),
    "proto": ("proto", "protocol"),
}
PROTO_CODE = {"tcp": 0, "udp": 1, "icmp": 2}


def load(path):
    df = pd.read_csv(path, low_memory=False)
    y_bin = df["label"].astype(int).to_numpy()
    y_type = df["type"].astype(str).to_numpy()
    X = df.drop(columns=[c for c in DROP if c in df.columns])
    for col in CATEGORICAL:
        if col in X.columns:
            X[col] = X[col].astype(str).astype("category").cat.codes
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)
    X = X.clip(lower=0)                         # MultinomialNB needs non-negative input
    X = X.loc[:, X.nunique() > 1]               # constant columns carry no information
    return X, y_bin, y_type


def mi_rank(X, y):
    discrete = np.array([c in CATEGORICAL or c == "dst_port" for c in X.columns])
    rng = np.random.default_rng(SEED)
    pick = rng.choice(len(X), size=min(100_000, len(X)), replace=False)
    mi = mutual_info_classif(X.iloc[pick].to_numpy(), y[pick], discrete_features=discrete,
                             random_state=SEED)
    return sorted(zip(X.columns, mi), key=lambda t: -t[1])


def choose_k(X, y, ranking):
    """Smallest top-k whose Decision Tree F1 is within 0.005 of using everything."""
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=SEED,
                                          stratify=y)
    rows, ks = [], [3, 5, 8, 10, 15, len(ranking)]
    for k in sorted(set(min(k, len(ranking)) for k in ks)):
        cols = [c for c, _ in ranking[:k]]
        dt = make_tree().fit(Xtr[cols], ytr)
        rows.append({"k": k, "f1": f1_score(yte, dt.predict(Xte[cols]))})
    best = max(r["f1"] for r in rows)
    chosen = min(r["k"] for r in rows if r["f1"] >= best - 0.005)
    return chosen, rows


def compare(X, y_bin, y_type):
    idx = np.arange(len(X))
    tr, te = train_test_split(idx, test_size=0.3, random_state=SEED, stratify=y_type)
    Xtr, Xte = X.iloc[tr].to_numpy(), X.iloc[te].to_numpy()
    binary, multi = [], []
    for name, model in models().items():
        print(f"  {name}...", flush=True)
        fit_s = timed_fit(model, Xtr, y_bin[tr])
        binary.append(binary_row(name, y_bin[te], model.predict(Xte), fit_s,
                                 size_kb(model), predict_us(model, Xte)))
        mm = models()[name]
        mfit = timed_fit(mm, Xtr, y_type[tr])
        mp = mm.predict(Xte)
        multi.append({"model": name, "micro_f1": f1_score(y_type[te], mp, average="micro"),
                      "macro_f1": f1_score(y_type[te], mp, average="macro", zero_division=0),
                      "weighted_f1": f1_score(y_type[te], mp, average="weighted",
                                              zero_division=0),
                      "train_s": mfit, "size_kb": size_kb(mm)})
    return binary, multi, (Xtr, y_bin[tr], Xte, y_bin[te])


def imbalance(split):
    from sklearn.tree import DecisionTreeClassifier

    Xtr, ytr, Xte, yte = split
    return [binary_row(f"Decision Tree, {label}", yte,
                       DecisionTreeClassifier(max_depth=6, class_weight=w,
                                              random_state=SEED).fit(Xtr, ytr).predict(Xte))
            for label, w in (("unweighted", None), ("class-balanced", "balanced"))]


def shared_frame(df, which):
    """Project a dataset onto the fields TON_IoT and UNSW-NB15 share."""
    i = 0 if which == "ton" else 1
    out = pd.DataFrame({name: df[cols[i]] for name, cols in SHARED.items()})
    out["proto"] = out["proto"].astype(str).str.lower().map(PROTO_CODE).fillna(3)
    return out.apply(pd.to_numeric, errors="coerce").fillna(0).clip(lower=0)


def transfer(ton_path, unsw_dir):
    """Train on one dataset, test on the other - the paper's generalisation test."""
    ton = pd.read_csv(ton_path, low_memory=False)
    unsw = pd.read_parquet(Path(unsw_dir) / "UNSW_Flow.parquet",
                           columns=[c[1] for c in SHARED.values()] + ["binary_label"])
    # keep UNSW's attack share as it is, but sample it to TON_IoT's size
    unsw = unsw.sample(n=min(len(unsw), 300_000), random_state=SEED)
    sets = {"TON_IoT": (shared_frame(ton, "ton"), ton["label"].astype(int).to_numpy()),
            "UNSW-NB15": (shared_frame(unsw, "unsw"),
                          unsw["binary_label"].astype(int).to_numpy())}
    rows = []
    for src, dst in (("TON_IoT", "UNSW-NB15"), ("UNSW-NB15", "TON_IoT")):
        (Xs, ys), (Xd, yd) = sets[src], sets[dst]
        # within-dataset reference on the same shared fields
        a, b, c, d = train_test_split(Xs, ys, test_size=0.3, random_state=SEED, stratify=ys)
        for name in ("Decision Tree", "Random Forest", "LightGBM"):
            same = models()[name].fit(a, c)
            p_same = precision_recall_fscore_support(d, same.predict(b), average="binary",
                                                     zero_division=0)
            cross = models()[name].fit(Xs, ys)
            p_cross = precision_recall_fscore_support(yd, cross.predict(Xd), average="binary",
                                                      zero_division=0)
            rows.append({"train": src, "test": dst, "model": name,
                         "same_f1": p_same[2], "cross_precision": p_cross[0],
                         "cross_recall": p_cross[1], "cross_f1": p_cross[2]})
            print(f"  transfer {src}->{dst} {name}: same-dataset F1 {p_same[2]:.3f}, "
                  f"cross-dataset F1 {p_cross[2]:.3f}", flush=True)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--unsw", required=True)
    ap.add_argument("--out", default="TON_IOT_EVALUATION.md")
    args = ap.parse_args()
    path = Path(args.data) / "train_test_network.csv"

    X, y_bin, y_type = load(path)
    counts = pd.Series(y_type).value_counts()
    print(f"{len(X):,} records, {X.shape[1]} usable features", flush=True)

    ranking = mi_rank(X, y_bin)
    k, k_rows = choose_k(X, y_bin, ranking)
    selected = [c for c, _ in ranking[:k]]
    print(f"MI selection: top {k} of {len(ranking)} features", flush=True)

    binary, multi, split = compare(X[selected], y_bin, y_type)
    imb = imbalance(split)
    trans = transfer(path, args.unsw)

    mi_lines = ["| Rank | Feature | Mutual Information |", "|---|---|---|"]
    mi_lines += [f"| {i} | `{c}` | {v:.4f} |" for i, (c, v) in enumerate(ranking[:15], 1)]
    k_lines = ["| Top-k features | Decision Tree F1 |", "|---|---|"]
    k_lines += [f"| {r['k']}{' (chosen)' if r['k'] == k else ''} | {r['f1']:.4f} |"
                for r in k_rows]
    t_lines = ["| Train on | Test on | Model | F1 within the training dataset | "
               "Precision on the other | Recall on the other | F1 on the other |",
               "|---|---|---|---|---|---|---|"]
    t_lines += [f"| {r['train']} | {r['test']} | {r['model']} | {r['same_f1']:.3f} | "
                f"{r['cross_precision']:.3f} | {r['cross_recall']:.3f} | "
                f"**{r['cross_f1']:.3f}** |" for r in trans]

    rep = [
        "# Base-paper protocol on TON_IoT", "",
        "Replicates the protocol of the base paper - S. Ismail, S. Dandan and A. Qushou, "
        "\"Intrusion Detection in IoT and IIoT: Comparing Lightweight Machine Learning "
        "Techniques Using TON_IoT, WUSTL-IIOT-2021, and EdgeIIoTset Datasets,\" *IEEE "
        "Access*, vol. 13, pp. 73468-73485, 2025 - on TON_IoT, its primary dataset.", "",
        "## Data", "",
        f"TON_IoT network train/test set (Hugging Face mirror `codymlewis/TON_IoT_network`): "
        f"{len(X):,} records. Classes: "
        + ", ".join(f"{k_} ({v:,})" for k_, v in counts.items()) + ".", "",
        "**Why records, not PacketWatch windows.** This file has no timestamp column, so "
        "the per-source time windows PacketWatch uses cannot be built without inventing "
        "time. The base paper classifies TON_IoT record by record on the dataset's own "
        "features, which is what is done here, so these numbers compare with the paper "
        "rather than with the live system. Source and destination IPs, source ports and "
        "free-text fields (URIs, user agents, certificate subjects) are dropped so models "
        "learn behaviour rather than memorising hosts; categorical fields are encoded.", "",
        "## Mutual Information feature selection", "", "\n".join(mi_lines), "",
        f"The paper selects features by MI. Here the subset is the smallest top-k whose "
        f"Decision Tree F1 is within 0.005 of using every feature:", "",
        "\n".join(k_lines), "",
        f"Selected: {', '.join(f'`{c}`' for c in selected)}.", "",
        "## Model comparison (binary: attack vs. normal)", "",
        "All models trained without class weighting, on the MI-selected features, with a "
        "stratified 70/30 split.", "",
        binary_table(binary),
        "## Model comparison (multi-class: attack type)", "",
        "Macro-F1 weights every class equally, so it exposes the rare MITM class that "
        "micro-F1 hides.", "",
        multi_table(multi),
        "## Class imbalance", "",
        "TON_IoT's train/test set is attack-majority (76% attack records), the reverse "
        "of the other datasets.", "",
        binary_table(imb, costs=False),
        "## Cross-dataset transfer", "",
        "The paper trains on TON_IoT and tests on WUSTL-IIoT-2021 to show models "
        "generalise. WUSTL-IIoT-2021 is not available from a public mirror, so the same "
        "test is run between TON_IoT and UNSW-NB15, on the seven fields both record "
        f"({', '.join(SHARED)}). UNSW-NB15 is sampled to 300,000 records.", "",
        "\n".join(t_lines), "",
        "## Reproduce", "", "```",
        "python -m evaluation.ton_iot --data <dir> --unsw <dir>", "```",
    ]
    Path(args.out).write_text("\n".join(rep), encoding="utf-8")
    Path(args.out).with_suffix(".json").write_text(json.dumps(
        {"records": len(X), "classes": counts.to_dict(),
         "mi": [(c, float(v)) for c, v in ranking], "k": k, "k_rows": k_rows,
         "selected": selected, "binary": binary, "multi": multi,
         "imbalance": imb, "transfer": trans}, indent=2, default=str), encoding="utf-8")
    print("\n" + binary_table(binary)); print(multi_table(multi))
    print("\n".join(t_lines)); print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
