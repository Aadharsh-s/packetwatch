"""REQ 2: Decision Tree + Multinomial Naive Bayes detection layer.

Fusion rule (our own design choice; VPID does not publish one):
traffic is flagged when EITHER classifier predicts "attack". False positives
from this permissive OR are filtered by the rule-based verification layer.
"""
import csv
import random

import joblib
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.tree import DecisionTreeClassifier

from . import config
from .features import FEATURE_NAMES

DT_PATH = config.MODEL_DIR / "dt.joblib"
NB_PATH = config.MODEL_DIR / "nb.joblib"

BENIGN, ATTACK = 0, 1


def _vec(r, n, pps, ports, ips, tcp, udp, icmp, syn, susp, lenb):
    """Build a feature vector with internally consistent counts."""
    n = max(1, n)
    return [
        n,
        min(pps, n),
        min(ports, n),
        min(ips, n),
        min(tcp, n),
        min(udp, n),
        min(icmp, n),
        min(syn, n),
        min(susp, n),
        lenb,
    ]


# --- behaviour profiles: each returns one synthetic 10 s window ---------------

def _elapsed(r):
    """Seconds of the 10 s window the behaviour has been running for.

    Sources are judged about once a second, so an attack is usually first seen
    only 1-2 s in; training on partial windows teaches that early shape.
    """
    return r.randint(1, config.WINDOW_SECONDS)


def _browsing(r):
    pps = r.randint(1, 40)
    n = pps * _elapsed(r)
    return _vec(r, n, pps, r.randint(1, 3), 1, n, r.randint(0, 3), 0,
                r.randint(0, 2), 0, r.randint(3, 14))


def _dns(r):
    pps = r.randint(1, 5)
    n = pps * _elapsed(r)
    return _vec(r, n, pps, r.randint(1, 2), 1, 0, n, 0, 0, 0, r.randint(0, 2))


def _streaming(r):
    pps = r.randint(20, 90)
    n = pps * _elapsed(r)
    tcp = r.random() < 0.5
    return _vec(r, n, pps, r.randint(1, 2), 1, n if tcp else 0,
                0 if tcp else n, 0, r.randint(0, 1), 0, r.randint(10, 14))


def _lan_chatter(r):
    n = r.randint(1, 40)
    udp = r.randint(n // 2, n)
    return _vec(r, n, r.randint(1, 10), r.randint(1, 6), r.randint(1, 5), n - udp, udp,
                r.randint(0, 2), r.randint(0, 2), r.randint(0, 2), r.randint(0, 5))


def _syn_scan(r):
    pps = r.randint(5, 300)
    n = pps * _elapsed(r)
    return _vec(r, n, pps, r.randint(max(5, n // 2), n), 1, n, 0, 0,
                r.randint(int(n * 0.9), n), r.randint(0, 10), r.randint(0, 1))


def _slow_scan(r):
    n = r.randint(5, 30)
    return _vec(r, n, r.randint(1, 3), r.randint(max(4, n - 2), n), 1, n, 0, 0,
                r.randint(n - 1, n), r.randint(0, 2), 0)


def _flood(r, proto_idx, syn=False):
    pps = r.randint(100, 2000)
    n = pps * _elapsed(r)
    counts = [0, 0, 0]
    counts[proto_idx] = n
    ports = 0 if proto_idx == 2 else r.randint(1, 5)
    return _vec(r, n, pps, ports, 1, *counts,
                r.randint(int(n * 0.9), n) if syn else 0, 0,
                0 if syn else r.randint(0, 14))


def _udp_flood(r):
    return _flood(r, 1)


def _icmp_flood(r):
    return _flood(r, 2)


def _syn_flood(r):
    return _flood(r, 0, syn=True)


def _suspicious_bruteforce(r):
    pps = r.randint(1, 30)
    n = max(3, pps * _elapsed(r))
    return _vec(r, n, pps, r.randint(1, 2), 1, n, 0, 0,
                r.randint(n // 3, n), n, r.randint(0, 2))


BENIGN_PROFILES = [_browsing, _dns, _streaming, _lan_chatter]
ATTACK_PROFILES = [_syn_scan, _slow_scan, _udp_flood, _icmp_flood, _syn_flood,
                   _suspicious_bruteforce]


def generate_training_data(n_per_profile=500, seed=42):
    r = random.Random(seed)
    X, y = [], []
    for profiles, label in ((BENIGN_PROFILES, BENIGN), (ATTACK_PROFILES, ATTACK)):
        # balance classes: same total samples for each label
        per = n_per_profile * 5 // len(profiles)
        for profile in profiles:
            for _ in range(per):
                X.append(profile(r))
                y.append(label)
    return X, y


def load_csv(path):
    """CSV with header FEATURE_NAMES + 'label' (0 benign / 1 attack)."""
    X, y = [], []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            X.append([int(float(row[name])) for name in FEATURE_NAMES])
            y.append(int(row["label"]))
    return X, y


def make_tree():
    """The Decision Tree configuration, shared by training and every evaluation.

    No class weighting. It was 'balanced' until MODEL_COMPARISON.md measured it on
    real, imbalanced traffic: on UNSW-NB15 it cut F1 from 0.733 to 0.438 and raised
    false alarms from 0.95% to 16.8%. The synthetic training set is already
    balanced, so dropping it leaves the shipped model's decisions unchanged, and
    it stops the problem from appearing if the model is retrained on real traffic.
    """
    return DecisionTreeClassifier(max_depth=6, random_state=42)


def train(csv_path=None, verbose=True):
    X, y = generate_training_data()
    if csv_path:
        cx, cy = load_csv(csv_path)
        X += cx
        y += cy
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=42,
                                              stratify=y)
    dt = make_tree()
    nb = MultinomialNB()
    dt.fit(X_tr, y_tr)
    nb.fit(X_tr, y_tr)
    if verbose:
        names = ["benign", "attack"]
        print("== Decision Tree ==")
        print(classification_report(y_te, dt.predict(X_te), target_names=names))
        print("== Multinomial Naive Bayes ==")
        print(classification_report(y_te, nb.predict(X_te), target_names=names))
    config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(dt, DT_PATH)
    joblib.dump(nb, NB_PATH)
    if verbose:
        print(f"Saved models to {config.MODEL_DIR}")
    return dt, nb


class Detector:
    def __init__(self, dt=None, nb=None):
        if dt is None or nb is None:
            if DT_PATH.exists() and NB_PATH.exists():
                dt, nb = joblib.load(DT_PATH), joblib.load(NB_PATH)
            else:
                print("[model] No saved models found - training on synthetic data...")
                dt, nb = train(verbose=False)
        self.dt, self.nb = dt, nb

    def predict(self, vec):
        return self.predict_many([vec])[0]

    def predict_many(self, vecs):
        """Classify several feature vectors in one call.

        sklearn's per-call overhead dwarfs the work for a single row, so the
        pipeline classifies every pending source in one batch per sweep.
        """
        if not vecs:
            return []
        dt_col = list(self.dt.classes_).index(ATTACK)
        nb_col = list(self.nb.classes_).index(ATTACK)
        dt_proba = self.dt.predict_proba(vecs)[:, dt_col]
        nb_proba = self.nb.predict_proba(vecs)[:, nb_col]
        out = []
        for dp, np_ in zip(dt_proba, nb_proba):
            dt_flag, nb_flag = dp >= 0.5, np_ >= 0.5
            out.append({
                "dt": bool(dt_flag),
                "nb": bool(nb_flag),
                "dt_proba": round(float(dp), 3),
                "nb_proba": round(float(np_), 3),
                "flagged": bool(dt_flag or nb_flag),  # OR fusion
            })
        return out
