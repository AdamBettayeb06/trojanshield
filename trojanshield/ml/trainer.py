"""
ml/trainer.py - Training Pipeline
===================================
Generates labeled feature vectors from samples and trains the classifier.
In production: fed by hundreds of parallel VM runs.

Usage:
  python -m ml.trainer --samples ./samples --output ./ml/model.json
  python -m ml.trainer --demo   (generates synthetic dataset + trains)
"""

import json
import math
import random
import argparse
import numpy as np
from pathlib import Path
from collections import Counter
from core.utils import Colors, entropy, extract_strings


# -- Synthetic training data generator ----------------------------------------

FAMILY_PROFILES = {
    "RAT": {
        "entropy_range":      (5.5, 7.8),
        "import_keywords":    ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                               "InternetOpenUrl", "WinExec"],
        "string_keywords":    ["shell", "command", "connect", "backdoor", "rat", "http"],
        "persistence":        True,
        "anti_analysis":      True,
        "network":            True,
    },
    "InfoStealer": {
        "entropy_range":      (4.5, 6.5),
        "import_keywords":    ["GetAsyncKeyState", "SetWindowsHookEx", "CryptEncrypt",
                               "InternetOpenUrl"],
        "string_keywords":    ["password", "cookie", "credential", "Login Data",
                               "chrome", "firefox", "steal"],
        "persistence":        False,
        "anti_analysis":      False,
        "network":            True,
    },
    "BankingTrojan": {
        "entropy_range":      (6.0, 7.5),
        "import_keywords":    ["WriteProcessMemory", "CryptDecrypt", "InternetOpenUrl"],
        "string_keywords":    ["webinject", "formgrab", "banking", "transfer",
                               "paypal", "bitcoin"],
        "persistence":        True,
        "anti_analysis":      True,
        "network":            True,
    },
    "Dropper": {
        "entropy_range":      (6.5, 7.9),
        "import_keywords":    ["URLDownloadToFile", "WinExec", "ShellExecute",
                               "CreateProcess"],
        "string_keywords":    ["download", "http", "payload", "install",
                               "temp", "drop"],
        "persistence":        False,
        "anti_analysis":      False,
        "network":            True,
    },
    "Ransomware": {
        "entropy_range":      (7.0, 7.95),
        "import_keywords":    ["CryptEncrypt", "CryptGenKey", "FindFirstFile",
                               "WriteFile"],
        "string_keywords":    ["encrypt", "ransom", "bitcoin", "decrypt",
                               "your files", "vssadmin"],
        "persistence":        True,
        "anti_analysis":      True,
        "network":            True,
    },
    "Keylogger": {
        "entropy_range":      (4.0, 6.0),
        "import_keywords":    ["GetAsyncKeyState", "SetWindowsHookEx", "GetForegroundWindow"],
        "string_keywords":    ["keylog", "keystroke", "capture", "clipboard", "screenshot"],
        "persistence":        True,
        "anti_analysis":      False,
        "network":            True,
    },
    "Backdoor": {
        "entropy_range":      (5.0, 7.0),
        "import_keywords":    ["RegSetValueEx", "CreateService", "OpenSCManager"],
        "string_keywords":    ["persist", "service", "startup", "autorun", "backdoor"],
        "persistence":        True,
        "anti_analysis":      True,
        "network":            True,
    },
    "BENIGN": {
        "entropy_range":      (3.5, 6.0),
        "import_keywords":    ["CreateWindow", "DrawText", "HeapAlloc", "ExitProcess"],
        "string_keywords":    ["help", "version", "copyright", "license", "about"],
        "persistence":        False,
        "anti_analysis":      False,
        "network":            False,
    },
}

FAMILY_LABELS = {f: i for i, f in enumerate(FAMILY_PROFILES.keys())}


def generate_feature_vector(family: str, noise: float = 0.1) -> np.ndarray:
    """Generate a synthetic 50-dim feature vector for a given malware family."""
    profile = FAMILY_PROFILES[family]
    rng     = random.Random()
    features = []

    # 1. Byte histogram (16 bins)
    ent_lo, ent_hi = profile["entropy_range"]
    target_entropy  = rng.uniform(ent_lo, ent_hi)
    # Approximate histogram that produces this entropy
    base_hist = [1.0/16] * 16
    if target_entropy > 6.0:
        # Flatten histogram (more uniform = higher entropy)
        hist = base_hist
    else:
        # Spike a few bins (less uniform = lower entropy)
        hist = [0.02] * 16
        for _ in range(4):
            hist[rng.randint(0,15)] += 0.2
        total = sum(hist)
        hist  = [h/total for h in hist]

    features.extend([h + rng.gauss(0, noise*0.02) for h in hist])

    # 2. Entropy features (5)
    features.append(target_entropy / 8.0)
    features.append(min(1.0, (target_entropy + rng.gauss(0, 0.3)) / 8.0))
    features.append(max(0.0, (target_entropy - 1.0 + rng.gauss(0, 0.3)) / 8.0))
    features.append(rng.uniform(0.2, 0.8) if target_entropy > 6.5 else rng.uniform(0, 0.3))
    features.append(rng.uniform(0.1, 0.5))

    # 3. File size
    size_range = {
        "RAT": (50000, 500000), "InfoStealer": (20000, 200000),
        "BankingTrojan": (100000, 800000), "Dropper": (10000, 100000),
        "Ransomware": (50000, 400000), "Keylogger": (10000, 150000),
        "Backdoor": (30000, 300000), "BENIGN": (10000, 10000000),
    }
    lo, hi = size_range.get(family, (10000, 500000))
    fsize  = rng.randint(lo, hi)
    features.append(min(1.0, math.log10(max(fsize, 1)) / 8.0))

    # 4. String features (8)
    n_strings = rng.randint(50, 500) if family == "BENIGN" else rng.randint(10, 200)
    features.append(n_strings / 1000.0)
    features.append(1.0 if profile["network"] else rng.uniform(0, 0.1))
    features.append(1.0 if family in ["RAT","Backdoor"] else rng.uniform(0, 0.2))
    features.append(1.0 if family in ["Dropper","Ransomware"] else rng.uniform(0, 0.2))
    features.append(1.0 if profile["persistence"] else rng.uniform(0, 0.15))
    features.append(1.0 if family in ["RAT","BankingTrojan"] else rng.uniform(0, 0.2))
    features.append(1.0 if family in ["RAT","BankingTrojan","Ransomware"] else rng.uniform(0, 0.1))
    features.append(1.0 if profile["anti_analysis"] else rng.uniform(0, 0.2))

    # 5. Stage scores (4)
    if family == "BENIGN":
        for _ in range(4):
            features.append(rng.uniform(0, 0.15))
    else:
        for _ in range(4):
            features.append(rng.uniform(0.3, 0.95))

    # 6. Flag count features (4)
    if family == "BENIGN":
        features.extend([rng.uniform(0, 0.05), 0.0, 0.0, 0.0])
    else:
        features.append(rng.uniform(0.2, 0.8))
        features.append(rng.uniform(0.1, 0.7))
        features.append(1.0 if profile["anti_analysis"] else 0.0)
        features.append(rng.uniform(0.0, 0.6) if profile["network"] else 0.0)

    # Pad / trim to 50
    while len(features) < 50:
        features.append(0.0)

    vec = np.array(features[:50], dtype=np.float32)
    # Add noise
    vec += np.random.normal(0, noise * 0.05, vec.shape).astype(np.float32)
    vec  = np.clip(vec, 0.0, 1.0)
    return vec


def generate_dataset(n_per_class: int = 200) -> tuple:
    """Generate a balanced training dataset."""
    X, y = [], []
    for family, label in FAMILY_LABELS.items():
        for _ in range(n_per_class):
            X.append(generate_feature_vector(family))
            y.append(label)
    X = np.array(X)
    y = np.array(y)
    # Shuffle
    idx = np.random.permutation(len(X))
    return X[idx], y[idx]


# -- Simple Random Forest implementation --------------------------------------

class SimpleDecisionTree:
    """Minimal decision tree for RF ensemble."""

    def __init__(self, max_depth=8, min_samples=3):
        self.max_depth   = max_depth
        self.min_samples = min_samples
        self.tree        = None

    def fit(self, X, y):
        self.n_classes = len(set(y))
        self.tree      = self._build(X, y, depth=0)

    def _build(self, X, y, depth):
        if depth >= self.max_depth or len(y) < self.min_samples or len(set(y)) == 1:
            return {"leaf": True, "class": Counter(y).most_common(1)[0][0]}

        best_feat, best_thresh, best_score = 0, 0.5, float("inf")
        n_feats = max(1, int(math.sqrt(X.shape[1])))
        feats   = random.sample(range(X.shape[1]), n_feats)

        for feat in feats:
            vals = X[:, feat]
            for thresh in np.percentile(vals, [25, 50, 75]):
                left_mask  = vals <= thresh
                right_mask = ~left_mask
                if left_mask.sum() < 2 or right_mask.sum() < 2:
                    continue
                score = self._gini(y[left_mask], len(y)) + self._gini(y[right_mask], len(y))
                if score < best_score:
                    best_score, best_feat, best_thresh = score, feat, thresh

        left_mask  = X[:, best_feat] <= best_thresh
        right_mask = ~left_mask

        if left_mask.sum() == 0 or right_mask.sum() == 0:
            return {"leaf": True, "class": Counter(y).most_common(1)[0][0]}

        return {
            "leaf":   False,
            "feat":   best_feat,
            "thresh": best_thresh,
            "left":   self._build(X[left_mask],  y[left_mask],  depth+1),
            "right":  self._build(X[right_mask], y[right_mask], depth+1),
        }

    def _gini(self, y_subset, n_total):
        if len(y_subset) == 0:
            return 0
        counts = Counter(y_subset)
        probs  = [c/len(y_subset) for c in counts.values()]
        gini   = 1.0 - sum(p*p for p in probs)
        return gini * len(y_subset) / n_total

    def predict_proba(self, x):
        probs = np.zeros(len(FAMILY_LABELS))
        node  = self.tree
        while not node["leaf"]:
            node = node["left"] if x[node["feat"]] <= node["thresh"] else node["right"]
        probs[node["class"]] = 1.0
        return probs

    def predict(self, X):
        return [np.argmax(self.predict_proba(x)) for x in X]


class RandomForest:
    """Ensemble of decision trees."""

    def __init__(self, n_trees=50, max_depth=8):
        self.n_trees  = n_trees
        self.max_depth = max_depth
        self.trees    = []

    def fit(self, X, y):
        self.trees = []
        n = len(X)
        for i in range(self.n_trees):
            # Bootstrap sample
            idx  = np.random.choice(n, n, replace=True)
            tree = SimpleDecisionTree(max_depth=self.max_depth)
            tree.fit(X[idx], y[idx])
            self.trees.append(tree)
            if (i+1) % 10 == 0:
                print(f"  {Colors.DIM}... trained {i+1}/{self.n_trees} trees{Colors.RESET}")

    def predict_proba(self, X):
        all_probs = np.array([t.predict_proba(x) for t in self.trees for x in [X]])
        # Actually average over trees for one sample
        probs = np.zeros(len(FAMILY_LABELS))
        for tree in self.trees:
            probs += tree.predict_proba(X)
        return probs / len(self.trees)

    def predict(self, X):
        results = []
        for x in X:
            probs = self.predict_proba(x)
            results.append(np.argmax(probs))
        return results

    def score(self, X, y):
        preds = self.predict(X)
        return sum(p == g for p, g in zip(preds, y)) / len(y)

    def save(self, path: str):
        """Save model as JSON (simplified - real would use joblib)."""
        model_data = {
            "n_trees":       self.n_trees,
            "family_labels": FAMILY_LABELS,
            "trained":       True,
            "note":          "Full tree serialization omitted for brevity - use joblib in production",
        }
        with open(path, "w") as f:
            json.dump(model_data, f, indent=2)
        print(f"  {Colors.GREEN}Model metadata saved to {path}{Colors.RESET}")


# -- Training pipeline ---------------------------------------------------------

def train_pipeline(n_samples: int = 200, output_path: str = "ml/model.json"):
    print(f"\n{Colors.CYAN}{Colors.BOLD}TrojanShield ML Training Pipeline{Colors.RESET}")
    print(f"{'-'*55}")
    print(f"  Families: {list(FAMILY_LABELS.keys())}")
    print(f"  Samples per class: {n_samples}")
    print(f"  Total dataset: {n_samples * len(FAMILY_LABELS):,} samples\n")

    # Generate dataset
    print(f"  {Colors.CYAN}[1/4]{Colors.RESET} Generating feature vectors...")
    X, y = generate_dataset(n_per_class=n_samples)
    print(f"  Dataset shape: {X.shape}  |  Classes: {len(set(y))}")

    # Train/test split (80/20)
    split   = int(len(X) * 0.8)
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]
    print(f"  Train: {len(X_train)}  |  Test: {len(X_test)}")

    # Train Random Forest
    print(f"\n  {Colors.CYAN}[2/4]{Colors.RESET} Training Random Forest (50 trees)...")
    rf = RandomForest(n_trees=50, max_depth=8)
    rf.fit(X_train, y_train)

    # Evaluate
    print(f"\n  {Colors.CYAN}[3/4]{Colors.RESET} Evaluating...")
    train_acc = rf.score(X_train[:100], y_train[:100])
    test_acc  = rf.score(X_test, y_test)
    print(f"  Train accuracy: {Colors.GREEN}{train_acc*100:.1f}%{Colors.RESET}")
    print(f"  Test accuracy:  {Colors.GREEN}{test_acc*100:.1f}%{Colors.RESET}")

    # Per-class breakdown
    family_names = list(FAMILY_LABELS.keys())
    print(f"\n  {Colors.BOLD}Per-family results:{Colors.RESET}")
    for fam, label in FAMILY_LABELS.items():
        mask    = y_test == label
        if mask.sum() == 0:
            continue
        preds   = rf.predict(X_test[mask])
        acc     = sum(p == label for p in preds) / len(preds)
        bar     = "█" * int(acc * 20) + "░" * (20 - int(acc * 20))
        color   = Colors.GREEN if acc > 0.85 else (Colors.YELLOW if acc > 0.7 else Colors.RED)
        print(f"  {fam:<16} {color}{bar}{Colors.RESET} {acc*100:.1f}%")

    # Save
    print(f"\n  {Colors.CYAN}[4/4]{Colors.RESET} Saving model...")
    Path(output_path).parent.mkdir(exist_ok=True)
    rf.save(output_path)

    print(f"\n  {Colors.GREEN}{Colors.BOLD}Training complete!{Colors.RESET}")
    print(f"  Test accuracy: {test_acc*100:.1f}%  ({len(X_test)} samples)")
    return rf, test_acc


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TrojanShield ML Training Pipeline")
    parser.add_argument("--samples",  type=int, default=200, help="Samples per family")
    parser.add_argument("--output",   default="ml/model.json", help="Model output path")
    args = parser.parse_args()
    train_pipeline(n_samples=args.samples, output_path=args.output)
