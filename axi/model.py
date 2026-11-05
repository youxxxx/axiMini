"""Train, threshold, evaluate and load the static LightGBM model.

    python -m axi.model train   # fit on train weeks, early-stop + pick thresholds on val
    python -m axi.model test    # ONE-SHOT report on the test weeks (refuses to run twice)

Discipline (log 10): every decision (iteration count, thresholds) is made on val. Test is
read once, after everything is frozen, so its numbers are an honest estimate of the future.
"""

import argparse
import hashlib
import json
import sys
import time

import lightgbm as lgb
import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, roc_auc_score, roc_curve

from axi import config, dataset

PAUC_MAX_FPR = 5e-3  # partial AUC region, same as thrember's tuning metric


# ---------------------------------------------------------------- thresholds & metrics
def threshold_for_fpr(scores: np.ndarray, y: np.ndarray, target_fpr: float) -> float:
    """Smallest t such that FPR(score >= t) <= target_fpr.

    Sort benign scores descending; at most k = floor(target * n_benign) of them may be >= t.
    So t = the next float above the (k+1)-th largest benign score: that one and everything
    tied with it fall below t. O(n log n) for the sort.
    """
    benign = np.sort(scores[y == 0])[::-1]
    k = int(np.floor(target_fpr * len(benign)))
    return float(np.nextafter(benign[k], np.inf))


def tpr_fpr_at(scores, y, t) -> tuple[float, float]:
    pred = scores >= t
    return float(pred[y == 1].mean()), float(pred[y == 0].mean())


def report(scores: np.ndarray, y: np.ndarray, t_low: float, t_high: float) -> dict:
    tpr_h, fpr_h = tpr_fpr_at(scores, y, t_high)
    tpr_l, fpr_l = tpr_fpr_at(scores, y, t_low)
    pred = (scores >= t_high).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    # "Oracle" threshold: what T_high WOULD have been if picked on this split. Comparing it
    # with the val-chosen threshold separates ranking drift from threshold (calibration) drift.
    t_oracle = threshold_for_fpr(scores, y, config.TARGET_FPR)
    zone = np.where(scores >= t_high, "quarantine", np.where(scores >= t_low, "sandbox", "pass"))
    zones = {z: {"benign": int(((zone == z) & (y == 0)).sum()),
                 "malicious": int(((zone == z) & (y == 1)).sum())}
             for z in ("pass", "sandbox", "quarantine")}
    return {
        "n": int(len(y)), "n_benign": int((y == 0).sum()), "n_malicious": int((y == 1).sum()),
        "roc_auc": float(roc_auc_score(y, scores)),
        "pauc_5e-3": float(roc_auc_score(y, scores, max_fpr=PAUC_MAX_FPR)),
        "t_high": {"threshold": t_high, "tpr": tpr_h, "fpr": fpr_h,
                   "f1": float(f1_score(y, pred)),
                   "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}},
        "t_low": {"threshold": t_low, "tpr": tpr_l, "fpr": fpr_l},
        "oracle_t_high": {"threshold": t_oracle, "tpr": tpr_fpr_at(scores, y, t_oracle)[0]},
        "zones": zones,
    }


def tpr_at_fpr_curve(scores, y, fprs=(1e-4, 1e-3, 1e-2)) -> dict:
    """TPR at fixed FPRs, read off the ROC curve (best possible, i.e. oracle thresholds)."""
    fpr, tpr, _ = roc_curve(y, scores)
    return {f"{f:g}": float(tpr[np.searchsorted(fpr, f, side="right") - 1]) for f in fprs}


def _pauc_feval(preds, ds):
    """Custom LightGBM eval: partial AUC (FPR <= 0.5%), higher is better.

    For built-in objectives LightGBM 4 passes probabilities here; AUC is rank-based anyway.
    """
    return "pauc", roc_auc_score(ds.get_label(), preds, max_fpr=PAUC_MAX_FPR), True


# ---------------------------------------------------------------- data
def _train_dataset() -> lgb.Dataset:
    if config.TRAIN_CACHE.exists():
        print(f"[*] loading binned train set from {config.TRAIN_CACHE.name}")
        return lgb.Dataset(str(config.TRAIN_CACHE), params={"verbose": -1}).construct()
    seqs, y = dataset.load_split("train")
    ds = lgb.Dataset(seqs, label=y, categorical_feature=config.CATEGORICAL_FEATURES,
                     params={"verbose": -1}).construct()
    ds.save_binary(str(config.TRAIN_CACHE))
    return ds


def _file_sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- train
def train() -> None:
    t0 = time.perf_counter()
    train_ds = _train_dataset()
    X_val, y_val = dataset.load_split_dense("val")
    # reference=train_ds: val must be binned with the TRAIN bin boundaries (log 09 §5.4).
    val_ds = lgb.Dataset(X_val, label=y_val, reference=train_ds).construct()
    print(f"[*] data ready in {time.perf_counter() - t0:.1f}s: "
          f"train {train_ds.num_data()} x {train_ds.num_feature()}, val {val_ds.num_data()}")

    history: dict = {}
    t1 = time.perf_counter()
    booster = lgb.train(
        config.LGBM_PARAMS, train_ds, num_boost_round=config.NUM_BOOST_ROUND,
        valid_sets=[val_ds], valid_names=["val"], feval=_pauc_feval,
        callbacks=[lgb.early_stopping(config.EARLY_STOPPING_ROUNDS, verbose=True),
                   lgb.log_evaluation(50), lgb.record_evaluation(history)],
    )
    train_s = time.perf_counter() - t1
    print(f"[*] trained in {train_s:.0f}s, best_iteration={booster.best_iteration}")

    # Thresholds are chosen on val with the frozen model.
    s_val = booster.predict(X_val, num_iteration=booster.best_iteration)
    t_high = threshold_for_fpr(s_val, y_val, config.TARGET_FPR)
    t_low = threshold_for_fpr(s_val, y_val, config.TARGET_FPR_LOW)
    val_report = report(s_val, y_val, t_low, t_high)
    val_report["tpr_at_fpr"] = tpr_at_fpr_curve(s_val, y_val)

    config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(config.MODEL_PATH), num_iteration=booster.best_iteration)
    meta = {
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "model_file": config.MODEL_PATH.name,
        "model_sha256": _file_sha256(config.MODEL_PATH),
        "feature_dim": config.FEATURE_DIM,
        "best_iteration": booster.best_iteration,
        "train_seconds": round(train_s, 1),
        "params": config.LGBM_PARAMS,
        "split_weeks": {k: list(v) for k, v in config.SPLIT_WEEKS.items()},
        "t_low": t_low, "t_high": t_high,
        "target_fpr": config.TARGET_FPR, "target_fpr_low": config.TARGET_FPR_LOW,
        "val": val_report,
        "val_pauc_history": history["val"]["pauc"],
    }
    config.MODEL_META_PATH.write_text(json.dumps(meta, indent=2))
    _print_report("val", val_report)
    print(f"[+] saved {config.MODEL_PATH} and {config.MODEL_META_PATH.name}")


# ---------------------------------------------------------------- load / predict
class Model:
    """Frozen model + thresholds, as used by the scanner."""

    def __init__(self):
        self.meta = json.loads(config.MODEL_META_PATH.read_text())
        if _file_sha256(config.MODEL_PATH) != self.meta["model_sha256"]:
            raise RuntimeError("model file does not match its metadata (sha256 mismatch)")
        self.booster = lgb.Booster(model_file=str(config.MODEL_PATH))
        self.t_low, self.t_high = self.meta["t_low"], self.meta["t_high"]

    def score(self, X: np.ndarray) -> np.ndarray:
        return self.booster.predict(np.atleast_2d(X))

    def verdict(self, score: float) -> str:
        if score >= self.t_high:
            return "quarantine"
        return "sandbox" if score >= self.t_low else "pass"


# ---------------------------------------------------------------- one-shot test
def test(force: bool = False) -> None:
    if config.TEST_REPORT_PATH.exists() and not force:
        sys.exit(f"[!] {config.TEST_REPORT_PATH.name} exists: the test split was already used. "
                 "Re-running after changing anything would turn test into a second val set. "
                 "Pass --force only if you retrained for reasons unrelated to test results.")
    m = Model()
    X, y = dataset.load_split_dense("test")
    t0 = time.perf_counter()
    s = m.score(X)
    pred_s = time.perf_counter() - t0
    rep = report(s, y, m.t_low, m.t_high)
    rep["tpr_at_fpr"] = tpr_at_fpr_curve(s, y)
    rep["predict_us_per_row"] = pred_s / len(y) * 1e6
    rep["model_sha256"] = m.meta["model_sha256"]
    config.TEST_REPORT_PATH.write_text(json.dumps(rep, indent=2))
    _print_report("val (from training)", m.meta["val"])
    _print_report("TEST", rep)
    print(f"[*] batch predict: {rep['predict_us_per_row']:.1f} us/row")


def _print_report(name: str, r: dict) -> None:
    h, lo, c = r["t_high"], r["t_low"], r["t_high"]["confusion"]
    print(f"\n=== {name}: n={r['n']}")
    print(f"  ROC-AUC {r['roc_auc']:.5f}   pAUC(FPR<=0.5%) {r['pauc_5e-3']:.5f}")
    print(f"  T_high={h['threshold']:.6f}: TPR {h['tpr']:.4f}  FPR {h['fpr']:.5f}  F1 {h['f1']:.4f}")
    print(f"    confusion: TN {c['tn']}  FP {c['fp']}  FN {c['fn']}  TP {c['tp']}")
    print(f"  T_low ={lo['threshold']:.6f}: TPR {lo['tpr']:.4f}  FPR {lo['fpr']:.5f}")
    o = r["oracle_t_high"]
    print(f"  oracle T_high for FPR 0.1% on this split: {o['threshold']:.6f} (TPR {o['tpr']:.4f})")
    print(f"  TPR@FPR (oracle): {r['tpr_at_fpr']}")
    print(f"  zones: {r['zones']}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["train", "test"])
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    train() if a.cmd == "train" else test(a.force)
