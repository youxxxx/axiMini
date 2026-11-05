"""Central paths and tunables. Every module imports from here so nothing hardcodes a path."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Large or generated artifacts (all git-ignored).
DATA_DIR = ROOT / "data"
EMBER_DIR = DATA_DIR / "ember2024"      # raw EMBER2024 *.jsonl files land here
VECTOR_DIR = DATA_DIR / "vectors"       # our own memmapped feature matrices
MODEL_DIR = ROOT / "models"
WATCH_DIR = ROOT / "watched"            # folder monitored by the daemon
QUARANTINE_DIR = ROOT / "quarantine"
DB_PATH = DATA_DIR / "events.db"

# EMBER2024 subset selection (see logs/2026-11-04_02_*.md for the reasoning).
EMBER_FILE_TYPE = "Win32"
EMBER_SPLIT = "test"
FEATURE_DIM = 2568           # thrember PEFeatureExtractor().dim (EMBER feature v3)

# Temporal split over the 12 weekly files of Win32_test (2024-09-22 .. 2024-12-14), by sorted
# file order: train on the past, pick thresholds on the near future, report on the far future.
SPLIT_WEEKS = {
    "train": range(0, 8),    # weeks 1-8   (480k rows)
    "val": range(8, 10),     # weeks 9-10  (120k rows)
    "test": range(10, 12),   # weeks 11-12 (120k rows)
}

# Decision policy. Real values are chosen on the validation split during training
# and saved next to the model; these are only placeholders until then.
TARGET_FPR = 0.001          # <= 0.1% benign files flagged at T_HIGH (auto-quarantine)
TARGET_FPR_LOW = 0.01       # <= 1% benign files reach T_LOW (= sandbox budget, see log 10)
DEFAULT_T_LOW = 0.35
DEFAULT_T_HIGH = 0.85

# Model artifacts.
MODEL_PATH = MODEL_DIR / "axi_lgbm.txt"         # LightGBM text model (portable, diffable)
MODEL_META_PATH = MODEL_DIR / "axi_lgbm.json"   # thresholds + val metrics + provenance
TEST_REPORT_PATH = MODEL_DIR / "test_report.json"
TRAIN_CACHE = VECTOR_DIR / "train.lgb.bin"      # binned train Dataset (log 09 §5.4)
CATEGORICAL_FEATURES = [2, 3, 4, 5, 6, 701, 702]  # same as thrember's training code

LGBM_PARAMS = {
    "objective": "binary",
    "learning_rate": 0.05,
    "num_leaves": 512,
    "min_data_in_leaf": 50,
    "feature_fraction": 0.5,   # column subsample per tree
    "bagging_fraction": 0.8,   # row subsample ...
    "bagging_freq": 1,         # ... redrawn every iteration
    "num_threads": 8,          # physical cores; hyper-threads don't help histogram building much
    "metric": "None",          # we evaluate with our own feval (partial AUC), see axi/model.py
    "verbose": -1,
    "seed": 42,
}
NUM_BOOST_ROUND = 3000
EARLY_STOPPING_ROUNDS = 200
