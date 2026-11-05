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
TARGET_FPR = 0.001          # <= 0.1% benign files flagged at T_HIGH
DEFAULT_T_LOW = 0.35
DEFAULT_T_HIGH = 0.85
