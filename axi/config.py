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

# Decision policy. Real values are chosen on the validation split during training
# and saved next to the model; these are only placeholders until then.
TARGET_FPR = 0.001          # <= 0.1% benign files flagged at T_HIGH
DEFAULT_T_LOW = 0.35
DEFAULT_T_HIGH = 0.85
