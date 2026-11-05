"""EMBER2024 jsonl -> on-disk feature matrices, plus a LightGBM-friendly loader.

Layout written under config.VECTOR_DIR, one set per weekly jsonl file:
    <week>.X.npy      float32 (n, FEATURE_DIM)   memmap-able .npy (has a header, unlike raw .dat)
    <week>.y.npy      int8    (n,)               0 = benign, 1 = malicious
    <week>.meta.npz   first_submission_date (int64), sha256 (S64)

Training never loads a whole split: `load_split` returns one `MemmapSequence` per week, and
lightgbm.Dataset accepts a list of Sequences, pulling rows batch by batch while binning.
"""

import json
import os
from multiprocessing import Pool
from pathlib import Path

import lightgbm as lgb
import numpy as np
import thrember

from axi import config


def week_files() -> list[Path]:
    """Weekly jsonl files in chronological order (file names start with ISO dates)."""
    files = sorted(config.EMBER_DIR.glob("*.jsonl"))
    if not files:
        raise FileNotFoundError(f"no jsonl in {config.EMBER_DIR}; run scripts/download_ember.py")
    return files


def _paths(week: Path) -> tuple[Path, Path, Path]:
    stem = config.VECTOR_DIR / week.stem
    return Path(f"{stem}.X.npy"), Path(f"{stem}.y.npy"), Path(f"{stem}.meta.npz")


def vectorize_week(week: Path) -> tuple[str, int]:
    """Vectorize one weekly file. Idempotent: skipped if all outputs already exist.

    Outputs are written under temporary names and renamed at the end, so an interrupted
    run never leaves a half-written file that a later run would mistake for a finished one.
    """
    x_path, y_path, meta_path = _paths(week)
    if x_path.exists() and y_path.exists() and meta_path.exists():
        return week.name, len(np.load(y_path, mmap_mode="r"))

    with open(week, "rb") as f:
        n = sum(1 for _ in f)  # first pass: row count, so the memmap can be preallocated

    extractor = thrember.PEFeatureExtractor()
    assert extractor.dim == config.FEATURE_DIM
    tmp_x = x_path.with_suffix(".tmp.npy")
    X = np.lib.format.open_memmap(tmp_x, mode="w+", dtype=np.float32, shape=(n, config.FEATURE_DIM))
    y = np.empty(n, dtype=np.int8)
    ts = np.empty(n, dtype=np.int64)
    sha = np.empty(n, dtype="S64")

    with open(week, "rb") as f:
        for i, line in enumerate(f):
            rec = json.loads(line)
            X[i] = extractor.process_raw_features(rec)
            y[i] = rec["label"]
            ts[i] = rec["first_submission_date"]
            sha[i] = rec["sha256"].encode()

    X.flush()
    del X  # close the memmap (Windows can't rename a file that is still mapped)
    os.replace(tmp_x, x_path)
    np.save(y_path, y)
    np.savez(meta_path, first_submission_date=ts, sha256=sha)
    return week.name, n


def vectorize_all(processes: int = 12) -> None:
    config.VECTOR_DIR.mkdir(parents=True, exist_ok=True)
    weeks = week_files()
    # One process per week: process_raw_features is pure Python (GIL-bound), so threads won't help.
    with Pool(min(processes, len(weeks))) as pool:
        for name, n in pool.imap_unordered(vectorize_week, weeks):
            print(f"[+] {name}: {n} rows")


class MemmapSequence(lgb.Sequence):
    """Row access into one memmapped .npy for lightgbm.Dataset construction."""

    def __init__(self, x_path: Path, batch_size: int = 4096):
        self.X = np.load(x_path, mmap_mode="r")  # O(1): maps the file, reads nothing yet
        self.batch_size = batch_size

    def __getitem__(self, idx):
        # int -> 1-D row, slice -> 2-D block. lightgbm's Sequence path only accepts float64
        # ("sample_data[0] type float32 is not double"), so upcast per batch; the files stay
        # float32 (half the disk), and one batch of 4096 rows is only ~84 MB as float64.
        return np.asarray(self.X[idx], dtype=np.float64)

    def __len__(self) -> int:
        return self.X.shape[0]


def load_split(split: str) -> tuple[list[MemmapSequence], np.ndarray]:
    """Sequences (one per week) and the concatenated labels for a split in config.SPLIT_WEEKS."""
    weeks = [week_files()[i] for i in config.SPLIT_WEEKS[split]]
    seqs, ys = [], []
    for w in weeks:
        x_path, y_path, _ = _paths(w)
        seqs.append(MemmapSequence(x_path))
        ys.append(np.load(y_path))
    return seqs, np.concatenate(ys)


def load_split_dense(split: str) -> tuple[np.ndarray, np.ndarray]:
    """Fully materialized matrix; only for the small val/test splits (120k rows = 1.2 GB)."""
    seqs, y = load_split(split)
    return np.concatenate([s.X for s in seqs]), y


def split_overlap() -> dict[tuple[str, str], int]:
    """Count sha256 values shared between splits (same file in two splits = leakage)."""
    shas = {}
    for split, idxs in config.SPLIT_WEEKS.items():
        s = set()
        for i in idxs:
            s.update(np.load(_paths(week_files()[i])[2])["sha256"].tolist())
        shas[split] = s
    names = list(shas)
    return {(a, b): len(shas[a] & shas[b]) for i, a in enumerate(names) for b in names[i + 1:]}


if __name__ == "__main__":
    vectorize_all()
    for pair, k in split_overlap().items():
        print(f"[*] sha256 overlap {pair[0]}/{pair[1]}: {k}")
