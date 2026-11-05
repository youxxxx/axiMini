"""Explore the extracted EMBER2024 jsonl files before modelling.

Run:  .venv/Scripts/python.exe scripts/explore_ember.py
Prints: per-week row counts and label balance, metadata field coverage, and the key layout
of one raw record (lists/dicts summarized so the output stays readable).
"""

import json
import sys
from collections import Counter
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from axi import config  # noqa: E402


def scan_file(path: Path) -> dict:
    """One pass over one weekly file. O(lines); each line is parsed exactly once."""
    labels = Counter()
    first_sub_min, first_sub_max = None, None
    nbytes_line = 0
    with open(path, "rb") as f:
        for line in f:
            nbytes_line += len(line)
            rec = json.loads(line)
            labels[rec.get("label")] += 1
            ts = rec.get("first_submission_date")
            if ts is not None:
                first_sub_min = ts if first_sub_min is None else min(first_sub_min, ts)
                first_sub_max = ts if first_sub_max is None else max(first_sub_max, ts)
    n = sum(labels.values())
    return {"file": path.name, "rows": n, "labels": dict(labels),
            "avg_line_kib": nbytes_line / max(n, 1) / 1024,
            "first_sub": (first_sub_min, first_sub_max)}


def summarize(value, depth=0):
    """Compact type/size description of a JSON value."""
    if isinstance(value, dict):
        if depth >= 1:
            return f"dict[{len(value)} keys]"
        return {k: summarize(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return f"list[{len(value)}]"
    if isinstance(value, str) and len(value) > 60:
        return value[:60] + "..."
    return value


def main() -> None:
    files = sorted(config.EMBER_DIR.glob("*.jsonl"))
    with Pool(min(len(files), 12)) as pool:  # one process per file: JSON parsing is CPU-bound (GIL)
        stats = pool.map(scan_file, files)

    print(f"{'week file':<42}{'rows':>8}{'benign':>9}{'malic.':>9}{'other':>7}{'KiB/row':>9}")
    tot = Counter()
    for s in stats:
        lab = s["labels"]
        other = s["rows"] - lab.get(0, 0) - lab.get(1, 0)
        tot.update(lab)
        print(f"{s['file']:<42}{s['rows']:>8}{lab.get(0, 0):>9}{lab.get(1, 0):>9}{other:>7}"
              f"{s['avg_line_kib']:>9.1f}")
    n = sum(tot.values())
    print(f"{'TOTAL':<42}{n:>8}{tot.get(0, 0):>9}{tot.get(1, 0):>9}"
          f"{n - tot.get(0, 0) - tot.get(1, 0):>7}")
    print("label values seen:", dict(tot))
    print("first_submission_date range per file (min, max):")
    for s in stats:
        print(f"  {s['file'][:23]}  {s['first_sub']}")

    with open(files[0], "rb") as f:
        rec = json.loads(f.readline())
    print("\n--- layout of the first record in", files[0].name)
    print(json.dumps(summarize(rec), indent=2, default=str))


if __name__ == "__main__":
    main()
