"""Per-file scan latency (p50/p95/p99), original thrember extractor vs axi's fast one.

Run:  .venv/Scripts/python.exe -m scripts.bench_scan [N_FILES] [DIR]

Each file is read once before timing, so the OS file cache is warm and Windows Defender's
on-access scan (first open of a file) isn't counted; that cost is environmental (log 12 §5).
"""

import gc
import sys
import time
import warnings
from pathlib import Path

import numpy as np
import thrember

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from axi.scan import Scanner  # noqa: E402
from scripts.profile_features import sample_files  # noqa: E402

warnings.filterwarnings("ignore")


def pct(v) -> str:
    v = np.asarray(v) * 1e3
    return f"p50 {np.percentile(v, 50):7.1f}  p95 {np.percentile(v, 95):7.1f}  p99 {np.percentile(v, 99):7.1f}  max {v.max():7.1f} ms"


def main(n: int, root: str = r"C:\Windows\System32") -> None:
    files = sample_files(n, root)
    blobs = {}
    for f in files:
        try:
            blobs[f] = f.read_bytes()       # warm-up read (OS cache + Defender)
        except OSError:
            pass
    sizes = np.array([len(b) for b in blobs.values()])
    print(f"{len(blobs)} files from {root}, size p50 {np.median(sizes) / 1024:.0f} KiB, "
          f"p95 {np.percentile(sizes, 95) / 2**20:.1f} MiB")

    sc = Scanner()                          # also gc.freeze()s the loaded state
    ref = thrember.PEFeatureExtractor()
    gc.freeze()

    t_ref, t_scan, by_stage = [], [], {"read": [], "extract": [], "predict": []}
    for f, b in blobs.items():
        t = time.perf_counter()
        ref.feature_vector(b)
        t_ref.append(time.perf_counter() - t)
        t = time.perf_counter()
        r = sc.scan(f)
        t_scan.append(time.perf_counter() - t)
        for k in by_stage:
            if k in r.ms:
                by_stage[k].append(r.ms[k] / 1e3)
    print(f"original extractor only : {pct(t_ref)}")
    print(f"axi scan (end to end)   : {pct(t_scan)}")
    for k, v in by_stage.items():
        print(f"  {k:<8}              : {pct(v)}")
    small = sizes <= 1 << 20
    print(f"files <= 1 MiB ({small.sum()}): axi scan {pct(np.array(t_scan)[small])}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 300, *sys.argv[2:3])
