"""Per-feature-group timing of thrember's extractor on local PE files.

Run:  .venv/Scripts/python.exe scripts/profile_features.py [N_FILES]
"""

import sys
import time
from pathlib import Path

import numpy as np
import pefile
import thrember

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def sample_files(n: int, root: str = r"C:\Windows\System32") -> list[Path]:
    root = Path(root)
    files = sorted(list(root.glob("*.exe")) + list(root.glob("*.dll")))
    files = [f for f in files if f.is_file()]
    step = max(1, len(files) // n)
    return files[::step][:n]


def main(n: int = 200) -> None:
    ext = thrember.PEFeatureExtractor()
    times = {"pefile.PE": []} | {fe.name: [] for fe in ext.features}
    sizes = []
    for path in sample_files(n):
        try:
            bytez = path.read_bytes()
        except OSError:
            continue
        sizes.append(len(bytez))
        t = time.perf_counter()
        try:
            pe = pefile.PE(data=bytez)
        except pefile.PEFormatError:
            pe = None
        times["pefile.PE"].append(time.perf_counter() - t)
        for fe in ext.features:
            t = time.perf_counter()
            fe.raw_features(bytez, pe)
            times[fe.name].append(time.perf_counter() - t)
    total = np.sum([np.array(v) for v in times.values()], axis=0)
    print(f"{len(sizes)} files, size median {np.median(sizes)/1024:.0f} KiB, max {max(sizes)/2**20:.1f} MiB")
    print(f"{'stage':<16}{'mean ms':>9}{'p50 ms':>9}{'p95 ms':>9}{'share':>8}")
    for k, v in sorted(times.items(), key=lambda kv: -np.mean(kv[1])):
        v = np.array(v) * 1e3
        print(f"{k:<16}{v.mean():>9.2f}{np.median(v):>9.2f}{np.percentile(v, 95):>9.2f}"
              f"{v.sum() / total.sum() / 1e3:>8.1%}")
    t = total * 1e3
    print(f"{'TOTAL':<16}{t.mean():>9.2f}{np.median(t):>9.2f}{np.percentile(t, 95):>9.2f}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 200)
