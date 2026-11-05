"""Check that axi.features.FastPEFeatureExtractor is bit-identical to thrember's original.

Run:  .venv/Scripts/python.exe scripts/verify_features.py [N_FILES]

For each file, compares (1) the raw feature dicts with ==, and (2) the final float32 vectors
byte by byte (tobytes(), so even -0.0 vs 0.0 or NaN payloads would count as a difference).
Inputs: a spread of PE files from System32 / SysWOW64 / Program Files, plus synthetic edge
cases (non-PE data, tiny files, no printable strings, regex-dense text).
"""

import os
import random
import sys
import time
import warnings
from pathlib import Path

import numpy as np
import thrember

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from axi.features import FastPEFeatureExtractor, entropy_H  # noqa: E402

warnings.filterwarnings("ignore")


def real_files(n: int, seed: int = 0) -> list[Path]:
    roots = [Path(r"C:\Windows\System32"), Path(r"C:\Windows\SysWOW64"),
             Path(os.environ.get("ProgramFiles", r"C:\Program Files"))]
    files = []
    for root in roots:
        pattern = "**/*" if "Program Files" in str(root) else "*"
        for f in root.glob(pattern):
            if f.suffix.lower() in (".exe", ".dll", ".sys") and f.is_file():
                files.append(f)
            if len(files) > 200_000:
                break
    random.Random(seed).shuffle(files)
    return files[:n]


def synthetic() -> list[tuple[str, bytes]]:
    rnd = random.Random(1)
    regex_dense = ("http://evil.example.com/a?b=1 192.168.0.1 HKCU\\Software C:/Windows "
                   "powershell Invoke-Expression GET / HTTP/1.1 User-Agent: x base64 "
                   "00:11:22:33:44:55 fe80::1 1BoatSLRHtKNngkdXEeobR76b53LETtpyT "
                   "!This program cannot be run /dev/null /tmp/x <script>javascript</script>")
    return [
        ("tiny-1B", b"M"),
        ("tiny-3B", b"MZ\x90"),
        ("no-strings", bytes(rnd.randrange(0, 0x20) for _ in range(5000))),
        ("random-64k", rnd.randbytes(65536)),
        ("text-regex-dense", (regex_dense + "\x00").encode() * 50),
        ("adjacent-strings", b"\x01".join([b"http://a.b", b"HKCU_x", b"cookie", b"abcd", b"windowwindow"])),
        ("del-char", b"\x7f\x7f\x7fhtml\x7f\x00shell"),
        ("all-one-byte", b"A" * 10000),
    ]


def same(a: np.ndarray, b: np.ndarray) -> bool:
    return a.dtype == b.dtype and a.shape == b.shape and a.tobytes() == b.tobytes()


def main(n: int) -> None:
    ref, fast = thrember.PEFeatureExtractor(), FastPEFeatureExtractor()
    cases = [(str(p), p) for p in real_files(n)] + synthetic()
    mismatches, t_ref, t_fast, checked = [], 0.0, 0.0, 0
    for name, src in cases:
        try:
            bytez = src.read_bytes() if isinstance(src, Path) else src
        except OSError:
            continue
        t = time.perf_counter()
        r_ref = ref.raw_features(bytez)
        t_ref += time.perf_counter() - t
        t = time.perf_counter()
        r_fast = fast.raw_features(bytez)
        t_fast += time.perf_counter() - t
        v_ref, v_fast = ref.process_raw_features(r_ref), fast.process_raw_features(r_fast)
        checked += 1
        if r_ref != r_fast or not same(v_ref, v_fast):
            bad = [g for g in r_ref if r_ref[g] != r_fast.get(g)]
            mismatches.append((name, bad))
    # entropy_H directly against pefile's implementation on random data with skewed counts
    import pefile
    sec = pefile.SectionStructure(pefile.PE.__IMAGE_SECTION_HEADER_format__)
    rnd = random.Random(2)
    for _ in range(300):
        data = bytes(min(255, int(rnd.expovariate(0.05))) for _ in range(rnd.randrange(1, 5000)))
        if sec.entropy_H(data) != entropy_H(data):
            mismatches.append(("entropy_H random", []))
    print(f"checked {checked} inputs (+300 entropy_H cases): {len(mismatches)} mismatches")
    for m in mismatches[:20]:
        print("  MISMATCH", m)
    print(f"raw_features total: original {t_ref:.1f}s, fast {t_fast:.1f}s ({t_ref / t_fast:.1f}x)")
    sys.exit(1 if mismatches else 0)


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 1000)
