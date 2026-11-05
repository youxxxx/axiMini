"""Static scan of PE files: bytes -> features -> score -> verdict (+ optional explanation).

    python -m axi.scan <file-or-dir> [...] [--top 8] [--no-explain] [--json]

The Day-2 daemon imports `Scanner` directly; this CLI is a thin wrapper. UI text is Korean.
"""

import argparse
import gc
import json
import os
import sys
import time
import warnings
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np

from axi import config
from axi.features import GROUP_KO, FastPEFeatureExtractor, feature_names
from axi.model import Model

MAX_SCAN_BYTES = 128 * 2**20  # refuse huge inputs: extraction is O(size) and fully in RAM
PE_SUFFIXES = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".efi"}

VERDICT_KO = {
    "pass": "정상 (통과)",
    "sandbox": "의심 (샌드박스 분석 대상)",
    "quarantine": "악성 (격리 대상)",
    "not_pe": "PE 파일 아님 (검사 제외)",
    "error": "검사 실패",
}


@dataclass
class ScanResult:
    path: str
    sha256: str = ""
    size: int = 0
    score: float | None = None
    verdict: str = "error"
    error: str = ""
    ms: dict = field(default_factory=dict)          # stage -> milliseconds
    top: list = field(default_factory=list)         # explanation rows (see Scanner.explain)


class Scanner:
    def __init__(self):
        self.model = Model()                        # sha256-checked model + val thresholds
        self.ext = FastPEFeatureExtractor()         # bit-identical to thrember (log 12)
        self._names = None
        # pefile runs a FULL gc.collect() whenever it closes a PE (incl. every non-PE input),
        # and a full collection is O(live tracked objects): ~197k after importing thrember/
        # sklearn/scipy, i.e. ~35 ms per call. gc.freeze() moves everything alive now (modules,
        # model, extractor tables, all long-lived anyway) into a permanent generation the
        # collector skips. Output is unaffected; non-PE scans drop from ~35 ms to ~0 (log 12 §3).
        gc.freeze()

    def scan(self, path: str | Path, explain: int = 0) -> ScanResult:
        res = ScanResult(path=str(path))
        t0 = time.perf_counter()
        try:
            with open(path, "rb") as f:
                # Check the size first. f.read(MAX + 1) would make CPython allocate a
                # (MAX + 1)-byte buffer up front and shrink it afterwards: 128 MiB per call,
                # ~23 ms even for a 92-byte file (log 12 §3).
                res.size = os.fstat(f.fileno()).st_size
                if res.size > MAX_SCAN_BYTES:
                    res.error = f"파일이 너무 큼 (> {MAX_SCAN_BYTES >> 20} MiB)"
                    return res
                bytez = f.read()
        except OSError as e:
            res.error = f"읽기 실패: {e}"
            return res
        res.size = len(bytez)   # the file may have changed between fstat and read
        if not bytez:
            res.error = "빈 파일"
            return res
        if len(bytez) > MAX_SCAN_BYTES:
            res.error = f"파일이 너무 큼 (> {MAX_SCAN_BYTES >> 20} MiB)"
            return res
        t1 = time.perf_counter()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")      # pefile/signify chatter on odd files
            raw = self.ext.raw_features(bytez)
        x = self.ext.process_raw_features(raw)[None, :]
        t2 = time.perf_counter()
        res.sha256 = raw["sha256"]
        res.ms = {"read": (t1 - t0) * 1e3, "extract": (t2 - t1) * 1e3}

        if not raw["general"]["is_pe"]:
            # The model only ever saw PE files; a score for a text file would be meaningless.
            res.verdict = "not_pe"
            return res

        res.score = float(self.model.score(x)[0])
        res.verdict = self.model.verdict(res.score)
        res.ms["predict"] = (time.perf_counter() - t2) * 1e3
        if explain:
            t3 = time.perf_counter()
            res.top = self.explain(x, explain)
            res.ms["explain"] = (time.perf_counter() - t3) * 1e3
        return res

    def explain(self, x: np.ndarray, k: int) -> list[dict]:
        """Top-k features by |TreeSHAP contribution| (log-odds units).

        pred_contrib returns one value per feature plus a bias term, and they sum exactly to the
        raw score: raw(x) = bias + sum_i phi_i. Positive phi pushes toward "malicious".
        Cost ~0.4 s for 2063 trees (O(trees * leaves * depth^2)), ~1000x a plain predict, so the
        daemon will only explain files that are not plain "pass".
        """
        if self._names is None:
            self._names = feature_names(self.ext)
        phi = self.model.booster.predict(x, pred_contrib=True)[0]
        contrib, bias = phi[:-1], phi[-1]
        idx = np.argsort(-np.abs(contrib))[:k]
        rows = [{"group": self._names[i][0], "group_ko": GROUP_KO[self._names[i][0]],
                 "feature": self._names[i][1], "value": float(x[0, i]),
                 "contribution": float(contrib[i])} for i in idx]
        rows.append({"bias": float(bias), "raw_score": float(phi.sum())})
        return rows


# ---------------------------------------------------------------- CLI (Korean output)
def _iter_targets(args: list[str]):
    for a in args:
        p = Path(a)
        if p.is_dir():
            yield from sorted(f for f in p.iterdir() if f.is_file() and f.suffix.lower() in PE_SUFFIXES)
        else:
            yield p


def _print(res: ScanResult, sc: Scanner) -> None:
    print(f"\n■ {res.path}")
    if res.error:
        print(f"  판정: {VERDICT_KO['error']} - {res.error}")
        return
    print(f"  SHA-256 : {res.sha256}")
    print(f"  크기    : {res.size:,} 바이트")
    if res.score is not None:
        print(f"  악성 점수: {res.score:.6f}   (기준: 샌드박스 ≥ {sc.model.t_low:.6f}, "
              f"격리 ≥ {sc.model.t_high:.6f})")
    print(f"  판정    : {VERDICT_KO[res.verdict]}")
    if res.top:
        print("  주요 판단 근거 (TreeSHAP 기여도, 로그-오즈 단위 / + 악성 방향, - 정상 방향):")
        for r in res.top[:-1]:
            print(f"    {r['contribution']:+8.3f}  [{r['group_ko']}] {r['feature']} = {r['value']:g}")
        b = res.top[-1]
        print(f"    (기준값 {b['bias']:+.3f} + 기여도 합 = 원점수 {b['raw_score']:+.3f})")
    ms = "  ".join(f"{k} {v:.1f}" for k, v in res.ms.items())
    print(f"  소요 시간(ms): {ms}")


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")   # Korean on a cp949 console (log 07)
    ap = argparse.ArgumentParser(description="axiMini 정적 악성코드 검사")
    ap.add_argument("paths", nargs="+", help="검사할 파일 또는 폴더")
    ap.add_argument("--top", type=int, default=8, help="표시할 판단 근거 수")
    ap.add_argument("--no-explain", action="store_true", help="판단 근거 계산 생략 (빠름)")
    ap.add_argument("--json", action="store_true", help="JSON 출력")
    a = ap.parse_args()

    t = time.perf_counter()
    sc = Scanner()
    if not a.json:
        print(f"모델 로드 완료 ({(time.perf_counter() - t) * 1e3:.0f} ms, "
              f"{config.MODEL_PATH.name}, 트리 {sc.model.booster.num_trees()}개)")
    for p in _iter_targets(a.paths):
        res = sc.scan(p, explain=0 if a.no_explain else a.top)
        if a.json:
            print(json.dumps(asdict(res), ensure_ascii=False))
        else:
            _print(res, sc)


if __name__ == "__main__":
    main()
