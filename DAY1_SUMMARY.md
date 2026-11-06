# axiMini: Day 1 summary (static detection engine)

> ⚠️ **Superseded by [`README.md`](README.md)** (2026-11-06). This file is kept as a
> historical checkpoint at the end of Day 1. For up-to-date run instructions, the
> daemon/quarantine/sandbox/dashboard commands, and current test counts, read the README.

Day 1 builds the **static** half of the lite AI-EDR from `guide.pdf`. It reads a PE file's bytes without executing them, turns them into 2,568 numbers, scores them with a LightGBM model, and routes the file into one of three zones. Everything is offline: no Docker, and no live malware (the training data is pre-extracted features, not binaries).

```
 file ──► read (≤128 MiB) ──► is it a PE? ──no──► not_pe (skipped)
                                   │yes
                                   ▼
         FastPEFeatureExtractor (2568-dim vector, bit-identical to thrember / EMBER2024)
                                   ▼
         LightGBM (2063 trees) ──► score ∈ [0,1]
                                   ▼
     score < T_low (0.290884) ─► pass         정상 (통과)
     T_low ≤ score < T_high   ─► sandbox      의심 (샌드박스 분석 대상)    ← Day 2
     score ≥ T_high (0.999917)─► quarantine   악성 (격리 대상)            ← Day 2
                                   ▼ (optional)
         TreeSHAP: top features that pushed the score up/down
```

---

## 1. How to run everything (from a fresh clone)

All commands are for **Git Bash** in the repo root (`C:\Users\user\Documents\axiMini`). Use forward slashes. In PowerShell, replace `.venv/Scripts/python.exe` with `.venv\Scripts\python.exe`.

### 1.0 Prerequisites
| Need | Why | Check |
|---|---|---|
| Windows 10/11, **16 GB RAM** | training peak working set is ~10 GiB | |
| **~25 GiB free disk** | zip 2.4 + jsonl 10.4 + vectors 7.4 + cache 0.4 + model 0.05 GiB | |
| Python **3.12** | tested on 3.12.7 | `py -3.12 --version` |
| Git (to install thrember from GitHub) | | `git --version` |
| Internet (first run only) | Hugging Face download, ~2.4 GiB | |

### 1.1 One-time setup (~5 min)
```bash
py -3.12 -m venv .venv
.venv/Scripts/python.exe -m pip install --upgrade pip
.venv/Scripts/python.exe -m pip install -r requirements.txt
.venv/Scripts/python.exe scripts/check_env.py      # every Day-1 check must say OK (Docker WARN is fine today)
```

### 1.2 The pipeline: run once, in order

| # | Command | Time | Produces |
|---|---|---|---|
| 1 | `.venv/Scripts/python.exe scripts/download_ember.py` | ~5–15 min (network) | `data/zips/Win32_test.zip`, `data/ember2024/*.jsonl` (12 weekly files) |
| 2 | `.venv/Scripts/python.exe scripts/explore_ember.py` *(optional)* | ~15 s | prints rows/labels per week, record layout |
| 3 | `.venv/Scripts/python.exe -m axi.dataset` | ~2 min | `data/vectors/<week>.{X,y}.npy`, `.meta.npz`; prints sha256 overlap between splits |
| 4 | `.venv/Scripts/python.exe -m axi.model train` | ~27 min (+2 min the first time, to build the bin cache) | `data/vectors/train.lgb.bin`, `models/axi_lgbm.txt`, `models/axi_lgbm.json` |
| 5 | `.venv/Scripts/python.exe -m axi.model test` | ~15 s | `models/test_report.json`. **Run once only** (see §3) |

Every step is **idempotent**: re-running skips work that's already done (cached zip, existing vectors, cached bin file). Step 5 deliberately refuses a second run unless you pass `--force`.

To keep a console log of the long step: `.venv/Scripts/python.exe -m axi.model train 2>&1 | tee models/train_run.log`

### 1.3 Using the scanner
```bash
# one or more files: verdict + top-8 reasons (Korean output)
.venv/Scripts/python.exe -m axi.scan C:/Windows/SysWOW64/notepad.exe

# a whole folder (all .exe/.dll/.sys/...), fast mode without explanations
.venv/Scripts/python.exe -m axi.scan C:/Windows/SysWOW64 --no-explain

# options
#   --top N        number of reasons to show (default 8)
#   --no-explain   skip TreeSHAP (~430 ms/file saved)
#   --json         one JSON object per file (for scripts / the Day-2 daemon)
.venv/Scripts/python.exe -m axi.scan some.exe --json
```

Example output:
```
모델 로드 완료 (180 ms, axi_lgbm.txt, 트리 2063개)

■ C:\Windows\SysWOW64\notepad.exe
  SHA-256 : 2c520ccd5587...
  크기    : 307,712 바이트
  악성 점수: 0.000000   (기준: 샌드박스 ≥ 0.290884, 격리 ≥ 0.999917)
  판정    : 정상 (통과)
  주요 판단 근거 (TreeSHAP 기여도, 로그-오즈 단위 / + 악성 방향, - 정상 방향):
      -3.452  [PE 파싱 경고] pefilewarnings.warn67[Suspicious flags set for section...] = 0
      +1.807  [PE 헤더] header.coff.char[DLL] = 0
      ...
  소요 시간(ms): read 1.9  extract 63.4  predict 1.3  explain 438.5
```

From Python (this is what Day 2 will use):
```python
from axi.scan import Scanner
sc = Scanner()                       # loads + sha256-checks the model once
r = sc.scan("x.exe", explain=5)      # ScanResult(sha256, size, score, verdict, ms, top, error)
print(r.verdict, r.score)
```

### 1.4 Checks and benchmarks
```bash
.venv/Scripts/python.exe -m pytest -q tests                          # 14 tests, ~6 s
.venv/Scripts/python.exe scripts/verify_features.py 1000             # fast == original extractor, ~6 min
.venv/Scripts/python.exe -m scripts.bench_scan 400 C:/Windows/SysWOW64   # latency p50/p95/p99, ~5 min
.venv/Scripts/python.exe scripts/profile_features.py 300             # time per feature group
```

---

## 2. What was built

| File | Role |
|---|---|
| `axi/config.py` | every path, split, threshold target and hyperparameter in one place |
| `axi/dataset.py` | jsonl → per-week memmapped `.npy`; `MemmapSequence` feeds LightGBM in chunks (no full matrix in RAM) |
| `axi/model.py` | train (early stop on val pAUC), thresholds on val, one-shot test, `Model` loader with sha256 check |
| `axi/features.py` | fast **bit-identical** replacements for slow thrember groups; names for all 2568 features; Korean group labels |
| `axi/scan.py` | `Scanner` / `ScanResult` + the Korean CLI |
| `scripts/` | env check, download, explore, profile, verify, benchmark |
| `tests/test_features.py` | equivalence and feature-layout tests |
| `logs/01…12` | detailed per-query reasoning (the learning record) |

---

## 3. Results

**Data:** EMBER2024 `Win32_test`, with 720,000 PE files in 12 weekly files (2024-09-22 … 2024-12-14), exactly 50/50 benign/malicious. **Temporal split:** train = weeks 1–8 (480k), val = weeks 9–10 (120k), test = weeks 11–12 (120k). Sha256 overlap between splits: 0 / 0 / 1.

**Model:** LightGBM, lr 0.05, 512 leaves, early-stopped at **2063 trees** on validation partial AUC (FPR ≤ 0.5%), 26 min on 8 threads.

| | val (weeks 9–10) | **test (weeks 11–12)** |
|---|---|---|
| ROC-AUC | 0.99885 | 0.99816 |
| partial AUC (FPR ≤ 0.5%) | 0.970 | 0.958 |
| Detection rate at T_high | 93.6% | 92.6% |
| **False-positive rate at T_high** | **0.100%** (target) | **0.210%** |
| Detection / FPR at T_low | 98.2% / 1.0% | 97.9% / 1.6% |

**Headline lesson:** the false-positive rate doubled two weeks into the future. That's concept drift, ~8.5σ beyond binomial noise, so it's real. The thresholds were chosen on val and test was read once, so this is an honest estimate. It isn't something to tune away on test.

**Scan latency** (model loaded, warm cache, no explanation):

| Sample | before (original extractor) | **now** |
|---|---|---|
| SysWOW64, 400 files | p50 102 / p95 648 ms | **p50 30 / p95 278 ms** |
| System32, 400 files | p50 119 / p95 924 ms | **p50 36 / p95 355 ms** |

The p95 target (< 50 ms) isn't met: pefile's exact full parse of big DLLs dominates, and it's kept on purpose because parser warnings are features (log 12 §4).

---

## 4. Key decisions (and where they're explained)

| Decision | Instead of | Why | Log |
|---|---|---|---|
| EMBER2024 `thrember` extractor for train **and** scan | writing our own features | identical features in training and production | 02 |
| `Win32_test` only, split **by week** | full 24 GB train set; random split | fits 2 days; random splits leak the future | 02, 09 |
| memmap + `lightgbm.Sequence` (chunked) | loading everything into RAM | ~1 GiB binned dataset vs. 4.6 GiB raw; scales to the full set with a config change | 04, 09 |
| early stopping on **partial AUC** | logloss | we only operate at FPR ≈ 0.1% | 10 |
| thresholds from val **FPR targets** (0.1% / 1%) | a fixed 0.5 or the guide's 0.97 on test | a threshold is a false-alarm budget; choosing on test leaks | 10 |
| test is one-shot (code refuses a re-run) | iterating on test | otherwise test becomes a second val set | 10 |
| speedups must be **bit-identical**, verified | "close enough" | trees split on exact thresholds; train/serve skew is silent | 12 |
| signify pinned `<0.8`, thrember pinned to a commit | latest | 0.9 broke thrember's import; feature layout must never move | 07 |

---

## 5. Troubleshooting (things that actually happened)

| Symptom | Fix |
|---|---|
| `ImportError: cannot import name 'SignedPEFile'` | `pip install "signify>=0.7.1,<0.8"` (already in requirements) |
| `UnicodeEncodeError: 'cp949'` when printing Korean | the CLIs reconfigure stdout to UTF-8; for your own scripts use `sys.stdout.reconfigure(encoding="utf-8")` |
| `.venvScriptspython.exe: command not found` | in Git Bash, use forward slashes: `.venv/Scripts/python.exe` |
| `No such file` for a repo script | the shell's cwd moved; `cd /c/Users/user/Documents/axiMini` first |
| `axi.model test` exits with "already used" | intended. Delete `models/test_report.json` or pass `--force` only after a retrain for reasons unrelated to test results |
| first scan of a file is ~20 ms slower | Windows Defender's on-access scan; expected, leave Defender on |
| `ValueError: ... float32 is not double` | already handled in `MemmapSequence` (LightGBM's Sequence path needs float64) |

---

## 6. Before Day 2
1. *(optional)* Freeze exact versions: `.venv/Scripts/python.exe -m pip freeze > requirements.lock`
2. **Install WSL so Docker can run** (needed for the sandbox step): in an **administrator** PowerShell, run `wsl --install --no-distribution`, reboot, start Docker Desktop, then `docker info` must succeed.
3. Day 2 plan: watcher daemon (`watched/` → worker pool → `Scanner` → SQLite events with model hash → move `quarantine` verdicts to `quarantine/`), then the hardened Docker sandbox for `sandbox` verdicts (harmless simulated samples only), then the Korean Streamlit dashboard.
