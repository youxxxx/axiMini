---
name: project-axiMini
description: axiMini = lite 2-day version of guide.pdf's AI-EDR; current status and next step
metadata:
  type: project
---

Started 2026-11-04. Source spec: `guide.pdf` (DMDG Manual #04, Korean, 8-week, 4–5 person capstone).
Lite plan: `GUIDELINE.md`. Day 1 static engine, Day 2 daemon + quarantine + sandbox demo + dashboard.
No live malware in the lite version.

## Decisions so far
- Feature extractor + data: EMBER2024 `thrember` (feature v3, dim 2568, pure pefile). Same extractor for training (`process_raw_features` on jsonl) and scanning (`feature_vector` on bytes).
- Data subset: **Win32_test.zip only (4.9 GB)**, split by week into train/val/test (temporal split). Full Win32 train (23.7 GB) is an optional upgrade.
- Don't use `thrember.read_vectorized_features` for big subsets: it loads everything into RAM (16 GB machine). Instead, feed LightGBM through a `lightgbm.Sequence` over our `np.memmap` files, so the raw float32 matrix never sits in RAM; only the binned Dataset (~1 B/value) does. Then going from Win32_test to Win32_train is a config change (decided 2026-11-05, log 04).
- Known thrember quirks: labels written float32 but read int32; `read_metadata` builds challenge DF from test records; download functions `os.chdir()`; `email_addr` regex == `mac_addr` (keep it for consistency).
- thrember pinned to commit `0ef753e8…`; **signify pinned `>=0.7.1,<0.8`** (0.9 removed `SignedPEFile` import and renamed `iter_signed_datas`).
- Scan latency is ~600 ms on kernel32.dll vs a 50 ms target: StringExtractor 384 ms (S×R re.search calls), pefile full parse 100 ms (fast_load = 0.4 ms). An output-preserving optimization is planned as a later step (log 07 §5).

## Machine
- Windows 11 Pro, i7-11700F (16 threads), 16 GB RAM, ~370 GiB free on C:.
- Python 3.12.7 (also 3.14 present; use 3.12). venv at `.venv/`.
- Docker Desktop 29.9.2 installed per-user (`%LOCALAPPDATA%\Programs\DockerDesktop`), but the **engine does not start: WSL is not installed** (`Wsl/CallMsi/Install/REGDB_E_CLASSNOTREG`). User must fix before Day 2.
- pip install from GitHub was blocked by the Claude permission classifier, so the user runs installs themselves.

## Status
- Query 1: GUIDELINE.md + log 01.
- Query 2 (Day 1 · Step 1): .gitignore, notes moved into repo, venv, requirements.txt, `axi/` package with config, `scripts/check_env.py`. Waiting for the user to install requirements and fix WSL.
- 2026-11-05: requirements installed and all Day-1 checks green (log 07). Docker still blocked on WSL.
- 2026-11-05 Day 1 · Step 2 done (log 09): Win32_test = 12 weekly jsonl, 720k rows, 60k/week, exactly 50/50, no unlabeled. Vectorized to `data/vectors/<week>.{X,y}.npy` + `.meta.npz` (7 GiB, 1m45s, 12 procs). Split train = weeks 1-8, val = 9-10, test = 11-12 (`config.SPLIT_WEEKS`); sha256 overlap 0/0/1. `MemmapSequence` must upcast to float64 (lightgbm requirement). Binned train Dataset ≈ 1 GiB private, peak WS 10 GiB; cached as `data/vectors/train.lgb.bin` (0.43 GiB). Build val/test with `reference=train_ds`. Categorical idx [2,3,4,5,6,701,702].
- 2026-11-05 Day 1 · Step 3 done (log 10): `axi/model.py` (train / test / `Model` class with sha256-checked meta). lr 0.05, 512 leaves, ff 0.5, bagging 0.8, 8 threads, early stop on custom pAUC(max_fpr=5e-3), best_iter 2063, 26 min. T_high 0.999917 (val FPR 0.1%), T_low 0.290884 (val FPR 1% = sandbox budget). **Test already used once** (`models/test_report.json`; don't re-run or tune on it): ROC-AUC 0.99816, pAUC 0.958, TPR 92.65%, **FPR 0.21%** (drift, 8.5σ, not noise). Pretrained-thrember comparison skipped (time overlap).
- 2026-11-05 query 11: retraining question answered conceptually (log 11): full retrain / warm start / refit, churn > correlation. Optional churn experiment (weeks 1-6 vs 1-8) proposed, not run.
- 2026-11-05 Day 1 · Step 4 done (log 12): `axi/features.py` (FastPEFeatureExtractor: strings finditer+searchsorted, entropy via bincount in first-occurrence order; **bit-identical**, 1008 files, 0 mismatches, 1-ulp negative control caught), `feature_names()`, `axi/scan.py` (`Scanner`, `ScanResult`, Korean CLI, verdicts pass/sandbox/quarantine/not_pe/error, 128 MiB cap, TreeSHAP ~430 ms so explain only non-pass), `gc.freeze()` (pefile full gc.collect on close cost 35 ms), fstat-before-read fix. Latency p50 30–36 ms, **p95 278–355 ms** (pefile full parse; NOT optimized because pefilewarnings features depend on it). Tests: `tests/test_features.py` (14 pass). `scripts/__init__.py` exists so `-m scripts.bench_scan` works.
- 2026-11-05 query 13: `DAY1_SUMMARY.md` written (run-from-scratch instructions, results, decisions, troubleshooting); added `huggingface_hub` to requirements (was only transitive). Update the summary or a README when Day 2 adds commands.
- 2026-11-05 Day 2 · Step 1 done (log 14): `axi/daemon.py` (observer → `Pending` dict debounce 0.5 s → stabilizer: size+mtime stable over 0.2 s + openable → ready queue → dispatcher → ProcessPoolExecutor(2, Scanner per worker) → single SQLite writer), `axi/store.py` (WAL, synchronous=NORMAL, events table with model_sha256 + action cols, read-only connect for dashboard). CAS-style `pop(path, if_last_event)` fixes the lost-event race. Explain only sandbox/quarantine. Content routing (not extension), ignores .crdownload/.part/.tmp/~$, handles on_moved, initial scan. Detection latency ~0.8–1.1 s. `tests/test_daemon.py` end-to-end; 15 tests pass. Quarantine verdict is recorded only (no action yet).
- 2026-11-05 Day 2 · Step 2 done (log 15): `axi/quarantine.py`: rename-in-place (atomic, detects locked) → verify sha vs scanned (else put back, `changed`) → XOR-neutralized blob `<sha>.qbin` (MAGIC|key|data^key, fsync+replace, read-only) + sidecar JSON with origins → delete held original. Restore = allowlist FIRST then write (avoids re-quarantine race). store v2: `allowlist`, `actions` tables. Daemon `handle_result`: allowlist check before action. Real-FP hunt: 2636 installed programs → 0 quarantine, 4 sandbox (0.15%; Git getprocaddr32.exe 0.977). `--demo-t-high` flag (demo only, warns); known gap: events don't record which T_high was in force (add for dashboard). 23 tests pass. Demo rows kept in data/events.db for the dashboard.
- **Next:** Day 2 · Step 3: Docker sandbox (needs WSL: user must run `wsl --install --no-distribution` as admin + reboot). Old item still open: `requirements.lock`.
- (older) Day 1 wrap-up (`requirements.lock`) → Day 2 · Step 1: watcher daemon (watchdog → worker pool → Scanner → SQLite with model_sha256 per event → quarantine). User must install WSL before the sandbox step.
- Shell rule reminder: I slipped again in step 4 (`cd` into site-packages); always use absolute paths or `cd /c/Users/user/Documents/axiMini && ...`.

Note: pdftotext needs `-enc UTF-8` or the Korean text in guide.pdf gets dropped. Related: [[feedback-axiMini-working-rules]].
