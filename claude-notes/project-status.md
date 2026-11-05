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
- **Next:** Day 1 · Step 3: `axi/model.py`: train with early stopping on val, thresholds on val (FPR ≤ 0.1%), one-shot test report.

Note: pdftotext needs `-enc UTF-8` or the Korean text in guide.pdf gets dropped. Related: [[feedback-axiMini-working-rules]].
