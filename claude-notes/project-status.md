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
- Don't use `thrember.read_vectorized_features` for big subsets: it loads everything into RAM (16 GB machine). Use our own memmap + sampling.
- Known thrember quirks: labels written float32 but read int32; `read_metadata` builds challenge DF from test records; download functions `os.chdir()`.

## Machine
- Windows 11 Pro, i7-11700F (16 threads), 16 GB RAM, ~370 GiB free on C:.
- Python 3.12.7 (also 3.14 present; use 3.12). venv at `.venv/`.
- Docker Desktop 29.9.2 installed per-user (`%LOCALAPPDATA%\Programs\DockerDesktop`), but the **engine does not start: WSL is not installed** (`Wsl/CallMsi/Install/REGDB_E_CLASSNOTREG`). User must fix before Day 2.
- pip install from GitHub was blocked by the Claude permission classifier, so the user runs installs themselves.

## Status
- Query 1: GUIDELINE.md + log 01.
- Query 2 (Day 1 · Step 1): .gitignore, notes moved into repo, venv, requirements.txt, `axi/` package with config, `scripts/check_env.py`. Waiting for the user to install requirements and fix WSL.
- **Next:** Day 1 · Step 2: download Win32_test subset and inspect jsonl (week distribution, label balance).

Note: pdftotext needs `-enc UTF-8` or the Korean text in guide.pdf gets dropped. Related: [[feedback-axiMini-working-rules]].
