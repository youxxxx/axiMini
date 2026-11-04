# Log 01 — Project kickoff: reading the guide, scoping the lite version

- **Date:** 2026-11-04
- **Query type:** planning / documentation (no code written, as requested)
- **Files created:** `GUIDELINE.md`, `logs/2026-11-04_01_project-guideline.md` (this file), plus Claude's private memory notes (outside the repo, see §7)

---

## 1. What you asked

1. Don't build the whole thing yet.
2. Write a short guideline markdown file for the project.
3. Learning is the main goal, so write logs in detail.
4. The result should be a **lite but functioning** version that takes **about 2 days**. The guide is written for a team project that takes weeks.
5. If special environments are needed (VMs and so on), state them in the log.
6. Write a guideline file for Claude to remember these instructions.
7. Scan your GitHub and Codeforces pages once, as light background only.

## 2. What I did, step by step

### 2.1 Inspected the repo
```
.git/  .gitignore  CLAUDE.md  guide.pdf (5.2 MB, 71 pages)
```
No code yet, and no commits on `main`.

> ⚠️ **Small finding:** `.gitignore` contains `.pdf`. That pattern matches only a file literally named `.pdf`, so `guide.pdf` is **not** ignored, and `git status` confirms it is untracked-but-visible. If you meant to ignore PDFs, use `*.pdf`. I didn't change it, because you may want the guide committed.

### 2.2 Read guide.pdf
- Tool: `pdftotext` (from the MSYS2 `ucrt64` toolchain already on your machine). There is no Python PDF library installed.
- **Gotcha worth knowing:** the first extraction used pdftotext's default output encoding (Latin-1), and **all Korean text disappeared**. Only ASCII survived. Re-running with `-enc UTF-8` fixed it. Lesson: encoding is part of the data, the same as endianness is part of a binary format.
- Extracted text went to the Claude scratchpad (temp folder), not the repo.

### 2.3 Scanned your two sites (once each, as asked)
| URL | Result |
|-----|--------|
| github.com/youxxxx/Competitive_Programming | Public repo with folders `Codeforces/` and `others/`, 14 commits. The page didn't list languages. |
| codeforces.com/profile/youx | **HTTP 403**. Codeforces blocks automated fetches. I did not retry, since you asked for a single scan. |

Takeaway, used lightly: you're a competitive programmer. In explanations I'll use complexity and low-level framing where it helps, and spend more words on the ML-evaluation, Docker, and dashboard parts.

### 2.4 Wrote `GUIDELINE.md` and memory notes
See §5 and §7.

---

## 3. Summary of guide.pdf (so you don't have to re-read it all)

**Title:** DMDG Enterprise Master Manual #04 — "AI 기반 악성코드 조기 예측 및 샌드박스 동적 행위 탐지 관제 시스템". It describes an 8-week (160 h) capstone for a 4–5 person team.

**Core idea: a 2-stage hybrid EDR**
1. **Stage 1 — static screening (< 0.05 s):** parse the PE file without running it. Extract header fields, section entropy, and imported APIs, then score with an ML model.
2. **Stage 2 — dynamic sandbox (5–10 s):** files with ambiguous scores run inside an isolated Docker container. Their behaviour (file writes, process spawns, network calls) is recorded and judged.
3. A **Watchdog** daemon feeds new files into the pipeline. A **Streamlit SOC dashboard** shows everything.

**Chapter map**

| Part | Ch | Topic | Key tech |
|------|----|-------|----------|
| 1 | 01 | Why signatures fail (hash avalanche effect, packers, polymorphism) | `hashlib`, Shannon entropy |
| 1 | 02 | PE format: DOS header (`MZ` = 0x5A4D), NT headers, sections, IAT | `pefile` |
| 1 | 03 | 2-track data strategy: vectorized datasets for training, a few real samples only inside Docker | Docker + WSL2 |
| 2 | 04 | EMBER dataset (1.1 M samples, 2,381 features), Parquet loading | `pyarrow`, `pandas` |
| 2 | 05 | Entropy analysis, sliding-window entropy, virtual vs raw section size | `numpy` |
| 2 | 06 | Opcode n-grams | `capstone` |
| 3 | 07 | RF / XGBoost / LightGBM, cost-sensitive training, threshold tuning for FPR < 0.1% | `lightgbm` |
| 3 | 08 | MalConv (raw-byte 1D-CNN with gated conv) | `torch` |
| 3 | 09 | Stacking + ONNX export for < 50 ms inference | `onnxruntime` |
| 4 | 10 | Hardened Docker sandbox + strace capture | `docker` SDK |
| 4 | 11 | DNS tunnelling / DGA detection (entropy, length, digit ratio) | `scapy` |
| 4 | 12 | One-Class SVM / autoencoder on behaviour features | `sklearn` |
| 5 | 13 | Watchdog daemon, queue, thresholds 0.35 / 0.85 | `watchdog` |
| 5 | 14 | Streamlit dark SOC dashboard | `streamlit` |
| 5 | 15 | MLOps: auto-generated YARA rules, retraining | `yara-python` |
| App | A–F | Dangerous API list, EMBER notes, Docker hardening, MITRE ATT&CK, team roles, WSL2 | — |

**Target KPIs in the guide:** F1 ≥ 0.98, FPR ≤ 0.1%, static latency < 50 ms, sandbox < 10 s.

---

## 4. Scoping decisions: what's kept, cut, and why

The budget is **2 days for one person**, against **8 weeks × 4–5 people** in the guide, roughly a 1/100 compression. The rule I used: **keep one working path through every stage of the pipeline, and drop the alternatives at each stage.**

| Guide feature | Decision | Reason |
|---------------|----------|--------|
| PE static features (header, sections, entropy, imports) | **Keep** | This is the heart of the system, and it's the most low-level and educational part. |
| EMBER-style dataset | **Keep, as a subset** | You can't train a malware classifier without malware labels. Pre-vectorized features mean no live malware ever touches your disk. |
| SVM / RF / XGB / LightGBM comparison | **LightGBM only** | It's the best default for tabular data and trains in minutes on CPU. A model comparison is not where the learning is. |
| Threshold tuning for low FPR | **Keep** | This is the most important ML lesson in the guide. |
| MalConv (deep learning on raw bytes) | **Cut** | It reads 2 MB inputs, needs a GPU and hours of training, and adds little for a lite version. |
| Stacking, ONNX | **Cut** | LightGBM's native predict is already well under 50 ms per sample. |
| Opcode n-grams | **Stretch** | A nice disassembly exercise, but optional. |
| Watchdog daemon + queue | **Keep** | Needed for "real-time". |
| Quarantine | **Keep (move + rename)** | Process kill and firewall rules are cut. |
| Docker sandbox | **Keep, with harmless simulated samples** | Safety. See §6. The guide's Wine-in-Docker approach to running Windows malware is fragile anyway. |
| scapy DNS/C2 detection | **Cut** | The sandbox uses `--network none`, so there is no traffic to sniff. |
| One-Class SVM on behaviour | **Stretch** | It's cheap if time allows (syscall-count vectors). |
| Streamlit dashboard | **Keep, Korean UI** | Required by CLAUDE.md. |
| YARA auto-rules | **Stretch** | A small, fun add-on. |
| MITRE matrix, GeoIP, MLOps retraining, Docker Compose deploy | **Cut** | Team-scale polish. |

### 4.1 Improvements over the guide (per CLAUDE.md "recommend superior alternatives")

These are things I noticed while reading the code in the PDF. Each will be applied when we reach that step.

1. **Threshold chosen on the test set = data leakage (Ch 07).** The guide trains, predicts on `X_test`, then reports FPR at `0.97` on that same `X_test`. If 0.97 was picked by looking at those results, the reported FPR is optimistically biased. **Fix:** use three splits (train / validation / test). Pick the threshold on validation as the smallest `t` with `FPR_val(t) ≤ 0.1%`, then report test metrics once.
   - Detail: FPR 0.1% means 1 false positive per 1,000 benign files. To *measure* that with any confidence you need many thousands of benign validation samples. With 1,000 benign samples, one mistake flips you from 0% to 0.1%. Statistically it behaves like a binomial proportion: you need `n ≫ 1/p` samples.
2. **Inconsistent thresholds.** The intro uses "clean > 99% / malware > 95% / suspicious 60–95%", while Ch 13 uses `< 0.35` pass and `> 0.85` block. **Fix:** derive both thresholds from the validation set: `T_high` from the FPR target, `T_low` from a recall target. Store them next to the model.
3. **Feature consistency.** The guide trains on EMBER vectors (2,381 features from EMBER's own extractor) but extracts *different* features with raw `pefile` at inference time. A model is a function of a fixed feature space, so feeding it a differently built vector produces garbage silently. **Fix:** use the same extractor for training and scanning. The preferred route is the EMBER2024 project's `thrember` package, which (as I understand it) ships both the dataset features and a `pefile`-based extractor. I'll verify the exact package and dataset names during Day 1 setup before relying on them. The fallback is to train on our own extractor's features. That needs labelled raw files, which brings back the malware-handling problem, so it's less attractive.
4. **Entropy speed (Ch 01).** The guide loops `for b in chunk: byte_counts[b] += 1` in pure Python. That's O(n) with a large constant, roughly 50–100 ns per byte in CPython, so a 50 MB file takes seconds. **Fix:** `np.bincount(np.frombuffer(data, np.uint8), minlength=256)`. It's still O(n) but runs in C, so it's 100× faster or more.
5. **Sliding-window entropy (Ch 05).** The guide recomputes a full 256-bin histogram per window: O((n/step) · w). **Better:** keep a running histogram. Each step removes `step` old bytes and adds `step` new ones, which is O(step) to update the counts. Entropy itself can be maintained incrementally: track `S = Σ c·log c` and adjust only the touched bins, so `H = log w − S/w`. Total O(n). (This is the same trick as a sliding-window frequency count in CP.)
6. **Capstone mode (Ch 06).** It's hardcoded to `CS_MODE_32`. 64-bit PEs (`FILE_HEADER.Machine == 0x8664`) would be disassembled wrongly. The guide also searches for a section named `.text`, but packers rename sections (`UPX0`, `UPX1`). **Fix:** choose the mode from `Machine`, and take the section containing `AddressOfEntryPoint`, or any section with the `IMAGE_SCN_MEM_EXECUTE` flag.
7. **pefile speed.** `pefile.PE(path)` parses *all* data directories (resources, relocations…), which can be slow on big files. **Fix:** `pefile.PE(path, fast_load=True)`, then `pe.parse_data_directories(directories=[IMPORT, EXPORT])` for just what we need.
8. **Watchdog handler blocks (Ch 13).** The guide calls `time.sleep(0.3)` *inside* `on_created`. Handlers run on the observer's single dispatch thread, so this delays every other event. It also ignores files that are moved or renamed into the folder (`on_moved`), and a file can still be mid-write when `on_created` fires. **Fix:** the handler only enqueues the path. The worker waits until the file is "stable" (size unchanged across two checks and openable) before scanning, and deduplicates repeated events per path.
9. **Sandbox hardening (Ch 10).** The guide is good here (`network none`, `cap_drop ALL`, `no-new-privileges`, memory and CPU limits). Additions: `--read-only` root filesystem with a small `tmpfs` for writes, `--pids-limit` (fork-bomb guard), a non-root `--user`, and a hard timeout.
10. **YARA rule injection (Ch 15).** Indicators are pasted raw into `"$str = \"{ind}\""`. A quote or backslash in an indicator breaks the rule, or alters it. **Fix:** escape `\` and `"` first, or use hex strings.
11. **Deprecated APIs (Ch 14).** `df.style.applymap` → `Styler.map` (pandas ≥ 2.1). `st.dataframe(..., use_container_width=True)` → `width="stretch"` in current Streamlit.

---

## 5. The lite architecture (also in GUIDELINE.md)

```
 watched folder ──► Watchdog handler ──(path)──► queue ──► worker
                                                         │ wait until file stable
                                                         ▼
                                       Stage 1: features.py → LightGBM → score
                                         score < T_low   → PASS
                                         score ≥ T_high  → QUARANTINE (move to quarantine/)
                                         otherwise       → Stage 2 sandbox.py (Docker + strace)
                                                         │
                                                         ▼
                                       store.py → SQLite (events table)
                                                         │
                                                         ▼
                                       dashboard/app.py (Streamlit, Korean labels)
```

**Why SQLite between the daemon and the dashboard?** Streamlit re-runs the whole script on every interaction, so it can't hold the daemon's state in memory. Two separate processes need a shared store. SQLite is a single file with zero setup, and its WAL mode handles one writer plus several readers well. That's the simplest correct choice.

**Complexity notes, since you'll find these natural:**
- Feature extraction is O(file size) for entropy plus O(#sections + #imports) for headers. It's dominated by disk read.
- LightGBM inference is O(#trees × depth), so a few hundred trees × depth ~8 is a few thousand comparisons. That's microseconds. **The 50 ms budget is spent on I/O and parsing, not the model.**
- The queue decouples event bursts (O(1) enqueue) from scanning throughput.

---

## 6. Environment you need to set up

> Nothing below is installed by me yet. Set it up when we start Day 1. The exact commands will go in that day's log.

### Required
| Item | Version / notes | How to check |
|------|-----------------|--------------|
| **Python** | 3.11 or 3.12 (best wheel availability for LightGBM and yara-python on Windows) | `py --version` |
| **venv** | One per project: `py -3.12 -m venv .venv` | — |
| **Disk space** | ~10–20 GB free (dataset subset + Docker image) | — |
| **Docker Desktop** | Needed from **Day 2**. Use the **WSL 2 backend**. | `docker run --rm hello-world` |
| **WSL 2** | Docker Desktop installs or enables it. You may need to turn on *Virtual Machine Platform* in Windows Features and enable virtualization (VT-x/AMD-V) in BIOS. | `wsl --status` |

### NOT required for the lite version
- **A Windows VM for malware analysis.** The lite version never downloads or runs real malware:
  - Training uses **pre-extracted feature vectors** (numbers, not binaries).
  - Stage-1 test files are benign (`System32` binaries, plus optional harmless PEs we compile ourselves that just *import* suspicious APIs).
  - The Stage-2 sandbox runs our own **harmless scripts** that *imitate* malicious behaviour (write `*.locked` files, try a socket connect, spawn a child process).
- **Windows Defender changes.** Keep it on. Don't add exclusions.

### Only if you later extend to real malware (out of scope)
Then you'd want a **dedicated analysis VM** (Hyper-V or VirtualBox), not just Docker:
- Windows 10/11 guest, **host-only or no network**, shared folders and clipboard **disabled**, a clean **snapshot** to revert to after each run.
- Samples stay in password-protected zips (`infected` is the convention on MalwareBazaar) until they're inside the VM.
- Reason: Docker containers share the host kernel. A container escape exploit reaches your real machine. A VM adds a hypervisor boundary. Also, Windows malware doesn't run natively in Linux containers, which is why the guide resorts to Wine.

### Optional
- **C compiler** for building harmless test PEs: your MSYS2 `ucrt64` toolchain is already present. Check with `gcc --version` in the MSYS2 shell.
- **VS Code + Python extension** for debugging.

---

## 7. Notes for Claude itself

You asked for a guideline file for me. It's stored as Claude Code memory, which loads automatically in future sessions:
`C:\Users\user\.claude\projects\C--Users-user-Documents-axiMini\memory\`
- `feedback_axiMini_working_rules.md`: build step by step, detailed learning logs, 2-day lite scope, state environment needs in logs.
- `user_profile_competitive_programmer.md`: your background and how to pitch explanations.
- `project_axiMini.md`: project summary and current status.
- `MEMORY.md`: index.

These live outside the repo, so they aren't committed. If you'd prefer them version-controlled, I can copy the rules into `CLAUDE.md` instead.

---

## 8. Open questions for you

1. **Dataset size and disk:** how much free disk and RAM do you have? This decides how big an EMBER2024 subset we download.
2. **Docker:** is Docker Desktop already installed? If not, install it before Day 2.
3. **`.gitignore`:** keep `guide.pdf` tracked, or change the pattern to `*.pdf`?

## 9. Next step (waiting for your go-ahead)

**Day 1 · Step 1:** environment check, repo skeleton (`axi/` package, `requirements.txt`, `.gitignore` for `data/`, `models/`, `.venv/`), and verifying the dataset and extractor choice (§4.1 item 3) before writing any feature code.
