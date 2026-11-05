# axiMini — Project Guideline (Lite AI-EDR)

> A 2-day, single-person, **lite but working** version of the 8-week team project in `guide.pdf`
> ("AI 기반 악성코드 조기 예측 및 샌드박스 동적 행위 탐지 관제 시스템").
> Main goal: **learning**. Every step is logged in detail under `/logs`.

---

## 1. What the finished lite version does

```
 watched folder ──► [Watchdog daemon] ──► [Stage 1: static PE scan  (< 50 ms)]
                                              │ pefile features + LightGBM score
                                              ├─ score < T_low  → PASS (허용)
                                              ├─ score ≥ T_high → QUARANTINE (격리)
                                              └─ in between      → [Stage 2: Docker sandbox demo]
                                                                      strace behaviour summary
                         every verdict ──► SQLite event DB ──► [Streamlit SOC dashboard, Korean UI]
```

| # | Component | Lite scope | Dropped vs. guide.pdf |
|---|-----------|------------|-----------------------|
| 1 | Static features | header / section / entropy / imports via `pefile` (or EMBER2024 `thrember` extractor) | Opcode n-grams (stretch) |
| 2 | Model | LightGBM, threshold tuned on a **validation** set for FPR ≤ 0.1% | SVM/RF/XGB comparisons, MalConv, stacking, ONNX |
| 3 | Daemon | `watchdog` + worker queue + file-stability check | Priority queue, DLQ, backpressure |
| 4 | Quarantine | move + rename + log to DB | Process kill, firewall rules |
| 5 | Sandbox | hardened Docker container running **harmless simulated** samples under `strace` | Real malware, Wine, scapy C2 capture, One-Class SVM (stretch) |
| 6 | Dashboard | Streamlit: KPIs, event table, per-file detail, entropy chart — **all labels in Korean** | MITRE ATT&CK matrix, GeoIP |
| 7 | YARA | stretch: generate a rule from a quarantined file's IoCs | Hot-patch pipeline, retraining MLOps |

## 2. Two-day plan

**Day 1 — Static engine (offline, no Docker needed)**
1. Environment setup (see §4), repo skeleton, `requirements.txt`.
2. PE parser + feature extractor; unit-test on `C:\Windows\System32\*.exe`.
3. Get training data: EMBER2024 `Win32_test` raw features (4.9 GB, no live malware), split by week into train/val/test. Train LightGBM.
4. Evaluate: ROC-AUC, F1, FPR at the chosen threshold, per-file latency (p50/p95).
5. CLI: `python -m axi.scan <file>` → score + verdict + top features.

**Day 2 — Real-time system**
1. Watchdog daemon → worker → SQLite.
2. Quarantine action.
3. Docker sandbox runner (hardened flags) + strace parser, tested on simulated samples.
4. Streamlit dashboard (Korean UI).
5. End-to-end demo script + README. Stretch: YARA rule generator, One-Class SVM on syscall counts.

## 3. Proposed layout

```
axiMini/
├─ axi/                 # Python package
│  ├─ features.py       # PE parsing & feature vector
│  ├─ model.py          # train / load / predict, threshold selection
│  ├─ scan.py           # CLI entry
│  ├─ daemon.py         # watchdog + worker
│  ├─ sandbox.py        # docker runner + strace parser
│  ├─ store.py          # SQLite event store
│  └─ yara_gen.py       # (stretch)
├─ dashboard/app.py     # Streamlit (Korean UI)
├─ sandbox/Dockerfile   # sandbox image
├─ samples/simulated/   # harmless "malicious-looking" test programs
├─ data/  models/       # git-ignored
├─ tests/
└─ logs/                # per-query learning logs
```

## 4. Environment (host: Windows 11)

| Need | Why | Required? |
|------|-----|-----------|
| Python 3.11 or 3.12 + venv | all code | **Yes** |
| Git | versioning | Yes (already present) |
| Docker Desktop (WSL 2 backend) | Stage-2 sandbox | **Yes for Day 2** (installed, but WSL is missing; see log 02) |
| ~10–20 GB free disk | dataset subset + Docker image | Yes |
| Windows VM (Hyper-V/VirtualBox, host-only network, snapshots) | only if you later want to handle **real** malware | **No** for the lite version |

Safety rule for the lite version: **no live malware is downloaded or executed.** Training uses
pre-vectorized features; the sandbox runs only our own harmless simulated programs. Keep Windows Defender on.

## 5. Deviations from guide.pdf (better/safer/faster)

- Choose the decision threshold on a **validation** split, not the test split (the guide's `0.97` on test data leaks).
- Use **one** consistent feature extractor for training and inference (mixing EMBER features with custom pefile features silently breaks the model).
- Entropy with `numpy.bincount` (vectorized, O(n)) instead of a per-byte Python loop; sliding-window entropy can be updated incrementally in O(n) total instead of O(n·w/step).
- Pick the Capstone mode from `FILE_HEADER.Machine` (x86 vs x64) and find code via the entry-point/executable section, not the name `.text` (packers rename it).
- Watchdog: don't `sleep()` in the event handler (it blocks the observer thread); debounce in the worker and also handle `on_moved`.
- Sandbox hardening: `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit --memory --cpus`, non-root user.
- YARA generator must escape indicator strings (quotes/backslashes) before building a rule.
- Current API names: pandas `Styler.map` (not `applymap`); Streamlit `width="stretch"` (not `use_container_width`).

## 6. Definition of done

- [ ] `scan` CLI gives a verdict for any PE in < 50 ms (p95, after model load)
- [x] Reported metrics: ROC-AUC, F1, FPR at chosen threshold (target FPR ≤ 0.1%): val 0.10%, **test 0.21%** (drift, log 10)
- [ ] Dropping a file into the watched folder shows up in the dashboard within ~1 s
- [ ] High-score files are moved to `quarantine/`
- [ ] Mid-score files produce a sandbox behaviour summary (demo samples)
- [ ] Dashboard text is Korean; code/comments/logs are English
