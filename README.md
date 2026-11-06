# axiMini

A lite, fully working AI-EDR built in two days as a learning project from
[`guide.pdf`](guide.pdf) (DMDG Manual #04 — an 8-week 4–5 person spec).
Static ML scanner, real-time daemon, quarantine vault, hardened Linux sandbox,
Korean SOC dashboard. **No live malware anywhere in the lite version.**

```
 file ──► read ──► not PE? ──► 검사 제외 (recorded only)
            │
            ▼
 FastPEFeatureExtractor (2568 floats, bit-identical to thrember)
            │
            ▼
 LightGBM (2063 trees, 460ec1ca4d77…) ──► score ∈ [0,1]
            │
            ▼
   score < 0.290884  ──► ✅ 정상 (pass)
   0.290884 ≤ s < 0.999917 ──► ⚠️ 샌드박스 (dynamic analysis, Linux ELF only)
   score ≥ 0.999917  ──► 🚨 격리 (quarantine vault)
                                  │
                                  ▼
                          sha256 check → XOR-neutralize → sidecar JSON → delete original
                          (restore: allowlist first, then write back)

 Every verdict → SQLite events.db (WAL)  ◄──  Streamlit SOC dashboard (read-only)
```

---

## Results

### Static model (720,000 PE files, EMBER2024 Win32_test)
| | Val (weeks 9–10) | **Test (weeks 11–12)** |
|---|---|---|
| ROC-AUC | 0.99885 | 0.99816 |
| partial AUC (FPR ≤ 0.5%) | 0.970 | 0.958 |
| Detection @ T_high = 0.999917 | 93.6% | 92.6% |
| **False-positive rate @ T_high** | **0.100%** (target) | **0.210%** (8.5σ drift) |

Thresholds are picked on **val** and test is read **once**; the test code refuses a second run without `--force`. Drift details and mitigations in [`logs/2026-11-05_10_day1-step3-model.md`](logs/2026-11-05_10_day1-step3-model.md).

### Scan latency (p50 / p95, model already loaded, warm cache)
| Sample | Original extractor | **axi scan** |
|---|---|---|
| SysWOW64, 400 files | 102 / 648 ms | **30 / 278 ms** |
| System32, 400 files | 119 / 924 ms | **36 / 355 ms** |

Median is 3.3× faster. The tail is pefile's exact parse of large DLLs, kept because `pefilewarnings` features depend on it. Fast extractor is **bit-identical** to thrember, verified on 1,008 files + 8 synthetic edge cases + a 1-ulp negative control ([log 12](logs/2026-11-05_12_day1-step4-scan-cli.md)).

### Real-time daemon
Detection latency (file closed → verdict in DB): **~0.8–1.1 s** for normal files. Three design points worth noting ([log 14](logs/2026-11-05_14_day2-step1-daemon.md)):
- the observer thread **never sleeps** (the guide's `time.sleep(0.3)` drops events under load);
- routing is by **file content**, not extension (a PE renamed `invoice.pdf` is still scanned);
- a compare-and-swap on each entry's `last_event` fixes a lost-event race.

### Sandbox
A Linux ELF runs in a hardened throwaway container. The verdict is **what the container's defenses blocked**, not a signature match ([log 17](logs/2026-11-05_17_day2-step3-sandbox-retry.md)):
```
score = Σ weight(rule_fired), capped at 100
  net_denied (ENETUNREACH)    25    rofs_denied (EROFS)        20
  exec_denied (EACCES)        25    eperm_denied (EPERM)       10
  fork_eagain (EAGAIN)        10    mass_write (>15 files)     15
  mass_delete (>10 files)     20    timed_out                  10
```
Both benign samples (`benign_hello`, `benign_fileio`) score 0.

---

## Prerequisites
| | Why | Check |
|---|---|---|
| Windows 10/11, **16 GB RAM** | training peak working set ≈ 10 GiB | |
| **~25 GiB free disk** | zip 2.4 + jsonl 10.4 + vectors 7.4 + cache 0.4 + model 0.05 GiB | |
| Python **3.12** (3.12.7 tested) | | `py -3.12 --version` |
| Git | installs thrember from GitHub | `git --version` |
| Docker Desktop + WSL 2 | sandbox only | `docker info` |
| Internet (first run only) | Hugging Face dataset, ~2.4 GiB | |

In Git Bash all paths use forward slashes. In PowerShell, replace `.venv/Scripts/python.exe` with `.venv\Scripts\python.exe`.

---

## One-time setup
```bash
py -3.12 -m venv .venv
.venv/Scripts/python.exe -m pip install --upgrade pip
.venv/Scripts/python.exe -m pip install -r requirements.lock   # exact pinned versions
.venv/Scripts/python.exe scripts/check_env.py                  # all Day-1 checks must say OK
```

`requirements.lock` holds the 72 packages with exact versions; `requirements.txt` has the loose spec that was used to produce it.

---

## Day 1 — Build the static engine
Each step is idempotent. Re-running a step skips work already done.

| # | Command | Time | Output |
|---|---|---|---|
| 1 | `.venv/Scripts/python.exe scripts/download_ember.py` | ~5–15 min (network) | `data/zips/Win32_test.zip`, `data/ember2024/*.jsonl` |
| 2 | `.venv/Scripts/python.exe scripts/explore_ember.py` *(optional)* | ~15 s | per-week row counts, record layout |
| 3 | `.venv/Scripts/python.exe -m axi.dataset` | ~2 min | `data/vectors/<week>.{X,y}.npy`, `.meta.npz`; sha256 overlap check |
| 4 | `.venv/Scripts/python.exe -m axi.model train` | ~27 min | `data/vectors/train.lgb.bin`, `models/axi_lgbm.{txt,json}` |
| 5 | `.venv/Scripts/python.exe -m axi.model test` | ~15 s | `models/test_report.json` (runs **once**) |

Then either use the CLI scanner on individual files:
```bash
.venv/Scripts/python.exe -m axi.scan C:/Windows/SysWOW64/notepad.exe
.venv/Scripts/python.exe -m axi.scan some.exe --top 5 --no-explain
.venv/Scripts/python.exe -m axi.scan some.exe --json          # for scripts
```
or move on to Day 2.

---

## Day 2 — Real-time system

### Watcher daemon
```bash
.venv/Scripts/python.exe -m axi.daemon                           # watches ./watched with 2 workers
.venv/Scripts/python.exe -m axi.daemon --dir D:/inbox --workers 4 --no-initial-scan
.venv/Scripts/python.exe -m axi.daemon --demo-t-high 0.9         # DEMO ONLY (log 15 §5)
```
Drop any file into the watched folder; verdicts land in `data/events.db`. Ctrl+C stops it cleanly (drains in-flight scans). Each event stores `model_sha256`, so verdicts stay attributable after a retrain.

### Quarantine vault
When the daemon produces a `quarantine` verdict, the file is renamed in place (atomic on Windows), re-hashed to confirm it still matches the scanned bytes, XOR-neutralized into `quarantine/<sha256>.qbin`, and the original is deleted. A sidecar `<sha256>.json` keeps the audit trail.
```bash
.venv/Scripts/python.exe -m axi.quarantine list
.venv/Scripts/python.exe -m axi.quarantine show    <sha-prefix>       # sidecar JSON
.venv/Scripts/python.exe -m axi.quarantine restore <sha-prefix>       # allowlists sha256 FIRST, then writes
.venv/Scripts/python.exe -m axi.quarantine restore <sha-prefix> --to D:/analysis/foo.exe --no-allow
.venv/Scripts/python.exe -m axi.quarantine delete  <sha-prefix>       # permanent; sidecar kept as audit
.venv/Scripts/python.exe -m axi.quarantine allow   <full-sha256> --reason "..."
```
Restore allowlists the SHA-256 **before** writing the file, so the daemon doesn't re-quarantine the restored copy ([log 15 §4](logs/2026-11-05_15_day2-step2-quarantine.md)).

### Sandbox (Linux ELF, hardened container)
Needs Docker Desktop + WSL 2 running. The container uses `--network none --read-only` with `/work` on a `noexec` tmpfs, `--cap-drop ALL`, `no-new-privileges`, pids/memory/cpu limits, and a non-root user.
```bash
.venv/Scripts/python.exe -m axi.sandbox build                  # build axi-sandbox:1 (~15 s)
.venv/Scripts/python.exe -m axi.sandbox samples                # list bundled samples
.venv/Scripts/python.exe -m axi.sandbox run-sample benign_hello
.venv/Scripts/python.exe -m axi.sandbox run some.elf           # host file, read-only mount
.venv/Scripts/python.exe -m axi.sandbox run some.elf --json
```
Windows PE files can't be executed in a Linux container; the daemon marks them `sandbox_unsupported` (not wired yet, see "Future work").

### SOC dashboard (read-only)
```bash
.venv/Scripts/python.exe -m streamlit run dashboard/app.py
# http://localhost:8501
```
Korean UI, dark theme, four tabs: 이벤트 상세 (per-event TreeSHAP reasons), 격리소 (vault + allowlist), 조치 기록 (actions audit), 모델 & 지표 (val vs test with a drift banner and the training curve). The connection is opened with SQLite URI `mode=ro`, so a UI bug cannot alter the evidence it displays. Caching is keyed on `events.db` mtime, so the page reflects new events within one refresh.

---

## Tests
```bash
.venv/Scripts/python.exe -m pytest -q tests                        # 34 tests, ~15 s
.venv/Scripts/python.exe scripts/verify_features.py 1000           # fast == original extractor, ~6 min
.venv/Scripts/python.exe -m scripts.bench_scan 400 C:/Windows/SysWOW64   # latency, ~5 min
```
Coverage: 14 feature-equivalence + 8 quarantine + 9 sandbox parser/rules + 1 end-to-end daemon + 2 dashboard AppTest. One test (`test_pipeline`'s `os.utime` step) is known-flaky on NTFS; passes alone.

---

## Repository layout
```
axiMini/
├─ axi/                       # Python package (code and comments in English)
│  ├─ config.py               #   paths, split, thresholds, LGBM params
│  ├─ dataset.py              #   jsonl → memmapped .npy, lightgbm.Sequence loader
│  ├─ features.py             #   bit-identical fast feature extractor + names
│  ├─ model.py                #   train / test / sha256-checked Model
│  ├─ scan.py                 #   Scanner + Korean CLI
│  ├─ daemon.py               #   observer → stabilizer → worker pool → SQLite
│  ├─ store.py                #   SQLite schema v2 (events, allowlist, actions)
│  ├─ quarantine.py           #   XOR-neutralized vault + restore + allowlist CLI
│  └─ sandbox.py              #   hardened Docker runner + strace parser + rules
├─ dashboard/app.py           # Korean Streamlit SOC dashboard
├─ sandbox/Dockerfile         # Alpine + strace, musl-static samples
├─ samples/simulated/*.c      # benign samples (sandbox tests use these)
├─ scripts/                   # env check, download, explore, profile, verify, bench
├─ tests/                     # 34 pytest tests
├─ docs/
│  └─ YARA_RULE_GENERATOR.md  # design notes for future implementation
├─ logs/                      # per-query learning logs (01…18)
├─ .streamlit/config.toml     # dark SOC theme
├─ data/   models/   watched/   quarantine/   # git-ignored artifacts
├─ requirements.txt           # loose spec
├─ requirements.lock          # exact pins (pip freeze)
├─ guide.pdf                  # source spec (Korean, 8-week capstone)
├─ GUIDELINE.md               # 2-day lite plan with scope and definition of done
└─ README.md                  # this file
```

---

## Key decisions (with links to the detailed logs)

| Decision | Instead of | Why | Log |
|---|---|---|---|
| EMBER2024 `thrember` for train **and** scan | writing our own features | identical features in training and production | 02 |
| Temporal split by week | random split | random splits leak the future | 02, 09 |
| memmap + `lightgbm.Sequence` | loading everything into RAM | 1 GiB binned vs 4.6 GiB raw; same code for the full dataset | 04, 09 |
| Early stop on **partial AUC** | logloss | we only operate at FPR ≈ 0.1% | 10 |
| Thresholds from val FPR targets | fixed 0.5 or guide's 0.97-on-test | test-set tuning leaks | 10 |
| Test is one-shot | iterating on test | otherwise test is a second val set | 10 |
| Fast extractor must be **bit-identical** | "close enough" | trees split on exact thresholds | 12 |
| Daemon routes by content, not extension | ext allowlist | a renamed PE walks straight past | 14 |
| Observer handler never sleeps | guide's `time.sleep(0.3)` | OS event buffer overflow under load | 14 |
| Dashboard is **read-only** on SQLite | adding writer actions | UI bugs can't alter evidence | 18 |
| Score = **sandbox barriers hit**, not malware patterns | signature list | rule weights map 1:1 to hardening flags | 17 |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ImportError: cannot import name 'SignedPEFile'` | `pip install "signify>=0.7.1,<0.8"` (in `requirements.lock`); signify 0.9 removed it |
| Korean prints as `???` | the CLIs reconfigure stdout to UTF-8 internally; in your own code add `sys.stdout.reconfigure(encoding="utf-8")` |
| `.venvScriptspython.exe: command not found` | in Git Bash use forward slashes: `.venv/Scripts/python.exe` |
| `No such file` for a repo script | the shell's cwd moved; `cd /c/Users/user/Documents/axiMini` first |
| `axi.model test` says "already used" | intended; `models/test_report.json` guards it. `--force` only after a retrain |
| First scan of a file is ~20 ms slower | Windows Defender's on-access scan; expected, leave Defender on |
| `ValueError: ... float32 is not double` | already handled in `MemmapSequence` (LightGBM Sequence wants float64) |
| `docker info` fails with WSL error | `wsl --install --no-distribution` in admin PowerShell, reboot, start Docker Desktop |
| Dashboard shows "모델 파일이 없습니다" | run `python -m axi.model train` first |

---

## Future work

- **Scan p95 < 50 ms.** Would need retraining on features computed with a cheaper `pefile` parse, or a timeout + "too complex → sandbox" route for pathological files.
- **Allowlisting by signer** (authenticode publisher), not just by hash, so updated signed software isn't re-flagged.
- **Model retraining pipeline** (expanding window + warm start + threshold re-derivation on a fresh holdout). Concept discussed in [`logs/2026-11-05_11_retraining-question.md`](logs/2026-11-05_11_retraining-question.md).
- **Priority queue** in the daemon (`.exe` in Downloads before DLLs in build folders).
- **PE dynamic analysis** via a Windows VM; the daemon marks `sandbox_unsupported` meanwhile.
- **YARA rule generator** from quarantined files: design in [`docs/YARA_RULE_GENERATOR.md`](docs/YARA_RULE_GENERATOR.md).

---

## References
- `guide.pdf` — DMDG Manual #04 (Korean, 8-week capstone spec)
- EMBER2024 dataset: <https://huggingface.co/datasets/joyce8/EMBER2024>
- thrember feature extractor: pinned to commit `0ef753e8…`, see `requirements.lock`
- Per-query learning logs under [`logs/`](logs/) (`01` through `18`)
- `DAY1_SUMMARY.md` — historical checkpoint at end of Day 1 (now superseded by this README)
