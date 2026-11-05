# Log 12: Day 1 · Step 4: scan CLI, explanations, and exact-output speedups

- **Date:** 2026-11-05
- **Query:** "go to step 4"
- **Files created:**
  - `axi/features.py`: fast, bit-identical drop-ins for slow thrember feature groups, plus `feature_names()` and Korean group labels
  - `axi/scan.py`: `Scanner` class (used by the Day-2 daemon) and the `python -m axi.scan` CLI (Korean output)
  - `scripts/profile_features.py`: per-group timing
  - `scripts/verify_features.py`: fast vs. original equivalence check
  - `scripts/bench_scan.py`: p50/p95/p99 latency
  - `scripts/__init__.py`: makes `scripts` importable for `-m` and the tests
  - `tests/test_features.py`: 14 pytest cases
- **Files changed:** `GUIDELINE.md` (latency checkbox, honest status), `claude-notes/project-status.md`

> **Environment:** nothing new. Tip: Windows Defender scans a file on its first open, adding ~20 ms to the first read of any file. That's environmental and correct behaviour for an endpoint, so leave Defender on.

Commands:
```
.venv/Scripts/python.exe -m axi.scan C:/Windows/SysWOW64/notepad.exe          # verdict + top-8 reasons
.venv/Scripts/python.exe -m axi.scan <dir> --no-explain                        # fast, every PE in a folder
.venv/Scripts/python.exe -m axi.scan <file> --json                             # machine-readable
.venv/Scripts/python.exe scripts/verify_features.py 1000                       # equivalence check, ~6 min
.venv/Scripts/python.exe -m scripts.bench_scan 400 C:/Windows/SysWOW64         # latency, ~5 min
.venv/Scripts/python.exe -m pytest -q tests                                    # 14 tests, ~6 s
```

---

## 1. Results at a glance

**Latency, end to end (read → features → score → verdict, model already loaded, warm file cache, no explanation):**

| Sample (400 files) | Original thrember extractor only | **axi scan, full** | of which `extract` | `predict` |
|---|---|---|---|---|
| System32 (x64), size p50 162 KiB | p50 119 / p95 924 ms | **p50 36 / p95 355 ms** | 35 / 353 | 1.1 / 1.2 |
| SysWOW64 (x86, closer to the Win32 training domain), p50 110 KiB | p50 102 / p95 648 ms | **p50 30 / p95 278 ms** | 28 / 276 | 1.2 / 1.3 |
| SysWOW64 files ≤ 1 MiB (370) | | p50 29 / p95 154 ms | | |

- Speedup at p50 is ~3.3×. Model load (once) is 180 ms. Explanation (TreeSHAP) costs ~430 ms extra, so it's opt-out in the CLI and the daemon will only explain non-"pass" files.
- **Goal "< 50 ms p95": met at p50, not at p95.** The remaining tail is pefile's full parse of large DLLs, which I deliberately did not touch (§4). Note that the target population isn't small either: from our own val features (`general.size`), benign files have p50 150 KiB / p95 3.8 MiB, malicious p50 397 KiB / p95 24 MiB. So the tail is real.

**Equivalence:** 1,008 real PE files (System32, SysWOW64, Program Files) + 8 synthetic edge cases + 300 random `entropy_H` inputs → **0 mismatches**, compared both as raw dicts (`==`) and as final vectors byte by byte (`tobytes()`). Negative control: perturbing the entropy by **one ulp** (`math.nextafter`) is caught on every file (322 mismatches), so the checker isn't vacuous.

**CLI output (Korean UI):**
```
■ C:\Windows\SysWOW64\notepad.exe
  악성 점수: 0.000000   (기준: 샌드박스 ≥ 0.290884, 격리 ≥ 0.999917)
  판정    : 정상 (통과)
  주요 판단 근거 (TreeSHAP 기여도, 로그-오즈 단위 / + 악성 방향, - 정상 방향):
      -3.452  [PE 파싱 경고] pefilewarnings.warn67[Suspicious flags set for section...] = 0
      +1.807  [PE 헤더] header.coff.char[DLL] = 0
      -1.323  [데이터 디렉터리] datadirectories.DEBUG.size = 112
    (기준값 +0.512 + 기여도 합 = 원점수 -16.969)
■ C:\Windows\win.ini
  판정    : PE 파일 아님 (검사 제외)
```

## 2. Why "bit-identical", not "close enough"
The model was trained on vectors from thrember's original code (log 09). Tree splits are thresholds: `x[j] <= 4.7183`. A feature that differs in its last bit can fall on the other side of a split, so "approximately equal" isn't a property you can reason about; only equality is. And train/serve skew (different feature code at training and inference) is one of the classic silent ML production bugs: no error, just quietly worse predictions. So every speedup was required to be exact and was verified empirically.

## 3. The speedups (profile → fix → verify)

`scripts/profile_features.py`, 300 System32 files, share of `raw_features` time **before**:

| Stage | mean ms | share |
|---|---|---|
| strings | 134.5 | 56% |
| pefile parse | 61.7 | 26% |
| general | 16.9 | 7% |
| section | 16.5 | 7% |
| byteentropy | 6.8 | 3% |
| the other 8 groups | ~2.9 | ~1% |

### 3.1 Strings: O(S·R) Python calls → O(R) C-level scans
Original: for each of the S printable strings (tens of thousands in a big DLL), for each of the R = 76 regexes, `re.search(r, s)`. That's S·R Python-level calls, ~100k+ interpreter round trips, each doing almost no work.

New (`FastStringExtractor`):
1. Join all strings with `"\n"` into one text. Keep `starts[i]`, the offset of string i (a prefix sum).
2. For each regex, a single `finditer` over the whole text: one C-level scan.
3. Map each match start back to its owning string with `np.searchsorted(starts, pos, side="right") - 1` (binary search), and `count[k] = #distinct owners`.

The cost becomes R scans over total length L, all inside the regex engine's C loop. **Why it's exact**, the three properties that had to hold:
- **No match crosses a separator.** Strings are runs of bytes 0x20–0x7f, so `"\n"` (0x0a) is never inside one. No pattern can match `"\n"`: no `DOTALL` (so `.` in `.click` excludes it), no `\s`, no negated classes.
- **`\b` behaves the same at the edges.** In `re.search(r, s)`, position 0 has "nothing" before it (non-word). In the joined text it has `"\n"` (non-word). Same for the end.
- **Existence per string is preserved.** `finditer` returns leftmost, non-overlapping matches. Inside one string its first match is the leftmost one, the same as `re.search`. We only need "≥ 1 match per string", so later overlapping matches don't matter.

The same function also replaced the per-byte Python list comprehension `[b - 0x20 for b in joined]` with `np.frombuffer(joined, uint8) - 0x20` for the character histogram. It produces the same integer counts, so the same float32 math follows.

### 3.2 Entropy (`general`, `section`): Counter → bincount, same summation order
pefile's `entropy_H` (and thrember's inline copies) does `Counter(bytearray(data))`, a hash-map update per byte, then sums `-p·log2(p)` over the counter's values.

The subtle part: **floating-point addition isn't associative**, so the *order* of the ≤ 256 terms matters for the last bits. `Counter` iterates in insertion order, the order in which byte values **first occur** in the data. So the fast version:
1. `np.bincount` gives counts in one vectorized O(n) pass.
2. It recovers first-occurrence order by scanning 64 KiB prefix chunks with `np.unique(..., return_index=True)` until every present value has been seen. Usually one chunk, worst case O(n log chunk).
3. It runs *the same* Python float loop in that order.

That makes it bit-identical by construction, and the 300 random skewed inputs plus 1,008 files confirm it. For sections, the fast function is attached to each `pe.sections[i]` **instance** (`s.entropy_H = entropy_H`), which shadows the class method only for our parsed object: no global monkeypatch of pefile.

### 3.3 Two non-feature costs found while benchmarking
Both were invisible to the per-group profile and only showed up in end-to-end timing. A reminder to always measure the whole path.

1. **pefile runs a full `gc.collect()`** in `close()`, which happens on every non-PE input (the parse raises, then closes). A full collection is O(live tracked objects), and after importing thrember/sklearn/scipy/signify the process has ~197,000 of them: **35 ms** per non-PE file (0.3 ms in a bare interpreter). Fix: `gc.freeze()` at the end of `Scanner.__init__` moves everything alive at that point (modules, model, lookup tables, long-lived anyway) into a permanent generation that the collector skips. Non-PE scans: 35 ms → ~0. Large DLLs also got ~10% faster, because automatic gen-2 collections stop rescanning those objects. This is the same trick Instagram used for forked web workers.
2. **My own bug:** `f.read(MAX_SCAN_BYTES + 1)` (to detect oversize files) makes CPython allocate a 128 MiB buffer up front and shrink it after reading. That's **~23 ms per file even for 92 bytes**: page-faulting 128 MiB of fresh memory. Fix: `os.fstat(f.fileno()).st_size` first, then `f.read()`. Read p50 went from 23 ms to 0.3 ms. The length is re-checked after reading, because the file can change between `fstat` and `read` (a TOCTOU window; harmless here, but the code doesn't assume otherwise).

## 4. What I deliberately did NOT optimize: pefile's parse
After the fixes, pefile's full parse is most of what's left, and it owns the p95 tail. cProfile on `shell32.dll` (7.7 MiB):
- `parse_exceptions_directory` (x64 `.pdata` / UNWIND_INFO): **65%** of the parse
- relocations: ~15%
- `pefile.PE(data, fast_load=True)` alone: 0.4 ms

It's tempting to use `fast_load` and parse only the directories features read (imports, exports). But **`pefilewarnings` is a feature group** (88 dims), and its vocabulary includes warnings emitted *during* exception and relocation parsing ("Unknown UNWIND_CODE at…", "Invalid relocation information…", "Bad RVA in relocation data…"). Skipping those parsers changes features, and specifically on **malformed files**, the population where it matters most. Our System32 equivalence test would pass anyway, because Microsoft's DLLs are well-formed. That's exactly the kind of "verified on the wrong data" trap to avoid. So: exactness over speed. The tail is latency the daemon will absorb asynchronously (Day 2: a worker pool, and the user never waits on a scan).

If you ever want the tail gone, the correct routes are: (a) retrain on features computed with the cheaper parse (new model, new thresholds); or (b) a timeout plus a "too complex → sandbox" verdict for pathological files. Both are design decisions, not refactors.

## 5. `axi/scan.py` design
- **`Scanner`** loads the model once. `Model()` checks the model's sha256 against `axi_lgbm.json` (log 10). It also builds the fast extractor and calls `gc.freeze()`. `scan(path, explain=k)` returns a `ScanResult` dataclass with `sha256, size, score, verdict, error, ms{read, extract, predict, explain}, top[]`. The daemon and dashboard will consume this same object (or its JSON).
- **Verdicts:** `pass` / `sandbox` / `quarantine` from the val thresholds, plus two non-model outcomes:
  - `not_pe`: the model only ever saw PE files, so a score for `win.ini` would be meaningless. It isn't scored at all, rather than scored and ignored.
  - `error`: unreadable, empty, or > 128 MiB. Extraction is O(size) and fully in RAM, so a size cap is basic DoS protection for a daemon that scans whatever lands in a folder.
- **Explanations: TreeSHAP via `pred_contrib=True`.** LightGBM returns one contribution φᵢ per feature plus a bias, with the exact identity raw_score(x) = bias + Σ φᵢ (in log-odds). Positive φ pushes toward malicious. These are Shapley values: each feature's average marginal contribution over all orderings, computed exactly for trees in polynomial time (O(T·L·D²) instead of exponential). With 2063 trees × 512 leaves that's ~430 ms, about **400× a plain predict (1.1 ms)**. Hence `--no-explain`, and the daemon will explain only non-pass files.
- **`feature_names()`** mirrors each group's `process_raw_features` to name all 2568 dims, with a pytest guard: the length must equal `dim`, names must be unique, and thrember's categorical indices `[2..6, 701, 702]` must land on `is_pe`, `start_byte[0..3]`, `coff.machine`, `optional.subsystem`. They do, which independently confirms the layout. Hashed groups can only be named by bucket (`imports.func_hash[517]`): feature hashing is one-way, many names → one bucket.
  - The test caught a real bug on its first run: truncating warning names to 40 chars made 5 pairs collide. Now they carry their index (`warn67[...]`).

## 6. Reading the explanations: a learning note
- `kernel32.dll`'s strongest benign evidence was `authenticode.latest_signing_time` (−3.9). Signing *time* is a proxy for "signed recently by a real publisher". It's legitimate, but it's also a **temporal feature**: it works partly because of *when* the dataset was collected, and it can age badly (another face of the drift in log 10).
- `notepad.exe`'s top features are structural (no "suspicious section flags" warning, DEBUG and LOAD_CONFIG directories present). Malware toolchains often skip these.
- SHAP explains **the model**, not the world. A feature with a large φ is what the model relied on, not proof of maliciousness. For the dashboard, show these as "판단 근거" (grounds for the decision), not as "IoCs".

## 7. Upstream quirks noticed (no action; changing them would break feature consistency)
- `ExportsInfo.process_raw_features` stores `len(exports_hashed)` (always 128) instead of the number of exports, so the "count" dim is constant.
- `DataDirectories.process_raw_features` loops `range(1, len(raw_obj) - 1)` and skips the last directory (RESERVED), so its two dims are always 0.
- Both are harmless constants to a tree model (never split on). Recorded so nobody "fixes" them and silently breaks the trained model.

## 8. Next: Day 1 wrap-up, or Day 2
Day 1 is functionally complete (data → model → scan CLI). Open items before Day 2:
1. `pip freeze > requirements.lock` (end-of-Day-1 reproducibility snapshot).
2. **Your action for Day 2: install WSL** so Docker's engine can run (log 02 §6.2: run `wsl --install --no-distribution` in an **admin** PowerShell, reboot, start Docker Desktop, then `docker info` should succeed).

Day 2 · Step 1 would be the watcher daemon: watchdog on `watched/` → worker pool → `Scanner` → SQLite event log → quarantine move for `quarantine` verdicts. That part doesn't need Docker yet; the sandbox step does.
