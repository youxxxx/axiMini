# Log 07 — Requirements installed; `signify` API break fixed; first extractor smoke test

- **Date:** 2026-11-05
- **Query:** you ran `pip install -r requirements.txt` (success). I then pinned thrember, ran `check_env.py`, found and fixed an import failure, and smoke-tested the extractor.
- **Files changed:** `requirements.txt` (thrember commit pin and a `signify` pin), `claude-notes/project-status.md`
- **Environment changed:** `signify` 0.9.3 → **0.7.1** in `.venv`

---

## 1. Install result
- 70+ packages installed, all from **prebuilt wheels** (`cp312-win_amd64` or `py3-none-any`). Nothing compiled from source, which confirms that choosing Python 3.12 paid off.
- `thrember` was built locally from the Git clone into a pure-Python wheel (`py3-none-any`, 27 KB).
- Notable resolutions:
  - `lightgbm 4.7.0`, `numpy 2.5.4`, `scikit-learn 1.9.1`, `pandas 3.1.1`, `streamlit 1.66.1`, `pefile 2024.8.26`.
  - `watchdog`: pip first looked at 7.0.0, then **backtracked to 6.0.0**. Streamlit declares `watchdog<7`, and the resolver found the newest version satisfying *all* constraints. That's dependency resolution as a constraint-satisfaction search.

## 2. Pinning thrember
pip printed `Resolved https://github.com/FutureComputing4AI/EMBER2024 to commit 0ef753e81d98bf209f71b03cd331dfc190b5b54d`. `requirements.txt` now says:
```
thrember @ git+https://github.com/FutureComputing4AI/EMBER2024@0ef753e81d98bf209f71b03cd331dfc190b5b54d
```
**Why it matters:** a Git URL with no ref means "whatever `main` is today". If upstream changes the feature layout, a reinstall would silently produce vectors incompatible with a trained model. A commit hash is immutable (it *is* the content hash of the tree).

## 3. Bug: `import thrember` failed
```
ImportError: cannot import name 'SignedPEFile' from 'signify.authenticode'
```
### Root cause
- `thrember`'s `pyproject.toml` declares `signify>=0.7.1` with **no upper bound**, so pip installed the latest, **0.9.3**.
- From signify's changelog, **0.9.0 (2025-10-07)**:
  - "remove various concrete implementations as imports from `signify.authenticode`" → `SignedPEFile` now lives in `signify.authenticode.signed_file`.
  - "Renamed `AuthenticodeFile.iter_signed_datas` … to `iter_embedded_signatures`" → thrember's `features.py:935` calls the old name.
- So two breaking changes hit one feature group, `AuthenticodeSignature` (8 of the 2568 dims). Python imports eagerly, so the first break kills `import thrember` entirely.

### Options considered
| Option | Verdict |
|--------|---------|
| Patch thrember's import and method names for signify 0.9 | ❌ The renamed objects may also have changed *behaviour* (fields, verification, error classes). The features would silently differ from the ones in the EMBER2024 dataset, which is the exact train/scan inconsistency we're trying to avoid. |
| Pin `signify<0.9` (0.8.x) | Possible, but 0.8.0 (Aug 2025) may differ from what the dataset was built with. |
| **Pin `signify>=0.7.1,<0.8`** ✅ | It matches thrember's declared minimum and was the current version when EMBER2024 was produced (2024–mid 2025). That gives the closest reproduction of the dataset's Authenticode features. |

**General lesson:** an open-ended lower bound (`>=x`) in a library is a time bomb. Libraries should declare a compatible range (`>=0.7.1,<0.9`), and applications should pin exact versions (a lock file). We'll generate a lock file at the end of Day 1 (§7).

### Result
```
Successfully installed signify-0.7.1
[OK  ] import thrember                 ok
[OK  ] thrember extractor dim == 2568  2568
...
[WARN] docker engine reachable         ... npipe:////./pipe/dockerDesktopLinuxEngine
exit=0
```
All Day-1 checks pass. Docker is still waiting on the WSL fix (log 02 §6.2). The pipe name in the message changed because the Docker CLI context now points at Docker Desktop's Linux engine; the cause is the same.

## 4. Smoke test: extracting features from real Windows binaries
| File | Size | Vector | Non-zero dims | Time (cold) |
|------|------|--------|---------------|-------------|
| `notepad.exe` | 352 KiB | (2568,) float32 | 1068 | 140 ms |
| `kernel32.dll` | 841 KiB | (2568,) float32 | 1675 | 565 ms |

### Interesting details in the Authenticode output
- **notepad.exe: `num_certs: 0`.** It is genuinely Microsoft-signed, but by **catalog signing**: its hash is listed in a signed `.cat` file under `C:\Windows\System32\CatRoot`, and nothing is embedded in the PE. The EMBER features only see *embedded* signatures, so to this model notepad looks "unsigned". That's a real-world blind spot worth remembering when we interpret false positives on system files.
- **kernel32.dll: `num_certs: 2`, `chain_max_depth: 2`** (embedded signature). Its `signing_time_diff` ≈ 1.67 × 10⁹ s ≈ 53 years, which is nonsense as a time difference. Windows system binaries are built **reproducibly**: `FILE_HEADER.TimeDateStamp` holds a **hash of the build**, not a time. The feature quietly turns into noise for these files.

## 5. ⚠️ Latency finding: the extractor misses the 50 ms target
Per-group timing on `kernel32.dll` (after warm-up):

| Step | ms | Notes |
|------|----|-------|
| `pefile.PE(data=b)` full parse | **100.7** | `fast_load=True` takes **0.4 ms**. Almost all the cost is parsing data directories we may not need. |
| **StringExtractor** | **383.7** | **63% of total** |
| SectionInfo | 24.5 | |
| GeneralFileInfo | 23.9 | |
| ByteEntropyHistogram | 10.5 | |
| AuthenticodeSignature | 5.3 | |
| everything else | < 3 | |
| **Total** | **≈ 610** | target < 50 |

### Why StringExtractor is slow (an algorithm view)
```python
allstrings = self._allstrings.findall(bytez)                 # one C-level regex scan: fast
as_shifted_string = [b - 0x20 for b in b"".join(allstrings)] # per-byte Python loop: O(total string bytes) at ~50 ns/byte
for s in allstrings_ascii:                                   # S strings  (thousands)
    for k, r in self._regexes.items():                       # × R regexes (~77)
        if re.search(r, s): ...                              # → S·R ≈ 10^5 Python-level calls
```
The complexity is O(S·R) **interpreter-level calls**. Each call is cheap in C, but the Python dispatch overhead (~1–3 µs per call) dominates.

### How we could fix it *without changing the output*
1. Replace the per-byte list comprehension with `np.frombuffer(joined, np.uint8) - 0x20`, the same vectorization trick as for entropy.
2. Reduce S·R calls to R calls: join all strings with a separator that can't occur in them (`\n`; strings only contain `0x20–0x7f`) and run each regex **once** with `finditer` over the joined text. Then map each match's start offset back to a string index by binary search over prefix sums of lengths, and count **distinct** string indices per regex. That's R C-level scans plus O(M log S) for M matches.
   - **Caveat:** this is only equivalent if no regex can match *across* the separator (for example `\s`, a negated class like `[^x]`, or `.` with DOTALL) or depends on `^`/`$` anchors. Each of the 77 regexes would need checking, and the result must be **verified bit-for-bit** against the original on many files.
3. Use `pefile.PE(..., fast_load=True)` and parse only the directories the groups need, again verified for identical output.

**Not done now** (one step at a time, per your rules). This becomes a dedicated "latency" step after the model works. It's a good exercise, since it's essentially a CP optimization with an equivalence proof. Note that **training is unaffected**: the dataset JSON already contains the raw features, so this cost only applies when scanning new files.

## 6. A second upstream bug noticed (kept on purpose)
In `StringExtractor._regexes`, **`email_addr` has exactly the same pattern as `mac_addr`** (a copy-paste error), so the "email" feature actually counts MAC-address-like strings.
**We keep it.** The dataset was generated with the same code, so the model learned whatever that column really means. "Fixing" it only at scan time would *create* a train/scan mismatch. A broken-but-consistent feature beats a correct-but-inconsistent one.

## 7. Next step: Day 1 · Step 2 (waiting for your go-ahead)
1. Download only `Win32_test.zip` (4.9 GB) with `huggingface_hub.hf_hub_download` directly, avoiding thrember's `os.chdir()` side effect.
2. Explore: row count, label balance, rows per week (this sets the train/val/test boundaries), and one raw JSON record.
3. Write `axi/dataset.py`: stream the jsonl, vectorize into memmaps, and expose them as a `lightgbm.Sequence`.
4. Later: `pip freeze > requirements.lock` once Day 1 works, for exact reproducibility.

Docker/WSL (log 02 §6.2) is still pending but only blocks Day 2.
