# Log 09 — Day 1 · Step 2: download, explore, vectorize, chunked LightGBM loading

- **Date:** 2026-11-05
- **Query:** "go to step 2"
- **Files created:** `scripts/download_ember.py`, `scripts/explore_ember.py`, `axi/dataset.py`
- **Files changed:** `axi/config.py` (feature dim + temporal split), `claude-notes/project-status.md`
- **Data on disk (all git-ignored under `data/`):**
  - `data/zips/Win32_test.zip`: 2.42 GiB (kept, so re-extraction needs no re-download)
  - `data/ember2024/*.jsonl`: 12 files, 10.4 GiB
  - `data/vectors/*.X.npy / *.y.npy / *.meta.npz`: 7.0 GiB
  - `data/vectors/train.lgb.bin`: 0.43 GiB (LightGBM binary dataset, see §5.4)

> **Environment:** nothing new to install. Free disk went from ~375 GiB to ~355 GiB.

---

## 1. Download (`scripts/download_ember.py`)
- I used `huggingface_hub.hf_hub_download(repo_id="joyce8/EMBER2024", filename="Win32_test.zip", repo_type="dataset")` directly instead of `thrember.download_dataset`. That avoids its process-wide `os.chdir()` (log 02 §3.4) and keeps the zip cached, so re-runs are no-ops.
- **Zip-slip protection:** a malicious zip can contain member names like `../../Windows/x.dll`, and naive extraction writes outside the target folder. `safe_extract` resolves each target path and refuses any that isn't inside `data/ember2024/`. It also extracts only `.jsonl` members. This source is a well-known dataset, but downloaded archives are untrusted input by default.
- Extraction streams 1 MiB at a time (`zf.open` + `read(1<<20)`), so memory stays O(1) regardless of file size.
- The warning "unauthenticated requests to the HF Hub" is harmless. A free `HF_TOKEN` only raises rate limits.
- **Size surprise:** the README said "Win32 test 4.9 GB", but the zip was **2.42 GiB**. The 4.9 figure probably refers to another size or unit. Extracted JSON is 10.4 GiB (JSON compresses ~4×, because number text is very redundant).

## 2. Exploration (`scripts/explore_ember.py`)
One pass per weekly file, 12 processes in parallel, **14 s** for 10.4 GiB.

| | |
|---|---|
| Files | 12 weekly files, `2024-09-22_2024-09-28` … `2024-12-08_2024-12-14` |
| Rows | **720,000**, exactly **60,000 per week** |
| Labels | exactly **30,000 benign + 30,000 malicious per week**. No unlabeled (`-1`) rows. |
| Avg record | 14–17 KiB of JSON, growing slightly over time |

**Record layout** (first record, a malicious `cosmu`-family sample):
- **Metadata** (NOT features): `md5/sha1/sha256`, `tlsh` (a locality-sensitive hash), `first_submission_date`, `last_analysis_date`, `detection_ratio` ("66/74" AV engines), `label`, `family`, `family_confidence`, tag lists (`behavior`, `packer`, …), `week_id`, `caps/ttps/mbc` (capability, ATT&CK, and Malware Behavior Catalog tags).
- **Raw feature groups** (input to `process_raw_features`): `histogram`[256], `byteentropy`[256], `strings`{6}, `general`{4}, `header`{3}, `section`{3}, `imports`{5}, `exports`[], `datadirectories`[17], `richheader`[18], `authenticode`{8}, `pefilewarnings`[1].

⚠️ **Leakage warning, for learning:** `detection_ratio`, `family`, and the tags are *derived from the label source* (AV verdicts). If one were used as an input, the model would score near-perfectly and learn nothing real. Our feature vector comes only from `process_raw_features`, which ignores them. Be careful whenever adding "extra" columns.

### What the 50/50 balance means
Real endpoints see benign files far more often than malware, perhaps 1000:1. This dataset is artificially balanced. That's fine for **TPR and FPR**, which are rates *within* each class and so independent of the class ratio. It's misleading for **precision** and **accuracy**. With FPR 0.1%, TPR 95%, and a 1000:1 ratio, a million files give 1000 false alarms against 950 real detections, so precision is about 49%, even though the same model shows ~99.9% precision on 50/50 data. That's the **base-rate fallacy**, and it's why the guide's KPI is FPR, not accuracy.

## 3. Split decision (`config.SPLIT_WEEKS`)
| Split | Weeks | Rows | Purpose |
|-------|-------|------|---------|
| train | 1–8 (09-22 … 11-16) | 480,000 | fit trees |
| val | 9–10 (11-17 … 11-30) | 120,000 | early stopping, **threshold selection** |
| test | 11–12 (12-01 … 12-14) | 120,000 | touched **once**, for the final report |

- **Why by week and not by `first_submission_date`:** the files overlap by a few hours at their edges (week 4's min timestamp < week 3's max). The week file is the dataset authors' own unit, and the overlap is negligible.
- **Upstream contrast:** `thrember.train_model` takes its validation set with `train_test_split(..., stratify=y)`, a **random** split. Random splits leak future malware into validation, so early stopping and thresholds get tuned on "already seen" campaigns. Our temporal split measures what deployment faces: models trained on the past, judged on the future (**concept drift**).
- **Duplicate check (sha256):** train∩val = 0, train∩test = 0, **val∩test = 1**. One file in 120k is negligible; we'll leave it.

## 4. Vectorization (`axi/dataset.py`)
### 4.1 Format decisions
| Choice | Why |
|--------|-----|
| One output set per **week** | Parallelism (one process per file), idempotent re-runs, and splits are just lists of weeks |
| `.npy` via `np.lib.format.open_memmap` instead of raw `.dat` | The `.npy` header stores dtype and shape, so a reader can't misinterpret the bytes. thrember's float32-written/int32-read label bug (log 02 §3.4) is exactly what raw `.dat` invites. |
| `y` as **int8** | Labels are 0/1. 1 byte is enough and explicit. |
| `meta.npz` with `first_submission_date` + `sha256` | Needed for the leakage check, and later for "which file was this?" in the dashboard |
| Write to `*.tmp.npy`, then `os.replace` | Atomic rename: a crash mid-write never leaves a file that looks finished. `del X` before the rename matters on Windows, because a file can't be renamed while it's still memory-mapped (unlike POSIX). |
| Two passes per file (count lines, then fill) | The memmap must be preallocated with a known `n`. Counting is a cheap sequential read (~1 s). |
| `multiprocessing.Pool`, not threads | `json.loads` + `process_raw_features` are pure Python and hold the **GIL**, so threads would run them one at a time. Processes are independent interpreters; each writes its own file, with no shared state. |

### 4.2 Measurements
- Sample timing: `json.loads` 0.17 ms/row + `process_raw_features` 0.48 ms/row ≈ 0.65 ms/row. That's ~40 s per week on one core.
- Full run: **1 min 45 s** wall for 720k rows on 12 processes. The estimate was ~40 s; the difference is disk writes (7 GiB) and 12 processes competing for 8 physical cores (hyper-threads share execution units).
- Sanity: no NaN or inf. On average **~700 of 2568 dims are non-zero** (27%). Hashed import/export/section bins are mostly empty, which matters in §5.

## 5. Chunked LightGBM loading (follow-up to log 04)
### 5.1 `MemmapSequence(lgb.Sequence)`
- `np.load(path, mmap_mode="r")` is O(1). It maps the file and reads nothing, and pages load on first touch (same as `mmap` in C).
- `lgb.Dataset([seq_week1, …, seq_week8], label=y)`: LightGBM accepts a **list** of Sequences and treats them as concatenated rows. There's no need to concatenate ourselves (which would copy 4.6 GiB).

### 5.2 Bug hit: `ValueError: sample_data[0] type float32 is not double`
LightGBM's Sequence code path samples rows and passes them to its C API as `double*`, and it **rejects float32** instead of converting. Fix: `__getitem__` returns `np.asarray(self.X[idx], dtype=np.float64)`. The cast happens per batch (4096 × 2568 × 8 B ≈ 84 MB), and the files on disk stay float32, half the size.

### 5.3 Memory: the honest numbers (480k × 2568 train split)
| Moment | RSS (working set) | Private bytes |
|--------|-------------------|---------------|
| after `load_split` (memmaps opened) | 0.18 GiB | 1.11 GiB |
| after `Dataset.construct()` (134 s) | 5.76 GiB | 2.09 GiB |
| after dropping the memmaps | **1.16 GiB** | 2.08 GiB |
| **peak working set** during construct | **10.22 GiB** | — |

How to read this, since Windows counts memory differently from what you might expect:
- **RSS / working set** = physical pages currently mapped into the process, **including file-backed pages** from our memmaps. Those are a *cache* of the `.npy` files: the OS can drop them at any time and re-read them from disk. That's why RSS fell from 5.76 to 1.16 GiB the moment we closed the memmaps.
- **Private bytes** = memory only this process owns (heap, LightGBM's buffers). The ~1.1 GiB at start is mostly native libraries (numpy, LightGBM, OpenMP runtime) committing memory. **The binned dataset itself is ≈ 1 GiB** (2.09 − 1.11). That matches log 04's prediction of 480k × 2568 × 1 B = 1.15 GiB.
- **The 10.2 GiB peak** is mostly reclaimable file cache, plus the float64 batches and LightGBM's 200k-row sample during binning. Under memory pressure Windows trims it, but it's a good reason not to run a second heavy job at the same time on this 16 GB machine.

### 5.4 Binary dataset cache: 0.43 GiB
`ds.save_binary("data/vectors/train.lgb.bin")` wrote only **0.43 GiB**, smaller than the 1.15 GiB "1 byte per value" estimate. Two LightGBM techniques explain it:
- **Small bins:** a feature with ≤ 16 distinct bins is stored in **4 bits** (two per byte). Many features have few distinct values.
- **Exclusive Feature Bundling (EFB):** sparse features that are rarely non-zero *at the same time* (for example different hashed import buckets) are merged into one column with offset bin ranges. Finding the optimal bundling is graph colouring (NP-hard), so LightGBM uses a greedy approximation and tolerates a small conflict rate. That's a nice CP-flavoured heuristic inside a production ML library.

**Payoff:** later training runs can call `lgb.Dataset("data/vectors/train.lgb.bin")` and load in seconds, instead of re-binning for 134 s. ⚠️ The val/test Datasets must be built with `reference=train_ds` so they use the **same bin boundaries**. Otherwise bin 17 means different raw values in train and val.

## 6. Upstream details read during this step
- Categorical features in thrember's training code: indices `[2, 3, 4, 5, 6, 701, 702]`. We pass the same list. LightGBM then splits them by category subsets, not by `<` thresholds, which is right for codes like "machine type" where order is meaningless.
- Upstream tunes with `roc_auc_score(..., max_fpr=5e-3)`, a **partial AUC** that only looks at the FPR ≤ 0.5% region. That's the right metric family for us, since we only operate at FPR ≈ 0.1%.

## 7. Next step: Day 1 · Step 3 (waiting for your go-ahead)
1. `axi/model.py`: train LightGBM on `train.lgb.bin`, early stopping on val (validation built with `reference=`).
2. Pick `T_high` on **val** so FPR ≤ 0.1%, and `T_low` for a recall target. Save both with the model.
3. Report once on **test**: ROC-AUC, partial AUC (FPR ≤ 0.5%), TPR at FPR 0.1%, F1, and the confusion matrix. Compare val versus test to *see* the drift.
4. Optionally compare against thrember's pretrained Win32 benchmark model as a reference point.
