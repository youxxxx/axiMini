# Log 02 — Day 1 · Step 1: environment, skeleton, dataset & extractor check

- **Date:** 2026-11-04
- **Query:** you answered log 01's questions (300 GB disk, 16 GB RAM, Docker installed, use `*.pdf`), asked me to move my notes into the repo, and said to start Step 1.
- **Files changed or created:**
  - `.gitignore`: rewritten
  - `CLAUDE.md`: added a "Claude Notes" import section
  - `claude-notes/working-rules.md`, `claude-notes/user-profile.md`, `claude-notes/project-status.md`: moved here from Claude's memory dir
  - `requirements.txt`, `axi/__init__.py`, `axi/config.py`, `scripts/check_env.py`: new
  - `GUIDELINE.md`: two small updates
  - `.venv/`: created, git-ignored, packages not yet installed

> **🔧 Action items for you are in §6.** There are two: install the Python packages, and fix WSL so Docker can start.

---

## 1. Environment check: what I found

| Item | Result | Verdict |
|------|--------|---------|
| OS | Windows 11 Pro, build 26200 | ✅ |
| CPU | Intel i7-11700F, 8 cores / 16 threads | ✅ Good for LightGBM (multi-threaded) |
| RAM | 16 GB (you told me) | ⚠️ Enough, but it shapes the data plan (§3) |
| Disk | 373 GiB free on C: | ✅ |
| Python | `py --list` shows **3.14** (default) and **3.12.7** | ✅ We use **3.12**, see below |
| Git | 2.56 | ✅ |
| Docker Desktop | **CLI 29.9.2 installed** (per-user, today 17:21) in `%LOCALAPPDATA%\Programs\DockerDesktop` | ⚠️ The CLI works, but **the engine is not running** |
| WSL | `wsl --status` → error `Wsl/CallMsi/Install/REGDB_E_CLASSNOTREG` | ❌ **WSL is not installed**, so Docker's engine can't start |
| Hypervisor | `HypervisorPresent = True` | ✅ CPU virtualization is enabled in BIOS |

### Why Python 3.12 and not 3.14?
Packages with native (C/C++) code, such as LightGBM, numpy, and later yara-python, ship prebuilt **wheels** per Python minor version. A brand-new Python often lacks wheels for some of them for months, and pip then tries to compile from source, which fails on Windows without MSVC. 3.12 is mature, and every package we need has wheels for it. `thrember` requires ≥ 3.10.

### Why the Docker engine isn't running
Docker Desktop on Windows doesn't run containers on Windows itself. Linux containers need a **Linux kernel**. Docker Desktop runs a small Linux VM through **WSL 2** (a lightweight Hyper-V VM that Microsoft ships with a real Linux kernel), and the `docker.exe` CLI talks to the engine inside that VM over a named pipe (`//./pipe/docker_engine`). My test got:
```
failed to connect to the docker API at npipe:////./pipe/docker_engine ... The system cannot find the file specified.
```
That means nothing is listening on the pipe, because the VM can't start, because WSL isn't installed. `REGDB_E_CLASSNOTREG` means "COM class not registered": Windows 11 includes a small `wsl.exe` stub, and the real WSL is a separate package that hasn't been installed on this machine yet.

Also, `docker` isn't on the PATH in my shell. That's just because Docker was installed after this session's shell started. A new terminal will have it.

> This matters for **Day 2 only** (the sandbox). Day 1 doesn't need Docker.

---

## 2. Housekeeping done

### 2.1 `.gitignore`
Changed from `.pdf` (a literal filename) to `*.pdf`, and added standard entries. Each block has a reason:
- `.venv/`, `__pycache__/`, `*.py[cod]`, `.pytest_cache/`: machine-local or generated.
- `data/`, `models/`: GBs of dataset and trained model binaries. Git stores full snapshots of binaries, so they'd bloat history forever.
- `quarantine/`, `watched/`: runtime folders. Quarantine may hold files flagged as malicious, which must never be committed.
- `*.db`, `*.db-wal`, `*.db-shm`: SQLite database and its write-ahead-log side files.

### 2.2 Notes moved into the repo
- `~/.claude/projects/.../memory/*.md` → `claude-notes/` (renamed `working-rules.md`, `user-profile.md`, `project-status.md`). I deleted the old `MEMORY.md` index, so the memory dir is now empty.
- **How they still get loaded:** I appended an import section to `CLAUDE.md`:
  ```
  @claude-notes/working-rules.md
  @claude-notes/user-profile.md
  @claude-notes/project-status.md
  ```
  Claude Code expands `@path` lines in `CLAUDE.md` and includes those files in its context at session start. Without this, the moved files would just sit in the repo and I wouldn't see them.
- `user-profile.md` mentions your GitHub and Codeforces handles. If this repo becomes public, decide whether you're OK with that.

---

## 3. Dataset & extractor verification (the main technical work)

In log 01 I said I'd verify the EMBER2024 / `thrember` claims before relying on them. I read the project's README and the source of `pyproject.toml`, `download.py`, `model.py`, and `features.py` on GitHub. **I did not install it** (see §5).

### 3.1 Confirmed facts
| Question | Answer |
|----------|--------|
| Package | `thrember` 0.1.0, **not on PyPI**, installed from GitHub. Requires Python ≥ 3.10. |
| Dependencies | lightgbm, pefile, polars, scikit-learn, tqdm, signify (Authenticode), huggingface_hub, matplotlib. **No LIEF.** |
| Data host | Hugging Face dataset `joyce8/EMBER2024`, one zip per `{file_type}_{split}` |
| Sizes (zip) | Win32 train **23.7 GB**, Win32 test **4.9 GB**, Win64 train 12.9 GB, … |
| What's inside | **Raw feature JSON lines** (`.jsonl`), one JSON object per file with parsed features plus label. **No executables.** |
| Extractor | `thrember.PEFeatureExtractor`, **dim = 2568**, made of 12 groups (below) |
| Training path | `extractor.process_raw_features(json_obj)` → float32 vector |
| Scan path | `extractor.feature_vector(raw_bytes)` = `raw_features(bytes)` then `process_raw_features` |
| Pretrained models | `thrember.download_models()` fetches 14 benchmark LightGBM models (useful as a baseline later) |

**Feature groups (2568 total):**
| Group | Dim | What it captures | Low-level view |
|-------|-----|------------------|----------------|
| GeneralFileInfo | 7 | size, virtual size, has debug/relocs/resources/signature/TLS | header flags |
| ByteHistogram | 256 | normalized count of each byte value 0x00–0xFF | O(n) histogram |
| ByteEntropyHistogram | 256 | 2-D histogram of (window entropy, byte value) over sliding windows | local randomness, so it spots packed/encrypted regions |
| StringExtractor | 177 | printable strings: count, average length, char histogram, paths/URLs/registry keys/`MZ` occurrences | — |
| HeaderFileInfo | 74 | COFF & optional header fields: machine, timestamp, subsystem, versions, sizes | fixed-offset struct fields |
| SectionInfo | 224 | per-section name/size/entropy/virtual size/characteristics (hashed) | section table |
| ImportsInfo | 1282 | imported DLLs and functions, **feature-hashed** into fixed bins | IAT |
| ExportsInfo | 129 | exported function names, hashed | export directory |
| DataDirectories | 34 | size and RVA of the 16 data directories | optional header tail |
| RichHeader | 33 | undocumented MS linker "Rich" header (toolchain fingerprint) | XOR-masked block between DOS stub and PE header |
| AuthenticodeSignature | 8 | is it signed, chain validity, etc. | certificate table |
| PEFormatWarnings | 88 | which pefile parse warnings fired (malformed headers are a malware tell) | — |

**Feature hashing** (used in imports, exports, and section names): the set of possible API names is unbounded, so each string `s` maps to bin `h(s) mod k`. That gives a fixed-size vector with O(1) work per item and no vocabulary to store. The price is collisions. With k bins and m items, the expected number of colliding pairs is about m²/(2k), the birthday bound. It works well enough in practice because trees tolerate some noise.

### 3.2 Why this resolves the "feature consistency" problem from log 01
The same Python class produces the training vectors (from the JSON the EMBER authors extracted) and the scan-time vectors (from a real file's bytes). The vector layout is identical by construction. That was the guide's main flaw.

⚠️ **A remaining subtlety:** the dataset JSON was produced with *their* pefile version. If our pefile version parses some edge cases differently, a few fields can drift. For this lite project that's acceptable. A production system would pin the exact pefile version used to build the dataset.

### 3.3 Data plan decision: use **Win32_test only (4.9 GB)**, not Win32_train (23.7 GB)

> **Correction (2026-11-05, see log 04):** the RAM argument below overstates the problem. LightGBM can build its training set chunk by chunk (`lightgbm.Sequence`) and keeps only ~1 byte per value after binning, so the full Win32 train set is feasible in 16 GB. The subset choice still holds, but for download, vectorization, and iteration time, not RAM.
- **RAM math:** EMBER2024 has about 2.6 M training files across all types. If Win32 is roughly half, say ~1.3 M rows, then 1.3 M × 2568 features × 4 bytes ≈ **13 GB**. Add LightGBM's own binned copy and Python overhead, and that **doesn't fit in 16 GB**. The test zip is about ⅕ the size, around 250–350 k Win32 rows, so ≈ 3 GB. That fits comfortably.
- **Time:** training on ~200 k rows takes minutes on 16 threads. On ~1.3 M it would take tens of minutes per run. Since you're learning, more short experiments beat one long run.
- **Is it still a valid experiment?** Yes, as long as we **split by time**. EMBER2024's samples are tagged by **collection week**. Malware evolves (concept drift), so a random shuffle split would put "future" samples in training and inflate scores. We'll use the earliest weeks for train, the next for validation (threshold picking), and the latest for test. That mimics deployment: train on the past, face the future.
- **Upgrade path:** with 300 GB free, you can later download Win32_train and train on a memmapped random subsample. The code won't change.

### 3.4 Problems found in thrember (so we don't trip on them)
1. **`read_vectorized_features` loads the whole matrix into RAM** (`np.array(memmap)`). Fine for small subsets, but an OOM risk for big ones. We'll write our own loader using `np.memmap` (the OS pages data in lazily) and subsample row indices.
2. **Label dtype mismatch:** `vectorize_subset` writes `y` as float32, while `read_vectorized_features` reads it as int32. Reinterpreting the bytes of float `1.0` (0x3F800000) as an int gives 1065353216, not 1. We'll write our own vectors with explicit dtypes and avoid this path.
3. **`read_metadata` bug:** it builds the challenge DataFrame from the test records. We won't use it.
4. **`download_dataset` / `download_models` call `os.chdir()`.** That changes the working directory process-wide, which is a nasty side effect. We'll call them from a separate one-off script, or use `huggingface_hub.hf_hub_download` directly for a single file.
5. Not using `pefile.PE(fast_load=True)`: scan latency may be higher on large files. We'll **measure first** (p50/p95) before optimizing.

---

## 4. Skeleton created

```
axiMini/
├─ axi/
│  ├─ __init__.py        # package marker + version
│  └─ config.py          # every path & tunable in one place
├─ scripts/
│  └─ check_env.py       # environment self-test (run it after installing)
├─ claude-notes/         # Claude's notes (imported by CLAUDE.md)
├─ logs/
├─ requirements.txt
├─ GUIDELINE.md
└─ .venv/                # Python 3.12.7 (git-ignored)
```

Only files that are used now were created. Modules like `features.py` and `model.py` will appear when we write them, rather than as empty stubs.

- **`axi/config.py`**: a single source of truth for paths (`data/`, `models/`, `watched/`, `quarantine/`, `events.db`), plus placeholder thresholds. The real `T_low` and `T_high` will be computed from validation data and saved with the model, because a threshold is part of the model, not part of the code.
- **`scripts/check_env.py`**: checks the Python version, venv, every import (Day-1 packages required, Day-2 packages as warnings), **thrember's dim == 2568** (catches a wrong or old version), disk, RAM, and Docker engine reachability. It exits 1 if a required check fails, so it's usable in scripts.
  - Current output (no packages installed yet, as expected):
    ```
    [OK  ] python >= 3.10                  3.12.7
    [OK  ] running inside .venv            C:\Users\user\Documents\axiMini\.venv
    [FAIL] import thrember                 ModuleNotFoundError
    ... (all package imports FAIL/WARN)
    [OK  ] free disk >= 30 GiB             373 GiB
    [WARN] docker CLI on PATH              not found (open a new terminal?)
    ```
- **`requirements.txt`**: grouped by Day 1 / Day 2 / dev. `thrember` is a direct Git reference. After installing, pin it to a commit hash, so a future push to their repo can't silently change your features.

---

## 5. What I could not do, and why

`pip install git+https://github.com/FutureComputing4AI/EMBER2024` was **blocked by Claude Code's permission system**, which treats installing code from an external repository as needing your approval. That's a reasonable safety default: installing a package runs its build code on your machine. So the install step is yours (§6.1). You can also allow it for future sessions with a permission rule if you prefer.

---

## 6. 🔧 Your action items

### 6.1 Install Python packages (Day 1, needed now)
In this Claude session, type the following **one line at a time** (the `!` runs it here, so I can see the output).
> Corrected 2026-11-05 (log 05): `!` runs in **bash**, where `\` is an escape character, so the paths must use forward slashes.
```
! .venv/Scripts/python.exe -m pip install --upgrade pip
! .venv/Scripts/python.exe -m pip install -r requirements.txt
! .venv/Scripts/python.exe scripts/check_env.py
```
Expected: all `[OK]` except possibly the Docker lines. Downloads total a few hundred MB, mostly streamlit, pandas, and lightgbm. Then pin thrember:
```
! .venv/Scripts/python.exe -m pip freeze | grep thrember
```

### 6.2 Fix WSL so Docker can run (needed before Day 2)
1. Open **PowerShell as Administrator** (Start → type "PowerShell" → right-click → *Run as administrator*).
2. Run:
   ```powershell
   wsl --install --no-distribution
   ```
   - `--no-distribution` installs the WSL platform and kernel only, with no Ubuntu. Docker Desktop creates its own internal distro, so you don't need one. If you'd like a Linux shell for learning, run plain `wsl --install` instead, which adds Ubuntu.
   - If it fails with the same `REGDB_E_CLASSNOTREG` error, download the latest `wsl.*.x64.msi` from the official releases page **github.com/microsoft/WSL/releases** and run it.
3. **Reboot.**
4. Verify in a normal terminal: `wsl --version` should print versions instead of an error.
5. Start **Docker Desktop** from the Start menu and wait for "Engine running". Then run:
   ```
   docker run --rm hello-world
   ```
6. Optional: in Docker Desktop → Settings → Resources (WSL integration), memory is managed by WSL. To stop the WSL VM from claiming too much of your 16 GB, create `%UserProfile%\.wslconfig` with:
   ```ini
   [wsl2]
   memory=6GB
   ```
   Our sandbox containers are capped at 512 MB each, so 6 GB is plenty.

### 6.3 Nothing else
No VM, no Defender changes. The data we download is JSON feature vectors, not executables.

---

## 7. Next step: Day 1 · Step 2 (after 6.1 is done)
1. Download **only** `Win32_test.zip` (~4.9 GB) from Hugging Face into `data/ember2024/`.
2. Explore the data before modelling: number of rows, label balance (benign/malicious/unlabeled), and the **distribution by week** (this decides the split boundaries), plus one raw JSON record shown in full so you can see what "features" look like before vectorizing.
3. Write `axi/dataset.py`: stream the jsonl (it's too big to `json.load` whole), vectorize with `process_raw_features` into memmapped `X_*.npy` / `y_*.npy` per split.
