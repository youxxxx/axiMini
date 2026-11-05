# Log 14: Day 2 · Step 1: real-time watcher daemon → workers → SQLite

- **Date:** 2026-11-05
- **Query:** "go to day 2, step 1"
- **Files created:** `axi/daemon.py`, `axi/store.py`, `tests/test_daemon.py`
- **Files changed:** `axi/scan.py` (`scan(..., explain_verdicts=...)`), `claude-notes/project-status.md`
- **Runtime artifacts (git-ignored):** `data/events.db` (+ `-wal`, `-shm`), `watched/`

> **Environment:** nothing new (`watchdog` was installed on Day 1). Docker/WSL is still needed only for Step 3 (sandbox). Quarantine (moving files) is Step 2, so in this step a `quarantine` verdict is **recorded but not acted on**.

Commands:
```
.venv/Scripts/python.exe -m axi.daemon                 # watch ./watched, 2 workers, scan existing files first
.venv/Scripts/python.exe -m axi.daemon --dir D:/inbox --workers 4 --no-initial-scan
# then drop files into the folder; stop with Ctrl+C (finishes in-flight scans, then exits)
.venv/Scripts/python.exe -m pytest -q tests            # 15 tests incl. the end-to-end daemon test
```

---

## 1. What it looks like
Six files dropped into `watched/` (a PE disguised as `invoice.pdf`, a text file, a DLL in a subfolder):
```
20:41:53 작업자 프로세스 2개 시작 중 (모델 로드)...
20:41:56 실시간 감시 시작: C:\Users\user\Documents\axiMini\watched  (DB: ...\data\events.db, 종료: Ctrl+C)
20:41:57 ✅ 정상  ...\watched\notepad.exe  (점수 0.000000, 추출 61 ms, 감지→판정 815 ms, #1)
20:41:57 ✅ 정상  ...\watched\cmd.exe  (점수 0.000000, 추출 81 ms, 감지→판정 898 ms, #2)
20:41:57 ·  PE 아님  ...\watched\readme.txt  (점수 -, 추출 3 ms, 감지→판정 875 ms, #3)
20:41:57 ✅ 정상  ...\watched\invoice.pdf  (점수 0.000001, 추출 10 ms, 감지→판정 867 ms, #4)
20:41:57 ✅ 정상  ...\watched\kernel32.dll  (점수 0.000000, 추출 251 ms, 감지→판정 1064 ms, #5)
20:41:59 ✅ 정상  ...\watched\sub\shell32.dll  (점수 0.000000, 추출 1433 ms, 감지→판정 2263 ms, #6)
```
- `invoice.pdf` is really `calc.exe`. It was scanned as a PE because routing is by **content** (MZ header + pefile), not by extension. The guide's handler filters on `{".exe", ".dll", ...}`, which a renamed payload walks straight past (even the guide's own simulator uses `update.bin`).
- Every row in SQLite carries `model_sha256` (`460ec1ca4d77…`), so an old verdict stays attributable after a future retrain (log 11 §3.3).
- Startup: ~3 s to spawn the 2 worker processes and load the model in each. They're warmed up *before* the watcher starts, so the first file doesn't pay it.

**Detection latency** (file closed → verdict in DB): **~0.8–1.1 s** for normal files, 2.3 s for the 6.8 MiB shell32.dll (1.4 s extraction). Where the time goes: debounce 0.5 s + stability re-check 0.2 s + polling ≤ 0.1 s + extraction. The guide's "0.05 s" counts only the model's scoring; **any** correct watcher must wait for the writer to finish, so end-to-end can't be 50 ms without scanning half-written files. To go lower, shrink `DEBOUNCE_S` (e.g. 0.2 s) at the cost of more re-scans of files still being written.

## 2. Architecture (one process with 3 threads, plus N worker processes)
```
 watchdog observer thread   Handler.on_created/on_modified/on_moved ─► Pending.touch(path)   O(1), never blocks
          │                       (ignores *.crdownload, *.part, *.tmp, ~$office-locks)
          ▼
 stabilizer thread          every 0.1 s: entries quiet ≥ 0.5 s → stat → (size, mtime) unchanged
          │                 across 0.2 s? → openable? → ready queue
          ▼
 dispatcher thread          ready queue ─► ProcessPoolExecutor(N) ─► Scanner.scan()  (in a worker process)
          │                 ◄─ ScanResult dict; dispatcher is the ONLY SQLite writer
          ▼
 data/events.db (WAL)  ◄──  dashboard (Step 4) reads with read-only connections
```

### 2.1 Debounce = a dict keyed by path
Copying one file on Windows produces `created` plus several `modified` events (`ReadDirectoryChangesW` reports each write/attribute flush). `Pending` is `dict[path → (first_seen, last_event, …)]`: each event is an O(1) upsert, so a burst of k events for one file costs O(k) and becomes **one** entry. A path is "due" when `now − last_event ≥ 0.5 s`. That is the guide's "Debouncing 0.5s" box, implemented without sleeping.

### 2.2 Why the guide's `time.sleep(0.3)` in `on_created` is a bug
watchdog calls handlers **on its observer thread**, the same thread that drains the OS event buffer. Sleeping there blocks draining. Drop 100 files and that's 30 s during which the kernel buffer (`ReadDirectoryChangesW` has a fixed-size buffer) can **overflow, and the OS then drops events**. An EDR that silently misses files under load is worse than a slow one. Rule: event handlers only record; the work happens elsewhere.

### 2.3 "Is the file finished?": three conditions
1. **Quiet:** no events for 0.5 s.
2. **Stable:** `(size, mtime_ns)` equal across two `stat`s 0.2 s apart. A writer that pauses longer than the debounce window and then continues is caught here, or by the next event.
3. **Openable:** on Windows, most writers open files without `FILE_SHARE_READ`, so our `open()` raises `PermissionError` until they close. That's a free "writer is done" signal. We retry every 0.2 s for up to 120 s, then scan anyway (the worker records the error).

### 2.4 Two concurrency bugs caught in review, before any test
- **Lost-update race:** the stabilizer decides "stable" → a new write event arrives → the stabilizer pops the entry → that event is lost, and the half-new file is never rescanned. Fix: `pop(path, if_last_event=snapshot)` deletes only if `last_event` is unchanged since the stabilizer read it, under the lock. This is a compare-and-swap, the same idea as `std::atomic::compare_exchange` on the entry's version.
- **Doubled latency:** my first version reset the debounce clock after the first `stat`, so the minimum delay was 2 × 0.5 s. Now only real filesystem events move `last_event`, and the stability re-check has its own `next_check` timer (0.2 s).

### 2.5 Worker processes, not threads
Feature extraction is pure Python (pefile, our regex/entropy code) and holds the **GIL**, so N threads would run extraction one at a time. `ProcessPoolExecutor` gives N interpreters:
- Each worker builds its own `Scanner` once in `initializer` (model load + `gc.freeze()`, log 12). Windows uses **spawn**, not fork: each worker is a fresh interpreter that imports everything (~3 s), and there's no copy-on-write sharing. 2 workers ≈ 2 × ~300 MB RAM.
- Only the path goes to the worker and only a small dict comes back. Pickling the file bytes or the 2568-float vector across processes would be wasted IPC.
- **Backpressure:** at most `2 × workers` jobs are in the pool; the rest wait in the ready queue (bounded at 10,000). `Pending` is bounded by the number of distinct paths. So a flood of files grows queues, not unbounded memory in the pool.
- A worker exception becomes an `error` row; it never kills the dispatcher.

### 2.6 Explanations only where they're needed
TreeSHAP costs ~430 ms vs ~1 ms for a score (log 12). Workers call `scan(explain=8, explain_verdicts={"sandbox", "quarantine"})`, so **pass** files (the vast majority) cost no explanation at all, and suspicious ones arrive in the DB with their top-8 reasons already attached for the dashboard.

### 2.7 Other behaviour
- **Initial scan:** files that arrived while the daemon was down are queued at startup (pre-aged so they're due immediately). Disable with `--no-initial-scan`.
- **Recursive** watching (`watched/sub/shell32.dll` above).
- **No-op events:** after a scan, `last_scanned[path] = (size, mtime)`. A later event with the same signature (e.g. an AV touching the file) doesn't re-scan; a real modification does. Re-scanning on change is deliberate: a file whose content changed *is* a new file.
- **Ctrl+C:** stop the observer, drain in-flight jobs, write their rows, shut the pool down, print verdict stats.

## 3. SQLite store (`axi/store.py`)
- **Schema:** one `events` row per verdict: timestamps (`first_seen`, `scanned_at`, `detect_ms`), path, sha256, size, score, verdict, error, per-stage ms (JSON), top features (JSON), `model_sha256`, and `action` / `action_detail` (filled by Step 2's quarantine). Indexes on `scanned_at`, `verdict`, `sha256` cover the dashboard's queries (recent N, counts by verdict, "seen this hash before?").
- **WAL mode:** in the default rollback journal, a committing writer blocks readers. In **write-ahead logging**, commits append to `events.db-wal` and readers keep reading a consistent snapshot, so the dashboard polling every second never stalls the daemon. That's the `-wal`/`-shm` files next to the DB.
- **`synchronous=NORMAL`:** in WAL mode, a power cut can lose the last few commits but never corrupts the DB. That's the right trade for an event log (vs. `FULL`, which fsyncs on every insert).
- **Single writer:** only the dispatcher thread writes. SQLite allows one writer at a time anyway, and `sqlite3` connections shouldn't be shared across threads, so a single owner avoids `database is locked` and needs no locking code.
- **Read-only connections** for consumers (`mode=ro` URI): the dashboard can't alter the evidence it displays.

## 4. Testing
`tests/test_daemon.py` runs the **real** stack (observer, stabilizer, worker process, SQLite) on a temp folder and DB, and checks:

| Case | Expected | Result |
|---|---|---|
| file present before start | scanned by the initial scan (`not_pe`) | ✅ |
| PE copied as `update.bin` | scanned by content → `pass` | ✅ |
| `setup.exe.crdownload` → renamed `setup.exe` | only `setup.exe` gets a row (via `on_moved`) | ✅ |
| slow writer: 5 chunks with 0.3 s pauses | one row, **full size**, never a half-written scan | ✅ |
| created and deleted at once | no row | ✅ |
| timestamp-only change | no new row | ✅ (weak: Windows may not even raise an event for an atime change, so this mostly checks we don't crash) |

15/15 tests pass (~12 s). Also checked after the manual demo: killing the daemon left **no orphan worker processes**.

## 5. Known limits (fine for the lite version, listed for learning)
- **Event loss under extreme load:** the OS buffer can still overflow with thousands of files per second. Production EDRs pair the watcher with periodic **reconciliation scans** (walk and compare with what's in the DB), or use a kernel minifilter driver that sees every write synchronously. That's how real EDRs work, and it's out of scope here.
- **No priority queue** (the guide's design): all jobs are FIFO. A natural extension is to prioritize `.exe` in Downloads over DLLs in build folders.
- **No dead-letter queue:** failures are rows with `verdict = error` and the message, which serves the same forensic purpose.
- **A watcher only sees files at rest.** Fileless malware, process injection and in-memory payloads are invisible to this design. That's why the guide adds dynamic analysis (the sandbox, Step 3).
- **No live malicious sample to show a `quarantine` verdict:** by design, no live malware. Step 3's harmless simulated samples provide test inputs for the non-pass paths.

## 6. Next: Day 2 · Step 2: quarantine action
In the dispatcher, for `quarantine` verdicts:
- move the file into `quarantine/` under a sha256-based name;
- neutralize it (strip the extension, store original metadata in a sidecar JSON, mark it read-only);
- record `action` and `action_detail` in the event row;
- add a CLI to list and restore quarantined files.

Topics: atomic same-volume moves vs. cross-volume copies, files still locked by a running process, and why EDRs encrypt or XOR quarantined files so they can't be double-clicked.
