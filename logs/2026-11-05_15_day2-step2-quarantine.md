# Log 15: Day 2 · Step 2: quarantine, restore, allowlist

- **Date:** 2026-11-05
- **Query:** "go to day 2, step 2"
- **Files created:** `axi/quarantine.py` (vault + CLI), `tests/test_quarantine.py` (8 tests)
- **Files changed:**
  - `axi/daemon.py`: `handle_result`, demo threshold flag, ignores `.axiq-tmp`
  - `axi/store.py`: schema v2 adds `allowlist` and `actions`; upgrades v1 DBs in place
  - `GUIDELINE.md`: quarantine checkbox ticked
  - `claude-notes/project-status.md`
- **Runtime artifacts (git-ignored):** `quarantine/<sha256>.qbin` and `.json`; demo rows in `data/events.db`, kept so the dashboard step has data to show

> **Environment:** nothing new.

Commands:
```
.venv/Scripts/python.exe -m axi.daemon                        # quarantine verdicts are now acted on automatically
.venv/Scripts/python.exe -m axi.quarantine list               # 격리 항목 목록
.venv/Scripts/python.exe -m axi.quarantine show <sha-prefix>  # sidecar JSON (origins, score, model, reasons)
.venv/Scripts/python.exe -m axi.quarantine restore <sha-prefix> [--to PATH] [--no-allow]
.venv/Scripts/python.exe -m axi.quarantine delete <sha-prefix>   # permanent; the sidecar stays as an audit record
.venv/Scripts/python.exe -m axi.quarantine allow <sha256> --reason "..."
.venv/Scripts/python.exe -m axi.daemon --demo-t-high 0.9      # DEMO ONLY, see §5
```

---

## 1. Live demo (real files, demo threshold 0.9)
```
21:27:28 ⚠️ 데모 모드: 격리 임계값을 0.9000로 낮춤 (실제 값 0.999917). 운영 환경에서 사용 금지!
21:27:36 🚨 악성(격리 대상)  ...\watched\getprocaddr32.exe  (점수 0.977325, ..., #7)
21:27:36      └ 격리 완료: ...\quarantine\db0dc45b5711...e70.qbin
21:27:36 ✅ 정상  ...\watched\notepad.exe  (점수 0.000000, ..., #8)
21:27:36 ⚠️ 의심(샌드박스 대상)  ...\watched\setup_wm.exe  (점수 0.815029, ..., #9)
$ python -m axi.quarantine restore db0dc45b
복원 완료: ...\watched\getprocaddr32.exe  (허용 목록에 추가됨)
21:27:41 🚨 악성(격리 대상)  ...\watched\getprocaddr32.exe  (점수 0.977325, ..., #10)
21:27:41      └ 허용 목록 파일 - 조치 안 함: 허용 목록 (오탐 처리된 해시)
```
- The restored file's sha256 equals the original's (`db0dc45b5711b783…`).
- The audit table reads `quarantine:quarantined → allowlist → restore`.
- The restore re-triggered the watcher (the file reappeared in `watched/`). The scan still says "quarantine", but the **allowlist check runs before any action**, so it stays. That's the whole false-positive workflow end to end.

## 2. Moving a file into quarantine safely
The naive version is `read → write copy → delete original`. Two failure windows:
- **TOCTOU** (time-of-check to time-of-use): the file can be replaced between our scan and the delete, and we'd delete bytes we never saved or scanned.
- **Crash between steps:** the file is deleted but the copy isn't written yet, so evidence is lost.

`quarantine_file` orders the steps so every intermediate state is recoverable:

| Step | Operation | If it fails / something changed |
|---|---|---|
| 1 | `os.rename(path, path.<rand>.axiq-tmp)`, in the **same directory** | `PermissionError` → file is open or running → `locked`, untouched |
| 2 | read the renamed file, sha256 it | hash ≠ scanned hash → rename back → `changed`; the daemon rescans the new content |
| 3 | write the encoded blob to a temp file in the vault, `fsync`, `os.replace` | crash → original still sits under the held name, vault untouched |
| 4 | write the sidecar JSON (atomic), then delete the held original | delete refused → `copied_not_removed`: evidence saved, original left under the unrunnable `.axiq-tmp` name |

Why each piece:
- **Rename first:** a rename within one directory (one volume) is a single metadata operation. Once it succeeds, the bytes we read in step 2 are the bytes that were at `path`, and nobody can launch the file by its name anymore. A cross-volume "rename" would really be copy + delete, which isn't atomic. That's why the held file stays in the same directory, and the vault write is a separate copy.
- **`fsync` before `os.replace`:** `os.replace` is atomic for visibility, but without `fsync` a power cut could leave a correctly named file with missing data. Write the data durably, *then* publish the name. This is the standard write-temp-then-rename pattern, the same one we used for `.npy` in log 09.
- **Windows specifics:**
  - CPython opens files without `FILE_SHARE_DELETE`, so while any process has the file open, rename and delete are refused. That's exactly the `locked` test case.
  - A read-only file can't be replaced or deleted until its attribute is cleared, hence the `chmod(S_IWRITE)` before replace or delete in the vault.
  - A **running** `.exe` can usually be renamed but not deleted, which is what the `copied_not_removed` state covers. A real EDR kills the process first (the guide's "Kill"), which needs privileges and process-tree reasoning. Out of scope here.

## 3. The vault format
- **Name = sha256** (content addressing): two copies of the same malware share one blob, with one `origins[]` entry per location (tested). There are no name collisions, and the path itself is an index.
- **`.qbin` = `MAGIC(8) | key(32) | data XOR key`**, with a fresh random key per file, stored in the header.
  - This is **neutralization, not encryption**. The key is right there. The goals are that (1) the stored bytes are no longer a PE, so a double-click does nothing; (2) antivirus and our own watcher don't keep re-detecting the file; (3) no plain-text copy of the payload sits on disk. Real AVs do the same (XOR or RC4 with a known key).
  - Putting the key in the blob (not only the sidecar) means a lost sidecar never makes a sample unrecoverable.
  - The XOR is vectorized with numpy (`a ^ np.resize(key, n)`): O(n) in C, not a Python loop per byte.
- **Read-only blob:** guards against accidental modification, though not against an admin.
- **Sidecar JSON** per sha: status (`quarantined` / `restored` / `deleted`) and every origin with path, time, mtime, event id, score, verdict, model sha256, and the top-5 TreeSHAP reasons. `delete` removes the blob but **keeps the sidecar**: evidence of what happened outlives the sample.

## 4. False positives: restore implies allowlist
Log 10 measured a test FPR of 0.21%, so false positives *will* happen. The workflow:
1. A user or analyst checks a quarantined file and decides it's benign.
2. `restore` **first** adds its sha256 to the `allowlist` table, **then** writes the file back.
3. The daemon checks the allowlist **before acting** on any verdict.

The order in step 2 matters. Restoring into the watched folder triggers a rescan within ~1 s. If the file appeared before the allowlist row was committed, the daemon would quarantine it again: a race between the CLI process and the daemon process, resolved by ordering the writes. `restore --no-allow` exists for "restore elsewhere to analyze" (e.g. `--to D:/analysis/`), and prints that it may be re-quarantined.

**Why allowlist by hash and not by path:** a path allowlist (`C:/tools/*`) is a gift to attackers. Drop malware into the allowed path and it's ignored. A sha256 allowlist covers *exactly these bytes*; any change, even one byte, is scanned again. Production EDRs also allowlist by **signer** (e.g. "signed by Microsoft"), which survives updates. That's the "allowlisting" remedy from log 10 §2, and a good extension using the authenticode info we already extract.

**Audit:** every action (`quarantine:<status>`, `allowlist`, `restore`, `delete`) is a row in `actions` with time, sha and detail, and the event row's `action` column shows what happened to that scan. The dashboard (Step 4) will show both.

## 5. Why there's a `--demo-t-high` flag, and its rules
There's no live malware in this project, so nothing legitimately reaches T_high = 0.999917, and the quarantine path could only be shown with a fake. I first measured how our real model treats real software on this PC:

| | |
|---|---|
| Scanned | 2,636 installed program files (Program Files, Program Files (x86), %LOCALAPPDATA%\Programs) |
| `quarantine` | **0** |
| `sandbox` (score ≥ 0.290884) | **4 (0.15%)**: Git's `getprocaddr32.exe` 0.977, Windows Media Player `setup_wm.exe` 0.815, Git `docx-strip-pii.exe` 0.578, Docker Desktop Installer 0.317 |

These are real false positives at the sandbox level. Installers and small helper tools (tiny binaries that resolve APIs dynamically: `getprocaddr32` literally exists to call `GetProcAddress`) look like droppers to a static model. The 0.15% sandbox rate is far under val's 1%, because installed, mostly signed software is easier than EMBER's benign set.

So the demo lowers T_high **explicitly and loudly**: a warning line at startup, a flag named "demo", and the threshold is overridden only in the worker processes for that run. A real false positive (0.977) then exercises the real code path. Rules: never use it in production, and know that demo-run events are stored like normal events. **Known gap:** the event row doesn't record which T_high was in force. I'll add a `thresholds` field when the dashboard needs it (Step 4).

## 6. Tests (8 new, 23 total, all passing)
| Test | Checks |
|---|---|
| encode round trip | decode(encode(x)) == x; no `MZ`, no plain-text slice; new key each time |
| move + record | original gone, no leftover temp, blob read-only and decodes to the original, sidecar origin |
| changed after scan | wrong expected sha → file put back, no blob |
| locked | file held open → `locked`, file untouched |
| duplicates | 2 copies → 1 blob, 2 origins, `already_quarantined` |
| restore | allowlist then restore, sha verified, blob removed, status `restored`, second restore refused, actions = [allowlist, restore] |
| no overwrite | restore refuses if the target path is occupied |
| daemon handler | quarantine verdict → action `quarantined`; after restore the same verdict → `allowlisted`, file stays |

## 7. Next: Day 2 · Step 3: Docker sandbox (needs WSL)
For `sandbox` verdicts: run **harmless simulated** samples (our own small programs that mimic malware behaviours: writing many files, touching autorun-like paths, attempting network connections) in a hardened Linux container under `strace`, and parse syscalls into a behaviour summary.

- Container flags: `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`, plus pids, memory and CPU limits, and a non-root user.
- A Linux container can't run a Windows PE (the guide's Wine option is out of scope), so the sandbox runs the simulated Linux samples, and the daemon links a sandbox verdict to the matching sample.

**Your action before Step 3:** in an **administrator** PowerShell run `wsl --install --no-distribution`, reboot, start Docker Desktop, and check that `docker info` prints server info. `scripts/check_env.py` should then show Docker as OK.
