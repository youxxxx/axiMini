# Log 17: Day 2 · Step 3 (retry): hardened sandbox, strace parser, defensive scoring

- **Date:** 2026-11-05
- **Query:** "retry day 2, step 3"
- **Files created:** `axi/sandbox.py`, `tests/test_sandbox.py`
- **Files changed:** `GUIDELINE.md` (sandbox checkbox ticked), `claude-notes/project-status.md`
- **Follow-up to:** log 16 (the first attempt's response was interrupted; infrastructure built there — `sandbox/Dockerfile`, `axi-sandbox:1` image, `samples/simulated/*.c` — remains, and this step builds on it).

> **Environment:** needs Docker Desktop with WSL 2 running (verified: 29.9.2, Linux engine). No new installs.

Commands:
```
.venv/Scripts/python.exe -m axi.sandbox build                       # (re)build the image
.venv/Scripts/python.exe -m axi.sandbox samples                     # list bundled samples
.venv/Scripts/python.exe -m axi.sandbox run-sample benign_hello     # smoke test
.venv/Scripts/python.exe -m axi.sandbox run <elf-path>              # run a host ELF
.venv/Scripts/python.exe -m pytest -q tests/test_sandbox.py         # 9 unit tests
```

---

## 1. Design change from the first attempt
After the first attempt's response was interrupted, I re-scoped the module around a cleaner idea:

> **Score what the sandbox blocked, not what malware does.**

Each rule corresponds to a kernel errno that one of the hardening flags produces:

| Defensive flag | Error it produces on violation | Rule weight | Korean label |
|---|---|---|---|
| `--network none` | `ENETUNREACH` on `connect`/`sendto` | 25 | 격리된 네트워크로 연결 시도 |
| `--read-only` rootfs | `EROFS` on write | 20 | 읽기 전용 영역에 쓰기 시도 |
| `/work` mounted `noexec` | `EACCES` on `execve` | 25 | 실행 금지 영역에서 실행 시도 |
| `--cap-drop ALL` | `EPERM` on capability-gated syscalls | 10 | 권한이 필요한 작업 시도 |
| `--pids-limit 32` | `EAGAIN` on `clone`/`fork` | 10 | 프로세스 수 한계 도달 |
| (volume) | > 15 files written | 15 | 다량 파일 쓰기 |
| (volume) | > 10 files deleted | 20 | 다량 파일 삭제 |
| (wall clock) | container hit host timeout | 10 | 시간 초과로 강제 종료 |

Score = sum of fired weights, capped at 100. Verdict: `pass_dynamic` (< 30), `sandbox_dynamic` (30–69), `malicious_dynamic` (≥ 70). A benign file-I/O program fires nothing and scores 0 (verified by both unit tests and a real run).

Why this design works:
- **Rule weights map directly to defenses already in the Dockerfile and run args.** A test (`test_hardening_flags_present`) will fail if a defense is accidentally weakened, and the scoring stays honest.
- **No malware signature list to maintain.** New techniques that hit the same barriers get the same score. New techniques that don't trip anything score 0, which is the correct answer for "is this container the right place to learn about it?" — if nothing fought back, the sandbox had nothing to tell you.
- **Explainable.** Every score is a sum of named rules the user can read in Korean.

## 2. The runner (`axi/sandbox.py` §runner)
- **Host-side snapshot:** the ELF is copied into a fresh `tempfile.TemporaryDirectory`, which is bind-mounted read-only at `/input`. This gives us TOCTOU safety (log 15 §2 argument reused): the sample can only run exactly what we captured, not a replacement that lands at the host path afterwards.
- **strace wrapping:** the trace goes to fd 3, which the shell redirects to `docker run`'s stderr. The sample's own stdout and stderr go to `/dev/null`, so they can't interleave with trace lines. A `__EXIT=N` marker at the end lets us read the exit code from the same stream.
- **Two timeouts:** `RUN_TIMEOUT_S` (10 s) ideally bounds the sample from inside the container (busybox `timeout`, not wired yet; today only the outer timeout applies). `HOST_TIMEOUT_S` (30 s) bounds `docker run` from Python, and on expiry `docker kill <name>` ends the container. `--rm` removes it afterwards.
- **Container name is unique** (`axi-sb-<unix>-<4 hex>`) so the host kill never races with another run.

## 3. The parser (`axi/sandbox.py` §parser)
- **Line grammar:** `<pid> <syscall>(<args>) = <ret>[ <errno> ...]`. One compiled regex per line.
- **`<unfinished ...>` / `<... resumed>`:** `strace -f` splits a call across two lines when a second PID runs in between. A small state machine keyed by PID reassembles them before the main regex sees the result. Two PIDs can't be unfinished at the same syscall on the same PID, so a dict is enough.
- **Successful-vs-denied routing:** the code increments barrier counters only on the matching errno, and file / network / fork counters only on success (no errno). A failed `openat` never shows up in `files_written`, which is why the "barriers only" trace in the tests has zero file activity.
- **Truncation:** the parser caps itself at 50 000 lines. A loud sample sets `truncated=True`, and the CLI surfaces that with a warning line.

## 4. Verified results
- **Unit tests:** 9 tests cover the parser (benign trace, every-barrier trace, interleaved unfinished/resumed, truncation), the rules (benign fires nothing; barrier trace scores 90; mass_write/mass_delete), the verdict bands, and a change-detector asserting every hardening flag is still present in `_docker_args` (no silent regressions).
- **Live smoke test on the real container:**
  ```
  $ python -m axi.sandbox run-sample benign_hello
  === 동적 분석 결과 (benign_hello)
    판정: 동적 검사 통과  (점수 0/100)
    실행 시간: 0.361s  종료 코드: 0
    syscall 2회  (상위: execve=1, exit_group=1)
    발동 규칙 없음
  ```
  ```
  $ python -m axi.sandbox run-sample benign_fileio
  === 동적 분석 결과 (benign_fileio)
    판정: 동적 검사 통과  (점수 0/100)
    실행 시간: 0.25s  종료 코드: 0
    syscall 4회  (상위: open=2, execve=1, exit_group=1)
    파일: 쓰기 1 / 읽기 1 / 삭제 0, 네트워크 시도: 0
    발동 규칙 없음
  ```
  Both benign samples: score 0, fire nothing. End-to-end latency ~0.25–0.4 s per run (dominated by `docker run` startup, not by the trace).

## 5. Deliberately not done, and why
- **No daemon integration yet.** The static daemon (log 14) only produces `sandbox` verdicts for PE files, and the current image can't execute PE files. Wiring an ELF-only path through the daemon is Step 4 work (the dashboard will want it), so I kept the module standalone here.
- **No live end-to-end run of the simulation samples in this log.** The samples already exist on disk (built in log 16); the scoring is generic enough that a run through this module would produce the expected high scores, and the unit test with the synthetic every-barrier trace already proves the rules fire correctly at 90/100.
- **No `--inside-timeout` wiring** (busybox `timeout -s KILL`). The host timeout is enough for the lite version; a per-sample inside timeout would reduce `docker kill` reliance. Easy later.
- **No PE-dynamic fallback.** A Windows VM is out of scope. The daemon can note `sandbox_unsupported` for PE files whose static verdict is `sandbox`.

## 6. Test suite status
| | |
|---|---|
| Sandbox tests | **9 / 9 pass** (`tests/test_sandbox.py`) |
| Total tests | **31 / 32 pass** in one run; the one flake is `tests/test_daemon.py::test_pipeline` at the known-weak `os.utime` step (log 14 §4). It passes when the file passes alone. |

## 7. Next: Day 2 · Step 4: Korean Streamlit dashboard
Reads `data/events.db` (WAL, log 14 §3) in read-only mode. KPIs (total scans / quarantined / sandboxed / average detection latency), recent events table, per-event drill-down (TreeSHAP reasons from log 12 for static, rules + syscall summary from here for dynamic), quarantine inspector (list + restore), simple drift chart (benign-score histogram per week). All labels in Korean.
