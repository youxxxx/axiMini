"""Real-time folder watcher: filesystem events -> stable files -> scan workers -> SQLite.

    python -m axi.daemon [--dir watched] [--workers 2] [--no-initial-scan]

Pipeline (threads in this process, plus a pool of worker PROCESSES):

  watchdog observer thread      Handler.on_*  -> Pending.touch(path)    (O(1), never blocks)
           │
  stabilizer thread             every 100 ms: paths quiet for >= DEBOUNCE_S whose size+mtime
           │                    stopped changing and that can be opened -> ready queue
           ▼
  dispatcher thread             ready queue -> ProcessPoolExecutor (Scanner per process)
           │                    <- results; the ONLY thread that writes SQLite
           ▼
  data/events.db (WAL)          read by the dashboard

Design notes vs. guide.pdf ch.13 (details in log 14):
  * no time.sleep() in the event handler: it would stall the observer thread and drop events;
  * on_moved is handled: browsers download to *.crdownload / *.part and rename at the end;
  * files are routed by content (MZ check in Scanner), not by extension: "update.bin" is a PE too;
  * worker processes, not threads: feature extraction is pure Python and holds the GIL.
"""

import argparse
import logging
import os
import queue
import signal
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import asdict, dataclass
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from axi import config, store

DEBOUNCE_S = 0.5            # quiet time after the last event before a file is considered
STABLE_S = 0.2              # size+mtime must be unchanged across a check this far apart
TICK_S = 0.1                # stabilizer polling period
MAX_WAIT_S = 120.0          # give up waiting for a file that never stabilizes / stays locked
EXPLAIN_TOP = 8
EXPLAIN_VERDICTS = {"sandbox", "quarantine"}
IGNORED_SUFFIXES = {".crdownload", ".part", ".partial", ".download", ".tmp", ".swp"}
IGNORED_PREFIXES = ("~$", ".~")   # Office lock files, editor temp files

log = logging.getLogger("axi.daemon")


# ---------------------------------------------------------------- event intake
@dataclass
class _Entry:
    first_seen: float     # first event of this "version" of the file (for detection latency)
    last_event: float     # most recent event (debounce clock; only real events move it)
    size: int = -1        # (size, mtime) at the previous stability check
    mtime_ns: int = -1
    next_check: float = 0.0


class Pending:
    """path -> _Entry, shared by the observer thread (writer) and the stabilizer (reader).

    A dict keyed by path *is* the debouncer: a burst of N events for one file (Windows sends
    created + several modified during a copy) collapses into one entry in O(1) each.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._d: dict[str, _Entry] = {}

    def touch(self, path: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            e = self._d.get(path)
            if e is None:
                self._d[path] = _Entry(first_seen=now, last_event=now)
            else:
                e.last_event = now

    def due(self, now: float) -> list[tuple[str, float, _Entry]]:
        """(path, last_event snapshot, entry) for entries quiet for DEBOUNCE_S."""
        with self._lock:
            return [(p, e.last_event, e) for p, e in self._d.items()
                    if now - e.last_event >= DEBOUNCE_S and now >= e.next_check]

    def recheck(self, path: str, size: int, mtime_ns: int, at: float) -> None:
        with self._lock:
            e = self._d.get(path)
            if e is not None:
                e.size, e.mtime_ns, e.next_check = size, mtime_ns, at

    def pop(self, path: str, if_last_event: float | None = None) -> bool:
        """Remove the entry, but only if no newer event arrived since `if_last_event`.

        Without this check: stabilizer decides "stable" -> a new write event arrives -> the
        stabilizer pops the entry -> that event is lost, and we may scan a half-new file.
        """
        with self._lock:
            e = self._d.get(path)
            if e is None or (if_last_event is not None and e.last_event != if_last_event):
                return False
            del self._d[path]
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._d)


def _ignored(path: str) -> bool:
    name = os.path.basename(path)
    return name.lower().endswith(tuple(IGNORED_SUFFIXES)) or name.startswith(IGNORED_PREFIXES)


class Handler(FileSystemEventHandler):
    def __init__(self, pending: Pending):
        self.pending = pending

    def _add(self, path: str) -> None:
        if not _ignored(path):
            self.pending.touch(path)

    def on_created(self, event):
        if not event.is_directory:
            self._add(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._add(event.src_path)

    def on_moved(self, event):
        # "x.exe.crdownload" -> "x.exe": the final name is what matters
        if not event.is_directory:
            self._add(event.dest_path)


# ---------------------------------------------------------------- stability check
@dataclass
class Job:
    path: str
    first_seen: float
    size: int
    mtime_ns: int


def stabilizer(pending: Pending, ready: "queue.Queue[Job]", last_scanned: dict,
               stop: threading.Event) -> None:
    """Promote debounced paths to the ready queue once the file is really finished.

    "Finished" = (1) no events for DEBOUNCE_S, (2) size and mtime equal to the previous
    check, (3) we can open it for reading (on Windows a writer usually holds the file without
    FILE_SHARE_READ, so open() raises PermissionError until it closes it).
    """
    while not stop.is_set():
        now = time.time()
        for path, seen, e in pending.due(now):
            try:
                st = os.stat(path)
            except FileNotFoundError:
                pending.pop(path, seen)              # deleted / renamed away before we got to it
                continue
            except OSError:
                continue
            sig = (st.st_size, st.st_mtime_ns)
            if (e.size, e.mtime_ns) != sig:          # first look, or still growing: look again
                pending.recheck(path, *sig, at=now + STABLE_S)
                continue
            if last_scanned.get(path) == sig:        # an event that didn't change the content
                pending.pop(path, seen)
                continue
            try:
                with open(path, "rb"):
                    pass
            except PermissionError:
                if now - e.first_seen < MAX_WAIT_S:
                    pending.recheck(path, *sig, at=now + STABLE_S)
                    continue                         # still locked by its writer: retry later
            except OSError:
                pending.pop(path, seen)
                continue
            if pending.pop(path, seen):              # False -> a new event came in: not done yet
                ready.put(Job(path, e.first_seen, *sig))
        stop.wait(TICK_S)


# ---------------------------------------------------------------- worker processes
_scanner = None


def _init_worker() -> None:
    """Runs once in each worker process (Windows 'spawn': a fresh interpreter, ~3 s import)."""
    global _scanner
    import warnings
    warnings.filterwarnings("ignore")
    from axi.scan import Scanner
    _scanner = Scanner()


def _scan_job(path: str) -> dict:
    res = _scanner.scan(path, explain=EXPLAIN_TOP, explain_verdicts=EXPLAIN_VERDICTS)
    return asdict(res)


# ---------------------------------------------------------------- dispatcher (single DB writer)
VERDICT_LINE = {
    "pass": "✅ 정상", "sandbox": "⚠️ 의심(샌드박스 대상)", "quarantine": "🚨 악성(격리 대상)",
    "not_pe": "·  PE 아님", "error": "❌ 검사 실패",
}


def dispatcher(ready: "queue.Queue[Job]", pool: ProcessPoolExecutor, workers: int,
               db_path: Path, model_sha: str, last_scanned: dict, stop: threading.Event,
               stats: dict) -> None:
    con = store.connect(db_path)
    inflight = {}
    max_inflight = workers * 2   # backpressure: at most 2 queued jobs per worker in the pool
    while not (stop.is_set() and not inflight and ready.empty()):
        while len(inflight) < max_inflight:
            try:
                job = ready.get(timeout=TICK_S if not inflight else 0)
            except queue.Empty:
                break
            inflight[pool.submit(_scan_job, job.path)] = job
        if not inflight:
            if stop.is_set():
                break
            continue
        done, _ = wait(inflight, timeout=TICK_S, return_when=FIRST_COMPLETED)
        for fut in done:
            job = inflight.pop(fut)
            try:
                res = fut.result()
            except Exception as e:  # a crashed worker must not kill the daemon
                res = {"path": job.path, "verdict": "error", "error": f"작업자 오류: {e!r}"}
            last_scanned[job.path] = (job.size, job.mtime_ns)
            row = store.insert_event(con, first_seen=job.first_seen, path=job.path, result=res,
                                     model_sha256=model_sha if res.get("score") is not None else None)
            stats[res["verdict"]] = stats.get(res["verdict"], 0) + 1
            score = f"{res['score']:.6f}" if res.get("score") is not None else "-"
            ms = res.get("ms", {})
            log.info("%s  %s  (점수 %s, 추출 %.0f ms, 감지→판정 %.0f ms, #%d)",
                     VERDICT_LINE[res["verdict"]], job.path, score, ms.get("extract", 0),
                     (time.time() - job.first_seen) * 1e3, row)
            if res.get("error"):
                log.info("     └ %s", res["error"])
    con.close()


# ---------------------------------------------------------------- main
def initial_scan(root: Path, pending: Pending) -> int:
    """Files that arrived while the daemon was down. Pre-aged so they're due immediately."""
    n, t = 0, time.time() - DEBOUNCE_S
    for dirpath, _, names in os.walk(root):
        for name in names:
            p = os.path.join(dirpath, name)
            if not _ignored(p):
                pending.touch(p, now=t)
                n += 1
    return n


def run(watch_dir: Path, workers: int, initial: bool, db_path: Path = config.DB_PATH,
        stop: threading.Event | None = None) -> dict:
    import json
    watch_dir.mkdir(parents=True, exist_ok=True)
    model_sha = json.loads(config.MODEL_META_PATH.read_text())["model_sha256"]
    stop = stop or threading.Event()
    pending, ready, last_scanned, stats = Pending(), queue.Queue(maxsize=10_000), {}, {}

    log.info("작업자 프로세스 %d개 시작 중 (모델 로드)...", workers)
    pool = ProcessPoolExecutor(max_workers=workers, initializer=_init_worker)
    for f in [pool.submit(int, 0) for _ in range(workers)]:
        f.result()   # forces every worker to spawn + load the model before we start watching
    observer = Observer()
    observer.schedule(Handler(pending), str(watch_dir), recursive=True)
    observer.start()
    if initial:
        log.info("기존 파일 %d개 검사 예약", initial_scan(watch_dir, pending))
    threads = [
        threading.Thread(target=stabilizer, args=(pending, ready, last_scanned, stop),
                         name="stabilizer", daemon=True),
        threading.Thread(target=dispatcher, args=(ready, pool, workers, db_path, model_sha,
                                                  last_scanned, stop, stats),
                         name="dispatcher", daemon=True),
    ]
    for t in threads:
        t.start()
    log.info("실시간 감시 시작: %s  (DB: %s, 종료: Ctrl+C)", watch_dir.resolve(), db_path)
    try:
        while not stop.is_set():
            stop.wait(0.5)
    except KeyboardInterrupt:
        stop.set()
    log.info("종료 중... (진행 중인 검사를 마무리합니다)")
    observer.stop()
    observer.join()
    for t in threads:
        t.join()
    pool.shutdown(wait=True)
    log.info("종료 완료. 판정 통계: %s", stats)
    return stats


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="axiMini 실시간 파일 감시 데몬")
    ap.add_argument("--dir", type=Path, default=config.WATCH_DIR, help="감시할 폴더")
    ap.add_argument("--workers", type=int, default=2, help="검사 작업자 프로세스 수")
    ap.add_argument("--db", type=Path, default=config.DB_PATH, help="이벤트 DB 경로")
    ap.add_argument("--no-initial-scan", action="store_true", help="시작 시 기존 파일 검사 생략")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S",
                        stream=sys.stdout)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    run(a.dir, a.workers, not a.no_initial_scan, a.db)


if __name__ == "__main__":
    main()
