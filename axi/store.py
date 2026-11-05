"""SQLite event store: one row per scan verdict.

Concurrency model (log 14 §4):
  * the daemon has exactly ONE writer thread (its dispatcher), so writes never contend;
  * the dashboard (Day 2 · Step 4) opens its own read-only connections;
  * WAL journal mode lets those readers run while the writer commits (in the default rollback
    journal mode, a writer blocks readers during commit).
"""

import json
import sqlite3
import time
from pathlib import Path

from axi import config

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    first_seen    REAL    NOT NULL,   -- unix time of the first filesystem event for this version
    scanned_at    REAL    NOT NULL,   -- unix time the verdict was produced
    detect_ms     REAL    NOT NULL,   -- scanned_at - first_seen (includes debounce + queueing)
    path          TEXT    NOT NULL,
    file_name     TEXT    NOT NULL,
    sha256        TEXT,
    size          INTEGER,
    score         REAL,               -- NULL for not_pe / error
    verdict       TEXT    NOT NULL,   -- pass | sandbox | quarantine | not_pe | error
    error         TEXT,
    stage_ms      TEXT,               -- JSON {read, extract, predict, explain}
    top_features  TEXT,               -- JSON list (only for non-pass verdicts)
    model_sha256  TEXT,               -- which model produced the score (log 11 §3.3)
    action        TEXT,               -- what the system did about it (Day 2 · Step 2: quarantine)
    action_detail TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_scanned_at ON events(scanned_at);
CREATE INDEX IF NOT EXISTS ix_events_verdict    ON events(verdict);
CREATE INDEX IF NOT EXISTS ix_events_sha256     ON events(sha256);
"""


def connect(db_path: Path | str = config.DB_PATH, readonly: bool = False) -> sqlite3.Connection:
    db_path = Path(db_path)
    if readonly:
        # URI mode=ro: the dashboard can never modify the evidence it displays.
        con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=5)
    else:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(db_path, timeout=5)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")  # durable at checkpoints; fine for an event log
        con.executescript(_SCHEMA)
        con.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        con.commit()
    con.row_factory = sqlite3.Row
    return con


def insert_event(con: sqlite3.Connection, *, first_seen: float, path: str, result: dict,
                 model_sha256: str | None, action: str | None = None,
                 action_detail: str | None = None) -> int:
    """`result` is `dataclasses.asdict(ScanResult)` as returned by a worker process."""
    now = time.time()
    cur = con.execute(
        """INSERT INTO events (first_seen, scanned_at, detect_ms, path, file_name, sha256, size,
                               score, verdict, error, stage_ms, top_features, model_sha256,
                               action, action_detail)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (first_seen, now, (now - first_seen) * 1e3, path, Path(path).name,
         result.get("sha256") or None, result.get("size"), result.get("score"),
         result["verdict"], result.get("error") or None,
         json.dumps(result.get("ms") or {}), json.dumps(result.get("top") or [], ensure_ascii=False),
         model_sha256, action, action_detail),
    )
    con.commit()
    return cur.lastrowid


def recent_events(con: sqlite3.Connection, limit: int = 100) -> list[sqlite3.Row]:
    return con.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
