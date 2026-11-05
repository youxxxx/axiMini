"""End-to-end: real watchdog observer + stabilizer + worker process + SQLite, on a temp folder."""

import os
import shutil
import threading
import time
from pathlib import Path

import pytest

from axi import daemon, store

PE_SRC = Path(r"C:\Windows\SysWOW64\notepad.exe")


def _wait_for(pred, timeout=30.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.1)
    return False


@pytest.fixture
def running_daemon(tmp_path):
    watch, db = tmp_path / "watched", tmp_path / "events.db"
    watch.mkdir()
    (watch / "preexisting.txt").write_text("arrived while the daemon was down")
    stop = threading.Event()
    t = threading.Thread(target=daemon.run, args=(watch, 1, True, db, stop), daemon=True)
    t.start()
    assert _wait_for(lambda: db.exists() and _rows(db), 60), "daemon did not start / initial scan"
    yield watch, db
    stop.set()
    t.join(30)


def _rows(db):
    con = store.connect(db, readonly=True)
    try:
        return {r["file_name"]: dict(r) for r in store.recent_events(con, 1000)}
    finally:
        con.close()


def test_pipeline(running_daemon):
    watch, db = running_daemon
    assert _rows(db)["preexisting.txt"]["verdict"] == "not_pe"            # initial scan

    # 1) plain copy of a benign PE under a misleading extension: routed by content, not name
    shutil.copy(PE_SRC, watch / "update.bin")
    # 2) browser-style download: write *.crdownload, then rename to the final name
    part = watch / "setup.exe.crdownload"
    shutil.copy(PE_SRC, part)
    os.replace(part, watch / "setup.exe")
    # 3) slow writer: chunks with pauses shorter than the debounce window
    data = PE_SRC.read_bytes()
    with open(watch / "slow.exe", "wb") as f:
        for i in range(0, len(data), len(data) // 5 + 1):
            f.write(data[i:i + len(data) // 5 + 1])
            f.flush()
            time.sleep(0.3)
    # 4) created and deleted before it stabilizes -> no event row
    (watch / "gone.exe").write_bytes(b"MZ" + b"\0" * 100)
    (watch / "gone.exe").unlink()

    names = {"update.bin", "setup.exe", "slow.exe"}
    assert _wait_for(lambda: names <= set(_rows(db)), 60), _rows(db).keys()
    rows = _rows(db)
    for n in names:
        r = rows[n]
        assert r["verdict"] == "pass" and r["size"] == len(data), r
        assert r["model_sha256"] and r["detect_ms"] >= daemon.DEBOUNCE_S * 1e3
    assert "setup.exe.crdownload" not in rows and "gone.exe" not in rows

    # 5) an event that doesn't change content (re-open + close) must not produce a new row
    n_before = len(store.recent_events(store.connect(db, readonly=True), 1000))
    os.utime(watch / "update.bin", ns=(time.time_ns(), os.stat(watch / "update.bin").st_mtime_ns))
    time.sleep(2)
    assert len(store.recent_events(store.connect(db, readonly=True), 1000)) == n_before
