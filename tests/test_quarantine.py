"""Quarantine vault: atomic move, integrity, locking, dedup, restore + allowlist, daemon handler."""

import hashlib
import os
import shutil
import stat
from pathlib import Path

import pytest

from axi import daemon, quarantine, store

PE_SRC = Path(r"C:\Windows\SysWOW64\notepad.exe")


@pytest.fixture
def env(tmp_path):
    watch, vault = tmp_path / "watched", tmp_path / "vault"
    watch.mkdir()
    con = store.connect(tmp_path / "events.db")
    yield watch, vault, con
    con.close()
    for p in vault.glob("*") if vault.exists() else []:
        os.chmod(p, stat.S_IWRITE)   # let pytest clean up read-only blobs


def _drop(watch: Path, name: str = "evil.exe") -> tuple[Path, str]:
    p = watch / name
    shutil.copy(PE_SRC, p)
    return p, hashlib.sha256(p.read_bytes()).hexdigest()


def test_encode_roundtrip_and_neutralized():
    data = PE_SRC.read_bytes()
    blob = quarantine.encode(data)
    assert quarantine.decode(blob) == data
    assert blob[:2] != b"MZ" and data[:200] not in blob   # no longer a PE, no plain-text copy
    assert quarantine.encode(data) != blob                # fresh random key every time


def test_quarantine_moves_and_records(env):
    watch, vault, _ = env
    p, sha = _drop(watch)
    q = quarantine.quarantine_file(p, sha, {"score": 0.9999, "event_id": 1}, vault=vault)
    assert q.status == "quarantined" and q.sha256 == sha
    assert not p.exists() and not list(watch.iterdir())           # no leftover .axiq-tmp
    blob, meta = vault / f"{sha}.qbin", vault / f"{sha}.json"
    assert not os.access(blob, os.W_OK)                           # read-only
    assert quarantine.decode(blob.read_bytes()) == PE_SRC.read_bytes()
    m = quarantine._load_meta(meta)
    assert m["status"] == "quarantined" and m["origins"][0]["path"] == str(p)


def test_changed_after_scan_is_put_back(env):
    watch, vault, _ = env
    p, _ = _drop(watch)
    q = quarantine.quarantine_file(p, "0" * 64, {}, vault=vault)
    assert q.status == "changed" and p.exists()                   # untouched, back under its name
    assert not vault.exists() or not list(vault.glob("*.qbin"))


def test_locked_file_is_not_touched(env):
    watch, vault, _ = env
    p, sha = _drop(watch)
    with open(p, "rb"):   # CPython opens without FILE_SHARE_DELETE -> rename is refused on Windows
        q = quarantine.quarantine_file(p, sha, {}, vault=vault)
    assert q.status == "locked" and p.exists()


def test_duplicate_content_shares_one_blob(env):
    watch, vault, _ = env
    p1, sha = _drop(watch, "a.exe")
    p2, _ = _drop(watch, "b.exe")
    assert quarantine.quarantine_file(p1, sha, {}, vault=vault).status == "quarantined"
    assert quarantine.quarantine_file(p2, sha, {}, vault=vault).status == "already_quarantined"
    assert len(list(vault.glob("*.qbin"))) == 1
    assert len(quarantine._load_meta(vault / f"{sha}.json")["origins"]) == 2


def test_restore_allowlists_first_and_verifies(env):
    watch, vault, con = env
    p, sha = _drop(watch)
    quarantine.quarantine_file(p, sha, {}, vault=vault)
    target = quarantine.restore(sha, con, vault=vault)
    assert target == p and hashlib.sha256(p.read_bytes()).hexdigest() == sha
    assert store.is_allowed(con, sha)
    assert not (vault / f"{sha}.qbin").exists()
    assert quarantine._load_meta(vault / f"{sha}.json")["status"] == "restored"
    with pytest.raises(SystemExit):
        quarantine.restore(sha, con, vault=vault)                 # already restored
    acts = [r["action"] for r in con.execute("SELECT action FROM actions ORDER BY id")]
    assert acts == ["allowlist", "restore"]


def test_restore_refuses_to_overwrite(env):
    watch, vault, con = env
    p, sha = _drop(watch)
    quarantine.quarantine_file(p, sha, {}, vault=vault)
    p.write_bytes(b"something else now lives here")
    with pytest.raises(SystemExit):
        quarantine.restore(sha, con, vault=vault)


def test_daemon_handler_quarantines_then_respects_allowlist(env):
    watch, vault, con = env
    p, sha = _drop(watch)
    st = os.stat(p)
    job = daemon.Job(str(p), 0.0, st.st_size, st.st_mtime_ns)
    res = {"path": str(p), "sha256": sha, "size": st.st_size, "score": 0.99995,
           "verdict": "quarantine", "ms": {}, "top": []}
    row = daemon.handle_result(con, job, res, "m" * 64, vault, {})
    ev = con.execute("SELECT action FROM events WHERE id=?", (row,)).fetchone()
    assert ev["action"] == "quarantined" and not p.exists()

    quarantine.restore(sha, con, vault=vault)                     # analyst: false positive
    row = daemon.handle_result(con, job, res, "m" * 64, vault, {})
    ev = con.execute("SELECT action FROM events WHERE id=?", (row,)).fetchone()
    assert ev["action"] == "allowlisted" and p.exists()            # not re-quarantined
