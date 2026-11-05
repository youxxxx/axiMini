"""Quarantine vault: take a file away from where it can run, keep it recoverable, log everything.

    python -m axi.quarantine list
    python -m axi.quarantine show    <sha256-prefix>
    python -m axi.quarantine restore <sha256-prefix> [--to PATH] [--no-allow]
    python -m axi.quarantine delete  <sha256-prefix>          # permanent
    python -m axi.quarantine allow   <sha256> [--reason TEXT]

Vault layout (config.QUARANTINE_DIR):
    <sha256>.qbin   MAGIC(8) | key(32) | data XOR key   read-only; not runnable, not a PE anymore
    <sha256>.json   sidecar: every original location, scan score, model, timestamps, status

Moving a file into quarantine (log 15 §2):
    1. rename original -> "<name>.<rand>.axiq-tmp" in the SAME directory (atomic; fails if locked)
    2. read + sha256 the renamed file; if it isn't what we scanned, put it back and stop
    3. write the encoded blob to a temp file in the vault, fsync, os.replace (atomic publish)
    4. write the sidecar (atomic), then delete the renamed original
Every step either completes or leaves the file in a recoverable place: never "deleted but not
saved", never "saved but the path now points at something we didn't scan".
"""

import argparse
import hashlib
import json
import os
import secrets
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from axi import config, store

MAGIC = b"AXIQ\x00\x01\x00\x00"
KEY_LEN = 32
TMP_SUFFIX = ".axiq-tmp"     # the daemon ignores this suffix (it's our own intermediate)


@dataclass
class QResult:
    status: str     # quarantined | already_quarantined | changed | locked | missing | copied_not_removed
    detail: str = ""
    sha256: str = ""


# ---------------------------------------------------------------- encoding
def _xor(data: bytes, key: bytes) -> bytes:
    """Repeating-key XOR, vectorized: O(n) in numpy instead of a Python loop per byte."""
    a = np.frombuffer(data, dtype=np.uint8)
    k = np.frombuffer(key, dtype=np.uint8)
    return (a ^ np.resize(k, a.size)).tobytes()


def encode(data: bytes) -> bytes:
    """Neutralize, don't protect: XOR isn't encryption, it just makes sure the stored bytes are
    no longer a runnable PE, an AV won't keep re-detecting them, and a double-click does nothing."""
    key = secrets.token_bytes(KEY_LEN)
    return MAGIC + key + _xor(data, key)


def decode(blob: bytes) -> bytes:
    if blob[:len(MAGIC)] != MAGIC:
        raise ValueError("not an axiMini quarantine blob")
    key = blob[len(MAGIC):len(MAGIC) + KEY_LEN]
    return _xor(blob[len(MAGIC) + KEY_LEN:], key)


# ---------------------------------------------------------------- atomic file helpers
def _atomic_write(path: Path, data: bytes, readonly: bool = False) -> None:
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(4)}.tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())   # data on disk BEFORE the rename makes it visible
    if path.exists():
        os.chmod(path, stat.S_IWRITE)   # Windows refuses to replace a read-only file
    os.replace(tmp, path)
    if readonly:
        os.chmod(path, stat.S_IREAD)


def _paths(sha: str, vault: Path) -> tuple[Path, Path]:
    return vault / f"{sha}.qbin", vault / f"{sha}.json"


def _load_meta(meta_path: Path) -> dict:
    return json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}


def _save_meta(meta_path: Path, meta: dict) -> None:
    _atomic_write(meta_path, json.dumps(meta, indent=2, ensure_ascii=False).encode("utf-8"))


# ---------------------------------------------------------------- quarantine
def quarantine_file(path: str | Path, expected_sha256: str | None, info: dict,
                    vault: Path = config.QUARANTINE_DIR) -> QResult:
    """Move `path` into the vault. `info` (score, event_id, model_sha256, ...) goes to the sidecar."""
    path = Path(path)
    vault.mkdir(parents=True, exist_ok=True)
    held = path.with_name(f"{path.name}.{secrets.token_hex(4)}{TMP_SUFFIX}")
    try:
        st = os.stat(path)
        os.rename(path, held)        # step 1: atomic; from now on nobody can run it by its name
    except FileNotFoundError:
        return QResult("missing", "파일이 이미 없음")
    except PermissionError as e:
        # typically the file is open / running. A real EDR would now kill the process (guide ch.13);
        # out of scope for the lite version.
        return QResult("locked", f"사용 중이라 이동 불가: {e.strerror}")

    data = held.read_bytes()        # step 2: hash exactly the bytes we're about to keep
    sha = hashlib.sha256(data).hexdigest()
    if expected_sha256 and sha != expected_sha256:
        # The file changed after it was scanned: our verdict is about other bytes. Put it back
        # (only if nothing new took its name) and let the daemon rescan the new content.
        try:
            if not path.exists():
                os.rename(held, path)
        except OSError:
            pass
        return QResult("changed", "검사 후 파일 내용이 바뀜 (재검사 필요)", sha)

    blob_path, meta_path = _paths(sha, vault)
    already = blob_path.exists()
    if not already:
        _atomic_write(blob_path, encode(data), readonly=True)          # step 3
    meta = _load_meta(meta_path) or {"sha256": sha, "size": len(data), "status": "quarantined",
                                     "origins": []}
    meta["status"] = "quarantined"
    meta["origins"].append({"path": str(path), "quarantined_at": time.time(),
                            "mtime": st.st_mtime, **info})
    _save_meta(meta_path, meta)                                          # step 4
    for attempt in range(5):
        try:
            os.remove(held)
            break
        except PermissionError:
            time.sleep(0.2 * (attempt + 1))
    else:
        return QResult("copied_not_removed",
                       f"격리 사본은 저장했지만 원본 삭제 실패 (이름 변경된 채 남음: {held.name})", sha)
    return QResult("already_quarantined" if already else "quarantined", str(blob_path), sha)


# ---------------------------------------------------------------- vault operations
def _resolve(prefix: str, vault: Path) -> str:
    matches = [p.stem for p in vault.glob(f"{prefix.lower()}*.json")]
    if len(matches) != 1:
        raise SystemExit(f"[!] '{prefix}'에 해당하는 격리 항목이 {len(matches)}개입니다 (정확히 1개여야 함)")
    return matches[0]


def list_items(vault: Path = config.QUARANTINE_DIR) -> list[dict]:
    if not vault.exists():
        return []
    return sorted((_load_meta(p) for p in vault.glob("*.json")),
                  key=lambda m: -m["origins"][-1]["quarantined_at"])


def restore(sha: str, con, to: Path | None = None, allow: bool = True,
            vault: Path = config.QUARANTINE_DIR) -> Path:
    """Decode back to the original (or `to`) path. Allowlists FIRST, then writes the file.

    Order matters: the restore target is usually inside the watched folder. If the file appeared
    before the hash was allowlisted, the daemon would rescan it and quarantine it again.
    """
    blob_path, meta_path = _paths(sha, vault)
    meta = _load_meta(meta_path)
    if meta.get("status") != "quarantined" or not blob_path.exists():
        raise SystemExit(f"[!] 복원할 수 없음: 상태 '{meta.get('status')}'")
    data = decode(blob_path.read_bytes())
    if hashlib.sha256(data).hexdigest() != sha:
        raise SystemExit("[!] 격리 파일 무결성 검사 실패 (sha256 불일치). 복원하지 않습니다.")
    target = Path(to) if to else Path(meta["origins"][-1]["path"])
    if target.exists():
        raise SystemExit(f"[!] 대상 경로에 이미 파일이 있음: {target}")
    if allow:
        store.allow(con, sha, f"격리 복원 (오탐 판정) -> {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(target, data)
    meta["status"], meta["restored_at"], meta["restored_to"] = "restored", time.time(), str(target)
    _save_meta(meta_path, meta)
    os.chmod(blob_path, stat.S_IWRITE)
    os.remove(blob_path)
    store.log_action(con, "restore", sha, str(target))
    return target


def purge(sha: str, con, vault: Path = config.QUARANTINE_DIR) -> None:
    blob_path, meta_path = _paths(sha, vault)
    if blob_path.exists():
        os.chmod(blob_path, stat.S_IWRITE)
        os.remove(blob_path)
    meta = _load_meta(meta_path)
    meta["status"], meta["deleted_at"] = "deleted", time.time()
    _save_meta(meta_path, meta)          # the sidecar stays as the audit record
    store.log_action(con, "delete", sha)


# ---------------------------------------------------------------- CLI (Korean output)
STATUS_KO = {"quarantined": "격리 중", "restored": "복원됨", "deleted": "영구 삭제됨"}


def _fmt_time(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="axiMini 격리소 관리")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="격리 항목 목록")
    p = sub.add_parser("show", help="격리 항목 상세")
    p.add_argument("sha")
    p = sub.add_parser("restore", help="격리 해제 (기본: 허용 목록에 추가)")
    p.add_argument("sha")
    p.add_argument("--to", type=Path, help="원래 위치 대신 복원할 경로")
    p.add_argument("--no-allow", action="store_true", help="허용 목록에 추가하지 않음 (재격리될 수 있음)")
    p = sub.add_parser("delete", help="격리 파일 영구 삭제")
    p.add_argument("sha")
    p = sub.add_parser("allow", help="해시를 허용 목록에 추가")
    p.add_argument("sha")
    p.add_argument("--reason", default="수동 허용")
    a = ap.parse_args()
    vault = config.QUARANTINE_DIR

    if a.cmd == "list":
        items = list_items(vault)
        if not items:
            print("격리 항목 없음")
        for m in items:
            o = m["origins"][-1]
            score = f"{o['score']:.6f}" if o.get("score") is not None else "-"
            print(f"{m['sha256'][:12]}  {STATUS_KO.get(m['status'], m['status']):<6}  "
                  f"{_fmt_time(o['quarantined_at'])}  점수 {score}  {m['size']:>10,} B  {o['path']}")
        return
    con = store.connect()
    if a.cmd == "allow":
        store.allow(con, a.sha.lower(), a.reason)
        print(f"허용 목록에 추가됨: {a.sha.lower()}")
        return
    sha = _resolve(a.sha, vault)
    if a.cmd == "show":
        print(json.dumps(_load_meta(_paths(sha, vault)[1]), indent=2, ensure_ascii=False))
    elif a.cmd == "restore":
        target = restore(sha, con, a.to, allow=not a.no_allow, vault=vault)
        print(f"복원 완료: {target}" + ("" if a.no_allow else "  (허용 목록에 추가됨)"))
    elif a.cmd == "delete":
        purge(sha, con, vault)
        print(f"영구 삭제 완료: {sha}")


if __name__ == "__main__":
    main()
