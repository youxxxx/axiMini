"""Stage-2 dynamic analysis: run an ELF binary in a hardened throwaway container under strace,
then summarize what the container's defensive layers observed and blocked.

    python -m axi.sandbox build                     # build the image (samples compiled inside)
    python -m axi.sandbox samples                   # list samples bundled in the image
    python -m axi.sandbox run <elf-path>            # run a host ELF
    python -m axi.sandbox run-sample <name>         # run one of the bundled samples

Design notes (log 17):
  * The score reflects **how much of the container's defensive surface the binary touched**
    (network denied, exec denied, read-only filesystem denied, capability denied, pids cap hit,
    unusual file I/O volume), not a match against malware signatures. A binary that avoids every
    barrier scores 0; one that repeatedly tries forbidden operations scores higher regardless of
    its exact technique. This keeps the rules short and easy to audit.
  * Only Linux ELF files run here. The container shares the kernel of Docker Desktop's WSL 2
    VM, so a Windows PE cannot execute. Dynamic PE analysis would need a Windows VM; marked as
    "sandbox_unsupported" by the daemon integration (future).
"""

import argparse
import json
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from axi import config

IMAGE = "axi-sandbox:1"
DOCKERFILE = config.ROOT / "sandbox" / "Dockerfile"
SAMPLES_SRC = config.ROOT / "samples" / "simulated"
RUN_TIMEOUT_S = 10          # inside-container wall clock
HOST_TIMEOUT_S = 30         # docker startup + the above; after this the host kills the container
MAX_TRACE_LINES = 50_000    # cap parser memory on a noisy binary


# ---------------------------------------------------------------- data types
@dataclass
class Behavior:
    """What the trace shows the binary did; what the container's barriers blocked."""
    syscalls: Counter = field(default_factory=Counter)
    errno_counts: Counter = field(default_factory=Counter)
    files_written: list[str] = field(default_factory=list)
    files_read: list[str] = field(default_factory=list)
    files_deleted: list[str] = field(default_factory=list)
    network_attempts: int = 0       # connect/sendto that succeeded at the syscall level
    exec_denied: int = 0            # execve/execveat -> EACCES (noexec mount)
    rofs_denied: int = 0            # -> EROFS (rootfs read-only)
    net_denied: int = 0             # connect/sendto -> ENETUNREACH (network none)
    eperm_denied: int = 0           # -> EPERM (capability we dropped)
    forks: int = 0
    fork_eagain: int = 0            # clone/fork/vfork -> EAGAIN (pids-limit hit)
    duration_s: float = 0.0
    timed_out: bool = False
    exit_code: int | None = None
    truncated: bool = False
    trace_lines: int = 0


@dataclass
class SandboxResult:
    behavior: Behavior
    score: int                       # 0..100: how much of the defensive surface was hit
    verdict: str                     # pass_dynamic | sandbox_dynamic | malicious_dynamic
    rules: list[dict]                # fired rules, each with a Korean label and weight
    sample: str = ""


VERDICT_KO = {
    "pass_dynamic": "동적 검사 통과",
    "sandbox_dynamic": "의심 (추가 검토 필요)",
    "malicious_dynamic": "악성 동작 확인됨",
}


# ---------------------------------------------------------------- image management
def image_exists() -> bool:
    return subprocess.run(["docker", "image", "inspect", IMAGE],
                          capture_output=True).returncode == 0


def build() -> None:
    if not DOCKERFILE.exists():
        raise SystemExit(f"Dockerfile가 없음: {DOCKERFILE}")
    subprocess.run(
        ["docker", "build", "-t", IMAGE, "-f", str(DOCKERFILE), str(SAMPLES_SRC)],
        check=True,
    )


def list_samples() -> list[str]:
    """Names of sample binaries baked into the image (derived from the source C files)."""
    return sorted(p.stem for p in SAMPLES_SRC.glob("*.c"))


# ---------------------------------------------------------------- runner
def _docker_args(container_name: str, host_mount: Path | None) -> list[str]:
    """Hardening flags in one list so they can be audited as data.

    Each line below is a defensive layer; the scoring rules key off the kernel error each one
    produces when a binary fights it. Removing any flag weakens the sandbox silently.
    """
    args = [
        "docker", "run", "--rm", "--name", container_name,
        "--network", "none",                           # connect/sendto -> ENETUNREACH
        "--read-only",                                 # writes to / -> EROFS
        "--tmpfs", "/work:rw,noexec,nosuid,nodev,size=16m,mode=1777",   # /work writable but not execable
        "--cap-drop", "ALL",                           # capability-gated calls -> EPERM
        "--security-opt", "no-new-privileges",         # setuid cannot raise privileges
        "--pids-limit", "32",                          # fork past limit -> EAGAIN
        "--memory", "128m", "--memory-swap", "128m",
        "--cpus", "0.5",
        "--user", "10001:10001",                       # non-root
    ]
    if host_mount is not None:
        # /input is read-only; the sample can be executed from here (host mount defaults to exec).
        args += ["-v", f"{host_mount.as_posix()}:/input:ro"]
    args.append(IMAGE)
    return args


def _strace_cmd(target: str) -> list[str]:
    """Wrap the target in strace, writing the trace to fd 3 (= stderr of docker run).

    The sample's own stdout and stderr go to /dev/null, so they can't interleave with the trace.
    The "__EXIT=N" marker at the end lets us read the target's exit code from the same stream.
    """
    # -f follow forks; -qq no attach banners; -s 96 cap string arg length;
    # -e signal=none drop signal lines; -e trace=... only process/file/network syscall classes.
    return [
        "sh", "-c",
        f"strace -f -qq -e signal=none -e trace=%process,%file,%network "
        f"-s 96 -o /proc/self/fd/3 {target} 3>&2 >/dev/null 2>&1; "
        f'echo "__EXIT=$?" >&2'
    ]


def run_elf(path: Path, timeout: float = HOST_TIMEOUT_S) -> SandboxResult:
    """Run a host ELF in a fresh container; return parsed behaviour + score + rules."""
    if not image_exists():
        raise SystemExit(f"이미지 '{IMAGE}' 없음. 먼저 실행: python -m axi.sandbox build")
    if not path.is_file():
        raise SystemExit(f"파일 없음: {path}")

    container_name = f"axi-sb-{int(time.time())}-{secrets.token_hex(4)}"
    with tempfile.TemporaryDirectory() as tmp_s:
        tmp = Path(tmp_s)
        # Snapshot the file first: the sample can only ever execute what we captured here,
        # not a replacement that lands at `path` after we checked it.
        target = tmp / path.name
        shutil.copy(path, target)
        target.chmod(0o755)

        args = _docker_args(container_name, host_mount=tmp) + _strace_cmd(f"/input/{path.name}")
        t0 = time.perf_counter()
        try:
            proc = subprocess.run(args, capture_output=True, timeout=timeout)
            stderr = proc.stderr or b""
            timed_out = False
        except subprocess.TimeoutExpired as e:
            # Host-side kill; --rm then removes the container on exit.
            subprocess.run(["docker", "kill", container_name], capture_output=True)
            stderr = e.stderr or b""
            timed_out = True
        duration = time.perf_counter() - t0

    return _build_result(stderr.decode("utf-8", errors="replace"), duration, timed_out)


def _build_result(trace_text: str, duration: float, timed_out: bool) -> SandboxResult:
    behavior = parse_trace(trace_text, max_lines=MAX_TRACE_LINES)
    behavior.duration_s = round(duration, 3)
    behavior.timed_out = timed_out
    m = re.search(r"__EXIT=(-?\d+)", trace_text)
    if m:
        behavior.exit_code = int(m.group(1))
    rules = apply_rules(behavior)
    score = min(100, sum(r["weight"] for r in rules))
    if score >= 70:
        verdict = "malicious_dynamic"
    elif score >= 30:
        verdict = "sandbox_dynamic"
    else:
        verdict = "pass_dynamic"
    return SandboxResult(behavior=behavior, score=score, verdict=verdict, rules=rules)


# ---------------------------------------------------------------- strace parser
# Normal strace -f line (pid + syscall + args + return value, optional errno):
#     10    connect(4, {...}) = -1 ENETUNREACH (Network unreachable)
_LINE = re.compile(
    r"^(?P<pid>\d+)\s+"
    r"(?P<syscall>\w+)\((?P<args>.*)\)\s*=\s*"
    r"(?P<ret>-?[\w?]+)"
    r"(?:\s+(?P<errno>E[A-Z0-9_]+)\b[^\n]*)?\s*$"
)
# With -f, two PIDs can interleave and strace splits the call into
#     <pid> <sys>(<args> <unfinished ...>     and     <pid> <... <sys> resumed> <rest> ) = <ret> ...
_UNFINISHED = re.compile(r"^(?P<pid>\d+)\s+(?P<syscall>\w+)\((?P<args>.*)\s+<unfinished \.\.\.>\s*$")
_RESUMED = re.compile(r"^(?P<pid>\d+)\s+<\.\.\.\s+\w+ resumed>\s*(?P<rest>.*)$")


def _join_unfinished(text: str, max_lines: int) -> tuple[list[str], bool]:
    """Pair <unfinished ...> with its matching <... resumed>. Return (joined lines, truncated?)."""
    pending: dict[str, str] = {}
    out: list[str] = []
    truncated = False
    for i, line in enumerate(text.splitlines()):
        if i >= max_lines:
            truncated = True
            break
        m = _UNFINISHED.match(line)
        if m:
            pending[m.group("pid")] = f'{m.group("pid")} {m.group("syscall")}({m.group("args")}'
            continue
        m = _RESUMED.match(line)
        if m:
            started = pending.pop(m.group("pid"), None)
            if started is not None:
                out.append(started + m.group("rest"))
            continue
        out.append(line)
    return out, truncated


def _first_quoted(args: str) -> str | None:
    m = re.search(r'"([^"]*)"', args)
    return m.group(1) if m else None


def parse_trace(text: str, max_lines: int = MAX_TRACE_LINES) -> Behavior:
    b = Behavior()
    lines, b.truncated = _join_unfinished(text, max_lines)
    b.trace_lines = len(lines)
    for line in lines:
        m = _LINE.match(line)
        if not m:
            continue
        syscall = m.group("syscall")
        args = m.group("args")
        ret = m.group("ret")
        errno = m.group("errno")
        b.syscalls[syscall] += 1
        if errno:
            b.errno_counts[errno] += 1

        # Route each syscall to the right counter. Only errno-driven counters increment on
        # failure (the "sandbox blocked it" signal); file/network counters increment on success.
        if errno == "ENETUNREACH":
            b.net_denied += 1
        elif errno == "EROFS":
            b.rofs_denied += 1
        elif errno == "EACCES" and syscall in ("execve", "execveat"):
            b.exec_denied += 1
        elif errno == "EPERM":
            b.eperm_denied += 1
        elif errno == "EAGAIN" and syscall in ("clone", "fork", "vfork", "clone3"):
            b.fork_eagain += 1

        if not errno:
            if syscall in ("connect", "sendto"):
                b.network_attempts += 1
            elif syscall in ("openat", "open"):
                path = _first_quoted(args)
                if path:
                    if any(flag in args for flag in ("O_WRONLY", "O_RDWR", "O_CREAT")):
                        b.files_written.append(path)
                    else:
                        b.files_read.append(path)
            elif syscall in ("unlink", "unlinkat"):
                path = _first_quoted(args)
                if path:
                    b.files_deleted.append(path)
            elif syscall in ("clone", "fork", "vfork", "clone3") and ret != "-1":
                b.forks += 1

    # First-touch order, dedup; large volumes get summarized by the rules below.
    b.files_written = list(dict.fromkeys(b.files_written))
    b.files_read = list(dict.fromkeys(b.files_read))
    b.files_deleted = list(dict.fromkeys(b.files_deleted))
    return b


# ---------------------------------------------------------------- rules
# Each rule = (name, predicate on Behavior, weight, Korean label).
# The weights are intentionally conservative: hitting one barrier is suspicious, hitting several
# is strong evidence. A benign file-I/O program should fire nothing and score 0.
RULES = [
    ("net_denied",   lambda b: b.net_denied > 0,              25, "격리된 네트워크로 연결 시도"),
    ("exec_denied",  lambda b: b.exec_denied > 0,             25, "실행 금지 영역에서 실행 시도"),
    ("rofs_denied",  lambda b: b.rofs_denied > 0,             20, "읽기 전용 영역에 쓰기 시도"),
    ("eperm_denied", lambda b: b.eperm_denied > 0,            10, "권한이 필요한 작업 시도"),
    ("fork_eagain",  lambda b: b.fork_eagain > 0,             10, "프로세스 수 한계 도달"),
    ("mass_write",   lambda b: len(b.files_written) > 15,     15, "다량 파일 쓰기"),
    ("mass_delete",  lambda b: len(b.files_deleted) > 10,     20, "다량 파일 삭제"),
    ("timed_out",    lambda b: b.timed_out,                   10, "시간 초과로 강제 종료"),
]


def apply_rules(b: Behavior) -> list[dict]:
    fired = []
    for name, check, weight, label_ko in RULES:
        value = check(b)
        if value:
            fired.append({"name": name, "weight": weight, "label": label_ko,
                          "value": int(value) if isinstance(value, bool) else int(value)})
    return fired


# ---------------------------------------------------------------- CLI
def _print_result(r: SandboxResult) -> None:
    b = r.behavior
    tag = f" ({r.sample})" if r.sample else ""
    print(f"\n=== 동적 분석 결과{tag}")
    print(f"  판정: {VERDICT_KO[r.verdict]}  (점수 {r.score}/100)")
    tmsg = "  ⏱  제한 시간 도달" if b.timed_out else ""
    print(f"  실행 시간: {b.duration_s}s  종료 코드: {b.exit_code}{tmsg}")
    top = ", ".join(f"{k}={v}" for k, v in b.syscalls.most_common(5))
    print(f"  syscall {sum(b.syscalls.values())}회  (상위: {top})")
    print(f"  파일: 쓰기 {len(b.files_written)} / 읽기 {len(b.files_read)} / 삭제 {len(b.files_deleted)}, "
          f"네트워크 시도: {b.network_attempts}")
    if b.errno_counts:
        em = ", ".join(f"{k}={v}" for k, v in b.errno_counts.most_common())
        print(f"  거부된 syscall: {em}")
    if b.truncated:
        print(f"  ⚠️  trace가 {MAX_TRACE_LINES:,}줄에서 잘림")
    if r.rules:
        print("  발동 규칙:")
        for rule in r.rules:
            print(f"    +{rule['weight']:>3}  {rule['label']}")
    else:
        print("  발동 규칙 없음")


def _result_json(r: SandboxResult) -> str:
    d = asdict(r)
    d["behavior"]["syscalls"] = dict(r.behavior.syscalls)
    d["behavior"]["errno_counts"] = dict(r.behavior.errno_counts)
    return json.dumps(d, ensure_ascii=False, indent=2)


def _run_sample(name: str, json_out: bool) -> None:
    """Copy a pre-built sample out of the image into a temp dir, then run it as a host ELF."""
    if name not in list_samples():
        raise SystemExit(f"샘플 없음: {name} (사용 가능: {', '.join(list_samples())})")
    with tempfile.TemporaryDirectory() as tmp_s:
        tmp = Path(tmp_s)
        cid = subprocess.run(
            ["docker", "create", IMAGE, "true"],   # a throwaway container just to copy from
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        try:
            subprocess.run(["docker", "cp", f"{cid}:/samples/{name}", str(tmp / name)],
                           check=True, capture_output=True)
        finally:
            subprocess.run(["docker", "rm", cid], capture_output=True)
        result = run_elf(tmp / name)
    result.sample = name
    print(_result_json(result) if json_out else "", end="")
    if not json_out:
        _print_result(result)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="axiMini 동적 분석 샌드박스")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build", help="샌드박스 이미지 빌드")
    sub.add_parser("samples", help="내장 샘플 목록")
    p = sub.add_parser("run", help="호스트의 ELF 파일을 샌드박스에서 실행")
    p.add_argument("path", type=Path)
    p.add_argument("--json", action="store_true", help="JSON 출력")
    p = sub.add_parser("run-sample", help="내장 샘플 실행")
    p.add_argument("name")
    p.add_argument("--json", action="store_true", help="JSON 출력")
    a = ap.parse_args()

    if a.cmd == "build":
        build()
    elif a.cmd == "samples":
        print("\n".join(list_samples()))
    elif a.cmd == "run":
        result = run_elf(a.path)
        result.sample = a.path.name
        print(_result_json(result)) if a.json else _print_result(result)
    elif a.cmd == "run-sample":
        _run_sample(a.name, a.json)


if __name__ == "__main__":
    main()
