"""Parser + rules + scoring. End-to-end Docker runs aren't in here (slow, need the image);
`scripts/smoke_sandbox.py` does one with benign_hello."""

from axi import sandbox
from axi.sandbox import Behavior, apply_rules, parse_trace, _build_result


# A realistic benign trace: file write, read-back, delete. No barriers hit.
BENIGN_TRACE = """\
10    execve("/input/hello", ["/input/hello"], 0x7ffd /* 5 vars */) = 0
10    brk(NULL)                        = 0x2000
10    openat(AT_FDCWD, "/work/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3
10    write(3, "hello\\n", 6)          = 6
10    close(3)                         = 0
10    openat(AT_FDCWD, "/work/out.txt", O_RDONLY) = 3
10    read(3, "hello\\n", 1024)        = 6
10    close(3)                         = 0
10    unlink("/work/out.txt")          = 0
10    exit_group(0)                    = ?
__EXIT=0
"""

# A trace that hits every defensive layer once. Expected to trigger several rules.
BARRIERS_TRACE = """\
10    execve("/input/x", ["/input/x"], 0x7ffd /* 5 vars */) = 0
10    socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 4
10    connect(4, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("203.0.113.1")}, 16) = -1 ENETUNREACH (Network unreachable)
10    openat(AT_FDCWD, "/etc/cron.d/x", O_WRONLY|O_CREAT|O_APPEND, 0644) = -1 EROFS (Read-only file system)
10    execve("/work/helper", ["/work/helper"], 0x7ffd) = -1 EACCES (Permission denied)
10    setuid(0)                        = -1 EPERM (Operation not permitted)
10    clone(child_stack=0x7f00, flags=CLONE_VM) = -1 EAGAIN (Resource temporarily unavailable)
10    exit_group(1)                    = ?
__EXIT=1
"""

# Interleaved -f output: two PIDs, one call split across <unfinished>/<resumed>.
INTERLEAVED_TRACE = """\
10    clone(child_stack=0 <unfinished ...>
11    execve("/bin/true", ["/bin/true"], 0x7ffd /* 5 vars */) = 0
10    <... clone resumed>)             = 11
11    exit_group(0)                    = ?
10    wait4(11, [{WIFEXITED(s)}], 0, NULL) = 11
"""


def test_parser_benign():
    b = parse_trace(BENIGN_TRACE)
    assert b.files_written == ["/work/out.txt"] and b.files_read == ["/work/out.txt"]
    assert b.files_deleted == ["/work/out.txt"]
    assert b.net_denied == b.exec_denied == b.rofs_denied == 0
    assert b.network_attempts == 0
    assert b.syscalls["openat"] == 2 and b.syscalls["exit_group"] == 1
    assert not b.errno_counts and not b.truncated


def test_parser_barriers():
    b = parse_trace(BARRIERS_TRACE)
    assert b.net_denied == 1 and b.rofs_denied == 1 and b.exec_denied == 1
    assert b.eperm_denied == 1 and b.fork_eagain == 1
    assert b.errno_counts == {"ENETUNREACH": 1, "EROFS": 1, "EACCES": 1,
                              "EPERM": 1, "EAGAIN": 1}
    # The failed openat must NOT count as a file write.
    assert b.files_written == [] and b.files_read == []


def test_parser_handles_unfinished_resumed():
    b = parse_trace(INTERLEAVED_TRACE)
    # The resumed clone has ret 11 (not -1, no errno): one successful fork.
    assert b.forks == 1 and b.fork_eagain == 0
    assert b.syscalls["clone"] == 1 and b.syscalls["execve"] == 1


def test_parser_truncation():
    noise = "10    getpid()                         = 10\n" * 100
    b = parse_trace(noise, max_lines=10)
    assert b.truncated and b.trace_lines == 10


def test_rules_benign_fires_nothing():
    rules = apply_rules(parse_trace(BENIGN_TRACE))
    assert rules == []


def test_rules_barriers_fire_and_score():
    result = _build_result(BARRIERS_TRACE, duration=0.5, timed_out=False)
    names = {r["name"] for r in result.rules}
    assert {"net_denied", "exec_denied", "rofs_denied", "eperm_denied", "fork_eagain"} <= names
    assert result.score == 25 + 25 + 20 + 10 + 10 == 90  # all five barriers at once
    assert result.verdict == "malicious_dynamic"         # 90 is well above 70
    assert result.behavior.exit_code == 1


def test_mass_write_and_delete_rules():
    b = Behavior()
    b.files_written = [f"/work/f{i}" for i in range(20)]
    b.files_deleted = [f"/work/f{i}" for i in range(15)]
    names = {r["name"] for r in apply_rules(b)}
    assert "mass_write" in names and "mass_delete" in names


def test_verdict_bands():
    assert _build_result("", 0.0, False).verdict == "pass_dynamic"        # nothing
    heavy = BARRIERS_TRACE + "10    openat(AT_FDCWD, \"/etc/shadow\", O_WRONLY) = -1 EROFS (Read-only file system)\n" * 20
    r = _build_result(heavy, 0.0, True)
    assert r.verdict == "malicious_dynamic" and r.score >= 70


def test_hardening_flags_present():
    """Every defensive layer the rules depend on must stay in _docker_args. Change-detector."""
    args = " ".join(sandbox._docker_args("test", host_mount=None))
    for required in ["--network none", "--read-only", "noexec", "--cap-drop ALL",
                     "no-new-privileges", "--pids-limit", "--memory", "--user 10001:10001"]:
        assert required in args, f"{required} missing from docker args"
