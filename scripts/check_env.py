"""Environment self-check for axiMini.

Run:  .venv\\Scripts\\python.exe scripts\\check_env.py
Prints one line per check and exits non-zero if a required check fails.
"""

import importlib
import platform
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from axi import config  # noqa: E402

GIB = 1024 ** 3
results: list[tuple[str, bool, bool, str]] = []  # (name, ok, required, detail)


def check(name: str, ok: bool, detail: str = "", required: bool = True) -> None:
    results.append((name, ok, required, detail))


# 1. Python version: thrember needs >= 3.10; we standardize on 3.12.
v = sys.version_info
check("python >= 3.10", v >= (3, 10), platform.python_version())
check("running inside .venv", sys.prefix != sys.base_prefix, sys.prefix, required=False)

# 2. Required imports. Day-2 packages are reported but not required yet.
for mod, required in [
    ("thrember", True), ("lightgbm", True), ("pefile", True), ("numpy", True),
    ("sklearn", True), ("psutil", True),
    ("watchdog", False), ("docker", False), ("streamlit", False), ("pandas", False),
]:
    try:
        m = importlib.import_module(mod)
        check(f"import {mod}", True, getattr(m, "__version__", "ok"), required)
    except Exception as e:  # ImportError, or a broken native wheel
        check(f"import {mod}", False, type(e).__name__, required)

# 3. thrember extractor sanity: feature dimension must be 2568 (EMBER feature v3).
try:
    import thrember
    dim = thrember.PEFeatureExtractor().dim
    check("thrember extractor dim == 2568", dim == 2568, str(dim))
except Exception as e:
    check("thrember extractor dim == 2568", False, type(e).__name__)

# 4. Hardware: ~6 GB download + extraction + vectors for the Win32 test subset.
free = shutil.disk_usage(config.ROOT).free / GIB
check("free disk >= 30 GiB", free >= 30, f"{free:.0f} GiB")
try:
    import psutil
    ram = psutil.virtual_memory().total / GIB
    check("RAM >= 8 GiB", ram >= 8, f"{ram:.1f} GiB")
except ImportError:
    pass

# 5. Docker engine (Day 2). `docker info` fails fast if the engine/WSL is down.
docker_exe = shutil.which("docker")
if docker_exe:
    r = subprocess.run([docker_exe, "info", "--format", "{{.ServerVersion}}"],
                       capture_output=True, text=True, timeout=30)
    check("docker engine reachable", r.returncode == 0,
          r.stdout.strip() or r.stderr.strip()[:80], required=False)
else:
    check("docker CLI on PATH", False, "not found (open a new terminal?)", required=False)

width = max(len(n) for n, *_ in results)
for name, ok, required, detail in results:
    tag = "OK  " if ok else ("FAIL" if required else "WARN")
    print(f"[{tag}] {name:<{width}}  {detail}")

sys.exit(0 if all(ok or not req for _, ok, req, _ in results) else 1)
