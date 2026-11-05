"""DRAFT, not imported anywhere. Reconstruction of the interrupted axi/sandbox.py (log 16).

Everything above the "--- not written ---" marker is what had been written when the response was
stopped. Everything below it is the planned structure, as comments only.

Stage-2 dynamic analysis: run a Linux ELF in a hardened, throwaway container under strace,
then turn the syscall trace into a behaviour summary and a rule-based verdict.

    python -m axi.sandbox build                     # build the image (samples compiled inside)
    python -m axi.sandbox samples                   # list built-in simulated samples
    python -m axi.sandbox run ransom_sim            # run a built-in sample
    python -m axi.sandbox run path/to/elf [--trace] # run a host file (copied in read-only)
    python -m axi.sandbox export all samples/bin    # copy the compiled samples out (for the daemon demo)

Why Linux ELF only: the container shares the Linux kernel of Docker Desktop's WSL 2 VM, so it
can't execute Windows PE files. PE dynamic analysis needs a Windows VM (or Wine, which the guide
mentions but is out of scope). See log 16 §1.
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
RUN_TIMEOUT_S = 15          # inside the container (busybox timeout)
HOST_TIMEOUT_S = 40         # docker startup + the above; then the host kills the container
# MAX_TRACE_L...            # <- the write was cut off here (intended: MAX_TRACE_LINES, a cap on
#                           #    how many strace lines are parsed, so a noisy sample can't blow up memory)

# ------------------------------------------------------------------ not written
#
# 1. Image management
#    - build(): `docker build -t IMAGE -f DOCKERFILE SAMPLES_SRC`
#    - samples(): list the sample names (the *.c stems in SAMPLES_SRC)
#    - export(): docker create + docker cp + docker rm, to copy compiled samples to the host
#
# 2. Runner: CRITICAL, left as a description only
#    - Builds the `docker run` argument list with the hardening flags already verified by hand
#      in this step (no network, read-only rootfs, noexec tmpfs work dir, all capabilities
#      dropped, no-new-privileges, pids/memory/cpu limits, non-root user, unique container name).
#    - Host files: copy to a fresh temp dir first (snapshot), bind-mount that dir read-only.
#    - Wraps the target in strace (follow forks, quiet, signals off, process/file/network
#      syscall classes) and writes the trace to a separate fd, so the sample's own output can't
#      mix into it. Exit code and timeout are reported via a marker line.
#    - Host-side timeout: on expiry, kill the container by name; always clean up the temp dir.
#
# 3. strace parser: CRITICAL, left as a description only
#    - Line format seen in the manual test:
#        <pid>  <syscall>(<args>) = <ret> [<ERRNO> (<message>)]
#    - Must also join "<unfinished ...>" / "<... X resumed>" pairs that -f produces when two
#      processes interleave.
#    - Output: a list of (pid, syscall, args, ret, errno) records.
#
# 4. Behaviour summary + rules: CRITICAL, left as a description only
#    - Aggregates: syscall counts, files created/deleted/renamed, exec attempts, network
#      attempts (address, result), sensitive paths touched, denied operations, fork successes and
#      failures.
#    - Explainable rules, each with a weight and a Korean label for the UI, e.g. many renames
#      to a new extension, writes to autostart locations, outbound connect attempts, executing a
#      file created during the run, hitting the pids limit, reading credential files, enumerating
#      /proc. The weights sum to a 0-100 risk score, which maps to pass / sandbox / quarantine.
#    - The benign samples must score 0 (regression check).
#
# 5. CLI (Korean output): build | samples | run <name-or-path> [--trace] | export
#
# 6. Daemon integration (planned): ELF files (magic 7F 45 4C 46) go to a single sandbox worker
#    thread; PE files with a sandbox verdict get action "sandbox_unsupported" (needs a Windows VM).
#    Events get `stage` (static/dynamic) and `behavior` (JSON) columns; schema v3.
