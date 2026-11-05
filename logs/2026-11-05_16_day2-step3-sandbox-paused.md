# Log 16: Day 2 · Step 3 (sandbox): partial progress and pause

- **Date:** 2026-11-05
- **Queries:** "go to day 2, step 3"; "show me sandbox.py that you wrote partially in a separate file"; "can you write the whole file if I turn off some Windows defender features?"; a question about whether a reworded "compliance" framing prompt would work.

## Done
- Docker engine verified: 29.9.2, WSL 2 backend. The user's WSL install worked.
- `samples/simulated/*.c`: 8 small C programs, 2 benign and 6 that imitate malware behaviours. They touch only files they create themselves, inside the container.
- `sandbox/Dockerfile`: image `axi-sandbox:1` (16.7 MB). A multi-stage build compiles the samples statically; the runtime holds only strace.
- One manual check: strace works under full hardening (`--network none --read-only`, noexec tmpfs, `--cap-drop ALL`, `no-new-privileges`, pids/memory/cpu limits, non-root user). Outbound connects fail in the kernel with `ENETUNREACH`.

## Not done
The runner, strace parser and behaviour rules (`axi/sandbox.py`) were not written. The response that was writing them was stopped by a safety classifier, and nothing reached disk. `drafts/sandbox_partial.py` holds the reconstructed header, imports and constants, with the remaining sections described only in comments.

## Answers given
- **Disabling Windows Defender doesn't affect this.** The stop happened on the model side, before any file was written. Defender should stay on (GUIDELINE §4 safety rule).
- **Re-framing prompts:** I won't use a reworded or relabelled prompt to get around the stop. The options offered instead:
  1. the user writes the runner and parser from the draft, and I review;
  2. a reduced sandbox: benign samples plus a behaviour summary;
  3. skip to Step 4 (dashboard) and leave the sandbox as a stretch goal.

## Addendum: "do you get logs for the violation, or can you guess by trial and error?"
- No logs, rule name or reason code are available to me. The only signal was a notice that a safety classifier stopped the response and that the content shouldn't be reproduced, even reworded.
- Any guess at the trigger would be speculation. Probing variations one by one to find the boundary would amount to the same workaround declined above, so I won't do it.
