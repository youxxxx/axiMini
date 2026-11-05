# Log 08 — `.venv/Scripts/python.exe: No such file or directory`

- **Date:** 2026-11-05
- **Query:** you ran `! .venv/Scripts/python.exe scripts/check_env.py` and got "No such file or directory".
- **Files changed:** none

## Cause (my side effect)
- The shell behind `!` and behind my own Bash tool is **one persistent bash process**. Its working directory carries over between commands.
- While investigating the `signify` bug (log 07) I ran `cd .venv/Lib/site-packages/thrember` and left the shell there.
- Your command used a **relative** path, so bash looked for `.../thrember/.venv/Scripts/python.exe`, which doesn't exist.
- Confirmed with `pwd` → `/c/Users/user/Documents/axiMini/.venv/Lib/site-packages/thrember`.

## Fix
I ran `cd /c/Users/user/Documents/axiMini` and re-ran the check. The result is identical to log 07 §3: every Day-1 check `[OK]`, Docker `[WARN]` (WSL pending), exit 0.

## Prevention
- From now on I'll use `cd` only inside a subshell, `(cd dir && cmd)`, or use absolute paths, so the shared shell always stays at the project root.
- On your side, if a relative command ever fails like this, `! pwd` shows where the shell is.

## Concept: relative paths resolve against the process's current working directory
This is the same as `fopen("data.txt")` in C: it resolves against the CWD at call time, not against where the program file lives. That's why `scripts/check_env.py` computes `ROOT = Path(__file__).resolve().parent.parent` instead of trusting the CWD. The script works from any directory, but the *interpreter path* you typed is still relative.

## Follow-up: pin verification
You ran `pip freeze | grep thrember`:
```
thrember @ git+https://github.com/FutureComputing4AI/EMBER2024@0ef753e81d98bf209f71b03cd331dfc190b5b54d
```
It matches the line pinned in `requirements.txt` (log 07 §2) exactly, so the installed version and the declared version agree. No change needed; the pin step from log 02 §6.1 is complete.
