# Log 05 — Fix: install commands failed (`.venvScriptspython.exe: command not found`)

- **Date:** 2026-11-05
- **Query:** you ran the three install commands from log 02 §6.1 via `!`, and all three failed.
- **Files changed:** log 02 §6.1 (commands corrected)

## What happened
```
/usr/bin/bash: line 1: .venvScriptspython.exe: command not found
```
- The `!` prefix in Claude Code runs the command in the session's shell, which here is **Git Bash**, not cmd or PowerShell.
- In bash, `\` is an **escape character**. Unquoted, `\S` becomes just `S`, so `.venv\Scripts\python.exe` turned into `.venvScriptspython.exe`. Bash consumed the backslashes before Python ever saw them.
- **This was my mistake:** log 02 gave Windows-style paths for a bash context.

## Fix
Use forward slashes. Windows itself accepts `/` as a path separator, and bash leaves it alone:
```
! .venv/Scripts/python.exe -m pip install --upgrade pip
! .venv/Scripts/python.exe -m pip install -r requirements.txt
! .venv/Scripts/python.exe scripts/check_env.py
```
Enter **one command per `!` line**. Your paste put all three in a single input. That happened to work here, because bash runs one line after another, but separate inputs make each output easier to read.

## Related notes (shell differences on Windows, for reference)
| Shell | Path separator | Escape char | Example |
|-------|----------------|-------------|---------|
| cmd.exe | `\` (also accepts `/` in most places) | `^` | `.venv\Scripts\python.exe` |
| PowerShell | `\` or `/` | `` ` `` (backtick) | `.venv\Scripts\python.exe` |
| Git Bash / WSL bash | `/` | `\` | `.venv/Scripts/python.exe` |

The pip cache and downloads are unaffected, since nothing ran. Next step: same as before, once `check_env.py` reports all `[OK]` for the Day-1 packages.
