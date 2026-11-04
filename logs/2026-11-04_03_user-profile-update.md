# Log 03 — Update user profile from saved Codeforces page

- **Date:** 2026-11-04
- **Query:** you saved your Codeforces profile page (which returned HTTP 403 to my fetch in log 01) into the repo. You asked me to update the user-profile note if needed and then delete the page and its asset files.
- **Files changed:** `claude-notes/user-profile.md`
- **Files deleted:** `youx - Codeforces.html` and the `youx - Codeforces_files/` folder (about 60 CSS/JS/image assets the browser saved alongside the page)

## 1. How the page was read
- The `.html` was ~290 KB, almost entirely Codeforces site chrome and scripts. I parsed it **locally** with the Python standard library only (`re` + `html.unescape`): I dropped `<script>`/`<style>` blocks, stripped tags, and printed the text around "Contest rating". No third-party code was run, and none of the saved `.js` files were executed.
- **Two small Windows gotchas, for learning:**
  1. `print()` failed with `UnicodeEncodeError: 'cp949' codec can't encode '—'`. On a Korean-locale Windows, Python's console stdout defaults to the **CP949** code page, which can't represent the em-dash `—`.
  2. Setting `PYTHONIOENCODING=utf-8` had no effect, because I ran Python with `-I` (isolated mode). Isolated mode ignores all `PYTHON*` environment variables. That's the point of `-I` when handling untrusted files, but it also ignores the helpful ones. The fix was `sys.stdout.reconfigure(encoding="utf-8")` inside the script.

  This is the same theme as log 01's `pdftotext` issue: **text is bytes plus an encoding, and Windows defaults are often not UTF-8.** We'll set UTF-8 explicitly wherever the project reads or writes text.

## 2. What the page said (the relevant parts)
| Field | Value |
|-------|-------|
| Rank | **Master** |
| Contest rating | **2105** (max 2105, master) |
| Problems solved (all time) | **914** |
| Registered | 8 years ago (~2018) |
| Rating graph span | roughly Sep 2018 – early 2020 |
| Last year / last month | 0 problems |

## 3. Profile note update
`claude-notes/user-profile.md` now records the above and refines how I explain things:
- Assume CP-level algorithms and complexity knowledge. Never explain big-O or basic data structures.
- Spend explanation on what CP doesn't cover: ML evaluation (splits, leakage, thresholds), OS and container isolation, Python packaging and ecosystem, UI.
- Use C++/systems analogies where useful (`np.memmap` ≈ `mmap`, the Python GIL vs native threads).

I also removed stale memory-system metadata fields (`node_type`, `originSessionId`) from the front matter, since the note now lives in the repo.

## 4. Cleanup
Both the page and its assets folder are deleted, and `git status` confirms nothing from them remains (they were never committed). The only remaining reference to the page's contents is the summary in §2 and in the profile note.

## 5. Status
There's no change to the project plan. Still pending from log 02 §6: install requirements and run `scripts/check_env.py`, and fix WSL for Docker.
