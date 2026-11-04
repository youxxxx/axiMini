---
name: feedback-aximini-working-rules
description: "How the user wants the axiMini project run — learning-first, detailed logs, lite 2-day scope, incremental build, env setup stated in logs"
metadata:
  node_type: memory
  type: feedback
  originSessionId: 72150f88-ae41-4336-aa46-77a0699025d7
  modified: 2026-11-04T07:27:08.971Z
---

Rules the user set on 2026-11-04 (first query of axiMini):

1. **Don't build the whole thing at once.** Work step by step; wait for the user's go-ahead before moving to the next big chunk.
2. **Learning is the main goal.** Write `/logs/*.md` in detail (what was done, why, alternatives, concepts explained) even if it costs more tokens.
3. **Scope = lite but functioning, ~2 days of work.** guide.pdf is designed for a multi-week team project; cut it down (see GUIDELINE.md in the repo).
4. **State required environment setup in the log** (VMs, Docker, installs, Defender settings) so the user can set it up themselves.
5. Project CLAUDE.md also applies: a log per query, English for code/logs/docs, Korean for UI text, guide.pdf as the main reference but proactively recommend better methods.

6. **Claude's notes live in the repo** under `claude-notes/` (moved there from Claude's private memory dir at the user's request on 2026-11-04). They're imported by `CLAUDE.md`. Update them here, not in `~/.claude/.../memory/`.

**Why:** The user is doing this to learn, not just to get a deliverable; they want to understand and set up each piece themselves.
**How to apply:** For every query, write a detailed log; explain reasoning in the log; keep scope tight; list env prerequisites before code that needs them. Related: [[user-profile-competitive-programmer]], [[project-axiMini]].
