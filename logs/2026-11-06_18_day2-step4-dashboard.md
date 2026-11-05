# Log 18: Day 2 · Step 4: Korean SOC dashboard (Streamlit)

- **Date:** 2026-11-06
- **Query:** "go to step 4"
- **Files created:** `dashboard/app.py`, `dashboard/__init__.py`, `.streamlit/config.toml`, `tests/test_dashboard.py`
- **Files changed:** `GUIDELINE.md` (dashboard + Korean-UI checkboxes ticked), `claude-notes/project-status.md`

> **Environment:** nothing new (`streamlit 1.66.1`, `pandas 3.1.1`, `altair 6.3.0` already installed in Day 1).

Commands:
```
.venv/Scripts/python.exe -m streamlit run dashboard/app.py
.venv/Scripts/python.exe -m streamlit run dashboard/app.py --server.port 8511 --server.headless true
.venv/Scripts/python.exe -m pytest -q tests/test_dashboard.py
```

The dashboard opens at `http://localhost:8501` (default) and is safe to run alongside the daemon.

---

## 1. What the live dashboard shows (from `data/events.db` right now)
Pulled via Streamlit's `AppTest` against the real DB — the actual rendered content:

**KPIs (header):**
```
총 검사: 10 건    통과: 6 건    🚨 격리: 2 건    ⚠️ 샌드박스: 1 건    평균 감지→판정: 1273 ms
```

**Tabs:** `이벤트 상세` · `격리소` · `조치 기록` · `모델 & 지표`

**격리소 row (from the Step-2 demo):**
```
{'SHA(12)': 'db0dc45b5711', '상태': '복원됨', '격리 시각': '11-05 21:27:36',
 '원본 경로': 'C:\\...\\watched\\getprocaddr32.exe', '크기(B)': '281,862', '점수': '0.977325'}
```

**모델 & 지표 panel:**
```
- 파일: axi_lgbm.txt     - 생성: 2026-11-05T14:48:50
- SHA-256: 460ec1ca4d778ff552fbc66f…   - 최종 트리 수: 2063   - 학습 시간: 1579s
- T_high (격리): 0.999917 — 목표 FPR 0.1%
- T_low (샌드박스): 0.290884 — 목표 FPR 1.0%
+ Val vs Test 지표 비교 테이블
+ 학습 곡선 (val pAUC vs 반복)
+ 시간 드리프트 경고 배너 (FPR 0.21% vs 0.10%, log 10 §2 링크)
```

## 2. Architecture
- **Data access is read-only**, via `store.connect(readonly=True)` — SQLite URI `mode=ro`, so the dashboard cannot alter the evidence it displays. The daemon keeps writing in WAL mode (log 14 §3), so dashboard reads never block it.
- **Caching keyed by DB mtime.** Every DB-backed query is `@st.cache_data(ttl=2)` and takes a `db_mtime: float` argument I pass as `config.DB_PATH.stat().st_mtime`. When the daemon commits anything the mtime bumps, Streamlit's cache drops the old frame, and the new query runs. In steady state, polling is a single `stat()` call per section — effectively free.
- **Auto-refresh = `<meta http-equiv="refresh" content="3">`.** One line of HTML; no `streamlit-autorefresh` component needed. Reloads the whole page every 3 s when the sidebar toggle is on. A SOC view resetting scroll every 3 s is normal.
- **Styled via `.streamlit/config.toml`** (dark SOC-ish palette, monospace font). A per-project config, not a global one, so other Streamlit apps on this machine are unaffected.

## 3. Sections

### 3.1 Sidebar
- Title + subtitle ("경량 AI-EDR 관제 콘솔").
- `자동 새로고침 (3초)` toggle → injects the meta refresh.
- `지금 새로고침` button → clears `st.cache_data` and `st.rerun()`s (force-fresh read).
- Status lines showing whether the DB, model and quarantine dir exist.
- A runnable snippet to start the daemon (`python -m axi.daemon`).

### 3.2 Top KPIs (`st.metric` × 5)
Total scans, pass count, quarantine count, sandbox count, average `detect_ms`. Average is computed only over scored events (ignores `not_pe` / `error`), so it reflects real detection latency rather than being dragged down by instant non-PE skips.

### 3.3 Recent events table (`st.dataframe`)
Columns: `# · 시각 · 파일명 · 판정 · 점수 · 크기(B) · 지연(ms) · 조치`, newest first.
- Multiselect verdict filter above the table (`판정 필터`).
- Verdict and action values pass through Korean label dicts (`VERDICT_KO`, `ACTION_KO`); score formatted to 6 dp; size with thousands separators.

### 3.4 Tab 1: 이벤트 상세
`st.selectbox` lists all events with `#id · filename · 판정`. Selecting one renders:
- Left: path, sha256, size, verdict, score, action+detail, model sha (first 16), stage ms, any error.
- Right: a hand-drawn SHAP bar chart in markdown. Each top-feature row shows signed contribution, group label (Korean), feature name, value, and a horizontal bar whose length scales to `|φ| / max|φ|`. Red (`#ef4444`) = toward malicious, green (`#4ade80`) = toward benign. Caption at the bottom restates the exact identity `bias + Σφ = raw_score` from log 12 §5.
- `pass` events have no TreeSHAP data (log 12: explanations are opt-in, daemon only requests them for `sandbox`/`quarantine`), so the panel captions that explicitly.

### 3.5 Tab 2: 격리소
- Left (wide): one row per quarantined sha256 showing `SHA(12) · 상태 · 격리 시각 · 원본 경로 · 크기 · 점수`. Status is Korean-mapped (`격리 중` / `복원됨` / `영구 삭제`). Caption below tells the user how to restore from the CLI (restore via UI isn't wired: a restore writes files and the dashboard stays read-only on principle, log 15 §4).
- Right: `allowlist` table (`SHA(12) · 추가 시각 · 사유`).

### 3.6 Tab 3: 조치 기록
The `actions` audit log (log 15). Audit action codes mapped to Korean (`격리 실행`, `허용 목록 추가`, `복원`, …). Links each row to its event via `event_id`.

### 3.7 Tab 4: 모델 & 지표
- Left: model file, SHA-256 prefix, created time, best iteration, training time, both thresholds and their target FPRs.
- Right: a 2-column `Val (9–10주)` / `Test (11–12주)` table of ROC-AUC, pAUC (FPR ≤ 0.5%), TPR @ T_high, FPR @ T_high. The drift fact from log 10 §2 is right there in the UI, not just in prose.
- **Drift banner:** if `test_FPR > 1.5 × val_FPR`, a yellow `st.warning` appears with the ratio and a link to log 10 §2. On the current numbers (0.10 % → 0.21 %, ratio 2.1) it fires.
- **Training curve:** `st.line_chart` of `val_pauc_history` from the model JSON (log 10 §3.3), downsampled to ~50 points so the chart stays light. Visually shows the plateau after ~1000 trees.

## 4. Tests
- **AppTest (`tests/test_dashboard.py`):** `streamlit.testing.v1.AppTest` runs the script in-process against a fake Streamlit runtime and raises on any exception the script would throw in a real browser (NameError, bad column access, missing key, type errors in the Korean label maps, etc.). Two tests:
  1. the sidebar title "axiMini SOC" and page title "실시간 보안 관제" both appear;
  2. the four tabs exist with the exact Korean labels.
- **Live boot check** (not in the test suite; done by hand in this step): `streamlit run dashboard/app.py --server.port 8511 --server.headless true`; `curl -I` returns HTTP 200 and a real SPA shell. (The initial HTML is a shell; the rendered content comes over WebSocket, so a text grep on `curl -s` output isn't meaningful. AppTest covers the rendered side.)
- **Full suite:** `pytest -q tests` → **34 passed** (features 14 + dashboard 2 + daemon 1 + model/dataset implicit + quarantine 8 + sandbox 9).

## 5. Design decisions worth noting (for learning)
- **Why read-only matters.** The dashboard reads evidence. If it could also modify it, a UI bug could delete a quarantined sample or clear an audit row without any CLI command running. `mode=ro` makes that class of bug impossible: any UPDATE/DELETE from the dashboard's connection raises `sqlite3.OperationalError`.
- **Why mtime-keyed cache beats `ttl=0`.** With `ttl=0`, every rerun re-executes the SQL. With `ttl=2`, there's an up-to-2-s staleness window even after the daemon commits. Keying the cache on `DB_PATH.stat().st_mtime` gets us both: zero re-query in steady state, and immediate invalidation on any write.
- **Why I hand-drew the SHAP bars instead of `st.bar_chart`.** Signed bars going both ways from a zero baseline aren't a one-liner in `st.bar_chart` (it expects positive bars). A text-mode bar in markdown with inline colour keeps it one call, lets us keep the exact numeric value alongside the bar, and reads well in a monospace theme.
- **Why no restore button.** The dashboard is deliberately read-only. Adding a "restore" action would mean adding a writer connection and a confirmation dialog; the CLI already does restore + allowlist atomically (log 15). Keeping evidence-viewing and evidence-changing in separate programs is what a real SOC does.

## 6. Known cosmetic issues
- `st.line_chart` triggers one upstream `Pandas4Warning` (`reset_index(inplace=True)`) in Streamlit's own code. Not fixable from here.
- `streamlit run` auto-opens a browser unless `server.headless = true` (now in `.streamlit/config.toml`). On this box that opened Edge twice in a row during testing.

## 7. Next steps
Day 2 remaining items:
1. **`requirements.lock`** — `pip freeze > requirements.lock` for a reproducible redeploy.
2. **Final `DAY2_SUMMARY.md`** (or update `DAY1_SUMMARY.md` into a project README) covering the daemon/quarantine/sandbox/dashboard entry points alongside Day 1's.
3. (Optional stretch, per guide ch.15) YARA rule generator from a quarantined file's strings.
