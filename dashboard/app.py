"""SOC-style dashboard for axiMini events.

    .venv/Scripts/python.exe -m streamlit run dashboard/app.py

Reads `data/events.db` and the quarantine vault directly, and the model's `models/*.json`.
DB access is READ-ONLY (store.connect(readonly=True) uses `file:…?mode=ro`), so the dashboard
can never modify the evidence it displays. SQLite WAL (log 14 §3) lets the daemon keep writing
while this reads.

All UI strings are Korean per CLAUDE.md "Language Protocol"; code/comments stay English.
"""

import json
import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st

# Ensure `from axi import ...` works when launched as `streamlit run dashboard/app.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from axi import config, quarantine, store  # noqa: E402

VERDICT_KO = {
    "pass": "✅ 정상", "sandbox": "⚠️ 의심", "quarantine": "🚨 악성",
    "not_pe": "· PE 아님", "error": "❌ 오류",
}
ACTION_KO = {
    "quarantined": "격리 완료", "already_quarantined": "격리 완료(기존 격리본 있음)",
    "allowlisted": "허용 목록(조치 안 함)", "changed": "검사 후 변경(재검사 대기)",
    "locked": "사용 중이라 격리 실패", "missing": "파일 없음",
    "copied_not_removed": "사본만 저장(원본 삭제 실패)",
}
Q_STATUS_KO = {"quarantined": "격리 중", "restored": "복원됨", "deleted": "영구 삭제"}
AUDIT_ACTION_KO = {
    "quarantine:quarantined": "격리 실행",
    "quarantine:already_quarantined": "격리 실행(중복)",
    "quarantine:locked": "격리 실패(사용 중)",
    "quarantine:changed": "격리 중단(내용 변경)",
    "allowlist": "허용 목록 추가", "restore": "복원", "delete": "영구 삭제",
}


# ---------------------------------------------------------------- data access
# ttl is short because the daemon writes continuously; the WAL query itself is < 1 ms.
@st.cache_data(ttl=2)
def load_events(db_mtime: float) -> pd.DataFrame:  # noqa: ARG001 (mtime invalidates cache)
    con = store.connect(readonly=True)
    try:
        return pd.read_sql_query("SELECT * FROM events ORDER BY id DESC", con)
    finally:
        con.close()


@st.cache_data(ttl=2)
def load_actions(db_mtime: float) -> pd.DataFrame:  # noqa: ARG001
    con = store.connect(readonly=True)
    try:
        return pd.read_sql_query("SELECT * FROM actions ORDER BY id DESC", con)
    finally:
        con.close()


@st.cache_data(ttl=2)
def load_allowlist(db_mtime: float) -> pd.DataFrame:  # noqa: ARG001
    con = store.connect(readonly=True)
    try:
        return pd.read_sql_query("SELECT * FROM allowlist ORDER BY added_at DESC", con)
    finally:
        con.close()


@st.cache_data(ttl=10)
def load_quarantine_items() -> list[dict]:
    return quarantine.list_items()


@st.cache_data(ttl=60)
def load_model_meta() -> dict:
    return json.loads(config.MODEL_META_PATH.read_text()) if config.MODEL_META_PATH.exists() else {}


@st.cache_data(ttl=60)
def load_test_report() -> dict:
    return json.loads(config.TEST_REPORT_PATH.read_text()) if config.TEST_REPORT_PATH.exists() else {}


def _db_mtime() -> float:
    """Cache key for the DB-backed queries: the event DB's mtime. Each daemon commit (WAL
    checkpoint or main-file write) bumps this, which drops the cache; polling the number itself
    is a stat() call, essentially free."""
    try:
        return config.DB_PATH.stat().st_mtime
    except FileNotFoundError:
        return 0.0


# ---------------------------------------------------------------- rendering helpers
def _fmt_score(s) -> str:
    return "-" if pd.isna(s) else f"{s:.6f}"


def _fmt_ts(t: float) -> str:
    return time.strftime("%m-%d %H:%M:%S", time.localtime(t))


def _format_events_table(df: pd.DataFrame) -> pd.DataFrame:
    """Narrow + localize columns for display. The full row stays available via the drill-down."""
    d = df[["id", "scanned_at", "file_name", "verdict", "score", "size",
            "detect_ms", "action"]].copy()
    d["scanned_at"] = d["scanned_at"].map(_fmt_ts)
    d["verdict"] = d["verdict"].map(lambda v: VERDICT_KO.get(v, v))
    d["score"] = d["score"].map(_fmt_score)
    d["size"] = d["size"].map(lambda n: f"{int(n):,}" if pd.notna(n) else "-")
    d["detect_ms"] = d["detect_ms"].map(lambda n: f"{n:.0f}")
    d["action"] = d["action"].map(lambda a: ACTION_KO.get(a, a) if a else "-")
    d.columns = ["#", "시각", "파일명", "판정", "점수", "크기(B)", "지연(ms)", "조치"]
    return d


def _render_treeshap(top: list[dict]) -> None:
    """A SHAP bar chart in markdown: positive (red) pushes toward malicious, negative (green) toward benign."""
    if not top:
        st.caption("TreeSHAP 설명이 없습니다. (pass 결과는 설명을 계산하지 않음)")
        return
    rows, bias_row = top[:-1], top[-1]
    if not rows:
        st.caption("판단 근거가 비어 있습니다.")
        return
    max_abs = max(abs(r["contribution"]) for r in rows) or 1.0
    st.markdown("**주요 판단 근거** (+ 악성 방향 · − 정상 방향)")
    for r in rows:
        bar_len = int(round(abs(r["contribution"]) / max_abs * 24))
        bar = "█" * bar_len
        color = "#ef4444" if r["contribution"] > 0 else "#4ade80"
        line = (f"<code>{r['contribution']:+7.3f}</code> "
                f"<span style='color:#94a3b8'>[{r['group_ko']}]</span> "
                f"<code>{r['feature']}</code> = <code>{r['value']:g}</code> "
                f"<span style='color:{color};font-family:monospace'>{bar}</span>")
        st.markdown(line, unsafe_allow_html=True)
    st.caption(f"기준값 {bias_row['bias']:+.3f} + 기여도 합 = 원점수 {bias_row['raw_score']:+.3f}")


def _render_event_detail(ev: pd.Series) -> None:
    c1, c2 = st.columns([1, 2])
    with c1:
        st.markdown(f"**파일**: `{ev['path']}`")
        st.markdown(f"**SHA-256**: `{ev['sha256'] or '-'}`")
        size = f"{int(ev['size']):,} 바이트" if pd.notna(ev["size"]) else "-"
        st.markdown(f"**크기**: {size}")
        st.markdown(f"**판정**: {VERDICT_KO.get(ev['verdict'], ev['verdict'])}")
        if pd.notna(ev["score"]):
            st.markdown(f"**악성 점수**: `{ev['score']:.6f}`")
        if ev["action"]:
            st.markdown(f"**조치**: {ACTION_KO.get(ev['action'], ev['action'])}")
            if ev["action_detail"]:
                st.caption(ev["action_detail"])
        if ev["model_sha256"]:
            st.markdown(f"**모델**: `{ev['model_sha256'][:16]}…`")
        if ev["stage_ms"]:
            ms = json.loads(ev["stage_ms"])
            parts = "  ".join(f"{k} {v:.1f}" for k, v in ms.items())
            st.markdown(f"**단계별(ms)**: {parts}")
        if ev["error"]:
            st.error(f"오류: {ev['error']}")
    with c2:
        if ev["top_features"]:
            _render_treeshap(json.loads(ev["top_features"]))
        else:
            st.caption("판단 근거 데이터가 없습니다.")


# ---------------------------------------------------------------- page
st.set_page_config(page_title="axiMini SOC 대시보드", page_icon="🛡️", layout="wide")

# --- sidebar
with st.sidebar:
    st.title("🛡️ axiMini SOC")
    st.caption("경량 AI-EDR 관제 콘솔")
    auto_refresh = st.toggle("자동 새로고침 (3초)", value=False, help="메타 리프레시로 페이지 전체 재로드")
    if st.button("지금 새로고침", width="stretch"):
        st.cache_data.clear()
        st.rerun()
    st.divider()
    db_exists = config.DB_PATH.exists()
    st.caption(f"DB: `{config.DB_PATH.name}` {'✓' if db_exists else '— 없음'}")
    model_exists = config.MODEL_PATH.exists()
    st.caption(f"모델: `{config.MODEL_PATH.name}` {'✓' if model_exists else '— 없음'}")
    st.caption(f"격리소: `{config.QUARANTINE_DIR.name}/`")
    st.divider()
    st.caption("데몬 시작:")
    st.code("python -m axi.daemon", language="bash")

if auto_refresh:
    # A single <meta http-equiv="refresh"> is a full page reload: cheap, preserves URL params,
    # and doesn't need an extra component. Scroll position resets, which is fine for a SOC view.
    st.markdown('<meta http-equiv="refresh" content="3">', unsafe_allow_html=True)

st.title("실시간 보안 관제")

# --- KPIs
events = load_events(_db_mtime()) if config.DB_PATH.exists() else pd.DataFrame()
if events.empty:
    st.info("아직 이벤트가 없습니다. `python -m axi.daemon`으로 데몬을 시작하고 `watched/` 폴더에 "
            "파일을 떨어뜨리면 여기 표시됩니다.")
else:
    counts = events["verdict"].value_counts().to_dict()
    # avg_latency excludes NaN automatically. We only trust it when there's at least one scored event.
    scored = events[events["score"].notna()]
    avg_latency = scored["detect_ms"].mean() if not scored.empty else 0
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("총 검사", f"{len(events):,} 건")
    k2.metric("통과", f"{counts.get('pass', 0):,} 건")
    k3.metric("🚨 격리", f"{counts.get('quarantine', 0):,} 건")
    k4.metric("⚠️ 샌드박스", f"{counts.get('sandbox', 0):,} 건")
    k5.metric("평균 감지→판정", f"{avg_latency:.0f} ms")

# --- events table + filters
if not events.empty:
    with st.container():
        c1, c2 = st.columns([3, 1])
        c1.subheader("최근 이벤트")
        pick = c2.multiselect("판정 필터", options=list(VERDICT_KO.keys()),
                              format_func=lambda v: VERDICT_KO[v], default=[])
        shown = events if not pick else events[events["verdict"].isin(pick)]
        st.dataframe(_format_events_table(shown), width="stretch", height=280, hide_index=True)
    st.caption(f"표시 중: {len(shown):,} / {len(events):,} 건")

# --- tabs
tab_detail, tab_q, tab_audit, tab_model = st.tabs(
    ["이벤트 상세", "격리소", "조치 기록", "모델 & 지표"])

with tab_detail:
    if events.empty:
        st.caption("표시할 이벤트가 없습니다.")
    else:
        ids = events["id"].tolist()
        chosen = st.selectbox(
            "이벤트 선택", ids,
            format_func=lambda i: f"#{i}  ·  {events[events['id']==i]['file_name'].iloc[0]}  "
                                  f"·  {VERDICT_KO.get(events[events['id']==i]['verdict'].iloc[0])}",
        )
        _render_event_detail(events[events["id"] == chosen].iloc[0])

with tab_q:
    items = load_quarantine_items()
    allow = load_allowlist(_db_mtime())
    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown("**격리 항목**")
        if not items:
            st.caption("격리 항목 없음.")
        else:
            rows = []
            for m in items:
                o = m["origins"][-1]
                rows.append({"SHA(12)": m["sha256"][:12], "상태": Q_STATUS_KO.get(m["status"], m["status"]),
                             "격리 시각": _fmt_ts(o["quarantined_at"]),
                             "원본 경로": o["path"], "크기(B)": f"{m['size']:,}",
                             "점수": _fmt_score(o.get("score"))})
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
            st.caption("복원: `python -m axi.quarantine restore <SHA 앞 8자리>`  "
                       "— 복원 시 해시가 자동으로 허용 목록에 추가됩니다.")
    with c2:
        st.markdown("**허용 목록 (오탐 처리된 해시)**")
        if allow.empty:
            st.caption("허용 목록 없음.")
        else:
            d = allow.copy()
            d["added_at"] = d["added_at"].map(_fmt_ts)
            d["sha256"] = d["sha256"].str[:12]
            d.columns = ["SHA(12)", "추가 시각", "사유"]
            st.dataframe(d, width="stretch", hide_index=True)

with tab_audit:
    actions = load_actions(_db_mtime())
    st.markdown("**조치 로그** — 이벤트 → 조치 → 복원 / 허용 흐름을 추적합니다.")
    if actions.empty:
        st.caption("조치 기록 없음.")
    else:
        d = actions.copy()
        d["ts"] = d["ts"].map(_fmt_ts)
        d["sha256"] = d["sha256"].fillna("-").str[:12]
        d["action"] = d["action"].map(lambda a: AUDIT_ACTION_KO.get(a, a))
        d["event_id"] = d["event_id"].fillna(0).astype(int).replace(0, None)
        d = d[["id", "ts", "action", "sha256", "detail", "event_id"]]
        d.columns = ["#", "시각", "조치", "SHA(12)", "세부", "이벤트"]
        st.dataframe(d, width="stretch", hide_index=True)

with tab_model:
    meta = load_model_meta()
    test = load_test_report()
    if not meta:
        st.warning("모델 메타 파일이 없습니다. `python -m axi.model train`을 먼저 실행하세요.")
    else:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**모델**")
            st.markdown(f"- 파일: `{meta['model_file']}`")
            st.markdown(f"- 생성: `{meta['created']}`")
            st.markdown(f"- SHA-256: `{meta['model_sha256'][:24]}…`")
            st.markdown(f"- 최종 트리 수: `{meta['best_iteration']}`")
            st.markdown(f"- 학습 시간: `{meta['train_seconds']:.0f}s`")
            st.markdown(f"- T_high (격리): `{meta['t_high']:.6f}` "
                        f"— 목표 FPR {meta['target_fpr']:.1%}")
            st.markdown(f"- T_low (샌드박스): `{meta['t_low']:.6f}` "
                        f"— 목표 FPR {meta['target_fpr_low']:.1%}")
        with c2:
            st.markdown("**지표 비교 (Val vs Test)** — 시간 드리프트 측정")
            val = meta.get("val", {})
            rows = []
            if val:
                rows.append({"지표": "ROC-AUC",
                             "Val (9–10주)": f"{val.get('roc_auc', 0):.5f}",
                             "Test (11–12주)": f"{test.get('roc_auc', 0):.5f}" if test else "-"})
                rows.append({"지표": "pAUC (FPR ≤ 0.5%)",
                             "Val (9–10주)": f"{val.get('pauc_5e-3', 0):.5f}",
                             "Test (11–12주)": f"{test.get('pauc_5e-3', 0):.5f}" if test else "-"})
                vth, tth = val.get("t_high", {}), test.get("t_high", {}) if test else {}
                rows.append({"지표": "TPR @ T_high",
                             "Val (9–10주)": f"{vth.get('tpr', 0):.4f}",
                             "Test (11–12주)": f"{tth.get('tpr', 0):.4f}" if tth else "-"})
                rows.append({"지표": "FPR @ T_high (목표 0.1%)",
                             "Val (9–10주)": f"{vth.get('fpr', 0):.5f}",
                             "Test (11–12주)": f"{tth.get('fpr', 0):.5f}" if tth else "-"})
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
        if test:
            vfpr = meta["val"]["t_high"]["fpr"]
            tfpr = test["t_high"]["fpr"]
            if tfpr > vfpr * 1.5:
                st.warning(f"⚠️ 시간 드리프트 감지: Test 시점 FPR({tfpr:.3%})이 "
                           f"Val 시점({vfpr:.3%})의 {tfpr / vfpr:.1f}배 "
                           f"(기록 참조: `logs/2026-11-05_10_day1-step3-model.md` §2).")

        if meta.get("val_pauc_history"):
            st.markdown("**학습 곡선** — 반복당 val pAUC")
            h = meta["val_pauc_history"]
            # Every nth point to keep the chart light (~50 marks is enough).
            step = max(1, len(h) // 50)
            df_curve = pd.DataFrame({"반복": list(range(0, len(h), step)),
                                     "pAUC": h[::step]}).set_index("반복")
            st.line_chart(df_curve, height=240)
