"""Generate a 5-minute Korean presentation PDF (A4 portrait).

    .venv/Scripts/python.exe scripts/make_presentation.py

Each slide is a matplotlib Figure sized A4 portrait, drawn with shape primitives + a Korean
font (Malgun Gothic on Windows). PdfPages streams all slides into one PDF.
"""

import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.backends.backend_pdf import PdfPages  # noqa: E402
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle, Circle  # noqa: E402

plt.rcParams["font.family"] = "Malgun Gothic"
plt.rcParams["axes.unicode_minus"] = False

# A4 portrait inches
W_IN, H_IN = 8.27, 11.69
# Virtual coord space (0-100 x, 0-141 y) — convenient round numbers with A4 aspect
XMAX, YMAX = 100, 141

# SOC-ish dark palette (matches the dashboard)
BG = "#0b1220"
PANEL = "#111a2f"
PANEL2 = "#1e293b"
FG = "#e2e8f0"
MUTED = "#94a3b8"
ACCENT = "#4ade80"       # green (pass, good)
WARN = "#fbbf24"         # amber (sandbox, caution)
DANGER = "#ef4444"       # red (quarantine, bad)
INFO = "#60a5fa"         # blue (neutral tech)


def new_slide():
    fig = plt.figure(figsize=(W_IN, H_IN), facecolor=BG)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, XMAX)
    ax.set_ylim(0, YMAX)
    ax.set_facecolor(BG)
    ax.axis("off")
    return fig, ax


def footer(ax, page_num, total):
    ax.text(5, 4, "axiMini · 1주 경량 AI-EDR", fontsize=8, color=MUTED, ha="left")
    ax.text(XMAX - 5, 4, f"{page_num} / {total}", fontsize=8, color=MUTED, ha="right")


def title_bar(ax, text, subtext=None):
    ax.text(50, 130, text, fontsize=22, color=FG, ha="center", fontweight="bold")
    # accent underline
    ax.add_patch(Rectangle((35, 126), 30, 0.6, color=ACCENT, lw=0))
    if subtext:
        ax.text(50, 122, subtext, fontsize=11, color=MUTED, ha="center")


def box(ax, x, y, w, h, text, fc=PANEL, ec=MUTED, fontsize=11, color=FG, bold=False, lw=1.2):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=fc, ec=ec, lw=lw))
    ax.text(x + w / 2, y + h / 2, text, fontsize=fontsize, color=color,
            ha="center", va="center", fontweight="bold" if bold else "normal")


def arrow(ax, x1, y1, x2, y2, color=MUTED, lw=1.5, style="-|>"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                                 arrowstyle=style, mutation_scale=18,
                                 color=color, lw=lw))


# ======================================================================= slides
def shield(ax, cx, cy, size, color):
    """Draw a shield-shaped pictogram using matplotlib primitives."""
    from matplotlib.patches import Polygon
    pts = [(cx, cy + size), (cx + size, cy + size * 0.5), (cx + size * 0.9, cy - size * 0.3),
           (cx, cy - size), (cx - size * 0.9, cy - size * 0.3), (cx - size, cy + size * 0.5)]
    ax.add_patch(Polygon(pts, closed=True, fc=color, ec=FG, lw=1.5, alpha=0.9))
    ax.text(cx, cy, "axi", fontsize=int(size * 3), ha="center", va="center",
            color=BG, fontweight="bold")


def slide_title(ax, n, total):
    footer(ax, n, total)
    shield(ax, 50, 98, 7, ACCENT)
    ax.text(50, 80, "axiMini", fontsize=48, ha="center", color=FG, fontweight="bold")
    ax.text(50, 73, "경량 AI 기반 EDR", fontsize=16, ha="center", color=ACCENT)
    ax.text(50, 69, "Lite AI-based Endpoint Detection & Response", fontsize=11, ha="center", color=MUTED)

    # Flow: 8주 팀 프로젝트 → 1주 축소판
    box(ax, 15, 45, 70, 10, "가이드라인 · 8주 · 4–5 명 팀 과제", fc=PANEL2, ec=MUTED, fontsize=13)
    arrow(ax, 50, 44, 50, 36, color=ACCENT, lw=2.5)
    box(ax, 15, 22, 70, 13, "1주 축소판 · 1 인\n동작하는 전체 파이프라인", fc=PANEL, ec=ACCENT, fontsize=14, bold=True, lw=2)

    ax.text(50, 14, "정적 분석 · 실시간 감시 · 격리소 · 샌드박스 · 대시보드",
            fontsize=10, ha="center", color=MUTED)


def slide_what(ax, n, total):
    footer(ax, n, total)
    title_bar(ax, "무엇을 만들었나", "What this does")

    # Rows with colored letter-badges as pictograms
    rows = [
        ("감시", INFO,   "파일 생성 감시", "Watched folder monitoring (watchdog)"),
        ("AI",   ACCENT, "AI 정적 분석",   "Static ML scan (LightGBM, 2568-dim features)"),
        ("동적", WARN,   "동적 분석",       "Dynamic analysis in a hardened Docker sandbox"),
        ("격리", DANGER, "자동 격리",       "Automatic quarantine with recoverable vault"),
        ("관제", INFO,   "실시간 관제",     "Live Korean SOC dashboard"),
    ]
    y = 100
    for label, color, kr, en in rows:
        ax.add_patch(Circle((15, y), 5, fc=color, ec=FG, lw=1.0, alpha=0.9))
        ax.text(15, y, label, fontsize=10, ha="center", va="center", color=BG, fontweight="bold")
        ax.text(24, y + 2, kr, fontsize=15, color=FG, va="center", fontweight="bold")
        ax.text(24, y - 3, en, fontsize=9, color=MUTED, va="center")
        y -= 16

    # Scope badge
    ax.add_patch(FancyBboxPatch((20, 10), 60, 10, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=PANEL, ec=DANGER, lw=1.5))
    ax.text(50, 15, "주의: 실제 악성코드 없음  ·  No live malware in this project",
            fontsize=10, ha="center", va="center", color=DANGER, fontweight="bold")


def slide_architecture(ax, n, total):
    footer(ax, n, total)
    title_bar(ax, "전체 구조", "End-to-end pipeline")

    # vertical flow diagram
    box(ax, 30, 112, 40, 8, "파일 생성/수정\nwatched/ 폴더", fc=PANEL, ec=MUTED, fontsize=11)
    arrow(ax, 50, 111, 50, 107, color=MUTED)

    box(ax, 25, 98, 50, 8, "Watchdog 데몬 + Stabilizer (0.5s 디바운스)", fc=PANEL2, ec=INFO, fontsize=10)
    arrow(ax, 50, 97, 50, 93, color=MUTED)

    box(ax, 20, 84, 60, 8, "LightGBM 정적 분석 (score 0 ~ 1)", fc=PANEL2, ec=INFO, fontsize=11, bold=True)
    arrow(ax, 50, 83, 50, 79, color=MUTED)

    # Three branches
    box(ax, 5, 65, 25, 10, "정상 (pass)\nscore < 0.29", fc=PANEL, ec=ACCENT, fontsize=10, color=ACCENT)
    box(ax, 37.5, 65, 25, 10, "샌드박스\n0.29 ~ 0.9999", fc=PANEL, ec=WARN, fontsize=10, color=WARN)
    box(ax, 70, 65, 25, 10, "격리\nscore ≥ 0.9999", fc=PANEL, ec=DANGER, fontsize=10, color=DANGER)
    arrow(ax, 35, 83, 17, 76, color=ACCENT)
    arrow(ax, 50, 83, 50, 76, color=WARN)
    arrow(ax, 65, 83, 82, 76, color=DANGER)

    # Second row: sandbox + quarantine targets
    arrow(ax, 50, 64, 50, 59, color=WARN)
    arrow(ax, 82, 64, 82, 59, color=DANGER)
    box(ax, 37.5, 48, 25, 10, "Docker\n샌드박스 분석", fc=PANEL2, ec=WARN, fontsize=9)
    box(ax, 70, 48, 25, 10, "격리소 Vault\n(XOR 중화)", fc=PANEL2, ec=DANGER, fontsize=9)

    # Merge to SQLite
    arrow(ax, 17, 64, 25, 35, color=ACCENT)
    arrow(ax, 50, 47, 40, 35, color=WARN)
    arrow(ax, 82, 47, 75, 35, color=DANGER)
    box(ax, 25, 25, 50, 8, "SQLite 이벤트 DB (WAL, model_sha256 기록)", fc=PANEL, ec=INFO, fontsize=10)
    arrow(ax, 50, 24, 50, 20, color=MUTED)

    box(ax, 25, 10, 50, 8, "Streamlit SOC 대시보드 (한국어, 읽기 전용)",
        fc=PANEL, ec=ACCENT, fontsize=10, color=ACCENT, bold=True)


def slide_static(ax, n, total):
    footer(ax, n, total)
    title_bar(ax, "정적 분석 엔진", "Static scanner")

    # Flow
    box(ax, 20, 110, 60, 8, "파일 바이트 (최대 128 MiB)", fc=PANEL2, ec=MUTED, fontsize=10)
    arrow(ax, 50, 109, 50, 105, color=MUTED)
    box(ax, 10, 92, 80, 12, "FastPEFeatureExtractor\n→ 2,568-차원 float32 벡터 (EMBER2024 호환, 비트 단위 동일)",
        fc=PANEL, ec=INFO, fontsize=11)
    arrow(ax, 50, 91, 50, 87, color=MUTED)
    box(ax, 10, 76, 80, 10, "LightGBM · 트리 2,063 개 · 모델 460ec1ca4d77…",
        fc=PANEL, ec=INFO, fontsize=11, bold=True)
    arrow(ax, 50, 75, 50, 71, color=MUTED)

    # Thresholds
    ax.text(50, 68, "임계값 (threshold) — Val 데이터로 선택", fontsize=11, ha="center", color=FG)
    y = 58
    for color, label, thr, note in [
        (ACCENT, "T_low  (샌드박스 진입)", "0.290884", "Val FPR 1.0%"),
        (DANGER, "T_high (자동 격리)",    "0.999917", "Val FPR 0.1%"),
    ]:
        ax.add_patch(FancyBboxPatch((10, y), 80, 8, boxstyle="round,pad=0.4,rounding_size=1.2",
                                    fc=PANEL2, ec=color, lw=1.5))
        ax.text(14, y + 4, label, fontsize=11, color=FG, va="center")
        ax.text(70, y + 4, thr, fontsize=12, color=color, va="center", ha="right", fontweight="bold")
        ax.text(88, y + 4, note, fontsize=9, color=MUTED, va="center", ha="right")
        y -= 11

    # Dataset
    ax.add_patch(FancyBboxPatch((10, 20), 80, 14, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=PANEL, ec=MUTED, lw=1.2))
    ax.text(50, 30, "학습 데이터 (training data)", fontsize=10, ha="center", color=MUTED)
    ax.text(50, 25.5, "EMBER2024 Win32_test · 720,000 PE 파일 · 시간순 분할",
            fontsize=11, ha="center", color=FG, fontweight="bold")
    ax.text(50, 22, "train 1-8주 (480k) · val 9-10주 (120k) · test 11-12주 (120k)",
            fontsize=9, ha="center", color=MUTED)


def slide_daemon(ax, n, total):
    footer(ax, n, total)
    title_bar(ax, "실시간 감시 데몬", "Real-time watcher daemon")

    # Thread diagram
    box(ax, 10, 108, 80, 8, "watchdog Observer Thread (파일 이벤트 수신)",
        fc=PANEL2, ec=INFO, fontsize=10)
    arrow(ax, 50, 107, 50, 103, color=MUTED)
    box(ax, 10, 93, 80, 8, "Pending 딕셔너리 (경로 → 시각) · 0.5초 디바운스",
        fc=PANEL, ec=MUTED, fontsize=10)
    arrow(ax, 50, 92, 50, 88, color=MUTED)
    box(ax, 10, 78, 80, 8, "Stabilizer: size+mtime 안정 · 파일 열기 가능?",
        fc=PANEL, ec=MUTED, fontsize=10)
    arrow(ax, 50, 77, 50, 73, color=MUTED)
    box(ax, 10, 63, 80, 8, "ProcessPoolExecutor · Scanner × N 작업자 (GIL 회피)",
        fc=PANEL, ec=INFO, fontsize=10)
    arrow(ax, 50, 62, 50, 58, color=MUTED)
    box(ax, 10, 48, 80, 8, "Dispatcher (단일 DB 쓰기 스레드) → SQLite WAL",
        fc=PANEL, ec=INFO, fontsize=10)

    # Key design points
    y = 36
    for text, color in [
        ("파일 확장자가 아니라 내용(MZ)으로 PE 판정", ACCENT),
        ("핸들러에서 time.sleep() 금지 (이벤트 유실 방지)", ACCENT),
        ("lost-update 레이스 방지: compare-and-swap on last_event", ACCENT),
    ]:
        ax.add_patch(Circle((12, y), 1.2, fc=color, ec="none"))
        ax.text(16, y, text, fontsize=10, color=color, va="center")
        y -= 7

    # Latency badge
    ax.add_patch(FancyBboxPatch((15, 8), 70, 9, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=PANEL2, ec=ACCENT, lw=1.5))
    ax.text(50, 12.5, "감지 → 판정 지연시간: 약 0.8 – 1.1 초",
            fontsize=11, ha="center", va="center", color=ACCENT, fontweight="bold")


def slide_quarantine(ax, n, total):
    footer(ax, n, total)
    title_bar(ax, "격리소 (Quarantine Vault)", "Safe, recoverable, auditable")

    # 4-step flow
    steps = [
        ("1", "원본 파일 이름 변경 (같은 폴더)", "rename → *.axiq-tmp (원자적)", INFO),
        ("2", "SHA-256 재확인", "검사 시점 바이트와 일치하는지 검증", INFO),
        ("3", "XOR 중화 + 쓰기 전용 저장", "<sha>.qbin  (MAGIC | key | data^key)", DANGER),
        ("4", "원본 삭제 + 사이드카 JSON 기록", "원본 경로, 점수, 모델, 판단 근거", ACCENT),
    ]
    y = 115
    for num, kr, en, color in steps:
        ax.add_patch(Circle((15, y), 3.5, color=color, lw=0))
        ax.text(15, y, num, fontsize=14, ha="center", va="center", color=BG, fontweight="bold")
        ax.text(22, y + 2, kr, fontsize=12, color=FG, va="center", fontweight="bold")
        ax.text(22, y - 2.5, en, fontsize=9, color=MUTED, va="center")
        if num != "4":
            ax.plot([15, 15], [y - 4, y - 10], color=MUTED, lw=1.5)
        y -= 15

    # Restore flow
    ax.add_patch(FancyBboxPatch((8, 32), 84, 20, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=PANEL2, ec=ACCENT, lw=1.5))
    ax.text(50, 47, "복원 (Restore) — 오탐 (False Positive) 처리", fontsize=11,
            ha="center", color=ACCENT, fontweight="bold")
    ax.text(50, 42, "① 허용 목록(allowlist)에 SHA-256 먼저 등록", fontsize=10, ha="center", color=FG)
    ax.text(50, 38, "② 그 다음 원래 경로에 복원 (재격리 레이스 방지)", fontsize=10, ha="center", color=FG)
    ax.text(50, 34, "데몬은 모든 판정 전에 allowlist를 먼저 확인", fontsize=9, ha="center", color=MUTED)

    # CLI
    ax.add_patch(FancyBboxPatch((8, 10), 84, 16, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=BG, ec=MUTED, lw=1.0))
    ax.text(10, 22, "CLI", fontsize=9, color=MUTED, va="center", fontfamily="monospace")
    for i, line in enumerate([
        "$ python -m axi.quarantine list",
        "$ python -m axi.quarantine restore <sha-prefix>",
        "$ python -m axi.quarantine delete  <sha-prefix>",
    ]):
        ax.text(12, 19 - i * 3, line, fontsize=9, color=FG, va="center", fontfamily="monospace")


def slide_sandbox(ax, n, total):
    footer(ax, n, total)
    title_bar(ax, "동적 분석 샌드박스", "Hardened Docker sandbox")

    # Container visualization
    ax.add_patch(FancyBboxPatch((10, 70), 80, 45, boxstyle="round,pad=0.4,rounding_size=1.5",
                                fc=PANEL2, ec=INFO, lw=2))
    ax.text(50, 111, "Docker Container (axi-sandbox:1)", fontsize=12, ha="center",
            color=INFO, fontweight="bold")

    # Hardening flags
    flags = [
        "--network none",           "connect → ENETUNREACH",
        "--read-only",              "write → EROFS",
        "/work: noexec",            "execve → EACCES",
        "--cap-drop ALL",           "cap syscall → EPERM",
        "--pids-limit 32",          "fork → EAGAIN",
        "--user 10001 (non-root)",  "privileged ops 거부",
    ]
    for i, (flag, effect) in enumerate(zip(flags[::2], flags[1::2])):
        row = i // 2
        col = i % 2
        xp = 14 + col * 40
        yp = 102 - row * 8
        ax.add_patch(Circle((xp + 0.5, yp), 1, fc=ACCENT, ec="none"))
        ax.text(xp + 3, yp, flag, fontsize=9, color=FG, fontfamily="monospace", va="center")
        ax.text(xp + 3, yp - 3, effect, fontsize=7.5, color=MUTED, va="center")

    # Scoring
    arrow(ax, 50, 69, 50, 65, color=MUTED)
    ax.text(50, 62, "점수 계산 방식 (Scoring)", fontsize=11, ha="center", color=FG)
    ax.text(50, 58, "방어 장벽이 몇 개 건드려졌는가로 측정 (공격 패턴 매칭 X)",
            fontsize=9, ha="center", color=MUTED)

    # Example scoring table
    ax.add_patch(FancyBboxPatch((10, 20), 80, 32, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=PANEL, ec=MUTED, lw=1))
    rules = [
        ("네트워크 차단 위반", "net_denied (ENETUNREACH)", "+25"),
        ("실행 금지 위반",    "exec_denied (EACCES)",      "+25"),
        ("쓰기 금지 위반",    "rofs_denied (EROFS)",        "+20"),
        ("대량 파일 삭제",    "mass_delete > 10",            "+20"),
        ("대량 파일 쓰기",    "mass_write > 15",             "+15"),
        ("권한 요구",         "eperm_denied (EPERM)",        "+10"),
    ]
    y = 46
    for kr, en, w in rules:
        ax.text(14, y, "●", fontsize=9, color=WARN, va="center")
        ax.text(18, y, kr, fontsize=9, color=FG, va="center")
        ax.text(52, y, en, fontsize=8, color=MUTED, va="center", fontfamily="monospace")
        ax.text(86, y, w, fontsize=10, color=WARN, va="center", ha="right", fontweight="bold")
        y -= 4

    ax.text(50, 14, "합산 점수: 30 미만 = 통과 · 30–69 = 의심 · 70+ = 악성",
            fontsize=10, ha="center", color=FG)
    ax.text(50, 10.5, "정상 샘플(benign_hello, benign_fileio)은 둘 다 0점",
            fontsize=8, ha="center", color=ACCENT, fontstyle="italic")


def slide_dashboard(ax, n, total):
    footer(ax, n, total)
    title_bar(ax, "SOC 대시보드", "Korean SOC Console (Streamlit)")

    # Mock browser frame
    ax.add_patch(FancyBboxPatch((6, 25), 88, 100, boxstyle="round,pad=0.4,rounding_size=1.5",
                                fc=BG, ec=MUTED, lw=1.5))
    ax.add_patch(Rectangle((6, 118), 88, 7, color=PANEL))
    for i, c in enumerate([DANGER, WARN, ACCENT]):
        ax.add_patch(Circle((10 + i * 3, 121.5), 1, color=c))

    # Title
    ax.text(50, 116, "axiMini SOC · 실시간 보안 관제", fontsize=11, ha="center", color=FG,
            fontweight="bold")

    # KPI row
    kpis = [("총 검사", "10 건", FG), ("통과", "6 건", ACCENT),
            ("격리", "2 건", DANGER), ("샌드박스", "1 건", WARN),
            ("평균 지연", "1,273 ms", INFO)]
    for i, (label, val, color) in enumerate(kpis):
        x = 9 + i * 17
        ax.add_patch(FancyBboxPatch((x, 102), 15, 11, boxstyle="round,pad=0.3,rounding_size=0.8",
                                    fc=PANEL, ec=MUTED, lw=0.8))
        ax.text(x + 7.5, 110, label, fontsize=7, ha="center", color=MUTED)
        ax.text(x + 7.5, 106, val, fontsize=11, ha="center", color=color, fontweight="bold")

    # Tab labels
    tabs = ["이벤트 상세", "격리소", "조치 기록", "모델 & 지표"]
    for i, t in enumerate(tabs):
        x = 8 + i * 22
        active = (i == 0)
        ax.add_patch(Rectangle((x, 94), 20, 4,
                               fc=PANEL if active else BG, ec=MUTED, lw=0.5))
        ax.text(x + 10, 96, t, fontsize=8.5, ha="center",
                color=ACCENT if active else MUTED,
                fontweight="bold" if active else "normal")

    # Event detail mock
    ax.add_patch(FancyBboxPatch((9, 30), 82, 60, boxstyle="round,pad=0.3,rounding_size=1.0",
                                fc=PANEL, ec=MUTED, lw=0.5))
    ax.text(14, 85, "파일: watched\\getprocaddr32.exe", fontsize=8, color=FG)
    ax.text(14, 81, "SHA-256: db0dc45b5711…", fontsize=8, color=MUTED, fontfamily="monospace")
    ax.text(14, 77, "악성 점수: 0.977325  →  악성 (격리됨)", fontsize=9, color=DANGER,
            fontweight="bold")

    # Mock SHAP bars
    ax.text(14, 71, "주요 판단 근거 (TreeSHAP)", fontsize=8, color=FG)
    shap_rows = [
        ("+2.95", "header.coff.char[DLL]", 2.95, DANGER),
        ("-2.39", "pefilewarnings.warn67", 2.39, ACCENT),
        ("+1.44", "header.coff.timestamp", 1.44, DANGER),
        ("-1.21", "datadirectories.DEBUG.size", 1.21, ACCENT),
        ("+0.98", "section.n_rx", 0.98, DANGER),
    ]
    max_mag = 2.95
    for i, (val, feat, mag, color) in enumerate(shap_rows):
        y = 66 - i * 4
        ax.text(14, y, val, fontsize=8, color=color, fontfamily="monospace")
        ax.text(23, y, feat, fontsize=8, color=FG, fontfamily="monospace")
        barw = (mag / max_mag) * 22
        ax.add_patch(Rectangle((60, y - 0.9), barw, 1.8, color=color))

    ax.text(14, 43, "단계별 (ms): read 1.9 · extract 63 · predict 1.3 · explain 438",
            fontsize=7, color=MUTED, fontfamily="monospace")
    ax.text(14, 39, "조치: 격리 완료 (quarantine/db0dc45b5711…qbin)",
            fontsize=7, color=ACCENT, fontfamily="monospace")
    ax.text(14, 35, "모델: 460ec1ca4d77… (학습 시점 고정)",
            fontsize=7, color=MUTED, fontfamily="monospace")

    ax.text(50, 20, "SQLite 연결은 mode=ro — UI 버그가 증거를 조작할 수 없음",
            fontsize=9, ha="center", color=ACCENT, fontstyle="italic")
    ax.text(50, 16, "DB mtime 기반 캐싱으로 데몬 쓰기 직후 즉시 반영",
            fontsize=9, ha="center", color=MUTED)


def slide_results_model(ax, n, total):
    footer(ax, n, total)
    title_bar(ax, "결과 ① 모델 성능", "Results · Model performance")

    # Headline numbers
    ax.add_patch(FancyBboxPatch((8, 95), 40, 25, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=PANEL, ec=INFO, lw=1.5))
    ax.text(28, 115, "Val (9-10주)", fontsize=10, ha="center", color=MUTED)
    ax.text(28, 108, "ROC-AUC  0.99885", fontsize=12, ha="center", color=FG, fontweight="bold")
    ax.text(28, 103, "pAUC(FPR≤0.5%)  0.970", fontsize=10, ha="center", color=INFO)
    ax.text(28, 98, "FPR @ T_high  0.100%", fontsize=10, ha="center", color=ACCENT)

    ax.add_patch(FancyBboxPatch((52, 95), 40, 25, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=PANEL, ec=WARN, lw=1.5))
    ax.text(72, 115, "Test (11-12주)", fontsize=10, ha="center", color=MUTED)
    ax.text(72, 108, "ROC-AUC  0.99816", fontsize=12, ha="center", color=FG, fontweight="bold")
    ax.text(72, 103, "pAUC(FPR≤0.5%)  0.958", fontsize=10, ha="center", color=INFO)
    ax.text(72, 98, "FPR @ T_high  0.210%", fontsize=10, ha="center", color=DANGER, fontweight="bold")

    # Drift explanation
    ax.add_patch(FancyBboxPatch((8, 65), 84, 23, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=PANEL2, ec=DANGER, lw=1.5))
    ax.text(50, 83, "[주의] 시간 드리프트 감지 (Concept Drift)", fontsize=12,
            ha="center", color=DANGER, fontweight="bold")
    ax.text(50, 77, "학습 2주 후: 오탐률이 2배로 상승 (0.10% → 0.21%)",
            fontsize=11, ha="center", color=FG)
    ax.text(50, 72, "이항 분포 기준 8.5σ — 노이즈가 아닌 실제 분포 변화",
            fontsize=10, ha="center", color=MUTED)
    ax.text(50, 68, "ROC-AUC는 거의 변하지 않지만(0.9989 → 0.9982)\n운용 임계값에서의 FPR은 극적으로 변함",
            fontsize=9, ha="center", color=MUTED)

    # Detection latency
    ax.add_patch(FancyBboxPatch((8, 35), 84, 23, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=PANEL, ec=ACCENT, lw=1.5))
    ax.text(50, 54, "탐지 성능", fontsize=12, ha="center", color=ACCENT, fontweight="bold")
    ax.text(28, 48, "92.6%", fontsize=24, ha="center", color=ACCENT, fontweight="bold")
    ax.text(28, 43, "Test 세트 탐지율 (TPR)", fontsize=9, ha="center", color=MUTED)
    ax.text(72, 48, "0.21%", fontsize=24, ha="center", color=DANGER, fontweight="bold")
    ax.text(72, 43, "Test 세트 오탐률 (FPR)", fontsize=9, ha="center", color=MUTED)
    ax.text(50, 38, "목표: FPR ≤ 0.1% · 달성: val V test X (드리프트)",
            fontsize=9, ha="center", color=MUTED)

    # Honest caveat
    ax.text(50, 25, "[핵심] 가장 중요한 결과는 \"드리프트가 실제로 측정됐다\"는 것",
            fontsize=10, ha="center", color=FG, fontweight="bold")
    ax.text(50, 20, "생산 환경에서는 안전 여유, 주기적 재학습, 서명 허용 목록으로 완화",
            fontsize=9, ha="center", color=MUTED)
    ax.text(50, 16, "(개념만 설명 — 재학습 파이프라인은 범위 밖, 설계는 로그 11)",
            fontsize=8, ha="center", color=MUTED, fontstyle="italic")


def slide_results_latency(ax, n, total):
    footer(ax, n, total)
    title_bar(ax, "결과 ② 속도", "Results · Latency")

    # Scan latency (horizontal bar chart)
    ax.text(50, 120, "파일 1개 스캔 시간 (ms, p50 중앙값)", fontsize=12, ha="center", color=FG)

    # Original
    ax.text(15, 112, "원본 thrember", fontsize=9, color=MUTED, va="center", ha="right")
    ax.add_patch(Rectangle((16, 110), 50, 4, color=DANGER, alpha=0.7))
    ax.text(68, 112, "119 ms", fontsize=10, color=FG, va="center", fontweight="bold")

    # Ours
    ax.text(15, 104, "axi (고속)", fontsize=9, color=MUTED, va="center", ha="right")
    ax.add_patch(Rectangle((16, 102), 15, 4, color=ACCENT, alpha=0.9))
    ax.text(33, 104, "36 ms  (3.3× 빠름)", fontsize=10, color=ACCENT, va="center", fontweight="bold")

    # Why
    ax.add_patch(FancyBboxPatch((10, 78), 80, 18, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=PANEL, ec=MUTED, lw=1))
    ax.text(50, 92, "주요 최적화 (출력은 비트 단위 동일)", fontsize=10,
            ha="center", color=FG, fontweight="bold")
    ax.text(14, 87, "①", fontsize=10, color=ACCENT); ax.text(18, 87, "문자열 regex: S×R → R (finditer + searchsorted)", fontsize=9, color=FG)
    ax.text(14, 83, "②", fontsize=10, color=ACCENT); ax.text(18, 83, "엔트로피: Counter → bincount (첫 등장 순서 보존)", fontsize=9, color=FG)
    ax.text(14, 79, "③", fontsize=10, color=ACCENT); ax.text(18, 79, "gc.freeze(): pefile close()의 전체 GC 비용 제거", fontsize=9, color=FG)

    # Detection latency
    ax.text(50, 68, "실시간 탐지 지연 (파일 저장 완료 → DB 기록)",
            fontsize=12, ha="center", color=FG)
    ax.add_patch(FancyBboxPatch((15, 48), 70, 15, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=PANEL2, ec=ACCENT, lw=1.5))
    ax.text(50, 57, "약 0.8 – 1.1 초", fontsize=20, ha="center",
            color=ACCENT, fontweight="bold")
    ax.text(50, 51, "디바운스 0.5s + 안정성 0.2s + 추출 + 예측", fontsize=9,
            ha="center", color=MUTED)

    # Verification
    ax.add_patch(FancyBboxPatch((10, 20), 80, 22, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=PANEL, ec=INFO, lw=1))
    ax.text(50, 37, "[검증] 비트 단위 동일성 검증", fontsize=11, ha="center",
            color=INFO, fontweight="bold")
    ax.text(50, 33, "학습 시 쓴 추출기 vs 스캔 시 쓴 고속 추출기 = 동일 바이트",
            fontsize=10, ha="center", color=FG)
    ax.text(50, 29, "실제 PE 1,008 개 + 합성 엣지 케이스 8 개 → 불일치 0",
            fontsize=9, ha="center", color=ACCENT)
    ax.text(50, 25, "음성 통제: 엔트로피를 1 ulp 바꾸면 모두 실패 (검증기를 사용하는 이유)",
            fontsize=9, ha="center", color=MUTED, fontstyle="italic")


def slide_diffs(ax, n, total):
    footer(ax, n, total)
    title_bar(ax, "가이드라인 대비 주요 차이점", "Deliberate deviations from the spec")

    diffs = [
        ("무작위 분할 → 시간순 분할",
         "guide: random split (미래 유출)   ·   axi: by week (실제 배포 조건)"),
        ("Test 세트 임계값 → Val 세트 임계값",
         "guide: threshold=0.97 on test   ·   axi: val FPR로 선택, test는 1회 측정만"),
        ("정확도 → Partial AUC",
         "50/50 데이터에서 accuracy/precision 오해 유발 → FPR ≤ 0.5% 구간만 평가"),
        ("확장자 라우팅 → 내용 라우팅",
         "update.bin 으로 이름 바꾼 PE 도 정상 검사"),
        ("핸들러 sleep() → 즉시 반환",
         "OS 이벤트 버퍼 오버플로우 방지 (Debouncing을 별도 스레드로)"),
        ("샌드박스 서명 매칭 → 방어 장벽 측정",
         "공격 패턴 DB 유지 비용 없음, 새로운 기법에도 강건"),
        ("대시보드에 삭제 버튼 → 읽기 전용",
         "UI 버그가 증거를 조작할 수 없게 함 (CLI가 유일한 writer)"),
    ]
    y = 115
    for kr, en in diffs:
        ax.add_patch(FancyBboxPatch((6, y - 6), 88, 10,
                                    boxstyle="round,pad=0.3,rounding_size=1.0",
                                    fc=PANEL, ec=MUTED, lw=0.8))
        ax.text(10, y + 1, "►", fontsize=14, color=ACCENT, va="center")
        ax.text(14, y + 1.5, kr, fontsize=10.5, color=FG, va="center", fontweight="bold")
        ax.text(14, y - 2.5, en, fontsize=8.5, color=MUTED, va="center")
        y -= 14

    ax.text(50, 10, "공통 원칙: \"측정 가능한 방어적 설계\" 우선",
            fontsize=10, ha="center", color=ACCENT, fontstyle="italic")


def slide_summary(ax, n, total):
    footer(ax, n, total)
    title_bar(ax, "요약", "Summary")

    # Big achievement box
    ax.add_patch(FancyBboxPatch((10, 95), 80, 28, boxstyle="round,pad=0.5,rounding_size=1.5",
                                fc=PANEL, ec=ACCENT, lw=2))
    ax.text(50, 116, "1주간 완성한 동작하는 Lite AI-EDR",
            fontsize=14, ha="center", color=ACCENT, fontweight="bold")
    ax.text(50, 110, "8주 팀 프로젝트의 핵심 파이프라인을 1인 범위로 구현",
            fontsize=10, ha="center", color=FG)
    ax.text(50, 104, "정적 분석 · 실시간 데몬 · 격리 · 샌드박스 · 대시보드",
            fontsize=10, ha="center", color=MUTED)
    ax.text(50, 99, "34개 테스트 통과 · 720,000 PE 파일 학습",
            fontsize=9, ha="center", color=MUTED)

    # Stats row
    stats = [("19", "학습 로그"), ("34", "자동 테스트"), ("720k", "학습 데이터"),
             ("2,063", "LightGBM 트리"), ("2,568", "특징 차원")]
    for i, (num, label) in enumerate(stats):
        x = 7 + i * 17.5
        ax.add_patch(FancyBboxPatch((x, 75), 15, 15,
                                    boxstyle="round,pad=0.3,rounding_size=1.0",
                                    fc=PANEL2, ec=INFO, lw=1))
        ax.text(x + 7.5, 84, num, fontsize=16, ha="center", color=INFO, fontweight="bold")
        ax.text(x + 7.5, 78, label, fontsize=8, ha="center", color=MUTED)

    # Open items
    ax.add_patch(FancyBboxPatch((10, 48), 80, 22, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=PANEL, ec=WARN, lw=1.2))
    ax.text(50, 66, "남은 과제 (Open items)", fontsize=11, ha="center",
            color=WARN, fontweight="bold")
    ax.text(14, 62, "• 스캔 p95 < 50 ms 미달 (pefile 전체 파싱 유지 선택)",
            fontsize=9, color=FG)
    ax.text(14, 58, "• 데몬 ↔ 샌드박스 연동 (ELF 라우팅)",
            fontsize=9, color=FG)
    ax.text(14, 54, "• YARA 룰 자동 생성기 (docs/YARA_RULE_GENERATOR.md에 설계 완료)",
            fontsize=9, color=FG)
    ax.text(14, 50, "• 서명자 기반 허용 목록, 재학습 파이프라인",
            fontsize=9, color=FG)

    # Final
    ax.text(50, 36, "학습한 것", fontsize=11, ha="center", color=FG, fontweight="bold")
    for i, line in enumerate([
        "ML 평가 (시간순 분할, 임계값 선택, 드리프트 측정)",
        "실시간 시스템 설계 (디바운스, 레이스 방지, 백프레셔)",
        "컨테이너 격리 (Linux 네임스페이스, cap-drop, strace)",
        "증거 처리 (원자적 이동, 감사 로그, 읽기 전용 UI)",
    ]):
        ax.text(50, 32 - i * 4, f"· {line}", fontsize=9, ha="center", color=ACCENT)

    # thank you
    ax.text(50, 11, "감사합니다 · Thank you", fontsize=14, ha="center",
            color=FG, fontweight="bold")


# ======================================================================= main
def main() -> None:
    out = Path(__file__).resolve().parent.parent / "docs" / "presentation.pdf"
    out.parent.mkdir(parents=True, exist_ok=True)

    slides = [slide_title, slide_what, slide_architecture, slide_static, slide_daemon,
              slide_quarantine, slide_sandbox, slide_dashboard, slide_results_model,
              slide_results_latency, slide_diffs, slide_summary]
    total = len(slides)

    with PdfPages(out) as pdf:
        for i, draw in enumerate(slides, start=1):
            fig, ax = new_slide()
            draw(ax, i, total)
            pdf.savefig(fig, facecolor=BG)
            plt.close(fig)
            print(f"  [{i}/{total}]  {draw.__name__}")

    kb = out.stat().st_size / 1024
    print(f"wrote {out}  ({kb:.0f} KB, {total} slides)")


if __name__ == "__main__":
    sys.exit(main())
