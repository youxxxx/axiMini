# Log 20: 5-minute Korean presentation PDF

- **Date:** 2026-11-06
- **Query:** "make a pdf file for a 5 minute(brief) presentation" (Korean, portrait, 적은 글 · 그림 위주)
- **Files created:** `scripts/make_presentation.py`, `docs/presentation.pdf`

> **Environment:** nothing new. matplotlib and Korean font `Malgun Gothic` are already available on Windows.

Commands:
```
.venv/Scripts/python.exe scripts/make_presentation.py     # writes docs/presentation.pdf
```
The script is deterministic, so re-running produces the same bytes (good for version control
of any committed intermediate PNGs; the PDF itself is listed in `.gitignore` under `docs/*.pdf`
if the user prefers it not committed).

---

## 1. What the PDF contains (12 slides, A4 portrait, ~271 KB)

| # | 제목 | 핵심 내용 |
|---|---|---|
| 1 | axiMini (표지) | 방패형 로고, "guide.pdf · 8주 · 4–5 명 팀 과제 → 2일 축소판 · 1 인" |
| 2 | 무엇을 만들었나 | 5개의 색상 배지 (감시 / AI / 동적 / 격리 / 관제), "실제 악성코드 없음" 배너 |
| 3 | 전체 구조 | end-to-end 플로우: 파일 → 데몬 → LightGBM → 3-way split → sandbox / vault → SQLite → 대시보드 |
| 4 | 정적 분석 엔진 | 2568-dim 벡터, 2063 트리, T_low/T_high 색상 배지, 720k 데이터 시간순 분할 |
| 5 | 실시간 감시 데몬 | Observer → Pending → Stabilizer → Pool → Dispatcher 흐름, 핵심 설계 포인트 3개 |
| 6 | 격리소 | 4-단계 번호 플로우 (rename → verify → XOR → sidecar), 복원 흐름, CLI 예시 |
| 7 | 샌드박스 | Docker 컨테이너 시각화 + 6개 하드닝 플래그, 점수 규칙 표 |
| 8 | SOC 대시보드 | 모의 브라우저 UI, KPI, 탭, 실제 이벤트 (TreeSHAP 바) |
| 9 | 결과 ① 모델 성능 | Val/Test 메트릭 비교, 드리프트 경고, 큰 숫자 두 개 (92.6%, 0.21%) |
| 10 | 결과 ② 속도 | 스캔 지연 bar chart, 탐지 지연 배지, 비트 동일성 검증 결과 |
| 11 | guide.pdf 대비 차이점 | 7개 의도적 편차 (분할, 임계값, 메트릭, 라우팅, 샌드박스, 대시보드) |
| 12 | 요약 | 큰 성과 박스, 5개 스탯 배지, 남은 과제, 학습한 것, 감사합니다 |

5분 발표 기준으로 슬라이드 당 평균 25초. 각 슬라이드는 하나의 메시지에 집중.

## 2. Design decisions

### 2.1 Why matplotlib + PdfPages, not reportlab or weasyprint
- **Matplotlib is already installed** (thrember pulls it in; log 07).
- `PdfPages` streams one figure per slide into a single PDF: identical rendering to what the
  user sees in a Jupyter notebook, deterministic output, no browser runtime.
- Shape primitives (`FancyBboxPatch`, `FancyArrowPatch`, `Circle`, `Polygon`) are enough for
  the diagrams. No HTML / CSS surface to debug.

### 2.2 Korean font — `Malgun Gothic`
- Pre-installed on Windows 10/11; matplotlib finds it without extra configuration.
- Set globally with `plt.rcParams["font.family"] = "Malgun Gothic"`.
- `plt.rcParams["axes.unicode_minus"] = False` so the hyphen in e.g. "FPR ≤ 0.5%" doesn't
  render as a minus-sign placeholder.

### 2.3 No emojis — colored shapes and letter-badges instead
First attempt used 🛡️ 📁 🤖 🧪 🚨 📊 ⚠️ emojis. `Malgun Gothic` lacks most of these and
matplotlib's fallback rendered them as "BASIC LATIN / TRANSPORT & MAP SYM" placeholder boxes
(visible in a test PNG). The fix:
- **Pictograms are drawn** with `Circle` + Korean label inside (slide 2), `Polygon` for the
  shield logo (slide 1), and `FancyBboxPatch` for everything else.
- The visual hierarchy is color-coded consistently with the dashboard theme (log 18):
  `ACCENT` green for good / pass, `WARN` amber for sandbox / caution, `DANGER` red for
  quarantine / bad, `INFO` blue for neutral tech.
- Caveat: one `>` symbol remains in slide 11 (bullet marker); it renders as a geometric glyph
  in Malgun Gothic, no placeholder.

### 2.4 Virtual coordinate space
Each slide uses `ax.set_xlim(0, 100)` and `ax.set_ylim(0, 141)` — round numbers approximating
A4 portrait ratio (1 : 1.414). Positioning a box at `(10, 80)` is easier to reason about than
absolute inches, and the actual output is still scaled to A4 for print.

### 2.5 SOC theme consistency
The same palette as the dashboard (`#0b1220` background, `#4ade80` accent, etc. — see
`.streamlit/config.toml` from log 18). If someone later screenshots the dashboard next to a
slide, they match.

## 3. Content choices

### 3.1 What the 5-minute brief had to cover (from the user)
1. Simplified overall structure → **slide 3** (one full diagram)
2. Results → **slides 9–10** (model performance + latency)
3. What differs from `guide.pdf` → **slide 11** (7 deviations with brief rationale)

### 3.2 Everything else is scaffolding for those three
- Slides 1–2 set up what the project is (10 seconds each).
- Slides 4–8 give one slide to each subsystem so the architecture (slide 3) has substance
  behind it — ~25 seconds each in a brief talk.
- Slide 12 closes with stats and open items; a presenter can use it as the final "what's next"
  moment.

### 3.3 Honest results, not sales pitch
Slide 9 shows the **test FPR drift (0.10% → 0.21%, 8.5σ)** prominently in red. This is the
most important finding from log 10 and the one most worth defending in Q&A. A presentation
that hid it would misrepresent the project.

### 3.4 Difference list phrased as "guide → axi"
Every row of slide 11 is `guide's way → axi's way`, with a one-line why. This makes it clear
the deviations are **deliberate design choices**, not shortcuts.

## 4. Troubleshooting notes (for future PDF generation)

- **`sed` on Windows/Git Bash with multi-byte characters** silently fails for some emoji
  Unicode points (`📌` U+1F4CC survived two sed passes). Use Python with `encoding="utf-8"`
  for emoji replacements instead.
- **`UnicodeEncodeError: 'cp949' codec can't encode character` inside `print()`** in Python
  inline scripts: `sys.stdout.reconfigure(encoding="utf-8")` fixes it (same cp949 issue from
  log 07 §4).
- **Verify with PNG previews** before trusting the PDF: `fig.savefig(…, dpi=85)` catches
  missing-glyph warnings that `PdfPages` silently falls back on.

## 5. Not done
- No tests for the presentation script. Visual QA is a PNG preview per slide, done once in
  this step.
- Not wired into `scripts/check_env.py`; it's an ad-hoc deliverable.
