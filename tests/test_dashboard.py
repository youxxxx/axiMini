"""Streamlit AppTest smoke test: the dashboard must render without exceptions on all four tabs.

AppTest runs the script in-process against a fake Streamlit runtime; it catches NameError,
TypeError, bad column access etc. that would 500 in a real browser. It doesn't check layout.
"""

from pathlib import Path

import pytest

st_testing = pytest.importorskip("streamlit.testing.v1", reason="streamlit testing missing")

APP = Path(__file__).resolve().parent.parent / "dashboard" / "app.py"


def _run():
    at = st_testing.AppTest.from_file(str(APP), default_timeout=20)
    at.run()
    assert not at.exception, [str(e) for e in at.exception]
    return at


def test_dashboard_runs_with_real_db():
    at = _run()
    # The sidebar header and page header must be present whether or not events exist.
    assert any("axiMini SOC" in b.value for b in at.sidebar.title)
    assert any("실시간 보안 관제" in t.value for t in at.title)


def test_all_tabs_render():
    """AppTest doesn't auto-execute every tab; it does evaluate the script linearly, so each tab's
    body ran during _run(). This just asserts the tabs exist by their Korean labels."""
    at = _run()
    labels = [t.label for t in at.tabs]
    assert labels == ["이벤트 상세", "격리소", "조치 기록", "모델 & 지표"]
