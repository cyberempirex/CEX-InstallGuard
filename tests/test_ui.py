"""Tests for the animated UI primitives (CI-safe: non-TTY paths)."""
import io
import time
from contextlib import redirect_stdout

from cex_installguard import ui


def test_scan_progress_silent_when_not_tty():
    """Non-TTY (CI, pipes): no live frames, one plain summary at finish."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        sp = ui.ScanProgress('Scanning', color=False)
        sp.start()
        sp.update(1, 3, 'a/b.sh')
        sp.update(2, 3, 'a/c.sh')
        sp.finish(files=3, findings=5)
    out = buf.getvalue()
    assert 'Scanning' not in out          # no live animation frames
    assert 'Scan complete' in out
    assert '3 files' in out and '5 findings' in out
    assert '\x1b[?25l' not in out         # cursor untouched


def test_scan_progress_status_text():
    sp = ui.ScanProgress('Scanning', color=False)
    sp.update(4, 8, '/repo/some/script.sh')
    text = sp.status_text()
    assert '4/8' in text and '(50%)' in text and 'script.sh' in text


def test_spinner_context_manager_quiet():
    buf = io.StringIO()
    with redirect_stdout(buf):
        with ui.Spinner('Loading', color=False):
            time.sleep(0.02)
    assert buf.getvalue() == ''            # nothing animated off-TTY


def test_scan_progress_cancel_is_silent():
    buf = io.StringIO()
    with redirect_stdout(buf):
        sp = ui.ScanProgress('Scanning', color=False)
        sp.start()
        sp.update(1, 2, 'x.sh')
        sp.cancel()
    assert buf.getvalue() == ''


def test_risk_meter_off_tty_noop():
    buf = io.StringIO()
    with redirect_stdout(buf):
        ui.risk_meter(81, color=False)
    assert buf.getvalue() == ''


def test_animated_frame_contains_progress():
    """Frame rendering itself is testable without a TTY."""
    sp = ui.ScanProgress('Scanning', color=False)
    sp.update(1, 4, 'd.sh')
    frame = sp._frame(3)
    assert 'Scanning' in frame and '1/4' in frame and '25%)' in frame


def test_short_path_truncation():
    assert ui._short('') == ''
    long_name = 'x' * 50
    assert len(ui._short(long_name)) <= 33
