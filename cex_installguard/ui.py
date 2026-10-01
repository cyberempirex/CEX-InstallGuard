"""Animated terminal UI primitives for CEX-InstallGuard (stdlib-only).

Professional scan feedback, in the spirit of modern tool CLIs:

* :class:`Spinner` — a *thread-driven* spinner that animates while real
  work happens in the main thread (the v11 spinner merely slept for a
  fixed duration).
* :class:`ScanProgress` — a live one-line status: spinner + progress bar +
  files done/total + the file being scanned + elapsed time.
* :func:`risk_meter` — an animated fill of the final risk bar.

Everything degrades gracefully: when stdout is not a TTY (CI logs, piped
output) or colors are disabled, nothing animates and a single plain
summary line is printed instead. The cursor is always restored, even on
errors, via ``stop()``/``finish()`` in ``finally`` blocks.
"""
from __future__ import annotations

import shutil
import sys
import threading
import time

from .terminal import CYAN, GRAY, GREEN, RED, TEAL, YELLOW, paint, enabled

SPIN_FRAMES = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
HIDE_CURSOR = '\x1b[?25l'
SHOW_CURSOR = '\x1b[?25h'
ERASE_LINE = '\x1b[2K'


def _is_tty(color: bool) -> bool:
    return enabled(color) and sys.stdout.isatty()


def _short(path: str, limit: int = 32) -> str:
    p = path.rsplit('/', 1)[-1] if path else ''
    return p[:limit] + ('…' if len(p) > limit else '')


class _Animator:
    """Shared machinery: a background thread that is the only stdout writer."""

    def __init__(self, color: bool = True, interval: float = 0.07):
        self._color = color
        self._interval = interval
        self._thread: threading.Thread | None = None
        self._stop_evt = threading.Event()
        self._lock = threading.Lock()
        self._hidden = False

    # -- lifecycle ---------------------------------------------------------- #

    def _begin(self) -> None:
        if _is_tty(self._color):
            sys.stdout.write(HIDE_CURSOR)
            sys.stdout.flush()
            self._hidden = True
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def _end(self) -> None:
        self._stop_evt.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None
        if self._hidden:
            sys.stdout.write('\r' + ERASE_LINE + SHOW_CURSOR)
            sys.stdout.flush()
            self._hidden = False

    def _run(self) -> None:
        i = 0
        while not self._stop_evt.wait(self._interval):
            line = self._frame(i)
            i += 1
            if line is not None:
                sys.stdout.write('\r' + ERASE_LINE + line)
                sys.stdout.flush()

    # -- overrides ------------------------------------------------------------ #

    def _frame(self, i: int) -> str | None:
        raise NotImplementedError


class Spinner(_Animator):
    """Context-manager spinner: ``with Spinner('Loading rules'): …``"""

    def __init__(self, label: str = 'Working', color: bool = True,
                 interval: float = 0.07):
        super().__init__(color, interval)
        self._label = label

    def __enter__(self) -> 'Spinner':
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self) -> None:
        self._begin()

    def stop(self) -> None:
        self._end()

    def _frame(self, i: int) -> str | None:
        return f'  {paint(SPIN_FRAMES[i % len(SPIN_FRAMES)], CYAN, _is_tty(self._color))}  {self._label}…'


class ScanProgress(_Animator):
    """Live scan status line driven by the scanner's progress callback.

    Signature-compatible with ``scanner.ProgressCallback``:
    ``update(done, total, path)``.
    """

    def __init__(self, label: str = 'Scanning', color: bool = True,
                 width: int = 22):
        super().__init__(color)
        self._label = label
        self._width = width
        self._t0 = time.monotonic()
        self._done = 0
        self._total = 0
        self._current = ''

    # -- callback API ---------------------------------------------------------- #

    def update(self, done: int, total: int, path: str) -> None:
        with self._lock:
            self._done, self._total, self._current = done, total, path

    def start(self) -> None:
        self._t0 = time.monotonic()
        self._begin()

    def cancel(self) -> None:
        """Stop animating without printing a summary."""
        self._end()

    def finish(self, files: int | None = None, findings: int | None = None) -> None:
        """Stop animating and print a plain-text completion summary."""
        elapsed = time.monotonic() - self._t0
        self._end()
        done = self._done if files is None else files
        cur = '' if findings is None else f' · {findings} findings'
        print(f'  Scan complete · {done} file{"s" if done != 1 else ""}'
              f'{cur} · {elapsed:.2f}s')

    # -- rendering -------------------------------------------------------------- #

    def status_text(self) -> str:
        """Current status line (also used in tests)."""
        with self._lock:
            done, total, path = self._done, self._total, self._current
        pct = 100 if total == 0 else int(done * 100 / total)
        filled = round(self._width * max(0, min(100, pct)) / 100)
        elapsed = time.monotonic() - self._t0
        on = _is_tty(self._color)
        bar = paint('█' * filled, CYAN, on) + paint('░' * (self._width - filled),
                                                    GRAY, on)
        label = paint(f'{SPIN_FRAMES[0]} {self._label}', CYAN, on)
        return (f'  {label} {bar} {done}/{total} ({pct}%) '
                f'· {_short(path)} · {elapsed:5.1f}s')

    def _frame(self, i: int) -> str | None:
        with self._lock:
            done, total, path = self._done, self._total, self._current
        pct = 100 if total == 0 else int(done * 100 / total)
        filled = round(self._width * max(0, min(100, pct)) / 100)
        elapsed = time.monotonic() - self._t0
        on = True
        bar = paint('█' * filled, CYAN, on) + paint('░' * (self._width - filled),
                                                    GRAY, on)
        spin = paint(SPIN_FRAMES[i % len(SPIN_FRAMES)], CYAN, on)
        return (f'  {spin} {self._label} {bar} {done}/{total} ({pct}%) '
                f'· {_short(path)} · {elapsed:5.1f}s')


def risk_meter(score: int, color: bool = True, steps: int = 24,
               delay: float = 0.016) -> None:
    """Animate the final risk bar filling up, then leave it on screen."""
    if not _is_tty(color):
        return
    verdict_color = RED if score >= 70 else YELLOW if score >= 30 else GREEN
    width = 30
    for step in range(1, steps + 1):
        current = round(score * width * step / (steps * 100))
        bar = paint('█' * current, verdict_color, True) + \
            paint('░' * (width - current), GRAY, True)
        sys.stdout.write(f'\r  Risk  {bar} {score * step // steps:>3}/100')
        sys.stdout.flush()
        if step < steps:
            time.sleep(delay)
    sys.stdout.write('\n')
    sys.stdout.flush()


def color_depth_ok() -> bool:
    """True when the terminal is likely to render box/bar glyphs."""
    return _is_tty(True) and shutil.get_terminal_size((80, 24)).columns >= 60
