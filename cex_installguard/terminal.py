"""Terminal presentation: colors, boxes, banner, dashboard and report render.

All output is decorative; the scanner engine never depends on this module.
"""
from __future__ import annotations

import os
import shutil
import sys
import textwrap
import time

from .version import VERSION

RESET = '\033[0m'; BOLD = '\033[1m'; DIM = '\033[2m'
CYAN = '\033[96m'; BLUE = '\033[94m'; GREEN = '\033[92m'
YELLOW = '\033[93m'; RED = '\033[91m'; MAGENTA = '\033[95m'
WHITE = '\033[97m'; GRAY = '\033[90m'; TEAL = '\033[38;5;43m'
SPIN = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

SEV_COLOR = {'critical': RED, 'high': YELLOW, 'medium': MAGENTA, 'low': CYAN}


def enabled(value=True) -> bool:
    return bool(value and sys.stdout.isatty()
                and os.environ.get('TERM') != 'dumb')


def paint(text, color, on=True):
    return f'{color}{text}{RESET}' if on else text


def clear(on=True):
    if enabled(on):
        print('\033[2J\033[H', end='')


def width(default=76) -> int:
    try:
        return max(64, min(110, shutil.get_terminal_size((default, 24)).columns))
    except OSError:
        return default


def box(title, lines, color=CYAN, color_on=True):
    on = enabled(color_on); w = width(); inner = w - 4
    print(paint('╭' + '─' * (w - 2) + '╮', color, on))
    print(paint('│', color, on)
          + paint('  ' + title.upper().ljust(inner), BOLD + color, on)
          + paint('│', color, on))
    print(paint('├' + '─' * (w - 2) + '┤', color, on))
    for line in lines:
        for part in textwrap.wrap(str(line), inner - 2) or ['']:
            print(paint('│', color, on) + '  ' + part.ljust(inner - 2)
                  + paint('│', color, on))
    print(paint('╰' + '─' * (w - 2) + '╯', color, on))


def banner(color=True):
    on = enabled(color); w = width(); inner = w - 2
    logo = [' ██████╗███████╗██╗  ██╗', '██╔════╝██╔════╝╚██╗██╔╝',
            '██║     █████╗   ╚███╔╝ ', '██║     ██╔══╝   ██╔██╗ ',
            '╚██████╗███████╗██╔╝ ██╗', ' ╚═════╝╚══════╝╚═╝  ╚═╝']
    print(paint('╭' + '─' * inner + '╮', CYAN, on))
    for row in logo:
        print(paint('│', CYAN, on) + paint(row.ljust(inner), BOLD + CYAN, on)
              + paint('│', CYAN, on))
    print(paint('│', CYAN, on)
          + paint('  INSTALLGUARD  •  SHELL & INSTALLER SECURITY'.ljust(inner),
                  WHITE + BOLD, on)
          + paint('│', CYAN, on))
    print(paint('│', CYAN, on)
          + paint(f'  v{VERSION}  •  CyberEmpireX  •  STATIC ANALYSIS'.ljust(inner),
                  TEAL, on)
          + paint('│', CYAN, on))
    print(paint('│', CYAN, on)
          + paint('  INSPECT FIRST. EXECUTE LATER.'.ljust(inner), DIM, on)
          + paint('│', CYAN, on))
    print(paint('╰' + '─' * inner + '╯', CYAN, on))


def section(title, color=CYAN):
    w = width(); label = f'┌─ {title.upper()} '
    print('\n' + paint(label + '─' * max(3, w - len(label) - 1) + '┐',
                      color, enabled(True)))


def spinner(label, on=True, seconds=.45):
    if not enabled(on):
        return
    end = time.monotonic() + seconds; i = 0
    while time.monotonic() < end:
        print(f'\r  {paint(SPIN[i % len(SPIN)], CYAN)}  {label}...',
              end='', flush=True)
        time.sleep(.045); i += 1
    print('\r' + ' ' * max(30, len(label) + 12) + '\r', end='')


def progress(label, pct, on=True, detail=''):
    if not enabled(on):
        return
    n = 34; f = round(n * max(0, min(100, pct)) / 100)
    print(f'\r  {label:<18} {paint("█" * f, CYAN)}'
          f'{paint("░" * (n - f), GRAY)} {pct:3d}%  {detail:<22}',
          end='', flush=True)
    if pct >= 100:
        print()


def _bar(score, n=30):
    filled = round(score * n / 100)
    return '█' * filled + '░' * (n - filled)


def dashboard(r, color=True):
    on = enabled(color); c = r.counts()
    rc = RED if r.score >= 70 else YELLOW if r.score >= 30 else GREEN
    cats = r.categories()
    cat_line = ', '.join(f'{k} ×{v}' for k, v in list(cats.items())[:6]) or 'none'
    lines = [
        f'Risk score   {_bar(r.score, 24)}  {r.score}/100',
        f'Verdict      {r.verdict}',
        f'Files        {r.files:,}    Lines {r.lines:,}    '
        f'Duration {r.duration_ms:.1f} ms',
        f'Findings     C:{c["critical"]}  H:{c["high"]}  '
        f'M:{c["medium"]}  L:{c["low"]}',
        f'Categories   {cat_line}',
    ]
    box('Security Dashboard', lines, rc, on)


def _exit_hint(r) -> str:
    c = r.counts()
    if c['critical'] or c['high']:
        return ('Exit code 2 — high or critical findings present. '
                'Do not run this script before review.')
    if r.metadata.get('scan_errors'):
        return 'Exit code 1 — the scan itself reported errors.'
    return 'Exit code 0 — no high or critical findings matched.'


def render(r, color=True, compact=False, quiet=False):
    """Render a scan result to the terminal.

    ``compact`` prints a one-line summary; ``quiet`` prints findings and the
    verdict without the banner and dashboard.
    """
    on = enabled(color)
    if compact:
        c = r.counts()
        print(f'{r.target} | {r.verdict} | {r.score}/100 | '
              f'C:{c["critical"]} H:{c["high"]} M:{c["medium"]} L:{c["low"]}')
        return
    if not quiet:
        clear(on); banner(color); dashboard(r, color)
    else:
        print(paint(f'{r.verdict}  {r.score}/100  ({len(r.active())} active findings)',
                    SEV_COLOR.get('critical', RED) if r.verdict == 'BLOCK'
                    else YELLOW, on))
    if r.metadata.get('scan_errors'):
        section('Scan Errors', RED)
        for e in r.metadata['scan_errors']:
            print('  ' + e)
    active = r.active()
    if not active:
        box('Analysis Result',
            ['No configured rule matched the analyzed content.',
             'This does not prove the target is safe; static analysis '
             'has limits.'], GREEN, on)
        return
    section('Findings', RED if r.counts()['critical'] else YELLOW)
    for i, f in enumerate(active, 1):
        fc = SEV_COLOR.get(f.severity, CYAN)
        print(f'\n  {paint(f"[{i:02d}]", DIM, on)} '
              f'{paint(f.rule_id, fc + BOLD, on)}  '
              f'{paint(f.severity.upper(), fc, on)}  '
              f'{paint(f.title, BOLD, on)}')
        print(f'      {paint("SOURCE", DIM, on)} {f.source}  '
              f'{paint("LINE", DIM, on)} {f.line}  '
              f'{paint("CONF", DIM, on)} {f.confidence}')
        print(f'      {paint("EVIDENCE", DIM, on)} {f.code[:240]}')
        print(f'      {paint("WHY", DIM, on)} {f.description}')
        print(f'      {paint("FIX", TEAL, on)} {f.remediation}')
    print()
    print(paint(f'  {_exit_hint(r)}', DIM, on))


def menu():
    on = enabled(True)
    entries = [
        ('1', 'Analyze Script', 'Static analysis of one shell / installer file'),
        ('2', 'Scan Repository', 'Recursive scan with worker pool and risk map'),
        ('3', 'Quick Command', 'Analyze one command without executing it'),
        ('4', 'Findings', 'Inspect findings from the last scan'),
        ('5', 'Rule Explorer', 'Search and inspect detection rules'),
        ('6', 'Security Profile', 'Policy, engines, limits and capabilities'),
        ('7', 'Reports', 'Generate JSON, SARIF or HTML'),
        ('8', 'About', 'Product, architecture and security model'),
        ('0', 'Exit', 'Close the security console'),
    ]
    print(paint('╭─ COMMAND CENTER ' + '─' * max(3, width() - 21) + '╮', BLUE, on))
    for k, t, d in entries:
        print(f'│  {paint(k, YELLOW + BOLD, on)}  {paint(t, BOLD, on):<23} '
              f'{paint(d, DIM, on)}')
    print(paint('╰' + '─' * (width() - 1) + '╯', BLUE, on))


def pause():
    try:
        input(paint('\n  Press Enter to return...', MAGENTA, enabled(True)))
    except (EOFError, KeyboardInterrupt):
        print()


def ask(label):
    try:
        return input(paint(f'\n  {label}: ', CYAN, enabled(True))).strip()
    except (EOFError, KeyboardInterrupt):
        print(); return ''
