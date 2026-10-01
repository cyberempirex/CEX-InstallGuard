"""Command-line interface for CEX-InstallGuard.

Runs entirely offline with the Python standard library; target content is
never executed. Omitting ``target`` opens the interactive console.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .baseline import apply as apply_baseline, load as load_baseline
from .baseline import save as save_baseline
from .config import color_requested, discover, load as load_config
from .config import load_ignore_file
from .interactive import launch
from .policy import exit_code_at
from .reporter import html_report, json_report, sarif_report
from .rules import all_rules, rule_count
from .scanner import assess, scan_path
from .scoring import SEVERITY_ORDER
from .suppressions import apply as apply_suppressions
from .terminal import render
from .ui import ScanProgress, Spinner, risk_meter
from .version import VERSION


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='cex-installguard',
        description=('CEX-InstallGuard — static shell and installer security '
                     'analysis. Target scripts are never executed.'))
    p.add_argument('target', nargs='?',
                   help='file or directory; omit to open the interactive console')
    p.add_argument('-r', '--recursive', action='store_true',
                   help='scan directories recursively')
    p.add_argument('--workers', type=int, default=4, metavar='N',
                   help='parallel scan workers (default: 4)')
    p.add_argument('--max-size', type=int, default=5242880, metavar='BYTES',
                   help='per-file size limit (default: 5 MiB)')
    p.add_argument('--min-severity', choices=SEVERITY_ORDER, default=None,
                   help='suppress findings below this severity before scoring')
    p.add_argument('--exclude', action='append', default=[], metavar='GLOB',
                   help='exclude paths matching a glob (e.g. vendor/*); repeatable')
    p.add_argument('--fail-on', choices=('critical', 'high', 'medium', 'low', 'none'),
                   default='high', metavar='SEV',
                   help='minimum severity that produces exit code 2 (default: high)')
    p.add_argument('--quiet', action='store_true',
                   help='print only the verdict line and findings')
    p.add_argument('--json', metavar='PATH', help='write a JSON report')
    p.add_argument('--sarif', metavar='PATH', help='write a SARIF 2.1.0 report')
    p.add_argument('--html', metavar='PATH', help='write a standalone HTML report')
    p.add_argument('--rules', action='store_true',
                   help='list the detection rule registry and exit')
    p.add_argument('--config', metavar='PATH', help='JSON configuration file')
    p.add_argument('--baseline', metavar='PATH',
                   help='suppress findings matching this saved baseline')
    p.add_argument('--save-baseline', metavar='PATH',
                   help='save the current scan as a baseline')
    p.add_argument('--suppress', action='append', default=[], metavar='REGEX',
                   help='suppress by rule ID or source line regex; repeatable')
    p.add_argument('--no-color', action='store_true',
                   help='disable ANSI colors (same as --color=never)')
    p.add_argument('--color', choices=('auto', 'always', 'never'),
                   default='auto', metavar='WHEN',
                   help='when to use ANSI color (default: auto; honors '
                        'NO_COLOR and CLICOLOR_FORCE)')
    p.add_argument('--no-rc', action='store_true',
                   help='do not search for a .cex-installguard.json project '
                        'config (shellcheck-style discovery)')
    p.add_argument('--compact', action='store_true', help='one-line summary output')
    p.add_argument('--version', action='version',
                   version=f'CEX-InstallGuard {VERSION}')
    return p


def _apply_min_severity(result, severity: str | None) -> None:
    """Suppress findings below ``severity`` (config layer, kept out of scoring)."""
    if not severity:
        return
    floor = SEVERITY_ORDER.index(severity)
    allowed = set(SEVERITY_ORDER[:floor + 1])
    for f in result.findings:
        if f.severity not in allowed:
            f.suppressed = True


def _print_registry() -> int:
    print(f'CEX-InstallGuard {VERSION} — {rule_count()} detection rules\n')
    print(f'{"ID":8}{"SEVERITY":10}{"CATEGORY":22}{"CONF":7}TITLE')
    print('-' * 78)
    for r in all_rules():
        print(f'{r.rule_id:8}{r.severity:10}{r.category:22}{r.confidence:7}{r.title}')
    print('\nDetection layers: structured AST analysis + dataflow + content patterns')
    print('Keyword indicators: KW001')
    return 0


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)

    if a.rules:
        return _print_registry()
    if not a.target:
        return launch()

    use_color = color_requested(a.color, a.no_color)

    # project config: explicit --config wins; otherwise shellcheck-style
    # discovery (.cex-installguard.json in the target dir and parents)
    if a.config:
        cfg = load_config(a.config)
    else:
        discovered, rc_path = discover(a.target, use_rc=not a.no_rc)
        cfg = discovered if discovered is not None else load_config(None)
        if rc_path and not a.quiet:
            print(f'  Using project config: {rc_path}', file=sys.stderr)

    recursive = a.recursive or (cfg.get('recursive', False)
                                and Path(a.target).is_dir())
    max_size = a.max_size if a.max_size != 5242880 \
        else int(cfg.get('max_file_size', 5242880))
    workers = a.workers if a.workers != 4 else int(cfg.get('workers', 4))

    ignore_paths = list(cfg.get('ignore_paths', []))
    # .installguardignore at the scan root (semgrep-style patterns)
    ignore_paths.extend(load_ignore_file(a.target))
    for pattern in a.exclude:
        ignore_paths.append(pattern)

    # live scan progress: animates on a TTY, silent single summary in CI
    progress = ScanProgress('Scanning', color=use_color)
    result = None
    progress.start()
    try:
        result = assess(scan_path(Path(a.target), recursive, max_size, workers,
                                   progress_callback=progress.update,
                                   ignore_paths=ignore_paths))
    finally:
        if result is None or a.quiet:
            progress.cancel()
        else:
            progress.finish(files=result.files)

    disabled = set(cfg.get('disabled_rules', []))
    if disabled:
        for f in result.findings:
            if f.rule_id in disabled:
                f.suppressed = True

    _apply_min_severity(result, a.min_severity)
    if a.baseline and Path(a.baseline).exists():
        apply_baseline(result, load_baseline(a.baseline))
    if a.suppress:
        apply_suppressions(result, a.suppress)
    assess(result)

    if not (a.quiet or a.compact or not use_color):
        risk_meter(result.score)
    render(result, use_color, a.compact, a.quiet)

    if a.json:
        json_report(result, a.json)
    if a.sarif:
        sarif_report(result, a.sarif)
    if a.html:
        html_report(result, a.html)
    if a.save_baseline:
        save_baseline(result, a.save_baseline)
    return exit_code_at(result, a.fail_on)
