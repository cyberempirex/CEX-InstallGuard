#!/usr/bin/env python3
"""Regenerate docs/rules.md from the rule registry.

Run from the repository root:

    python tools/generate_docs.py

This guarantees the published rule catalogue matches the executable
registry exactly — no hand-maintained counts, no stale rule lists.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cex_installguard.rules import (all_rules, rule_count, structural_ids)
from cex_installguard.version import VERSION

SECTIONS = [
    ('Remote execution & supply chain',
     {'IG001', 'IG034', 'IG011', 'IG047', 'IG048', 'IG031', 'IG032',
      'IG016'}),
    ('Network retrieval hygiene',
     {'IG014', 'IG035', 'IG036', 'IG037', 'IG023'}),
    ('Destructive operations',
     {'IG002', 'IG019', 'IG030', 'IG003', 'IG004', 'IG005', 'IG025'}),
    ('Privilege & permissions',
     {'IG006', 'IG007', 'IG008', 'IG046', 'IG040'}),
    ('System configuration & persistence',
     {'IG009', 'IG013', 'IG021', 'IG038', 'IG039', 'IG045', 'IG033'}),
    ('Evasion & defense tampering',
     {'IG017', 'IG026', 'IG027', 'IG041', 'IG042'}),
    ('Obfuscation & dynamic execution',
     {'IG010', 'IG015', 'IG024', 'IG043', 'IG022', 'IG044'}),
    ('Environment & secrets',
     {'IG020', 'IG018', 'IG029'}),
    ('Staging & dependencies',
     {'IG028', 'IG012'}),
]

_structural = structural_ids()


def render() -> str:
    out = [
        '# Rule Engine',
        '',
        f'Generated from the executable registry — {rule_count()} rules for '
        f'CEX-InstallGuard {VERSION}.',
        'Regenerate with `python tools/generate_docs.py`.',
        '',
        'Rules are evaluated in two layers:',
        '',
        '- **Structural rules** — analyzed from the parsed shell AST '
        '(commands, arguments, redirections) plus cross-line dataflow. '
        'This is the primary detection layer.',
        '- **Content rules** — textual patterns for signals that are not '
        'command-shaped (fork bombs, encoded blobs).',
        '',
        '## Rule catalogue',
        '',
    ]
    used: set[str] = set()
    for title, ids in SECTIONS:
        rows = [r for r in all_rules() if r.rule_id in ids]
        used |= ids
        out += [f'### {title}', '',
                '| ID | Severity | Confidence | Layer | Title |',
                '|----|----------|-------------|-------|-------|']
        for r in sorted(rows, key=lambda x: x.rule_id):
            layer = 'structural' if r.rule_id in _structural else 'content'
            out.append(f'| {r.rule_id} | {r.severity} | {r.confidence} | '
                       f'{layer} | {r.title} |')
        out.append('')
    leftovers = [r for r in all_rules() if r.rule_id not in used]
    if leftovers:
        out += ['### Other', '',
                '| ID | Severity | Confidence | Layer | Title |',
                '|----|----------|-------------|-------|-------|']
        for r in sorted(leftovers, key=lambda x: x.rule_id):
            layer = 'structural' if r.rule_id in _structural else 'content'
            out.append(f'| {r.rule_id} | {r.severity} | {r.confidence} | '
                       f'{layer} | {r.title} |')
        out.append('')

    out += [
        '### Keyword indicators',
        '',
        '| ID | Title |',
        '|----|-------|',
        '| KW001 | Suspicious security keyword (backdoor, ransomware, '
        'rootkit, …) |',
        '',
        '## Remediation guidance',
        '',
        'Every finding carries its remediation inline (CLI `FIX` line, '
        'report `remediation` field). The registry in '
        '`cex_installguard/rules.py` is the single source of truth for '
        'titles, severities, categories, confidence and remediation text.',
        '',
    ]
    return '\n'.join(out) + '\n'


if __name__ == '__main__':
    doc = render()
    path = Path(__file__).resolve().parent.parent / 'docs' / 'rules.md'
    path.write_text(doc, encoding='utf-8')
    print(f'wrote {path} ({rule_count()} rules)')
