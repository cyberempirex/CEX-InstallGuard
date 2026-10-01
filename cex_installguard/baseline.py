"""Baseline suppression for CEX-InstallGuard v12.

Fingerprints v2 are stable across line edits and whitespace changes:

    ``RULEID | source | normalized-code | ordinal``

* ``normalized-code`` is the evidence with all whitespace collapsed, so
  reformatting does not resurrect a suppressed finding.
* ``ordinal`` is the nth occurrence of the same rule+code in the file, so
  findings remain distinguishable without depending on line numbers.

Legacy v1 fingerprints (``RULEID:source:line:code``) are still computed
when applying, so baselines saved by v10/v11 keep working until they are
regenerated.
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, ScanResult
from .version import VERSION

FORMAT_V2 = 'cex-installguard-baseline-v2'


def _norm(code: str) -> str:
    return ' '.join(code.split())


def fingerprint_v2(f: Finding, ordinal: int) -> str:
    return f'{f.rule_id}|{f.source}|{_norm(f.code)}|{ordinal}'


def fingerprint_v1(f: Finding) -> str:
    """Legacy v10/v11 fingerprint (line-number dependent)."""
    return f'{f.rule_id}:{f.source}:{f.line}:{f.code.strip()}'


def _v2_map(findings: list[Finding]) -> dict[int, str]:
    """Ordinal-aware v2 fingerprint per finding index."""
    counts: dict[tuple, int] = {}
    out: dict[int, str] = {}
    for i, f in enumerate(findings):
        key = (f.rule_id, f.source, _norm(f.code))
        counts[key] = counts.get(key, 0) + 1
        out[i] = fingerprint_v2(f, counts[key])
    return out


def save(r: ScanResult, p) -> None:
    active = r.active()
    fps = [_v2_map(active)[i] for i in range(len(active))]
    Path(p).write_text(json.dumps({
        'format': FORMAT_V2, 'version': VERSION, 'target': r.target,
        'fingerprints': fps}, indent=2), encoding='utf-8')


def load(p) -> dict:
    """Load a baseline: returns {'v2': set, 'v1': set, 'target': str}.

    The format field decides which fingerprint generation the file holds;
    within one file all fingerprints are the same generation. (Evidence
    text can contain ``|`` characters, so fingerprints themselves are never
    sniffed by shape.)
    """
    raw = json.loads(Path(p).read_text(encoding='utf-8'))
    fps = [f for f in raw.get('fingerprints', []) if isinstance(f, str)]
    if raw.get('format') == FORMAT_V2:
        v2, v1 = set(fps), set()
    else:
        v2, v1 = set(), set(fps)
    return {'v2': v2, 'v1': v1, 'target': raw.get('target')}


def apply(r: ScanResult, b: dict) -> ScanResult:
    """Suppress findings matching either fingerprint generation."""
    v2 = _v2_map(r.findings)
    for i, f in enumerate(r.findings):
        if v2[i] in b.get('v2', ()) or fingerprint_v1(f) in b.get('v1', ()):
            f.suppressed = True
    return r
