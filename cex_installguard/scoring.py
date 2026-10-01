"""Risk scoring, verdicts and exit-code policy.

The score is a 0–100 risk index built from severity weights, adjusted by
each finding's confidence and compressed with diminishing returns so that a
pile of low-grade findings cannot masquerade as a critical one, and a few
severe findings still reach the top of the scale.

Verdict ladder (worst match wins):

==============  =========================================================
Verdict         Condition
==============  =========================================================
``BLOCK``       any active critical finding
``REVIEW``      any active high finding, or score >= 60
``CAUTION``     any active medium finding, or score >= 30
``LOW-SIGNAL``  any active low finding
``NO-FINDINGS`` nothing matched (this is *not* a proof of safety)
==============  =========================================================
"""
from __future__ import annotations

import math

from .models import ScanResult

SEVERITY_WEIGHT: dict[str, float] = {
    'critical': 40.0, 'high': 25.0, 'medium': 10.0, 'low': 3.0,
}

# Confidence multipliers: a low-confidence match should not weigh like a
# certain one. Unknown confidence values fall back to ``medium``.
CONFIDENCE_MULTIPLIER: dict[str, float] = {
    'high': 1.0, 'medium': 0.6, 'low': 0.3,
}

# Compression constant: score = 100 * (1 - 2 ** (-raw / COMPRESS)).
# One critical (raw 40) scores 37; two (raw 59) score 50; a large pile of
# lows saturates far below a critical because of per-group log damping.
COMPRESS = 60.0

SEVERITY_ORDER = ('critical', 'high', 'medium', 'low')


def raw_score(findings) -> float:
    """Uncompressed weighted severity total.

    Each severity group is aggregated with logarithmic damping
    (``weight * (1 + log10(1 + count))``) so that ten medium findings add
    up to far less than ten times one medium, and no volume of low findings
    can outweigh a single critical one. Confidence further scales each
    group's contribution.
    """
    buckets: dict[tuple[str, str], int] = {}
    for f in findings:
        key = (f.severity, f.confidence)
        buckets[key] = buckets.get(key, 0) + 1
    total = 0.0
    for (severity, confidence), count in buckets.items():
        weight = SEVERITY_WEIGHT.get(severity, 1.0)
        damping = 1 + math.log10(1 + count)
        total += weight * damping * CONFIDENCE_MULTIPLIER.get(confidence, 0.6)
    return total


def score(findings) -> int:
    """Compressed 0–100 risk index for an iterable of findings."""
    return int(round(100 * (1 - 2 ** (-raw_score(findings) / COMPRESS))))


def assess(result: ScanResult) -> ScanResult:
    """Attach score, verdict and risk drivers to a scan result in place."""
    active = result.active()
    result.score = score(active)
    c = result.counts()
    if c['critical']:
        result.verdict = 'BLOCK'
    elif c['high'] or result.score >= 60:
        result.verdict = 'REVIEW'
    elif c['medium'] or result.score >= 30:
        result.verdict = 'CAUTION'
    elif c['low']:
        result.verdict = 'LOW-SIGNAL'
    else:
        result.verdict = 'NO-FINDINGS'
    result.metadata['risk_drivers'] = sorted(
        ((f.rule_id, f.severity, f.category) for f in active),
        key=lambda x: (-SEVERITY_WEIGHT.get(x[1], 0), x[0]))[:10]
    result.metadata['raw_score'] = round(raw_score(active), 1)
    return result


def exit_code(r: ScanResult) -> int:
    """Process exit code: 0 clean, 1 scan error, 2 high/critical findings."""
    if r.errors and not r.active():
        return 1
    return 2 if (r.counts()['critical'] or r.counts()['high']) else 0
