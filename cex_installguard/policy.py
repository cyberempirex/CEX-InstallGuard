"""Exit-code policy.

* ``0`` — no finding at/above the ``--fail-on`` threshold and no blocking error
* ``1`` — scan/input error without qualifying findings
* ``2`` — at least one finding at/above the threshold (default: high)

The severity ladder lives in :mod:`cex_installguard.scoring`.
"""
from .scoring import SEVERITY_ORDER, exit_code  # re-export

__all__ = ['exit_code', 'SEVERITY_ORDER']


def exit_code_at(r, fail_on: str = 'high') -> int:
    """Exit code when the failure threshold is set to ``fail_on``."""
    if fail_on in ('none', None):
        return 1 if (r.errors and not r.active()) else 0
    floor = SEVERITY_ORDER.index(fail_on)
    active_sevs = {SEVERITY_ORDER.index(f.severity)
                   for f in r.active() if f.severity in SEVERITY_ORDER}
    if any(s <= floor for s in active_sevs):
        return 2
    return 1 if (r.errors and not r.active()) else 0
