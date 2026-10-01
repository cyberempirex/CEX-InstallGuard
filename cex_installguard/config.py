"""Configuration loading and discovery.

Follows the shellcheck RC-file convention: unless disabled with ``--no-rc``,
a project file named ``.cex-installguard.json`` is searched in the target's
directory and each parent directory (up to the filesystem root), then in
the user's home directory. The first file found wins; an explicit
``--config PATH`` always takes precedence.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

RC_NAME = '.cex-installguard.json'
IGNORE_NAME = '.installguardignore'

DEFAULT = {
    'max_file_size': 5242880,
    'workers': 4,
    'recursive': True,
    'disabled_rules': [],
    'ignore_paths': ['.git', '.venv', 'venv', 'node_modules'],
}


def load(path=None):
    """Load explicit config, or defaults when no path is given."""
    if not path:
        return DEFAULT.copy()
    x = DEFAULT.copy()
    x.update(json.loads(Path(path).read_text(encoding='utf-8')))
    return x


def discover(target=None, use_rc=True) -> tuple[dict | None, str | None]:
    """Find and load the nearest ``.cex-installguard.json``.

    Search order: the target's directory and each parent, then the user's
    home directory. Returns ``(config, path)`` — ``(None, None)`` when no
    file is found or discovery is disabled.
    """
    if not use_rc:
        return None, None
    candidates: list[Path] = []
    if target:
        start = Path(target)
        start = start if start.is_dir() else start.parent
        if start.is_dir():
            candidates.extend([start, *start.parents])
    home = Path.home()
    candidates.append(home)
    for d in candidates:
        f = d / RC_NAME
        try:
            if f.is_file():
                cfg = DEFAULT.copy()
                cfg.update(json.loads(f.read_text(encoding='utf-8')))
                return cfg, str(f)
        except (OSError, ValueError):
            continue                     # unreadable/invalid: keep looking
    return None, None


def load_ignore_file(root) -> list[str]:
    """Read gitignore-style patterns from ``.installguardignore``.

    Each non-blank, non-comment line is a glob pattern (shell-style,
    matched against paths relative to the scan root, like
    ``.semgrepignore``). Leading ``!`` is not supported.
    """
    if not root:
        return []
    p = Path(root)
    p = p if p.is_dir() else p.parent
    f = p / IGNORE_NAME
    if not f.is_file():
        return []
    patterns = []
    try:
        for line in f.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('!'):
                patterns.append(line)
    except OSError:
        return []
    return patterns


def color_requested(explicit: str | None = None,
                    no_color_flag: bool = False) -> bool:
    """Resolve whether ANSI color should be used.

    Precedence (following the NO_COLOR / CLICOLOR conventions):
    ``--no-color`` flag → ``--color`` flag → ``CLICOLOR_FORCE`` →
    ``NO_COLOR`` environment → TTY auto-detection.
    """
    if no_color_flag:
        return False
    if explicit == 'always':
        return True
    if explicit == 'never':
        return False
    # explicit 'auto' or unset → environment, then TTY.
    # NO_COLOR wins over CLICOLOR_FORCE (no-color.org + bixense
    # CLICOLOR conventions: CLICOLOR_FORCE applies only when NO_COLOR
    # is unset).
    if os.environ.get('NO_COLOR'):
        return False
    if os.environ.get('CLICOLOR_FORCE'):
        return True
    import sys
    return sys.stdout.isatty()
