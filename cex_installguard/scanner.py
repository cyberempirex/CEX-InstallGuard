"""Scanning pipeline for CEX-InstallGuard v12.

Pipeline per file:

1. **Parse** the source with the structured shell parser
   (:mod:`cex_installguard.shellparser`).
2. **Analyze** the AST with the dataflow-aware rule engine
   (:mod:`cex_installguard.analyzer`).
3. **Content layer** — a slim set of textual rules (fork bombs, encoded
   blobs, indicator keywords) over comment-stripped lines.
4. **Dedupe** by (rule, line, normalized code) and sort deterministically.

Repository scans additionally: honor configured ignore paths, skip binary
files instead of erroring, and sort all findings by location so results do
not depend on worker scheduling.
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from .analyzer import Analyzer
from .models import Finding, ScanResult
from .parser import normalize
from .rules import KEYWORDS, RULES
from .scoring import assess

EXTS = {'.sh', '.bash', '.zsh', '.ksh', '.dash', '.command', '.inc'}
NAMES = {'install', 'bootstrap', 'setup', 'configure', 'uninstall', 'entrypoint'}
DEFAULT_SKIP = {'.git', '.hg', '.svn', '.venv', 'venv', 'node_modules',
                '__pycache__', '.tox', '.mypy_cache', '.pytest_cache'}
DEFAULT_MAX_SIZE = 5_242_880          # 5 MiB
BINARY_SNIFF = 8192

ProgressCallback = Callable[[int, int, str], None]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Single-file scanning                                                         #
# --------------------------------------------------------------------------- #

def looks_binary(data: bytes) -> bool:
    """Heuristic binary detection: NUL byte or undecodable UTF-8."""
    if b'\x00' in data[:BINARY_SNIFF]:
        return True
    try:
        data[:BINARY_SNIFF].decode('utf-8')
        return False
    except UnicodeDecodeError:
        return True


def scan_text(text: str, source: str = '<text>', rules=None) -> list[Finding]:
    """Scan one script's text: structural analysis + content rules."""
    findings: list[Finding] = []

    # normalize line endings so CRLF files parse identically
    text = text.replace('\r\n', '\n').replace('\r', '\n')

    # 1-2. structural analysis (AST + dataflow)
    findings.extend(Analyzer(source).analyze(text))

    # 1b. de-obfuscation pass: ${IFS}/$IFS used as word separator is a
    # common evasion; re-scan a space-normalized copy and merge findings.
    if re.search(r'\$\{?IFS\}?', text):
        deobf = re.sub(r'\$\{IFS\}|\$IFS', ' ', text)
        findings.extend(Analyzer(source).analyze(deobf))

    # 3. content layer (runs on comment-stripped raw lines: encoded blobs
    # live inside quotes, which string-masking would hide)
    lines = normalize(text.splitlines())
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        for rule in (rules if rules is not None else RULES):
            m = re.search(rule.pattern, line, re.I)
            if m:
                findings.append(Finding(
                    rule.rule_id, rule.title, rule.severity, rule.category,
                    rule.confidence, n, max(1, m.start() + 1), line.strip(),
                    rule.description, rule.remediation, source=source))
        low = line.lower()
        for kw, sev in KEYWORDS.items():
            pos = low.find(kw)
            if pos >= 0:
                findings.append(Finding(
                    'KW001', 'Suspicious security keyword', sev, 'indicator',
                    'medium', n, pos + 1, line.strip(),
                    f'Source contains indicator keyword: {kw}.',
                    'Review manually; a keyword alone is not proof of '
                    'maliciousness.', source=source,
                    evidence={'keyword': kw}))
                break

    # 4. deterministic order + dedupe
    findings.sort(key=lambda f: (f.line, f.rule_id,
                                 ' '.join(f.code.split())))
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        k = (f.rule_id, f.source, f.line, ' '.join(f.code.split()))
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def scan_file(path, max_size: int = DEFAULT_MAX_SIZE):
    """Read and scan one file.

    Returns ``(text, findings, sha256, note)``. ``note`` is a short string
    when the file was skipped ('binary' or 'too-large'); errors raise.
    """
    p = Path(path)
    st = p.stat()
    if st.st_size > max_size:
        return None, [], '', 'too-large'
    data = p.read_bytes()
    digest = sha256(data)
    if looks_binary(data):
        return None, [], digest, 'binary'
    text = data.decode('utf-8', errors='replace')
    return text, scan_text(text, str(p)), digest, None


# --------------------------------------------------------------------------- #
# Discovery                                                                    #
# --------------------------------------------------------------------------- #

def candidates(root, recursive: bool = True,
               ignore_paths: list[str] | None = None) -> list[Path]:
    """Discover shell/install files under ``root`` (never executes anything).

    ``ignore_paths`` entries may be directory names (``node_modules``) or
    glob patterns matched against every path prefix (``build/*``).
    """
    p = Path(root)
    if p.is_file():
        return [p]
    if not p.exists():
        raise FileNotFoundError(str(p))
    ignore_names = set(DEFAULT_SKIP)
    ignore_globs: list[str] = []
    for ig in (ignore_paths or []):
        if any(ch in ig for ch in '*?['):
            ignore_globs.append(ig)
        else:
            ignore_names.add(ig)

    import fnmatch
    it = p.rglob('*') if recursive else p.glob('*')
    out = []
    for x in it:
        if not x.is_file():
            continue
        parts = x.relative_to(p).parts if x != p else ()
        if any(part in ignore_names for part in parts):
            continue
        rel = '/'.join(parts)
        if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(part, g)
               for g in ignore_globs for part in parts):
            continue
        if x.suffix.lower() in EXTS or x.name in NAMES or os.access(x, os.X_OK):
            out.append(x)
    return sorted(set(out))


# --------------------------------------------------------------------------- #
# Repository scanning                                                          #
# --------------------------------------------------------------------------- #

def scan_path(path, recursive: bool = True, max_size: int = DEFAULT_MAX_SIZE,
              workers: int = 4, progress_callback: ProgressCallback | None = None,
              ignore_paths: list[str] | None = None) -> ScanResult:
    """Scan a file or directory tree. Deterministic regardless of workers."""
    start = time.perf_counter()
    paths = candidates(path, recursive, ignore_paths)
    r = ScanResult(str(path), files=0, metadata={
        'workers': max(1, workers), 'recursive': recursive,
        'discovered': len(paths)})

    def one(p: Path):
        try:
            text, fs, digest, note = scan_file(p, max_size)
            return p, text, fs, digest, note, None
        except Exception as e:  # noqa: BLE001 — surface per-file failures
            return p, None, [], None, None, str(e)

    skipped_binary: list[str] = []
    if not paths:
        r.errors.append('No supported shell/install files were discovered.')
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(paths) or 1))) as ex:
        futures = [ex.submit(one, p) for p in paths]
        for fut in as_completed(futures):
            p, text, fs, digest, note, err = fut.result()
            if err:
                r.errors.append(err)
                continue
            if note == 'binary':
                skipped_binary.append(str(p))
                continue
            if note == 'too-large':
                skipped_binary.append(str(p) + ' (over size limit)')
                continue
            r.files += 1
            r.lines += len(text.splitlines())
            r.bytes_read += len(text.encode())
            r.findings.extend(fs)
            if progress_callback:
                progress_callback(r.files, len(paths), str(p))
    r.duration_ms = (time.perf_counter() - start) * 1000
    # deterministic output: independent of worker completion order
    r.findings.sort(key=lambda f: (f.source, f.line, f.rule_id,
                                   ' '.join(f.code.split())))
    r.metadata['scan_errors'] = list(r.errors)
    r.metadata['skipped_binary'] = sorted(skipped_binary)
    return r
