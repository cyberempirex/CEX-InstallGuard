"""Report generation: JSON, SARIF 2.1.0 and standalone HTML.

All writers are pure functions of a :class:`ScanResult` — no execution of
target content, no network access.
"""
from __future__ import annotations

import html as _html
import json
import os
from pathlib import Path

from .models import Finding, ScanResult
from .rules import all_rules
from .version import VERSION

SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}


def _ordered(result: ScanResult) -> list[Finding]:
    return sorted(result.active(),
                  key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.source, f.line))


def json_report(r: ScanResult, path: str) -> None:
    """Write the full machine-readable scan result as pretty JSON."""
    Path(path).write_text(json.dumps(r.to_dict(), indent=2), encoding='utf-8')


# --------------------------------------------------------------------------- #
# SARIF 2.1.0                                                                  #
# --------------------------------------------------------------------------- #

def _sarif_level(severity: str) -> str:
    return {'critical': 'error', 'high': 'error',
            'medium': 'warning', 'low': 'note'}.get(severity, 'note')


def sarif_report(r: ScanResult, path: str) -> None:
    """Write a SARIF 2.1.0 log consumable by GitHub Code Scanning et al."""
    rules_meta = [
        {
            'id': rule.rule_id,
            'name': rule.title.replace(' ', '-').lower(),
            'shortDescription': {'text': rule.title},
            'properties': {'severity': rule.severity,
                           'category': rule.category,
                           'confidence': rule.confidence},
            'helpUri': 'https://github.com/cyberempirex/CEX-InstallGuard',
        }
        for rule in all_rules()
    ]
    # checkout-relative URIs (GitHub Code Scanning matches these against
    # files committed at the repo root) + %SRCROOT% base for local viewers
    root = Path(r.target)
    root = root if root.is_dir() else root.parent
    try:
        root_uri = root.resolve().as_uri().rstrip('/') + '/'
    except (OSError, ValueError):
        root_uri = None

    def _rel(uri: str) -> tuple[str, str | None]:
        """Relative URI + uriBaseId for a finding source, if possible."""
        if uri in ('<text>', '<quick-command>'):
            return uri, None
        try:
            rel = os.path.relpath(uri, root)
        except (ValueError, TypeError):
            return uri, None
        if rel.startswith('..'):
            return uri.replace(os.sep, '/'), None
        return rel.replace(os.sep, '/'), '%SRCROOT%'

    results = []
    for f in _ordered(r):
        uri, uri_base = _rel(f.source)
        location = {'uri': uri}
        if uri_base:
            location['uriBaseId'] = uri_base
        results.append({
            'ruleId': f.rule_id,
            'level': _sarif_level(f.severity),
            'message': {'text': f'{f.title}: {f.description}'},
            'properties': {'confidence': f.confidence,
                           'remediation': f.remediation},
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': location,
                    'region': {'startLine': f.line, 'startColumn': f.column},
                }
            }],
        })
    doc = {
        'version': '2.1.0',
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'runs': [{
            'originalUriBaseIds': {'%SRCROOT%': {'uri': root_uri}} \
                if root_uri else {},
            'tool': {
                'driver': {
                    'name': 'CEX-InstallGuard',
                    'version': VERSION,
                    'informationUri':
                        'https://github.com/cyberempirex/CEX-InstallGuard',
                    'rules': rules_meta,
                }
            },
            'properties': {'target': r.target, 'verdict': r.verdict,
                           'score': r.score, 'scanVersion': VERSION},
            'results': results,
        }],
    }
    Path(path).write_text(json.dumps(doc, indent=2), encoding='utf-8')


# --------------------------------------------------------------------------- #
# HTML                                                                         #
# --------------------------------------------------------------------------- #

_VERDICT_COLOR = {
    'BLOCK': '#ff5c69', 'REVIEW': '#ffb454', 'CAUTION': '#e6d135',
    'LOW-SIGNAL': '#4ec9b0', 'NO-FINDINGS': '#3ad29f', 'UNKNOWN': '#8b98a9',
}
_SEV_COLOR = {
    'critical': '#ff5c69', 'high': '#ffb454',
    'medium': '#e6d135', 'low': '#4ec9b0',
}

_HTML_STYLE = """
:root{color-scheme:dark}
*{box-sizing:border-box;margin:0;padding:0}
body{font:14px/1.55 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif;
     background:#0d1117;color:#dbe3ec;padding:40px 20px}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:20px;letter-spacing:.4px}
.muted{color:#8b98a9}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-weight:700;
       font-size:12px;letter-spacing:.6px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
       gap:14px;margin:22px 0}
.card{background:#161c26;border:1px solid #232c3a;border-radius:12px;padding:16px}
.card .k{font-size:11px;text-transform:uppercase;letter-spacing:1.2px;color:#8b98a9}
.card .v{font-size:26px;font-weight:800;margin-top:6px}
.card .s{font-size:12px;color:#8b98a9;margin-top:4px}
.score-bar{height:10px;border-radius:6px;background:#232c3a;overflow:hidden;
           margin-top:10px}
.score-fill{height:100%;border-radius:6px}
table{width:100%;border-collapse:collapse;background:#161c26;
      border:1px solid #232c3a;border-radius:12px;overflow:hidden}
th{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#8b98a9;
   text-align:left;padding:12px 14px;border-bottom:1px solid #232c3a}
td{padding:11px 14px;border-bottom:1px solid #1c2532;vertical-align:top}
tr:last-child td{border-bottom:none}
.code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;
      background:#0d1117;border:1px solid #232c3a;border-radius:6px;
      padding:2px 7px;max-width:420px;display:inline-block;white-space:nowrap;
      overflow:hidden;text-overflow:ellipsis;max-width:34vw}
footer{margin-top:26px;font-size:12px;color:#607089;text-align:center}
"""

_HTML_SCRIPT = """
function filter(s){
  document.querySelectorAll('[data-sev]').forEach(function(row){
    row.style.display = (!s || row.dataset.sev===s) ? '' : 'none';
  });
  document.querySelectorAll('.fbtn').forEach(function(b){
    b.classList.toggle('active', b.dataset.sev===s);
  });
}
"""


def html_report(r: ScanResult, path: str) -> None:
    """Write a self-contained dark-theme HTML report (no external assets)."""
    e = _html.escape
    c = r.counts()
    cat = r.categories()
    vc = _VERDICT_COLOR.get(r.verdict, '#8b98a9')

    sev_chip = lambda f: (
        f'<span class="badge" style="background:{_SEV_COLOR.get(f.severity, "#8b98a9")}22;'
        f'color:{_SEV_COLOR.get(f.severity, "#8b98a9")}">{e(f.severity.upper())}</span>')

    buttons = ''.join(
        f'<button class="fbtn" data-sev="{s}" '
        f'style="background:#161c26;border:1px solid #232c3a;color:#dbe3ec;'
        f'border-radius:8px;padding:5px 12px;cursor:pointer;margin-right:6px"'
        f' onclick="filter(\'{s}\')">{s.upper()} ({c[s]})</button>'
        for s in ('critical', 'high', 'medium', 'low') if c[s])

    rows = ''.join(
        f'<tr data-sev="{f.severity}">'
        f'<td><code>{e(f.rule_id)}</code></td>'
        f'<td>{sev_chip(f)}</td>'
        f'<td><code>{e(f.source)}:{f.line}</code></td>'
        f'<td><b>{e(f.title)}</b><div class="muted" style="margin-top:3px">{e(f.description)}</div>'
        f'<div class="muted" style="margin-top:3px">Fix: {e(f.remediation)}</div></td>'
        f'<td><span class="code" title="{e(f.code)}">{e(f.code)}</span></td>'
        f'</tr>'
        for f in _ordered(r)) or (
        '<tr><td colspan="5" class="muted" style="padding:24px;text-align:center">'
        'No active findings. This does not prove the target is safe.'
        '</td></tr>')

    cat_rows = ''.join(
        f'<div style="display:flex;justify-content:space-between;gap:10px;padding:4px 0">'
        f'<span>{e(k)}</span><span class="muted">{v}</span></div>'
        for k, v in cat.items()) or '<span class="muted">none</span>'

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CEX-InstallGuard Report — {e(r.target)}</title>
<style>{_HTML_STYLE}</style></head><body><div class="wrap">
<h1>CEX-InstallGuard <span class="muted" style="font-weight:400">· security report</span></h1>
<p class="muted">Target <code>{e(r.target)}</code> · generated by CEX-InstallGuard {VERSION} · static analysis, target never executed</p>

<div class="cards">
  <div class="card"><div class="k">Verdict</div>
    <div class="v"><span class="badge" style="background:{vc}22;color:{vc}">{e(r.verdict)}</span></div>
    <div class="s">exit policy: {'2' if (c['critical'] or c['high']) else '0'}</div></div>
  <div class="card"><div class="k">Risk score</div><div class="v">{r.score}<span class="muted">/100</span></div>
    <div class="score-bar"><div class="score-fill" style="width:{max(2, r.score)}%;background:{vc}"></div></div></div>
  <div class="card"><div class="k">Files / lines</div><div class="v">{r.files:,}</div>
    <div class="s">{r.lines:,} lines · {r.bytes_read:,} bytes · {r.duration_ms:.0f} ms</div></div>
  <div class="card"><div class="k">Findings</div><div class="v">{len(r.active())}</div>
    <div class="s">{c['critical']} critical · {c['high']} high · {c['medium']} medium · {c['low']} low</div></div>
</div>

<div class="card" style="margin-bottom:22px"><div class="k">Top categories</div>
<div style="margin-top:8px">{cat_rows}</div></div>

<div style="margin-bottom:10px">{buttons}
<button class="fbtn active" onclick="filter('')"
 style="background:#161c26;border:1px solid #232c3a;color:#dbe3ec;border-radius:8px;
 padding:5px 12px;cursor:pointer">ALL ({len(r.active())})</button></div>
<table><thead><tr><th>Rule</th><th>Severity</th><th>Location</th><th>Finding</th><th>Evidence</th></tr></thead>
<tbody>{rows}</tbody></table>
<footer>Findings are evidence for review, not a declaration of maliciousness.
Static analysis has limits; a clean report is not proof of safety.</footer>
</div><script>{_HTML_SCRIPT}</script></body></html>"""
    Path(path).write_text(doc, encoding='utf-8')
