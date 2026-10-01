# Python API

```python
from cex_installguard.api import analyze_text, analyze_path

result = analyze_text('printf "%s\\n" hello')
result = analyze_path('.', recursive=True)

for f in result.active():
    print(f.rule_id, f.severity, f.line, f.code)
```

`analyze_text` and `analyze_path` return a `ScanResult` and never execute
the analyzed source. A `ScanResult` exposes `findings`, `active()`,
`counts()`, `categories()`, `density()`, `score`, and `verdict`.

Lifecycle findings (`IG048`–`IG051`) carry an evidence chain:

```python
f = next(x for x in result.active() if x.rule_id == 'IG048')
print(f.evidence['causal_command'])   # the exact command that downloaded it
print([s['step'] for s in f.evidence['chain']])
# ['download', 'made executable', 'executed']
```

Lower-level entry points: `cex_installguard.engine.AnalysisEngine` and
`cex_installguard.scanner.scan_text` / `scan_path`.
