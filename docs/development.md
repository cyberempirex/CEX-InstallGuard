# Development

```bash
python -m pytest -q                       # full suite
python -m compileall -q cex_installguard tests
python tools/generate_docs.py             # regenerate docs/rules.md
python -m cex_installguard examples/dangerous.sh --no-color
```

## Conventions

- The parser is fuzz-tested; malformed input must never raise.
- New rules are declared once in `rules.py`; the analyzer references them by
  ID only. `docs/rules.md` is generated from the registry and CI fails if it
  drifts.
- Detection changes must preserve precision: prefer a narrower rule over a
  broader one, and add a regression test for every fixed false positive.
- The artifact lifecycle (`IG048`–`IG051`) is the reference example of a
  precise rule family — one fact per transition, with the causal command in
  evidence.
