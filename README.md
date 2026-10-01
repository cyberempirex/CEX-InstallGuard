# CEX-InstallGuard

**Static shell and installer security analysis for CyberEmpireX.**

> Inspect first. Execute later.

CEX-InstallGuard analyzes shell/install scripts without executing them. It parses each script into a structured command tree — commands, arguments, pipelines, redirections — and evaluates a dataflow-aware rule engine over that tree, so related actions anywhere in a file produce high-confidence findings: a URL stored in a variable, a payload staged by a download and executed dozens of lines later, or an elevated write to system configuration.

## Version 13.0.0

Version 13 builds on the structured shell parser and AST/dataflow analyzer with a semantic artifact-lifecycle model, improved execution semantics, stronger evasion coverage, and expanded regression/adversarial testing.

### What is actually implemented

- A **structured shell tokenizer/parser** (`shellparser.py`): quoting, escapes, expansions, command substitution, pipelines, sequences, redirections, heredocs, subshell groups, assignment prefixes — tolerant of malformed input by design
- **AST-based analyzer** (`analyzer.py`): 52 security rules driven by command/argument analysis and per-file **dataflow tracking** (remote variables, staged download/decode artifacts reaching execution sinks)
- Content rules for non-command signals (fork bombs, encoded blobs) and keyword indicators
- **False-positive fixes over v11**: quoted variables in `rm` are not flagged; `PATH=` appends are not flagged; static `eval` strings are not flagged; secret exposure requires printing a variable, not a literal
- **Position-stable baseline fingerprints (v2)** — suppression survives line edits and reformatting; v1 baselines still apply
- Configured **ignore paths** (and `--exclude` globs) honored during discovery
- **Binary files are skipped** (with metadata), not reported as errors
- Deterministic results: findings sorted by location, independent of worker count
- Risk scoring: confidence-weighted, log-damped severity model with a documented verdict ladder
- JSON, SARIF 2.1.0 (per-finding artifact locations + full rule registry) and standalone HTML dashboard reports
- Interactive Termux console with command center, finding inspector, rule explorer, security profile
- Animated scan feedback: live spinner + progress bar + elapsed time while scanning, and an animated risk meter on completion — silent and CI-safe when piped or `--no-color`
- **Execution-evasion coverage**: indirect command names (`C=curl; $C …`),
  `env`-prefixed commands, static `eval` / `bash -c` string bodies,
  heredocs written to script files, and taint through `cp`/`mv` are all
  detected via recursive analysis with shared file state
- **Project conventions**: shellcheck-style `.cex-installguard.json`
  discovery, semgrep-style `.installguardignore` files, `--color=WHEN`
  with `NO_COLOR`/`CLICOLOR_FORCE` support, and SARIF output with
  checkout-relative URIs for GitHub Code Scanning
- CLI and Python API; CI tests (205: unit, integration, regression, and adversarial)
- Docs generated from the rule registry (`tools/generate_docs.py`) so documentation cannot drift
- No target script execution

The runtime uses Python's standard library; optional external security tools are not required for the core engine.

## Termux

```bash
termux-setup-storage
cd ~/storage/downloads/CEX-InstallGuard
python -m cex_installguard
```

The no-argument command opens the interactive CEX-InstallGuard console.

## Direct scanning

```bash
python -m cex_installguard examples/dangerous.sh
python -m cex_installguard ./my-project --recursive
python -m cex_installguard ./my-project --recursive --workers 8
python -m cex_installguard script.sh --min-severity high
python -m cex_installguard script.sh --exclude 'vendor/*' --exclude 'test-data/*'
python -m cex_installguard script.sh --quiet
```

Exit codes (threshold set by `--fail-on`, default `high`):

- `0` — no finding at/above the failure threshold and no blocking scan error
- `1` — scan/input error without qualifying findings
- `2` — at least one finding at/above the threshold

## Reports

```bash
python -m cex_installguard script.sh --json report.json
python -m cex_installguard script.sh --sarif report.sarif.json
python -m cex_installguard script.sh --html report.html
```

The SARIF output carries per-finding artifact locations and the full rule registry, ready for GitHub Code Scanning. The HTML report is a standalone dark dashboard with severity filtering.

## Baselines

```bash
python -m cex_installguard script.sh --save-baseline baseline.json
python -m cex_installguard script.sh --baseline baseline.json
```

v13 baselines use position-stable fingerprints: inserting lines or changing whitespace does not resurrect suppressed findings. Baselines saved by earlier releases continue to work.

Suppress a rule explicitly:

```bash
python -m cex_installguard script.sh --suppress 'IG012'
```

## Risk model

The score is a 0–100 index computed from severity weights (critical 40, high 25, medium 10, low 3), each scaled by confidence and aggregated with logarithmic damping per severity group, then compressed exponentially. Consequences:

- one critical finding scores 37/100 and verdict `BLOCK`
- a large pile of low findings can never outweigh a single critical
- verdict ladder: `BLOCK` (any critical) · `REVIEW` (any high, or score ≥ 60) · `CAUTION` (any medium, or score ≥ 30) · `LOW-SIGNAL` · `NO-FINDINGS`

No findings is **not** a declaration of safety; static analysis has limits.

## Rules

```bash
python -m cex_installguard --rules
```

See `docs/rules.md` for the generated rule catalogue.
