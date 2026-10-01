# Architecture

CEX-InstallGuard 13 separates the shell parser, AST analyzer, artifact
lifecycle tracker, scanning pipeline, rule registry, scoring,
configuration, baselines, suppressions, and reporting. The target script
is never executed. The architecture is **stable as of 13.0.0**: future
work prioritizes correctness, maintainability and reliability over new
features.

## Analysis pipeline

```
source text
   │
   ▼
shellparser.py ─── tokenize + recursive-descent parse (tolerant)
   │                words, quotes, expansions, pipelines, redirects,
   │                heredocs, subshells, assignment prefixes,
   │                control-flow keywords (if/for/while/case) as separators
   ▼
analyzer.py ────── 50 structural rules over the command tree
   │                + per-file dataflow (remote vars, artifacts)
   │                + artifact lifecycle (downloaded → executable →
   │                  interpreted / sourced / executed)
   │                + command-wrapper unwrapping (sudo/timeout/env/xargs)
   │                + depth-bounded recursive analysis of embedded code
   ▼
scanner.py ──────── content layer (fork bombs, blobs, keywords)
   │                + ${IFS} de-obfuscation re-scan
   │                + deterministic dedupe and sort
   ▼
scoring.py ─────── confidence-weighted, log-damped risk score,
   │                verdict ladder, exit-code policy
   ▼
reporter.py ────── JSON · SARIF 2.1.0 (checkout-relative) · HTML
```

## Artifact lifecycle

The central semantic model. A file is tracked through five *distinct*
states, each reported once, at the acting command, with the exact causal
command in evidence:

| State | Rule | Severity | Meaning |
|-------|------|----------|---------|
| downloaded / decoded | — | — | content arrived from the network or a decode stage |
| made executable | `IG049` | medium | `chmod +x` on the artifact — *preparation*, not running |
| interpreted | `IG050` | critical | passed to `bash`/`sh`/`python`/`perl`/… |
| sourced | `IG051` | high | `. file` / `source file` |
| executed | `IG048` | critical | the artifact path is invoked as a command |

Conflating these was the pre-13 weakness. Making a file executable is not
the same as running it; sourcing is not the same as interpreting. Each
finding carries `evidence.chain` (the ordered steps with line numbers and
command text), `evidence.causal_command` and `evidence.causal_line`, so a
reviewer can see exactly which command downloaded the artifact and which
command ran it.

## Module map

| Module | Responsibility |
|--------|----------------|
| `shellparser.py` | Tokenizer + parser producing a `Statement`/`Pipeline`/`Command`/`Word` tree. Control-flow keywords are separators, not commands. Never executes anything; malformed input degrades to words. |
| `analyzer.py` | AST rule engine: command/argument analysis, pipeline adjacency, dataflow (URL-derived variables, artifact lifecycle), command-wrapper unwrapping, per-command handlers. |
| `rules.py` | The registry: 50 structural + 2 content rules with metadata. Single source of truth; self-validating. |
| `scanner.py` | Orchestration: discovery (ignore paths, exclusion globs), binary sniffing, parallel scanning, deterministic ordering. |
| `config.py` | Configuration: `.cex-installguard.json` discovery, `.installguardignore`, color policy. |
| `scoring.py` / `policy.py` | Risk model, verdicts, exit codes. |
| `baseline.py` | Position-stable fingerprints (v2) with v1 compatibility. |
| `reporter.py` | Report writers (JSON, SARIF, HTML). |
| `cli.py` / `interactive.py` | CLI and the Termux console. |
| `api.py` / `engine.py` | Public programmatic entry points. |

## Design guarantees

- **No execution**: every layer is pure text analysis; nothing in the
  target is run, and no shell command string is ever constructed.
- **Offline**: no network access at any point; reports are generated
  locally.
- **Tolerance**: the parser cannot be crashed by adversarial input, and
  recursive analysis of embedded code is depth-bounded (fuzz-tested).
- **Determinism**: results are sorted by (source, line, rule, code) and do
  not depend on worker scheduling.
- **Documentation**: `docs/rules.md` is generated from the registry
  (`tools/generate_docs.py`) and CI fails if it drifts.
