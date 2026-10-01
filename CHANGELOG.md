# Changelog

## 13.0.0 — final major release (architecture frozen)

Full-codebase audit and semantic overhaul. The architecture is **stable
from this release**: future work prioritizes correctness, maintainability
and reliability over new features.

### Artifact lifecycle (the core semantic fix)

v12 conflated five different facts about a file. They are now distinct,
each reported once, at the acting command:

- **`IG048` executed** (critical) — the artifact path is invoked as a command
- **`IG050` interpreted** (critical) — passed to `bash`/`sh`/`python`/`perl`/…
- **`IG051` sourced** (high) — `. file` / `source file`
- **`IG049` made executable** (medium) — `chmod +x` (preparation, **not** running)

`curl -o /tmp/x …; chmod +x /tmp/x` no longer reports *execution*; only an
actual invocation does. `cp`/`mv`/`install` propagate artifact identity, and
`install -m 755` records the execute-bit grant. Every lifecycle finding
points at the acting command and carries `evidence.causal_command`,
`evidence.causal_line` and the ordered `evidence.chain`.

### Parser and analysis

- **Control-flow awareness**: `if`/`then`/`elif`/`else`/`fi`/`for`/`while`/
  `until`/`do`/`done`/`case`/`esac`/`select`/`function`/`in` are treated as
  statement separators, so a pipeline hidden behind one
  (`if curl … | sh`, `while read x; do curl … | sh; done`) is analyzed.
  Keywords used as arguments (`echo if`) are unaffected.
- **Command-wrapper unwrapping**: `sudo`, `doas`, `timeout`, `nice`, `env`,
  `command`, `stdout`/`stdbuf`, `setsid`, `ionice`, `exec` and `xargs` are
  resolved to the command they actually run; the wrapper's own finding is
  preserved (`sudo rm -rf /` → both privilege and destructive findings).
- **Variable chains**: `A=curl; B=$A; $B …` resolves one step.
- **Depth-bounded recursion**: embedded code (`eval`, `bash -c`, command
  substitution, heredocs) is analyzed recursively up to a bound; exceeding
  it emits `IG052` instead of raising `RecursionError`.

### Precision and hygiene

- Content-layer and structural findings are deduplicated by
  (rule, source, line, normalized code); results are byte-for-byte
  deterministic across runs and worker counts.
- Removed **eight dead/duplicate modules** (`animation`, `shellcheck`,
  `discovery`, `hashing`, `filesystem`, `errors`, `normalization`,
  `metrics`); folded `metrics` into `ScanResult`.
- New rules: `IG049`, `IG050`, `IG051`, `IG052`. Registry now self-validating
  at 52 rules.

### Tests

- 40 new tests (**205 total**): the five-way lifecycle separation with exact
  causal attribution, control-flow bodies, wrapper unwrapping, variable
  chains, obfuscation, dedup, determinism, **fuzz** (malformed/binary/unicode
  input must never raise) and **end-to-end** CLI (exit codes, JSON/SARIF/HTML,
  baseline round-trip, exclusions).

### Documentation

Rewrote `architecture.md` (lifecycle model, module map),
`security-model.md`, `api.md`, `development.md`, `reports.md`, `termux.md`;
regenerated `docs/rules.md` from the registry.

## 12.2.0
## 12.2.0

Real-world usability release: closes the documented evasion gaps and
adopts standard CLI/report conventions from professional tools.

### Detection: previously-missed execution evasions

- **Indirect command names**: `C=curl; $C http://x | sh` — variables holding
  literal command names are tracked and resolved before rule dispatch
  (`_effective_name`), including inside pipelines.
- **`env` prefixes**: `env VAR=1 curl … | sh` — assignments and flags are
  skipped to find the command actually being run.
- **Static `eval` / `bash -c` bodies**: the string body is itself shell
  code — it is now parsed and analyzed recursively with the file's state
  (staged artifacts, remote-variable taint) shared, so
  `eval "cu""rl http://x | sh"` and `bash -c "/tmp/tool"` are caught.
- **Heredoc-written scripts**: heredoc bodies redirected into a file are
  analyzed as shell. Heredocs merely fed to a program's stdin are not
  (avoids false positives on documentation blocks).
- **Taint through `cp`/`mv`/`install`**: a staged (downloaded/decoded)
  artifact that is copied keeps its taint at the new path.

### CLI conventions (researched from shellcheck / semgrep / no-color.org)

- **Project config discovery**: `.cex-installguard.json` is found in the
  target's directory and each parent, then the home directory
  (shellcheck-style RC lookup). `--no-rc` disables; `--config` overrides.
- **`.installguardignore`**: gitignore-style ignore patterns at the scan
  root (semgrep-style), merged with config `ignore_paths` and `--exclude`.
- **`--color=WHEN`** (`auto|always|never`) plus support for the `NO_COLOR`
  and `CLICOLOR_FORCE` environment conventions (NO_COLOR wins).
- **SARIF**: checkout-relative artifact URIs with `uriBaseId: %SRCROOT%`
  and `originalUriBaseIds`, as GitHub Code Scanning expects; results now
  match against files committed at the repository root.

### Tests

- 16 new tests (165 total) covering every new detection, the RC/ignore
  discovery, color precedence, and exit-code stability.

## 12.1.0
## 12.1.0

Professional animated CLI experience (stdlib-only, CI-safe).

- New `ui.py`: thread-driven `Spinner` and `ScanProgress` — a live status
  line (spinner + progress bar + files done/total + current file +
  elapsed time) that animates while the scan actually runs, replacing the
  fixed-duration v11-era spinner. Cursor is hidden during animation and
  always restored, even on errors.
- `risk_meter`: the final risk bar fills with a short sweep animation
  before the dashboard renders.
- The interactive console's live scan now uses the same `ScanProgress`
  engine instead of its ad-hoc progress bar.
- Graceful degradation: on non-TTY output (CI logs, pipes) or with
  `--no-color`, nothing animates; a single plain
  `Scan complete · N files · M findings · X.XXs` summary line is printed.
- 7 new UI tests (149 total).

## 12.0.0
## 12.0.0

Major upgrade: regex-only execution detection replaced by a structured
shell parser and AST analyzer, plus defect fixes across the board.

### Structured shell parsing (new engine core)

- New `shellparser.py`: tolerant POSIX-ish tokenizer and recursive-descent
  parser. Handles quoting, backslash escapes, `$VAR`/`${VAR}`, `$(...)` and
  backtick substitution, pipelines, `;`/`&&`/`||` sequences, redirections
  (`> >> < 2> &>`), heredocs, subshell groups, assignment prefixes and line
  continuations. Malformed input degrades to words instead of raising —
  verified by fuzz tests.
- New `analyzer.py`: 46 structural rules evaluated over the parsed command
  tree with per-file dataflow tracking. Pipeline adjacency (curl | sh) is
  now detected from actual pipeline structure; downloads/decodes stage
  artifacts that are tracked to any later execution sink; variable
  assignments typed as remote/URL feed execution-sink analysis.
- `scanner.py` orchestrates parse → analyze → content layer (fork bombs,
  encoded blobs, keywords) → deterministic dedupe and sort.
- `${IFS}`-as-separator obfuscation handled by a de-obfuscation re-scan.
- CRLF line endings normalized before parsing.

### False-positive fixes (v11 regressions addressed)

- IG030: quoted variables in `rm` (`rm -rf "$SAFE_DIR"`) are no longer
  flagged; only unquoted, glob-expanding variables are.
- IG020: `PATH="$PATH:/x"` appends are no longer flagged as injection;
  PATH replacement and `LD_PRELOAD`/`LD_LIBRARY_PATH` still are.
- IG010: `eval` of a static string is no longer flagged.
- IG029: secret exposure requires printing a variable, not a literal
  containing the word PASSWORD.
- IG009/IG013/IG038/IG040/IG045: sensitive-write rules now fire only on
  actual write targets (redirects, `tee`, `cp`, `install`, `mv`), not on
  any line mentioning a path.

### Defect fixes

- Baseline fingerprints v2: position-stable across line edits and
  whitespace changes (`RULE|source|normalized-code|ordinal`); v1 baselines
  from v10/v11 still apply (both generations computed when matching).
- Fixed v12 baseline load bug where fingerprints containing `|` characters
  in pipeline evidence were misclassified.
- Configured `ignore_paths` are now honored during discovery (previously
  read from config but never used); `--exclude` CLI globs added.
- Binary files (NUL byte / undecodable UTF-8 sniff) are skipped with
  metadata instead of being reported as scan errors; executable binaries
  discovered via the executable bit no longer break the scan.
- `mkfs.*` command variants (e.g. `mkfs.ext4`) now match the IG004 rule.
- Reverse-shell `/dev/tcp/` endpoints detected in any word or redirect
  target, including `exec 3<>/dev/tcp/...` forms.
- Deterministic results: findings sorted by (source, line, rule, code)
  independent of worker scheduling; verified by a dedicated test.

### Testing and documentation

- Test suite grown from 34 to 142 tests across unit (parser, analyzer),
  integration (scanner, CLI, reports), regression (v11 behaviors, false
  positives) and adversarial (obfuscation, fuzz, malformed input, CRLF,
  unicode, deeply nested input) suites.
- `docs/rules.md` is now generated from the executable registry by
  `tools/generate_docs.py`, eliminating documentation drift.
- README rewritten for v12.

## 11.0.0
## 11.0.0

Major upgrade: dataflow-aware analysis, a redesigned risk model, professional
reports and CLI, and an engineering-quality pass across the codebase.

### Intelligence

- Added 13 new direct detection rules (IG034–IG046): interpreter piping,
  TLS bypass, plain-HTTP and raw-IP retrieval, authorized_keys and sudoers
  tampering, user creation, DNS/hosts modification, history suppression,
  SELinux/AppArmor disabling, cryptomining indicators, large encoded blobs,
  and setuid creation.
- New dataflow correlation engine (IG047–IG048): tracks URL-derived variables
  and staged download/decode artifacts across arbitrary distances in a file
  and flags when they reach an execution primitive. Window-based correlation
  (IG031–IG033) is retained.
- Redesigned risk model: confidence-weighted severity scoring with
  per-severity logarithmic damping and exponential compression, so no volume
  of low-grade findings can outweigh a single critical one. Verdict ladder
  now also reacts to the compressed score (REVIEW at ≥ 60, CAUTION at ≥ 30).
- Added rule-registry self-validation (duplicate IDs, bad severity, invalid
  regex) exercised in CI tests.

### Professional UX

- New CLI flags: `--min-severity`, `--quiet`, plus `--rules` now prints a
  documented registry table with confidence and contextual-rule summary.
- SARIF report: fixed artifact locations to use each finding's own source
  file (previously every finding pointed at the scan root), added the full
  rule metadata registry, confidence and remediation properties.
- HTML report: rebuilt as a self-contained dark dashboard with verdict and
  score cards, category breakdown, severity filter buttons and remediation
  guidance — no external assets or network.
- Terminal report now shows category summary, exit-code guidance line and
  a quiet mode suitable for scripts and CI logging.

### Engineering quality

- Removed dead code (`rule_patterns.py`) and the duplicated `assess`
  implementation; scoring and exit-code policy now live only in
  `cex_installguard.scoring` (re-exported via `policy` and `scanner` for
  compatibility).
- Rewrote the core modules (rules, scanner, scoring, reporter, cli,
  terminal, policy) with docstrings, type hints and readable formatting.
- Test suite expanded from 12 to 34 tests: new rules, dataflow correlation,
  scoring properties, SARIF regression and CLI flag coverage.
- Version bumped everywhere consistently (package, models, reports).

## 10.0.0

- Rebuilt the terminal surface around a branded CEX-InstallGuard command center.
- Added a large product banner with version, CyberEmpireX identity and security model.
- Added live repository scan progress driven by actual completed files.
- Added a session state showing the last scan verdict and risk score.
- Added a finding inspector with selectable finding details.
- Added rule detail inspection with severity, confidence, tags, pattern, explanation and remediation.
- Added separate Security Profile, Reports and About surfaces.
- Added platform and Python runtime information to the command center.
- Kept the runtime dependency-free and preserved the underlying static-analysis engine.
- Updated package metadata and report versioning to 10.0.0.
- Expanded regression validation to 12 passing tests.

## 6.0.0

- Reworked the scanner into a functional analysis pipeline rather than a presentation-heavy shell.
- Added contextual multi-line correlation for download→execution, decode→execution and elevated sensitive modification.
- Added shell comment handling, quoted-string masking and tokenization.
- Added executable-file discovery for extensionless installers.
- Added parallel repository scanning and scan metadata.
- Added baseline and explicit suppression workflows to the CLI.
- Added functional JSON, SARIF 2.1.0 and HTML reports.
- Rebuilt the interactive console with separate Security Profile, Reports and About screens.
- Corrected the safety wording: no-findings is not equivalent to safe.
- Added regression tests for contextual detections and baseline behavior.
