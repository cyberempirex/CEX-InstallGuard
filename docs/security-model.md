# Security Model

CEX-InstallGuard is deliberately **non-executing**. It is a static
analyzer: it reads source text and produces findings as pure data.

## Guarantees

- **The target is never run.** No analyzed file is invoked as a program,
  sourced, interpreted, or written to a shell.
- **No shell command strings are constructed.** Analysis works on a parsed
  tree of words and commands; nothing is passed to a shell.
- **No network access.** Scanning is fully offline. Nothing is uploaded;
  reports are generated locally.
- **No dynamic evaluation.** The `eval`/`bash -c` handlers *parse* embedded
  text into the same AST and analyze it — they never evaluate it. Recursive
  analysis is depth-bounded (`Analyzer.MAX_DEPTH`) so adversarial nesting
  degrades gracefully instead of exhausting the interpreter stack.
- **Untrusted input is handled defensively.** Files are size-capped, binary
  files are skipped rather than decoded, and the parser is fuzz-tested
  against malformed input.

## Trust boundaries

A finding is a *signal for review*, not proof of maliciousness. Keyword and
pattern matches carry lower confidence by design. The scanner never
modifies the files it reads.

## Reporting

Reports contain file paths, line numbers, matched text and rule metadata.
They are written only where the user asks (`--json`, `--sarif`, `--html`).
No telemetry is collected or transmitted.
