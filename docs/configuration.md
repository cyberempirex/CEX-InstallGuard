# Configuration

Unless `--no-rc` is passed, a project file named `.cex-installguard.json` is discovered automatically (shellcheck-style): the target's directory and each parent directory are searched, then the user's home directory. The first file found wins; an explicit `--config PATH` always takes precedence.

```json
{
  "max_file_size": 5242880,
  "workers": 4,
  "recursive": true,
  "disabled_rules": [],
  "ignore_paths": [".git", ".venv", "venv", "node_modules", "vendor"]
}
```

| Key | Meaning |
|-----|---------|
| `max_file_size` | Per-file size limit in bytes; larger files are skipped with metadata (not an error). |
| `workers` | Parallel scan workers for directory scans. |
| `recursive` | Default recursion for directory targets (the `--recursive` flag overrides). |
| `disabled_rules` | Rule IDs whose findings are suppressed before scoring. |
| `ignore_paths` | Directory names or glob patterns excluded during discovery (also drives the CLI `--exclude` flag; both are honored in v12). |

## CLI-only controls

| Flag | Meaning |
|------|---------|
| `--min-severity` | Suppress findings below this severity before scoring. |
| `--fail-on` | Minimum severity that produces exit code 2 (default `high`); `none` disables. |
| `--exclude` | Repeatable glob excluding paths from discovery. |
| `--baseline` / `--save-baseline` | Apply / create suppression baselines (v2 position-stable fingerprints). |
| `--suppress` | Repeatable regex over rule ID or source line. |
| `--quiet` / `--compact` | Machine-friendly output modes. |

## Ignore files

A `.installguardignore` file at the scan root (semgrep-style) lists
gitignore-style glob patterns, one per line:

```
node_modules
test-data
vendor/*
```

Patterns are merged with config `ignore_paths` and repeated `--exclude` globs.

## Color

`--color=WHEN` (`auto`, `always`, `never`) controls ANSI color. The
`NO_COLOR` and `CLICOLOR_FORCE` environment conventions are honored
(`NO_COLOR` wins; `--no-color` is an alias for `--color=never`).

Exit codes: `0` clean, `1` scan error without qualifying findings, `2` findings at/above the `--fail-on` threshold.
