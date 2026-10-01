# Reports

Three formats, each with a clear purpose:

- **JSON** (`--json PATH`) — automation and diffing. Contains the full
  finding list with `evidence` (including the lifecycle chain).
- **SARIF** (`--sarif PATH`) — code-scanning integrations. Artifact URIs are
  **checkout-relative** with `uriBaseId: %SRCROOT%` and an
  `originalUriBaseIds` entry, so results match files committed at the
  repository root (GitHub Code Scanning).
- **HTML** (`--html PATH`) — a standalone, self-contained review page.

All reports are written locally and never transmitted. Findings are ordered
deterministically by (source, line, rule, code).
