# Rule Engine

Generated from the executable registry — 52 rules for CEX-InstallGuard 13.0.0.
Regenerate with `python tools/generate_docs.py`.

Rules are evaluated in two layers:

- **Structural rules** — analyzed from the parsed shell AST (commands, arguments, redirections) plus cross-line dataflow. This is the primary detection layer.
- **Content rules** — textual patterns for signals that are not command-shaped (fork bombs, encoded blobs).

## Rule catalogue

### Remote execution & supply chain

| ID | Severity | Confidence | Layer | Title |
|----|----------|-------------|-------|-------|
| IG001 | critical | high | structural | Remote pipe to shell |
| IG011 | high | high | structural | Remote command substitution |
| IG016 | high | medium | structural | Encoded payload decode |
| IG031 | high | high | structural | Download followed by execution |
| IG032 | critical | high | structural | Decoded payload reaches execution |
| IG034 | critical | high | structural | Remote pipe to interpreter |
| IG047 | high | high | structural | Remote content flows into execution |
| IG048 | critical | high | structural | Downloaded artifact executed |

### Network retrieval hygiene

| ID | Severity | Confidence | Layer | Title |
|----|----------|-------------|-------|-------|
| IG014 | medium | high | structural | Network retrieval |
| IG023 | high | medium | structural | Hidden executable download |
| IG035 | high | high | structural | Insecure TLS bypass |
| IG036 | medium | medium | structural | Plain-text network retrieval |
| IG037 | high | medium | structural | Raw IP endpoint download |

### Destructive operations

| ID | Severity | Confidence | Layer | Title |
|----|----------|-------------|-------|-------|
| IG002 | critical | high | structural | Recursive destructive deletion |
| IG003 | critical | high | structural | Raw block-device write |
| IG004 | critical | high | structural | Filesystem formatting |
| IG005 | critical | high | content | Fork bomb pattern |
| IG019 | high | high | structural | Broad wildcard deletion |
| IG025 | high | medium | structural | Process termination sweep |
| IG030 | medium | medium | structural | Unquoted destructive variable |

### Privilege & permissions

| ID | Severity | Confidence | Layer | Title |
|----|----------|-------------|-------|-------|
| IG006 | high | medium | structural | Privilege escalation command |
| IG007 | high | high | structural | World-writable permissions |
| IG008 | high | high | structural | Recursive ownership change |
| IG040 | critical | high | structural | Sudoers policy modification |
| IG046 | critical | high | structural | Setuid binary creation |

### System configuration & persistence

| ID | Severity | Confidence | Layer | Title |
|----|----------|-------------|-------|-------|
| IG009 | high | high | structural | System configuration write |
| IG013 | high | high | structural | Persistence modification |
| IG021 | medium | medium | structural | Shell startup sourcing |
| IG033 | high | high | structural | Elevated system modification |
| IG038 | high | high | structural | SSH authorized keys modification |
| IG039 | medium | medium | structural | New user or group creation |
| IG045 | medium | medium | structural | DNS or hosts file modification |

### Evasion & defense tampering

| ID | Severity | Confidence | Layer | Title |
|----|----------|-------------|-------|-------|
| IG017 | medium | high | structural | Self deletion |
| IG026 | high | high | structural | Firewall/security control change |
| IG027 | high | high | structural | Log tampering |
| IG041 | medium | high | structural | History suppression |
| IG042 | high | high | structural | Mandatory access control disabled |

### Obfuscation & dynamic execution

| ID | Severity | Confidence | Layer | Title |
|----|----------|-------------|-------|-------|
| IG010 | high | high | structural | Dynamic eval execution |
| IG015 | high | high | structural | Interpreter-spawned command execution |
| IG022 | critical | high | structural | Suspicious reverse-shell primitive |
| IG024 | medium | medium | structural | Shell spawned from shell |
| IG043 | critical | high | structural | Cryptomining indicator |
| IG044 | medium | low | content | Large encoded literal |

### Environment & secrets

| ID | Severity | Confidence | Layer | Title |
|----|----------|-------------|-------|-------|
| IG018 | high | medium | structural | Credential-like assignment |
| IG020 | high | high | structural | PATH/library injection |
| IG029 | high | high | structural | Environment secret exposure |

### Staging & dependencies

| ID | Severity | Confidence | Layer | Title |
|----|----------|-------------|-------|-------|
| IG012 | medium | medium | structural | Package installation/removal |
| IG028 | medium | medium | structural | Temporary executable permission |

### Other

| ID | Severity | Confidence | Layer | Title |
|----|----------|-------------|-------|-------|
| IG049 | medium | high | structural | Downloaded artifact made executable |
| IG050 | critical | high | structural | Downloaded artifact interpreted |
| IG051 | high | high | structural | Downloaded artifact sourced |
| IG052 | medium | high | structural | Excessive nesting depth |

### Keyword indicators

| ID | Title |
|----|-------|
| KW001 | Suspicious security keyword (backdoor, ransomware, rootkit, …) |

## Remediation guidance

Every finding carries its remediation inline (CLI `FIX` line, report `remediation` field). The registry in `cex_installguard/rules.py` is the single source of truth for titles, severities, categories, confidence and remediation text.

