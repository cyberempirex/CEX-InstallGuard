"""Rule registry for CEX-InstallGuard v12.

Two complementary layers:

* **Structural rules** (:data:`STRUCTURAL_RULES`) — evaluated by the AST
  analyzer in :mod:`cex_installguard.analyzer`. They inspect parsed
  commands, arguments, redirections and dataflow. This is the primary
  detection layer.
* **Content rules** (:data:`RULES`) — plain-text patterns for signals that
  are not command-shaped: fork bombs, encoded blobs, indicator keywords.

Every rule carries stable metadata (ID, severity, category, confidence,
description, remediation). The registry is self-validating: duplicate IDs,
invalid severities and broken regexes are reported by
:func:`validate_registry` and asserted in CI.
"""
from __future__ import annotations

import re
from typing import Iterable

from .models import Rule

# --------------------------------------------------------------------------- #
# Content (regex) rules — the slim textual layer                              #
# --------------------------------------------------------------------------- #

RULES: list[Rule] = [
    Rule('IG005', 'Fork bomb pattern', 'critical', 'resource-exhaustion',
         r':\s*\(\)\s*\{[^}]*\|[^}]*&\s*\}\s*;\s*:',
         'Matches a classic shell fork-bomb pattern.',
         'Remove uncontrolled process spawning.',
         'high', ('process',)),
    Rule('IG044', 'Large encoded literal', 'medium', 'obfuscation',
         r'[A-Za-z0-9+/=]{120,}|\b[0-9a-fA-F]{120,}\b',
         'Contains an unusually long encoded blob typical of smuggled '
         'payloads.',
         'Decode the literal and review its contents before executing.',
         'low', ('obfuscation', 'blob')),
]

# Suspicious single-word indicators promoted to findings when present.
KEYWORDS: dict[str, str] = {
    'reverse_shell': 'critical', 'backdoor': 'critical', 'keylogger':
        'critical', 'ransomware': 'critical', 'meterpreter': 'critical',
    'botnet': 'critical', 'rootkit': 'critical', 'cryptominer': 'high',
    'malware': 'high', 'trojan': 'high', 'shellcode': 'high',
    'exfiltrat': 'high',
}


# --------------------------------------------------------------------------- #
# Structural rules — metadata consumed by the analyzer                         #
# --------------------------------------------------------------------------- #

def _S(rule_id, title, severity, category, description, remediation,
       confidence='high', tags=()):
    return Rule(rule_id, title, severity, category, '',
                description, remediation, confidence, tags)


STRUCTURAL_RULES: list[Rule] = [
    # -- remote execution & supply chain ------------------------------------ #
    _S('IG001', 'Remote pipe to shell', 'critical', 'remote-execution',
       'Downloads remote content and immediately executes it as shell code.',
       'Separate download and execution; verify source and integrity.',
       'high', ('download', 'execution')),
    _S('IG034', 'Remote pipe to interpreter', 'critical', 'remote-execution',
       'Downloads remote content and immediately executes it in a '
       'general-purpose interpreter.',
       'Download to a reviewable file, inspect it, then run it deliberately.',
       'high', ('download', 'execution', 'interpreter')),
    _S('IG011', 'Remote command substitution', 'high', 'remote-execution',
       'Retrieves network content inside command substitution.',
       'Separate retrieval from execution.'),
    _S('IG047', 'Remote content flows into execution', 'high',
       'remote-execution',
       'A remote/URL-derived value stored in a variable reaches an '
       'execution primitive in a later line.',
       'Bind remote content to a verified, hashed artifact before use.'),
    _S('IG048', 'Downloaded artifact executed', 'critical',
       'remote-execution',
       'A file created by a download or decode stage is invoked directly '
       'as a command (execution), not merely written or chmod-ed.',
       'Verify the artifact checksum and provenance before execution.',
       'high', ('download', 'execution', 'artifact')),
    _S('IG050', 'Downloaded artifact interpreted', 'critical',
       'remote-execution',
       'A file created by a download or decode stage is passed to an '
       'interpreter (bash/sh/python/perl/...), which runs its contents '
       'exactly as if it had been executed.',
       'Download to a reviewable path, inspect the contents, then run it '
       'deliberately.',
       'high', ('download', 'execution', 'interpreter', 'artifact')),
    _S('IG051', 'Downloaded artifact sourced', 'high',
       'remote-execution',
       'A file created by a download or decode stage is sourced (`. file` / '
       '`source file`), evaluating its contents in the current shell.',
       'Never source remote content; review and vendor it instead.',
       'high', ('download', 'execution', 'source', 'artifact')),
    _S('IG049', 'Downloaded artifact made executable', 'medium',
       'remote-execution',
       'A file created by a download or decode stage has its executable bit '
       'set. This is a preparation step, not execution, but it commonly '
       'precedes running the artifact.',
       'Confirm the artifact provenance before granting execute permission.',
       'high', ('download', 'permissions', 'artifact')),
    _S('IG031', 'Download followed by execution', 'high', 'remote-execution',
       'Network retrieval is close to an execution primitive, increasing '
       'supply-chain risk.',
       'Separate retrieval from execution and verify integrity before '
       'execution.'),
    _S('IG032', 'Decoded payload reaches execution', 'critical',
       'obfuscation',
       'An encoded/decoded payload is connected to a shell execution '
       'primitive.',
       'Decode to a reviewable artifact and inspect it before execution.'),
    _S('IG052', 'Excessive nesting depth', 'medium', 'obfuscation',
       'Command substitution or eval nesting exceeds the analysis depth '
       'bound, a strong indicator of deliberately obfuscated code.',
       'Unwrap and review the nested layers manually.', 'high'),
    _S('IG016', 'Encoded payload decode', 'high', 'obfuscation',
       'Decodes an opaque payload.',
       'Inspect decoded content before use.', 'medium'),

    # -- network retrieval hygiene ------------------------------------------ #
    _S('IG014', 'Network retrieval', 'medium', 'network',
       'Retrieves remote content.',
       'Use trusted pinned URLs and verify content.'),
    _S('IG035', 'Insecure TLS bypass', 'high', 'network',
       'Disables transport verification for a network retrieval.',
       'Never disable certificate validation; fix the trust chain instead.'),
    _S('IG036', 'Plain-text network retrieval', 'medium', 'network',
       'Retrieves remote content over an unencrypted connection.',
       'Use HTTPS endpoints only; plain HTTP can be tampered with in '
       'transit.', 'medium'),
    _S('IG037', 'Raw IP endpoint download', 'high', 'network',
       'Contacts a raw IP address instead of a named, verifiable host.',
       'Prefer named domains with valid TLS certificates.', 'medium'),
    _S('IG023', 'Hidden executable download', 'high', 'remote-execution',
       'Downloads into a temporary executable location.',
       'Use controlled staging and verify provenance.', 'medium'),

    # -- destructive operations ---------------------------------------------- #
    _S('IG002', 'Recursive destructive deletion', 'critical', 'destructive',
       'Recursively deletes a root or broad filesystem path.',
       'Narrow the target and validate it before deletion.'),
    _S('IG019', 'Broad wildcard deletion', 'high', 'destructive',
       'Deletes wildcard paths.',
       'Use explicit paths and validate them.'),
    _S('IG030', 'Unquoted destructive variable', 'medium', 'destructive',
       'Uses an unquoted variable in a destructive command; word-splitting '
       'or glob expansion can widen the delete.',
       'Quote and validate the variable before deletion.', 'medium'),
    _S('IG003', 'Raw block-device write', 'critical', 'destructive',
       'Writes directly to a block device.',
       'Require an explicit device allowlist and confirmation.'),
    _S('IG004', 'Filesystem formatting', 'critical', 'destructive',
       'Formats a filesystem or initializes swap.',
       'Validate the target device and require confirmation.'),
    _S('IG025', 'Process termination sweep', 'high', 'destructive',
       'Terminates matching processes broadly.',
       'Target exact processes or services.', 'medium'),

    # -- privilege & permissions --------------------------------------------- #
    _S('IG006', 'Privilege escalation command', 'high', 'privilege',
       'Runs through a privilege-changing utility.',
       'Use least privilege and document elevation.', 'medium'),
    _S('IG007', 'World-writable permissions', 'high', 'permissions',
       'Grants broad write/execute permissions.',
       'Use the minimum required mode.'),
    _S('IG008', 'Recursive ownership change', 'high', 'permissions',
       'Recursively changes ownership.',
       'Restrict the path and validate ownership.'),
    _S('IG046', 'Setuid binary creation', 'critical', 'privilege',
       'Marks a file setuid, allowing execution with the owner\u2019s '
       'privileges.',
       'Avoid setuid bits in installer scripts; use sudoers policy instead.'),
    _S('IG040', 'Sudoers policy modification', 'critical', 'privilege',
       'Modifies sudo privilege policy, a common backdoor vector.',
       'Use visudo with a reviewed, narrowly scoped policy.'),

    # -- system configuration & persistence ---------------------------------- #
    _S('IG009', 'System configuration write', 'high', 'configuration',
       'Writes to sensitive system configuration.',
       'Limit writes to application-owned configuration.'),
    _S('IG013', 'Persistence modification', 'high', 'persistence',
       'Modifies startup or persistence locations.',
       'Use documented service installation paths.'),
    _S('IG021', 'Shell startup sourcing', 'medium', 'persistence',
       'Sources shell startup configuration.',
       'Verify origin and content before sourcing.', 'medium'),
    _S('IG038', 'SSH authorized keys modification', 'high', 'persistence',
       'Adds or rewrites SSH authorized keys, a classic remote-access '
       'backdoor.',
       'Never modify authorized_keys from an installer; manage access '
       'centrally.'),
    _S('IG039', 'New user or group creation', 'medium', 'persistence',
       'Creates a user or group, which may establish a persistent access '
       'path.',
       'Document why a new account is required and remove it afterwards.',
       'medium'),
    _S('IG045', 'DNS or hosts file modification', 'medium', 'configuration',
       'Rewrites host resolution, which can silently redirect traffic.',
       'Manage DNS through system configuration management only.',
       'medium'),
    _S('IG033', 'Elevated system modification', 'high', 'privilege',
       'Privilege-changing execution occurs with a sensitive system '
       'modification.',
       'Minimize privileges and explicitly validate the affected resource.'),

    # -- evasion & defense tampering ------------------------------------------ #
    _S('IG017', 'Self deletion', 'medium', 'evasion',
       'Attempts to delete the running script.',
       'Avoid self-deletion unless explicitly required.', 'high'),
    _S('IG026', 'Firewall/security control change', 'high', 'evasion',
       'Changes host firewall controls.',
       'Require explicit administrative intent.'),
    _S('IG027', 'Log tampering', 'high', 'evasion',
       'Deletes or destroys common logs.',
       'Never erase security logs in an installer.'),
    _S('IG041', 'History suppression', 'medium', 'evasion',
       'Clears or disables shell history, hiding the commands that were run.',
       'Do not suppress audit history in installation tooling.'),
    _S('IG042', 'Mandatory access control disabled', 'high', 'evasion',
       'Disables SELinux or AppArmor confinement for the host or a binary.',
       'Keep MAC enforcement enabled; profile the workload instead.'),

    # -- obfuscation & dynamic execution -------------------------------------- #
    _S('IG010', 'Dynamic eval execution', 'high', 'execution',
       'Evaluates dynamically constructed shell code.',
       'Avoid eval; use validated arguments.'),
    _S('IG015', 'Interpreter-spawned command execution', 'high', 'execution',
       'Executes dynamically supplied interpreter code.',
       'Prefer reviewable source files.'),
    _S('IG024', 'Shell spawned from shell', 'medium', 'execution',
       'Spawns a shell for a dynamic command string.',
       'Prefer direct validated invocation.', 'medium'),
    _S('IG043', 'Cryptomining indicator', 'critical', 'malware-indicator',
       'Contains well-known cryptomining tool or protocol indicators.',
       'Remove mining payloads; investigate how the script arrived.'),
    _S('IG022', 'Suspicious reverse-shell primitive', 'critical', 'network',
       'Contains a common reverse-shell primitive.',
       'Remove unexpected remote command channels.'),

    # -- environment & secrets -------------------------------------------------- #
    _S('IG020', 'PATH/library injection', 'high', 'environment',
       'Replaces executable search paths or sets library-loading variables.',
       'Use scoped environment changes.'),
    _S('IG018', 'Credential-like assignment', 'high', 'secrets',
       'Contains a credential-like value.',
       'Use environment variables or a secret manager.', 'medium'),
    _S('IG029', 'Environment secret exposure', 'high', 'secrets',
       'May print sensitive environment variables.',
       'Avoid printing secrets and redact sensitive values.'),

    # -- staging & dependencies -------------------------------------------------- #
    _S('IG028', 'Temporary executable permission', 'medium', 'permissions',
       'Makes a temporary artifact executable.',
       'Use controlled staging and verify integrity.', 'medium'),
    _S('IG012', 'Package installation/removal', 'medium', 'dependencies',
       'Changes installed software packages.',
       'Pin versions and verify sources.', 'medium'),
]

# --------------------------------------------------------------------------- #
# Merged registry helpers                                                       #
# --------------------------------------------------------------------------- #

_ALL: list[Rule] = sorted(STRUCTURAL_RULES + RULES,
                          key=lambda r: r.rule_id)
RULE_BY_ID: dict[str, Rule] = {r.rule_id: r for r in _ALL}
STRUCTURAL_BY_ID: dict[str, Rule] = {r.rule_id: r for r in STRUCTURAL_RULES}


def all_rules() -> list[Rule]:
    """Every registered rule (structural + content), sorted by ID."""
    return list(_ALL)


def rule_count() -> int:
    """Total number of registered rules."""
    return len(_ALL)


def structural_ids() -> set[str]:
    """IDs implemented by the AST analyzer."""
    return set(STRUCTURAL_BY_ID)


def active_rules(ids: Iterable[str] | None = None) -> list[Rule]:
    """All rules, or only those whose IDs appear in ``ids``."""
    return [r for r in _ALL if not ids or r.rule_id in ids]


def search_rules(term: str) -> list[Rule]:
    """Case-insensitive search across ID, title, category, description."""
    q = term.lower()
    return [r for r in _ALL
            if q in ' '.join((r.rule_id, r.title, r.category,
                              r.description, *r.tags)).lower()]


def validate_registry() -> list[str]:
    """Return human-readable consistency errors (duplicates, bad values)."""
    problems: list[str] = []
    seen: set[str] = set()
    for r in _ALL:
        if r.rule_id in seen:
            problems.append(f'duplicate rule id {r.rule_id}')
        seen.add(r.rule_id)
        if r.severity not in ('critical', 'high', 'medium', 'low'):
            problems.append(f'{r.rule_id}: invalid severity {r.severity!r}')
        if r.pattern:
            try:
                re.compile(r.pattern)
            except re.error as exc:
                problems.append(f'{r.rule_id}: bad pattern ({exc})')
    return problems
