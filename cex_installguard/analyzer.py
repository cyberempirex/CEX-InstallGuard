"""AST-based security analyzer for CEX-InstallGuard v12.

Replaces regex-only execution detection with structured analysis of the
parsed command tree (:mod:`cex_installguard.shellparser`):

* **Command/argument analysis** — flags, targets and modes are read from
  parsed words, so ``rm -rf "$SAFE_DIR"`` (quoted variable) is no longer
  confused with ``rm -rf $TARGET/*`` (unquoted glob), and a ``PATH=``
  assignment that merely appends to ``$PATH`` is not flagged as injection.
* **Pipeline awareness** — ``curl … | sh`` is detected from actual pipeline
  adjacency, not a regex that also matches unrelated nearby lines.
* **Dataflow tracking** — URL-derived variables and files staged by
  downloads/decodes are tracked across the whole file; any later execution
  sink (including ``chmod +x`` then direct invocation many lines apart)
  produces a finding with the full chain as evidence.
* **Context-aware rules** — elevated writes, persistence installs and
  log/system tampering are recognized from the actual target of the write
  (redirect, ``tee``, ``cp``, ``install``), not from substrings anywhere in
  a line.

The analyzer never executes anything. Findings are pure data.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .models import Finding
from .rules import STRUCTURAL_BY_ID
from .shellparser import (Command, Group, Pipeline, Statement, Word,
                          parse, walk_statements)

# --------------------------------------------------------------------------- #
# Shared matchers                                                              #
# --------------------------------------------------------------------------- #

URL_RE = re.compile(r'(?:https?|ftp)://', re.I)
IP_URL_RE = re.compile(r'https?://\d{1,3}(?:\.\d{1,3}){3}', re.I)
HTTP_PLAIN_RE = re.compile(r'["\x27\s]http://', re.I)
BASE64ISH_RE = re.compile(r'^[A-Za-z0-9+/=]{120,}$')
RETrieval_NAMES = ('curl', 'wget', 'fetch', 'aria2c')
DECODE_NAMES = ('base64', 'openssl', 'xxd')
EXEC_NAMES = {'bash', 'sh', 'zsh', 'dash', 'ksh', 'source', '.', 'exec',
              'eval'}
INTERPRETERS = {'python', 'python3', 'perl', 'ruby', 'node', 'php', 'pwsh'}
PRIV_NAMES = {'sudo', 'su', 'doas', 'runuser'}
SENSITIVE_WRITE_PREFIXES = ('/etc/', '/boot/', '/usr/lib/systemd/',
                            '/etc/systemd/')
PERSISTENCE_WRITE_PREFIXES = ('/etc/cron', '/var/spool/cron', '/etc/rc.local',
                              '/etc/profile', '/etc/profile.d/',
                              '/etc/sudoers')
TMP_PREFIXES = ('/tmp/', '/var/tmp/', '/dev/shm/')
BLOCK_DEVICE_RE = re.compile(r'^/dev/(?:sd|nvme|mmcblk|vd)[a-z0-9]*')
URL_VAR_RE = re.compile(r'(?:https?|ftp)://')
SECRET_NAME_RE = re.compile(
    r'(?i)^(?:password|passwd|api[_-]?key|apikey|secret|token|'
    r'access[_-]?key)$')
SECRET_PRINT_RE = re.compile(r'(?:TOKEN|PASSWORD|SECRET|API[_-]?KEY)')
CRYPTOMINE_RE = re.compile(
    r'(?i)(?:xmrig|minerd|stratum\+tcp|cryptonight|nicehash|mining.?pool)')
REVERSE_SHELL_RE = re.compile(r'^/dev/tcp/[^/]+/\d+$')
PACKAGES = {'apt', 'apt-get', 'dnf', 'yum', 'pacman', 'apk', 'brew', 'pip',
            'pip3', 'npm', 'gem'}
PACKAGE_ACTIONS = {'install', 'remove', 'uninstall', 'erase', 'autoremove'}

severity_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

# Command wrappers: utilities that simply run the command that follows.
# ``sudo -u bob curl …`` and ``timeout 30 curl …`` really run ``curl``.
WRAPPERS = {'sudo', 'doas', 'nice', 'nohup', 'timeout', 'env', 'command',
            'builtin', 'stdbuf', 'setsid', 'ionice', 'exec', 'xargs'}
# Wrapper flags that consume the following token as a value.
_VALUE_FLAGS = {'-u', '-g', '-p', '-C', '-r', '-t', '-D', '-n', '-c',
                '--user', '--group', '--chdir'}
_DURATION_RE = re.compile(r'^\d+(?:\.\d+)?[smhd]?$')
_ASSIGN_RE = re.compile(r'^[A-Za-z_]\w*=')


# --------------------------------------------------------------------------- #
# Rule metadata (merged into the public registry by rules.py)                  #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class StructuralRuleMeta:
    rule_id: str
    title: str
    severity: str
    category: str
    description: str
    remediation: str
    confidence: str = 'high'
    tags: tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# Analyzer                                                                     #
# --------------------------------------------------------------------------- #

@dataclass
class Artifact:
    """A file the script brings into existence or modifies, tracked through
    its lifecycle so that *downloaded*, *made executable*, *interpreted*,
    *sourced* and *executed* are never conflated.

    ``origin`` records how the file's content arrived (``download`` or
    ``decode``); ``executable`` records an execute-bit grant; and each
    lifecycle finding names the exact causal command and the full chain.
    """
    path: str
    origin: str = ''                 # 'download' | 'decode' | ''
    origin_line: int = 0
    origin_command: str = ''
    executable: bool = False
    exec_line: int = 0
    exec_command: str = ''
    reported: set[str] = field(default_factory=set)


@dataclass
class _FileState:
    remote_vars: set[str] = field(default_factory=set)
    artifacts: dict[str, Artifact] = field(default_factory=dict)
    seen_fingerprints: set[str] = field(default_factory=set)
    var_values: dict[str, str] = field(default_factory=dict)


class Analyzer:
    """Analyzes one parsed shell script. Instantiate per file.

    ``state`` may be shared with a parent analyzer so that recursive
    analysis of embedded script bodies (command substitutions, ``eval``
    strings, heredocs written to files) sees the same variable values,
    remote-content taint and staged artifacts as the outer script.
    """

    MAX_DEPTH = 24        # bounds recursion on adversarial nested payloads

    def __init__(self, source: str = '<text>', state: _FileState | None = None,
                 depth: int = 0):
        self.source = source
        self.findings: list[Finding] = []
        self.state = state if state is not None else _FileState()
        self.depth = depth

    def _analyze_embedded(self, text: str, line: int) -> None:
        """Recursively analyze embedded shell code with shared state.

        Recursion is depth-bounded so a deeply nested payload
        (``eval "eval \"eval …\""``) degrades gracefully instead of
        raising ``RecursionError``.
        """
        if not text or not text.strip():
            return
        if self.depth >= self.MAX_DEPTH:
            self.add('IG052', line, text.strip()[:240])
            return
        sub = Analyzer(self.source, state=self.state, depth=self.depth + 1)
        for f in sub.analyze(text):
            f.line = line
            self.findings.append(f)

    # -- plumbing ---------------------------------------------------------- #

    def add(self, rule_id: str, line: int, code: str,
            evidence: Optional[dict] = None) -> None:
        """Add a finding; title/severity/category come from the registry."""
        meta = STRUCTURAL_BY_ID.get(rule_id)
        self.findings.append(Finding(
            rule_id=rule_id,
            title=meta.title if meta else rule_id,
            severity=meta.severity if meta else 'medium',
            category=meta.category if meta else 'general',
            confidence=meta.confidence if meta else 'medium',
            line=line, column=1, code=code.strip()[:240],
            description=meta.description if meta else '',
            remediation=meta.remediation if meta else '',
            source=self.source,
            evidence=evidence or {}))

    def analyze(self, text: str) -> list[Finding]:
        statements = parse(text)
        self._analyze_statements(statements)
        self.findings.sort(key=lambda f: (f.line, severity_rank.get(
            f.severity, 9), f.rule_id))
        return self.findings

    def _analyze_statements(self, stmts: list[Statement]) -> None:
        for stmt in stmts:
            for node in stmt.nodes:
                if isinstance(node, Group):
                    self._analyze_statements(node.body)
                else:
                    self._pipeline(node, stmt)
            self._statement_adjacency(stmt)

    def _statement_adjacency(self, stmt: Statement) -> None:
        """IG031: retrieval and an execution primitive joined in one
        statement (``curl … && chmod +x f && ./f``) but not piped."""
        pipes = [n for n in stmt.nodes if isinstance(n, Pipeline)]
        if not pipes:
            return
        has_retrieval = any(
            c.name in RETrieval_NAMES for p in pipes for c in p.commands)
        if not has_retrieval:
            return
        for p in pipes:
            for c in p.commands:
                execish = (c.name in EXEC_NAMES
                           or c.name == 'chmod' and
                           any(a in ('+x', 'u+x') for a in c.args()))
                if execish and not (len(p.commands) > 1 and
                                     any(x.name in RETrieval_NAMES
                                         for x in p.commands) and
                                     c.name in EXEC_NAMES):
                    self.add('IG031', c.line, self._cmd_text(c),
                             evidence={'statement': [
                                 self._cmd_text(x) for p2 in pipes
                                 for x in p2.commands][:6]})
                    return

    # -- pipeline level ---------------------------------------------------- #

    def _pipeline(self, pipe: Pipeline, stmt: Statement) -> None:
        cmds = pipe.commands
        names = [self._effective_name(c) for c in cmds]
        joined = ' | '.join(self._cmd_text(c) for c in cmds)

        # --- remote pipe to shell / interpreter ------------------------ #
        if any(n in RETrieval_NAMES for n in names):
            for i, c in enumerate(cmds):
                if names[i] in RETrieval_NAMES and i == 0:
                    rest = names[i + 1:]
                    if 'sh' in rest or 'bash' in rest or 'eval' in rest:
                        self.add('IG001', c.line, joined)
                    elif any(n in INTERPRETERS for n in rest):
                        self.add('IG034', c.line, joined)

        # --- decode + exec in the same pipeline -------------------------- #
        decodes = [c for c in cmds if self._is_decode(c)]
        execs = [c for c in cmds if c.name in EXEC_NAMES or
                 c.name in INTERPRETERS and c.has_flag('-c', '-e', '--eval')]
        if decodes and execs:
            self.add('IG032', decodes[0].line, joined)

        # --- per-command analysis ----------------------------------------- #
        for c in cmds:
            self._command(c, pipe, stmt)

        # --- artifact origin from pipeline redirects / tee ---------------- #
        line = cmds[0].line if cmds else 1
        if any(c.name in RETrieval_NAMES for c in cmds):
            for target in self._write_targets(cmds):
                self._record_artifact(target, 'download', line, joined)
        if decodes:
            for target in self._write_targets(cmds):
                self._record_artifact(target, 'decode', line, joined)

    def _write_targets(self, cmds: list[Command]) -> list[str]:
        """Files written by this pipeline: redirects and tee arguments."""
        out: list[str] = []
        for c in cmds:
            for r in c.redirects:
                if r.op in ('>', '>>', '&>') and r.target.text:
                    out.append(self._norm_path(r.target.text))
            if c.name == 'tee' and not c.has_flag('-a'):
                for w in c.arg_words():
                    if not w.text.startswith('-'):
                        out.append(self._norm_path(w.text))
        return out

    @staticmethod
    def _norm_path(p: str) -> str:
        p = p.strip('"\'')
        if p.startswith('./'):
            p = p[2:]
        return p

    @staticmethod
    def _is_decode(c: Command) -> bool:
        if c.name == 'base64' and c.has_flag('-d', '-D', '--decode'):
            return True
        if c.name == 'openssl' and c.has_flag('-d') or \
                (c.name == 'openssl' and 'enc' in c.args() and
                 any(a in ('-d', '-D') for a in c.args())):
            return True
        if c.name == 'xxd' and c.has_flag('-r', '-revert'):
            return True
        return False

    def _effective_name(self, c: Command) -> str:
        """Resolve the command name actually being run.

        Handles `mkfs.*` variants, command wrappers that simply run the
        command that follows (`sudo -u bob curl …`, `timeout 30 curl …`,
        `env VAR=x cmd`, `curl … | xargs sh`), and indirect command names
        (`C=curl; $C …`). Resolution happens before any rule dispatch so
        pipeline-level checks see the same name.
        """
        name = c.name
        # indirect command names: `C=curl; $C …`
        if name.startswith('$'):
            resolved = self.state.var_values.get(name.strip('${}'), '')
            if resolved:
                name = resolved.rsplit('/', 1)[-1]
        # command wrappers run the command that follows them
        hops = 0
        while name in WRAPPERS and hops < 8:
            hops += 1
            ws = c.arg_words()
            i, nxt = 0, None
            while i < len(ws):
                t = ws[i].text
                if t.startswith('-'):
                    i += 2 if t in _VALUE_FLAGS else 1
                    continue
                if _DURATION_RE.match(t) or _ASSIGN_RE.match(t):
                    i += 1
                    continue
                nxt = t.rsplit('/', 1)[-1]
                break
            if not nxt or nxt == name:
                break
            name = nxt
        if re.match(r'^mkfs\.', name):
            return 'mkfs'
        return name

    @staticmethod
    def _cmd_text(c: Command) -> str:
        bits = [f'{k}={v.text}' for k, v in c.assignments] + \
            [w.text for w in c.words]
        for r in c.redirects:
            bits.append(f'{r.op}{r.target.text}')
        return ' '.join(bits)

    # -- command level ------------------------------------------------------ #

    def _command(self, c: Command, pipe: Pipeline, stmt: Statement) -> None:
        name = c.name

        # assignments (prefix or standalone statement)
        for var, value in c.assignments:
            self._assignment(c, var, value)

        if not name:
            return

        if name == 'export':
            for w in c.arg_words():
                if '=' in w.text:
                    var, _, val = w.text.partition('=')
                    self._assignment(c, var, Word(val, w.segments, w.quoted))
            return

        # effective command name: mkfs.* variants, wrapper prefixes
        # (`sudo`/`timeout`/`env`/`xargs`) and indirect names (`C=curl; $C`)
        raw_name = name
        name = self._effective_name(c)
        if raw_name != name:
            pre = _HANDLERS.get(raw_name)
            if pre is not None:            # e.g. sudo → privilege finding
                pre(self, c, pipe, stmt)

        # `eval` and `bash -c` with static string bodies: the body is
        # itself shell code — parse and analyze it with shared state.
        if name == 'eval' and c.arg_words() and \
                all(w.is_static() for w in c.arg_words()):
            self._analyze_embedded(' '.join(w.text for w in c.arg_words()),
                                   c.line)
        elif name in ('bash', 'sh', 'zsh', 'dash', 'ksh') and c.has_flag('-c'):
            vals = [w for w in c.arg_words() if not w.text.startswith('-')]
            if vals and all(w.is_static() for w in vals):
                self._analyze_embedded(vals[0].text.strip('"\''), c.line)

        # heredoc written to a file: the body is (usually) a script
        has_output = any(r.op in ('>', '>>', '&>') for r in c.redirects)
        if has_output:
            for r in c.redirects:
                if r.op == '<<' and r.heredoc_body.strip():
                    self._analyze_embedded(r.heredoc_body, c.line)

        # copying a staged artifact keeps it staged (taint through cp/mv)
        if name in ('cp', 'mv', 'install'):
            pargs = [self._norm_path(w.text) for w in c.arg_words()
                     if not w.text.startswith('-')]
            if len(pargs) >= 2:
                dest = pargs[-1]
                for srcp in pargs[:-1]:
                    art = self._artifact(srcp)
                    if art and art.origin:
                        new_art = self.state.artifacts.get(dest) or \
                            Artifact(path=dest)
                        if not new_art.origin:
                            new_art.origin = art.origin
                            new_art.origin_line = art.origin_line
                            new_art.origin_command = art.origin_command
                        # `install -m 755 src dest` also grants execute
                        if name == 'install':
                            mvals = c.flag_values(('-m', '--mode'))
                            if mvals and self._mode_grants_exec(mvals[0].text):
                                new_art.executable = True
                                new_art.exec_line = c.line
                                new_art.exec_command = self._cmd_text(c)
                        self.state.artifacts[dest] = new_art

        handler = _HANDLERS.get(name)
        if handler:
            handler(self, c, pipe, stmt)

        # any command with an output redirect writes files: analyze targets
        if any(r.op in ('>', '>>', '&>') for r in c.redirects):
            targets = [self._norm_path(r.target.text)
                       for r in c.redirects
                       if r.op in ('>', '>>', '&>') and r.target.text]
            _check_write_targets(self, c, targets)

        # plain decode command (no exec adjacent → still worth reporting)
        if self._is_decode(c):
            self.add('IG016', c.line, self._cmd_text(c))

        # command substitutions inside any word: analyze recursively
        for w in c.words:
            for inner in w.cmdsubs:
                if inner.strip().split(' ', 1)[0] in RETrieval_NAMES:
                    self.add('IG011', c.line, self._cmd_text(c),
                             evidence={'substitution': inner.strip()[:120]})
                if self.depth < self.MAX_DEPTH:
                    sub = Analyzer(self.source, state=self.state,
                                   depth=self.depth + 1)
                    for f in sub.analyze(inner):
                        f.line = c.line
                        self.findings.append(f)

        # generic URL arguments
        if name in RETrieval_NAMES:
            self._retrieval(c)

        # artifact lifecycle transitions
        self._lifecycle(c)

        # cryptomining indicators in any word
        for w in c.words:
            if CRYPTOMINE_RE.search(w.text):
                self.add('IG043', c.line, self._cmd_text(c))
                break

        # /dev/tcp reverse-shell redirection in any word or redirect target
        for w in c.words[1:] + [r.target for r in c.redirects]:
            if REVERSE_SHELL_RE.match(w.text.strip('"\'')):
                self.add('IG022', c.line, self._cmd_text(c),
                         evidence={'endpoint': w.text})
                break

    # -- assignments --------------------------------------------------------- #

    def _assignment(self, cmd: Command, var: str, value: Word) -> None:
        text = value.text

        # PATH / library injection (FP-fixed: appending to $PATH is benign)
        if var == 'PATH':
            if 'PATH' not in value.vars:      # no $PATH reference → replace
                self.add('IG020', cmd.line, f'{var}={text}')
        elif var in ('LD_PRELOAD', 'LD_LIBRARY_PATH'):
            self.add('IG020', cmd.line, f'{var}={text}')

        # history suppression
        if var == 'HISTSIZE' and text.strip() in ('0', '""', "''"):
            self.add('IG041', cmd.line, f'{var}={text}', evidence={'variable': var})

        # credential-like literal
        if SECRET_NAME_RE.match(var):
            lit = next((s[1] for s in value.segments
                        if s[0] == 'lit'), '')
            if len(lit) >= 8:
                self.add('IG018', cmd.line, f'{var}=***')

        # dataflow: URL or remote-substitution values
        if URL_VAR_RE.search(text) or any(
                inner.strip().split(' ', 1)[0] in RETrieval_NAMES
                for inner in value.cmdsubs):
            self.state.remote_vars.add(var)
        elif any(v in self.state.remote_vars for v in value.vars):
            self.state.remote_vars.add(var)      # indirection: A=$B
        else:
            self.state.remote_vars.discard(var)

        # track simple literal values (for indirect command names) and
        # resolve one-step chains: `A=curl; B=$A; $B …`
        if value.is_static() and len(text) < 200:
            self.state.var_values[var] = text.strip('"\'')
        elif (len(value.vars) == 1 and not value.cmdsubs
              and value.vars[0] in self.state.var_values):
            self.state.var_values[var] = self.state.var_values[value.vars[0]]
        else:
            self.state.var_values.pop(var, None)

    def _sink_check(self, c: Command, w: Word) -> None:
        """A word referencing remote vars inside an execution primitive."""
        used = set(w.vars) & self.state.remote_vars
        if used and (c.name in EXEC_NAMES or c.name in INTERPRETERS):
            self.add('IG047', c.line, self._cmd_text(c), evidence={'variables': sorted(used)})

    # -- artifact lifecycle ------------------------------------------------- #

    def _record_artifact(self, path: str, kind: str, line: int,
                         command: str) -> None:
        """Register a file whose content arrived from ``kind`` (if new)."""
        if not path:
            return
        art = self.state.artifacts.get(path)
        if art is None:
            art = Artifact(path=path)
            self.state.artifacts[path] = art
        if kind and not art.origin:
            art.origin = kind
            art.origin_line = line
            art.origin_command = command

    def _artifact(self, text: str) -> Optional[Artifact]:
        """Resolve a word to a tracked artifact.

        Exact path match first; a slash-less word may also match a tracked
        artifact by basename (``bash x`` where ``./x`` was downloaded).
        Basename matching is deliberately not applied to slashed paths, to
        keep attribution precise.
        """
        if not text:
            return None
        p = self._norm_path(text)
        if p in self.state.artifacts:
            return self.state.artifacts[p]
        if '/' not in text:
            for path, art in self.state.artifacts.items():
                if path.rsplit('/', 1)[-1] == p:
                    return art
        return None

    @staticmethod
    def _mode_grants_exec(mode: str) -> bool:
        if mode in ('+x', 'u+x', 'a+x', 'g+x', 'o+x', 'ugo+x'):
            return True
        return mode.isdigit() and bool(int(mode, 8) & 0o111)

    @staticmethod
    def _looks_like_path(text: str) -> bool:
        return '/' in text or text.startswith('.')

    def _report_lifecycle(self, rule_id: str, c: Command, art: Artifact,
                          action: str) -> None:
        """Emit one lifecycle finding, anchored at the acting command and
        carrying the exact causal command plus the full chain."""
        key = f'{rule_id}:{art.path}'
        if key in art.reported:
            return
        art.reported.add(key)
        chain = []
        if art.origin:
            chain.append({'step': art.origin, 'line': art.origin_line,
                          'command': art.origin_command})
        if art.exec_line and action != 'made executable':
            chain.append({'step': 'made executable', 'line': art.exec_line,
                          'command': art.exec_command})
        chain.append({'step': action, 'line': c.line,
                      'command': self._cmd_text(c)})
        self.add(rule_id, c.line, self._cmd_text(c), evidence={
            'artifact': art.path,
            'action': action,
            'causal_command': art.origin_command,
            'causal_line': art.origin_line,
            'chain': chain,
        })

    def _lifecycle(self, c: Command) -> None:
        """Distinguish the five artifact transitions.

        * ``IG048`` executed      — the artifact path is the command itself
        * ``IG050`` interpreted   — passed to bash/sh/python/perl/...
        * ``IG051`` sourced       — ``. file`` / ``source file``
        * ``IG049`` made executable — ``chmod +x`` (preparation, not running)
        Each is reported once per artifact, at the acting command's line.
        """
        name = self._effective_name(c)
        if not c.words:
            return

        # (a) direct execution: the command word is a tracked path
        head = c.words[0]
        if self._looks_like_path(head.text):
            art = self._artifact(head.text)
            if art and art.origin:
                self._report_lifecycle('IG048', c, art, 'executed')

        # (b) execute-bit grant: preparation, not execution
        if name == 'chmod' and c.args():
            if self._mode_grants_exec(c.args()[0]):
                for w in c.arg_words()[1:]:
                    art = self._artifact(w.text)
                    if art and art.origin:
                        art.executable = True
                        art.exec_line = c.line
                        art.exec_command = self._cmd_text(c)
                        self._report_lifecycle('IG049', c, art,
                                               'made executable')

        # (c) interpreted: an interpreter given the artifact as its script
        if name in INTERPRETERS or name in ('bash', 'sh', 'zsh', 'dash',
                                            'ksh'):
            for w in c.arg_words():
                if w.text.startswith('-'):
                    continue
                art = self._artifact(w.text)
                if art and art.origin:
                    self._report_lifecycle('IG050', c, art, 'interpreted')
                    break

        # (d) sourced: evaluated in the current shell
        if name in ('source', '.'):
            for w in c.arg_words():
                art = self._artifact(w.text)
                if art and art.origin:
                    self._report_lifecycle('IG051', c, art, 'sourced')
                    break

    # -- retrieval (curl / wget) ---------------------------------------------- #

    def _retrieval(self, c: Command) -> None:
        text = self._cmd_text(c)
        url_words = [w for w in c.arg_words() if URL_RE.search(w.text)]
        urls = [w.text for w in url_words]

        if urls:
            self.add('IG014', c.line, text)

        # staging into files
        staged = [self._norm_path(w.text) for w in
                  c.flag_values(('-o', '--output', '-O'))]
        for r in c.redirects:
            if r.op in ('>', '>>', '&>') and r.target.text:
                staged.append(self._norm_path(r.target.text))
        for p in staged:
            self._record_artifact(p, 'download', c.line, text)
            if any(p.startswith(t) for t in TMP_PREFIXES):
                self.add('IG023', c.line, text)

        if c.has_flag('-k', '--insecure', '--no-check-certificate'):
            self.add('IG035', c.line, text)

        for w in url_words:
            if IP_URL_RE.search(w.text):
                self.add('IG037', c.line, text)
            if HTTP_PLAIN_RE.search(' ' + w.text):
                self.add('IG036', c.line, text)

        # remote-var usage as URL (keeps var tracked for sinks)
        for w in c.arg_words():
            self._sink_check(c, w)


# --------------------------------------------------------------------------- #
# Per-command handlers (registered by command name)                            #
# --------------------------------------------------------------------------- #

def _h_rm(a: Analyzer, c: Command, pipe: Pipeline, stmt: Statement) -> None:
    args = c.args()
    recursive = any(re.match(r'^-[a-zA-Z]*r', x) or x == '--recursive'
                    for x in args if x.startswith('-'))
    targets = [w for w in c.arg_words() if not w.text.startswith('-')]
    text = a._cmd_text(c)

    for w in targets:
        t = w.text
        if t in ('/', '/*', '/*/') or re.match(r'^\$\{?\w+\}?/\*$', t):
            if recursive:
                a.add('IG002', c.line, text)
            else:
                a.add('IG019', c.line, text)
        elif t in ('*', './*') or (t.endswith('/*') and t.startswith('/')):
            a.add('IG019', c.line, text)
        elif t.startswith('$') and not w.quoted:
            # FP fix (v12): only *unquoted* variables glob-expand in rm
            a.add('IG030', c.line, text, evidence={'variable': t})
        elif t.startswith('/var/log'):
            a.add('IG027', c.line, text)
        elif t == '$0' or t == '"$0"' or t == "'$0'":
            a.add('IG017', c.line, text)


def _h_dd(a: Analyzer, c: Command, pipe: Pipeline, stmt: Statement) -> None:
    text = a._cmd_text(c)
    of_targets = [x[3:] for x in c.args() if x.startswith('of=')]
    for r in c.redirects:
        if r.op in ('>', '>>'):
            of_targets.append(r.target.text)
    for t in of_targets:
        if BLOCK_DEVICE_RE.match(t):
            a.add('IG003', c.line, text)
            break


def _h_mkfs(a: Analyzer, c: Command, pipe: Pipeline, stmt: Statement) -> None:
    a.add('IG004', c.line, a._cmd_text(c))


def _h_chmod(a: Analyzer, c: Command, pipe: Pipeline, stmt: Statement) -> None:
    args = c.args()
    text = a._cmd_text(c)
    if not args:
        return
    mode = args[0]
    targets = [w for w in c.arg_words()[1:] if not w.text.startswith('-')]
    if mode in ('777', 'a+rwx', '+rwx'):
        a.add('IG007', c.line, text)
    if mode in ('u+s',) or (mode.isdigit() and len(mode) == 4 and
                            mode.startswith('4')):
        a.add('IG046', c.line, text)
    if mode in ('+x', 'u+x') or (mode.isdigit() and int(mode) & 0o111):
        for w in targets:
            if any(w.text.startswith(t) for t in TMP_PREFIXES):
                a.add('IG028', c.line, text)


def _h_chown(a: Analyzer, c: Command, pipe: Pipeline, stmt: Statement) -> None:
    if c.has_flag('-R', '--recursive'):
        a.add('IG008', c.line, a._cmd_text(c))


def _h_priv(a: Analyzer, c: Command, pipe: Pipeline, stmt: Statement) -> None:
    a.add('IG006', c.line, a._cmd_text(c))
    # elevated system modification: sudo + sensitive target in same statement
    for node in stmt.nodes:
        if isinstance(node, Pipeline):
            for other in node.commands:
                targets = a._write_targets([other])
                for w in other.arg_words():
                    if any(w.text.startswith(p)
                           for p in SENSITIVE_WRITE_PREFIXES):
                        targets.append(a._norm_path(w.text))
                for target in targets:
                    if any(target.startswith(p)
                           for p in SENSITIVE_WRITE_PREFIXES):
                        a.add('IG033', c.line, a._cmd_text(c),
                              evidence={'target': target})
                        return


def _h_killall(a: Analyzer, c: Command, pipe: Pipeline,
               stmt: Statement) -> None:
    if any(not w.text.startswith('-') for w in c.arg_words()):
        a.add('IG025', c.line, a._cmd_text(c))


def _h_firewall(a: Analyzer, c: Command, pipe: Pipeline,
                stmt: Statement) -> None:
    if any(x in ('-F', '--flush', 'flush', 'disable', 'stop', 'delete',
                 'remove') for x in c.args()):
        a.add('IG026', c.line, a._cmd_text(c))


def _h_logtamper(a: Analyzer, c: Command, pipe: Pipeline,
                 stmt: Statement) -> None:
    text = a._cmd_text(c)
    if c.name in ('truncate', 'shred'):
        for w in c.arg_words():
            if '/var/log' in w.text or w.text.endswith('.log'):
                a.add('IG027', c.line, text)
                break


def _h_eval(a: Analyzer, c: Command, pipe: Pipeline, stmt: Statement) -> None:
    for w in c.arg_words():
        a._sink_check(c, w)
        if not w.is_static():
            a.add('IG010', c.line, a._cmd_text(c))
            return


def _h_interpreter(a: Analyzer, c: Command, pipe: Pipeline,
                   stmt: Statement) -> None:
    text = a._cmd_text(c)
    if c.name == 'bash' or c.name == 'sh' or c.name in ('zsh', 'dash', 'ksh'):
        if c.has_flag('-c'):
            for w in c.arg_words():
                if not w.text.startswith('-') and not w.is_static():
                    a.add('IG024', c.line, text)
                    break
    if c.has_flag('-c', '-e', '--eval', '-r'):
        a.add('IG015', c.line, text)
    for w in c.arg_words():
        a._sink_check(c, w)


def _h_exec(a: Analyzer, c: Command, pipe: Pipeline, stmt: Statement) -> None:
    for w in c.arg_words():
        a._sink_check(c, w)
    if c.name in ('source', '.'):
        for w in c.arg_words():
            if re.search(r'(?:\.bashrc|\.profile|\.zshrc|profile\.d)',
                         w.text):
                a.add('IG021', c.line, a._cmd_text(c))


def _h_reverse(a: Analyzer, c: Command, pipe: Pipeline,
               stmt: Statement) -> None:
    text = a._cmd_text(c)
    if c.name in ('nc', 'ncat', 'socat'):
        if c.has_flag('-e') or any('exec:' in x for x in c.args()):
            a.add('IG022', c.line, text)
    if c.name in ('bash', 'sh', 'zsh', 'dash', 'ksh', 'exec'):
        for w in c.arg_words():
            if REVERSE_SHELL_RE.match(w.text):
                a.add('IG022', c.line, text)


def _h_setenforce(a: Analyzer, c: Command, pipe: Pipeline,
                  stmt: Statement) -> None:
    if '0' in c.args():
        a.add('IG042', c.line, a._cmd_text(c))


def _h_aa(a: Analyzer, c: Command, pipe: Pipeline, stmt: Statement) -> None:
    if c.name in ('aa-disable', 'aa-complain'):
        a.add('IG042', c.line, a._cmd_text(c))


def _h_history(a: Analyzer, c: Command, pipe: Pipeline,
               stmt: Statement) -> None:
    if '-c' in c.args():
        a.add('IG041', c.line, a._cmd_text(c))


def _h_unset(a: Analyzer, c: Command, pipe: Pipeline,
             stmt: Statement) -> None:
    if any(x in ('HISTFILE', 'HISTSIZE') for x in c.args()):
        a.add('IG041', c.line, a._cmd_text(c))


def _h_set(a: Analyzer, c: Command, pipe: Pipeline, stmt: Statement) -> None:
    if '+o' in c.args() and 'history' in c.args():
        a.add('IG041', c.line, a._cmd_text(c))


def _h_useradd(a: Analyzer, c: Command, pipe: Pipeline,
               stmt: Statement) -> None:
    a.add('IG039', c.line, a._cmd_text(c))


def _h_package(a: Analyzer, c: Command, pipe: Pipeline,
               stmt: Statement) -> None:
    if any(x in PACKAGE_ACTIONS for x in c.args()):
        a.add('IG012', c.line, a._cmd_text(c))


def _h_crontab(a: Analyzer, c: Command, pipe: Pipeline,
               stmt: Statement) -> None:
    if any(x.startswith('-') and not x.startswith('--') for x in c.args()):
        a.add('IG013', c.line, a._cmd_text(c))


def _h_systemctl(a: Analyzer, c: Command, pipe: Pipeline,
                 stmt: Statement) -> None:
    if any(x in ('enable', 'link', 'preset') for x in c.args()):
        a.add('IG013', c.line, a._cmd_text(c))


def _check_write_targets(a: Analyzer, c: Command, targets: list) -> None:
    """Shared sensitive-target analysis for any file-writing command."""
    text = a._cmd_text(c)
    for t in targets:
        if any(t.startswith(p) for p in SENSITIVE_WRITE_PREFIXES):
            if t.startswith('/etc/sudoers') or 'sudoers' in t:
                a.add('IG040', c.line, text)
            else:
                a.add('IG009', c.line, text)
        if 'authorized_keys' in t:
            a.add('IG038', c.line, text)
        if t.startswith('/etc/hosts') or t.startswith('/etc/resolv'):
            a.add('IG045', c.line, text)
        if any(t.startswith(p) for p in PERSISTENCE_WRITE_PREFIXES):
            if 'sudoers' not in t:
                a.add('IG013', c.line, text)
        if t.startswith('/var/log') and c.name in ('cp', 'install', 'mv',
                                                   'tee'):
            a.add('IG027', c.line, text)


def _h_write_cmd(a: Analyzer, c: Command, pipe: Pipeline,
                 stmt: Statement) -> None:
    """cp / install / mv / tee: writes to sensitive targets."""
    targets = [a._norm_path(w.text) for w in c.arg_words()[1:]
               if not w.text.startswith('-')]
    for r in c.redirects:
        if r.op in ('>', '>>', '&>') and r.target.text:
            targets.append(a._norm_path(r.target.text))
    if c.name == 'tee':
        targets = [a._norm_path(w.text) for w in c.arg_words()
                   if not w.text.startswith('-')]
    _check_write_targets(a, c, targets)


def _h_secretprint(a: Analyzer, c: Command, pipe: Pipeline,
                   stmt: Statement) -> None:
    """FP fix (v12): only flags printing a *variable* that looks secret."""
    for w in c.arg_words():
        if w.vars and any(SECRET_PRINT_RE.search(v) for v in w.vars):
            a.add('IG029', c.line, a._cmd_text(c))
            return


def _h_unlink(a: Analyzer, c: Command, pipe: Pipeline,
              stmt: Statement) -> None:
    if any(w.text.strip('"\'') == '$0' for w in c.arg_words()):
        a.add('IG017', c.line, a._cmd_text(c))


_HANDLERS: dict[str, Callable] = {
    'rm': _h_rm,
    'dd': _h_dd,
    'mkfs': _h_mkfs, 'mkswap': _h_mkfs,
    'chmod': _h_chmod,
    'chown': _h_chown,
    'sudo': _h_priv, 'su': _h_priv, 'doas': _h_priv, 'runuser': _h_priv,
    'killall': _h_killall, 'pkill': _h_killall,
    'iptables': _h_firewall, 'nft': _h_firewall, 'ufw': _h_firewall,
    'firewall-cmd': _h_firewall,
    'truncate': _h_logtamper, 'shred': _h_logtamper,
    'eval': _h_eval,
    'python': _h_interpreter, 'python3': _h_interpreter,
    'perl': _h_interpreter, 'ruby': _h_interpreter, 'node': _h_interpreter,
    'php': _h_interpreter,
    'bash': _h_interpreter, 'sh': _h_interpreter, 'zsh': _h_interpreter,
    'dash': _h_interpreter, 'ksh': _h_interpreter,
    'exec': _h_exec, 'source': _h_exec, '.': _h_exec,
    'nc': _h_reverse, 'ncat': _h_reverse, 'socat': _h_reverse,
    'setenforce': _h_setenforce, 'aa-disable': _h_aa, 'aa-complain': _h_aa,
    'history': _h_history, 'unset': _h_unset, 'set': _h_set,
    'useradd': _h_useradd, 'adduser': _h_useradd,
    'groupadd': _h_useradd, 'addgroup': _h_useradd,
    'apt': _h_package, 'apt-get': _h_package, 'dnf': _h_package,
    'yum': _h_package, 'pacman': _h_package, 'apk': _h_package,
    'brew': _h_package, 'pip': _h_package, 'pip3': _h_package,
    'npm': _h_package, 'gem': _h_package,
    'crontab': _h_crontab,
    'systemctl': _h_systemctl,
    'cp': _h_write_cmd, 'install': _h_write_cmd, 'mv': _h_write_cmd,
    'tee': _h_write_cmd,
    'echo': _h_secretprint, 'printf': _h_secretprint,
    'env': _h_secretprint, 'printenv': _h_secretprint,
    'unlink': _h_unlink,
}


def analyze_text(text: str, source: str = '<text>') -> list[Finding]:
    """Analyze one script and return its findings (structural layer)."""
    return Analyzer(source).analyze(text)
