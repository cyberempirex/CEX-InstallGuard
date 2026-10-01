"""Structured shell tokenizer and parser for CEX-InstallGuard v12.

This module replaces regex-only execution detection with a real (if
pragmatic) POSIX-ish shell grammar. It never executes anything — it is pure
text analysis, tolerant by design: malformed input degrades into words
rather than raising, so the analyzer always has something to inspect and
adversarial scripts cannot crash the scanner.

Supported syntax
----------------
* comments (``#`` at word start, honoring quotes)
* single / double quotes and backslash escapes
* adjacent-segment concatenation (``cu`` + ``rl`` → one word ``curl``)
* variable expansions ``$VAR`` / ``${VAR}``
* command substitutions ``$(...)`` and legacy backticks (recursively parsed
  by the analyzer)
* pipelines ``a | b | c``
* sequences ``;``, ``&&``, ``||`` and newlines
* redirections ``> >> < 2> 2>> &>`` and heredocs ``<<TAG``
* background ``&`` and subshell groups ``( ... )``
* variable-assignment command prefixes (``VAR=x cmd ...``)
* line continuations (backslash-newline)

Not modeled (treated as plain words): arithmetic ``$((...))`` (opaque
expansion), process substitution, ``case``/``if`` control-flow keywords
(they surface as ordinary words, which the analyzer can ignore), globs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Union


# --------------------------------------------------------------------------- #
# Model                                                                        #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Expansion:
    """One expansion inside a word: a variable or a command substitution."""
    kind: str                      # 'var' | 'cmdsub' | 'backtick' | 'arith'
    name: str = ''                 # variable name, or inner command text


# A word segment is ('lit', text) or ('exp', Expansion).
Segment = tuple[str, Union[str, Expansion]]


@dataclass
class Word:
    """A shell word (command name or argument) with its internal structure.

    ``text`` is the reconstructed source text; ``segments`` keep the
    structure so callers can tell quoted from unquoted and static from
    expanded. ``quoted`` is True when any part came from quotes.
    """
    text: str
    segments: list[Segment] = field(default_factory=list)
    quoted: bool = False

    # -- convenience ------------------------------------------------------- #
    def has_cmdsub(self) -> bool:
        return any(s[0] == 'exp' and s[1].kind in ('cmdsub', 'backtick')
                   for s in self.segments)

    @property
    def vars(self) -> list[str]:
        """Variable names referenced anywhere in the word."""
        return [s[1].name for s in self.segments
                if s[0] == 'exp' and s[1].kind == 'var' and s[1].name]

    @property
    def cmdsubs(self) -> list[str]:
        """Inner command texts of $(...) / backtick substitutions."""
        return [s[1].name for s in self.segments
                if s[0] == 'exp' and s[1].kind in ('cmdsub', 'backtick')]

    def is_static(self) -> bool:
        """True when the word contains no expansions at all."""
        return not any(s[0] == 'exp' for s in self.segments)


@dataclass
class Redirect:
    op: str                          # '>', '>>', '<', '2>', '2>>', '&>', '<<'
    target: Word
    heredoc_tag: str = ''
    heredoc_body: str = ''


@dataclass
class Command:
    """A single simple command: ``VAR=x cmd arg1 arg2 < in > out``."""
    assignments: list[tuple[str, Word]] = field(default_factory=list)
    words: list[Word] = field(default_factory=list)
    redirects: list[Redirect] = field(default_factory=list)
    line: int = 1

    @property
    def name(self) -> str:
        """Command name with leading path stripped (/usr/bin/curl → curl)."""
        if not self.words:
            return ''
        return self.words[0].text.rsplit('/', 1)[-1]

    def arg_words(self) -> list[Word]:
        return self.words[1:]

    def args(self) -> list[str]:
        return [w.text for w in self.words[1:]]

    def flag_values(self, flags: tuple[str, ...]) -> list[Word]:
        """Words that immediately follow any of ``flags`` (e.g. -o/--output)."""
        out: list[Word] = []
        ws = self.words
        for i, w in enumerate(ws):
            if i > 0 and w.text in flags and i + 1 < len(ws):
                out.append(ws[i + 1])
        return out

    def has_flag(self, *flags: str) -> bool:
        return any(w.text in flags for w in self.words[1:])


@dataclass
class Pipeline:
    commands: list[Command] = field(default_factory=list)
    background: bool = False

    def command_names(self) -> list[str]:
        return [c.name for c in self.commands]


@dataclass
class Group:
    """A parenthesized subshell: ``( cd /tmp && curl x | sh )``."""
    body: list['Statement'] = field(default_factory=list)
    line: int = 1


Node = Union[Pipeline, Group]


@dataclass
class Statement:
    """One complete statement: nodes joined by ``;``, ``&&`` or ``||``."""
    nodes: list[Node] = field(default_factory=list)
    joiners: list[str] = field(default_factory=list)
    line: int = 1


class ParseError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Tokenizer                                                                    #
# --------------------------------------------------------------------------- #

_MULTI_OPS = ('&&', '||', '>>', '<<', ';;')
_SINGLE_OPS = '|;&<>()'
_NAME_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')


@dataclass
class Token:
    kind: str                       # 'word' | 'op' | 'newline'
    text: str
    line: int
    word: Optional[Word] = None
    heredoc_tag: str = ''
    heredoc_body: str = ''


class _Cursor:
    """Flat cursor over source text with line tracking."""

    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.line = 1
        self.n = len(text)

    def eof(self) -> bool:
        return self.pos >= self.n

    def ch(self) -> str:
        return self.text[self.pos] if self.pos < self.n else ''

    def at(self, k: int = 0) -> str:
        p = self.pos + k
        return self.text[p] if p < self.n else ''

    def starts(self, s: str) -> bool:
        return self.text.startswith(s, self.pos)

    def advance(self, k: int = 1) -> None:
        for _ in range(k):
            if self.pos < self.n:
                if self.text[self.pos] == '\n':
                    self.line += 1
                self.pos += 1

    def skip_inline_ws(self) -> None:
        while self.pos < self.n and self.text[self.pos] in ' \t':
            self.advance()

    def skip_to_line_end(self) -> None:
        while self.pos < self.n and self.text[self.pos] != '\n':
            self.advance()


def _find_balanced(cur: _Cursor, open_ch: str, close_ch: str,
                   open_tok: str, close_tok: str) -> str:
    """Read through a balanced region from just after the opener.

    Returns the inner text; cursor is left just after the closer.  Tolerant:
    an unterminated region consumes the rest of the input.
    """
    start = cur.pos
    depth = 1
    quote = None
    while not cur.eof():
        c = cur.ch()
        if quote:
            if c == '\\' and quote == '"':
                cur.advance()
            elif c == quote:
                quote = None
            cur.advance()
            continue
        if c in ('"', "'"):
            quote = c
        elif cur.starts(open_tok):
            depth += 1
            cur.advance(len(open_tok))
            continue
        elif cur.starts(close_tok):
            depth -= 1
            if depth == 0:
                inner = cur.text[start:cur.pos]
                cur.advance(len(close_tok))
                return inner
            cur.advance(len(close_tok))
            continue
        cur.advance()
    return cur.text[start:]


def _read_word(cur: _Cursor) -> Optional[Word]:
    """Read one word from the cursor, or None at a non-word position."""
    segments: list[Segment] = []
    quoted = False
    lit: list[str] = []

    def flush() -> None:
        if lit:
            segments.append(('lit', ''.join(lit)))
            lit.clear()

    started = False
    while not cur.eof():
        c = cur.ch()
        # word terminators
        if c in ' \t\n|;&<>()' and not (c == '(' and False):
            break
        if c == '#' and (not started or (segments == [] and not lit)):
            # comment at word boundary handled by caller; a '#' mid-word is
            # literal text in POSIX only after non-blank — safest: treat as
            # comment when nothing has been consumed for this word yet.
            if not started:
                break
            # mid-word '#' — treat as literal (e.g. C++ style is rare)
            lit.append(c); cur.advance()
            continue
        started = True
        # backslash escape
        if c == '\\':
            nxt = cur.at(1)
            if nxt == '\n':                      # line continuation
                cur.advance(2)
                continue
            if nxt:
                lit.append(nxt)
                cur.advance(2)
                continue
            lit.append(c)
            cur.advance()
            continue
        # single quote: fully literal
        if c == "'":
            quoted = True
            flush()
            cur.advance()
            startp = cur.pos
            while not cur.eof() and cur.ch() != "'":
                cur.advance()
            segments.append(('lit', cur.text[startp:cur.pos]))
            if not cur.eof():
                cur.advance()                     # closing quote
            continue
        # double quote: expansions inside
        if c == '"':
            quoted = True
            cur.advance()
            while not cur.eof() and cur.ch() != '"':
                cc = cur.ch()
                if cc == '\\' and cur.at(1) in ('"', '\\', '$', '`'):
                    lit.append(cur.at(1))
                    cur.advance(2)
                elif cc == '$':
                    _read_dollar(cur, segments, lit)
                elif cc == '`':
                    flush()
                    _read_backtick(cur, segments)
                else:
                    lit.append(cc)
                    cur.advance()
            if not cur.eof():
                cur.advance()                      # closing quote
            continue
        # dollar expansion
        if c == '$':
            flush()
            _read_dollar(cur, segments, lit)
            continue
        # backtick
        if c == '`':
            flush()
            _read_backtick(cur, segments)
            continue
        lit.append(c)
        cur.advance()

    flush()
    if not segments:
        return None
    return _build_word(segments, quoted)


def _read_dollar(cur: _Cursor, segments: list, lit: list) -> None:
    """Read a $ expansion at the cursor (which sits on '$')."""
    if cur.at(1) == '(':
        if cur.at(2) == '(':                      # $((...)) arithmetic
            cur.advance(3)
            inner = _find_balanced(cur, '(', ')', '(', ')')
            # _find_balanced already consumed one level; text starts after ((
            segments.append(('exp', Expansion('arith', inner)))
            return
        cur.advance(2)                           # skip $(
        inner = _find_balanced(cur, '(', ')', '(', ')')
        segments.append(('exp', Expansion('cmdsub', inner)))
        return
    if cur.at(1) == '{':
        cur.advance(2)
        startp = cur.pos
        depth = 1
        while not cur.eof():
            if cur.ch() == '{':
                depth += 1
            elif cur.ch() == '}':
                depth -= 1
                if depth == 0:
                    break
            cur.advance()
        content = cur.text[startp:cur.pos]
        if not cur.eof():
            cur.advance()                        # closing }
        # strip modifiers: ${VAR:-x} → VAR
        m = _NAME_RE.match(content)
        name = m.group(0) if m else content
        segments.append(('exp', Expansion('var', name)))
        return
    m = _NAME_RE.match(cur.text, cur.pos + 1)
    if m:
        cur.advance(1 + m.end() - (cur.pos + 1))
        segments.append(('exp', Expansion('var', m.group(0))))
        return
    # lone '$'
    lit.append('$')
    cur.advance()


def _read_backtick(cur: _Cursor, segments: list) -> None:
    cur.advance()                                 # opening `
    startp = cur.pos
    while not cur.eof() and cur.ch() != '`':
        if cur.ch() == '\\' and cur.at(1) == '`':
            cur.advance()
        cur.advance()
    segments.append(('exp', Expansion('backtick', cur.text[startp:cur.pos])))
    if not cur.eof():
        cur.advance()                             # closing `


def _split_assignment(word: Word) -> Optional[tuple[str, Word]]:
    """Split ``VAR=value`` into ``(VAR, value-word)`` keeping segments.

    A word is an assignment candidate only when its first segment is a
    literal starting with a shell name followed by ``=``. Expansions in the
    value (``X=$(curl ...)``) are preserved for dataflow analysis.
    """
    if not word.segments:
        return None
    kind, first = word.segments[0]
    if kind != 'lit':
        return None
    m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)=(.*)$', first, re.S)
    if not m:
        return None
    rest_lit = m.group(2)
    segments: list[Segment] = ([('lit', rest_lit)] if rest_lit else []) + \
        list(word.segments[1:])
    value = _build_word(segments, word.quoted)
    return m.group(1), value


def _build_word(segments: list[Segment], quoted: bool) -> Word:
    """Reconstruct the source text of a word from its segments."""
    out: list[str] = []
    for kind, val in segments:
        if kind == 'lit':
            out.append(val)
        else:
            if val.kind == 'var':
                out.append('${' + val.name + '}')
            elif val.kind == 'cmdsub':
                out.append('$(' + val.name + ')')
            elif val.kind == 'backtick':
                out.append('`' + val.name + '`')
            else:
                out.append('$(( ' + val.name + ' ))')
    return Word(''.join(out), segments, quoted)


def _read_heredoc_body(cur: _Cursor, tag: str) -> str:
    """Consume a heredoc body from the cursor up to a line equal to ``tag``.

    The cursor must be positioned at the start of the body (just after the
    command line's newline). Tolerant: an unterminated body consumes the
    rest of the input.
    """
    start = cur.pos
    pat = re.compile(r'(?m)^' + re.escape(tag) + r'[ \t]*\r?$')
    m = pat.search(cur.text, cur.pos)
    if m:
        body = cur.text[start:m.start()]
        # advance past the terminator line, counting newlines
        nl = cur.text.count('\n', cur.pos, m.end())
        cur.advance(m.end() - cur.pos)
        cur.line += nl
        return body
    body = cur.text[start:]
    nl = cur.text.count('\n', cur.pos, len(cur.text))
    cur.advance(len(cur.text) - cur.pos)
    cur.line += nl
    return body


def tokenize(text: str) -> list[Token]:
    """Tokenize shell source. Tolerant of malformed input by design."""
    tokens: list[Token] = []
    pending_heredocs: list[Token] = []      # '<<' tokens awaiting their body
    cur = _Cursor(text)

    while not cur.eof():
        cur.skip_inline_ws()

        if cur.eof():
            break

        c = cur.ch()

        # newline — heredoc bodies for this line start after it
        if c == '\n':
            tokens.append(Token('newline', '\n', cur.line))
            cur.advance()
            for tok in pending_heredocs:
                tok.heredoc_body = _read_heredoc_body(cur, tok.heredoc_tag)
            pending_heredocs = []
            continue

        # comment (word-boundary #)
        if c == '#':
            cur.skip_to_line_end()
            continue

        # line continuation
        if c == '\\' and cur.at(1) == '\n':
            cur.advance(2)
            continue

        # heredoc / redirect operators
        if cur.starts('<<'):
            line = cur.line
            cur.advance(2)
            cur.skip_inline_ws()
            tagw = _read_word(cur)
            tag = tagw.text if tagw else ''
            tok = Token('op', '<<', line, heredoc_tag=tag)
            tokens.append(tok)
            if tag:
                pending_heredocs.append(tok)
            continue

        if cur.starts('>>'):
            tokens.append(Token('op', '>>', cur.line))
            cur.advance(2)
            continue

        if c in '|;&<>()':
            for op in _MULTI_OPS:
                if cur.starts(op):
                    tokens.append(Token('op', op, cur.line))
                    cur.advance(len(op))
                    break
            else:
                tokens.append(Token('op', c, cur.line))
                cur.advance()
            continue

        # fd-prefixed redirect: 2> / 2>> / 3> ...
        m = re.match(r'\d+(>>?)', cur.text[cur.pos:])
        if m and (cur.pos == 0 or cur.text[cur.pos - 1] in ' \t\n;|&('):
            op = m.group(0)
            tokens.append(Token('op', op, cur.line))
            cur.advance(len(op))
            continue

        # plain word
        wline = cur.line
        w = _read_word(cur)
        if w is not None:
            tokens.append(Token('word', w.text, wline, word=w))
        elif not cur.eof() and cur.ch() not in ' \t\n':
            # defensive: consume one char to guarantee progress
            cur.advance()

    for tok in pending_heredocs:
        tok.heredoc_body = _read_heredoc_body(cur, tok.heredoc_tag)
    return tokens


# --------------------------------------------------------------------------- #
# Parser                                                                       #
# --------------------------------------------------------------------------- #

_REDIRECT_OPS = ('>', '>>', '<', '2>', '2>>', '&>', '<<')
_JOINERS = ('&&', '||')

# Shell reserved words that open/close control-flow blocks. They are
# treated as statement separators, so a pipeline hidden behind one
# (``if curl … | sh``, ``while read x; do curl … | sh; done``) is still
# analyzed as a pipeline. A reserved word is only recognized at a
# command-start position, so ``echo if`` is unaffected.
_RESERVED = frozenset((
    'if', 'then', 'elif', 'else', 'fi', 'for', 'while', 'until', 'do',
    'done', 'case', 'esac', 'select', 'function', 'in', 'time', 'coproc',
))
_ASSIGN_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=(.*)$', re.S)


class _Parser:
    """Recursive-descent parser over the token stream.

    Statement := Node (JOINER Node)* [SEPARATOR]
    Node      := Pipeline | Group
    Pipeline  := Command ('|' Command)* ['&']
    """

    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.i = 0
        self.n = len(tokens)

    # -- token helpers ----------------------------------------------------- #
    def peek(self, k: int = 0) -> Optional[Token]:
        p = self.i + k
        return self.tokens[p] if p < self.n else None

    def take(self) -> Token:
        t = self.tokens[self.i]
        self.i += 1
        return t

    # -- grammar ----------------------------------------------------------- #
    def parse(self) -> list[Statement]:
        stmts: list[Statement] = []
        while self.i < self.n:
            t = self.peek()
            if t is None:
                break
            if t.kind == 'newline':
                self.take()
                continue
            stmt = self.parse_statement()
            if stmt.nodes:
                stmts.append(stmt)
        return stmts

    def parse_statement(self) -> Statement:
        line = self.peek().line
        stmt = Statement(line=line)
        while self.i < self.n:
            t = self.peek()
            if t.kind == 'newline' or (t.kind == 'op' and t.text in (';', ';;')):
                self.take()
                break
            if t.kind == 'op' and t.text in _JOINERS:
                if not stmt.nodes:
                    self.take()
                    continue
                stmt.joiners.append(self.take().text)
                continue
            if (t.kind == 'word' and t.word is not None
                    and t.word.text in _RESERVED and t.word.is_static()):
                self.take()          # control-flow keyword: separator
                continue
            node = self.parse_node()
            if node is not None:
                stmt.nodes.append(node)
            elif self.i < self.n:
                t = self.peek()
                if t.kind == 'op' and t.text in (';', ';;'):
                    self.take()
                    break
                if t.kind == 'op' and t.text == ')':
                    self.take()   # unmatched close: consume to guarantee progress
                    break
                self.take()   # defensive progress
        return stmt

    def parse_node(self) -> Optional[Node]:
        t = self.peek()
        if t is None:
            return None
        if t.kind == 'op' and t.text == '(':
            return self.parse_group()
        if t.kind == 'op' and t.text in _REDIRECT_OPS:
            # statement starting with a redirect: attach to an empty command
            pl = Pipeline()
            cmd = Command(line=t.line)
            self.attach_redirect(cmd)
            if cmd.redirects or cmd.words:
                pl.commands.append(cmd)
            return pl if pl.commands else None
        if t.kind != 'word':
            return None
        return self.parse_pipeline()

    def parse_group(self) -> Group:
        line = self.take().line           # '('
        depth = 1
        inner: list[Token] = []
        while self.i < self.n:
            t = self.peek()
            if t.kind == 'op':
                if t.text == '(':
                    depth += 1
                elif t.text == ')':
                    depth -= 1
                    if depth == 0:
                        self.take()
                        return Group(_Parser(inner).parse(), line)
            inner.append(self.take())
        return Group(_Parser(inner).parse(), line)   # unterminated: tolerant

    def parse_pipeline(self) -> Pipeline:
        pl = Pipeline()
        while self.i < self.n:
            t = self.peek()
            if t.kind == 'op' and t.text == '|':
                self.take()
                continue
            if t.kind == 'op' and t.text == '&':
                self.take()
                pl.background = True
                return pl
            if t.kind == 'op' and t.text in _REDIRECT_OPS:
                if not pl.commands:
                    cmd = Command(line=t.line)
                else:
                    cmd = pl.commands[-1]
                self.attach_redirect(cmd)
                if not pl.commands:
                    pl.commands.append(cmd)
                continue
            if t.kind == 'word':
                pl.commands.append(self.parse_command())
                continue
            break                                    # newline, ;, &&, ||, )
        return pl

    def parse_command(self) -> Command:
        t = self.peek()
        line = t.line
        cmd = Command(line=line)
        while self.i < self.n:
            t = self.peek()
            if t.kind == 'word':
                if not cmd.words:
                    split = _split_assignment(t.word)
                    if split is not None:
                        cmd.assignments.append(split)
                        self.take()
                        continue
                cmd.words.append(self.take().word)
                continue
            if t.kind == 'op' and t.text in _REDIRECT_OPS:
                self.attach_redirect(cmd)
                continue
            break                                    # |, &, newline, ;, &&, ||, ), (
        return cmd

    def attach_redirect(self, cmd: Command) -> None:
        t = self.take()                              # the redirect op
        j = self.i
        while j < self.n and self.tokens[j].kind == 'newline':
            j += 1
        target = None
        if j < self.n and self.tokens[j].kind == 'word':
            target = self.tokens[j].word
        if t.text == '<<':
            red = Redirect('<<',
                           target if target is not None else Word(''),
                           t.heredoc_tag, t.heredoc_body)
            self.i = j + 1 if target is not None else self.i
        else:
            red = Redirect(t.text, target if target is not None else Word(''))
            self.i = j + 1 if target is not None else self.i
        cmd.redirects.append(red)


def parse(text: str) -> list[Statement]:
    """Parse shell source into a list of top-level statements."""
    return _Parser(tokenize(text)).parse()


def walk_statements(stmts: list[Statement]):
    """Yield every (statement, node, command) triple, recursing into groups."""
    for stmt in stmts:
        for node in stmt.nodes:
            if isinstance(node, Group):
                yield from walk_statements(node.body)
            else:
                for cmd in node.commands:
                    yield stmt, node, cmd


def iter_commands(text: str):
    """Convenience: parse ``text`` and yield every Command in document order."""
    for _, _, cmd in walk_statements(parse(text)):
        yield cmd
