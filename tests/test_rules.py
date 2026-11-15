import pytest

from scanner.engine import ScanOptions, check_line
from scanner.patterns import PATTERNS
from tests.corpus import CORPUS

RULES = {p.id: p for p in PATTERNS}


def test_every_rule_has_fixtures():
    missing = sorted(set(RULES) - set(CORPUS))
    assert not missing, f"rules without positive/negative fixtures: {missing}"


def test_no_orphan_fixtures():
    assert not sorted(set(CORPUS) - set(RULES))


def test_rule_ids_unique_and_well_formed():
    ids = [p.id for p in PATTERNS]
    assert len(ids) == len(set(ids))
    assert all(i.startswith("LS-") and i.split("-")[-1].isdigit() for i in ids)


def test_at_least_150_rules():
    assert len(PATTERNS) >= 150


def _hits(line, path, rule_id):
    path = path or "src/app.py"
    return [f for f in check_line(line, 1, path, ScanOptions(no_entropy=True)) if f.rule_id == rule_id]


@pytest.mark.parametrize("rule_id", sorted(CORPUS))
def test_positive_fixture_matches(rule_id):
    positive, _, path = CORPUS[rule_id]
    assert _hits(positive, path, rule_id), f"{rule_id} missed: {positive}"


@pytest.mark.parametrize("rule_id", sorted(CORPUS))
def test_negative_fixture_does_not_match(rule_id):
    _, negative, path = CORPUS[rule_id]
    assert not _hits(negative, path, rule_id), f"{rule_id} false positive: {negative}"
