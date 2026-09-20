"""Tests for CI/CD gate policy and configuration loading."""

from argus_header.config_loader import load_config
from argus_header.engine.policy import SEVERITY_ORDER, evaluate_gate
from argus_header.models.configuration import Configuration


def _minimal_score(value):
    return {"value": value}


def test_fail_on_high_with_high_finding():
    result = evaluate_gate(
        _minimal_score(90),
        [{"severity": "HIGH"}],
        fail_on="high",
        minimum_score=80,
    )
    assert result.passed is False
    assert "HIGH" in result.reason


def test_fail_on_critical_ignores_high():
    result = evaluate_gate(
        _minimal_score(90),
        [{"severity": "HIGH"}],
        fail_on="critical",
        minimum_score=80,
    )
    assert result.passed is True


def test_min_score_failure():
    result = evaluate_gate(
        _minimal_score(75),
        [],
        fail_on="none",
        minimum_score=80,
    )
    assert result.passed is False
    assert "below the minimum" in result.reason


def test_pass_when_under_threshold():
    result = evaluate_gate(
        _minimal_score(90),
        [{"severity": "MEDIUM"}],
        fail_on="high",
        minimum_score=80,
    )
    assert result.passed is True


def test_severity_order_defined():
    assert SEVERITY_ORDER == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def test_fail_on_low_fails_on_any_finding():
    result = evaluate_gate(
        _minimal_score(95),
        [{"severity": "LOW"}],
        fail_on="low",
        minimum_score=80,
    )
    assert result.passed is False


def test_config_loads_yaml():
    text = """
target:
  timeout: 5
  redirects: false
  method: HEAD
rules:
  csp: false
  cors: true
policy:
  minimum_score: 90
  fail_on: critical
"""
    config = Configuration.loads(text)

    assert config.timeout == 5
    assert config.redirects is False
    assert config.method == "HEAD"
    assert config.rules.csp is False
    assert config.rules.cors is True
    assert config.policy.minimum_score == 90
    assert config.policy.fail_on == "critical"


def test_config_defaults():
    config = Configuration.loads("")

    assert config.timeout == 10
    assert config.redirects is True
    assert config.rules.csp is True
    assert config.policy.minimum_score == 80
    assert config.policy.fail_on == "high"


def test_config_invalid_root_rejected():
    import pytest

    with pytest.raises(TypeError):
        Configuration.loads("- just a list")


def test_load_config_returns_none_when_no_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert load_config(None) is None


def test_load_config_explicit_missing_raises():
    import pytest

    with pytest.raises(FileNotFoundError):
        load_config("does-not-exist.yml")


def test_enabled_rule_keys():
    config = Configuration.loads("rules:\n  csp: false\n  cookies: false")
    keys = config.enabled_rule_keys()
    assert "csp" not in keys
    assert "cookies" not in keys
    assert "cors" in keys
