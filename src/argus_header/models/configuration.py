"""Configuration model for `.argus.yml` policy files.

The configuration allows users to tune the scanner without having to pass
every option on the CLI. Supported top-level sections mirror the CLI:

    target:
      timeout: 10
      redirects: true
      method: GET

    rules:
      csp: true
      cors: true
      cookies: true
      hsts: true
      cache: true
      cross_origin: true
      referrer: true
      permissions: true

    policy:
      minimum_score: 80
      fail_on: high

    output:
      json: report.json
      sarif: report.sarif
      report: report.html
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

# Lowercased rule category names accepted in the config `rules` block.
KNOWN_RULES = [
    "csp",
    "cors",
    "cookies",
    "hsts",
    "cache",
    "cross_origin",
    "referrer",
    "permissions",
    "base_headers",
]


@dataclass
class TargetConfig:
    timeout: int = 10
    redirects: bool = True
    method: str = "GET"


@dataclass
class RulesConfig:
    csp: bool = True
    cors: bool = True
    cookies: bool = True
    hsts: bool = True
    cache: bool = True
    cross_origin: bool = True
    referrer: bool = True
    permissions: bool = True
    base_headers: bool = True

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> RulesConfig:
        result = cls()
        for key in KNOWN_RULES:
            if key in data:
                setattr(result, key, bool(data[key]))
        return result

    def to_mapping(self) -> dict[str, bool]:
        return {key: bool(getattr(self, key)) for key in KNOWN_RULES}


@dataclass
class PolicyConfig:
    minimum_score: int = 80
    fail_on: str = "high"
    enabled_rules: RulesConfig = field(default_factory=RulesConfig)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> PolicyConfig:
        result = cls()
        if "minimum_score" in data:
            result.minimum_score = int(data["minimum_score"])
        if "fail_on" in data:
            result.fail_on = str(data["fail_on"]).lower()
        if "rules" in data and isinstance(data["rules"], Mapping):
            result.enabled_rules = RulesConfig.from_mapping(data["rules"])
        return result


@dataclass
class Configuration:
    """Merged scanner configuration.

    Values are sourced from the `.argus.yml` file when present; CLI flags
    are applied on top during a scan and therefore take precedence.
    """

    timeout: int = 10
    redirects: bool = True
    method: str = "GET"
    rules: RulesConfig = field(default_factory=RulesConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)

    @classmethod
    def loads(cls, text: str) -> Configuration:
        """Parse a configuration from a YAML/JSON document string."""
        import yaml

        data = yaml.safe_load(text) or {}
        if not isinstance(data, Mapping):
            raise TypeError("Configuration root must be a mapping.")
        return cls.from_mapping(data)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> Configuration:
        result = cls()

        target = data.get("target") or {}
        if isinstance(target, Mapping):
            if "timeout" in target:
                result.timeout = int(target["timeout"])
            if "redirects" in target:
                result.redirects = bool(target["redirects"])
            if "method" in target:
                result.method = str(target["method"]).upper()

        rules = data.get("rules") or {}
        if isinstance(rules, Mapping):
            result.rules = RulesConfig.from_mapping(rules)

        policy = data.get("policy") or {}
        if isinstance(policy, Mapping):
            result.policy = PolicyConfig.from_mapping(policy)

        return result

    def enabled_rule_keys(self) -> list[str]:
        """Return the lowercased rule categories that are enabled."""
        return [k for k in KNOWN_RULES if getattr(self.rules, k)]
