"""Engine package: rules, findings and the Security Score Engine 2.0.

Module attributes are resolved lazily (PEP 562) so that importing any
submodule (e.g. ``analyzers``) does not trigger a circular import through
the eager import of the rules registry.
"""

from __future__ import annotations

from typing import Any

_LAZY = {
    "RULES": "rules",
    "Rule": "rules",
    "normalize_headers": "rules",
    "run_rule": "rules",
    "run_rules": "rules",
    "as_dicts": "findings",
    "dicts_to_findings": "findings",
    "findings_to_dicts": "findings",
    "make_finding": "findings",
    "calculate_grade_extended": "scoring",
    "calculate_score_2": "scoring",
    "classify_finding": "scoring",
}


def __getattr__(name: str) -> Any:
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    module = importlib.import_module(f"{__name__}.{module_name}")
    return getattr(module, name)


def __dir__() -> list[str]:
    return sorted(set(list(globals()) + list(_LAZY)))
