"""Loading of `.argus.yml` / `.argus.yaml` / `.argus.json` configuration."""

from __future__ import annotations

from pathlib import Path

from argus_header.models.configuration import Configuration


def load_config(path: str | None) -> Configuration | None:
    """Load a Configuration from file. Returns None when no path is given.

    Raises FileNotFoundError if an explicit path does not exist. When
    ``path`` is None, searches the current directory for a default config
    file (``.argus.yml``, ``.argus.yaml`` or ``.argus.json``).
    """
    if path:
        return _from_file(path)

    for candidate in (".argus.yml", ".argus.yaml", ".argus.json"):
        if Path(candidate).exists():
            return _from_file(candidate)

    return None


def _from_file(path: str) -> Configuration:
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    text = filepath.read_text(encoding="utf-8")
    return Configuration.loads(text)
