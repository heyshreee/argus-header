#!/usr/bin/env python3
"""Cross-platform one-shot bootstrap for Argus Header.

Creates a single virtual environment (``.venv``), installs the editable
package (with its ``[api]`` extra), runtime and development requirements,
then runs the test suite and static checks to verify the setup.

Works on Windows, Linux and macOS with a plain Python 3:
    python bootstrap.py

Only the Python standard library is required to run this script.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"


def resolve_python() -> str:
    """Return the interpreter used to create the virtual environment."""
    for candidate in ("python", "python3"):
        try:
            subprocess.run(
                [candidate, "--version"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return candidate
        except OSError:
            continue
    raise RuntimeError(
        "Could not find a Python interpreter. Install Python 3.9+ and retry."
    )


def env_python() -> Path:
    """Return the path to the virtual environment's Python interpreter."""
    is_windows = sys.platform == "win32"
    subdir = "Scripts" if is_windows else "bin"
    return VENV_DIR / subdir / ("python.exe" if is_windows else "python")


def run(cmd: list[str], cwd: Path | None = None) -> None:
    """Execute a command, print it first, and abort on failure."""
    printable = " ".join(cmd)
    print(f"\n>>> {printable}")
    result = subprocess.run(cmd, cwd=cwd or ROOT)
    if result.returncode != 0:
        print(f"\n[FAILED] Command returned {result.returncode}: {printable}")
        sys.exit(result.returncode)


def create_venv(python: str) -> None:
    """Create the virtual environment if it does not already exist."""
    if env_python().exists():
        print(f"[SKIP] Virtual environment already exists at {VENV_DIR}")
        return
    print(f"[CREATE] {VENV_DIR}")
    run([python, "-m", "venv", str(VENV_DIR)])


def activate_hint() -> str:
    """Return an OS-specific command to activate the environment."""
    if sys.platform == "win32":
        return r".\.venv\Scripts\Activate.ps1"
    return "source .venv/bin/activate"


def main() -> int:
    print("=" * 60)
    print(" Argus Header - bootstrap installer")
    print("=" * 60)

    python = resolve_python()
    print(f"[PYTHON] {python}")

    create_venv(python)
    py = env_python()

    run([str(py), "-m", "pip", "install", "--upgrade", "pip"])
    run([str(py), "-m", "pip", "install", "-e", ".[api]"])
    run(
        [
            str(py),
            "-m",
            "pip",
            "install",
            "-r",
            str(ROOT / "requirements.txt"),
            "-r",
            str(ROOT / "requirements-dev.txt"),
        ]
    )

    print("\n" + "=" * 60)
    print(" Verifying setup: tests + static checks")
    print("=" * 60)

    run([str(py), "-m", "pytest", "tests/", "-q"])
    run([str(py), "-m", "ruff", "check", "src/", "tests/"])
    run([str(py), "-m", "black", "--check", "src/", "tests/"])
    run([str(py), "-m", "mypy", "src/"])

    print("\n" + "=" * 60)
    print(" Bootstrap complete.")
    print("=" * 60)
    print(f"\n  Activate the environment:  {activate_hint()}")
    print("  Run a scan:                argus-header https://example.com")
    print("  Show the score:            argus-header https://example.com --score\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())