#!/usr/bin/env python3
"""
Linter runner script for Linux Security Monitor.

Runs all code quality and security linters:
- black (code formatting)
- isort (import sorting)
- flake8 (linting)
- mypy (type checking)
- bandit (security linting)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

# Project root
PROJECT_ROOT = Path(__file__).parent.parent.parent
SRC_DIR = PROJECT_ROOT / "src"
TESTS_DIR = PROJECT_ROOT / "tests"


def run_command(
    cmd: List[str],
    description: str,
    check: bool = False,
) -> Tuple[bool, str]:
    """
    Run a linter command.

    Args:
        cmd: Command to run.
        description: Description of what is being checked.
        check: If True, fail on non-zero exit.

    Returns:
        Tuple of (success, output).
    """
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'='*60}")

    try:
        result = subprocess.run(
            cmd,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)

        success = result.returncode == 0

        if success:
            print(f"✅ {description}: PASSED")
        else:
            print(f"❌ {description}: FAILED (exit code {result.returncode})")

        return success, result.stdout + result.stderr

    except subprocess.TimeoutExpired:
        print(f"⏱️  {description}: TIMEOUT (exceeded 5 minutes)")
        return False, "Timeout"
    except FileNotFoundError:
        print(f"⚠️  {description}: TOOL NOT FOUND")
        print(f"   Install with: pip install {' '.join(cmd[:1])}")
        return True, "Tool not found (skipped)"  # Don't fail if tool not installed
    except Exception as e:
        print(f"❌ {description}: ERROR - {e}")
        return False, str(e)


def check_black() -> bool:
    """Check code formatting with black."""
    success, _ = run_command(
        [
            sys.executable,
            "-m",
            "black",
            "--check",
            "--diff",
            str(SRC_DIR),
            str(TESTS_DIR),
        ],
        "Black (Code Formatting)",
    )
    return success


def check_isort() -> bool:
    """Check import sorting with isort."""
    success, _ = run_command(
        [
            sys.executable,
            "-m",
            "isort",
            "--check-only",
            "--diff",
            str(SRC_DIR),
            str(TESTS_DIR),
        ],
        "isort (Import Sorting)",
    )
    return success


def check_flake8() -> bool:
    """Check code with flake8."""
    success, _ = run_command(
        [
            sys.executable,
            "-m",
            "flake8",
            str(SRC_DIR),
            str(TESTS_DIR),
            "--max-line-length=100",
            "--ignore=E203,W503",
            "--exclude=__pycache__,.git,venv,build,dist",
        ],
        "flake8 (Linting)",
    )
    return success


def check_mypy() -> bool:
    """Check types with mypy."""
    success, _ = run_command(
        [
            sys.executable,
            "-m",
            "mypy",
            str(SRC_DIR),
            "--ignore-missing-imports",
            "--no-error-summary",
        ],
        "mypy (Type Checking)",
    )
    return success


def check_bandit() -> bool:
    """Check security with bandit."""
    success, _ = run_command(
        [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            str(SRC_DIR),
            "-ll",  # Low and low severity
            "-q",   # Quiet mode
            "-f",
            "json",
        ],
        "bandit (Security Linting)",
    )
    return success


def main() -> int:
    """Run all linters."""
    print("=" * 60)
    print("Linux Security Monitor - Linter Runner")
    print("=" * 60)
    print(f"Project: {PROJECT_ROOT}")
    print(f"Python: {sys.executable}")
    print(f"Version: {sys.version}")

    results: List[Tuple[str, bool]] = []

    # Run all linters
    results.append(("black", check_black()))
    results.append(("isort", check_isort()))
    results.append(("flake8", check_flake8()))
    results.append(("mypy", check_mypy()))
    results.append(("bandit", check_bandit()))

    # Summary
    print("\n" + "=" * 60)
    print("Linter Summary")
    print("=" * 60)

    passed = sum(1 for _, success in results if success)
    total = len(results)

    for name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"  {name:15s} {status}")

    print(f"\nTotal: {passed}/{total} passed")

    if passed == total:
        print("\n✅ All linters passed!")
        return 0
    else:
        print(f"\n❌ {total - passed} linter(s) failed")
        print("\nTo fix formatting issues, run:")
        print("  python -m black src/ tests/")
        print("  python -m isort src/ tests/")
        return 1


if __name__ == "__main__":
    sys.exit(main())

