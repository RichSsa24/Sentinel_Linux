# Contributing to Linux Security Monitor

Thank you for your interest in contributing to this project. This document provides guidelines and standards for contributions.

## Code of Conduct

- Be respectful and professional in all interactions
- Focus on constructive feedback
- Respect differing viewpoints and experiences
- Accept responsibility for mistakes and learn from them

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - System information (OS, Python version)
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs (sanitized of sensitive data)

### Suggesting Features

1. Check existing feature requests
2. Describe the use case and benefit
3. Consider implementation complexity
4. Be open to alternative approaches

### Submitting Code

#### Prerequisites

- Python 3.9+ for Python development
- ShellCheck for Bash development
- Git for version control

#### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/linux-security-monitor.git
cd linux-security-monitor

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

#### Branch Naming

Use descriptive branch names:
- `feature/user-activity-dashboard`
- `bugfix/auth-monitor-crash`
- `security/input-validation-fix`
- `docs/installation-guide-update`

#### Commit Messages

Follow conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `security`: Security fix
- `docs`: Documentation
- `refactor`: Code refactoring
- `test`: Test additions/modifications
- `chore`: Maintenance tasks

Examples:
```
feat(monitors): add USB device monitoring capability

Implements monitoring for USB device connections and disconnections.
Includes detection of unauthorized storage devices.

Closes #123
```

```
fix(auth-monitor): handle malformed auth.log entries

Some systems generate non-standard log entries that caused
parsing failures. Added fallback parsing logic.

Fixes #456
```

## Code Standards

### Python Code

#### Style Guide
- Follow PEP 8
- Use Black for formatting (line length: 100)
- Use isort for import sorting
- Maximum function length: 50 lines
- Maximum file length: 500 lines

#### Type Hints
All functions must include type hints:

```python
def analyze_process(
    pid: int,
    include_children: bool = False
) -> ProcessAnalysisResult:
    """
    Analyze a process for suspicious behavior.
    
    Args:
        pid: Process ID to analyze.
        include_children: Whether to include child processes.
        
    Returns:
        ProcessAnalysisResult containing threat indicators.
        
    Raises:
        ProcessNotFoundError: If the process does not exist.
        PermissionError: If insufficient privileges to analyze.
    """
    ...
```

#### Docstrings
Use Google-style docstrings for all public functions, classes, and modules:

```python
class ThreatAnalyzer:
    """
    Analyzes system events to identify potential threats.
    
    This analyzer processes events from various monitors and applies
    threat detection rules to identify suspicious activity.
    
    Attributes:
        rules: Collection of detection rules.
        threshold: Minimum confidence score for alerts.
        
    Example:
        >>> analyzer = ThreatAnalyzer(rules=default_rules)
        >>> result = analyzer.analyze(event)
        >>> if result.is_threat:
        ...     handle_threat(result)
    """
```

#### Error Handling
- Use custom exceptions from `src/core/exceptions.py`
- Never catch bare `Exception` unless re-raising
- Include actionable error messages
- Log exceptions with appropriate severity

```python
try:
    result = process_log_entry(entry)
except MalformedLogEntry as e:
    logger.warning(
        "Skipping malformed log entry at line %d: %s",
        line_number,
        e.message
    )
    metrics.increment("log_parse_errors")
except PermissionError:
    logger.error(
        "Insufficient permissions to read log file: %s",
        log_path
    )
    raise
```

#### Security Requirements
- Validate all inputs using functions from `src/utils/validators.py`
- Sanitize outputs using functions from `src/utils/sanitizers.py`
- Never log sensitive data (passwords, tokens, PII)
- Use parameterized queries for any database operations
- Use `secrets` module for cryptographic randomness

### Bash Code

#### Style Guide
- ShellCheck compliance required (no warnings)
- Use `#!/usr/bin/env bash` shebang
- Use `set -euo pipefail` at the start
- Quote all variables: `"${variable}"`
- Use `[[` instead of `[` for conditionals

#### Documentation
Include header documentation:

```bash
#!/usr/bin/env bash
#
# Script: service_checker.sh
# Description: Monitors system services for security-relevant changes
# Author: Security Team
# Version: 1.0.0
#
# Usage:
#   ./service_checker.sh [options]
#
# Options:
#   -h, --help     Show this help message
#   -v, --verbose  Enable verbose output
#   -c, --config   Path to configuration file
#
# Exit Codes:
#   0 - Success, no issues found
#   1 - Issues detected
#   2 - Configuration error
#   3 - Permission denied
#
# Dependencies:
#   - systemctl
#   - awk
#   - grep
```

#### Function Documentation

```bash
# Checks if a service is running and returns its status
# 
# Arguments:
#   $1 - Service name
#   $2 - (optional) Timeout in seconds, default 5
#
# Returns:
#   0 if service is running
#   1 if service is stopped
#   2 if service not found
#
# Example:
#   if check_service_status "sshd"; then
#       echo "SSH is running"
#   fi
check_service_status() {
    local service_name="${1:?Service name required}"
    local timeout="${2:-5}"
    ...
}
```

#### Error Handling

```bash
# Use trap for cleanup
cleanup() {
    rm -f "${TEMP_FILE:-}"
    exit "${1:-0}"
}
trap 'cleanup 1' ERR
trap 'cleanup 0' EXIT

# Check command availability
require_command() {
    local cmd="${1:?Command name required}"
    if ! command -v "${cmd}" &>/dev/null; then
        log_error "Required command not found: ${cmd}"
        exit 2
    fi
}
```

## Testing Requirements

### Python Tests

- Minimum 80% code coverage
- Use pytest framework
- Include unit, integration, and security tests

```python
class TestUserMonitor:
    """Tests for UserMonitor class."""
    
    def test_detect_privilege_escalation(self, mock_auth_log):
        """Should detect sudo usage by non-admin users."""
        monitor = UserMonitor()
        events = monitor.analyze(mock_auth_log)
        
        assert len(events) == 1
        assert events[0].event_type == "privilege_escalation"
        assert events[0].severity == Severity.HIGH
    
    def test_handles_malformed_log_gracefully(self, malformed_log):
        """Should not crash on malformed log entries."""
        monitor = UserMonitor()
        # Should not raise
        events = monitor.analyze(malformed_log)
        assert isinstance(events, list)
```

### Bash Tests

Use bats (Bash Automated Testing System):

```bash
#!/usr/bin/env bats

@test "service_checker detects stopped critical service" {
    # Arrange
    systemctl stop test-critical-service
    
    # Act
    run ./service_checker.sh --check test-critical-service
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "CRITICAL" ]]
}
```

## Pull Request Process

### Before Submitting

1. Run all tests: `pytest tests/ -v`
2. Run linting: `flake8 src/ tests/`
3. Run type checking: `mypy src/`
4. Run ShellCheck: `shellcheck scripts/bash/*.sh`
5. Update documentation if needed
6. Add changelog entry

### PR Template

```markdown
## Description
[Describe what this PR does]

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Security fix
- [ ] Documentation update
- [ ] Refactoring

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Security Considerations
[Describe any security implications]

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests pass locally
- [ ] No new warnings introduced
```

### Review Process

1. Automated checks must pass
2. At least one maintainer approval required
3. Security-sensitive changes require additional review
4. Address all review comments

## Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create release PR
4. After merge, tag release
5. GitHub Actions handles package publishing

## Getting Help

- Open a Discussion for questions
- Join our community chat (link TBD)
- Review existing documentation

## Recognition

Contributors are recognized in:
- CHANGELOG.md for each release
- README.md contributors section
- Annual contributor acknowledgment

Thank you for contributing to Linux Security Monitor!



