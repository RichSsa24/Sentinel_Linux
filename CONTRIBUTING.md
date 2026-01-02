# Contributing to Sentinel Linux

## Overview

**What this document is**: This guide explains how to contribute to Sentinel Linux, including code standards, testing requirements, and the pull request process.

**Who should read this**:
- **Developers**: Contributing code, features, or bug fixes
- **Security Researchers**: Adding detection rules or improving security features
- **Documentation Writers**: Improving documentation and examples
- **Testers**: Writing tests or reporting bugs

**Why contributions matter**: Open-source projects thrive on community contributions. Your contributions help make Sentinel Linux better for everyone.

## Code of Conduct

**What this means**: Guidelines for respectful, professional interaction in the project.

**Why it exists**: A positive, inclusive environment encourages more contributions and better collaboration.

**Our standards**:
- Be respectful and professional in all interactions
- Focus on constructive feedback
- Respect differing viewpoints and experiences
- Accept responsibility for mistakes and learn from them

**Enforcement**: Violations may result in temporary or permanent bans from the project.

## How to Contribute

### Reporting Bugs

**What this means**: Reporting issues you've found in Sentinel Linux.

**When to report**: When you encounter unexpected behavior, crashes, or incorrect results.

**Before reporting**:
1. **Check existing issues**: Your bug may already be reported
   - **Why**: Avoids duplicate issues and saves maintainer time
   - **How**: Search GitHub Issues for similar problems

2. **Use the bug report template**: Provides structure for bug reports
   - **Why**: Ensures all necessary information is included
   - **What it includes**: System info, steps to reproduce, expected vs actual behavior

3. **Include the following**:
   - **System information**: OS, Python version, Sentinel Linux version
     - **Why**: Bugs may be platform-specific
   - **Steps to reproduce**: Exact commands or actions that trigger the bug
     - **Why**: Helps maintainers reproduce and fix the issue
   - **Expected vs actual behavior**: What should happen vs what actually happens
     - **Why**: Clarifies what the bug is
   - **Relevant logs**: Error messages, stack traces (sanitized of sensitive data)
     - **Why**: Provides diagnostic information
     - **Important**: Remove passwords, API keys, IP addresses, or other sensitive data

**Example bug report**:
```markdown
**System**: Ubuntu 22.04, Python 3.10, Sentinel Linux 1.0.0
**Steps to reproduce**:
1. Run `sudo python scripts/python/run_monitor.py --config /etc/Sentinel_Linux/config.yaml`
2. Wait 5 minutes
3. Check logs

**Expected**: Monitor runs without errors
**Actual**: Monitor crashes with "PermissionError: [Errno 13] Permission denied: '/proc/1234'"

**Logs**: [sanitized error trace]
```

### Suggesting Features

**What this means**: Proposing new functionality or improvements.

**When to suggest**: When you have an idea for a feature that would benefit users.

**Before suggesting**:
1. **Check existing feature requests**: Your idea may already be proposed
   - **Why**: Avoids duplicate discussions

2. **Describe the use case and benefit**: Explain why the feature is needed
   - **Why**: Helps maintainers understand the value
   - **What to include**: Who would use it, what problem it solves

3. **Consider implementation complexity**: Simple features are more likely to be accepted
   - **Why**: Maintainers have limited time
   - **How**: Break complex features into smaller pieces

4. **Be open to alternative approaches**: Your idea may be implemented differently
   - **Why**: Maintainers may have better solutions

**Example feature request**:
```markdown
**Feature**: Support for Docker container monitoring

**Use case**: Many organizations run services in Docker containers. Monitoring container activity would help detect container escapes and malicious activity.

**Benefit**: Extends Sentinel Linux to containerized environments, increasing its usefulness.

**Implementation ideas**: Monitor Docker events, track container processes, detect suspicious container behavior.
```

### Submitting Code

**What this means**: Contributing code changes (bug fixes, features, improvements).

**Prerequisites**:
- **Python 3.9+**: For Python development
  - **Why**: Sentinel Linux requires Python 3.9+
- **ShellCheck**: For Bash development
  - **Why**: Ensures Bash scripts are correct and portable
- **Git**: For version control
  - **Why**: All code is managed with Git

#### Development Setup

**What this does**: Sets up your environment for development.

**Why it's needed**: Ensures you have all required tools and dependencies.

```bash
# Fork and clone the repository
# What this does: Creates your own copy of the repository
# Why fork: Allows you to make changes without affecting the main repository
git clone https://github.com/RichSsa24/Sentinel_Linux.git
cd Sentinel_Linux

# Create virtual environment
# What this does: Creates isolated Python environment
# Why it's needed: Prevents conflicts with system Python packages
python -m venv venv
source venv/bin/activate

# Install development dependencies
# What this does: Installs Sentinel Linux plus testing tools, linters, etc.
# Why it's needed: Development requires additional tools
pip install -e ".[dev]"

# Install pre-commit hooks
# What this does: Sets up Git hooks that run checks before commits
# Why it's useful: Catches issues before they're committed
pre-commit install
```

**What pre-commit hooks do**: Automatically run `black`, `isort`, `flake8`, and `mypy` before each commit.

#### Branch Naming

**What this means**: How to name your Git branches.

**Why it matters**: Clear branch names help maintainers understand what your changes do.

**Convention**: `type/description`

**Types**:
- `feature/`: New functionality
- `bugfix/`: Bug fixes
- `security/`: Security fixes
- `docs/`: Documentation changes
- `refactor/`: Code refactoring
- `test/`: Test additions/modifications

**Examples**:
- `feature/user-activity-dashboard` - New dashboard feature
- `bugfix/auth-monitor-crash` - Fixes crash in auth monitor
- `security/input-validation-fix` - Security fix for input validation
- `docs/installation-guide-update` - Updates to installation guide

**Why descriptive names**: Makes it easy to understand what the branch contains without reading the code.

#### Commit Messages

**What this means**: How to write commit messages.

**Why it matters**: Good commit messages help understand project history and make debugging easier.

**Format**: Follow conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

**Types** (same as branch types):
- `feat`: New feature
- `fix`: Bug fix
- `security`: Security fix
- `docs`: Documentation
- `refactor`: Code refactoring
- `test`: Test additions/modifications
- `chore`: Maintenance tasks

**Scope**: Optional, indicates what part of the codebase is affected (e.g., `monitors`, `analyzers`, `reporters`).

**Description**: Brief summary of the change (50 characters or less, imperative mood).

**Body**: Optional, detailed explanation of what and why (wrap at 72 characters).

**Footer**: Optional, references to issues (e.g., `Closes #123`, `Fixes #456`).

**Examples**:

```
feat(monitors): add USB device monitoring capability

Implements monitoring for USB device connections and disconnections.
Includes detection of unauthorized storage devices.

Closes #123
```

**Why this format**: 
- Easy to parse for automated tools
- Consistent across the project
- Makes it easy to generate changelogs

```
fix(auth-monitor): handle malformed auth.log entries

Some systems generate non-standard log entries that caused
parsing failures. Added fallback parsing logic.

Fixes #456
```

## Code Standards

**What this section covers**: Standards for writing code that will be accepted into the project.

**Why standards exist**: Consistent code is easier to read, maintain, and debug.

### Python Code

#### Style Guide

**What this means**: Rules for formatting and organizing Python code.

**Why it matters**: Consistent style makes code easier to read and understand.

**Standards**:
- **Follow PEP 8**: Python's official style guide
  - **Why**: Industry standard, widely recognized
- **Use Black for formatting**: Automatic code formatter (line length: 100)
  - **Why**: Ensures consistent formatting, eliminates style debates
- **Use isort for import sorting**: Automatically sorts imports
  - **Why**: Consistent import order makes code cleaner
- **Maximum function length: 50 lines**: Keep functions focused
  - **Why**: Long functions are hard to understand and test
- **Maximum file length: 500 lines**: Split large files into modules
  - **Why**: Large files are hard to navigate and maintain

**How to enforce**: Pre-commit hooks automatically run `black` and `isort`.

#### Type Hints

**What this means**: Annotations that specify the types of function parameters and return values.

**Why they're required**: 
- Improves code readability
- Enables static type checking with `mypy`
- Helps IDEs provide better autocomplete
- Catches type errors before runtime

**Example**:

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

**What each part means**:
- `pid: int`: Parameter `pid` must be an integer
- `include_children: bool = False`: Optional boolean parameter with default value
- `-> ProcessAnalysisResult`: Function returns a `ProcessAnalysisResult` object
- `Raises`: Documents exceptions that may be raised

**Why this is important**: Makes it clear what types are expected, reducing bugs.

#### Docstrings

**What this means**: Documentation strings that describe functions, classes, and modules.

**Why they're required**: Code without documentation is hard to understand and use.

**Format**: Use Google-style docstrings (as shown in examples above).

**What to include**:
- **Brief description**: What the function/class does
- **Detailed description**: More context if needed
- **Args/Parameters**: Each parameter with type and description
- **Returns**: Return value with type and description
- **Raises**: Exceptions that may be raised
- **Example**: Usage example (for complex functions)

**Example**:

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

**Why Google-style**: Widely used, well-supported by tools, readable.

#### Error Handling

**What this means**: How to handle errors and exceptions in code.

**Why it matters**: Proper error handling prevents crashes and provides useful error messages.

**Standards**:
- **Use custom exceptions**: From `src/core/exceptions.py`
  - **Why**: More specific than generic exceptions, easier to handle
- **Never catch bare `Exception`**: Unless re-raising
  - **Why**: Catches too much, may hide bugs
- **Include actionable error messages**: Tell users what went wrong and how to fix it
  - **Why**: Helps users resolve issues
- **Log exceptions with appropriate severity**: Use correct log level
  - **Why**: Helps with debugging and monitoring

**Example**:

```python
try:
    result = process_log_entry(entry)
except MalformedLogEntry as e:
    # What this does: Logs the error but continues processing
    # Why WARNING: Not critical, can recover
    logger.warning(
        "Skipping malformed log entry at line %d: %s",
        line_number,
        e.message
    )
    metrics.increment("log_parse_errors")
except PermissionError:
    # What this does: Logs and re-raises critical error
    # Why ERROR: Cannot continue without permissions
    logger.error(
        "Insufficient permissions to read log file: %s",
        log_path
    )
    raise  # Re-raise because we can't continue
```

**Why this approach**: Handles recoverable errors gracefully, fails fast on critical errors.

#### Security Requirements

**What this means**: Security best practices that must be followed.

**Why they're critical**: Sentinel Linux handles sensitive security data and requires elevated privileges.

**Requirements**:
- **Validate all inputs**: Using functions from `src/utils/validators.py`
  - **Why**: Prevents injection attacks, path traversal, etc.
- **Sanitize outputs**: Using functions from `src/utils/sanitizers.py`
  - **Why**: Prevents log injection, XSS, etc.
- **Never log sensitive data**: Passwords, tokens, PII
  - **Why**: Logs may be accessible to unauthorized users
- **Use parameterized queries**: For any database operations
  - **Why**: Prevents SQL injection
- **Use `secrets` module**: For cryptographic randomness
  - **Why**: `random` module is not cryptographically secure

**Example**:

```python
from src.utils.validators import validate_path, validate_hash
from src.utils.sanitizers import sanitize_log_message
import secrets

# Validate input
file_path = validate_path(user_input)  # Prevents path traversal

# Sanitize output
safe_message = sanitize_log_message(user_message)  # Prevents log injection

# Generate secure random
token = secrets.token_urlsafe(32)  # Cryptographically secure
```

### Bash Code

**What this section covers**: Standards for Bash scripts in the project.

**Why it matters**: Bash scripts are part of the project and should follow standards.

#### Style Guide

**What this means**: Rules for writing Bash scripts.

**Standards**:
- **ShellCheck compliance required**: No warnings allowed
  - **Why**: ShellCheck finds bugs and portability issues
- **Use `#!/usr/bin/env bash` shebang**: More portable than `/bin/bash`
  - **Why**: Works on systems where bash is in different locations
- **Use `set -euo pipefail`**: Exit on error, undefined variables, pipe failures
  - **Why**: Prevents silent failures and bugs
- **Quote all variables**: `"${variable}"` not `${variable}`
  - **Why**: Prevents word splitting and glob expansion
- **Use `[[` instead of `[`**: More features, safer
  - **Why**: `[[` is a Bash builtin with better features

**Example**:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Good: quoted variable
if [[ -f "${config_file}" ]]; then
    echo "Config file exists"
fi

# Bad: unquoted variable (may break with spaces)
if [ -f $config_file ]; then
    echo "Config file exists"
fi
```

#### Documentation

**What this means**: Header documentation for Bash scripts.

**Why it's required**: Scripts need documentation just like code.

**What to include**:

```bash
#!/usr/bin/env bash
#
# Script: service_checker.sh
# Description: Monitors system services for security-relevant changes
# Author: Ricardo Solís
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

**Why each part matters**:
- **Script name**: Identifies the script
- **Description**: What the script does
- **Author**: Who wrote it
- **Version**: Version number for tracking
- **Usage**: How to run the script
- **Options**: Command-line options
- **Exit Codes**: What each exit code means
- **Dependencies**: Required external commands

#### Function Documentation

**What this means**: Documentation for Bash functions.

**Why it's needed**: Functions should be documented like code functions.

**Format**:

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

**Why this format**: Clear, consistent, easy to understand.

#### Error Handling

**What this means**: How to handle errors in Bash scripts.

**Why it matters**: Scripts should handle errors gracefully.

**Best practices**:

```bash
# Use trap for cleanup
# What this does: Defines cleanup function
cleanup() {
    rm -f "${TEMP_FILE:-}"  # Remove temp file if it exists
    exit "${1:-0}"  # Exit with provided code or 0
}
# What this does: Run cleanup on error
trap 'cleanup 1' ERR
# What this does: Run cleanup on normal exit
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

**Why traps**: Ensures cleanup happens even if script fails.

## Testing Requirements

**What this section covers**: Requirements for testing code contributions.

**Why testing is required**: Tests ensure code works correctly and prevent regressions.

### Python Tests

**What this means**: Tests for Python code using pytest.

**Requirements**:
- **Minimum 80% code coverage**: Most code must be tested
  - **Why**: Ensures code is actually tested
- **Use pytest framework**: Standard Python testing framework
  - **Why**: Widely used, well-supported
- **Include unit, integration, and security tests**: Different types of tests
  - **Why**: Unit tests test individual components, integration tests test interactions, security tests test security

**Example**:

```python
class TestUserMonitor:
    """Tests for UserMonitor class."""
    
    def test_detect_privilege_escalation(self, mock_auth_log):
        """Should detect sudo usage by non-admin users."""
        # Arrange: Set up test
        monitor = UserMonitor()
        
        # Act: Execute code being tested
        events = monitor.analyze(mock_auth_log)
        
        # Assert: Verify results
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

**Why this structure**: Arrange-Act-Assert pattern makes tests clear and easy to understand.

### Bash Tests

**What this means**: Tests for Bash scripts using bats (Bash Automated Testing System).

**Why bats**: Standard tool for testing Bash scripts.

**Example**:

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

**What this section covers**: How to submit code changes for review.

**Why process exists**: Ensures code quality and consistency.

### Before Submitting

**What this means**: Steps to complete before creating a pull request.

**Checklist**:
1. **Run all tests**: `pytest tests/ -v`
   - **Why**: Ensures your changes don't break existing functionality
2. **Run linting**: `flake8 src/ tests/`
   - **Why**: Ensures code follows style guidelines
3. **Run type checking**: `mypy src/`
   - **Why**: Catches type errors
4. **Run ShellCheck**: `shellcheck scripts/bash/*.sh`
   - **Why**: Ensures Bash scripts are correct
5. **Update documentation**: If your changes affect documentation
   - **Why**: Documentation must match code
6. **Add changelog entry**: Document your changes
   - **Why**: Helps users understand what changed

### PR Template

**What this means**: Template for pull request descriptions.

**Why it's useful**: Ensures all necessary information is included.

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

**What this means**: How pull requests are reviewed.

**Steps**:
1. **Automated checks must pass**: CI/CD runs tests, linting, etc.
   - **Why**: Catches issues before human review
2. **At least one maintainer approval required**: Code must be reviewed
   - **Why**: Ensures code quality
3. **Security-sensitive changes require additional review**: Extra scrutiny for security
   - **Why**: Security bugs can be critical
4. **Address all review comments**: Respond to feedback
   - **Why**: Ensures issues are resolved

## Release Process

**What this means**: How new versions are released.

**For maintainers only**: Regular contributors don't need to know this, but it's documented for transparency.

**Steps**:
1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create release PR
4. After merge, tag release
5. GitHub Actions handles package publishing

## Getting Help

**What this means**: Where to get help if you're stuck.

**Resources**:
- **Open a Discussion**: For questions and general discussion
- **Join community chat**: (link TBD) Real-time help
- **Review existing documentation**: May answer your question

## Recognition

**What this means**: How contributors are recognized.

**Contributors are recognized in**:
- CHANGELOG.md for each release
- README.md contributors section
- Annual contributor acknowledgment

**Why recognition matters**: Acknowledges the valuable contributions of community members.

Thank you for contributing to Sentinel Linux!
