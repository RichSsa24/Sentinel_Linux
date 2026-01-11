# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure
- Core monitoring framework
- User activity monitoring module
- Process anomaly detection
- Network connection monitoring
- File integrity monitoring (FIM)
- Authentication event monitoring
- Service status monitoring
- System log analysis
- MITRE ATT&CK technique mapping
- IOC matching engine
- Statistical anomaly detection
- Console, JSON, and Syslog reporters
- Webhook notification support
- Comprehensive Bash audit scripts
- Sigma rule support
- YARA rule integration
- Interactive real-time dashboard (`src/cli/dashboard.py`) with Rich library
- Monitor control script (`scripts/bash/run_monitor.sh`) with full lifecycle management
- Comprehensive linting script (`scripts/python/run_linters.py`) for automated code quality checks
- Unit tests for correlation engine (`tests/unit/test_correlation_engine.py`)
- Unit tests for exception handling (`tests/unit/test_exception_handling.py`)

### Changed
- Fixed typo in README.md title (removed trailing 'j')
- Enhanced path validation in file integrity monitor, log monitor, IOC matcher, and settings loader
- Improved error handling in `log_analyzer.sh` for temporary file creation
- Updated CLI to include dashboard command

### Security
- Input validation for all external data
- Secure configuration handling
- Privilege minimization support
- TLS support for network communications
- Path traversal protection in file operations (file_integrity_monitor, log_monitor, ioc_matcher, settings)
- Enhanced temporary file handling in Bash scripts
- Comprehensive security audit completed (Phases 1-6)

## [1.0.0] - 2024-XX-XX

### Added
- Production-ready release
- Complete documentation
- Full test coverage
- Enterprise deployment support

---

## Version History Template

### [X.Y.Z] - YYYY-MM-DD

#### Added
- New features

#### Changed
- Changes in existing functionality

#### Deprecated
- Soon-to-be removed features

#### Removed
- Removed features

#### Fixed
- Bug fixes

#### Security
- Security fixes and improvements



