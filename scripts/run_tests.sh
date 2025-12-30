#!/usr/bin/env bash
#
# Automated Test Runner for Linux Security Monitor
#
# Runs all tests including unit, integration, security, and code quality checks.
#
# Usage:
#   ./run_tests.sh [options]
#
# Options:
#   -a, --all         Run all tests (default)
#   -u, --unit        Run unit tests only
#   -i, --integration Run integration tests only
#   -s, --security    Run security tests only
#   -l, --lint        Run linters only
#   -c, --coverage    Generate coverage report
#   -q, --quick       Quick tests (skip slow tests)
#   -v, --verbose     Verbose output
#

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Options
RUN_UNIT=false
RUN_INTEGRATION=false
RUN_SECURITY=false
RUN_LINT=false
RUN_ALL=true
GENERATE_COVERAGE=false
QUICK_MODE=false
VERBOSE=false

# Results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

usage() {
    cat << EOF
Linux Security Monitor - Test Runner

Usage: $(basename "$0") [options]

Options:
    -a, --all         Run all tests (default)
    -u, --unit        Run unit tests only
    -i, --integration Run integration tests only
    -s, --security    Run security tests only
    -l, --lint        Run linters only
    -c, --coverage    Generate coverage report
    -q, --quick       Quick tests (skip slow tests)
    -v, --verbose     Verbose output
    -h, --help        Show this help message

Examples:
    $(basename "$0")                    # Run all tests
    $(basename "$0") -u -c              # Run unit tests with coverage
    $(basename "$0") -l                 # Run linters only
    $(basename "$0") -q                 # Quick test run

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -a|--all)         RUN_ALL=true; shift ;;
            -u|--unit)        RUN_UNIT=true; RUN_ALL=false; shift ;;
            -i|--integration) RUN_INTEGRATION=true; RUN_ALL=false; shift ;;
            -s|--security)    RUN_SECURITY=true; RUN_ALL=false; shift ;;
            -l|--lint)        RUN_LINT=true; RUN_ALL=false; shift ;;
            -c|--coverage)    GENERATE_COVERAGE=true; shift ;;
            -q|--quick)       QUICK_MODE=true; shift ;;
            -v|--verbose)     VERBOSE=true; shift ;;
            -h|--help)        usage; exit 0 ;;
            *)                echo "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    # If all, set all flags
    if [[ "$RUN_ALL" == "true" ]]; then
        RUN_UNIT=true
        RUN_INTEGRATION=true
        RUN_SECURITY=true
        RUN_LINT=true
    fi
}

log_header() {
    echo ""
    echo -e "${BOLD}${CYAN}========================================${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}========================================${NC}"
    echo ""
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED_TESTS++)) || true
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED_TESTS++)) || true
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    ((SKIPPED_TESTS++)) || true
}

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

check_dependencies() {
    log_header "Checking Dependencies"

    local deps=("python3" "pip")
    local missing=()

    for dep in "${deps[@]}"; do
        if command -v "$dep" &>/dev/null; then
            log_success "$dep found"
        else
            log_failure "$dep not found"
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo ""
        echo -e "${RED}Missing dependencies: ${missing[*]}${NC}"
        exit 1
    fi

    # Check Python version
    local python_version
    python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    log_info "Python version: $python_version"

    # Check if pytest is installed
    if python3 -c "import pytest" 2>/dev/null; then
        log_success "pytest installed"
    else
        log_info "Installing pytest..."
        pip install pytest pytest-cov pytest-asyncio --quiet
    fi
}

setup_environment() {
    log_header "Setting Up Environment"

    cd "$PROJECT_ROOT"

    # Create virtual environment if needed
    if [[ ! -d "venv" ]]; then
        log_info "Creating virtual environment..."
        python3 -m venv venv
    fi

    # Activate virtual environment
    source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null || true

    # Install dependencies
    log_info "Installing dependencies..."
    pip install -e ".[dev]" --quiet 2>/dev/null || pip install -r requirements.txt --quiet

    log_success "Environment ready"
}

run_linters() {
    log_header "Running Linters"

    local lint_failed=false

    # Black (code formatting)
    log_info "Running black..."
    if command -v black &>/dev/null || python3 -c "import black" 2>/dev/null; then
        if black --check --quiet src/ tests/ 2>/dev/null; then
            log_success "black: Code formatting OK"
        else
            log_failure "black: Code formatting issues found"
            [[ "$VERBOSE" == "true" ]] && black --diff src/ tests/ 2>/dev/null || true
            lint_failed=true
        fi
    else
        log_skip "black: Not installed"
    fi
    ((TOTAL_TESTS++)) || true

    # isort (import sorting)
    log_info "Running isort..."
    if command -v isort &>/dev/null || python3 -c "import isort" 2>/dev/null; then
        if isort --check-only --quiet src/ tests/ 2>/dev/null; then
            log_success "isort: Import sorting OK"
        else
            log_failure "isort: Import sorting issues found"
            lint_failed=true
        fi
    else
        log_skip "isort: Not installed"
    fi
    ((TOTAL_TESTS++)) || true

    # flake8 (linting)
    log_info "Running flake8..."
    if command -v flake8 &>/dev/null || python3 -c "import flake8" 2>/dev/null; then
        if flake8 src/ tests/ --max-line-length=100 --ignore=E203,W503 2>/dev/null; then
            log_success "flake8: No linting errors"
        else
            log_failure "flake8: Linting errors found"
            lint_failed=true
        fi
    else
        log_skip "flake8: Not installed"
    fi
    ((TOTAL_TESTS++)) || true

    # mypy (type checking)
    log_info "Running mypy..."
    if command -v mypy &>/dev/null || python3 -c "import mypy" 2>/dev/null; then
        if mypy src/ --ignore-missing-imports --no-error-summary 2>/dev/null; then
            log_success "mypy: Type checking OK"
        else
            log_failure "mypy: Type errors found"
            lint_failed=true
        fi
    else
        log_skip "mypy: Not installed"
    fi
    ((TOTAL_TESTS++)) || true

    # Bandit (security linting)
    log_info "Running bandit..."
    if command -v bandit &>/dev/null || python3 -c "import bandit" 2>/dev/null; then
        if bandit -r src/ -q -ll 2>/dev/null; then
            log_success "bandit: No security issues"
        else
            log_failure "bandit: Security issues found"
            lint_failed=true
        fi
    else
        log_skip "bandit: Not installed"
    fi
    ((TOTAL_TESTS++)) || true

    # ShellCheck for bash scripts
    log_info "Running shellcheck..."
    if command -v shellcheck &>/dev/null; then
        local shell_errors=0
        for script in scripts/bash/*.sh; do
            if [[ -f "$script" ]]; then
                if ! shellcheck "$script" 2>/dev/null; then
                    ((shell_errors++)) || true
                fi
            fi
        done
        if [[ $shell_errors -eq 0 ]]; then
            log_success "shellcheck: Bash scripts OK"
        else
            log_failure "shellcheck: $shell_errors script(s) with issues"
            lint_failed=true
        fi
    else
        log_skip "shellcheck: Not installed"
    fi
    ((TOTAL_TESTS++)) || true

    return $([[ "$lint_failed" == "true" ]] && echo 1 || echo 0)
}

run_unit_tests() {
    log_header "Running Unit Tests"

    local pytest_args=("-v" "tests/unit/")

    if [[ "$QUICK_MODE" == "true" ]]; then
        pytest_args+=("-m" "not slow")
    fi

    if [[ "$GENERATE_COVERAGE" == "true" ]]; then
        pytest_args+=("--cov=src" "--cov-report=term-missing" "--cov-report=html:coverage_html")
    fi

    if [[ "$VERBOSE" != "true" ]]; then
        pytest_args+=("-q")
    fi

    log_info "Running: pytest ${pytest_args[*]}"

    if pytest "${pytest_args[@]}" 2>&1; then
        log_success "Unit tests passed"
        return 0
    else
        log_failure "Unit tests failed"
        return 1
    fi
}

run_integration_tests() {
    log_header "Running Integration Tests"

    local pytest_args=("-v" "tests/integration/")

    if [[ "$QUICK_MODE" == "true" ]]; then
        pytest_args+=("-m" "not slow")
    fi

    if [[ "$VERBOSE" != "true" ]]; then
        pytest_args+=("-q")
    fi

    log_info "Running: pytest ${pytest_args[*]}"

    if pytest "${pytest_args[@]}" 2>&1; then
        log_success "Integration tests passed"
        return 0
    else
        log_failure "Integration tests failed"
        return 1
    fi
}

run_security_tests() {
    log_header "Running Security Tests"

    local pytest_args=("-v" "tests/security/" "-m" "security")

    if [[ "$VERBOSE" != "true" ]]; then
        pytest_args+=("-q")
    fi

    log_info "Running: pytest ${pytest_args[*]}"

    if pytest "${pytest_args[@]}" 2>&1; then
        log_success "Security tests passed"
        return 0
    else
        log_failure "Security tests failed"
        return 1
    fi
}

run_bash_tests() {
    log_header "Running Bash Script Tests"

    local scripts=(
        "scripts/bash/health_check.sh"
        "scripts/bash/service_checker.sh"
    )

    for script in "${scripts[@]}"; do
        if [[ -f "$PROJECT_ROOT/$script" ]]; then
            log_info "Testing: $script"
            ((TOTAL_TESTS++)) || true

            # Syntax check
            if bash -n "$PROJECT_ROOT/$script" 2>/dev/null; then
                log_success "$script: Syntax OK"
            else
                log_failure "$script: Syntax error"
            fi
        fi
    done
}

generate_report() {
    log_header "Test Summary"

    local total=$((PASSED_TESTS + FAILED_TESTS + SKIPPED_TESTS))

    echo ""
    echo -e "Total tests:   ${BOLD}$total${NC}"
    echo -e "Passed:        ${GREEN}$PASSED_TESTS${NC}"
    echo -e "Failed:        ${RED}$FAILED_TESTS${NC}"
    echo -e "Skipped:       ${YELLOW}$SKIPPED_TESTS${NC}"

    if [[ $total -gt 0 ]]; then
        local pass_rate=$((PASSED_TESTS * 100 / total))
        echo ""
        echo -e "Pass rate:     ${BOLD}${pass_rate}%${NC}"
    fi

    if [[ "$GENERATE_COVERAGE" == "true" && -d "coverage_html" ]]; then
        echo ""
        echo -e "Coverage report: ${CYAN}coverage_html/index.html${NC}"
    fi

    echo ""
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}${BOLD}Some tests failed. Please review the output above.${NC}"
        return 1
    fi
}

main() {
    parse_args "$@"

    echo -e "${BOLD}Linux Security Monitor - Test Runner${NC}"
    echo "======================================"
    echo "Project: $PROJECT_ROOT"
    echo "Date: $(date)"

    local exit_code=0

    check_dependencies
    setup_environment

    if [[ "$RUN_LINT" == "true" ]]; then
        run_linters || exit_code=1
    fi

    if [[ "$RUN_UNIT" == "true" ]]; then
        run_unit_tests || exit_code=1
    fi

    if [[ "$RUN_INTEGRATION" == "true" ]]; then
        run_integration_tests || exit_code=1
    fi

    if [[ "$RUN_SECURITY" == "true" ]]; then
        run_security_tests || exit_code=1
    fi

    run_bash_tests

    generate_report

    exit $exit_code
}

main "$@"

