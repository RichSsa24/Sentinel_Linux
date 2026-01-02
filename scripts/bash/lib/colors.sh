#!/bin/bash
# Color definitions for Sentinel Linux bash scripts
#
# This library provides color codes for terminal output.
# Colors are automatically disabled if output is not a terminal.

# Check if output is a terminal
if [[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]]; then
    # Terminal colors
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'
    CYAN='\033[0;36m'
    WHITE='\033[1;37m'
    BOLD='\033[1m'
    NC='\033[0m' # No Color (reset)
else
    # No colors (not a terminal or dumb terminal)
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    MAGENTA=''
    CYAN=''
    WHITE=''
    BOLD=''
    NC=''
fi

# Colorized logging functions
log_info_colored() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_error_colored() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_warning_colored() {
    echo -e "${YELLOW}[WARNING]${NC} $*" >&2
}

log_success_colored() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

