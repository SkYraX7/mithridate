#!/usr/bin/env bash
# Mithridate setup — macOS, Linux, and WSL
# Usage: bash scripts/setup.sh
set -euo pipefail

PYTHON_MIN_MINOR=11
PYENV_PYTHON_VERSION="3.11.9"

# ── helpers ─────────────────────────────────────────────────────────────────

find_python() {
    for candidate in python3.12 python3.11 python3 python; do
        if command -v "$candidate" &>/dev/null; then
            ver=$("$candidate" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            major=$(echo "$ver" | cut -d. -f1)
            minor=$(echo "$ver" | cut -d. -f2)
            if [ "${major:-0}" -ge 3 ] && [ "${minor:-0}" -ge "$PYTHON_MIN_MINOR" ]; then
                echo "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

install_via_pyenv() {
    if ! command -v pyenv &>/dev/null; then
        echo "  → installing pyenv..."
        curl -fsSL https://pyenv.run | bash
    fi

    export PYENV_ROOT="${PYENV_ROOT:-$HOME/.pyenv}"
    export PATH="$PYENV_ROOT/bin:$PATH"
    # shellcheck disable=SC1090
    eval "$(pyenv init --path)"
    eval "$(pyenv init -)"

    echo "  → installing Python $PYENV_PYTHON_VERSION via pyenv (this may take a few minutes)..."
    pyenv install -s "$PYENV_PYTHON_VERSION"
    pyenv local "$PYENV_PYTHON_VERSION"
}

install_python_macos() {
    if command -v brew &>/dev/null; then
        echo "  → installing Python 3.11 via Homebrew..."
        brew install python@3.11
    else
        echo "  Homebrew not found — falling back to pyenv."
        install_via_pyenv
    fi
}

install_python_linux() {
    # Ubuntu/Debian 22.04+ ships python3.11 in standard repos
    if command -v apt-get &>/dev/null; then
        echo "  → trying apt-get install python3.11..."
        if sudo apt-get update -qq && sudo apt-get install -y python3.11 python3.11-venv 2>/dev/null; then
            return 0
        fi
        echo "  apt install failed (older distro?) — falling back to pyenv."
        echo "  → installing build dependencies..."
        sudo apt-get install -y \
            build-essential curl git \
            libssl-dev zlib1g-dev libbz2-dev \
            libreadline-dev libsqlite3-dev libffi-dev
    fi
    install_via_pyenv
}

# ── main ────────────────────────────────────────────────────────────────────

echo "=== Mithridate setup ==="
echo ""

OS="$(uname -s)"

if ! PYTHON=$(find_python 2>/dev/null); then
    echo "Python 3.${PYTHON_MIN_MINOR}+ not found — installing..."
    case "$OS" in
        Darwin) install_python_macos ;;
        Linux)  install_python_linux ;;
        *)
            echo "Unsupported OS: $OS"
            echo "Install Python 3.11+ manually from https://python.org and re-run."
            exit 1
            ;;
    esac
    # Re-search after install (pyenv may have set .python-version)
    PYTHON=$(find_python) || {
        echo "Python install did not land on PATH. Open a new shell and re-run."
        exit 1
    }
fi

echo "Python: $PYTHON ($($PYTHON --version))"
echo ""

# Virtual environment
if [ ! -d .venv ]; then
    echo "Creating virtual environment..."
    "$PYTHON" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "Installing dependencies..."
pip install --upgrade pip setuptools wheel -q
pip install -e ".[dev]" -q

# .env
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
    else
        printf 'ANTHROPIC_API_KEY=\n' > .env
    fi
    echo ""
    echo "  Created .env — open it and set your ANTHROPIC_API_KEY."
fi

echo ""
echo "Done!  Activate the environment with:"
echo "  source .venv/bin/activate"
echo ""
echo "Then verify with:"
echo "  mithridate eval --gate-only"
