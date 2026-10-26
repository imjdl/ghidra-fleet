#!/usr/bin/env bash
# Build the ghidra-fleet virtualenv (Linux/macOS):
#   - fastmcp from PyPI
#   - pyghidra + jpype1 from the wheels bundled with the local Ghidra install
#     (version-matched by design; do NOT mix with PyPI pyghidra)
# Usage:
#   GHIDRA_INSTALL_DIR=/path/to/ghidra scripts/setup_env.sh
#   (or pass the install dir as the first argument)
set -euo pipefail
cd "$(dirname "$0")/.."

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-${1:-}}"
if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    echo "[ERROR] GHIDRA_INSTALL_DIR not set."
    echo        "Usage: GHIDRA_INSTALL_DIR=/path/to/ghidra scripts/setup_env.sh"
    exit 1
fi
DIST="$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist"

if [ ! -d "$DIST" ]; then
    echo "[ERROR] PyGhidra dist not found: $DIST"
    echo        "Is '$GHIDRA_INSTALL_DIR' really a Ghidra install dir?"
    exit 1
fi

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python

if [ ! -d .venv ]; then
    "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
. .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install fastmcp

PYGHIDRA_WHEEL="$(ls "$DIST"/pyghidra-*.whl 2>/dev/null | head -n1 || true)"
if [ -z "$PYGHIDRA_WHEEL" ]; then
    echo "[ERROR] no pyghidra wheel found in $DIST"
    exit 1
fi
python -m pip install "$PYGHIDRA_WHEEL" --no-deps
python -m pip install packaging

# pyghidra pins Jpype1==x.y.z; the bundled wheel set may not cover every
# Python version - fall back to PyPI jpype1 when this tag/platform is missing.
PYTAG="$(python -c 'import sys;print(f"cp{sys.version_info[0]}{sys.version_info[1]}")')"
JPYPE_WHEEL="$(ls "$DIST"/jpype1-*-"$PYTAG"-"$PYTAG"-*.whl 2>/dev/null | head -n1 || true)"
if [ -n "$JPYPE_WHEEL" ]; then
    python -m pip install "$JPYPE_WHEEL"
else
    echo "bundled jpype1 has no $PYTAG wheel - installing latest jpype1 from PyPI"
    python -m pip install jpype1
fi

python -m pip install -e . --no-deps

echo
echo "[OK] ghidra-fleet env ready. Test:"
echo "  GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR .venv/bin/python -m ghidra_fleet"
