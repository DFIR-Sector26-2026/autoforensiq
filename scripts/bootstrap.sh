#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${ROOT_DIR}/venv"

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "Python 3 is required but was not found on PATH."
  exit 1
fi

if [[ ! -d "${VENV_DIR}" ]]; then
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

python -m pip install --upgrade pip setuptools wheel
python -m pip install -r "${ROOT_DIR}/requirements.txt"

missing_tools=()

check_command() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    missing_tools+=("${name}")
  fi
}

check_any_path() {
  local label="$1"
  shift

  local path
  for path in "$@"; do
    if [[ -f "${path}" ]]; then
      return 0
    fi
  done

  missing_tools+=("${label}")
  return 1
}

check_regripper() {
  if [[ -n "${REGRIPPER_PATH:-}" && -f "${REGRIPPER_PATH}" ]]; then
    return 0
  fi

  check_any_path "RegRipper rip.pl" \
    "${HOME}/regripper/rip.pl" \
    "${HOME}/RegRipper3.0/rip.pl" \
    "${HOME}/RegRipper/rip.pl" \
    "${HOME}/Desktop/RegRipper3.0/rip.pl"
}

check_command tshark
check_command fls
check_command perl
if ! command -v log2timeline.py >/dev/null 2>&1 && ! command -v log2timeline >/dev/null 2>&1; then
  missing_tools+=("log2timeline.py/log2timeline")
fi
check_regripper

if [[ ${#missing_tools[@]} -gt 0 ]]; then
  echo
  echo "Python dependencies are installed, but these live-run tools are still missing:"
  for tool in "${missing_tools[@]}"; do
    echo "  - ${tool}"
  done
  echo
  echo "Install them separately, then re-run this script if you want to verify PATH availability."
fi

echo
echo "Setup complete. Activate the environment with: source venv/bin/activate"