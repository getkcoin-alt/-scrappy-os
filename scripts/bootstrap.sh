#!/usr/bin/env bash
#
# Scrappy OS bootstrap.
#
# Sets up a virtualenv, installs the package, creates the data and workspace
# directories, and runs the self-check.
#
# What this script deliberately does NOT do:
#   * install system packages (it tells you what is missing and stops)
#   * modify anything outside the repository and the data directory
#   * write a .env if one already exists
#   * run as root without saying so
#
# Usage:
#   ./scripts/bootstrap.sh              # install and verify
#   ./scripts/bootstrap.sh --with-tests # also run the test suite
#   ./scripts/bootstrap.sh --dev        # dev extras (ruff, mypy, pytest)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${REPO_ROOT}/.venv"
MIN_PYTHON_MINOR=12
RUN_TESTS=0
DEV_EXTRAS=0

for arg in "$@"; do
  case "${arg}" in
    --with-tests) RUN_TESTS=1; DEV_EXTRAS=1 ;;
    --dev)        DEV_EXTRAS=1 ;;
    -h|--help)    sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "Unknown option: ${arg}" >&2; exit 2 ;;
  esac
done

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'
else
  BOLD=""; GREEN=""; YELLOW=""; RED=""; RESET=""
fi

step() { printf '\n%s==> %s%s\n' "${BOLD}" "$*" "${RESET}"; }
ok()   { printf '    %s✓%s %s\n' "${GREEN}" "${RESET}" "$*"; }
warn() { printf '    %s!%s %s\n' "${YELLOW}" "${RESET}" "$*"; }
die()  { printf '\n    %s✗ %s%s\n\n' "${RED}" "$*" "${RESET}" >&2; exit 1; }

# ---------------------------------------------------------------------------
step "Checking the environment"
# ---------------------------------------------------------------------------

[[ "$(uname -s)" == "Linux" ]] || die "Scrappy OS v0.1 targets Linux. Found: $(uname -s)"

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  ok "${PRETTY_NAME:-unknown Linux} ($(uname -m))"
else
  warn "no /etc/os-release; continuing anyway"
fi

# Find a Python new enough to run this. `python3` is often older than what is
# installed, so check the versioned names first.
PYTHON=""
for candidate in python3.13 python3.12 python3; do
  if command -v "${candidate}" >/dev/null 2>&1; then
    minor="$("${candidate}" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo 0)"
    major="$("${candidate}" -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo 0)"
    if [[ "${major}" -eq 3 && "${minor}" -ge "${MIN_PYTHON_MINOR}" ]]; then
      PYTHON="$(command -v "${candidate}")"
      break
    fi
  fi
done

if [[ -z "${PYTHON}" ]]; then
  die "Python 3.${MIN_PYTHON_MINOR}+ is required and was not found.
    Install it with your package manager, for example:
      Debian/Ubuntu:  sudo apt install python3.12 python3.12-venv
      Fedora/RHEL:    sudo dnf install python3.12
    This script will not install system packages for you."
fi
ok "$(${PYTHON} --version) at ${PYTHON}"

if ! "${PYTHON}" -c 'import venv' >/dev/null 2>&1; then
  die "The venv module is missing. On Debian/Ubuntu: sudo apt install python3-venv"
fi

command -v git >/dev/null 2>&1 && ok "git $(git --version | awk '{print $3}')" \
  || warn "git is not installed; the git.* tools will report it as unavailable"

if [[ "$(id -u)" -eq 0 ]]; then
  warn "running as root."
  warn "Scrappy OS should run as a dedicated unprivileged account - see deploy/README.md."
fi

# ---------------------------------------------------------------------------
step "Creating the virtualenv"
# ---------------------------------------------------------------------------

if [[ -d "${VENV}" ]]; then
  ok "reusing ${VENV}"
else
  "${PYTHON}" -m venv "${VENV}"
  ok "created ${VENV}"
fi

"${VENV}/bin/python" -m pip install --quiet --upgrade pip setuptools wheel
ok "pip $(${VENV}/bin/pip --version | awk '{print $2}')"

# ---------------------------------------------------------------------------
step "Installing scrappy-os"
# ---------------------------------------------------------------------------

if [[ "${DEV_EXTRAS}" -eq 1 ]]; then
  "${VENV}/bin/pip" install --quiet -e "${REPO_ROOT}[dev]"
  ok "installed with dev extras"
else
  "${VENV}/bin/pip" install --quiet -e "${REPO_ROOT}"
  ok "installed"
fi

# ---------------------------------------------------------------------------
step "Setting up configuration"
# ---------------------------------------------------------------------------

if [[ -f "${REPO_ROOT}/.env" ]]; then
  ok ".env already exists - leaving it untouched"
else
  cp "${REPO_ROOT}/.env.example" "${REPO_ROOT}/.env"
  chmod 600 "${REPO_ROOT}/.env"
  ok "created .env from .env.example (mode 0600)"
  warn "it defaults to the offline development provider; edit it to use a real model"
fi

DATA_DIR="$("${VENV}/bin/python" - <<'PY'
from scrappy_os.core.config import load_settings

settings = load_settings()
settings.ensure_directories()
print(settings.data_dir)
PY
)"
ok "data directory: ${DATA_DIR}"

# ---------------------------------------------------------------------------
if [[ "${RUN_TESTS}" -eq 1 ]]; then
  step "Running the test suite"
  "${VENV}/bin/python" -m pytest -q || die "tests failed - do not deploy this checkout"
  ok "tests passed"
fi

# ---------------------------------------------------------------------------
step "Running scrappy doctor"
# ---------------------------------------------------------------------------

set +e
"${VENV}/bin/scrappy" doctor
DOCTOR_STATUS=$?
set -e

# ---------------------------------------------------------------------------
printf '\n%s==> Next steps%s\n\n' "${BOLD}" "${RESET}"
cat <<EOF
  Activate the virtualenv:
      source .venv/bin/activate

  Ask Scrappy OS something read-only:
      scrappy ask "Inspect disk usage and tell me what filesystem is most full"

  See what it did:
      scrappy audit

  Check state and configuration:
      scrappy status
      scrappy config show
      scrappy tools

  Run the local API on 127.0.0.1:8787:
      scrappy serve

  Point it at a real model (edit .env):
      SCRAPPY_MODEL_PROVIDER=ollama   OLLAMA_BASE_URL=http://127.0.0.1:11434
      SCRAPPY_MODEL_PROVIDER=openai   OPENAI_API_KEY=...

  Deploying as a service:
      deploy/README.md

EOF

if [[ ${DOCTOR_STATUS} -ne 0 ]]; then
  warn "doctor reported failures above. Fix them before giving Scrappy OS real work."
  exit "${DOCTOR_STATUS}"
fi
