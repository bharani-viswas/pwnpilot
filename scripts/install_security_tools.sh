#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "[!] Please run as root (sudo)."
  exit 1
fi

if [[ ! -f /etc/os-release ]]; then
  echo "[!] Cannot detect OS: /etc/os-release missing."
  exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
DISTRO_ID=${ID:-unknown}
DISTRO_LIKE=${ID_LIKE:-}

case "${DISTRO_ID}" in
  kali|ubuntu)
    ;;
  *)
    if [[ "${DISTRO_LIKE}" != *"debian"* ]]; then
      echo "[!] Unsupported distro: ${DISTRO_ID}. Supported: kali, ubuntu."
      exit 1
    fi
    ;;
esac

export DEBIAN_FRONTEND=noninteractive

APT_PACKAGES=(
  python3
  python3-venv
  python3-pip
  git
  curl
  jq
  nmap
  nikto
  sqlmap
  whatweb
  whois
  dnsutils
  zaproxy
  docker.io
)

# Optional alternatives can be installed manually; docker.io is default runtime in v1.

echo "[*] Updating apt indexes..."
apt-get update -y

echo "[*] Installing base and security tooling..."
apt-get install -y "${APT_PACKAGES[@]}"

echo "[*] Installing nuclei (if not available from apt)..."
if ! command -v nuclei >/dev/null 2>&1; then
  # Preferred install path from official package manager endpoint.
  go_bin_dir="/usr/local/bin"
  curl -fsSL https://raw.githubusercontent.com/projectdiscovery/nuclei/main/v2/cmd/nuclei/install.sh | bash || true
  if ! command -v nuclei >/dev/null 2>&1 && [[ -x "${go_bin_dir}/nuclei" ]]; then
    ln -sf "${go_bin_dir}/nuclei" /usr/bin/nuclei
  fi
fi

echo "[*] Ensuring Python virtual environment exists..."
APP_DIR=${APP_DIR:-"$(cd "$(dirname "$0")/.." && pwd)"}
VENV_DIR="${APP_DIR}/.venv"
if [[ ! -d "${VENV_DIR}" ]]; then
  python3 -m venv "${VENV_DIR}"
fi

if [[ -f "${APP_DIR}/requirements.txt" ]]; then
  echo "[*] Installing Python dependencies from requirements.txt..."
  "${VENV_DIR}/bin/pip" install --upgrade pip
  "${VENV_DIR}/bin/pip" install -r "${APP_DIR}/requirements.txt"
else
  echo "[i] requirements.txt not found; skipping pip dependency installation."
fi

echo "[*] Writing dependency manifest..."
mkdir -p "${APP_DIR}/.install"
{
  echo "installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "distro_id=${DISTRO_ID}"
  echo "distro_like=${DISTRO_LIKE}"
  echo "packages=${APT_PACKAGES[*]}"
} > "${APP_DIR}/.install/dependency-manifest.env"

echo "[*] Running post-install verification..."
"${APP_DIR}/scripts/verify_toolchain.sh"

echo "[+] Installation complete."
