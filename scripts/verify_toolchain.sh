#!/usr/bin/env bash
set -euo pipefail

REQUIRED_CMDS=(
  python3
  pip3
  git
  curl
  jq
  nmap
  nikto
  sqlmap
  whatweb
  whois
  dig
)

OPTIONAL_CMDS=(
  nuclei
  zaproxy
)

missing_required=0
missing_optional=0

echo "[*] Verifying required toolchain..."
for cmd in "${REQUIRED_CMDS[@]}"; do
  if command -v "${cmd}" >/dev/null 2>&1; then
    printf "  [OK] %s -> %s\n" "${cmd}" "$(command -v "${cmd}")"
  else
    printf "  [MISSING] %s\n" "${cmd}"
    missing_required=1
  fi
done

echo "[*] Checking optional tools..."
for cmd in "${OPTIONAL_CMDS[@]}"; do
  if command -v "${cmd}" >/dev/null 2>&1; then
    printf "  [OK] %s -> %s\n" "${cmd}" "$(command -v "${cmd}")"
  else
    printf "  [OPTIONAL] %s (not critical)\n" "${cmd}"
    missing_optional=1
  fi
done

if [[ ${missing_required} -ne 0 ]]; then
  echo "[!] One or more REQUIRED tools are missing."
  exit 1
fi

if [[ ${missing_optional} -ne 0 ]]; then
  echo "[*] Some optional tools are missing, but core functionality works."
fi

echo "[+] Toolchain verification passed."
