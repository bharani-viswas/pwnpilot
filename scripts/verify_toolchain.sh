#!/usr/bin/env bash
set -euo pipefail

REQUIRED_CMDS=(
  python3
  pip3
  git
  curl
  jq
  nmap
  nuclei
  nikto
  sqlmap
  whatweb
  whois
  dig
  zaproxy
)

missing=0

echo "[*] Verifying required toolchain..."
for cmd in "${REQUIRED_CMDS[@]}"; do
  if command -v "${cmd}" >/dev/null 2>&1; then
    printf "[OK] %s -> %s\n" "${cmd}" "$(command -v "${cmd}")"
  else
    printf "[MISSING] %s\n" "${cmd}"
    missing=1
  fi
done

if [[ ${missing} -ne 0 ]]; then
  echo "[!] One or more required tools are missing."
  exit 1
fi

echo "[+] Toolchain verification passed."
