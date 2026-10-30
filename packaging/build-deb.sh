#!/usr/bin/env bash
# Construye el .deb desde la raíz del repositorio.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if ! command -v dpkg-buildpackage >/dev/null; then
  echo "Falta dpkg-buildpackage. En Debian: sudo apt install dpkg-dev debhelper" >&2
  exit 1
fi
dpkg-buildpackage -us -uc -b
echo
echo "Paquete en el directorio padre. Instala con:"
echo "  sudo apt install ../invizible-linux_*.deb"
