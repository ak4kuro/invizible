#!/usr/bin/env bash
# Actualiza /usr/lib/invizible-linux sin reconstruir el .pkg (corrige tor.service).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
dest="$(mktemp -d)"
trap 'rm -rf "$dest"' EXIT
bash "$ROOT/packaging/install-files.sh" "$dest"
sudo cp -a "$dest/usr/lib/invizible-linux/invizible_linux/." /usr/lib/invizible-linux/invizible_linux/
sudo chmod -R a+rX /usr/lib/invizible-linux/invizible_linux
sudo mkdir -p /var/log/tor
sudo chown tor:tor /var/log/tor 2>/dev/null || sudo chown debian-tor:debian-tor /var/log/tor 2>/dev/null || true
sudo chmod 755 /var/log/tor
sudo systemctl reset-failed tor.service 2>/dev/null || true
echo "Helper actualizado. Cierra InviZible con Salir y vuelve a abrirlo."
