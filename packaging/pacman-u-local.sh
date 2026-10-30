#!/usr/bin/env bash
# Instala .pkg.tar.zst locales cuando pacman exige LocalFileSigLevel=Required.
# No cambia /etc/pacman.conf: solo esta invocación.
set -euo pipefail
if (($# < 1)); then
  echo "uso: pacman-u-local.sh paquete.pkg.tar.zst [...]" >&2
  exit 2
fi
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
sed 's/^LocalFileSigLevel.*/LocalFileSigLevel = Optional/' /etc/pacman.conf >"$tmp"
echo "Instalando $* (firma local opcional solo en esta orden)"
sudo pacman --config "$tmp" -U --needed --noconfirm "$@"
