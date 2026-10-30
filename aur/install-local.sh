#!/usr/bin/env bash
# Instala el .pkg.tar.zst generado por makepkg cuando pacman exige firma
# en archivos locales (LocalFileSigLevel = Required) y el paquete no está firmado.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
if ((EUID == 0)); then
  echo "No ejecutes este instalador con sudo. Lánzalo como usuario; sudo solo se pedirá para instalar el paquete." >&2
  exit 1
fi

shopt -s nullglob
pkgs=("$DIR"/invizible-linux-*-any.pkg.tar.zst)
if ((${#pkgs[@]} == 0)); then
  echo "No hay paquete. Primero: cd aur && makepkg -s" >&2
  echo "O el instalador completo: ./install-arch.sh" >&2
  exit 1
fi
bash "$ROOT/packaging/pacman-u-local.sh" "${pkgs[-1]}"
