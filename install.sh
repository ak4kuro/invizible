#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

if ((EUID == 0)); then
  echo "No ejecutes el instalador con sudo. Lánzalo como usuario; sudo solo se pedirá para instalar paquetes." >&2
  exit 1
fi

arch_like=0
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" == "arch" || "${ID_LIKE:-}" == *arch* ]]; then
    arch_like=1
  fi
fi
if ((arch_like)) && command -v pacman >/dev/null; then
  echo "Arch: instalador completo (panel, Tor, DNSCrypt, I2P, lyrebird, oniux)…"
  exec "$ROOT/aur/install-arch.sh"
fi

BIN_DIR="${HOME}/.local/bin"
APP_DIR="${HOME}/.local/share/applications"
ICON_DIR="${HOME}/.local/share/icons/hicolor/scalable/apps"

mkdir -p "$BIN_DIR" "$APP_DIR" "$ICON_DIR"

ln -sf "$ROOT/invizible-linux" "$BIN_DIR/invizible-linux"
chmod +x "$ROOT/invizible-linux" "$ROOT/scripts/invizible-run" "$ROOT/scripts/setup-system.sh"
ln -sf "$ROOT/scripts/invizible-run" "$BIN_DIR/invizible-run"

install -m 644 "$ROOT/data/icons/net.invizible.Linux.svg" "$ICON_DIR/net.invizible.Linux.svg"
sed "s|^Exec=.*|Exec=${BIN_DIR}/invizible-linux|" \
  "$ROOT/data/net.invizible.Linux.desktop" > "$APP_DIR/net.invizible.Linux.desktop"

if command -v update-desktop-database >/dev/null; then
  update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true
fi
if command -v gtk-update-icon-cache >/dev/null; then
  gtk-update-icon-cache -f "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true
fi

echo "Instalado para el usuario: $BIN_DIR/invizible-linux"
echo
if command -v sudo >/dev/null; then
  sudo "$ROOT/scripts/setup-system.sh" "$ROOT"
elif command -v pkexec >/dev/null; then
  pkexec "$ROOT/scripts/setup-system.sh" "$ROOT"
else
  echo "La app está instalada, pero falta sudo o pkexec para instalar paquetes y el helper del sistema." >&2
  exit 1
fi
echo
echo "Abre InviZible Linux desde el menú o ejecuta: invizible-linux"
echo "Pruebas de fugas: pestaña Fugas, o INICIAR y luego Ejecutar pruebas."
echo
echo "Paquete Arch (AUR local): cd aur && makepkg -s && ./install-local.sh"
echo "Paquete Debian: ./packaging/build-deb.sh && sudo apt install ../invizible-linux_*.deb"
