#!/usr/bin/env bash
# Instalador completo para Arch y derivados (pacman). Instala el panel y
# todo lo necesario: módulos, cortafuegos, puentes lyrebird y oniux.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AUR="$ROOT/aur"
LOCAL_BIN="${HOME}/.local/bin"
mkdir -p "$LOCAL_BIN"
export PATH="$LOCAL_BIN:${HOME}/.cargo/bin:$PATH"

log() { printf '==> %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

if ((EUID == 0)); then
  echo "No ejecutes este instalador con sudo. Lánzalo como usuario; sudo solo se pedirá para instalar paquetes." >&2
  exit 1
fi

if ! have pacman; then
  echo "Este instalador es para Arch Linux (pacman)." >&2
  exit 1
fi

OFFICIAL=(
  base-devel
  python
  python-gobject
  python-cairo
  gtk4
  libadwaita
  tor
  dnscrypt-proxy
  i2pd
  polkit
  nftables
  torsocks
  go
  rust
  git
  firejail
  libayatana-appindicator
)

log "Instalando paquetes oficiales"
sudo pacman -S --needed --noconfirm -- "${OFFICIAL[@]}"

log "Construyendo InviZible Linux"
(
  cd "$AUR"
  makepkg -sf --noconfirm
)

shopt -s nullglob
pkgs=("$AUR"/invizible-linux-*-any.pkg.tar.zst)
if ((${#pkgs[@]} == 0)); then
  echo "makepkg no generó el paquete." >&2
  exit 1
fi
log "Instalando ${pkgs[-1]##*/}"
bash "$ROOT/packaging/pacman-u-local.sh" "${pkgs[-1]}"

install_snowflake() {
  if have lyrebird; then
    log "Snowflake ya está incluido en lyrebird: $(command -v lyrebird)"
    return 0
  fi
  if have snowflake-client || have snowflake; then
    log "snowflake ya está: $(command -v snowflake-client || command -v snowflake)"
    return 0
  fi
  log "Compilando snowflake-client"
  local tmp
  tmp="$(mktemp -d)"
  GOBIN="$tmp" CGO_ENABLED=0 go install \
    gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/client@latest
  local built
  built="$(find "$tmp" -maxdepth 1 -type f -perm -u+x | head -n 1)"
  if [[ -z "$built" ]]; then
    rm -rf "$tmp"
    echo "go install no dejó snowflake-client" >&2
    return 1
  fi
  install -m 755 "$built" "$LOCAL_BIN/snowflake-client"
  rm -rf "$tmp"
  log "snowflake-client: $LOCAL_BIN/snowflake-client"
}

install_lyrebird() {
  if have lyrebird || have obfs4proxy; then
    log "lyrebird ya está: $(command -v lyrebird || command -v obfs4proxy)"
    return 0
  fi
  log "Compilando lyrebird (puentes obfs4; el AUR lyrebird-proxy-git está roto)"
  GOBIN="$LOCAL_BIN" CGO_ENABLED=0 go install \
    gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/cmd/lyrebird@latest
  if [[ ! -x "$LOCAL_BIN/lyrebird" ]]; then
    echo "go install no dejó $LOCAL_BIN/lyrebird" >&2
    return 1
  fi
  log "lyrebird: $LOCAL_BIN/lyrebird"
}

install_oniux() {
  if have oniux; then
    log "oniux ya está: $(command -v oniux)"
    return 0
  fi
  local yay=""
  yay="$(command -v yay || true)"
  [[ -z "$yay" ]] && yay="$(command -v paru || true)"
  if [[ -n "$yay" ]]; then
    log "Instalando oniux desde AUR"
    if "$yay" -S --needed --noconfirm oniux; then
      have oniux && return 0
    fi
    local cache pkg
    cache="${HOME}/.cache/yay/oniux"
    shopt -s nullglob
    local built=("$cache"/oniux-*.pkg.tar.zst)
    shopt -u nullglob
    for pkg in "${built[@]+"${built[@]}"}"; do
      [[ "$pkg" == *"-debug-"* ]] && continue
      [[ -f "$pkg" ]] || continue
      log "Instalando oniux ya compilado (sin .sig)"
      bash "$ROOT/packaging/pacman-u-local.sh" "$pkg" || true
      have oniux && return 0
    done
  fi
  log "Compilando oniux con cargo (puede tardar)"
  cargo install --locked --git https://gitlab.torproject.org/tpo/core/oniux.git oniux
  have oniux || {
    echo "No se pudo instalar oniux." >&2
    return 1
  }
}

install_lyrebird
install_snowflake || log "snowflake se puede instalar luego (Instalar lyrebird en la app)"
install_oniux || log "oniux se puede instalar luego desde la pestaña Apps"

if have gtk-update-icon-cache; then
  sudo gtk-update-icon-cache -f /usr/share/icons/hicolor >/dev/null 2>&1 || true
fi
if have update-desktop-database; then
  sudo update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
fi

echo
log "Listo."
echo "  Panel:     invizible-linux"
echo "  Helper:    /usr/lib/invizible-linux/helper (pkexec)"
echo "  lyrebird:  $(command -v lyrebird 2>/dev/null || echo "falta")"
echo "  snowflake: $(command -v snowflake-client 2>/dev/null || { have lyrebird && echo "incluido en lyrebird" || echo "falta"; })"
echo "  oniux:     $(command -v oniux 2>/dev/null || echo "falta")"
echo
echo "Si lyrebird está en $LOCAL_BIN y no aparece, abre una terminal nueva (PATH)."
echo "Cierra InviZible con Salir si ya estaba abierto, y vuelve a abrirlo."
