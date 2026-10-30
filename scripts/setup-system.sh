#!/usr/bin/env bash
# Se ejecuta elevado: instala paquetes del sistema y el ayudante de pkexec.
set -euo pipefail

ROOT="${1:-}"
if [[ -z "$ROOT" ]]; then
  echo "uso: setup-system.sh /ruta/al/repositorio" >&2
  exit 2
fi
if ((EUID != 0)); then
  echo "Este paso necesita root; ejecútalo mediante sudo o pkexec." >&2
  exit 1
fi

# Los binarios de usuario (lyrebird/snowflake con Go, oniux con cargo) van al
# HOME de quien llamó a sudo/pkexec, no al de root.
caller_uid="${PKEXEC_UID:-${SUDO_UID:-}}"
caller_home=""
if [[ -n "$caller_uid" ]]; then
  caller_home="$(getent passwd "$caller_uid" | cut -d: -f6 || true)"
  if [[ -n "$caller_home" ]]; then
    export HOME="$caller_home"
    unset XDG_RUNTIME_DIR XDG_DATA_HOME XDG_CONFIG_HOME 2>/dev/null || true
  fi
fi

export INVIZIBLE_SKIP_HELPER=1
/usr/bin/python3 "$ROOT/invizible-linux" --setup

# El ayudante pkexec necesita el paquete junto al wrapper, no solo el wrapper.
DEST=/usr/local/lib/invizible-linux
install -d "$DEST"
cp -a "$ROOT/src/invizible_linux" "$DEST/"
find "$DEST/invizible_linux" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
chmod -R a+rX "$DEST/invizible_linux"
install -m 755 "$ROOT/scripts/helper-wrapper" "$DEST/helper"
install -D -m 644 "$ROOT/data/net.invizible.Linux.policy" /usr/share/polkit-1/actions/net.invizible.Linux.policy

# Repara lo que pueda haber quedado como root en el HOME del usuario
# (bundle de Tor, enlaces de ~/.local/bin, configuración).
if [[ -n "$caller_uid" && -n "$caller_home" ]]; then
  caller_gid="$(id -g "$caller_uid" 2>/dev/null || echo "$caller_uid")"
  chown -R "$caller_uid:$caller_gid" \
    "$caller_home/.local/share/invizible-linux" \
    "$caller_home/.config/invizible-linux" 2>/dev/null || true
  find "$caller_home/.local/bin" -maxdepth 1 -user root \
    \( -name 'lyrebird' -o -name 'snowflake*' -o -name 'oniux' -o -name 'webtunnel*' \
       -o -name 'conjure*' -o -name 'obfs4proxy' -o -name 'meek-client' -o -name 'tor' \) \
    -exec chown -h "$caller_uid:$caller_gid" {} + 2>/dev/null || true
fi

echo "Helper pkexec instalado en $DEST/helper."
