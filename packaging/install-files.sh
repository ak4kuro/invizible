#!/usr/bin/env bash
# Copia el árbol de instalación a DESTDIR (Arch makepkg y Debian dh).
set -euo pipefail

DEST="${1:?uso: install-files.sh DESTDIR}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$DEST/usr/lib/invizible-linux"

install -d "$LIB/data/icons"
install -d "$LIB/scripts"
cp -a "$ROOT/src/invizible_linux" "$LIB/"
find "$LIB" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
chmod -R a+rX "$LIB/invizible_linux"
install -m644 "$ROOT/data/icons/net.invizible.Linux.svg" \
  "$LIB/data/icons/net.invizible.Linux.svg"
install -Dm755 "$ROOT/scripts/helper-wrapper" "$LIB/helper"
install -Dm755 "$ROOT/scripts/invizible-run" "$LIB/scripts/invizible-run"

install -Dm755 /dev/stdin "$DEST/usr/bin/invizible-linux" <<'EOF'
#!/usr/bin/env python3
import sys
sys.path.insert(0, "/usr/lib/invizible-linux")
from invizible_linux.app import main
if __name__ == "__main__":
    raise SystemExit(main())
EOF
install -Dm755 /dev/stdin "$DEST/usr/bin/invizible-run" <<'EOF'
#!/usr/bin/env python3
import runpy
import sys
sys.path.insert(0, "/usr/lib/invizible-linux")
runpy.run_path("/usr/lib/invizible-linux/scripts/invizible-run", run_name="__main__")
EOF

install -Dm644 "$ROOT/data/net.invizible.Linux.desktop" \
  "$DEST/usr/share/applications/net.invizible.Linux.desktop"
install -Dm644 "$ROOT/data/icons/net.invizible.Linux.svg" \
  "$DEST/usr/share/icons/hicolor/scalable/apps/net.invizible.Linux.svg"
install -Dm644 /dev/stdin "$DEST/usr/share/polkit-1/actions/net.invizible.Linux.policy" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>InviZible Linux</vendor>
  <action id="net.invizible.Linux.helper">
    <description>Gestionar DNS y cortafuegos de InviZible Linux</description>
    <description xml:lang="es">Gestionar DNS y cortafuegos de InviZible Linux</description>
    <message>InviZible Linux necesita privilegios para el cortafuegos nftables y el DNS del sistema.</message>
    <message xml:lang="es">InviZible Linux necesita privilegios para el cortafuegos nftables y el DNS del sistema.</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/lib/invizible-linux/helper</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
  </action>
</policyconfig>
EOF
