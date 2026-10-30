# InviZible Linux

Panel gráfico para Linux inspirado en **InviZible Lite**: activa DNSCrypt, Tor, I2P y un cortafuegos desde una sola pantalla.

No es un port oficial ni un clon del APK. Usa los mismos programas libres en el escritorio (GTK4 / libadwaita). Versión **0.7.0**.

## Qué hace

| Módulo | En Android (InviZible) | Aquí |
| --- | --- | --- |
| DNSCrypt | Cifra las consultas DNS | `dnscrypt-proxy` en `127.0.0.1:5354` |
| Tor | Anonimato, .onion, puente de censura | `tor` SOCKS `127.0.0.1:9050` o `tor.service` |
| I2P | Red invisible | `i2pd` HTTP `127.0.0.1:4444` |
| Cortafuegos | Por aplicación (VPN/root) | nftables: LAN, IPv6, kill-switch, NAT a Tor (`meta skuid` del usuario `tor`) |

La lógica de la GUI es la de InviZible: **marcas módulos y pulsas INICIAR**. No arrancan al marcar la casilla. **Cerrar la ventana no detiene los módulos**; usa DETENER o **Salir**. Si no hay icono de bandeja, al cerrar llega una notificación del sistema.

Si activas cortafuegos o modo sistema, **un solo pkexec** aplica nft, DNS e IPv6. Si lo cancelas, **no se arrancan módulos** (fallo cerrado).

## Ajustes (como en la APK)

La barra inferior replica el menú de InviZible Lite:

- **Rápidos**: perfil Casa/Censura/Máximo, autostart, DNS, todo el tráfico por Tor, sitios (PAC), LAN, WiFi de confianza, PAC en Firefox, puentes Snowflake, bandeja, tema
- **Comunes**: modo superusuario (`tor.service` + nftables), SOCKS5 de salida, kill-switch, DHCP/NTP/portal cautivo
- **DNSCrypt**: puerto, DoH/ODoH, DNSSEC, no-log, no-filtro, TCP, proxy, DNS64, listas
- **Tor**: nodos, padding, TransPort/SOCKS/DNS, aislamiento, Snowflake, ControlPort
- **I2P**: ancho de banda, HTTP/SOCKS, SAM, UPnP, resiembra
- **Cortafuegos**: LAN, onion/i2p, IPv6 (nft + sysctl), kill-switch, HTTP, STUN/mDNS/LLMNR

Las opciones solo de Android (tethering, BusyBox, wakelock, ARP, multi-usuario) no se incluyen.

Al pulsar INICIAR se regeneran `dnscrypt-proxy.toml`, `torrc`, `tor-sites.pac` e `i2pd.conf` en `~/.config/invizible-linux/`.

## Requisitos

Arch (instalador completo: panel, dependencias, lyrebird y oniux):

```bash
./install.sh
# o
cd aur && ./install-arch.sh
```

Ejecuta el instalador como usuario, sin `sudo`; solo se elevará para instalar paquetes del sistema.

El instalador usa `pacman` para lo que está en extra, compila **lyrebird** con Go (el AUR `lyrebird-proxy-git` está roto) e instala **oniux** desde AUR o cargo. Si pacman exige firma en paquetes locales, no cambia `/etc/pacman.conf`: solo esa instalación admite el `.pkg` sin `.sig`.

Paquetes a mano:

```bash
sudo pacman -S --needed gtk4 libadwaita python-gobject python-cairo tor dnscrypt-proxy i2pd polkit nftables torsocks go rust git
```

Debian / Ubuntu (12 / 22.04 o posterior, GTK4 + libadwaita):

```bash
sudo apt update
sudo apt install python3-gi python3-gi-cairo python3-cairo gir1.2-gtk-4.0 gir1.2-adw-1 \
  tor dnscrypt-proxy i2pd nftables pkexec
# recomendado (en stable puede no existir lyrebird)
sudo apt install torsocks
sudo apt install lyrebird || sudo apt install obfs4proxy
sudo apt install snowflake-client || true
```

## Uso

```bash
./invizible-linux
# o
./install.sh
invizible-linux
```

Paquete Arch (solo el `.pkg` si ya corriste `makepkg`):

```bash
cd aur && ./install-local.sh
```

`makepkg -si` falla si pacman tiene `LocalFileSigLevel = Required` (el paquete local no lleva `.sig`). `install-local.sh` no cambia `/etc/pacman.conf`: solo esa instalación admite el archivo local sin firma. Si prefieres cumplir la política, firma con `makepkg --sign` y añade la clave a `pacman-key`.

Paquete Debian:

```bash
sudo apt install dpkg-dev debhelper
./packaging/build-deb.sh
sudo apt install ../invizible-linux_*.deb
```

Instala también el helper de polkit en `/usr/lib/invizible-linux/helper`.

### Modo proxy (por defecto)

- Tor: SOCKS5 `127.0.0.1:9050`
- I2P: HTTP `127.0.0.1:4444`
- DNS: `127.0.0.1:5354`
- PAC de sitios: `~/.config/invizible-linux/tor-sites.pac`. El navegador **no** lo carga solo: en Inicio, **Copiar URL del PAC** y pégala en Firefox → Red → URL de configuración automática.

### Modo sistema

En Comunes activa **Ejecutar módulos como superusuario**. Al iniciar:

- escribe un drop-in de `torrc` y arranca **`tor.service`** (usuario `tor`)
- nftables exime `meta skuid <uid de tor>` y redirige el resto a TransPort
- bloquea IPv6 (nftables + sysctl)
- cambia el DNS global

Al pulsar DETENER se revierten DNS, nftables, IPv6 y se para `tor.service` si lo arrancó esta app.

## Aplicaciones por Tor

Pestaña **Apps**. Cada app tiene: **Normal**, **Tor estricto** (oniux), **Tor laxo** (SOCKS con aislamiento) o **Directo**.

Al pulsar **Iniciar** se crean `invizible-tor-*.desktop` (estricto) e `invizible-lax-*.desktop` (laxo).

En **Inicio → Opciones rápidas** hay perfiles **Casa / Censura / Máximo** y **Nuevo circuito Tor** (SIGNAL NEWNYM).

En linux-hardened: **Activar namespaces de usuario**, o usa Tor laxo.

## Puentes

Por defecto intenta **Snowflake**. Si no hay cliente, Tor arranca **sin puentes** (no se queda colgado) y aparece **Instalar lyrebird**. En Arch no uses `lyrebird-proxy-git` del AUR (el PKGBUILD instala `lyrepird` y falla): pulsa el botón o `go install gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/cmd/lyrebird@latest`. En Debian: `sudo apt install lyrebird` o `obfs4proxy`. Pega puentes propios en modo lista propia.

## Pruebas de fugas

Pestaña **Fugas** (con los módulos en marcha):

- IP directa y salida Tor por SOCKS
- Salida oniux (si está disponible)
- IPv6, DNS, STUN, `resolv.conf`

Informes en `~/.local/share/invizible-linux/leak-reports/`.

## Pruebas

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Archivos

- Configuración: `~/.config/invizible-linux/`
- Registros: `~/.local/share/invizible-linux/logs/`
- Candado de privilegios: `$XDG_RUNTIME_DIR/invizible-linux/privileged.lock`
