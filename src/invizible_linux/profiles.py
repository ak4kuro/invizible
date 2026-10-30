from __future__ import annotations

import configparser
import json
import socket
import subprocess
from pathlib import Path
from typing import Any

from .config import DATA_HOME, lines_of

PROFILES: dict[str, dict[str, Any]] = {
    "home": {
        "system_mode": False,
        "firewall": False,
        "kill_switch": False,
        "route_all_tor": False,
        "block_ipv6": False,
        "tor_bridges_mode": "none",
        "allow_lan": True,
        "fascist_firewall": False,
        "force_tcp": False,
    },
    "censorship": {
        "system_mode": False,
        "firewall": False,
        "kill_switch": False,
        "route_all_tor": False,
        "tor_bridges_mode": "default",
        "fascist_firewall": True,
        "force_tcp": True,
        "allow_lan": True,
    },
    "max": {
        "system_mode": True,
        "firewall": True,
        "kill_switch": True,
        "route_all_tor": True,
        "block_ipv6": True,
        "block_stun": True,
        "block_mdns": True,
        "block_llmnr": True,
        "prevent_dns_leak": True,
        "allow_lan": False,
        "tor_bridges_mode": "default",
        "ks_allow_dhcp": True,
        "ks_allow_ntp": True,
        "ks_allow_captive": True,
    },
}


def apply_profile(settings: dict[str, Any], name: str) -> None:
    blob = PROFILES.get(name) or PROFILES["home"]
    settings["usage_profile"] = name if name in PROFILES else "home"
    settings.update(blob)


def current_ssid() -> str:
    try:
        proc = subprocess.run(
            ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        proc = None
    if proc and proc.returncode == 0:
        for line in (proc.stdout or "").splitlines():
            if line.startswith("yes:"):
                return line.split(":", 1)[-1]
    try:
        proc = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True, timeout=2)
        if proc.returncode == 0:
            return (proc.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ""


def effective_allow_lan(settings: dict[str, Any], ssid: str | None = None) -> bool:
    allow = bool(settings.get("allow_lan"))
    if not settings.get("block_lan_free_wifi"):
        return allow
    if ssid is None:
        ssid = current_ssid()
    if not ssid:
        return allow
    trusted = set(lines_of(str(settings.get("trusted_wifi") or "")))
    return ssid in trusted


def newnym(*, control_port: int = 9051, cookie: Path | None = None) -> str:
    sock = socket.create_connection(("127.0.0.1", control_port), timeout=3)
    sock.settimeout(3)
    try:
        # El ControlPort de Tor no envía saludo; hay que mandar AUTHENTICATE primero.
        if cookie and cookie.is_file():
            hexed = cookie.read_bytes().hex().encode()
            sock.sendall(b"AUTHENTICATE " + hexed + b"\r\n")
        else:
            sock.sendall(b"AUTHENTICATE\r\n")
        reply = sock.recv(256)
        if b"250" not in reply:
            raise RuntimeError("ControlPort rechazó AUTHENTICATE: " + reply.decode("utf-8", errors="replace")[:120])
        sock.sendall(b"SIGNAL NEWNYM\r\n")
        reply = sock.recv(256)
        if b"250" not in reply:
            raise RuntimeError("NEWNYM falló: " + reply.decode("utf-8", errors="replace")[:120])
        return "Circuito nuevo pedido."
    finally:
        sock.close()


def cookie_path() -> Path:
    return DATA_HOME / "tor" / "control_auth_cookie"


_PAC_BEGIN = "// BEGIN INVIZIBLE-LINUX PAC"
_PAC_END = "// END INVIZIBLE-LINUX PAC"


def _mozilla_profiles(root: Path) -> list[Path]:
    profiles: list[Path] = []
    ini = root / "profiles.ini"
    parser = configparser.ConfigParser()
    if ini.is_file():
        try:
            parser.read(ini, encoding="utf-8")
        except configparser.Error:
            parser.clear()
    for section in parser.sections():
        raw = parser.get(section, "Path", fallback="")
        if not raw:
            continue
        profile = Path(raw).expanduser()
        if parser.getboolean(section, "IsRelative", fallback=True):
            profile = root / profile
        if profile.is_dir():
            profiles.append(profile)
    if root.is_dir():
        profiles.extend(path for path in root.iterdir() if path.is_dir() and (path / "prefs.js").is_file())
    return list(dict.fromkeys(profiles))


def _write_pac_user_js(path: Path, enabled: bool, pac_url: str) -> bool:
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    start = text.find(_PAC_BEGIN)
    if start >= 0:
        end = text.find(_PAC_END, start)
        end = len(text) if end < 0 else end + len(_PAC_END)
        text = (text[:start].rstrip() + "\n" + text[end:].lstrip("\n")).strip("\n")
    if enabled:
        block = (
            f"{_PAC_BEGIN}\n"
            'user_pref("network.proxy.type", 2);\n'
            f'user_pref("network.proxy.autoconfig_url", {json.dumps(pac_url)});\n'
            'user_pref("network.proxy.socks_remote_dns", true);\n'
            f"{_PAC_END}\n"
        )
        text = (text.rstrip("\n") + "\n" + block) if text else block
    if path.is_file() and path.read_text(encoding="utf-8") == text:
        return False
    path.write_text(text, encoding="utf-8")
    return True


def apply_firefox_pac(enabled: bool, pac_url: str) -> Path | None:
    roots = (Path.home() / ".mozilla" / "firefox", Path.home() / ".librewolf")
    first: Path | None = None
    for root in roots:
        for profile in _mozilla_profiles(root):
            user_js = profile / "user.js"
            if _write_pac_user_js(user_js, enabled, pac_url) and first is None:
                first = user_js
    return first


def firefox_pac_status(settings: dict[str, Any]) -> str:
    if not settings.get("firefox_pac"):
        return "Navegador: SOCKS manual"
    pending = False
    for root in (Path.home() / ".mozilla" / "firefox", Path.home() / ".librewolf"):
        for profile in _mozilla_profiles(root):
            try:
                if 'network.proxy.type", 2' in (profile / "prefs.js").read_text(encoding="utf-8", errors="replace"):
                    return "Navegador: Tor (PAC)"
            except OSError:
                pass
            try:
                if "tor-sites.pac" in (profile / "user.js").read_text(encoding="utf-8", errors="replace"):
                    pending = True
            except OSError:
                pass
    return "Navegador: PAC pendiente (reinicia Firefox)" if pending else "Navegador: PAC no escrito"
