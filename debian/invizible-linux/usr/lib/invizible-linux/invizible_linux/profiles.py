from __future__ import annotations

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


def apply_firefox_pac(enabled: bool, pac_url: str) -> Path | None:
    dest = Path.home() / ".mozilla" / "firefox" / "policies" / "policies.json"
    if not enabled and not dest.exists():
        return None
    dest.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {}
    if dest.exists():
        try:
            data = json.loads(dest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
    policies = data.setdefault("policies", {})
    if not isinstance(policies, dict):
        policies = {}
        data["policies"] = policies
    if enabled:
        policies["Proxy"] = {
            "Mode": "autoConfig",
            "AutoConfigURL": pac_url,
            "Locked": False,
        }
    else:
        proxy = policies.get("Proxy")
        if isinstance(proxy, dict) and proxy.get("AutoConfigURL") == pac_url:
            policies.pop("Proxy", None)
    dest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    librewolf = Path.home() / ".librewolf" / "policies" / "policies.json"
    if librewolf.parent.parent.is_dir():
        librewolf.parent.mkdir(parents=True, exist_ok=True)
        librewolf.write_text(dest.read_text(encoding="utf-8"), encoding="utf-8")
    return dest
