from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .config import CONFIG_DIR, lines_of


def pac_text(settings: dict[str, Any]) -> str:
    socks = settings.get("socks_port") or "9050"
    i2p_port = settings.get("i2p_http_port") or "4444"
    unlock = lines_of(settings.get("tor_sites_unlock") or "")
    exclude = lines_of(settings.get("tor_sites_exclude") or "")
    route_all = bool(settings.get("route_all_tor"))
    onion_result = "PROXY" if settings.get("fw_allow_onion", True) else '"DIRECT"'
    i2p_result = f'"PROXY 127.0.0.1:{i2p_port}"' if settings.get("i2p") and settings.get("fw_allow_i2p", True) else '"DIRECT"'
    checks_unlock = []
    for host in unlock:
        host = host.lstrip(".")
        checks_unlock.append(f'    if (dnsDomainIs(host, "{host}") || shExpMatch(host, "*.{host}")) return PROXY;')
    checks_excl = []
    for host in exclude:
        host = host.lstrip(".")
        checks_excl.append(f'    if (dnsDomainIs(host, "{host}") || shExpMatch(host, "*.{host}")) return "DIRECT";')
    default = "PROXY" if route_all else "DIRECT"
    return f"""function FindProxyForURL(url, host) {{
    var PROXY = "SOCKS5 127.0.0.1:{socks}";
    if (shExpMatch(host, "*.onion") || shExpMatch(host, "*.onion.")) return {onion_result};
    if (shExpMatch(host, "*.i2p") || shExpMatch(host, "*.i2p.")) return {i2p_result};
    if (isPlainHostName(host) || dnsDomainIs(host, "localhost")) return "DIRECT";
    if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
    if (isInNet(host, "192.168.0.0", "255.255.0.0")) return "DIRECT";
    if (isInNet(host, "172.16.0.0", "255.240.0.0")) return "DIRECT";
{chr(10).join(checks_excl)}
{chr(10).join(checks_unlock)}
    return {default};
}}
"""


def pac_file_url() -> str:
    return (CONFIG_DIR / "tor-sites.pac").resolve().as_uri()


def write_pac(settings: dict[str, Any]) -> Path:
    dest = CONFIG_DIR / "tor-sites.pac"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(pac_text(settings), encoding="utf-8")
    return dest


def _safe_id(app_id: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in app_id)[:80]


def sync_desktop_launchers(settings: dict[str, Any], runner: Path) -> list[Path]:
    apps_dir = Path.home() / ".local/share/applications"
    apps_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    existing = list(apps_dir.glob("invizible-tor-*.desktop"))
    keep = set()
    for app_id in settings.get("oniux_tor_apps") or []:
        slug = _safe_id(str(app_id).removesuffix(".desktop"))
        path = apps_dir / f"invizible-tor-{slug}.desktop"
        name = str(app_id).removesuffix(".desktop")
        path.write_text(
            "[Desktop Entry]\n"
            "Type=Application\n"
            f"Name={name} (Tor)\n"
            f"Comment=Lanzado por InviZible Linux a través de Tor\n"
            f"Exec={runner} --tor-strict \"{app_id}\"\n"
            "Terminal=false\n"
            "Categories=Network;Security;\n"
            "StartupNotify=true\n",
            encoding="utf-8",
        )
        written.append(path)
        keep.add(path)
    for app_id in settings.get("oniux_lax_apps") or []:
        slug = _safe_id(str(app_id).removesuffix(".desktop"))
        path = apps_dir / f"invizible-lax-{slug}.desktop"
        name = str(app_id).removesuffix(".desktop")
        path.write_text(
            "[Desktop Entry]\n"
            "Type=Application\n"
            f"Name={name} (Tor laxo)\n"
            f"Comment=SOCKS Tor con aislamiento por app (puede fugar)\n"
            f"Exec={runner} --tor-lax \"{app_id}\"\n"
            "Terminal=false\n"
            "Categories=Network;Security;\n"
            "StartupNotify=true\n",
            encoding="utf-8",
        )
        written.append(path)
        keep.add(path)
    for app_id in settings.get("oniux_clear_apps") or []:
        slug = _safe_id(str(app_id).removesuffix(".desktop"))
        path = apps_dir / f"invizible-direct-{slug}.desktop"
        name = str(app_id).removesuffix(".desktop")
        path.write_text(
            "[Desktop Entry]\n"
            "Type=Application\n"
            f"Name={name} (Directo)\n"
            f"Comment=Lanzado por InviZible Linux sin Tor\n"
            f"Exec={runner} --direct \"{app_id}\"\n"
            "Terminal=false\n"
            "Categories=Network;\n"
            "StartupNotify=true\n",
            encoding="utf-8",
        )
        written.append(path)
        keep.add(path)
    for old in existing + list(apps_dir.glob("invizible-direct-*.desktop")) + list(apps_dir.glob("invizible-lax-*.desktop")):
        if old not in keep:
            old.unlink(missing_ok=True)
    return written


def runner_path() -> Path:
    found = shutil.which("invizible-run")
    if found:
        return Path(found)
    from .config import PROJECT_ROOT

    return PROJECT_ROOT / "scripts" / "invizible-run"
