from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

APP_ID = "net.invizible.Linux"
APP_NAME = "InviZible Linux"
APP_VERSION = "0.7.0"

_mod_dir = Path(__file__).resolve().parent
if (_mod_dir.parent / "data").is_dir():
    PROJECT_ROOT = _mod_dir.parent
else:
    PROJECT_ROOT = _mod_dir.parents[1]
DATA_DIR = PROJECT_ROOT / "data"
TEMPLATES_DIR = _mod_dir / "templates"

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "invizible-linux"
DATA_HOME = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "invizible-linux"
RUNTIME_DIR = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "invizible-linux"
LOG_DIR = DATA_HOME / "logs"
LEAK_REPORT_DIR = DATA_HOME / "leak-reports"
PRIV_LOCK = RUNTIME_DIR / "privileged.lock"
ROOT_LOCK = Path("/run/invizible-linux.lock")
SYSTEM_TOR_FLAG = Path("/run/invizible-linux.system-tor")
SETTINGS_PATH = CONFIG_DIR / "settings.json"
AUTOSTART_PATH = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "autostart" / "net.invizible.Linux.desktop"
# tor.service (ProtectSystem) no puede escribir en /run. Solo syslog (y /var/lib/tor).
SYSTEM_TOR_LOG = Path("/var/log/invizible-tor-notice.log")

DNS_PRESETS: dict[str, list[str]] = {
    "dns_cloudflare": ["cloudflare", "cloudflare-ipv4"],
    "dns_quad9": ["quad9-dnscrypt-ip4-filter-pri", "quad9-dnscrypt-ip4-nofilter-pri"],
    "dns_mullvad": ["mullvad-doh"],
    "dns_adguard": ["adguard-dns-doh"],
}

# Claves alineadas con InviZible Lite/Pro (APK 7.5).
DEFAULT_SETTINGS: dict[str, Any] = {
    # Módulos de la pantalla principal
    "dns": True,
    "tor": True,
    "i2p": False,
    "firewall": False,
    "system_mode": False,
    # Ajustes rápidos
    "sw_autostart_dns": False,
    "sw_autostart_tor": False,
    "sw_autostart_itpd": False,
    "autostart_delay": "0",
    "dns_server_names": "cloudflare, cloudflare-ipv4",
    "dns_server_extra": "",
    "prevent_dns_leak": True,
    "route_all_tor": True,
    "tor_sites_unlock": "",
    "tor_apps_unlock": "",
    "tor_sites_exclude": "",
    "tor_apps_exclude": "",
    "hide_to_tray": True,
    "dns_cloudflare": True,
    "dns_quad9": False,
    "dns_mullvad": False,
    "dns_adguard": False,
    "oniux_tor_apps": [],
    "oniux_clear_apps": [],
    "show_all_apps": False,
    "site_refresh_interval": "12",
    "allow_lan": True,
    "tor_bridges_mode": "default",
    "tor_bridges": "",
    "exclude_udp": False,
    "fake_sni": False,
    "auto_update": True,
    "through_tor_update": False,
    "logs_realtime": True,
    "block_lan_free_wifi": True,
    "block_http": False,
    "theme": "night",
    "anonymized_relays": False,
    "relay_names": "anon-cs-fr, anon-cs-se",
    # Comunes
    "use_socks5_proxy": False,
    "socks5_address": "127.0.0.1:1080",
    "kill_switch": False,
    "refresh_rules": False,
    "dns_rebind_protection": True,
    "show_help": True,
    # DNSCrypt
    "listen_port": "5354",
    "dnscrypt_servers": True,
    "doh_servers": True,
    "odoh_servers": False,
    "ipv4_servers": True,
    "ipv6_servers": False,
    "require_dnssec": True,
    "require_nolog": True,
    "require_nofilter": False,
    "force_tcp": False,
    "enable_dnscrypt_proxy": False,
    "dnscrypt_proxy_port": "9050",
    "bootstrap_resolvers": "9.9.9.9, 8.8.8.8",
    "ignore_system_dns": True,
    "http3": True,
    "dns64": False,
    "dns64_prefix": "64:ff9b::/96",
    "block_unqualified": True,
    "block_undelegated": True,
    "block_ipv6": True,
    "blacklist": "",
    "whitelist": "",
    "ipblacklist": "",
    "forwarding_rules": "",
    "cloaking_rules": "",
    "refresh_delay_rules": "72",
    "enable_query_log": False,
    "ignored_qtypes": "DNSKEY, NS",
    "enable_nx_log": False,
    "dnscrypt_sources": (
        "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md\n"
        "https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md"
    ),
    "refresh_delay": "72",
    "dnscrypt_relays": (
        "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md\n"
        "https://download.dnscrypt.info/resolvers-list/v3/relays.md"
    ),
    "refresh_delay_relays": "72",
    # Tor
    "exclude_exit_nodes": False,
    "exit_nodes": False,
    "exclude_nodes": False,
    "entry_nodes": False,
    "strict_nodes": False,
    "exit_nodes_list": "",
    "entry_nodes_list": "",
    "exclude_nodes_list": "",
    "exclude_exit_nodes_list": "",
    "virtual_addr_network": "10.192.0.0/10",
    "hardware_accel": True,
    "avoid_disk_writes": True,
    "connection_padding": True,
    "reduced_connection_padding": True,
    "fascist_firewall": False,
    "new_circuit_period": "30",
    "max_circuit_dirtiness": "600",
    "dormant_client_timeout": "15",
    "enforce_distinct_subnets": True,
    "track_host_exits": False,
    "client_use_ipv4": True,
    "client_use_ipv6": False,
    "isolate_uid": True,
    "isolate_dest_address": True,
    "isolate_dest_port": True,
    "enable_socks_proxy": True,
    "socks_port": "9050",
    "enable_http_tunnel": False,
    "http_tunnel_port": "8118",
    "enable_transparent_proxy": True,
    "trans_port": "9040",
    "enable_tor_dns": True,
    "tor_dns_port": "5353",
    "snowflake_rendezvous": "amp",
    "snowflake_stun": "",
    "enable_socks_output": False,
    "socks5_output": "127.0.0.1:1080",
    # I2P
    "i2p_ipv4": True,
    "i2p_ipv6": False,
    "i2p_notransit": False,
    "i2p_floodfill": False,
    "i2p_bandwidth": "L",
    "i2p_share": "20",
    "i2p_ssu2": True,
    "i2p_ntcp2": True,
    "i2p_http_proxy": True,
    "i2p_http_port": "4444",
    "i2p_http_outproxy": False,
    "i2p_http_outproxy_address": "http://false.i2p",
    "i2p_socks_proxy": True,
    "i2p_socks_port": "4447",
    "i2p_socks_outproxy": False,
    "i2p_socks_outproxy_address": "127.0.0.1",
    "i2p_socks_outproxy_port": "9050",
    "i2p_ntcpproxy_enabled": False,
    "i2p_ntcpproxy": "socks://127.0.0.1:9050",
    "i2p_incoming": False,
    "i2p_incoming_host": "0.0.0.0",
    "i2p_incoming_port": "4567",
    "i2p_sam": False,
    "i2p_sam_port": "7656",
    "i2p_elgamal": True,
    "i2p_upnp": False,
    "i2p_reseed_verify": True,
    "i2p_transittunnels": "10",
    "i2p_openfiles": "500",
    "i2p_coresize": "0",
    "i2p_addressbook_url": "http://shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p/hosts.txt",
    "i2p_subscriptions": "",
    # Cortafuegos
    "fw_allow_onion": True,
    "fw_allow_i2p": True,
    "fw_allow_new_apps": False,
    "usage_profile": "home",
    "block_stun": True,
    "block_mdns": True,
    "block_llmnr": True,
    "ks_allow_dhcp": True,
    "ks_allow_ntp": True,
    "ks_allow_captive": True,
    "trusted_wifi": "",
    "firefox_pac": False,
    "oniux_lax_apps": [],
    "control_port": "9051",
}


def compose_dns_servers(settings: dict[str, Any]) -> str:
    names: list[str] = []
    seen: set[str] = set()
    for key, preset in DNS_PRESETS.items():
        if settings.get(key):
            for item in preset:
                if item not in seen:
                    seen.add(item)
                    names.append(item)
    for item in lines_of(str(settings.get("dns_server_extra") or "")):
        if item not in seen:
            seen.add(item)
            names.append(item)
    if not names:
        names = list(DNS_PRESETS["dns_cloudflare"])
    settings["dns_server_names"] = ", ".join(names)
    return settings["dns_server_names"]


def ensure_dirs() -> None:
    for path in (CONFIG_DIR, DATA_HOME, RUNTIME_DIR, LOG_DIR, LEAK_REPORT_DIR, CONFIG_DIR / "filters"):
        path.mkdir(parents=True, exist_ok=True)
    for path in (CONFIG_DIR, DATA_HOME, LOG_DIR, LEAK_REPORT_DIR):
        try:
            # Claves de Tor y registros DNS no deben ser legibles por otros usuarios.
            path.chmod(0o700)
        except OSError:
            pass


def load_settings() -> dict[str, Any]:
    ensure_dirs()
    if not SETTINGS_PATH.exists():
        save_settings(DEFAULT_SETTINGS.copy())
        return DEFAULT_SETTINGS.copy()
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return DEFAULT_SETTINGS.copy()
    merged = DEFAULT_SETTINGS.copy()
    for key, value in data.items():
        if key in DEFAULT_SETTINGS:
            merged[key] = value
    # compatibilidad con la primera versión
    if "dns_provider" in data and not data.get("dns_server_names"):
        mapping = {
            "cloudflare": "cloudflare, cloudflare-ipv4",
            "quad9": "quad9-dnscrypt-ip4-filter-pri, quad9-dnscrypt-ip4-nofilter-pri",
            "mullvad": "mullvad-doh",
        }
        merged["dns_server_names"] = mapping.get(str(data["dns_provider"]), merged["dns_server_names"])
    if "autostart" in data and data["autostart"]:
        merged["sw_autostart_dns"] = True
        merged["sw_autostart_tor"] = True
    if isinstance(merged.get("oniux_tor_apps"), str):
        merged["oniux_tor_apps"] = lines_of(merged["oniux_tor_apps"])
    if isinstance(merged.get("oniux_clear_apps"), str):
        merged["oniux_clear_apps"] = lines_of(merged["oniux_clear_apps"])
    if isinstance(merged.get("oniux_lax_apps"), str):
        merged["oniux_lax_apps"] = lines_of(merged["oniux_lax_apps"])
    if not merged.get("oniux_tor_apps") and merged.get("tor_apps_unlock"):
        merged["oniux_tor_apps"] = lines_of(str(merged["tor_apps_unlock"]))
    if "dns_cloudflare" not in data:
        names = {x.strip() for x in str(merged.get("dns_server_names") or "").split(",") if x.strip()}
        preset_all = {n for preset in DNS_PRESETS.values() for n in preset}
        for key, preset in DNS_PRESETS.items():
            merged[key] = any(item in names for item in preset)
        extra = [n for n in names if n not in preset_all]
        if extra:
            merged["dns_server_extra"] = ", ".join(extra)
    compose_dns_servers(merged)
    return merged


def save_settings(settings: dict[str, Any]) -> None:
    ensure_dirs()
    payload = DEFAULT_SETTINGS.copy()
    payload.update({k: v for k, v in settings.items() if k in DEFAULT_SETTINGS})
    for key in [k for k in payload if k.endswith("_port")]:
        try:
            port = int(str(payload[key]))
            if not 0 < port < 65536:
                raise ValueError
            payload[key] = str(port)
        except (TypeError, ValueError):
            payload[key] = str(DEFAULT_SETTINGS[key])
    compose_dns_servers(payload)
    settings["dns_server_names"] = payload["dns_server_names"]
    SETTINGS_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def lines_of(value: str) -> list[str]:
    items = []
    for raw in (value or "").replace(",", "\n").splitlines():
        item = raw.strip()
        if item and not item.startswith("#"):
            items.append(item)
    return items


def toml_bool(value: Any) -> str:
    return "true" if bool(value) else "false"


def toml_list(values: list[str]) -> str:
    inner = ", ".join("'" + v.replace("'", "") + "'" for v in values if v)
    return f"[{inner}]" if inner else "[]"
