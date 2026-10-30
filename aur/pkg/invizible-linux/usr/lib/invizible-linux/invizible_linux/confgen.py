from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .config import CONFIG_DIR, DATA_HOME, LOG_DIR, SYSTEM_TOR_LOG, lines_of, toml_bool, toml_list

DEFAULT_SNOWFLAKE = [
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.shazam.com,www.arcticgis.com,www.audible.com,www.goldenfrog.com,www.opera.com ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:443,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:3478 utls-imitate=hellorandomizedalpn",
    "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=www.shazam.com,www.arcticgis.com,www.audible.com,www.goldenfrog.com,www.opera.com ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:443,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:3478 utls-imitate=hellorandomizedalpn",
]


def find_pt(*names: str) -> str | None:
    from .distro import which_bin

    found = which_bin(*names)
    if found:
        return found
    candidates = []
    for name in names:
        candidates.extend(
            [
                Path("/usr/bin") / name,
                Path("/usr/sbin") / name,
                Path("/usr/lib/snowflake") / name,
                Path("/usr/lib/lyrebird") / name,
                Path("/usr/lib/obfs4proxy") / name,
                Path.home() / ".cargo" / "bin" / name,
            ]
        )
    for cand in candidates:
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return None


def resolve_bridges(settings: dict[str, Any]) -> tuple[str, list[str], str]:
    """Devuelve (modo efectivo, líneas de puente, aviso). Sin plugin no se fuerzan puentes."""
    requested = settings.get("tor_bridges_mode") or "none"
    if requested == "none":
        return "none", [], ""
    if requested == "default":
        if find_pt("snowflake-client", "snowflake"):
            return "default", list(DEFAULT_SNOWFLAKE), ""
        return (
            "none",
            [],
            "Snowflake no está instalado; Tor arranca sin puentes. Instala snowflake o usa lyrebird con puentes propios.",
        )
    bridges = lines_of(settings.get("tor_bridges") or "")
    if not bridges:
        return "none", [], "No hay puentes pegados; Tor arranca sin ofuscación."
    kinds = {bridge.split()[0] for bridge in bridges if bridge.split()}
    missing: list[str] = []
    if "obfs4" in kinds and not find_pt("lyrebird", "obfs4proxy"):
        missing.append("lyrebird/obfs4proxy")
    if "snowflake" in kinds and not find_pt("snowflake-client", "snowflake"):
        missing.append("snowflake")
    if ("meek_lite" in kinds or "meek" in kinds) and not find_pt("lyrebird", "obfs4proxy", "meek-client"):
        missing.append("lyrebird (meek)")
    if missing:
        return "none", [], f"Falta {', '.join(missing)}; Tor arranca sin puentes para no quedar colgado."
    return "own", bridges, ""


def _append_bridges(lines: list[str], settings: dict[str, Any]) -> str:
    mode, bridges, warning = resolve_bridges(settings)
    if mode == "none" or not bridges:
        return warning
    lines.append("UseBridges 1")
    kinds = {bridge.split()[0] for bridge in bridges if bridge.split()}
    if "obfs4" in kinds:
        pt = find_pt("lyrebird", "obfs4proxy")
        if pt:
            lines.append(f"ClientTransportPlugin obfs4 exec {pt}")
    if "snowflake" in kinds:
        pt = find_pt("snowflake-client", "snowflake")
        extra = ""
        if settings.get("snowflake_stun"):
            extra = f" -ice {settings['snowflake_stun']}"
        if pt:
            lines.append(f"ClientTransportPlugin snowflake exec {pt}{extra}")
    if "meek_lite" in kinds or "meek" in kinds:
        pt = find_pt("lyrebird", "obfs4proxy", "meek-client")
        if pt:
            lines.append(f"ClientTransportPlugin meek_lite exec {pt}")
    for bridge in bridges:
        lines.append(f"Bridge {bridge}")
    return warning


def _csv_names(value: str) -> list[str]:
    return [x.strip() for x in value.replace("\n", ",").split(",") if x.strip()]


def write_dnscrypt_toml(settings: dict[str, Any], logfile: Path) -> Path:
    port = settings.get("listen_port") or "5354"
    servers = _csv_names(settings.get("dns_server_names") or "cloudflare")
    sources = lines_of(settings.get("dnscrypt_sources") or "")
    relays = lines_of(settings.get("dnscrypt_relays") or "")
    bootstrap = _csv_names(settings.get("bootstrap_resolvers") or "9.9.9.9")
    qtypes = _csv_names(settings.get("ignored_qtypes") or "")
    filters = CONFIG_DIR / "filters"
    filters.mkdir(parents=True, exist_ok=True)

    def dump_list(key: str, filename: str) -> Path | None:
        rows = lines_of(settings.get(key) or "")
        path = filters / filename
        if rows:
            path.write_text("\n".join(rows) + "\n", encoding="utf-8")
            return path
        path.write_text("", encoding="utf-8")
        return path if rows else None

    blacklist = dump_list("blacklist", "blacklist.txt")
    whitelist = dump_list("whitelist", "whitelist.txt")
    ipbl = dump_list("ipblacklist", "ipblacklist.txt")
    forwarding = dump_list("forwarding_rules", "forwarding.txt")
    cloaking = dump_list("cloaking_rules", "cloaking.txt")

    proxy_block = ""
    if settings.get("enable_dnscrypt_proxy") or settings.get("use_socks5_proxy"):
        addr = settings.get("socks5_address") or "127.0.0.1:9050"
        if settings.get("enable_dnscrypt_proxy") and not settings.get("use_socks5_proxy"):
            addr = f"127.0.0.1:{settings.get('dnscrypt_proxy_port') or '9050'}"
        proxy_block = f"proxy = 'socks5://{addr}'\n"

    query = ""
    if settings.get("enable_query_log"):
        query = f"""
[query_log]
  file = '{LOG_DIR / "dnscrypt-query.log"}'
  ignored_qtypes = {toml_list(qtypes)}
"""
    nx = ""
    if settings.get("enable_nx_log"):
        nx = f"""
[nx_log]
  file = '{LOG_DIR / "dnscrypt-nx.log"}'
"""

    blocked = ""
    if blacklist and lines_of(settings.get("blacklist") or ""):
        blocked += f"blocked_names_file = '{blacklist}'\n"
    if whitelist and lines_of(settings.get("whitelist") or ""):
        blocked += f"allowed_names_file = '{whitelist}'\n"
    if ipbl and lines_of(settings.get("ipblacklist") or ""):
        blocked += f"blocked_ips_file = '{ipbl}'\n"
    if forwarding and lines_of(settings.get("forwarding_rules") or ""):
        blocked += f"forwarding_rules = '{forwarding}'\n"
    if cloaking and lines_of(settings.get("cloaking_rules") or ""):
        blocked += f"cloaking_rules = '{cloaking}'\n"

    anon = ""
    if settings.get("anonymized_relays"):
        vias = _csv_names(settings.get("relay_names") or "")
        if vias:
            via = toml_list(vias)
            anon = f"""
[anonymized_dns]
  skip_incompatible = true
  routes = [{{ server_name='*', via={via} }}]
"""

    dns64 = ""
    if settings.get("dns64"):
        dns64 = f"""
[dns64]
  prefix = ['{settings.get("dns64_prefix") or "64:ff9b::/96"}']
"""

    src_urls = ",\n      ".join(f"'{u}'" for u in sources) or (
        "'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md'"
    )
    relay_urls = ",\n      ".join(f"'{u}'" for u in relays) or (
        "'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md'"
    )
    delay = settings.get("refresh_delay") or "72"
    delay_r = settings.get("refresh_delay_relays") or "72"

    text = f"""# Generado por InviZible Linux a partir de los ajustes tipo APK.
listen_addresses = ['127.0.0.1:{port}']
server_names = {toml_list(servers)}
max_clients = 250
ipv4_servers = {toml_bool(settings.get("ipv4_servers"))}
ipv6_servers = {toml_bool(settings.get("ipv6_servers"))}
dnscrypt_servers = {toml_bool(settings.get("dnscrypt_servers"))}
doh_servers = {toml_bool(settings.get("doh_servers"))}
odoh_servers = {toml_bool(settings.get("odoh_servers"))}
require_dnssec = {toml_bool(settings.get("require_dnssec"))}
require_nolog = {toml_bool(settings.get("require_nolog"))}
require_nofilter = {toml_bool(settings.get("require_nofilter"))}
force_tcp = {toml_bool(settings.get("force_tcp"))}
timeout = 5000
keepalive = 30
http3 = {toml_bool(settings.get("http3"))}
ignore_system_dns = {toml_bool(settings.get("ignore_system_dns"))}
bootstrap_resolvers = {toml_list(bootstrap)}
lb_strategy = 'p2c'
lb_estimator = true
block_ipv6 = {toml_bool(settings.get("block_ipv6"))}
block_unqualified = {toml_bool(settings.get("block_unqualified"))}
block_undelegated = {toml_bool(settings.get("block_undelegated"))}
reject_ttl = 600
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400
netprobe_timeout = 60
log_file = '{logfile}'
log_level = 2
use_syslog = false
{proxy_block}{blocked}{query}{nx}{dns64}{anon}
[sources]
  [sources.public-resolvers]
    urls = [
      {src_urls}
    ]
    cache_file = '{DATA_HOME / "public-resolvers.md"}'
    minisign_key = 'RWQf6LRCGA9i56bjOTkFALACJ3by8pPQ2yOaYynH3N1T6wmwYqzY3QXe'
    refresh_delay = {delay}
    prefix = ''
  [sources.relays]
    urls = [
      {relay_urls}
    ]
    cache_file = '{DATA_HOME / "relays.md"}'
    minisign_key = 'RWQf6LRCGA9i56bjOTkFALACJ3by8pPQ2yOaYynH3N1T6wmwYqzY3QXe'
    refresh_delay = {delay_r}
    prefix = ''
"""
    dest = CONFIG_DIR / "dnscrypt-proxy.toml"
    dest.write_text(text, encoding="utf-8")
    return dest


def write_torrc(settings: dict[str, Any], *, datadir: Path, pidfile: Path, logfile: Path) -> Path:
    socks = settings.get("socks_port") or "9050"
    trans = settings.get("trans_port") or "9040"
    dns = settings.get("tor_dns_port") or "5353"
    isolate = []
    if settings.get("isolate_uid"):
        isolate += ["IsolateClientAddr", "IsolateSOCKSAuth", "IsolateClientProtocol"]
    if settings.get("isolate_dest_address"):
        isolate.append("IsolateDestAddr")
    if settings.get("isolate_dest_port"):
        isolate.append("IsolateDestPort")
    iso = (" " + " ".join(isolate)) if isolate else ""
    lines = [
        "# Generado por InviZible Linux a partir de los ajustes tipo APK.",
        f"ControlPort 127.0.0.1:9051",
        "CookieAuthentication 1",
        f"CookieAuthFile {datadir / 'control_auth_cookie'}",
        f"DataDirectory {datadir}",
        f"PidFile {pidfile}",
        f"Log notice file {logfile}",
        f"VirtualAddrNetworkIPv4 {settings.get('virtual_addr_network') or '10.192.0.0/10'}",
        "AutomapHostsOnResolve 1",
        f"HardwareAccel {1 if settings.get('hardware_accel') else 0}",
        f"AvoidDiskWrites {1 if settings.get('avoid_disk_writes') else 0}",
        f"NewCircuitPeriod {settings.get('new_circuit_period') or '30'}",
        f"MaxCircuitDirtiness {settings.get('max_circuit_dirtiness') or '600'}",
        f"DormantClientTimeout {settings.get('dormant_client_timeout') or '15'} minutes",
        f"EnforceDistinctSubnets {1 if settings.get('enforce_distinct_subnets') else 0}",
        f"ClientUseIPv4 {1 if settings.get('client_use_ipv4') else 0}",
        f"ClientUseIPv6 {1 if settings.get('client_use_ipv6') else 0}",
        "SafeSocks 1",
        "TestSocks 1",
    ]
    pad = settings.get("connection_padding")
    lines.append("ConnectionPadding auto" if pad else "ConnectionPadding 0")
    if settings.get("reduced_connection_padding"):
        lines.append("ReducedConnectionPadding 1")
    if settings.get("fascist_firewall"):
        lines.append("FascistFirewall 1")
    if settings.get("track_host_exits"):
        lines.append("TrackHostExits .")
    if settings.get("enable_socks_proxy", True):
        lines.append(f"SocksPort 127.0.0.1:{socks}{iso}")
    else:
        lines.append("SocksPort 0")
    if settings.get("enable_http_tunnel"):
        lines.append(f"HTTPTunnelPort 127.0.0.1:{settings.get('http_tunnel_port') or '8118'}")
    if settings.get("enable_transparent_proxy", True):
        lines.append(f"TransPort 127.0.0.1:{trans}")
    if settings.get("enable_tor_dns", True):
        lines.append(f"DNSPort 127.0.0.1:{dns}")
    if settings.get("enable_socks_output") or settings.get("use_socks5_proxy"):
        out = settings.get("socks5_output") if settings.get("enable_socks_output") else settings.get("socks5_address")
        if out:
            lines.append(f"Socks5Proxy {out}")

    def country_line(flag: str, option: str, key: str) -> None:
        if settings.get(flag):
            nodes = _csv_names(settings.get(key) or "")
            if nodes:
                braced = ",".join("{" + n.strip("{} ") + "}" if len(n.strip("{} ")) == 2 else n for n in nodes)
                lines.append(f"{option} {braced}")

    country_line("exit_nodes", "ExitNodes", "exit_nodes_list")
    country_line("entry_nodes", "EntryNodes", "entry_nodes_list")
    country_line("exclude_nodes", "ExcludeNodes", "exclude_nodes_list")
    country_line("exclude_exit_nodes", "ExcludeExitNodes", "exclude_exit_nodes_list")
    if settings.get("strict_nodes"):
        lines.append("StrictNodes 1")

    _append_bridges(lines, settings)

    dest = CONFIG_DIR / "torrc"
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dest


def write_system_torrc(settings: dict[str, Any]) -> Path:
    """torrc para tor.service (usuario tor/debian-tor, DataDirectory del paquete)."""
    socks = settings.get("socks_port") or "9050"
    trans = settings.get("trans_port") or "9040"
    dns = settings.get("tor_dns_port") or "5353"
    iso = ""
    flags = []
    if settings.get("isolate_uid"):
        flags += ["IsolateClientAddr", "IsolateSOCKSAuth", "IsolateClientProtocol"]
    if settings.get("isolate_dest_address"):
        flags.append("IsolateDestAddr")
    if settings.get("isolate_dest_port"):
        flags.append("IsolateDestPort")
    if flags:
        iso = " " + " ".join(flags)
    lines = [
        "## Generado por InviZible Linux para tor.service",
        f"Log notice file {SYSTEM_TOR_LOG}",
        "Log notice syslog",
        "RunAsDaemon 0",
        "AvoidDiskWrites 1",
        "SafeSocks 1",
        "TestSocks 1",
        "ClientUseIPv4 1",
        "ClientUseIPv6 0",
        f"SocksPort 127.0.0.1:{socks}{iso}",
        f"TransPort 127.0.0.1:{trans}",
        f"DNSPort 127.0.0.1:{dns}",
        "ControlPort 127.0.0.1:9051",
        "CookieAuthentication 1",
        "AutomapHostsOnResolve 1",
        "VirtualAddrNetworkIPv4 10.192.0.0/10",
    ]
    _append_bridges(lines, settings)
    dest = CONFIG_DIR / "torrc.system"
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dest


def write_i2pd_conf(settings: dict[str, Any], *, datadir: Path, pidfile: Path, logfile: Path) -> Path:
    parts = [
        "## Generado por InviZible Linux a partir de los ajustes tipo APK.",
        "log = file",
        f"logfile = {logfile}",
        "loglevel = info",
        f"ipv4 = {toml_bool(settings.get('i2p_ipv4'))}",
        f"ipv6 = {toml_bool(settings.get('i2p_ipv6'))}",
        f"notransit = {toml_bool(settings.get('i2p_notransit'))}",
        f"floodfill = {toml_bool(settings.get('i2p_floodfill'))}",
        f"bandwidth = {settings.get('i2p_bandwidth') or 'L'}",
        f"share = {settings.get('i2p_share') or '20'}",
        "daemon = false",
        f"pidfile = {pidfile}",
        f"datadir = {datadir}",
        "",
        "[ntcp2]",
        f"enabled = {toml_bool(settings.get('i2p_ntcp2'))}",
        "",
        "[ssu2]",
        f"enabled = {toml_bool(settings.get('i2p_ssu2'))}",
        "",
        "[http]",
        "enabled = true",
        "address = 127.0.0.1",
        "port = 7070",
        "",
        "[httpproxy]",
        f"enabled = {toml_bool(settings.get('i2p_http_proxy'))}",
        "address = 127.0.0.1",
        f"port = {settings.get('i2p_http_port') or '4444'}",
        "addresshelper = true",
    ]
    if settings.get("i2p_http_outproxy"):
        parts.append(f"outproxy = {settings.get('i2p_http_outproxy_address') or ''}")
    parts += [
        "",
        "[socksproxy]",
        f"enabled = {toml_bool(settings.get('i2p_socks_proxy'))}",
        "address = 127.0.0.1",
        f"port = {settings.get('i2p_socks_port') or '4447'}",
    ]
    if settings.get("i2p_socks_outproxy"):
        parts.append(f"outproxy = {settings.get('i2p_socks_outproxy_address') or '127.0.0.1'}")
        parts.append(f"outproxyport = {settings.get('i2p_socks_outproxy_port') or '9050'}")
    parts += [
        "",
        "[sam]",
        f"enabled = {toml_bool(settings.get('i2p_sam'))}",
        "address = 127.0.0.1",
        f"port = {settings.get('i2p_sam_port') or '7656'}",
        "",
        "[upnp]",
        f"enabled = {toml_bool(settings.get('i2p_upnp'))}",
        "",
        "[limits]",
        f"transittunnels = {settings.get('i2p_transittunnels') or '10'}",
        f"openfiles = {settings.get('i2p_openfiles') or '500'}",
        f"coresize = {settings.get('i2p_coresize') or '0'}",
        "",
        "[reseed]",
        f"verify = {toml_bool(settings.get('i2p_reseed_verify'))}",
        "",
        "[addressbook]",
        f"defaulturl = {settings.get('i2p_addressbook_url') or ''}",
        f"subscriptions = {settings.get('i2p_subscriptions') or ''}",
    ]
    if settings.get("i2p_incoming"):
        parts += [
            "",
            "[incoming]",
            f"host = {settings.get('i2p_incoming_host') or '0.0.0.0'}",
            f"port = {settings.get('i2p_incoming_port') or '4567'}",
        ]
    if settings.get("i2p_ntcpproxy_enabled"):
        parts += ["", f"ntcpproxy = {settings.get('i2p_ntcpproxy') or ''}"]
    dest = CONFIG_DIR / "i2pd.conf"
    dest.write_text("\n".join(parts) + "\n", encoding="utf-8")
    return dest


def _launcher() -> Path:
    found = shutil.which("invizible-linux")
    if found:
        return Path(found)
    from .config import PROJECT_ROOT

    return PROJECT_ROOT / "invizible-linux"


def sync_autostart(settings: dict[str, Any]) -> None:
    from .config import AUTOSTART_PATH

    want = any(settings.get(k) for k in ("sw_autostart_dns", "sw_autostart_tor", "sw_autostart_itpd"))
    AUTOSTART_PATH.parent.mkdir(parents=True, exist_ok=True)
    unit_dir = Path.home() / ".config/systemd/user"
    unit = unit_dir / "invizible-linux.service"
    exe = _launcher()
    if not want:
        AUTOSTART_PATH.unlink(missing_ok=True)
        subprocess.run(["systemctl", "--user", "disable", "--now", "invizible-linux.service"], capture_output=True)
        unit.unlink(missing_ok=True)
        return
    AUTOSTART_PATH.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=InviZible Linux\n"
        f"Exec={exe} --autostart\n"
        "Icon=net.invizible.Linux\n"
        "X-GNOME-Autostart-enabled=true\n",
        encoding="utf-8",
    )
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit.write_text(
        "[Unit]\n"
        "Description=InviZible Linux\n"
        "After=graphical-session.target\n"
        "PartOf=graphical-session.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={exe} --autostart\n"
        "Restart=on-failure\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n",
        encoding="utf-8",
    )
    subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    subprocess.run(["systemctl", "--user", "enable", "invizible-linux.service"], capture_output=True)
