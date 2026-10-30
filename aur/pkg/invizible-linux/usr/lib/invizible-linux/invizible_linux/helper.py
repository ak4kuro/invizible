#!/usr/bin/env python3
"""Ayudante privilegiado de InviZible Linux (pkexec). Solo aplica DNS, nftables y servicios de sistema."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parent.parent
if (_PKG_ROOT / "invizible_linux").is_dir() and str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from invizible_linux.config import SYSTEM_TOR_LOG as TOR_NOTICE

ALLOWED = {
    "status",
    "apply-firewall",
    "clear-firewall",
    "set-dns",
    "restore-dns",
    "start-system-tor",
    "stop-system-tor",
    "install-packages",
    "enable-userns",
    "write-system-torrc",
    "clear-system-torrc",
    "disable-ipv6",
    "restore-ipv6",
    "apply-all",
    "clear-all",
    "refresh-network",
}

DNS_LISTEN = "127.0.0.1:5354"
TOR_DNS = "127.0.0.1:5353"
TOR_TRANS = "9040"
RESOLV_BACKUP = Path("/etc/invizible-linux-resolv.bak")
NFT_TABLE = "inet invizible"
ROOT_LOCK = Path("/run/invizible-linux.lock")
SYSTEM_TOR_FLAG = Path("/run/invizible-linux.system-tor")
IPV6_SYSCTL = Path("/etc/sysctl.d/99-invizible-ipv6.conf")
TORRC_DROPIN = Path("/etc/tor/torrc.d/90-invizible.conf")
TORRC_MAIN = Path("/etc/tor/torrc")
BEGIN_MARK = "# BEGIN INVIZIBLE-LINUX"
END_MARK = "# END INVIZIBLE-LINUX"
OPTS_PATH = Path("/run/invizible-linux.opts.json")
HELPER_PATH_FILE = Path("/run/invizible-linux.helper")
DISPATCHER = Path("/etc/NetworkManager/dispatcher.d/99-invizible-linux")


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, text=True, capture_output=True)


def default_ifaces() -> list[str]:
    try:
        raw = run(["ip", "-j", "route", "show", "default"]).stdout
        data = json.loads(raw or "[]")
        names = []
        for row in data:
            dev = row.get("dev")
            if dev and dev not in names:
                names.append(dev)
        return names or ["wlan0", "eth0"]
    except (OSError, json.JSONDecodeError, subprocess.CalledProcessError):
        return ["wlan0", "eth0"]


def default_gateway() -> str | None:
    try:
        raw = run(["ip", "-j", "route", "show", "default"]).stdout
        data = json.loads(raw or "[]")
        for row in data:
            gw = row.get("gateway")
            if gw:
                return str(gw)
    except (OSError, json.JSONDecodeError, subprocess.CalledProcessError):
        pass
    return None


def wifi_ssid() -> str:
    r = run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"], check=False)
    for line in (r.stdout or "").splitlines():
        if line.startswith("yes:"):
            return line.split(":", 1)[-1]
    return ""


def effective_allow_lan(opts: dict[str, str]) -> bool:
    allow = opts.get("allow_lan", "1") == "1"
    if opts.get("block_lan_free_wifi") != "1":
        return allow
    ssid = wifi_ssid()
    if not ssid:
        return allow
    trusted = [x.strip() for x in (opts.get("trusted_wifi") or "").split(",") if x.strip()]
    return ssid in trusted


def tor_uid() -> str | None:
    from invizible_linux.distro import tor_uid as _tor_uid

    return _tor_uid()


def nft_exists() -> bool:
    r = run(["nft", "list", "table", *NFT_TABLE.split()], check=False)
    return r.returncode == 0


def clear_firewall() -> None:
    run(["nft", "delete", "table", *NFT_TABLE.split()], check=False)


def apply_firewall(opts: dict[str, str]) -> None:
    allow_lan = effective_allow_lan(opts)
    block_ipv6 = opts.get("block_ipv6", "1") == "1"
    kill_switch = opts.get("kill_switch", "1") == "1"
    route_tor = opts.get("route_all_tor", "0") == "1"
    dns_on = opts.get("dns", "0") == "1"
    tor_on = opts.get("tor", "0") == "1"
    uid = tor_uid()
    if kill_switch and not uid:
        kill_switch = False

    dns_port = opts.get("dns_port", "5354")
    tor_dns_port = opts.get("tor_dns_port", "5353")
    trans_port = opts.get("trans_port", "9040")
    prevent_leak = opts.get("prevent_dns_leak", "1") == "1"
    block_http = opts.get("block_http", "0") == "1"
    exclude_udp = opts.get("exclude_udp", "0") == "1"
    lan = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16"
    policy = "drop" if kill_switch else "accept"
    uid_return = f"meta skuid {uid} return" if uid and tor_on else ""
    uid_accept = f"meta skuid {uid} accept" if uid and tor_on else ""
    lan_nat = f"ip daddr {{ {lan} }} return" if allow_lan else ""
    lan_filter = f"ip daddr {{ {lan} }} accept" if allow_lan else ""
    ipv6_drop = "meta nfproto ipv6 ip6 daddr != ::1 drop" if block_ipv6 else ""
    http_drop = "tcp dport 80 drop" if block_http else ""
    stun_drop = "udp dport { 3478, 19302 } drop" if opts.get("block_stun", "1") == "1" else ""
    mdns_drop = "ip daddr 224.0.0.251 udp dport 5353 drop" if opts.get("block_mdns", "1") == "1" else ""
    llmnr_drop = "udp dport 5355 drop" if opts.get("block_llmnr", "1") == "1" else ""
    dhcp_ok = "udp dport { 67, 68 } accept\n    udp sport 68 accept" if kill_switch and opts.get("ks_allow_dhcp", "1") == "1" else ""
    ntp_ok = "udp dport 123 accept" if kill_switch and opts.get("ks_allow_ntp", "1") == "1" else ""
    gw = default_gateway()
    captive_ok = ""
    if kill_switch and opts.get("ks_allow_captive", "1") == "1" and gw:
        captive_ok = f"ip daddr {gw} tcp dport {{ 80, 443 }} accept"
    dns_redirect = ""
    if prevent_leak and dns_on and not (tor_on and route_tor):
        dns_redirect = f"udp dport 53 redirect to :{dns_port}\n    tcp dport 53 redirect to :{dns_port}"
    elif prevent_leak and tor_on and route_tor:
        dns_redirect = f"udp dport 53 redirect to :{tor_dns_port}\n    tcp dport 53 redirect to :{tor_dns_port}"
    trans_redirect = ""
    if tor_on and route_tor:
        trans_redirect = f"tcp flags & (fin|syn|rst|ack) == syn redirect to :{trans_port}"
        if exclude_udp:
            trans_redirect = f"tcp flags & (fin|syn|rst|ack) == syn redirect to :{trans_port}"

    rules = f"""
table {NFT_TABLE} {{
  chain output_nat {{
    type nat hook output priority -100; policy accept;
    oif "lo" return
    ip daddr 127.0.0.0/8 return
    {uid_return}
    {lan_nat}
    {dns_redirect}
    {trans_redirect}
  }}

  chain output_filter {{
    type filter hook output priority filter; policy {policy};
    oif "lo" accept
    ct state established,related accept
    {uid_accept}
    {dhcp_ok}
    {ntp_ok}
    {captive_ok}
    {lan_filter}
    {ipv6_drop}
    {stun_drop}
    {mdns_drop}
    {llmnr_drop}
    {http_drop}
  }}
}}
"""
    clear_firewall()
    proc = subprocess.run(["nft", "-f", "-"], input=rules, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "nftables rechazó las reglas")


def set_dns(backend: str) -> None:
    ifaces = default_ifaces()
    if shutil.which("resolvectl"):
        for iface in ifaces:
            if backend == "tor":
                run(["resolvectl", "dns", iface, TOR_DNS], check=False)
                run(["resolvectl", "dnsovertls", iface, "no"], check=False)
            elif backend == "dnscrypt":
                run(["resolvectl", "dns", iface, DNS_LISTEN], check=False)
                run(["resolvectl", "dnsovertls", iface, "no"], check=False)
            elif backend == "dot-quad9":
                run(
                    ["resolvectl", "dns", iface, "9.9.9.9#dns.quad9.net", "149.112.112.112#dns.quad9.net"],
                    check=False,
                )
                run(["resolvectl", "dnsovertls", iface, "yes"], check=False)
            else:
                run(
                    ["resolvectl", "dns", iface, "1.1.1.1#cloudflare-dns.com", "1.0.0.1#cloudflare-dns.com"],
                    check=False,
                )
                run(["resolvectl", "dnsovertls", iface, "yes"], check=False)
            run(["resolvectl", "domain", iface, "~."], check=False)
        return

    resolv = Path("/etc/resolv.conf")
    if resolv.exists() and not RESOLV_BACKUP.exists():
        RESOLV_BACKUP.write_text(resolv.read_text(encoding="utf-8"), encoding="utf-8")
    if backend == "tor":
        content = "nameserver 127.0.0.1\n"
    elif backend == "dnscrypt":
        content = "nameserver 127.0.0.1\n"
    elif backend == "dot-quad9":
        content = "nameserver 9.9.9.9\nnameserver 149.112.112.112\n"
    else:
        content = "nameserver 1.1.1.1\nnameserver 1.0.0.1\n"
    resolv.write_text(content, encoding="utf-8")


def set_lock(active: bool) -> None:
    if active:
        ROOT_LOCK.write_text("1\n", encoding="utf-8")
        try:
            ROOT_LOCK.chmod(0o644)
        except OSError:
            pass
    else:
        ROOT_LOCK.unlink(missing_ok=True)


def _safe_src(value: str) -> Path | None:
    path = Path(value)
    try:
        resolved = path.resolve()
    except OSError:
        return None
    if not resolved.is_file():
        return None
    text = str(resolved)
    allowed = text.startswith(("/home/", "/tmp/", "/var/tmp/", "/run/"))
    if not allowed:
        return None
    if resolved.name not in {"torrc", "torrc.system", "90-invizible.conf"} and resolved.suffix not in {".conf", ".torrc"}:
        return None
    return resolved


def disable_ipv6() -> None:
    IPV6_SYSCTL.write_text(
        "net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\n",
        encoding="utf-8",
    )
    for key in ("net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6"):
        run(["sysctl", "-w", f"{key}=1"], check=False)


def restore_ipv6() -> None:
    if IPV6_SYSCTL.exists():
        IPV6_SYSCTL.unlink(missing_ok=True)
        for key in ("net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6"):
            run(["sysctl", "-w", f"{key}=0"], check=False)


def _strip_invizible_block(text: str) -> str:
    lines = text.splitlines()
    out: list[str] = []
    skip = False
    for line in lines:
        if line.strip() == BEGIN_MARK:
            skip = True
            continue
        if line.strip() == END_MARK:
            skip = False
            continue
        if not skip:
            out.append(line)
    return "\n".join(out).rstrip() + "\n"


def _torrc_has_include(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.startswith("%include") and "torrc.d" in stripped:
            return True
    return False


def write_system_torrc(src: Path) -> None:
    TORRC_DROPIN.parent.mkdir(parents=True, exist_ok=True)
    TORRC_DROPIN.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    try:
        TORRC_DROPIN.chmod(0o644)
    except OSError:
        pass
    if not TORRC_MAIN.exists():
        TORRC_MAIN.write_text(
            f"{BEGIN_MARK}\n%include /etc/tor/torrc.d/*.conf\n{END_MARK}\n",
            encoding="utf-8",
        )
        return
    text = TORRC_MAIN.read_text(encoding="utf-8")
    if _torrc_has_include(text):
        return
    cleaned = _strip_invizible_block(text)
    TORRC_MAIN.write_text(
        cleaned + f"\n{BEGIN_MARK}\n%include /etc/tor/torrc.d/*.conf\n{END_MARK}\n",
        encoding="utf-8",
    )


def clear_system_torrc() -> None:
    TORRC_DROPIN.unlink(missing_ok=True)
    if TORRC_MAIN.exists():
        TORRC_MAIN.write_text(_strip_invizible_block(TORRC_MAIN.read_text(encoding="utf-8")), encoding="utf-8")


def restore_dns() -> None:
    ifaces = default_ifaces()
    if shutil.which("resolvectl"):
        for iface in ifaces:
            run(["resolvectl", "revert", iface], check=False)
        return
    if RESOLV_BACKUP.exists():
        Path("/etc/resolv.conf").write_text(RESOLV_BACKUP.read_text(encoding="utf-8"), encoding="utf-8")
        RESOLV_BACKUP.unlink(missing_ok=True)


def systemctl(*args: str) -> subprocess.CompletedProcess[str]:
    return run(["systemctl", *args], check=False)


def _save_opts(opts: dict[str, str]) -> None:
    OPTS_PATH.write_text(json.dumps(opts) + "\n", encoding="utf-8")
    try:
        OPTS_PATH.chmod(0o600)
    except OSError:
        pass
    HELPER_PATH_FILE.write_text(str(Path(__file__).resolve()) + "\n", encoding="utf-8")


def _load_opts() -> dict[str, str]:
    try:
        data = json.loads(OPTS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def prepare_tor_notice_log() -> None:
    TOR_NOTICE.parent.mkdir(parents=True, exist_ok=True)
    try:
        TOR_NOTICE.parent.chmod(0o755)
    except OSError:
        pass
    uid = tor_uid()
    if uid:
        try:
            os.chown(TOR_NOTICE.parent, int(uid), -1)
        except OSError:
            pass
    TOR_NOTICE.write_text("", encoding="utf-8")
    if uid:
        try:
            os.chown(TOR_NOTICE, int(uid), -1)
        except OSError:
            pass
    try:
        TOR_NOTICE.chmod(0o644)
    except OSError:
        pass


def restart_tor_unit() -> None:
    systemctl("reset-failed", "tor")
    r = systemctl("restart", "tor")
    if r.returncode != 0:
        systemctl("reset-failed", "tor")
        r = systemctl("start", "tor")
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "").strip()
        raise RuntimeError(err or "No se pudo iniciar tor.service")


def install_dispatcher() -> None:
    DISPATCHER.parent.mkdir(parents=True, exist_ok=True)
    DISPATCHER.write_text(
        "#!/bin/sh\n"
        "[ -f /run/invizible-linux.lock ] || exit 0\n"
        "HELPER=$(cat /run/invizible-linux.helper 2>/dev/null) || exit 0\n"
        "[ -n \"$HELPER\" ] || exit 0\n"
        "case \"$2\" in\n"
        "  up|down|dhcp4-change|dhcp6-change|connectivity-change)\n"
        "    /usr/bin/python3 \"$HELPER\" refresh-network\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    DISPATCHER.chmod(0o755)


def remove_dispatcher() -> None:
    DISPATCHER.unlink(missing_ok=True)


def apply_all(opts: dict[str, str]) -> None:
    _save_opts(opts)
    src = Path(opts.get("src") or "")
    if opts.get("start_tor") == "1":
        if src.is_file():
            write_system_torrc(src)
        prepare_tor_notice_log()
        restart_tor_unit()
        SYSTEM_TOR_FLAG.write_text("1\n", encoding="utf-8")
    if opts.get("apply_fw", "1") == "1":
        apply_firewall(opts)
    if opts.get("block_ipv6") == "1" and opts.get("apply_fw", "1") == "1":
        disable_ipv6()
    elif opts.get("apply_fw", "1") == "1":
        restore_ipv6()
    if opts.get("set_dns") == "1":
        set_dns(opts.get("backend", "dnscrypt"))
    if opts.get("refresh_rules") == "1":
        install_dispatcher()
    else:
        remove_dispatcher()
    set_lock(True)


def clear_all() -> None:
    if SYSTEM_TOR_FLAG.exists():
        systemctl("stop", "tor")
        SYSTEM_TOR_FLAG.unlink(missing_ok=True)
    clear_system_torrc()
    restore_ipv6()
    clear_firewall()
    restore_dns()
    remove_dispatcher()
    OPTS_PATH.unlink(missing_ok=True)
    HELPER_PATH_FILE.unlink(missing_ok=True)
    TOR_NOTICE.unlink(missing_ok=True)
    set_lock(False)


def refresh_network() -> None:
    if not ROOT_LOCK.exists():
        return
    opts = _load_opts()
    if not opts:
        return
    if opts.get("apply_fw", "1") == "1":
        apply_firewall(opts)
    if opts.get("set_dns") == "1":
        set_dns(opts.get("backend", "dnscrypt"))


def main() -> int:
    if os.geteuid() != 0:
        print("Este ayudante debe ejecutarse con privilegios (pkexec).", file=sys.stderr)
        return 2
    if len(sys.argv) < 2 or sys.argv[1] not in ALLOWED:
        print("Uso: helper <" + "|".join(sorted(ALLOWED)) + "> [k=v ...]", file=sys.stderr)
        return 2

    action = sys.argv[1]
    opts = {}
    backends = {"dnscrypt", "tor", "dot-cloudflare", "dot-quad9"}
    for item in sys.argv[2:]:
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        if key == "backend" and value in backends:
            opts[key] = value
        elif key == "packages":
            opts[key] = value
        elif key == "src":
            src_path = _safe_src(value)
            if src_path:
                opts[key] = str(src_path)
        elif key == "trusted_wifi" and all(c.isalnum() or c in " ,._-" for c in value):
            opts[key] = value
        elif key.replace("_", "").isalnum() and value in {"0", "1"}:
            opts[key] = value
        elif key.replace("_", "").isalnum() and value.isdigit():
            opts[key] = value

    try:
        if action == "status":
            print(
                json.dumps(
                    {
                        "firewall": nft_exists(),
                        "tor_unit": systemctl("is-active", "tor").stdout.strip(),
                        "ifaces": default_ifaces(),
                        "tor_uid": tor_uid(),
                        "privileged_lock": ROOT_LOCK.exists(),
                        "system_tor_ours": SYSTEM_TOR_FLAG.exists(),
                    }
                )
            )
        elif action == "apply-firewall":
            apply_firewall(opts)
            set_lock(True)
            print("ok")
        elif action == "clear-firewall":
            clear_firewall()
            if not SYSTEM_TOR_FLAG.exists():
                set_lock(False)
            print("ok")
        elif action == "set-dns":
            set_dns(opts.get("backend", "dnscrypt"))
            set_lock(True)
            print("ok")
        elif action == "restore-dns":
            restore_dns()
            print("ok")
        elif action == "write-system-torrc":
            src = Path(opts.get("src") or "")
            if not src.is_file():
                raise RuntimeError("Ruta de torrc de sistema no válida")
            write_system_torrc(src)
            print("ok")
        elif action == "clear-system-torrc":
            clear_system_torrc()
            print("ok")
        elif action == "disable-ipv6":
            disable_ipv6()
            print("ok")
        elif action == "restore-ipv6":
            restore_ipv6()
            print("ok")
        elif action == "start-system-tor":
            prepare_tor_notice_log()
            restart_tor_unit()
            SYSTEM_TOR_FLAG.write_text("1\n", encoding="utf-8")
            set_lock(True)
            print("ok")
        elif action == "stop-system-tor":
            if SYSTEM_TOR_FLAG.exists():
                systemctl("stop", "tor")
                SYSTEM_TOR_FLAG.unlink(missing_ok=True)
            print("ok")
        elif action == "apply-all":
            apply_all(opts)
            print("ok")
        elif action == "clear-all":
            clear_all()
            print("ok")
        elif action == "refresh-network":
            refresh_network()
            print("ok")
        elif action == "install-packages":
            from invizible_linux.distro import ALLOWED_PACKAGES, install_as_root, resolve_install_names

            raw = opts.get("packages") or ""
            requested = [p.strip() for p in raw.split(",") if p.strip()]
            pkgs = resolve_install_names(requested)
            pkgs = [p for p in pkgs if p in ALLOWED_PACKAGES]
            if not pkgs:
                raise RuntimeError("Lista de paquetes vacía o no permitida")
            print(install_as_root(pkgs))
        elif action == "enable-userns":
            proc_path = Path("/proc/sys/kernel/unprivileged_userns_clone")
            if proc_path.exists():
                proc_path.write_text("1\n", encoding="utf-8")
            conf = Path("/etc/sysctl.d/99-invizible-oniux.conf")
            conf.write_text("kernel.unprivileged_userns_clone = 1\n", encoding="utf-8")
            print("ok")
    except Exception as exc:  # noqa: BLE001
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
