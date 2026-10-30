from __future__ import annotations

import json
import os
import socket
import ssl
import struct
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

Progress = Callable[[str], None]


@dataclass
class LeakResult:
    key: str
    title: str
    status: str  # ok, leak, warn, error, info
    detail: str


def _http(url: str, timeout: float = 8.0, socks: tuple[str, int] | None = None) -> str:
    if socks:
        return _https_via_socks(url, socks[0], socks[1], timeout)
    req = urllib.request.Request(url, headers={"User-Agent": "InviZibleLinux/0.7"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace").strip()


def _https_via_socks(url: str, host: str, port: int, timeout: float) -> str:
    parsed = urlparse(url)
    dest_host = parsed.hostname or ""
    dest_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(b"\x05\x01\x00")
    hello = sock.recv(2)
    if hello != b"\x05\x00":
        sock.close()
        raise OSError("El proxy SOCKS5 rechazó la conexión")
    req = b"\x05\x01\x00\x03" + bytes([len(dest_host)]) + dest_host.encode() + struct.pack("!H", dest_port)
    sock.sendall(req)
    reply = sock.recv(262)
    if len(reply) < 2 or reply[1] != 0:
        sock.close()
        raise OSError("SOCKS5 CONNECT falló")
    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=dest_host)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    payload = (
        f"GET {path} HTTP/1.1\r\nHost: {dest_host}\r\nUser-Agent: InviZibleLinux/0.7\r\nConnection: close\r\n\r\n"
    ).encode()
    sock.sendall(payload)
    chunks = []
    while True:
        data = sock.recv(4096)
        if not data:
            break
        chunks.append(data)
    sock.close()
    raw = b"".join(chunks).decode("utf-8", errors="replace")
    _, _, body = raw.partition("\r\n\r\n")
    return body.strip()


def _dns_a(name: str, server: str = "", port: int = 53, timeout: float = 4.0) -> list[str]:
    if not server:
        return _dns_a_system(name)

    labels = name.strip(".").split(".")
    q = b"".join(bytes([len(x)]) + x.encode() for x in labels) + b"\x00\x00\x01\x00\x01"
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(header + q, (server, port))
        data, _ = sock.recvfrom(512)
    except OSError:
        return []
    finally:
        sock.close()
    if len(data) < 12:
        return []
    answers = struct.unpack("!H", data[6:8])[0]
    offset = 12 + len(q)
    ips = []
    for _ in range(answers):
        if offset + 12 > len(data):
            break
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset]:
                offset += 1 + data[offset]
            offset += 1
        if offset + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(rdata))
    return ips


def _dns_a_system(name: str) -> list[str]:
    ips = []
    try:
        for item in socket.getaddrinfo(name, None, socket.AF_INET):
            ip = item[4][0]
            if ip not in ips:
                ips.append(ip)
    except OSError:
        pass
    return ips


def _stun_mapped(timeout: float = 3.0) -> str | None:
    cookie = 0x2112A442
    tid = os.urandom(12)
    msg = struct.pack("!HHI", 0x0001, 0, cookie) + tid
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg, ("stun.l.google.com", 19302))
        data, _ = sock.recvfrom(1024)
    except OSError:
        return None
    finally:
        sock.close()
    if len(data) < 20:
        return None
    offset = 20
    length = struct.unpack("!H", data[2:4])[0]
    end = 20 + length
    while offset + 4 <= end and offset + 4 <= len(data):
        atype, alen = struct.unpack("!HH", data[offset : offset + 4])
        val = data[offset + 4 : offset + 4 + alen]
        offset += 4 + alen
        if alen % 4:
            offset += 4 - (alen % 4)
        if atype in (0x0020, 0x0001) and len(val) >= 8:
            family = val[1]
            port = struct.unpack("!H", val[2:4])[0]
            addr = val[4:8]
            if atype == 0x0020:
                port ^= cookie >> 16
                addr = bytes(b ^ c for b, c in zip(addr, struct.pack("!I", cookie)))
            if family == 0x01:
                return socket.inet_ntoa(addr)
    return None


def _to_int(value: Any, default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def run_leak_tests(settings: dict[str, Any], progress: Progress | None = None) -> list[LeakResult]:
    log = progress or (lambda _m: None)
    results: list[LeakResult] = []
    socks_port = _to_int(settings.get("socks_port"), 9050)
    dns_port = _to_int(settings.get("listen_port"), 5354)
    tor_on = False
    try:
        probe = socket.create_connection(("127.0.0.1", socks_port), timeout=0.3)
        probe.close()
        tor_on = True
    except OSError:
        tor_on = False

    ipv4 = ""
    log("IP pública IPv4…")
    try:
        ipv4 = _http("https://api.ipify.org")
        results.append(LeakResult("ipv4", "IP pública IPv4", "info", ipv4))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        results.append(LeakResult("ipv4", "IP pública IPv4", "error", str(exc)))

    log("¿Estás usando Tor?…")
    if tor_on:
        try:
            raw = _https_via_socks("https://check.torproject.org/api/ip", "127.0.0.1", socks_port, 12)
            data = json.loads(raw.split("\n")[-1] if raw else "{}")
            is_tor = bool(data.get("IsTor"))
            tor_ip = str(data.get("IP") or "")
            if is_tor:
                results.append(LeakResult("tor", "Circuito Tor (SOCKS)", "ok", f"Sí. Salida: {tor_ip}"))
            else:
                results.append(LeakResult("tor", "Circuito Tor (SOCKS)", "leak", f"SOCKS no sale por Tor ({tor_ip})"))
            if ipv4 and tor_ip and ipv4 == tor_ip:
                results.append(
                    LeakResult(
                        "direct",
                        "IP directa vs Tor",
                        "ok",
                        "La IP directa coincide con la salida Tor (modo sistema).",
                    )
                )
            elif ipv4 and tor_ip and ipv4 != tor_ip:
                results.append(
                    LeakResult(
                        "direct",
                        "IP directa vs Tor",
                        "warn",
                        f"Directa {ipv4} ≠ Tor {tor_ip}. El sistema no rutea todo por Tor (modo proxy).",
                    )
                )
        except (OSError, json.JSONDecodeError, TimeoutError) as exc:
            results.append(LeakResult("tor", "Circuito Tor (SOCKS)", "error", str(exc)))
    else:
        results.append(LeakResult("tor", "Circuito Tor (SOCKS)", "warn", "Tor no está en marcha en el puerto SOCKS."))
        try:
            raw = _http("https://check.torproject.org/api/ip")
            data = json.loads(raw)
            if data.get("IsTor"):
                results.append(LeakResult("tor-direct", "Tor en el sistema", "ok", f"Esta IP es de Tor: {data.get('IP')}"))
            else:
                results.append(
                    LeakResult("tor-direct", "Tor en el sistema", "info", f"No es Tor. IP: {data.get('IP')}. Inicia Tor para anonimato.")
                )
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            results.append(LeakResult("tor-direct", "Tor en el sistema", "error", str(exc)))

    log("IPv6…")
    v6 = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.connect(("2001:4860:4860::8888", 53))
        sock.close()
        has_v6 = True
    except OSError:
        has_v6 = False
    if has_v6:
        try:
            v6 = _http("https://ipv6.icanhazip.com", timeout=5)
        except (urllib.error.URLError, TimeoutError, OSError):
            v6 = None
    if v6 and ":" in v6:
        status = "leak" if (tor_on or settings.get("block_ipv6") or settings.get("route_all_tor")) else "warn"
        results.append(LeakResult("ipv6", "Fuga IPv6", status, f"IPv6 pública visible: {v6}"))
    else:
        results.append(LeakResult("ipv6", "Fuga IPv6", "ok", "No hay IPv6 pública (o está bloqueada)."))

    log("DNS (whoami)…")
    try:
        system_dns = _dns_a_system("whoami.akamai.net")
        local_dns = _dns_a("whoami.akamai.net", "127.0.0.1", dns_port)
        detail = f"Sistema: {', '.join(system_dns) or 'sin respuesta'}"
        if local_dns:
            detail += f" · DNSCrypt: {', '.join(local_dns)}"
        if not system_dns:
            results.append(LeakResult("dns", "Fuga DNS", "warn", detail + ". No se pudo consultar whoami."))
        elif ipv4 and ipv4 in system_dns:
            results.append(LeakResult("dns", "Fuga DNS", "leak", detail + ". El resolvedor ve tu IP real."))
        elif tor_on and local_dns and system_dns and set(system_dns) != set(local_dns):
            results.append(
                LeakResult(
                    "dns",
                    "Fuga DNS",
                    "warn",
                    detail + ". El DNS del sistema no es el de DNSCrypt.",
                )
            )
        else:
            results.append(LeakResult("dns", "Fuga DNS", "ok", detail))
    except OSError as exc:
        results.append(LeakResult("dns", "Fuga DNS", "error", str(exc)))

    log("STUN / WebRTC…")
    mapped = _stun_mapped()
    if not mapped:
        results.append(LeakResult("stun", "STUN (WebRTC)", "ok", "Sin respuesta STUN (UDP filtrado o bloqueado)."))
    elif ipv4 and mapped == ipv4 and tor_on:
        results.append(LeakResult("stun", "STUN (WebRTC)", "leak", f"STUN revela {mapped}, igual que tu IP directa."))
    elif ipv4 and mapped == ipv4:
        results.append(LeakResult("stun", "STUN (WebRTC)", "warn", f"STUN revela {mapped}. Un navegador puede filtrar esta IP."))
    elif tor_on and ipv4 and mapped != ipv4:
        results.append(LeakResult("stun", "STUN (WebRTC)", "warn", f"STUN {mapped} ≠ IP directa {ipv4}."))
    else:
        results.append(LeakResult("stun", "STUN (WebRTC)", "info", f"Dirección observada: {mapped}"))

    log("DNS del sistema…")
    resolv = ""
    resolv_path = "/etc/resolv.conf"
    try:
        resolv = open(resolv_path, encoding="utf-8").read()
    except OSError:
        resolv = ""
    ns = next((ln.strip() for ln in resolv.splitlines() if ln.startswith("nameserver")), "")
    if "127.0.0.1" in ns:
        results.append(LeakResult("resolv", "resolv.conf", "ok", ns))
    elif "127.0.0.53" in ns:
        results.append(LeakResult("resolv", "resolv.conf", "warn", ns + " (stub de systemd-resolved; el DNS real puede ser el del ISP)"))
    elif ns:
        results.append(LeakResult("resolv", "resolv.conf", "warn", ns + " (no es local)"))
    else:
        results.append(LeakResult("resolv", "resolv.conf", "warn", "No se pudo leer"))

    log("Salida aislada (oniux/torsocks)…")
    results.append(_isolation_probe(ipv4, tor_on))

    leaks = sum(1 for r in results if r.status == "leak")
    warns = sum(1 for r in results if r.status == "warn")
    if leaks:
        summary = f"{leaks} fuga(s) detectada(s)"
        status = "leak"
    elif warns:
        summary = f"Sin fugas graves, {warns} aviso(s)"
        status = "warn"
    else:
        summary = "Sin fugas evidentes en estas pruebas"
        status = "ok"
    report = save_leak_report(results)
    results.insert(0, LeakResult("summary", "Resumen", status, summary))
    results.append(LeakResult("report", "Informe guardado", "info", str(report)))
    return results


def _isolation_probe(direct_ip: str, tor_on: bool) -> LeakResult:
    try:
        from .oniuxctl import isolation_mode, oniux_binary
    except Exception as exc:  # noqa: BLE001
        return LeakResult("oniux", "Salida aislada", "error", str(exc))
    mode = isolation_mode()
    if mode != "oniux" or not oniux_binary():
        return LeakResult(
            "oniux",
            "Salida aislada",
            "info",
            f"Modo {mode}. Inicia Tor y lanza una app en modo Tor para comprobar el aislamiento.",
        )
    code = (
        "import urllib.request; "
        "print(urllib.request.urlopen('https://check.torproject.org/api/ip', timeout=12).read().decode())"
    )
    try:
        proc = subprocess.run(
            [oniux_binary(), "python3", "-c", code],
            capture_output=True,
            text=True,
            timeout=25,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return LeakResult("oniux", "Salida oniux", "warn", str(exc))
    raw = (proc.stdout or "").strip()
    if proc.returncode != 0:
        return LeakResult("oniux", "Salida oniux", "warn", (proc.stderr or raw or "oniux falló")[:240])
    try:
        data = json.loads(raw.split("\n")[-1] if raw else "{}")
    except json.JSONDecodeError:
        return LeakResult("oniux", "Salida oniux", "warn", raw[:240] or "sin JSON")
    is_tor = bool(data.get("IsTor"))
    ip = str(data.get("IP") or "")
    if is_tor:
        extra = f" Coincide con la IP directa ({direct_ip})." if direct_ip and ip == direct_ip else ""
        return LeakResult("oniux", "Salida oniux", "ok", f"Sí, sale por Tor: {ip}.{extra}")
    if not tor_on:
        return LeakResult("oniux", "Salida oniux", "warn", f"oniux no salió por Tor ({ip}). ¿Está Tor en marcha?")
    return LeakResult("oniux", "Salida oniux", "leak", f"oniux no usó Tor. IP: {ip}")


def save_leak_report(results: list[LeakResult]) -> Path:
    from .config import LEAK_REPORT_DIR, ensure_dirs

    ensure_dirs()
    path = LEAK_REPORT_DIR / time.strftime("leak-%Y%m%d-%H%M%S.txt")
    lines = [f"{item.status.upper():7} {item.title}: {item.detail}" for item in results]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
