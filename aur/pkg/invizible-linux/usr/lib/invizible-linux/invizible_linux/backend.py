from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .config import (
    CONFIG_DIR,
    DATA_HOME,
    LOG_DIR,
    PRIV_LOCK,
    RUNTIME_DIR,
    SYSTEM_TOR_LOG,
    ensure_dirs,
    load_settings,
    save_settings,
)
from .confgen import (
    resolve_bridges,
    sync_autostart,
    write_dnscrypt_toml,
    write_i2pd_conf,
    write_system_torrc,
    write_torrc,
)
from .distro import install_hint as distro_install_hint, install_hint_for, needed_packages, which_bin
from .launchers import write_pac


def _port(settings: dict, key: str, default: int) -> int:
    try:
        return int(str(settings.get(key) or default))
    except ValueError:
        return default


def which(name: str) -> str | None:
    return which_bin(name)


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def read_pid(path: Path) -> int | None:
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    return pid if pid_alive(pid) else None


def write_pid(path: Path, pid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid), encoding="utf-8")


def tail(path: Path, lines: int = 80) -> str:
    if not path.exists():
        return ""
    try:
        data = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(data[-lines:])


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.25)
        return sock.connect_ex((host, port)) == 0


@dataclass
class ModuleState:
    key: str
    title: str
    binary: str
    running: bool = False
    installed: bool = False
    detail: str = "Detenido"
    log_path: Path | None = None
    pid_path: Path | None = None
    extra: dict[str, str] = field(default_factory=dict)


class Controller:
    def __init__(self, log: LogFn | None = None) -> None:
        ensure_dirs()
        self.settings = load_settings()
        self._log = log or (lambda _msg: None)
        self._procs: dict[str, subprocess.Popen] = {}
        self._privileged_applied = False
        self.events: list[tuple[str, str]] = []

    def push_event(self, title: str, body: str) -> None:
        self.events.append((title, body))
        self.log(f"{title}: {body}")

    def log(self, message: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        self._log(f"[{stamp}] {message}")

    def missing_packages(self) -> list[str]:
        return needed_packages()

    def install_missing(self) -> str:
        missing = self.missing_packages()
        if not missing:
            return "Ya estaba todo instalado."
        if not which("pkexec"):
            raise RuntimeError("Falta pkexec. " + distro_install_hint())
        self.log("Instalando: " + ", ".join(missing))
        result = self.pkexec("install-packages", "packages=" + ",".join(missing))
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "instalación cancelada").strip())
        self.log("Paquetes instalados.")
        return (result.stdout or "ok").strip()

    def snapshot(self) -> dict[str, ModuleState]:
        dns_port = _port(self.settings, "listen_port", 5354)
        socks = _port(self.settings, "socks_port", 9050)
        i2p_http = _port(self.settings, "i2p_http_port", 4444)
        dns = which("dnscrypt-proxy") is not None
        tor = which("tor") is not None
        i2p = which("i2pd") is not None
        dns_run = bool(read_pid(RUNTIME_DIR / "dnscrypt.pid")) or port_open(dns_port)
        tor_run = bool(read_pid(RUNTIME_DIR / "tor.pid")) or port_open(socks)
        i2p_run = bool(read_pid(RUNTIME_DIR / "i2pd.pid")) or port_open(i2p_http)
        return {
            "dns": ModuleState(
                "dns",
                "DNSCrypt",
                "dnscrypt-proxy",
                running=dns_run,
                installed=dns,
                detail=self._dns_detail(dns, dns_run),
                log_path=LOG_DIR / "dnscrypt.log",
                extra={"proxy": f"127.0.0.1:{dns_port}"},
            ),
            "tor": ModuleState(
                "tor",
                "Tor",
                "tor",
                running=tor_run,
                installed=tor,
                detail=self._tor_detail(tor, tor_run),
                log_path=LOG_DIR / "tor.log",
                extra={"socks": f"127.0.0.1:{socks}", "trans": f"127.0.0.1:{_port(self.settings, 'trans_port', 9040)}"},
            ),
            "i2p": ModuleState(
                "i2p",
                "I2P",
                "i2pd",
                running=i2p_run,
                installed=i2p,
                detail=self._i2p_detail(i2p, i2p_run),
                log_path=LOG_DIR / "i2pd.log",
                extra={"http": f"127.0.0.1:{i2p_http}", "socks": f"127.0.0.1:{_port(self.settings, 'i2p_socks_port', 4447)}"},
            ),
        }

    def _dns_detail(self, installed: bool, running: bool) -> str:
        if not installed:
            return "No instalado"
        if running:
            return f"DNS cifrado en 127.0.0.1:{_port(self.settings, 'listen_port', 5354)}"
        return "Detenido"

    def _bootstrap_text(self, path: Path) -> str:
        log = tail(path, 80)
        if "Bootstrapped 100%" in log:
            return "Tor en marcha (100%)"
        for line in reversed(log.splitlines()):
            if "Bootstrapped" in line:
                chunk = line.split("] ")[-1] if "] " in line else line
                return chunk[-56:]
        return ""

    def _tor_detail(self, installed: bool, running: bool) -> str:
        if not installed:
            return "No instalado"
        if not running:
            return "Detenido"
        system = bool(self.settings.get("system_mode"))
        boot = self._bootstrap_text(SYSTEM_TOR_LOG if system else LOG_DIR / "tor.log")
        if boot:
            return ("tor.service · " + boot) if system else boot
        if system:
            return f"tor.service · SOCKS 127.0.0.1:{_port(self.settings, 'socks_port', 9050)}"
        return "Tor arrancando…"

    def _i2p_detail(self, installed: bool, running: bool) -> str:
        if not installed:
            return "No instalado"
        if running:
            return f"Proxy HTTP 127.0.0.1:{_port(self.settings, 'i2p_http_port', 4444)}"
        return "Detenido"

    def any_running(self) -> bool:
        snap = self.snapshot()
        return any(m.running for m in snap.values())

    def combined_log(self) -> str:
        chunks = []
        for name in ("dnscrypt.log", "tor.log", "i2pd.log", "app.log"):
            path = LOG_DIR / name
            text = tail(path, 60)
            if text:
                chunks.append(f"—— {name} ——\n{text}")
        return "\n\n".join(chunks) if chunks else "Sin registros todavía."

    def needs_privilege(self) -> bool:
        return bool(self.settings.get("system_mode") or self.settings.get("firewall"))

    def start_selected(self) -> None:
        ensure_dirs()
        save_settings(self.settings)
        wanted = [k for k in ("dns", "tor", "i2p") if self.settings.get(k)]
        if not wanted:
            raise RuntimeError("Selecciona al menos DNSCrypt, Tor o I2P.")
        _mode, _bridges, warn = resolve_bridges(self.settings)
        if warn:
            self.log(warn)
            self.push_event("Puentes", warn)
        from .launchers import pac_file_url, runner_path, sync_desktop_launchers
        from .profiles import apply_firefox_pac

        write_pac(self.settings)
        if self.settings.get("firefox_pac"):
            try:
                apply_firefox_pac(True, pac_file_url())
                self.log("PAC escrito en la política de Firefox.")
            except OSError as exc:
                self.log(f"PAC Firefox: {exc}")
        try:
            sync_desktop_launchers(self.settings, runner_path())
        except OSError as exc:
            self.log(f"Lanzadores: {exc}")
        sync_autostart(self.settings)

        if self.needs_privilege():
            ok = self.apply_privileged()
            if not ok:
                self.push_event("Sin protección", "pkexec cancelado o falló. No se han iniciado módulos.")
                raise RuntimeError(
                    "Se canceló o falló pkexec. No se han iniciado módulos (fallo cerrado: sin cortafuegos no hay arranque)."
                )
            if self.settings.get("system_mode") and self.settings.get("tor"):
                socks = _port(self.settings, "socks_port", 9050)
                deadline = time.time() + 12
                while time.time() < deadline and not port_open(socks):
                    time.sleep(0.4)

        errors: list[str] = []
        started = 0
        starters = {"dns": self.start_dns, "tor": self.start_tor, "i2p": self.start_i2p}
        for key in wanted:
            if key == "tor" and self.settings.get("system_mode"):
                if port_open(_port(self.settings, "socks_port", 9050)):
                    started += 1
                    self.log("Tor de sistema (tor.service) en marcha.")
                else:
                    errors.append("tor.service no abrió el puerto SOCKS.")
                    self.log(errors[-1])
                continue
            try:
                starters[key]()
                started += 1
            except RuntimeError as exc:
                errors.append(str(exc))
                self.log(str(exc))
        if started == 0:
            if self.needs_privilege():
                self.clear_privileged()
                self._privileged_applied = False
            raise RuntimeError("\n".join(errors) or "No se pudo iniciar ningún módulo.")

    def stop_all(self) -> None:
        self.kill_orphans()
        for key in ("i2p", "tor", "dns"):
            self.stop_module(key)
        if self._privileged_applied or self.privileged_dirty():
            self.clear_privileged()
            self._privileged_applied = False
        self._mark_priv(False)

    def kill_orphans(self) -> None:
        patterns = [
            str(CONFIG_DIR / "dnscrypt-proxy.toml"),
            str(CONFIG_DIR / "torrc"),
            str(CONFIG_DIR / "i2pd.conf"),
        ]
        mine = os.getpid()
        uid = os.getuid()
        for pattern in patterns:
            proc = subprocess.run(
                ["pgrep", "-u", str(uid), "-f", pattern],
                capture_output=True,
                text=True,
            )
            for line in (proc.stdout or "").split():
                try:
                    pid = int(line)
                except ValueError:
                    continue
                if pid in (0, mine) or not pid_alive(pid):
                    continue
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    continue
        time.sleep(0.3)
        for key in ("dnscrypt.pid", "tor.pid", "i2pd.pid"):
            path = RUNTIME_DIR / key
            pid = read_pid(path)
            if pid and pid_alive(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            path.unlink(missing_ok=True)

    def privileged_dirty(self) -> bool:
        if PRIV_LOCK.exists():
            return True
        root_lock = Path("/run/invizible-linux.lock")
        try:
            if root_lock.exists():
                return True
        except OSError:
            pass
        return self.firewall_active()

    def _mark_priv(self, active: bool) -> None:
        if active:
            PRIV_LOCK.parent.mkdir(parents=True, exist_ok=True)
            PRIV_LOCK.write_text("1\n", encoding="utf-8")
        else:
            PRIV_LOCK.unlink(missing_ok=True)

    def start_dns(self) -> None:
        binary = which("dnscrypt-proxy")
        if not binary:
            if self.settings.get("system_mode"):
                self.log("dnscrypt-proxy no está instalado: se usará DNS-over-TLS del sistema.")
                return
            raise RuntimeError("Falta dnscrypt-proxy. Instálalo con: " + install_hint_for(["dnscrypt-proxy"]))
        port = _port(self.settings, "listen_port", 5354)
        if port_open(port):
            self.log("DNSCrypt ya estaba en marcha.")
            return
        logfile = LOG_DIR / "dnscrypt.log"
        cfg = write_dnscrypt_toml(self.settings, logfile)
        self._spawn("dns", [binary, "-config", str(cfg)], RUNTIME_DIR / "dnscrypt.pid", logfile)
        self.log("DNSCrypt iniciado.")

    def start_tor(self) -> None:
        binary = which("tor")
        if not binary:
            raise RuntimeError("Falta tor. Instálalo con: " + install_hint_for(["tor"]))
        socks = _port(self.settings, "socks_port", 9050)
        write_pac(self.settings)
        if self.settings.get("system_mode"):
            self.log("Tor de sistema lo arranca el ayudante privilegiado.")
            return
        if port_open(socks):
            self.log("Tor ya estaba en marcha.")
            return
        datadir = DATA_HOME / "tor"
        datadir.mkdir(parents=True, exist_ok=True)
        logfile = LOG_DIR / "tor.log"
        pidfile = RUNTIME_DIR / "tor.pid"
        cfg = write_torrc(self.settings, datadir=datadir, pidfile=pidfile, logfile=logfile)
        self._spawn("tor", [binary, "-f", str(cfg)], pidfile, logfile)
        self.log("Tor iniciado. Esperando circuito…")

    def start_i2p(self) -> None:
        binary = which("i2pd")
        if not binary:
            raise RuntimeError("Falta i2pd. Instálalo con: " + install_hint_for(["i2pd"]))
        if port_open(_port(self.settings, "i2p_http_port", 4444)):
            self.log("I2P ya estaba en marcha.")
            return
        datadir = DATA_HOME / "i2pd"
        datadir.mkdir(parents=True, exist_ok=True)
        logfile = LOG_DIR / "i2pd.log"
        pidfile = RUNTIME_DIR / "i2pd.pid"
        cfg = write_i2pd_conf(self.settings, datadir=datadir, pidfile=pidfile, logfile=logfile)
        self._spawn(
            "i2p",
            [binary, f"--conf={cfg}", f"--datadir={datadir}", f"--pidfile={pidfile}"],
            pidfile,
            logfile,
        )
        self.log("I2P iniciado. La red P2P puede tardar unos minutos.")

    def stop_module(self, key: str) -> None:
        proc = self._procs.pop(key, None)
        pidfile = {
            "dns": RUNTIME_DIR / "dnscrypt.pid",
            "tor": RUNTIME_DIR / "tor.pid",
            "i2p": RUNTIME_DIR / "i2pd.pid",
        }[key]
        pid = None
        if proc and proc.poll() is None:
            pid = proc.pid
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        else:
            pid = read_pid(pidfile)
            if pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(0.4)
                    if pid_alive(pid):
                        os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        pidfile.unlink(missing_ok=True)
        self.log(f"Módulo {key} detenido.")

    def _spawn(self, key: str, cmd: list[str], pidfile: Path, logfile: Path) -> None:
        logfile.parent.mkdir(parents=True, exist_ok=True)
        log_handle = logfile.open("ab")
        proc = subprocess.Popen(
            cmd,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self._procs[key] = proc
        write_pid(pidfile, proc.pid)
        time.sleep(0.35)
        if proc.poll() not in (None, 0):
            raise RuntimeError(f"El proceso {cmd[0]} salió con código {proc.returncode}. Mira los registros.")

    def helper_path(self) -> Path:
        pkg_root = Path(__file__).resolve().parent.parent
        for cand in (
            pkg_root / "helper",
            Path("/usr/lib/invizible-linux/helper"),
            Path("/usr/local/lib/invizible-linux/helper"),
        ):
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        return Path(__file__).with_name("helper.py")

    def pkexec(self, *args: str) -> subprocess.CompletedProcess[str]:
        helper = self.helper_path()
        if helper.suffix == ".py":
            cmd = ["pkexec", "python3", str(helper), *args]
        else:
            cmd = ["pkexec", str(helper), *args]
        self.log("Solicitando privilegios: " + " ".join(args[:1]))
        return subprocess.run(cmd, text=True, capture_output=True)

    def install_bridges(self) -> str:
        from .distro import bridge_packages, detect, install_bridge_plugin

        if detect().family == "debian":
            pkgs = ",".join(bridge_packages())
            result = self.pkexec("install-packages", f"packages={pkgs}")
            if result.returncode != 0:
                raise RuntimeError((result.stderr or result.stdout or "cancelado").strip())
            return (result.stdout or "Plugin de puentes instalado.").strip()
        return install_bridge_plugin(self.log)

    def apply_privileged(self) -> bool:
        if not which("pkexec"):
            self.log("Sin pkexec: no se aplica cortafuegos ni DNS de sistema.")
            return False
        s = self.settings
        backend = (
            "tor"
            if s.get("tor") and s.get("route_all_tor")
            else "dnscrypt"
            if s.get("dns") and which("dnscrypt-proxy")
            else "dot-cloudflare"
        )
        flags = [
            f"dns={'1' if s.get('dns') else '0'}",
            f"tor={'1' if s.get('tor') else '0'}",
            f"allow_lan={'1' if s.get('allow_lan') else '0'}",
            f"block_ipv6={'1' if s.get('block_ipv6') else '0'}",
            f"kill_switch={'1' if s.get('kill_switch') else '0'}",
            f"route_all_tor={'1' if s.get('route_all_tor') and s.get('tor') else '0'}",
            f"prevent_dns_leak={'1' if s.get('prevent_dns_leak') else '0'}",
            f"block_http={'1' if s.get('block_http') else '0'}",
            f"exclude_udp={'1' if s.get('exclude_udp') else '0'}",
            f"block_stun={'1' if s.get('block_stun', True) else '0'}",
            f"block_mdns={'1' if s.get('block_mdns', True) else '0'}",
            f"block_llmnr={'1' if s.get('block_llmnr', True) else '0'}",
            f"ks_allow_dhcp={'1' if s.get('ks_allow_dhcp', True) else '0'}",
            f"ks_allow_ntp={'1' if s.get('ks_allow_ntp', True) else '0'}",
            f"ks_allow_captive={'1' if s.get('ks_allow_captive', True) else '0'}",
            f"block_lan_free_wifi={'1' if s.get('block_lan_free_wifi') else '0'}",
            "trusted_wifi=" + ",".join(x for x in str(s.get("trusted_wifi") or "").replace("\n", ",").split(",") if x.strip()),
            f"dns_port={_port(s, 'listen_port', 5354)}",
            f"tor_dns_port={_port(s, 'tor_dns_port', 5353)}",
            f"trans_port={_port(s, 'trans_port', 9040)}",
            f"apply_fw={'1' if s.get('firewall') or s.get('system_mode') else '0'}",
            f"set_dns={'1' if s.get('system_mode') else '0'}",
            f"refresh_rules={'1' if s.get('refresh_rules') else '0'}",
            f"start_tor={'1' if s.get('system_mode') and s.get('tor') else '0'}",
            f"backend={backend}",
        ]
        if s.get("system_mode") and s.get("tor"):
            cfg = write_system_torrc(s)
            flags.append(f"src={cfg}")
        result = self.pkexec("apply-all", *flags)
        if result.returncode != 0:
            self.log("Privilegios: " + (result.stderr or result.stdout or "cancelado").strip())
            self.push_event("Sin protección", (result.stderr or "pkexec cancelado").strip()[:180])
            return False
        self._privileged_applied = True
        self._mark_priv(True)
        self.log("Cortafuegos/DNS/IPv6 aplicados (un solo pkexec).")
        return True

    def clear_privileged(self) -> None:
        if not which("pkexec"):
            return
        result = self.pkexec("clear-all")
        if result.returncode != 0:
            self.log("Revertir: " + (result.stderr or result.stdout or "cancelado").strip())
            return
        self._mark_priv(False)
        self.log("Reglas de sistema revertidas.")

    def newnym(self) -> str:
        from .profiles import cookie_path, newnym

        port = _port(self.settings, "control_port", 9051)
        cookie = cookie_path() if cookie_path().is_file() else None
        try:
            msg = newnym(control_port=port, cookie=cookie)
        except (OSError, RuntimeError):
            msg = newnym(control_port=port, cookie=None)
        self.log(msg)
        return msg

    def firewall_active(self) -> bool:
        nft = which_bin("nft") or "nft"
        r = subprocess.run([nft, "list", "table", "inet", "invizible"], capture_output=True, text=True)
        return r.returncode == 0


def install_hint() -> str:
    return distro_install_hint()
