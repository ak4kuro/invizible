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
    ROOT_LOCK,
    RUNTIME_DIR,
    SYSTEM_TOR_FLAG,
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

LogFn = Callable[[str], None]

_PIDFILES = {
    "dns": "dnscrypt.pid",
    "tor": "tor.pid",
    "i2p": "i2pd.pid",
}

_PROC_BINARIES = {
    "dns": "dnscrypt-proxy",
    "tor": "tor",
    "i2p": "i2pd",
}


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
    try:
        if not path.exists():
            return ""
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
    occupied: bool = False
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
        line = f"[{stamp}] {message}"
        try:
            path = LOG_DIR / "app.log"
            if path.exists() and path.stat().st_size > 512 * 1024:
                path.write_bytes(path.read_bytes()[-256 * 1024 :])
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass
        self._log(line)

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
        dns_run = self._module_ours("dns")
        tor_run = self._module_ours("tor")
        i2p_run = self._module_ours("i2p")
        dns_occ = (not dns_run) and port_open(dns_port)
        tor_occ = (not tor_run) and port_open(socks)
        i2p_occ = (not i2p_run) and port_open(i2p_http)
        return {
            "dns": ModuleState(
                "dns",
                "DNSCrypt",
                "dnscrypt-proxy",
                running=dns_run,
                installed=dns,
                occupied=dns_occ,
                detail=self._dns_detail(dns, dns_run, dns_occ),
                log_path=LOG_DIR / "dnscrypt.log",
                extra={"proxy": f"127.0.0.1:{dns_port}"},
            ),
            "tor": ModuleState(
                "tor",
                "Tor",
                "tor",
                running=tor_run,
                installed=tor,
                occupied=tor_occ,
                detail=self._tor_detail(tor, tor_run, tor_occ),
                log_path=LOG_DIR / "tor.log",
                extra={"socks": f"127.0.0.1:{socks}", "trans": f"127.0.0.1:{_port(self.settings, 'trans_port', 9040)}"},
            ),
            "i2p": ModuleState(
                "i2p",
                "I2P",
                "i2pd",
                running=i2p_run,
                installed=i2p,
                occupied=i2p_occ,
                detail=self._i2p_detail(i2p, i2p_run, i2p_occ),
                log_path=LOG_DIR / "i2pd.log",
                extra={"http": f"127.0.0.1:{i2p_http}", "socks": f"127.0.0.1:{_port(self.settings, 'i2p_socks_port', 4447)}"},
            ),
        }

    def _dns_detail(self, installed: bool, running: bool, occupied: bool = False) -> str:
        if not installed:
            return "No instalado"
        if running:
            return f"DNS cifrado en 127.0.0.1:{_port(self.settings, 'listen_port', 5354)}"
        if occupied:
            return f"Puerto {_port(self.settings, 'listen_port', 5354)} ocupado (otro proceso)"
        return "Detenido"

    def _bootstrap_text(self, path: Path) -> str:
        # En modo sistema tor@default loggea a journald: el usuario (grupo
        # adm/systemd-journal) lo lee sin privilegios. La ruta de fichero solo
        # vale para el tor de usuario.
        if path == SYSTEM_TOR_LOG:
            try:
                out = subprocess.run(
                    ["journalctl", "-u", "tor@default", "-n", "120", "--no-pager", "-o", "cat"],
                    capture_output=True, text=True, timeout=3,
                ).stdout
                log = out[-8000:] if out else ""
            except (OSError, subprocess.SubprocessError):
                log = ""
        else:
            log = tail(path, 80)
        if "Bootstrapped 100%" in log:
            return "Tor en marcha (100%)"
        import re

        for line in reversed(log.splitlines()):
            match = re.search(r"Bootstrapped (\d+)%\s*\(([^)]+)\)", line)
            if match:
                return f"bootstrap {match.group(1)}% ({match.group(2)})"
        return ""

    def _tor_detail(self, installed: bool, running: bool, occupied: bool = False) -> str:
        if not installed:
            return "No instalado"
        if not running:
            if occupied:
                return f"Puerto {_port(self.settings, 'socks_port', 9050)} ocupado (¿tor.service?)"
            return "Detenido"
        system = bool(self.settings.get("system_mode") or self._system_tor_ours())
        boot = self._bootstrap_text(SYSTEM_TOR_LOG if system else LOG_DIR / "tor.log")
        if boot:
            return ("tor.service · " + boot) if system else boot
        if system:
            return "tor.service · arrancando…"
        return "Tor arrancando…"

    def _i2p_detail(self, installed: bool, running: bool, occupied: bool = False) -> str:
        if not installed:
            return "No instalado"
        if running:
            return f"Proxy HTTP 127.0.0.1:{_port(self.settings, 'i2p_http_port', 4444)}"
        if occupied:
            return f"Puerto {_port(self.settings, 'i2p_http_port', 4444)} ocupado (otro proceso)"
        return "Detenido"

    def _config_pattern(self, key: str) -> str:
        return {
            "dns": str(CONFIG_DIR / "dnscrypt-proxy.toml"),
            "tor": str(CONFIG_DIR / "torrc"),
            "i2p": str(CONFIG_DIR / "i2pd.conf"),
        }[key]

    def _comm_of(self, pid: int) -> str:
        try:
            return Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def _pid_is_module(self, pid: int, key: str) -> bool:
        # comm se trunca a 15 chars; ninguno de los nombres supera ese límite.
        return self._comm_of(pid) == _PROC_BINARIES[key]

    def _pids_for_config(self, key: str) -> list[int]:
        pattern = self._config_pattern(key)
        mine = os.getpid()
        uid = os.getuid()
        proc = subprocess.run(
            ["pgrep", "-u", str(uid), "-f", pattern],
            capture_output=True,
            text=True,
        )
        pids: list[int] = []
        for line in (proc.stdout or "").split():
            try:
                pid = int(line)
            except ValueError:
                continue
            if pid in (0, mine) or not pid_alive(pid):
                continue
            if not self._pid_is_module(pid, key):
                continue
            pids.append(pid)
        return pids

    def _system_tor_ours(self) -> bool:
        """Solo cuenta tor.service si esta sesión lo aplicó (PRIV_LOCK)."""
        try:
            return SYSTEM_TOR_FLAG.exists() and PRIV_LOCK.exists()
        except OSError:
            return False

    def _module_ours(self, key: str) -> bool:
        if key == "tor" and self._system_tor_ours() and port_open(_port(self.settings, "socks_port", 9050)):
            return True
        proc = self._procs.get(key)
        if proc is not None and proc.poll() is None:
            return True
        pid = read_pid(RUNTIME_DIR / _PIDFILES[key])
        if pid is not None and self._pid_is_module(pid, key):
            return True
        return bool(self._pids_for_config(key))

    def _port_is_ours(self, key: str) -> bool:
        return self._module_ours(key)

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
        s = self.settings
        # prevent_dns_leak solo tiene sentido si el DNS del sistema se cambia:
        # activarlo sin modo sistema/cortafuegos no hacía nada y el resolver
        # seguía siendo el del router (fuga DNS real).
        return bool(s.get("system_mode") or s.get("firewall") or s.get("prevent_dns_leak"))

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

        errors: list[str] = []
        started = 0
        starters = {"dns": self.start_dns, "tor": self.start_tor, "i2p": self.start_i2p}
        # 1) Daemons de usuario primero: el DNS del sistema solo se cambia
        # cuando el servicio que lo va a atender ya está escuchando. Antes se
        # aplicaba apply-all primero y si dnscrypt moría el DNS quedaba
        # apuntando a un puerto muerto (síntoma: «sin internet»).
        for key in wanted:
            if key == "tor" and self.settings.get("system_mode"):
                continue
            try:
                starters[key]()
                started += 1
            except RuntimeError as exc:
                errors.append(str(exc))
                self.log(str(exc))
        if self.settings.get("dns") and "dns" in wanted:
            dns_port = _port(self.settings, "listen_port", 5354)
            deadline = time.time() + 15
            while time.time() < deadline and not port_open(dns_port):
                time.sleep(0.4)
            if not port_open(dns_port):
                self.kill_orphans()
                raise RuntimeError(
                    "dnscrypt-proxy no abrió el puerto DNS. Se aborta sin tocar el DNS del sistema."
                )
        # 2) Con los servicios vivos se aplican privilegios (nft, DNS, tor.service).
        if self.needs_privilege():
            ok = self.apply_privileged()
            if not ok:
                self.kill_orphans()
                self.push_event("Sin protección", "pkexec cancelado o falló. No se han iniciado módulos.")
                raise RuntimeError(
                    "Se canceló o falló pkexec. No se han iniciado módulos (fallo cerrado: sin cortafuegos no hay arranque)."
                )
            if self.settings.get("system_mode") and self.settings.get("tor"):
                socks = _port(self.settings, "socks_port", 9050)
                deadline = time.time() + 12
                while time.time() < deadline and not port_open(socks):
                    time.sleep(0.4)
                if port_open(socks):
                    started += 1
                    self.log("Tor de sistema (tor.service) en marcha.")
                else:
                    errors.append("tor.service no abrió el puerto SOCKS.")
                    self.log(errors[-1])
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
        targets: set[int] = set()
        for key in ("dns", "tor", "i2p"):
            targets.update(self._pids_for_config(key))
        for key, name in _PIDFILES.items():
            pid = read_pid(RUNTIME_DIR / name)
            if pid is not None and self._pid_is_module(pid, key):
                targets.add(pid)
        for pid in targets:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                continue
        deadline = time.time() + 4
        remaining = {pid for pid in targets if pid_alive(pid)}
        while remaining and time.time() < deadline:
            time.sleep(0.2)
            remaining = {pid for pid in remaining if pid_alive(pid)}
        for pid in remaining:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        for name in _PIDFILES.values():
            (RUNTIME_DIR / name).unlink(missing_ok=True)

    def privileged_dirty(self) -> bool:
        if PRIV_LOCK.exists():
            return True
        try:
            if ROOT_LOCK.exists() or SYSTEM_TOR_FLAG.exists():
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
            if self._port_is_ours("dns"):
                self.log("DNSCrypt ya estaba en marcha.")
                return
            raise RuntimeError(
                f"El puerto DNS {port} está ocupado por otro proceso. "
                "Detén dnscrypt-proxy del sistema o cambia el puerto en Ajustes."
            )
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
        datadir = DATA_HOME / "tor"
        datadir.mkdir(parents=True, exist_ok=True)
        logfile = LOG_DIR / "tor.log"
        pidfile = RUNTIME_DIR / "tor.pid"
        # PTs externos: el spawn gestionado de tor mata los proxies en este
        # sistema; lanzándolos nosotros, tor conecta por SOCKS y listo. Vale
        # igual para modo sistema (las líneas van al drop-in de tor.service).
        ext = self._spawn_bridge_pts()
        cfg = write_torrc(self.settings, datadir=datadir, pidfile=pidfile, logfile=logfile, external_pts=ext)
        if self.settings.get("system_mode"):
            self.log("Tor de sistema lo arranca el ayudante privilegiado.")
            return
        if port_open(socks):
            if self._port_is_ours("tor"):
                self.log("Tor ya estaba en marcha.")
                return
            raise RuntimeError(
                f"El puerto SOCKS {socks} está ocupado (suele ser tor.service de Debian). "
                "Deténlo con: sudo systemctl stop tor "
                "o activa «Ejecutar módulos como superusuario»."
            )
        self._spawn("tor", [binary, "-f", str(cfg)], pidfile, logfile)
        self.log("Tor iniciado. Esperando circuito…")

    def _spawn_bridge_pts(self) -> dict[str, str]:
        """Lanza los transportes en modo externo y devuelve kind -> 'host:port'
        leído del protocolo CMETHOD en su stdout/log."""
        from .confgen import find_pt, resolve_bridges

        mode, bridges, _warn = resolve_bridges(self.settings)
        if mode == "none" or not bridges:
            return {}
        kinds = {b.split()[0].lower() for b in bridges if b.split()}
        candidates = {
            "snowflake": ("lyrebird", "snowflake-client", "snowflake"),
            "obfs4": ("lyrebird", "obfs4proxy"),
            "meek_lite": ("lyrebird", "obfs4proxy", "meek-client"),
        }
        self._ext_pt_procs = getattr(self, "_ext_pt_procs", [])
        out: dict[str, str] = {}
        for kind in kinds & set(candidates):
            binary = next((p for p in (find_pt(n) for n in candidates[kind]) if p), None)
            if not binary:
                self.log(f"Sin binario para el transporte {kind}.")
                continue
            statedir = DATA_HOME / "pt-state" / kind
            statedir.mkdir(parents=True, exist_ok=True)
            logfile = LOG_DIR / f"{kind}-pt.log"
            env = os.environ.copy()
            env.update({
                "TOR_PT_MANAGED_TRANSPORT_VER": "1",
                "TOR_PT_CLIENT_TRANSPORTS": kind,
                "TOR_PT_STATE_LOCATION": str(statedir),
            })
            handle = logfile.open("wb")
            try:
                proc = subprocess.Popen(
                    [binary], stdout=handle, stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL, start_new_session=True, env=env,
                )
            except OSError:
                handle.close()
                continue
            (RUNTIME_DIR / f"pt-{kind}.pid").write_text(str(proc.pid), encoding="utf-8")
            addr = None
            deadline = time.time() + 12
            while time.time() < deadline and proc.poll() is None:
                time.sleep(0.3)
                try:
                    m = re.search(rf"CMETHOD {kind} socks5 (\S+:\d+)", logfile.read_text(errors="replace"))
                except OSError:
                    m = None
                if m:
                    addr = m.group(1)
                    break
            if addr:
                self._ext_pt_procs.append((proc, handle))
                out[kind] = addr
                self.log(f"Transporte {kind} listo en {addr}.")
            else:
                proc.kill()
                handle.close()
                self.log(f"El transporte {kind} no anunció su SOCKS; mira {logfile.name}.")
        return out

    def start_i2p(self) -> None:
        binary = which("i2pd")
        if not binary:
            raise RuntimeError("Falta i2pd. Instálalo con: " + install_hint_for(["i2pd"]))
        i2p_http = _port(self.settings, "i2p_http_port", 4444)
        if port_open(i2p_http):
            if self._port_is_ours("i2p"):
                self.log("I2P ya estaba en marcha.")
                return
            raise RuntimeError(
                f"El puerto HTTP {i2p_http} está ocupado por otro proceso (¿i2pd.service?). "
                "Detén el servicio del sistema o cambia el puerto en Ajustes."
            )
        # AppArmor (perfil usr.bin.i2pd de Debian) solo deja escribir en
        # ~/.i2pd y /var/lib/i2pd: datadir, log y pidfile van dentro de ~/.i2pd.
        datadir = Path.home() / ".i2pd"
        datadir.mkdir(parents=True, exist_ok=True)
        logfile = datadir / "i2pd.log"
        pidfile = datadir / "i2pd.pid"
        cfg = write_i2pd_conf(self.settings, datadir=datadir, pidfile=pidfile, logfile=logfile)
        self._spawn(
            "i2p",
            [binary, f"--conf={cfg}", f"--datadir={datadir}", f"--pidfile={pidfile}"],
            RUNTIME_DIR / "i2pd.pid",
            logfile,
        )
        self.log("I2P iniciado. La red P2P puede tardar unos minutos.")

    def stop_module(self, key: str) -> None:
        proc = self._procs.pop(key, None)
        pidfile = RUNTIME_DIR / _PIDFILES[key]
        stopped = False
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            stopped = True
        else:
            pid = read_pid(pidfile)
            if pid is not None and not self._pid_is_module(pid, key):
                pid = None
            pids = [pid] if pid else self._pids_for_config(key)
            for target in pids:
                try:
                    os.kill(target, signal.SIGTERM)
                except OSError:
                    continue
                deadline = time.time() + 5
                while pid_alive(target) and time.time() < deadline:
                    time.sleep(0.2)
                if pid_alive(target):
                    try:
                        os.kill(target, signal.SIGKILL)
                    except OSError:
                        pass
                stopped = True
        pidfile.unlink(missing_ok=True)
        labels = {"dns": "DNSCrypt", "tor": "Tor", "i2p": "I2P"}
        name = labels.get(key, key)
        if stopped:
            self.log(f"{name} detenido.")
        else:
            self.log(f"{name} no tenía un proceso propio que detener.")

    def _spawn(self, key: str, cmd: list[str], pidfile: Path, logfile: Path) -> None:
        logfile.parent.mkdir(parents=True, exist_ok=True)
        log_handle = logfile.open("ab")
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        finally:
            log_handle.close()
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
        # Sin modo sistema, Tor y DNSCrypt corren como el usuario: no se pueden
        # eximir en nftables. Redirigir todo a Tor crearía un bucle (Tor se
        # transproxya a sí mismo) y el kill-switch cortaría también a los
        # módulos. En ambos casos el resultado es "no conecta nada".
        route_all = bool(s.get("route_all_tor") and s.get("tor") and s.get("system_mode"))
        if s.get("route_all_tor") and s.get("tor") and not s.get("system_mode"):
            self.log(
                "«Todo el tráfico por Tor» necesita el modo sistema (tor.service); "
                "sin él, el propio Tor entraría en bucle. Se ignora."
            )
        kill_switch = bool(s.get("kill_switch"))
        if kill_switch and not (s.get("system_mode") and s.get("tor")):
            kill_switch = False
            self.log("Kill-switch desactivado: fuera del modo sistema cortaría también a Tor/DNSCrypt.")
        backend = (
            "tor"
            if s.get("tor") and route_all
            else "dnscrypt"
            if s.get("dns") and which("dnscrypt-proxy")
            else "dot-cloudflare"
        )
        flags = [
            f"dns={'1' if s.get('dns') else '0'}",
            f"tor={'1' if s.get('tor') else '0'}",
            f"allow_lan={'1' if s.get('allow_lan') else '0'}",
            f"block_ipv6={'1' if s.get('block_ipv6') else '0'}",
            f"kill_switch={'1' if kill_switch else '0'}",
            f"route_all_tor={'1' if route_all else '0'}",
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
            "bootstrap_resolvers="
            + ",".join(
                x.strip() for x in str(s.get("bootstrap_resolvers") or "9.9.9.9, 8.8.8.8").split(",") if x.strip()
            ),
            f"apply_fw={'1' if s.get('firewall') or s.get('system_mode') else '0'}",
            f"set_dns={'1' if s.get('system_mode') or s.get('prevent_dns_leak') else '0'}",
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
        if self._system_tor_ours() and which("pkexec"):
            # La cookie de tor.service está en /var/lib/tor; la lee el ayudante.
            result = self.pkexec("newnym", f"port={port}")
            msg = (result.stdout or result.stderr or "NEWNYM falló").strip().splitlines()[-1]
            self.log(msg)
            return msg
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
        if r.returncode == 0:
            return True
        # Sin CAP_NET_ADMIN nft responde EPERM; los candados del ayudante son la señal secundaria.
        try:
            return PRIV_LOCK.exists() or ROOT_LOCK.exists() or SYSTEM_TOR_FLAG.exists()
        except OSError:
            return False


def install_hint() -> str:
    return distro_install_hint()
