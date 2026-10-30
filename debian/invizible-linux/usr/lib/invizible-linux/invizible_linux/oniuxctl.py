from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from .config import LOG_DIR, ensure_dirs
from .distro import rust_install_hint, which_bin

ONIUX_GIT = "https://gitlab.torproject.org/tpo/core/oniux.git"
LogFn = Callable[[str], None]


def _cargo_bin() -> Path:
    return Path.home() / ".cargo" / "bin"


def ensure_cargo_path() -> None:
    cargo = _cargo_bin()
    if cargo.is_dir():
        os.environ["PATH"] = str(cargo) + os.pathsep + os.environ.get("PATH", "")


def oniux_binary() -> str | None:
    ensure_cargo_path()
    found = which_bin("oniux")
    if found:
        return found
    candidate = _cargo_bin() / "oniux"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


def tun_ok() -> bool:
    return Path("/dev/net/tun").exists()


def userns_ok() -> bool:
    path = Path("/proc/sys/kernel/unprivileged_userns_clone")
    if not path.exists():
        return True
    try:
        return path.read_text(encoding="utf-8").strip() != "0"
    except OSError:
        return True


def isolation_mode() -> str:
    if oniux_binary() and tun_ok() and userns_ok():
        return "oniux"
    if shutil.which("torsocks"):
        return "torsocks"
    if shutil.which("firejail") and shutil.which("torsocks"):
        return "firejail"
    if shutil.which("firejail"):
        return "firejail"
    return "proxy"


def isolation_label() -> str:
    return {
        "oniux": "oniux (todo el tráfico por Tor)",
        "torsocks": "torsocks (puede fugar: DNS o hilos)",
        "firejail": "firejail --torsocks (puede fugar)",
        "proxy": "ALL_PROXY (navegadores suelen ignorarlo)",
    }.get(isolation_mode(), "proxy")


def isolation_short() -> str:
    return {
        "oniux": "oniux",
        "torsocks": "torsocks (puede fugar)",
        "firejail": "firejail (puede fugar)",
        "proxy": "solo proxy env",
    }.get(isolation_mode(), "proxy")


def status_text() -> str:
    binary = oniux_binary()
    bits = []
    if binary:
        bits.append(f"oniux: {binary}")
    else:
        bits.append("oniux no está instalado")
    bits.append("TUN OK" if tun_ok() else "Falta /dev/net/tun (modprobe tun)")
    bits.append("userns OK" if userns_ok() else "user namespaces desactivados")
    bits.append("aislamiento: " + isolation_label())
    return " · ".join(bits)


def strip_desktop_fields(commandline: str) -> list[str]:
    cleaned = re.sub(r"\s*%[fFuUdDnNickvm]", "", commandline or "")
    try:
        parts = shlex.split(cleaned)
    except ValueError:
        parts = cleaned.split()
    return [p for p in parts if p]


def launch_app(
    commandline: str,
    through_tor: bool,
    log: LogFn | None = None,
    socks_port: int = 9050,
    isolation: str = "",
    socks_user: str = "",
) -> subprocess.Popen:
    ensure_dirs()
    argv = strip_desktop_fields(commandline)
    if not argv:
        raise RuntimeError("No hay comando para lanzar.")
    env = os.environ.copy()
    note = log or (lambda _m: None)
    if through_tor and isolation == "lax":
        user = socks_user or "invizible"
        env["TORSOCKS_USERNAME"] = user
        env["TORSOCKS_PASSWORD"] = "invizible"
        proxy = f"socks5://{user}:invizible@127.0.0.1:{socks_port}"
        if shutil.which("torsocks"):
            argv = ["torsocks", "-a", "127.0.0.1", "-P", str(socks_port), *argv]
            note("torsocks laxo (IsolateSOCKSAuth) " + " ".join(argv[4:]))
        else:
            env["ALL_PROXY"] = proxy
            env["all_proxy"] = proxy
            note(f"SOCKS laxo {proxy} " + " ".join(argv))
        logfile = (LOG_DIR / "oniux.log").open("ab")
        return subprocess.Popen(
            argv,
            stdout=logfile,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=env,
        )
    if through_tor:
        mode = isolation_mode()
        proxy = f"socks5://127.0.0.1:{socks_port}"
        if mode == "oniux":
            # --no-private-tmp: sin él oniux monta un /tmp privado que oculta
            # /tmp/.X11-unix y las apps gráficas mueren con "cannot open display".
            argv = [oniux_binary() or "oniux", "--no-private-tmp", *argv]
            note("oniux " + " ".join(argv[1:]))
        elif mode == "torsocks":
            argv = ["torsocks", "-a", "127.0.0.1", "-P", str(socks_port), *argv]
            note("torsocks " + " ".join(argv[4:]))
        elif mode == "firejail":
            argv = ["firejail", "--quiet", "--torsocks", *argv]
            env["TORSOCKS_TOR_ADDRESS"] = "127.0.0.1"
            env["TORSOCKS_TOR_PORT"] = str(socks_port)
            note("firejail --torsocks " + " ".join(argv[3:]))
        else:
            env["ALL_PROXY"] = proxy
            env["all_proxy"] = proxy
            env["HTTP_PROXY"] = proxy
            env["HTTPS_PROXY"] = proxy
            env["http_proxy"] = proxy
            env["https_proxy"] = proxy
            note(f"ALL_PROXY={proxy} " + " ".join(argv))
    else:
        note("directo " + " ".join(argv))
    logfile = (LOG_DIR / "oniux.log").open("ab")
    return subprocess.Popen(
        argv,
        stdout=logfile,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=env,
    )


def _run(cmd: list[str], log: LogFn, env: dict[str, str] | None = None) -> None:
    log("$ " + " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env or os.environ.copy(),
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        text = line.rstrip()
        if text:
            log(text)
    code = proc.wait()
    if code != 0:
        raise RuntimeError(f"Falló ({code}): {' '.join(cmd)}")


def _yay_cache_pkg(name: str) -> Path | None:
    cache = Path.home() / ".cache" / "yay" / name
    pkgs = [
        p
        for p in sorted(cache.glob(f"{name}-*.pkg.tar.zst"))
        if "-debug-" not in p.name
    ]
    return pkgs[-1] if pkgs else None


def _pacman_u_local(pkg: Path, log: LogFn) -> None:
    """Instala un paquete local si pacman exige .sig y el AUR no lo firma."""
    src = Path("/etc/pacman.conf").read_text(encoding="utf-8")
    patched = [
        "LocalFileSigLevel = Optional\n" if line.startswith("LocalFileSigLevel") else line
        for line in src.splitlines(True)
    ]
    fd, tmp = tempfile.mkstemp(prefix="pacman-local-", suffix=".conf")
    os.close(fd)
    tmp_path = Path(tmp)
    try:
        tmp_path.write_text("".join(patched), encoding="utf-8")
        log(
            "pacman exige firma en paquetes locales; esta orden usa "
            "LocalFileSigLevel=Optional y no cambia /etc/pacman.conf."
        )
        _run(
            ["sudo", "pacman", "--config", str(tmp_path), "-U", "--needed", "--noconfirm", str(pkg)],
            log,
        )
    finally:
        tmp_path.unlink(missing_ok=True)


def install_oniux(log: LogFn) -> str:
    """Instala oniux como el usuario (AUR/cargo). pacman -U pedirá sudo."""
    ensure_cargo_path()
    if oniux_binary():
        return f"Ya está: {oniux_binary()}"

    env = os.environ.copy()
    env["PATH"] = str(_cargo_bin()) + os.pathsep + env.get("PATH", "")
    env.setdefault("CARGO_TERM_COLOR", "never")

    yay = shutil.which("yay") or shutil.which("paru")
    if yay:
        log(f"Instalando oniux con {Path(yay).name} (AUR)…")
        try:
            _run([yay, "-S", "--needed", "--noconfirm", "oniux"], log, env)
        except RuntimeError as exc:
            log(str(exc))
            cached = _yay_cache_pkg("oniux")
            if cached is not None:
                log(f"Instalando el paquete ya compilado: {cached.name}")
                try:
                    _pacman_u_local(cached, log)
                except RuntimeError as exc2:
                    log(str(exc2))
            if oniux_binary() is None:
                log("El AUR falló; se intenta con cargo.")
        ensure_cargo_path()
        if oniux_binary():
            return f"Instalado: {oniux_binary()}"

    cargo = shutil.which("cargo")
    if not cargo:
        rustup = shutil.which("rustup")
        if not rustup:
            log("Instalando Rust (rustup) en tu usuario…")
            installer = subprocess.run(
                ["curl", "--proto", "=https", "--tlsv1.2", "-sSf", "https://sh.rustup.rs"],
                capture_output=True,
            )
            if installer.returncode != 0:
                raise RuntimeError(
                    f"No hay cargo ni rustup. Instala Rust ({rust_install_hint()}) y vuelve a pulsar Instalar oniux."
                )
            proc = subprocess.run(
                ["sh", "-s", "--", "-y", "--default-toolchain", "stable"],
                input=installer.stdout,
                capture_output=True,
            )
            if proc.returncode != 0:
                raise RuntimeError((proc.stderr or proc.stdout or b"").decode("utf-8", errors="replace"))
            ensure_cargo_path()
            cargo = shutil.which("cargo")
        else:
            _run([rustup, "default", "stable"], log, env)
            ensure_cargo_path()
            cargo = shutil.which("cargo")
    if not cargo:
        raise RuntimeError("No se encontró cargo después de instalar Rust.")

    log("Compilando oniux (puede tardar varios minutos)…")
    _run(
        [
            cargo,
            "install",
            "--locked",
            "--git",
            ONIUX_GIT,
            "oniux",
        ],
        log,
        env,
    )
    ensure_cargo_path()
    found = oniux_binary()
    if not found:
        raise RuntimeError("cargo terminó pero no aparece el binario oniux.")
    return f"Instalado: {found}"
