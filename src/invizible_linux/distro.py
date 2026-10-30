from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

BINARIES = {
    "tor": "tor",
    "dnscrypt-proxy": "dnscrypt-proxy",
    "i2pd": "i2pd",
}

# Paquetes permitidos (el ayudante root solo instala esta lista).
ALLOWED_PACKAGES = {
    "tor",
    "dnscrypt-proxy",
    "i2pd",
    "gtk4",
    "libadwaita",
    "python-gobject",
    "python-cairo",
    "python3-gi",
    "python3-gi-cairo",
    "python3-cairo",
    "python3-gobject",
    "gir1.2-gtk-4.0",
    "gir1.2-adw-1",
    "libgtk-4-1",
    "libadwaita-1-0",
    "obfs4proxy",
    "lyrebird",
    "snowflake-client",
    "snowflake",
    "snowflake-pt",
    "torsocks",
    "firejail",
    "bind",
    "bind-tools",
    "dnsutils",
    "ca-certificates",
    "nftables",
    "pkexec",
    "policykit-1",
    "rustc",
    "cargo",
    "rust",
    "go",
    "golang-go",
    "gcc",
    "lyrebird-proxy-git",
}

# Si el primero no existe en el índice, se prueba el siguiente.
PACKAGE_ALTERNATES: dict[str, dict[str, tuple[str, ...]]] = {
    "debian": {
        "lyrebird": ("lyrebird", "obfs4proxy"),
        "snowflake-client": ("snowflake-client", "snowflake"),
        "snowflake": ("snowflake-client", "snowflake"),
        "python-gobject": ("python3-gi",),
        "python-cairo": ("python3-cairo", "python3-gi-cairo"),
        "gtk4": ("gir1.2-gtk-4.0",),
        "libadwaita": ("gir1.2-adw-1",),
        "bind": ("bind9-dnsutils", "dnsutils"),
        "bind-tools": ("bind9-dnsutils", "dnsutils"),
        "pkexec": ("pkexec", "policykit-1"),
        "rust": ("rustc", "cargo"),
    },
}

EXTRA_BIN_DIRS = (
    Path("/usr/bin"),
    Path("/usr/sbin"),
    Path("/usr/local/bin"),
    Path("/usr/local/sbin"),
    Path("/usr/lib/snowflake"),
    Path("/usr/lib/lyrebird"),
    Path("/usr/lib/obfs4proxy"),
)

LYREBIRD_GO = (
    "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/cmd/lyrebird@latest"
)
SNOWFLAKE_GO = (
    "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/client@latest"
)

TOR_DAEMON_USERS = ("debian-tor", "tor", "_tor")

TEB_INDEX = "https://dist.torproject.org/torbrowser/"
TEB_BINARIES = ("tor", "lyrebird", "snowflake-client", "webtunnel-client", "conjure-client", "obfs4proxy", "meek-client")

_DEBIAN_IDS = {
    "debian",
    "ubuntu",
    "linuxmint",
    "pop",
    "raspbian",
    "kali",
    "neon",
    "zorin",
    "elementary",
    "mx",
    "devuan",
    "parrot",
    "pureos",
    "trisquel",
    "tails",
    "antix",
    "lmde",
}


@dataclass
class Distro:
    id: str
    name: str
    family: str  # arch, debian, fedora, suse, void, alpine, unknown
    pkg: str
    modules: list[str] = field(default_factory=list)
    gui: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)


def _os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return data
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        data[key] = value.strip().strip('"')
    return data


def _bin_search_path() -> str:
    dirs = [Path.home() / ".local" / "bin", Path.home() / ".cargo" / "bin", *EXTRA_BIN_DIRS]
    extra = os.pathsep.join(str(p) for p in dirs)
    return extra + os.pathsep + os.environ.get("PATH", "")


def which_bin(*names: str) -> str | None:
    """Como shutil.which, pero también mira /usr/sbin y ~/.local/bin (Debian oculta sbin)."""
    search = _bin_search_path()
    for name in names:
        found = shutil.which(name, path=search)
        if found:
            return found
        for directory in (Path.home() / ".local" / "bin", *EXTRA_BIN_DIRS):
            cand = directory / name
            if cand.is_file() and os.access(cand, os.X_OK):
                return str(cand)
    return None


def tor_daemon_user() -> str | None:
    try:
        import pwd
    except ImportError:
        return None
    for name in TOR_DAEMON_USERS:
        try:
            pwd.getpwnam(name)
            return name
        except KeyError:
            continue
    return None


def tor_uid() -> str | None:
    try:
        import pwd
    except ImportError:
        return None
    name = tor_daemon_user()
    if not name:
        return None
    try:
        return str(pwd.getpwnam(name).pw_uid)
    except KeyError:
        return None


def detect() -> Distro:
    info = _os_release()
    os_id = (info.get("ID") or "").lower()
    like = (info.get("ID_LIKE") or "").lower()
    name = info.get("PRETTY_NAME") or info.get("NAME") or os_id or "Linux"
    blob = f"{os_id} {like}"

    if os_id in {"arch", "manjaro", "endeavouros", "cachyos", "garuda", "artix"} or "arch" in like:
        return Distro(
            os_id or "arch",
            name,
            "arch",
            "pacman",
            ["tor", "dnscrypt-proxy", "i2pd"],
            ["gtk4", "libadwaita", "python-gobject", "python-cairo"],
            ["lyrebird", "torsocks"],
        )
    if os_id in _DEBIAN_IDS or "debian" in like or "ubuntu" in like:
        return Distro(
            os_id or "debian",
            name,
            "debian",
            "apt",
            ["tor", "dnscrypt-proxy", "i2pd"],
            ["python3-gi", "python3-gi-cairo", "gir1.2-gtk-4.0", "gir1.2-adw-1"],
            ["lyrebird", "torsocks"],
        )
    if os_id in {"fedora", "nobara", "rhel", "centos", "rocky", "almalinux"} or "fedora" in like or "rhel" in like:
        return Distro(
            os_id or "fedora",
            name,
            "fedora",
            "dnf",
            ["tor", "dnscrypt-proxy", "i2pd"],
            ["gtk4", "libadwaita", "python3-gobject"],
            [],
        )
    if "suse" in blob:
        return Distro(
            os_id or "opensuse",
            name,
            "suse",
            "zypper",
            ["tor", "dnscrypt-proxy", "i2pd"],
            ["gtk4", "libadwaita", "python3-gobject"],
            [],
        )
    if os_id == "void":
        return Distro(os_id, name, "void", "xbps", ["tor", "dnscrypt-proxy", "i2pd"], ["gtk4", "libadwaita", "python3-gobject"], [])
    if os_id == "alpine":
        return Distro(os_id, name, "alpine", "apk", ["tor", "dnscrypt-proxy", "i2pd"], ["gtk4", "libadwaita", "py3-gobject3"], [])
    return Distro(os_id or "unknown", name, "unknown", "", ["tor", "dnscrypt-proxy", "i2pd"], [], [])


def missing_binaries() -> list[str]:
    missing = []
    for pkg, binary in BINARIES.items():
        if not which_bin(binary):
            missing.append(pkg)
    return missing


def needed_packages(distro: Distro | None = None) -> list[str]:
    distro = distro or detect()
    needed = []
    for pkg in distro.modules:
        binary = BINARIES.get(pkg, pkg)
        if not which_bin(binary):
            needed.append(pkg)
    return needed


def bridge_packages(distro: Distro | None = None) -> list[str]:
    distro = distro or detect()
    if distro.family == "debian":
        return ["lyrebird"]
    return ["lyrebird"]


def needed_extra_packages(distro: Distro | None = None) -> list[str]:
    """Puentes y aislamiento que faltan: torsocks, lyrebird, snowflake y toolchain de oniux."""
    distro = distro or detect()
    if distro.family not in {"arch", "debian"}:
        return []
    needed: list[str] = []

    if not which_bin("torsocks"):
        needed.append("torsocks")

    need_go = False
    lyrebird = which_bin("lyrebird")
    snowflake = which_bin("snowflake-client", "snowflake")
    has_apt_lyrebird = distro.family == "debian" and _apt_has("lyrebird")
    if not lyrebird:
        if has_apt_lyrebird:
            needed.append("lyrebird")
        elif not which_bin("obfs4proxy"):
            if distro.family == "debian" and _apt_has("obfs4proxy"):
                needed.append("lyrebird")
            else:
                need_go = True
    if not lyrebird and not snowflake and not has_apt_lyrebird:
        need_go = True
    if distro.family == "debian" and not lyrebird and snowflake and str(snowflake).startswith("/usr/"):
        need_go = True
    if need_go and not which_bin("go"):
        needed.append("golang-go" if distro.family == "debian" else "go")

    if not which_bin("oniux"):
        if not which_bin("cargo"):
            needed.append("cargo" if distro.family == "debian" else "rust")
        if not which_bin("cc", "gcc", "clang"):
            needed.append("gcc")
    return needed


def rust_install_hint(distro: Distro | None = None) -> str:
    distro = distro or detect()
    if distro.family == "arch":
        return "sudo pacman -S rust"
    if distro.family == "debian":
        return "sudo apt install rustc cargo"
    if distro.family == "fedora":
        return "sudo dnf install rust cargo"
    return "instala rustc y cargo"


def _apt_has(pkg: str) -> bool:
    proc = subprocess.run(
        ["apt-cache", "policy", pkg],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return False
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Candidate:") and "(none)" not in stripped:
            return True
    return False


def resolve_install_names(packages: list[str], distro: Distro | None = None) -> list[str]:
    distro = distro or detect()
    alts = PACKAGE_ALTERNATES.get(distro.family, {})
    out: list[str] = []
    seen: set[str] = set()
    for pkg in packages:
        choices = alts.get(pkg, (pkg,))
        chosen = None
        if distro.family == "debian":
            chosen = next((name for name in choices if _apt_has(name)), None)
            if chosen is None:
                continue
        name = chosen or choices[0]
        if name not in ALLOWED_PACKAGES:
            continue
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def install_command(packages: list[str], distro: Distro | None = None) -> list[str]:
    distro = distro or detect()
    pkgs = resolve_install_names(packages, distro)
    if not pkgs:
        raise RuntimeError("No hay paquetes válidos para instalar.")
    if distro.family == "arch":
        return ["pacman", "-S", "--needed", "--noconfirm", "--", *pkgs]
    if distro.family == "debian":
        return ["bash", "-lc", "apt-get update && apt-get install -y -- " + " ".join(pkgs)]
    if distro.family == "fedora":
        return ["dnf", "install", "-y", "--", *pkgs]
    if distro.family == "suse":
        return ["zypper", "--non-interactive", "install", "--", *pkgs]
    if distro.family == "void":
        return ["xbps-install", "-Sy", "--", *pkgs]
    if distro.family == "alpine":
        return ["apk", "add", "--", *pkgs]
    raise RuntimeError(f"Gestor de paquetes no soportado ({distro.name}). Instala a mano: {', '.join(pkgs)}")


def install_hint(distro: Distro | None = None) -> str:
    distro = distro or detect()
    pkgs = needed_packages(distro) or distro.modules
    return install_hint_for(pkgs, distro)


def install_hint_for(packages: list[str], distro: Distro | None = None) -> str:
    distro = distro or detect()
    try:
        cmd = install_command(packages, distro)
        if cmd[0] == "bash":
            return "sudo " + cmd[2]
        return "sudo " + " ".join(cmd)
    except RuntimeError:
        return "Instala: " + " ".join(packages)


def install_as_root(packages: list[str]) -> str:
    distro = detect()
    cmd = install_command(packages, distro)
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    proc = subprocess.run(cmd, text=True, capture_output=True, env=env)
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode != 0:
        raise RuntimeError(out or f"Falló la instalación ({proc.returncode})")
    return out or "ok"


def _go_install_binary(module: str, dest_name: str, log) -> str:
    go = which_bin("go")
    if not go:
        distro = detect()
        if distro.family == "arch":
            raise RuntimeError("No hay Go. Instálalo con: sudo pacman -S go")
        raise RuntimeError("No hay Go. Instálalo con: sudo apt install golang-go")
    dest_dir = Path.home() / ".local" / "bin"
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="invizible-go-"))
    try:
        env = os.environ.copy()
        env["GOBIN"] = str(tmp)
        env["CGO_ENABLED"] = "0"
        proc = subprocess.run([go, "install", module], capture_output=True, text=True, env=env)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "go install falló").strip()[:500])
        produced = [p for p in tmp.iterdir() if p.is_file() and os.access(p, os.X_OK)]
        if not produced:
            raise RuntimeError(f"go install no dejó un binario para {dest_name}.")
        target = dest_dir / dest_name
        shutil.move(str(produced[0]), str(target))
        target.chmod(0o755)
        return str(target)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def install_bridge_plugin(log=lambda _msg: None) -> str:
    """Instala lyrebird y snowflake-client (en Arch, con Go; no uses el AUR lyrebird-proxy-git)."""
    bits: list[str] = []
    distro = detect()
    lyre = which_bin("lyrebird", "obfs4proxy")
    snowflake_pt = which_bin("lyrebird")
    snow = which_bin("snowflake-client", "snowflake")
    if distro.family == "debian" and not lyre:
        try:
            install_as_root(["lyrebird"])
        except RuntimeError as exc:
            log(str(exc))
        lyre = which_bin("lyrebird", "obfs4proxy")
    if not lyre:
        log("Compilando lyrebird (puentes obfs4)…")
        lyre = _go_install_binary(LYREBIRD_GO, "lyrebird", log)
    if not snowflake_pt and (not snow or str(snow).startswith("/usr/")):
        # El paquete de Debian (2.10.x) está roto como proxy gestionado de tor
        # y no entiende -utls-imitate: se compila el actual del repo de Tor a
        # ~/.local/bin, que además tiene prioridad en which_bin/find_pt.
        try:
            log("Compilando snowflake-client desde el repo de Tor (versión actual)…")
            built = _go_install_binary(SNOWFLAKE_GO, "snowflake-client", log)
            snow = built
        except RuntimeError as exc:
            log(f"Snowflake no se pudo compilar ({exc}); se usará el de la distro." if snow else str(exc))
    if lyre:
        bits.append(lyre)
    if snow:
        bits.append(snow)
    if not bits:
        raise RuntimeError("No se instaló ningún plugin de puentes.")
    try:
        install_tor_expert(log)
    except RuntimeError as exc:
        log(f"Tor Expert Bundle no instalado: {exc}")
    return "Instalado: " + ", ".join(bits)


def _gui_packages_missing(distro: Distro) -> list[str]:
    if distro.family not in {"arch", "debian"}:
        return []
    try:
        import gi

        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Adw, Gtk

        import cairo

        _ = Adw, Gtk, cairo
    except (ImportError, ValueError):
        return list(distro.gui)
    return []


def _teb_fetch(url: str, dest: Path | None = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "invizible-linux"})
    with urllib.request.urlopen(req, timeout=90) as resp:
        data = resp.read()
    if dest is not None:
        dest.write_bytes(data)
    return data


def install_tor_expert(log=lambda _m: None) -> Path:
    """Tor Expert Bundle de torproject.org: tor + PTs (lyrebird cubre
    snowflake/obfs4/webtunnel) de versiones emparejadas. Los managed PT del tor
    de algunas distros mueren al spawn (status 1); con el bundle funcionan."""
    from .config import DATA_HOME

    html = _teb_fetch(TEB_INDEX).decode()
    vers = sorted(
        set(re.findall(r'href="(\d+\.\d+\.\d+)/"', html)),
        key=lambda v: [int(x) for x in v.split(".")],
    )
    if not vers:
        raise RuntimeError("No se pudo leer el índice de versiones de torproject.org")
    ver = vers[-1]

    arch = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(
        platform.machine().lower()
    )
    if not arch:
        raise RuntimeError(f"Arquitectura no soportada: {platform.machine()}")
    name = f"tor-expert-bundle-linux-{arch}-{ver}.tar.gz"
    base = f"{TEB_INDEX}{ver}/"
    log(f"Tor Expert Bundle {ver} ({arch}): verificando checksum…")

    sums = _teb_fetch(base + "sha256sums-signed-build.txt").decode(errors="replace")
    expect = next((l.split()[0] for l in sums.splitlines() if l.strip().endswith(" " + name)), None)
    if not expect:
        raise RuntimeError(f"{name} no aparece en sha256sums-signed-build.txt")

    dest_dir = DATA_HOME / "tor-expert"
    dest_dir.mkdir(parents=True, exist_ok=True)
    tgz = dest_dir / name
    log(f"Descargando {name}…")
    _teb_fetch(base + name, tgz)
    if hashlib.sha256(tgz.read_bytes()).hexdigest() != expect:
        tgz.unlink(missing_ok=True)
        raise RuntimeError("SHA256 no coincide; descarga abortada por seguridad")

    target = dest_dir / ver
    if target.exists():
        try:
            shutil.rmtree(target)
        except PermissionError as exc:
            raise RuntimeError(
                f"No se puede escribir {target} (archivos de root). "
                "Vuelve a ejecutar la parte elevada del instalador."
            ) from exc
    target.mkdir(parents=True)
    with tarfile.open(tgz) as tf:
        tf.extractall(target, filter="data")
    subprocess.run(["chmod", "-R", "a+rX", str(target)], check=False)
    tgz.unlink(missing_ok=True)

    local_bin = Path.home() / ".local/bin"
    local_bin.mkdir(parents=True, exist_ok=True)
    linked: list[str] = []
    for path in target.rglob("*"):
        # El bundle trae también binarios de depuración (debug/tor): no son el ejecutable.
        if "debug" in path.parts:
            continue
        if path.name in TEB_BINARIES and path.is_file() and os.access(path, os.X_OK):
            link = local_bin / path.name
            link.unlink(missing_ok=True)
            link.symlink_to(path)
            linked.append(path.name)
    if "tor" not in linked:
        raise RuntimeError("El bundle no contiene el binario tor esperado")
    log(f"Tor Expert Bundle {ver}: {', '.join(sorted(set(linked)))} enlazados en ~/.local/bin")
    return target


def setup_system(*, use_pkexec: bool = True) -> int:
    distro = detect()
    missing = needed_packages(distro)
    extras = needed_extra_packages(distro)
    gui = _gui_packages_missing(distro)
    print(f"Sistema: {distro.name} ({distro.family or 'desconocido'})")
    pkgs = missing + [p for p in extras + gui if p not in missing]
    failed = False
    if pkgs:
        print("Falta: " + ", ".join(pkgs))
        print("Comando: " + install_hint_for(pkgs, distro))
        helper = Path(__file__).with_name("helper.py")
        if os.geteuid() != 0:
            if shutil.which("sudo"):
                command = ["sudo", "python3", str(helper)]
            elif use_pkexec and shutil.which("pkexec"):
                command = ["pkexec", "python3", str(helper)]
            else:
                command = []
            if command:
                proc = subprocess.run(
                    [*command, "install-packages", "packages=" + ",".join(pkgs)],
                    text=True,
                )
                if proc.returncode != 0:
                    print(f"La instalación elevada salió con {proc.returncode}; no se instalaron todos los paquetes.")
                    failed = True
            else:
                print("Hace falta sudo o pkexec para instalar paquetes.")
                failed = True
        else:
            try:
                print(install_as_root(pkgs))
            except RuntimeError as exc:
                print(exc)
                failed = True
    else:
        print("Ya están tor, dnscrypt-proxy e i2pd.")

    helper_ok = (
        (
            Path("/usr/local/lib/invizible-linux/invizible_linux/helper.py").is_file()
            or Path("/usr/lib/invizible-linux/invizible_linux/helper.py").is_file()
        )
        and Path("/usr/share/polkit-1/actions/net.invizible.Linux.policy").is_file()
    )
    if os.geteuid() != 0 and not helper_ok:
        root = Path(__file__).resolve().parents[2]
        print(
            "Sin helper de pkexec: cortafuegos, DNS de sistema y modo sistema no funcionarán.\n"
            f"Instálalo con: sudo {root / 'scripts' / 'setup-system.sh'} {root}"
        )

    # Lo que no exista como paquete se compila como el usuario
    # (lyrebird/snowflake con Go, oniux con cargo), igual que en Arch.
    if distro.family in {"arch", "debian"}:
        try:
            print(install_bridge_plugin(print))
        except RuntimeError as exc:
            print(exc)
        try:
            from .oniuxctl import install_oniux

            print(install_oniux(print))
        except RuntimeError as exc:
            print(exc)
    return 1 if failed else 0
