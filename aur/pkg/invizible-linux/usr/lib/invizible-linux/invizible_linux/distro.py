from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
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
        if distro.family == "debian" and len(choices) > 1:
            chosen = next((name for name in choices if _apt_has(name)), None)
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
    snow = which_bin("snowflake-client", "snowflake")
    if distro.family == "debian" and not lyre:
        install_as_root(["lyrebird"])
        lyre = which_bin("lyrebird", "obfs4proxy")
    if distro.family == "debian" and not snow:
        try:
            install_as_root(["snowflake-client"])
        except RuntimeError as exc:
            log(str(exc))
        snow = which_bin("snowflake-client", "snowflake")
    if not lyre:
        log("Compilando lyrebird (puentes obfs4)…")
        lyre = _go_install_binary(LYREBIRD_GO, "lyrebird", log)
    if not snow:
        try:
            log("Compilando snowflake-client…")
            snow = _go_install_binary(SNOWFLAKE_GO, "snowflake-client", log)
        except RuntimeError as exc:
            log(f"Snowflake no se pudo instalar: {exc}")
    if lyre:
        bits.append(lyre)
    if snow:
        bits.append(snow)
    if not bits:
        raise RuntimeError("No se instaló ningún plugin de puentes.")
    return "Instalado: " + ", ".join(bits)


def setup_system(*, use_pkexec: bool = True) -> int:
    distro = detect()
    missing = needed_packages(distro)
    print(f"Sistema: {distro.name} ({distro.family or 'desconocido'})")
    if not missing:
        print("Ya está instalado tor, dnscrypt-proxy e i2pd.")
        return 0
    print("Falta: " + ", ".join(missing))
    print("Comando: " + install_hint(distro))
    helper = Path(__file__).with_name("helper.py")
    if use_pkexec and shutil.which("pkexec") and os.geteuid() != 0:
        proc = subprocess.run(
            ["pkexec", "python3", str(helper), "install-packages", "packages=" + ",".join(missing)],
            text=True,
        )
        return proc.returncode
    if os.geteuid() != 0:
        print("Hace falta root o pkexec.")
        return 2
    print(install_as_root(missing))
    return 0
