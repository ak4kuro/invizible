from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from invizible_linux.distro import (
    Distro,
    resolve_install_names,
    rust_install_hint,
    tor_daemon_user,
    which_bin,
)


def _debian() -> Distro:
    return Distro("debian", "Debian GNU/Linux", "debian", "apt")


class DistroTests(unittest.TestCase):
    def test_debian_lyrebird_falls_back_to_obfs4proxy(self) -> None:
        with patch("invizible_linux.distro._apt_has", side_effect=lambda pkg: pkg == "obfs4proxy"):
            names = resolve_install_names(["lyrebird"], _debian())
        self.assertEqual(names, ["obfs4proxy"])

    def test_debian_prefers_lyrebird_when_available(self) -> None:
        with patch("invizible_linux.distro._apt_has", side_effect=lambda pkg: pkg == "lyrebird"):
            names = resolve_install_names(["lyrebird"], _debian())
        self.assertEqual(names, ["lyrebird"])

    def test_debian_snowflake_client(self) -> None:
        with patch("invizible_linux.distro._apt_has", side_effect=lambda pkg: pkg == "snowflake-client"):
            names = resolve_install_names(["snowflake-client"], _debian())
        self.assertEqual(names, ["snowflake-client"])

    def test_lyrebird_avoids_snowflake_toolchain(self) -> None:
        from invizible_linux.distro import needed_extra_packages

        with (
            patch(
                "invizible_linux.distro.which_bin",
                side_effect=lambda *names: "/usr/bin/lyrebird" if "lyrebird" in names else None,
            ),
            patch("invizible_linux.distro._apt_has", return_value=False),
        ):
            needed = needed_extra_packages(_debian())
        self.assertNotIn("golang-go", needed)

    def test_debian_installs_lyrebird_even_if_obfs4proxy_exists(self) -> None:
        from invizible_linux.distro import needed_extra_packages

        with (
            patch(
                "invizible_linux.distro.which_bin",
                side_effect=lambda *names: "/usr/bin/obfs4proxy" if "obfs4proxy" in names else None,
            ),
            patch("invizible_linux.distro._apt_has", side_effect=lambda pkg: pkg == "lyrebird"),
        ):
            needed = needed_extra_packages(_debian())
        self.assertIn("lyrebird", needed)
        self.assertNotIn("golang-go", needed)

    def test_debian_system_snowflake_client_requests_current_build_toolchain(self) -> None:
        from invizible_linux.distro import needed_extra_packages

        with (
            patch(
                "invizible_linux.distro.which_bin",
                side_effect=lambda *names: (
                    "/usr/bin/snowflake-client" if "snowflake-client" in names else None
                ),
            ),
            patch("invizible_linux.distro._apt_has", return_value=False),
        ):
            needed = needed_extra_packages(_debian())
        self.assertIn("golang-go", needed)

    def test_rust_hint_debian(self) -> None:
        self.assertIn("apt", rust_install_hint(_debian()))

    def test_tor_user_prefers_debian_tor(self) -> None:
        def getpwnam(name: str):
            if name == "debian-tor":
                return SimpleNamespace(pw_uid=107, pw_name=name)
            raise KeyError(name)

        with patch("pwd.getpwnam", side_effect=getpwnam):
            self.assertEqual(tor_daemon_user(), "debian-tor")

    def test_tor_user_arch(self) -> None:
        def getpwnam(name: str):
            if name == "tor":
                return SimpleNamespace(pw_uid=43, pw_name=name)
            raise KeyError(name)

        with patch("pwd.getpwnam", side_effect=getpwnam):
            self.assertEqual(tor_daemon_user(), "tor")

    def test_which_bin_finds_explicit_file(self) -> None:
        self.assertTrue(callable(which_bin))

    def test_install_bridge_plugin_noop_if_present(self) -> None:
        from invizible_linux.distro import install_bridge_plugin

        with (
            patch("invizible_linux.distro.which_bin", return_value="/usr/bin/lyrebird"),
            patch("invizible_linux.distro.install_tor_expert", return_value="/tmp/teb"),
        ):
            msg = install_bridge_plugin()
        self.assertIn("/usr/bin/lyrebird", msg)

    def test_setup_uses_sudo_only_for_package_install(self) -> None:
        from invizible_linux.distro import setup_system

        proc = SimpleNamespace(returncode=0)
        with (
            patch("invizible_linux.distro.detect", return_value=_debian()),
            patch("invizible_linux.distro.needed_packages", return_value=["tor"]),
            patch("invizible_linux.distro.needed_extra_packages", return_value=[]),
            patch("invizible_linux.distro._gui_packages_missing", return_value=[]),
            patch("invizible_linux.distro.install_hint_for", return_value="sudo apt install tor"),
            patch("invizible_linux.distro.shutil.which", side_effect=lambda name: "/usr/bin/sudo" if name == "sudo" else None),
            patch("invizible_linux.distro.os.geteuid", return_value=1000),
            patch("invizible_linux.distro.subprocess.run", return_value=proc) as run,
            patch("invizible_linux.distro.install_bridge_plugin", return_value="ok"),
            patch("invizible_linux.oniuxctl.install_oniux", return_value="ok"),
        ):
            self.assertEqual(setup_system(), 0)
        self.assertEqual(run.call_args.args[0][:2], ["sudo", "python3"])
        self.assertEqual(run.call_args.args[0][-2:], ["install-packages", "packages=tor"])


if __name__ == "__main__":
    unittest.main()
