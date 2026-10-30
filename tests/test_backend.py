from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from invizible_linux import leaks
from invizible_linux.backend import Controller
from invizible_linux.config import SYSTEM_TOR_LOG


def _settings(**overrides):
    base = {
        "listen_port": 5354,
        "socks_port": 9050,
        "i2p_http_port": 4444,
        "i2p_socks_port": 4447,
        "trans_port": 9040,
        "system_mode": False,
        "firewall": False,
    }
    base.update(overrides)
    return base


def _controller():
    with (
        patch("invizible_linux.backend.ensure_dirs"),
        patch("invizible_linux.backend.load_settings", return_value=_settings()),
    ):
        return Controller(log=lambda _msg: None)


class SnapshotOwnershipTests(unittest.TestCase):
    def test_foreign_tor_port_is_occupied_not_running(self) -> None:
        ctl = _controller()
        with (
            patch("invizible_linux.backend.which", return_value="/usr/bin/x"),
            patch("invizible_linux.backend.read_pid", return_value=None),
            patch("invizible_linux.backend.port_open", return_value=True),
            patch.object(ctl, "_pids_for_config", return_value=[]),
            patch.object(ctl, "_system_tor_ours", return_value=False),
        ):
            snap = ctl.snapshot()
            self.assertFalse(snap["tor"].running)
            self.assertTrue(snap["tor"].occupied)
            self.assertIn("ocupado", snap["tor"].detail)
            self.assertFalse(ctl.any_running())

    def test_our_pidfile_counts_as_running(self) -> None:
        ctl = _controller()
        with (
            patch("invizible_linux.backend.which", return_value="/usr/bin/x"),
            patch("invizible_linux.backend.read_pid", return_value=4242),
            patch("invizible_linux.backend.port_open", return_value=True),
            patch.object(ctl, "_pids_for_config", return_value=[]),
            patch.object(ctl, "_pid_is_module", return_value=True),
            patch.object(ctl, "_system_tor_ours", return_value=False),
        ):
            snap = ctl.snapshot()
            self.assertTrue(snap["tor"].running)
            self.assertFalse(snap["tor"].occupied)
            self.assertTrue(ctl.any_running())

    def test_system_tor_flag_counts_as_running(self) -> None:
        ctl = _controller()
        with (
            patch("invizible_linux.backend.which", return_value="/usr/bin/x"),
            patch("invizible_linux.backend.read_pid", return_value=None),
            patch("invizible_linux.backend.port_open", return_value=True),
            patch.object(ctl, "_pids_for_config", return_value=[]),
            patch.object(ctl, "_system_tor_ours", return_value=True),
            patch.object(ctl, "_bootstrap_text", return_value=""),
        ):
            snap = ctl.snapshot()
            self.assertTrue(snap["tor"].running)
            self.assertEqual(snap["tor"].detail, "Iniciando…")

    def test_tor_progress_message_is_plain_language(self) -> None:
        ctl = _controller()
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp)
            (log_dir / "tor.log").write_text(
                "Bootstrapped 12% (conn_pt): Connecting to pluggable transport.\n",
                encoding="utf-8",
            )
            with (
                patch("invizible_linux.backend.LOG_DIR", log_dir),
                patch.object(ctl, "_system_tor_ours", return_value=False),
            ):
                self.assertEqual(ctl._tor_detail(True, True), "Conectando: 12%")
                (log_dir / "tor.log").write_text("Bootstrapped 100% (done): Done\n", encoding="utf-8")
                self.assertTrue(ctl._tor_detail(True, True).startswith("Conectado"))

    def test_system_tor_progress_uses_current_journal_invocation(self) -> None:
        ctl = _controller()

        def run(cmd, **_kwargs):
            if cmd[0] == "systemctl":
                return SimpleNamespace(stdout="abc123\n")
            self.assertIn("_SYSTEMD_INVOCATION_ID=abc123", cmd)
            self.assertIn("-g", cmd)
            return SimpleNamespace(stdout="Bootstrapped 100% (done): Done\n")

        with patch("invizible_linux.backend.subprocess.run", side_effect=run):
            self.assertEqual(ctl._bootstrap_text(SYSTEM_TOR_LOG), "Conectado")

    def test_i2p_running_message_is_simple(self) -> None:
        ctl = _controller()
        self.assertEqual(ctl._i2p_detail(True, True), "Activo · proxy 127.0.0.1:4444")
        ctl.settings.update({"system_mode": True, "route_all_tor": True})
        self.assertIn("limitado", ctl._i2p_detail(True, True))

    def test_dns_leak_prevention_enables_dns_redirect_without_full_firewall(self) -> None:
        ctl = _controller()
        ctl.settings.update({"dns": True, "prevent_dns_leak": True})
        result = SimpleNamespace(returncode=0, stdout="", stderr="")
        with (
            patch(
                "invizible_linux.backend.which",
                side_effect=lambda name: "/usr/bin/pkexec" if name == "pkexec" else "/usr/sbin/dnscrypt-proxy",
            ),
            patch.object(ctl, "pkexec", return_value=result) as pkexec,
            patch.object(ctl, "_mark_priv"),
        ):
            self.assertTrue(ctl.apply_privileged())

        flags = pkexec.call_args.args[1:]
        self.assertIn("apply_fw=1", flags)
        self.assertIn("dns_redirect_only=1", flags)

    def test_stale_system_flag_without_lock_is_not_running(self) -> None:
        ctl = _controller()
        with (
            patch("invizible_linux.backend.which", return_value="/usr/bin/x"),
            patch("invizible_linux.backend.read_pid", return_value=None),
            patch("invizible_linux.backend.port_open", return_value=True),
            patch.object(ctl, "_pids_for_config", return_value=[]),
            patch("invizible_linux.backend.SYSTEM_TOR_FLAG") as flag,
            patch("invizible_linux.backend.PRIV_LOCK") as lock,
            patch.object(ctl, "privileged_dirty", return_value=True),
        ):
            flag.exists.return_value = True
            lock.exists.return_value = False
            self.assertFalse(ctl._system_tor_ours())
            self.assertFalse(ctl.snapshot()["tor"].running)
            self.assertFalse(ctl.any_running())

    def test_start_tor_rejects_foreign_port(self) -> None:
        ctl = _controller()
        with (
            patch("invizible_linux.backend.which", return_value="/usr/bin/tor"),
            patch("invizible_linux.backend.port_open", return_value=True),
            patch("invizible_linux.backend.write_pac"),
            patch.object(ctl, "_port_is_ours", return_value=False),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                ctl.start_tor()
        self.assertIn("ocupado", str(ctx.exception))

    def test_leak_tests_accept_different_tor_exit_for_system_route(self) -> None:
        sock = SimpleNamespace(close=lambda: None)

        def http(url: str, timeout: float = 8.0, socks=None) -> str:
            if "api.ipify.org" in url:
                return "185.207.107.216"
            if "ipv6.icanhazip.com" in url:
                raise TimeoutError
            return '{"IsTor":true,"IP":"185.207.107.216"}'

        with (
            patch("invizible_linux.leaks.socket.create_connection", return_value=sock),
            patch("invizible_linux.leaks._http", side_effect=http),
            patch(
                "invizible_linux.leaks._https_via_socks",
                return_value='{"IsTor":true,"IP":"185.220.101.22"}',
            ),
            patch("invizible_linux.leaks._dns_a_system", return_value=["193.189.100.208"]),
            patch(
                "invizible_linux.leaks._dns_a",
                side_effect=lambda _name, server, port, timeout=4.0: (
                    ["193.189.100.208"] if server == "127.0.0.1" else []
                ),
            ),
            patch("invizible_linux.leaks._stun_mapped", return_value=None),
            patch("invizible_linux.leaks.save_leak_report", return_value=Path("/tmp/leak-test.txt")),
        ):
            results = leaks.run_leak_tests(
                {"system_mode": True, "route_all_tor": True, "socks_port": 9050, "listen_port": 5354}
            )

        by_key = {item.key: item for item in results}
        self.assertEqual(by_key["direct"].status, "ok")
        self.assertIn("otro circuito", by_key["direct"].detail)
        self.assertEqual(by_key["dns"].status, "ok")
        self.assertIn("Tor DNS", by_key["dns"].detail)
        self.assertEqual(by_key["dns-bypass"].status, "ok")
        self.assertEqual(by_key["oniux"].status, "info")
        self.assertIn("Omitida", by_key["oniux"].detail)
