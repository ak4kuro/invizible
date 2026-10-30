from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from invizible_linux import helper


class FirewallTests(unittest.TestCase):
    def test_dns_only_redirect_precedes_loopback_bypass(self) -> None:
        opts = {
            "dns_redirect_only": "1",
            "dns": "1",
            "dns_port": "5354",
            "prevent_dns_leak": "1",
            "bootstrap_resolvers": "9.9.9.9,8.8.8.8",
            "block_ipv6": "1",
            "block_stun": "1",
            "block_mdns": "1",
            "block_llmnr": "1",
        }
        with (
            patch("invizible_linux.helper.tor_uid", return_value=None),
            patch("invizible_linux.helper.default_gateway", return_value=None),
            patch("invizible_linux.helper.subprocess.run", return_value=SimpleNamespace(returncode=0)) as run,
        ):
            helper.apply_firewall(opts)

        rules = run.call_args.kwargs["input"]
        redirect = "meta nfproto ipv4 udp dport 53 redirect to :5354"
        self.assertIn(redirect, rules)
        self.assertLess(rules.index(redirect), rules.index('oif "lo" return'))
        self.assertNotIn("udp dport { 3478, 19302 } drop", rules)
        self.assertNotIn("meta nfproto ipv6 ip6 daddr != ::1 drop", rules)

    def test_transparent_redirect_accepts_loopback_after_nat(self) -> None:
        opts = {
            "tor": "1",
            "route_all_tor": "1",
            "kill_switch": "1",
            "prevent_dns_leak": "1",
            "dns": "1",
            "trans_port": "9040",
            "tor_dns_port": "5353",
        }
        with (
            patch("invizible_linux.helper.tor_uid", return_value="120"),
            patch("invizible_linux.helper.default_gateway", return_value=None),
            patch("invizible_linux.helper.subprocess.run", return_value=SimpleNamespace(returncode=0)) as run,
        ):
            helper.apply_firewall(opts)
        rules = run.call_args.kwargs["input"]
        self.assertIn("redirect to :9040", rules)
        self.assertIn("ip daddr 127.0.0.0/8 accept", rules)
        self.assertLess(rules.index("ip daddr 127.0.0.0/8 accept"), rules.index("meta l4proto udp drop"))

    def test_system_tor_apparmor_allows_pt_sleep_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local" / "system_tor"
            profile = root / "system_tor"
            profile.write_text("profile system_tor {}\n", encoding="utf-8")
            pt_dir = root / "pt"
            with (
                patch.object(helper, "PT_SYS_DIR", pt_dir),
                patch.object(helper, "AA_LOCAL", local),
                patch.object(helper, "AA_PROFILE", profile),
                patch.object(helper, "_find_pt", return_value=None),
                patch.object(helper, "run") as run,
            ):
                helper.ensure_tor_pts()
            text = local.read_text(encoding="utf-8")
            self.assertIn(f"{pt_dir}/* ix,", text)
            self.assertIn("/usr/bin/sleep ix,", text)
            self.assertIn("#include <abstractions/base>", text)
            run.assert_called_once_with(["apparmor_parser", "-r", str(profile)], check=False)

    def test_tor_resolver_dropin_uses_bootstrap_resolvers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            resolv = root / "tor-resolv.conf"
            dropin_dir = root / "tor@default.service.d"
            dropin = dropin_dir / "90-invizible.conf"
            with (
                patch.object(helper, "TOR_RESOLV_CONF", resolv),
                patch.object(helper, "TOR_SYSTEMD_DIR", dropin_dir),
                patch.object(helper, "TOR_SYSTEMD_DROPIN", dropin),
                patch.object(helper, "systemctl") as systemctl,
            ):
                helper.install_tor_resolver({"bootstrap_resolvers": "9.9.9.9:53, 1.1.1.1"})
            self.assertEqual(resolv.read_text(encoding="utf-8"), "nameserver 9.9.9.9\nnameserver 1.1.1.1\n")
            self.assertIn(f"BindReadOnlyPaths={resolv}:/etc/resolv.conf", dropin.read_text(encoding="utf-8"))
            systemctl.assert_called_once_with("daemon-reload")

            with (
                patch.object(helper, "TOR_RESOLV_CONF", resolv),
                patch.object(helper, "TOR_SYSTEMD_DIR", dropin_dir),
                patch.object(helper, "TOR_SYSTEMD_DROPIN", dropin),
                patch.object(helper, "systemctl") as systemctl,
            ):
                helper.clear_tor_resolver()
            self.assertFalse(resolv.exists())
            self.assertFalse(dropin.exists())
            systemctl.assert_called_once_with("daemon-reload")
