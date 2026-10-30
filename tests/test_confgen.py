from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from invizible_linux.confgen import resolve_bridges
from invizible_linux.launchers import pac_text
from invizible_linux.profiles import apply_firefox_pac, apply_profile, effective_allow_lan


class PacTests(unittest.TestCase):
    def test_onion_and_lan_are_explicit(self) -> None:
        text = pac_text({"socks_port": "9050", "route_all_tor": True, "tor_sites_unlock": "", "tor_sites_exclude": ""})
        self.assertIn("SOCKS5 127.0.0.1:9050", text)
        self.assertIn("*.onion", text)
        self.assertIn('return PROXY', text)
        self.assertIn("10.0.0.0", text)

    def test_unlock_without_route_all(self) -> None:
        text = pac_text(
            {
                "socks_port": "9150",
                "route_all_tor": False,
                "tor_sites_unlock": "example.com\n.foo.org",
                "tor_sites_exclude": "ads.example",
            }
        )
        self.assertIn("example.com", text)
        self.assertIn("foo.org", text)
        self.assertIn("ads.example", text)
        self.assertIn('return DIRECT', text)
        self.assertIn("9150", text)


class BridgeTests(unittest.TestCase):
    def test_none_stays_none(self) -> None:
        mode, bridges, warn = resolve_bridges({"tor_bridges_mode": "none"})
        self.assertEqual(mode, "none")
        self.assertEqual(bridges, [])
        self.assertEqual(warn, "")

    def test_default_without_plugin_falls_back(self) -> None:
        with patch("invizible_linux.confgen.find_pt", return_value=None):
            mode, bridges, warn = resolve_bridges({"tor_bridges_mode": "default"})
        self.assertEqual(mode, "none")
        self.assertEqual(bridges, [])
        self.assertIn("Snowflake", warn)

    def test_default_with_snowflake(self) -> None:
        with patch("invizible_linux.confgen.find_pt", return_value="/usr/bin/snowflake-client"):
            mode, bridges, warn = resolve_bridges({"tor_bridges_mode": "default"})
        self.assertEqual(mode, "default")
        self.assertGreater(len(bridges), 0)
        self.assertTrue(bridges[0].startswith("snowflake"))
        self.assertIn("url=https://voluble-torrone-fc39bf.netlify.app/", bridges[0])
        self.assertIn("fronts=vuejs.org", bridges[0])
        self.assertNotIn("cdn77.org", bridges[0])
        self.assertEqual(warn, "")

    def test_snowflake_rendezvous_modes_change_broker_lines(self) -> None:
        with patch("invizible_linux.confgen.find_pt", return_value="/usr/bin/lyrebird"):
            for rendezvous, expected in (
                ("amp", "ampcache=https://cdn.ampproject.org/"),
                ("sqs", "sqsqueue=https://sqs.us-east-1.amazonaws.com/"),
            ):
                mode, bridges, warn = resolve_bridges(
                    {"tor_bridges_mode": "default", "snowflake_rendezvous": rendezvous}
                )
                self.assertEqual(mode, "default")
                self.assertEqual(warn, "")
                self.assertTrue(all(expected in bridge for bridge in bridges))

    def test_default_with_lyrebird(self) -> None:
        with patch(
            "invizible_linux.confgen.find_pt",
            side_effect=lambda *names: "/usr/bin/lyrebird" if "lyrebird" in names else None,
        ):
            mode, bridges, warn = resolve_bridges({"tor_bridges_mode": "default"})
        self.assertEqual(mode, "default")
        self.assertTrue(bridges)
        self.assertEqual(warn, "")

    def test_snowflake_bridge_is_allowed_by_fascist_firewall(self) -> None:
        from invizible_linux import confgen

        with tempfile.TemporaryDirectory() as tmp:
            confgen.CONFIG_DIR = Path(tmp)
            with patch("invizible_linux.confgen.find_pt", return_value="/usr/bin/lyrebird"):
                dest = confgen.write_torrc(
                    {
                        "tor_bridges_mode": "default",
                        "fascist_firewall": True,
                        "socks_port": "9050",
                        "trans_port": "9040",
                        "tor_dns_port": "5353",
                    },
                    datadir=Path(tmp) / "tor",
                    pidfile=Path(tmp) / "tor.pid",
                    logfile=Path(tmp) / "tor.log",
                )
            text = dest.read_text(encoding="utf-8")
        self.assertIn("FascistFirewall 1", text)
        self.assertIn("ReachableORAddresses *:80,*:443", text)
        self.assertIn("ClientTransportPlugin snowflake exec", text)
        self.assertNotIn("ClientTransportPlugin snowflake socks5", text)

    def test_own_obfs4_without_lyrebird(self) -> None:
        with patch("invizible_linux.confgen.find_pt", return_value=None):
            mode, bridges, warn = resolve_bridges(
                {
                    "tor_bridges_mode": "own",
                    "tor_bridges": "obfs4 1.2.3.4:443 FINGERPRINT",
                }
            )
        self.assertEqual(mode, "none")
        self.assertIn("lyrebird", warn)

    def test_own_bridge_with_bridge_keyword_detects_plugin(self) -> None:
        with patch("invizible_linux.confgen.find_pt", return_value="/usr/bin/lyrebird"):
            mode, bridges, warn = resolve_bridges(
                {
                    "tor_bridges_mode": "own",
                    "tor_bridges": "Bridge obfs4 1.2.3.4:443 AAAA cert=x iat-mode=0",
                }
            )
        self.assertEqual(mode, "own")
        self.assertEqual(warn, "")
        self.assertEqual(len(bridges), 1)

    def test_own_snowflake_accepts_lyrebird(self) -> None:
        with patch(
            "invizible_linux.confgen.find_pt",
            side_effect=lambda *names: "/usr/bin/lyrebird" if "lyrebird" in names else None,
        ):
            mode, bridges, warn = resolve_bridges(
                {
                    "tor_bridges_mode": "own",
                    "tor_bridges": "snowflake 192.0.2.5:80 AAAA url=https://example.invalid/",
                }
            )
        self.assertEqual(mode, "own")
        self.assertEqual(warn, "")
        self.assertEqual(len(bridges), 1)

    def test_write_torrc_strips_bridge_keyword(self) -> None:
        from invizible_linux import confgen

        with tempfile.TemporaryDirectory() as tmp:
            confgen.CONFIG_DIR = Path(tmp)
            with patch("invizible_linux.confgen.find_pt", return_value="/usr/bin/lyrebird"):
                dest = confgen.write_torrc(
                    {
                        "tor_bridges_mode": "own",
                        "tor_bridges": "Bridge obfs4 1.2.3.4:443 AAAA cert=x iat-mode=0",
                        "socks_port": "9050",
                        "trans_port": "9040",
                        "tor_dns_port": "5353",
                    },
                    datadir=Path(tmp) / "tor",
                    pidfile=Path(tmp) / "tor.pid",
                    logfile=Path(tmp) / "tor.log",
                )
            text = dest.read_text(encoding="utf-8")
        self.assertIn("Bridge obfs4 1.2.3.4:443", text)
        self.assertNotIn("Bridge Bridge", text)
        self.assertIn("ClientTransportPlugin obfs4", text)

    def test_write_torrc_has_no_noop_mapaddress(self) -> None:
        from invizible_linux import confgen

        with tempfile.TemporaryDirectory() as tmp:
            confgen.CONFIG_DIR = Path(tmp)
            with patch("invizible_linux.confgen.find_pt", return_value=None):
                dest = confgen.write_torrc(
                    {
                        "tor_bridges_mode": "none",
                        "tor_sites_unlock": "example.com",
                        "route_all_tor": False,
                        "socks_port": "9050",
                        "trans_port": "9040",
                        "tor_dns_port": "5353",
                    },
                    datadir=Path(tmp) / "tor",
                    pidfile=Path(tmp) / "tor.pid",
                    logfile=Path(tmp) / "tor.log",
                )
            text = dest.read_text(encoding="utf-8")
        self.assertNotIn("MapAddress example.com example.com", text)

    def test_write_system_torrc_uses_var_log_tor(self) -> None:
        from invizible_linux import confgen

        with tempfile.TemporaryDirectory() as tmp:
            confgen.CONFIG_DIR = Path(tmp)
            dest = confgen.write_system_torrc(
                {
                    "socks_port": "9050",
                    "trans_port": "9040",
                    "tor_dns_port": "5353",
                }
            )
            text = dest.read_text(encoding="utf-8")
        self.assertNotIn("Log notice file", text)
        self.assertNotIn("/run/invizible-linux-tor.log", text)
        self.assertIn("CookieAuthentication 1", text)
        self.assertIn("Log notice syslog", text)

    def test_i2pd_uses_system_reseed_certificates_and_follows_redirects(self) -> None:
        from invizible_linux import confgen

        with tempfile.TemporaryDirectory() as tmp:
            with patch("invizible_linux.confgen.Path.is_dir", return_value=True):
                dest = confgen.write_i2pd_conf(
                    {"i2p_reseed_verify": True},
                    datadir=Path(tmp),
                    pidfile=Path(tmp) / "i2pd.pid",
                    logfile=Path(tmp) / "i2pd.log",
                )
            text = dest.read_text(encoding="utf-8")
        self.assertIn("certsdir = /usr/share/i2pd/certificates", text)
        self.assertIn("followredirect = true", text)

    def test_i2pd_disables_ssu2_when_all_udp_is_blocked_by_tor_route(self) -> None:
        from invizible_linux import confgen

        with tempfile.TemporaryDirectory() as tmp:
            dest = confgen.write_i2pd_conf(
                {
                    "system_mode": True,
                    "route_all_tor": True,
                    "exclude_udp": False,
                    "i2p_ssu2": True,
                    "i2p_ntcp2": True,
                },
                datadir=Path(tmp),
                pidfile=Path(tmp) / "i2pd.pid",
                logfile=Path(tmp) / "i2pd.log",
            )
            text = dest.read_text(encoding="utf-8")
        self.assertIn("[ssu2]\nenabled = false", text)
        self.assertIn("[ntcp2]\nenabled = true", text)


    def test_i2p_and_onion_toggles(self) -> None:
        text = pac_text({"socks_port": "9050", "i2p": True, "i2p_http_port": "4444"})
        self.assertIn('return "PROXY 127.0.0.1:4444"', text)
        self.assertIn('return PROXY;', text)
        text = pac_text({"socks_port": "9050", "i2p": True, "fw_allow_i2p": False, "fw_allow_onion": False})
        self.assertIn('*.i2p") || shExpMatch(host, "*.i2p.")) return "DIRECT"', text)
        self.assertIn('*.onion") || shExpMatch(host, "*.onion.")) return "DIRECT"', text)


class ProfileTests(unittest.TestCase):
    def test_max_enables_kill_switch(self) -> None:
        s: dict = {"allow_lan": True}
        apply_profile(s, "max")
        self.assertTrue(s["kill_switch"])
        self.assertTrue(s["system_mode"])
        self.assertFalse(s["allow_lan"])
        self.assertEqual(s["usage_profile"], "max")

    def test_home_is_proxy_only(self) -> None:
        s: dict = {}
        apply_profile(s, "home")
        self.assertFalse(s["system_mode"])
        self.assertFalse(s["firewall"])
        self.assertFalse(s["route_all_tor"])

    def test_trusted_wifi_allows_lan(self) -> None:
        s = {"allow_lan": False, "block_lan_free_wifi": True, "trusted_wifi": "Casa\nOficina"}
        self.assertTrue(effective_allow_lan(s, ssid="Casa"))
        self.assertFalse(effective_allow_lan(s, ssid="Starbucks"))
        self.assertFalse(effective_allow_lan(s, ssid=""))  # ethernet uses allow_lan=False

    def test_firefox_pac_uses_profile_user_js_and_can_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            profile = home / ".mozilla" / "firefox" / "abc.default-esr"
            profile.mkdir(parents=True)
            (profile / "prefs.js").write_text('user_pref("browser.shell.checkDefaultBrowser", false);\n')
            (profile / "user.js").write_text('user_pref("app.update.disabled", true);\n')
            with patch("invizible_linux.profiles.Path.home", return_value=home):
                changed = apply_firefox_pac(True, "file:///tmp/tor-sites.pac")
            self.assertEqual(changed, profile / "user.js")
            text = (profile / "user.js").read_text(encoding="utf-8")
            self.assertIn('user_pref("network.proxy.type", 2);', text)
            self.assertIn('user_pref("network.proxy.autoconfig_url", "file:///tmp/tor-sites.pac");', text)
            self.assertIn('user_pref("network.proxy.socks_remote_dns", true);', text)
            self.assertIn("app.update.disabled", text)

            with patch("invizible_linux.profiles.Path.home", return_value=home):
                apply_firefox_pac(False, "file:///tmp/tor-sites.pac")
            text = (profile / "user.js").read_text(encoding="utf-8")
            self.assertIn("app.update.disabled", text)
            self.assertNotIn("network.proxy.autoconfig_url", text)


if __name__ == "__main__":
    unittest.main()
