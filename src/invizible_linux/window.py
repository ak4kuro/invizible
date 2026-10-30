from __future__ import annotations

import threading
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from .backend import Controller, install_hint, tail
from .config import APP_NAME, CONFIG_DIR, DATA_DIR, LOG_DIR, save_settings
from .distro import detect
from .launchers import pac_file_url, runner_path, sync_desktop_launchers, write_pac
from .leaks import LeakResult, run_leak_tests
from .oniuxctl import isolation_label, isolation_short, install_oniux, launch_app, oniux_binary, status_text, userns_ok
from .prefs_ui import build_pages
from .tray import TrayController


def load_css() -> None:
    css_path = Path(__file__).with_name("style.css")
    provider = Gtk.CssProvider()
    provider.load_from_path(str(css_path))
    Gtk.StyleContext.add_provider_for_display(
        Gdk.Display.get_default(),
        provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
    )


class ModuleRow(Gtk.Box):
    def __init__(self, key: str, title: str, subtitle: str, active: bool) -> None:
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.add_css_class("module-card")
        self.key = key

        self.check = Gtk.CheckButton()
        self.check.set_active(active)
        self.check.add_css_class("module-check")
        self.check.set_valign(Gtk.Align.CENTER)

        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
        self.title = Gtk.Label(label=title, xalign=0)
        self.title.add_css_class("module-title")
        self.sub = Gtk.Label(label=subtitle, xalign=0)
        self.sub.add_css_class("module-sub")
        text.append(self.title)
        text.append(self.sub)

        self.status = Gtk.Label(label="Detenido", xalign=1)
        self.status.add_css_class("module-status")
        self.status.set_valign(Gtk.Align.CENTER)

        self.append(self.check)
        self.append(text)
        self.append(self.status)

        self.check.connect("toggled", lambda *_: self._sync_active())
        self._sync_active()

    def _sync_active(self) -> None:
        if self.check.get_active():
            self.add_css_class("active")
        else:
            self.remove_css_class("active")

    def set_status(self, text: str, kind: str = "") -> None:
        self.status.set_label(text)
        self.status.remove_css_class("ok")
        self.status.remove_css_class("warn")
        self.status.remove_css_class("err")
        if kind:
            self.status.add_css_class(kind)


class AppLaunchRow(Gtk.Box):
    def __init__(self, appinfo: Gio.AppInfo, settings: dict, on_change, on_launch) -> None:
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.add_css_class("app-row")
        self.appinfo = appinfo
        self.app_id = appinfo.get_id() or appinfo.get_executable() or appinfo.get_display_name()
        self.settings = settings
        self._on_change = on_change
        self._on_launch = on_launch

        icon = Gtk.Image()
        gicon = appinfo.get_icon()
        if gicon:
            icon.set_from_gicon(gicon)
        icon.set_pixel_size(28)
        self.append(icon)

        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0, hexpand=True)
        name = Gtk.Label(label=appinfo.get_display_name() or self.app_id, xalign=0)
        name.add_css_class("module-title")
        self.sub = Gtk.Label(label=appinfo.get_executable() or "", xalign=0)
        self.sub.add_css_class("module-sub")
        self.sub.set_wrap(True)
        text.append(name)
        text.append(self.sub)
        self.append(text)

        self.mode = Gtk.DropDown.new_from_strings(["Normal", "Tor estricto", "Tor laxo", "Directo"])
        self.mode.set_valign(Gtk.Align.CENTER)
        self.mode.set_tooltip_text(
            "Estricto: oniux (todo el tráfico). Laxo: SOCKS con aislamiento por app (puede fugar). Directo: red normal."
        )
        self._sync_from_settings()
        self.mode.connect("notify::selected", self._mode_changed)
        self.append(self.mode)

        open_btn = Gtk.Button(label="Abrir")
        open_btn.set_valign(Gtk.Align.CENTER)
        open_btn.connect("clicked", lambda *_: self._on_launch(self))
        self.append(open_btn)

        self.search_blob = " ".join(
            filter(
                None,
                [
                    appinfo.get_display_name(),
                    self.app_id,
                    appinfo.get_executable(),
                    appinfo.get_commandline(),
                ],
            )
        ).lower()

    def _sync_from_settings(self) -> None:
        tor = set(self.settings.get("oniux_tor_apps") or [])
        lax = set(self.settings.get("oniux_lax_apps") or [])
        clear = set(self.settings.get("oniux_clear_apps") or [])
        if self.app_id in tor:
            self.mode.set_selected(1)
        elif self.app_id in lax:
            self.mode.set_selected(2)
        elif self.app_id in clear:
            self.mode.set_selected(3)
        else:
            self.mode.set_selected(0)
        self._refresh_sub()

    def _refresh_sub(self) -> None:
        exe = self.appinfo.get_executable() or ""
        selected = self.mode.get_selected()
        if selected == 1:
            self.sub.set_label(f"{exe} · estricto · {isolation_short()}")
        elif selected == 2:
            self.sub.set_label(f"{exe} · laxo · SOCKS IsolateSOCKSAuth (puede fugar)")
        else:
            self.sub.set_label(exe)

    def _mode_changed(self, *_args) -> None:
        tor = [x for x in (self.settings.get("oniux_tor_apps") or []) if x != self.app_id]
        lax = [x for x in (self.settings.get("oniux_lax_apps") or []) if x != self.app_id]
        clear = [x for x in (self.settings.get("oniux_clear_apps") or []) if x != self.app_id]
        selected = self.mode.get_selected()
        if selected == 1:
            tor.append(self.app_id)
        elif selected == 2:
            lax.append(self.app_id)
        elif selected == 3:
            clear.append(self.app_id)
        self.settings["oniux_tor_apps"] = tor
        self.settings["oniux_lax_apps"] = lax
        self.settings["oniux_clear_apps"] = clear
        self._refresh_sub()
        self._on_change()

    def through_tor(self) -> bool:
        return self.mode.get_selected() in {1, 2}

    def isolation_kind(self) -> str:
        if self.mode.get_selected() == 2:
            return "lax"
        if self.mode.get_selected() == 1:
            return "strict"
        return ""


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application) -> None:
        super().__init__(application=app, title=APP_NAME)
        self.set_default_size(520, 820)
        self.add_css_class("invizible")
        load_css()

        self.controller = Controller(log=self._on_log)
        self._busy = False
        self._boot_notified = False

        self.toast = Adw.ToastOverlay()
        self.stack = Adw.ViewStack()
        self.stack.add_titled(self._build_home(), "home", "Inicio").set_icon_name("go-home-symbolic")
        self.stack.add_titled(self._build_apps(), "apps", "Apps").set_icon_name("system-run-symbolic")
        self.stack.add_titled(self._build_leaks(), "leaks", "Fugas").set_icon_name("network-wired-disconnected-symbolic")
        self.stack.add_titled(self._build_logs(), "logs", "Registros").set_icon_name("utilities-terminal-symbolic")
        names = [
            ("fast", "preferences-system-symbolic"),
            ("common", "applications-system-symbolic"),
            ("dnscrypt", "network-workgroup-symbolic"),
            ("torset", "network-vpn-symbolic"),
            ("i2pset", "network-server-symbolic"),
            ("firewall", "security-medium-symbolic"),
        ]
        for (name, icon), page in zip(names, build_pages(self.controller.settings, self._on_prefs_changed)):
            self.stack.add_titled(page, name, page.get_title() or name).set_icon_name(icon)

        header = Adw.HeaderBar()
        header.set_title_widget(Gtk.Label(label=APP_NAME))

        icon_path = DATA_DIR / "icons" / "net.invizible.Linux.svg"
        if icon_path.exists():
            picture = Gtk.Image.new_from_file(str(icon_path))
            picture.set_pixel_size(22)
            header.pack_start(picture)

        btn_apps = Gtk.Button.new_from_icon_name("system-run-symbolic")
        btn_apps.set_tooltip_text("Aplicaciones (oniux)")
        btn_apps.connect("clicked", lambda *_: self.stack.set_visible_child_name("apps"))
        header.pack_end(btn_apps)

        btn_leaks = Gtk.Button.new_from_icon_name("network-wired-disconnected-symbolic")
        btn_leaks.set_tooltip_text("Pruebas de fugas")
        btn_leaks.connect("clicked", lambda *_: self.stack.set_visible_child_name("leaks"))
        header.pack_end(btn_leaks)

        btn_fw = Gtk.Button.new_from_icon_name("security-medium-symbolic")
        btn_fw.set_tooltip_text("Cortafuegos")
        btn_fw.connect("clicked", lambda *_: self.stack.set_visible_child_name("firewall"))
        header.pack_end(btn_fw)

        btn_log = Gtk.Button.new_from_icon_name("utilities-terminal-symbolic")
        btn_log.set_tooltip_text("Registros")
        btn_log.connect("clicked", lambda *_: self.stack.set_visible_child_name("logs"))
        header.pack_end(btn_log)

        btn_set = Gtk.Button.new_from_icon_name("emblem-system-symbolic")
        btn_set.set_tooltip_text("Ajustes rápidos")
        btn_set.connect("clicked", lambda *_: self.stack.set_visible_child_name("fast"))
        header.pack_end(btn_set)

        btn_home = Gtk.Button.new_from_icon_name("go-home-symbolic")
        btn_home.set_tooltip_text("Inicio")
        btn_home.connect("clicked", lambda *_: self.stack.set_visible_child_name("home"))
        header.pack_start(btn_home)

        # Menú ☰ siempre visible (aunque no haya bandeja de sistema): salir,
        # iniciar/detener módulos y minimizar a bandeja si la hay.
        menu = Gio.Menu()
        menu.append("Iniciar/Detener módulos", "win.menu-toggle")
        menu.append("Minimizar a bandeja", "win.menu-hide")
        menu.append("Salir (detener todo)", "win.menu-quit")
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu)
        menu_btn.set_tooltip_text("Menú")
        for name, cb in (
            ("menu-toggle", self._on_start_stop),
            ("menu-hide", lambda *_: self.set_visible(False)),
            ("menu-quit", lambda *_: self._quit_from_tray()),
        ):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", lambda *_a, _p=None, _c=cb: _c())
            self.add_action(act)
        header.pack_start(menu_btn)

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)
        toolbar.set_content(self.stack)
        switcher = Adw.ViewSwitcherBar()
        switcher.set_stack(self.stack)
        switcher.set_reveal(True)
        toolbar.add_bottom_bar(switcher)
        self.toast.set_child(toolbar)
        self.set_content(self.toast)

        if hasattr(app, "keep_alive"):
            app.keep_alive(bool(self.controller.settings.get("hide_to_tray", True)))
        self.set_hide_on_close(bool(self.controller.settings.get("hide_to_tray", True)))
        self.tray = TrayController(
            show=self.reveal,
            toggle=self._on_start_stop,
            quit_app=self._quit_from_tray,
            running=self.controller.any_running,
        )
        self.connect("close-request", self._on_close)
        self._apply_theme()
        GLib.timeout_add_seconds(2, self._refresh)
        self._refresh()

    def _scrolled(self, child: Gtk.Widget) -> Gtk.ScrolledWindow:
        scroll = Gtk.ScrolledWindow(hexpand=True, vexpand=True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_child(child)
        return scroll

    def _build_home(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        page.add_css_class("page")

        hero = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, halign=Gtk.Align.CENTER)
        hero.add_css_class("hero")
        self.shield = Gtk.Label(label="🛡")
        self.shield.add_css_class("shield")
        self.shield_text = Gtk.Label(label="CORTAFUEGOS EN ESPERA")
        self.shield_text.add_css_class("shield-label")
        hero.append(self.shield)
        hero.append(self.shield_text)
        page.append(hero)

        self.banner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.banner.add_css_class("banner")
        self.banner_label = Gtk.Label(xalign=0, wrap=True)
        self.banner.append(self.banner_label)
        self.install_btn = Gtk.Button(label="Instalar lo necesario")
        self.install_btn.set_halign(Gtk.Align.START)
        self.install_btn.connect("clicked", self._on_install)
        self.banner.append(self.install_btn)
        page.append(self.banner)

        s = self.controller.settings
        self.row_dns = ModuleRow("dns", "DNSCrypt", "Cifra el DNS y evita manipulación", s["dns"])
        self.row_tor = ModuleRow("tor", "Tor", "Oculta tu IP y abre sitios .onion", s["tor"])
        self.row_i2p = ModuleRow("i2p", "I2P", "Red invisible (eepsites)", s["i2p"])
        for row in (self.row_dns, self.row_tor, self.row_i2p):
            row.check.connect("toggled", self._persist_modules)
            page.append(row)

        self.start_btn = Gtk.Button(label="INICIAR")
        self.start_btn.add_css_class("start-btn")
        self.start_btn.set_halign(Gtk.Align.CENTER)
        self.start_btn.set_margin_top(10)
        self.start_btn.connect("clicked", self._on_start_stop)
        page.append(self.start_btn)
        self.newnym_btn = Gtk.Button(label="Nuevo circuito Tor")
        self.newnym_btn.set_halign(Gtk.Align.CENTER)
        self.newnym_btn.connect("clicked", self._on_newnym)
        page.append(self.newnym_btn)

        hint = Gtk.Label(
            label="Marca los módulos y pulsa INICIAR. Cerrar la ventana no los detiene: "
            "usa DETENER o Salir (bandeja o el menú de aplicaciones).",
            wrap=True,
            xalign=0.5,
        )
        hint.add_css_class("hint")
        page.append(hint)

        self.bridges_btn = Gtk.Button(label="Instalar lyrebird (puentes Tor)")
        self.bridges_btn.set_halign(Gtk.Align.CENTER)
        self.bridges_btn.connect("clicked", self._on_install_bridges)
        page.append(self.bridges_btn)

        proxies = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        proxies.add_css_class("proxy-box")
        title = Gtk.Label(label="PROXIES LOCALES", xalign=0)
        title.add_css_class("section-title")
        self.proxy_label = Gtk.Label(
            label=self._proxy_text(),
            xalign=0,
        )
        self.proxy_label.add_css_class("mono")
        pac_hint = Gtk.Label(
            label="El PAC no lo carga ningún navegador solo. Copia la URL y pégala en Firefox → Ajustes → Red → URL de configuración automática.",
            wrap=True,
            xalign=0,
        )
        pac_hint.add_css_class("hint")
        pac_btn = Gtk.Button(label="Copiar URL del PAC")
        pac_btn.set_halign(Gtk.Align.START)
        pac_btn.connect("clicked", self._copy_pac)
        proxies.append(title)
        proxies.append(self.proxy_label)
        proxies.append(pac_hint)
        proxies.append(pac_btn)
        page.append(proxies)

        return self._scrolled(page)

    def _build_apps(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        page.add_css_class("page")
        title = Gtk.Label(label="APLICACIONES", xalign=0)
        title.add_css_class("section-title")
        page.append(title)
        intro = Gtk.Label(
            label="Estricto = oniux (todo el tráfico). Laxo = SOCKS con aislamiento por app (puede fugar). "
            "Directo = red normal. El método real se ve bajo el nombre.",
            wrap=True,
            xalign=0,
        )
        intro.add_css_class("hint")
        page.append(intro)

        self.oniux_status = Gtk.Label(label=status_text(), wrap=True, xalign=0)
        self.oniux_status.add_css_class("hint")
        page.append(self.oniux_status)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.oniux_install_btn = Gtk.Button(label="Instalar oniux")
        self.oniux_install_btn.connect("clicked", self._on_install_oniux)
        self.oniux_userns_btn = Gtk.Button(label="Activar namespaces de usuario")
        self.oniux_userns_btn.set_tooltip_text("oniux lo necesita. En linux-hardened suele estar desactivado.")
        self.oniux_userns_btn.connect("clicked", self._on_enable_userns)
        btn_box.append(self.oniux_install_btn)
        btn_box.append(self.oniux_userns_btn)
        refresh = Gtk.Button(label="Actualizar lista")
        refresh.connect("clicked", lambda *_: self._fill_app_list())
        btn_box.append(refresh)
        page.append(btn_box)

        self.app_search = Gtk.SearchEntry()
        self.app_search.set_placeholder_text("Buscar aplicación…")
        self.app_search.connect("search-changed", self._filter_apps)
        page.append(self.app_search)
        self.show_all_apps = Gtk.CheckButton(label="Mostrar todas las aplicaciones")
        self.show_all_apps.set_active(bool(self.controller.settings.get("show_all_apps")))
        self.show_all_apps.connect("toggled", self._toggle_show_all)
        page.append(self.show_all_apps)

        self.app_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        scroll = Gtk.ScrolledWindow(vexpand=True, hexpand=True, min_content_height=360)
        scroll.set_child(self.app_list)
        page.append(scroll)
        self._app_rows: list[AppLaunchRow] = []
        GLib.idle_add(self._fill_app_list)
        return page

    def _fill_app_list(self) -> bool:
        child = self.app_list.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.app_list.remove(child)
            child = nxt
        self._app_rows = []
        seen: set[str] = set()
        apps = []
        for info in Gio.AppInfo.get_all():
            if not info.should_show():
                continue
            app_id = info.get_id() or info.get_executable() or ""
            if not app_id or app_id in seen:
                continue
            seen.add(app_id)
            apps.append(info)
        tor = set(self.controller.settings.get("oniux_tor_apps") or [])
        lax = set(self.controller.settings.get("oniux_lax_apps") or [])
        clear = set(self.controller.settings.get("oniux_clear_apps") or [])

        def sort_key(info: Gio.AppInfo) -> tuple:
            aid = info.get_id() or ""
            rank = 0 if aid in tor else 1 if aid in lax else 2 if aid in clear else 3
            return (rank, (info.get_display_name() or "").lower())

        apps.sort(key=sort_key)
        for info in apps:
            row = AppLaunchRow(
                info,
                self.controller.settings,
                self._persist_oniux,
                self._launch_app_row,
            )
            self._app_rows.append(row)
            self.app_list.append(row)
        self._filter_apps()
        if hasattr(self, "oniux_status"):
            self.oniux_status.set_label(status_text())
            self.oniux_install_btn.set_visible(oniux_binary() is None)
            self.oniux_userns_btn.set_visible(not userns_ok())
        return False

    def _toggle_show_all(self, *_args) -> None:
        self.controller.settings["show_all_apps"] = self.show_all_apps.get_active()
        save_settings(self.controller.settings)
        self._filter_apps()

    def _filter_apps(self, *_args) -> None:
        query = ""
        if hasattr(self, "app_search"):
            query = (self.app_search.get_text() or "").strip().lower()
        show_all = bool(self.controller.settings.get("show_all_apps"))
        tor = set(self.controller.settings.get("oniux_tor_apps") or [])
        lax = set(self.controller.settings.get("oniux_lax_apps") or [])
        clear = set(self.controller.settings.get("oniux_clear_apps") or [])
        favorites = tor | lax | clear
        for row in self._app_rows:
            if query:
                row.set_visible(query in row.search_blob)
                continue
            if show_all or not favorites:
                row.set_visible(True)
            else:
                row.set_visible(row.app_id in favorites)

    def _copy_pac(self, *_args) -> None:
        write_pac(self.controller.settings)
        url = pac_file_url()
        display = Gdk.Display.get_default()
        if display:
            display.get_clipboard().set(url)
        self.toast.add_toast(Adw.Toast(title="PAC copiado. Pégalo en el navegador; no se aplica solo."))

    def _on_install_bridges(self, *_args) -> None:
        self.bridges_btn.set_sensitive(False)

        def work() -> None:
            try:
                msg = self.controller.install_bridges()
                GLib.idle_add(self._bridges_done, True, msg or "Plugin de puentes instalado. Vuelve a INICIAR Tor.")
            except Exception as exc:  # noqa: BLE001
                GLib.idle_add(self._bridges_done, False, str(exc))

        threading.Thread(target=work, daemon=True).start()

    def _bridges_done(self, ok: bool, message: str) -> bool:
        self.bridges_btn.set_sensitive(True)
        self._refresh()
        toast = Adw.Toast(title=message[:200])
        toast.set_timeout(5)
        self.toast.add_toast(toast)
        if not ok:
            self.stack.set_visible_child_name("logs")
        return False

    def _persist_oniux(self) -> None:
        save_settings(self.controller.settings)
        write_pac(self.controller.settings)
        try:
            sync_desktop_launchers(self.controller.settings, runner_path())
        except OSError as exc:
            self.controller.log(f"Lanzadores: {exc}")
        self._filter_apps()

    def _launch_app_row(self, row: AppLaunchRow) -> None:
        cmdline = row.appinfo.get_commandline() or row.appinfo.get_executable() or ""
        through = row.through_tor()
        try:
            socks = int(str(self.controller.settings.get("socks_port") or 9050))
        except ValueError:
            socks = 9050
        kind = row.isolation_kind()
        try:
            launch_app(
                cmdline,
                through_tor=through,
                log=self.controller.log,
                socks_port=socks,
                isolation=kind,
                socks_user=(row.app_id or "app")[:40],
            )
            if kind == "lax":
                how = "por Tor laxo (SOCKS, puede fugar)"
            elif through:
                how = f"por Tor estricto ({isolation_label()})"
            else:
                how = "en claro"
            self.toast.add_toast(Adw.Toast(title=f"Abriendo {row.appinfo.get_display_name()} {how}"))
        except Exception as exc:  # noqa: BLE001
            self.toast.add_toast(Adw.Toast(title=str(exc)))
            self.stack.set_visible_child_name("logs")

    def _on_enable_userns(self, *_args) -> None:
        self.oniux_userns_btn.set_sensitive(False)

        def work() -> None:
            try:
                result = self.controller.pkexec("enable-userns")
                if result.returncode != 0:
                    raise RuntimeError((result.stderr or result.stdout or "cancelado").strip())
                GLib.idle_add(self._userns_done, True, "Namespaces de usuario activados para oniux.")
            except Exception as exc:  # noqa: BLE001
                GLib.idle_add(self._userns_done, False, str(exc))

        threading.Thread(target=work, daemon=True).start()

    def _userns_done(self, ok: bool, message: str) -> bool:
        self.oniux_userns_btn.set_sensitive(True)
        self.oniux_status.set_label(status_text())
        self.oniux_userns_btn.set_visible(not userns_ok())
        toast = Adw.Toast(title=message[:200])
        toast.set_timeout(5)
        self.toast.add_toast(toast)
        return False

    def _on_install_oniux(self, *_args) -> None:
        self.oniux_install_btn.set_sensitive(False)
        self.oniux_install_btn.set_label("Instalando oniux…")

        def work() -> None:
            try:
                msg = install_oniux(self.controller.log)
                GLib.idle_add(self._oniux_installed, True, msg)
            except Exception as exc:  # noqa: BLE001
                GLib.idle_add(self._oniux_installed, False, str(exc))

        threading.Thread(target=work, daemon=True).start()

    def _oniux_installed(self, ok: bool, message: str) -> bool:
        self.oniux_install_btn.set_sensitive(True)
        self.oniux_install_btn.set_label("Instalar oniux")
        self.oniux_status.set_label(status_text())
        self.oniux_install_btn.set_visible(oniux_binary() is None)
        self.oniux_userns_btn.set_visible(not userns_ok())
        toast = Adw.Toast(title=message[:200])
        toast.set_timeout(6)
        self.toast.add_toast(toast)
        if not ok:
            self.stack.set_visible_child_name("logs")
        return False

    def _build_leaks(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        page.add_css_class("page")
        title = Gtk.Label(label="PRUEBAS DE FUGAS", xalign=0)
        title.add_css_class("section-title")
        page.append(title)
        intro = Gtk.Label(
            label="Comprueba IP, Tor por SOCKS, oniux, DNS, IPv6 y STUN. "
            "Activa los módulos, pulsa INICIAR y luego mide. Se guarda un informe en leak-reports.",
            wrap=True,
            xalign=0,
        )
        intro.add_css_class("hint")
        page.append(intro)
        self.leak_btn = Gtk.Button(label="Ejecutar pruebas")
        self.leak_btn.add_css_class("start-btn")
        self.leak_btn.set_halign(Gtk.Align.CENTER)
        self.leak_btn.connect("clicked", self._on_leak_tests)
        page.append(self.leak_btn)
        self.leak_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        page.append(self.leak_list)
        return self._scrolled(page)

    def _build_logs(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        page.add_css_class("page")
        title = Gtk.Label(label="REGISTROS", xalign=0)
        title.add_css_class("section-title")
        page.append(title)

        self.log_stack = Gtk.Stack()
        self.log_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        switcher = Gtk.StackSwitcher()
        switcher.set_stack(self.log_stack)
        page.append(switcher)

        self._log_paths: dict[str, Path] = {
            "app": LOG_DIR / "app.log",
            "dnscrypt": LOG_DIR / "dnscrypt.log",
            "tor": LOG_DIR / "tor.log",
            "i2p": Path.home() / ".i2pd" / "i2pd.log",
            "apps": LOG_DIR / "oniux.log",
        }
        self._log_text: dict[str, str] = {}
        self.log_views: dict[str, Gtk.TextView] = {}
        for key, label in (
            ("app", "Panel"),
            ("dnscrypt", "DNSCrypt"),
            ("tor", "Tor"),
            ("i2p", "I2P"),
            ("apps", "Apps"),
        ):
            view = Gtk.TextView(editable=False, wrap_mode=Gtk.WrapMode.WORD_CHAR, vexpand=True)
            view.add_css_class("logs")
            view.set_monospace(True)
            scroll = Gtk.ScrolledWindow(vexpand=True, hexpand=True, min_content_height=420)
            scroll.set_child(view)
            self.log_stack.add_titled(scroll, key, label)
            self.log_views[key] = view
        page.append(self.log_stack)
        self._refresh_logs()
        return page

    def _scroll_to_mark(self, view: Gtk.TextView, mark: Gtk.TextMark) -> bool:
        if not mark.get_deleted():
            view.scroll_to_mark(mark, 0.0, True, 0.0, 1.0)
        return False

    def _refresh_logs(self) -> None:
        if not hasattr(self, "log_views"):
            return
        realtime = bool(self.controller.settings.get("logs_realtime", True))
        if not realtime and self.stack.get_visible_child_name() != "logs":
            return
        for key, path in self._log_paths.items():
            text = tail(path, 250)
            if text == self._log_text.get(key):
                continue
            self._log_text[key] = text
            view = self.log_views[key]
            buf = view.get_buffer()
            buf.set_text(text or "Sin registro todavía.")
            mark = buf.create_mark(None, buf.get_end_iter(), False)
            view.scroll_to_mark(mark, 0.0, True, 0.0, 1.0)
            GLib.idle_add(self._scroll_to_mark, view, mark)

    def _proxy_text(self) -> str:
        s = self.controller.settings
        pac = CONFIG_DIR / "tor-sites.pac"
        return (
            f"Tor SOCKS 127.0.0.1:{s.get('socks_port') or '9050'}\n"
            f"I2P HTTP 127.0.0.1:{s.get('i2p_http_port') or '4444'}\n"
            f"DNS 127.0.0.1:{s.get('listen_port') or '5354'}\n"
            f"PAC sitios: {pac}"
        )

    def _apply_theme(self) -> None:
        theme = self.controller.settings.get("theme") or "night"
        manager = Adw.StyleManager.get_default()
        if theme == "day":
            manager.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
        elif theme == "auto":
            manager.set_color_scheme(Adw.ColorScheme.PREFER_DARK)
        else:
            manager.set_color_scheme(Adw.ColorScheme.FORCE_DARK)

    def _on_prefs_changed(self) -> None:
        self._apply_theme()
        if hasattr(self, "proxy_label"):
            self.proxy_label.set_label(self._proxy_text())
        app = self.get_application()
        if app is not None and hasattr(app, "keep_alive"):
            hide = bool(self.controller.settings.get("hide_to_tray", True))
            app.keep_alive(hide)
            self.set_hide_on_close(hide)
        from .profiles import apply_firefox_pac

        write_pac(self.controller.settings)
        try:
            apply_firefox_pac(bool(self.controller.settings.get("firefox_pac")), pac_file_url())
        except OSError as exc:
            self.controller.log(f"PAC Firefox: {exc}")
        self._refresh()

    def schedule_autostart(self) -> None:
        s = self.controller.settings
        if not any(s.get(k) for k in ("sw_autostart_dns", "sw_autostart_tor", "sw_autostart_itpd")):
            return
        if s.get("sw_autostart_dns"):
            s["dns"] = True
        if s.get("sw_autostart_tor"):
            s["tor"] = True
        if s.get("sw_autostart_itpd"):
            s["i2p"] = True
        try:
            delay = max(0, int(str(s.get("autostart_delay") or "0")))
        except ValueError:
            delay = 0
        self.row_dns.check.set_active(bool(s["dns"]))
        self.row_tor.check.set_active(bool(s["tor"]))
        self.row_i2p.check.set_active(bool(s["i2p"]))

        def boot() -> bool:
            if self.controller.any_running() or self._busy:
                return False
            self._on_start_stop()
            return False

        GLib.timeout_add_seconds(delay or 1, boot)

    def _persist_modules(self, *_args) -> None:
        self.controller.settings["dns"] = self.row_dns.check.get_active()
        self.controller.settings["tor"] = self.row_tor.check.get_active()
        self.controller.settings["i2p"] = self.row_i2p.check.get_active()
        save_settings(self.controller.settings)

    def _on_log(self, message: str) -> None:
        GLib.idle_add(self._append_log, message)

    def _append_log(self, _message: str = "") -> bool:
        self._refresh_logs()
        return False

    def _refresh(self) -> bool:
        snap = self.controller.snapshot()
        missing = self.controller.missing_packages()
        distro = detect()
        if missing:
            self.banner.set_visible(True)
            self.install_btn.set_visible(True)
            self.banner_label.set_label(
                f"{distro.name} · Falta: {', '.join(missing)}\n"
                f"Pulsa el botón o ejecuta: {install_hint()}"
            )
        else:
            self.banner.set_visible(True)
            self.install_btn.set_visible(False)
            self.banner_label.set_label(f"{distro.name} · tor, dnscrypt-proxy e i2pd listos")

        mapping = {"dns": self.row_dns, "tor": self.row_tor, "i2p": self.row_i2p}
        for key, row in mapping.items():
            st = snap[key]
            if not st.installed:
                row.set_status(st.detail, "err")
            elif st.running:
                row.set_status(st.detail, "ok")
            elif st.occupied:
                row.set_status(st.detail, "warn")
            else:
                row.set_status(st.detail, "")

        running = any(st.running for st in snap.values())
        fw = self.controller.settings.get("firewall") and (running or self.controller.firewall_active())
        if fw:
            self.shield.set_label("🛡")
            self.shield.remove_css_class("off")
            self.shield_text.set_label("CORTAFUEGOS ACTIVO" if self.controller.firewall_active() else "CORTAFUEGOS LISTO")
        else:
            self.shield.add_css_class("off")
            self.shield_text.set_label("CORTAFUEGOS EN ESPERA")

        if not self._busy:
            self._sync_start_button()
        if hasattr(self, "proxy_label"):
            self.proxy_label.set_label(self._proxy_text())
        if hasattr(self, "bridges_btn"):
            from .confgen import resolve_bridges

            _mode, _br, warn = resolve_bridges(self.controller.settings)
            want_pt = (self.controller.settings.get("tor_bridges_mode") or "none") != "none"
            self.bridges_btn.set_visible(bool(want_pt and warn))
        if hasattr(self, "newnym_btn"):
            self.newnym_btn.set_sensitive(bool(snap["tor"].running))
        self._drain_events()
        if snap["tor"].running and "100%" in (snap["tor"].detail or "") and not self._boot_notified:
            self._boot_notified = True
            self._notify("Circuito listo", "Tor ha llegado al 100%.")
        if not snap["tor"].running:
            self._boot_notified = False
        self._refresh_logs()
        return True

    def _drain_events(self) -> None:
        events = list(self.controller.events)
        self.controller.events.clear()
        for title, body in events:
            self._notify(title, body)

    def _notify(self, title: str, body: str) -> None:
        self.toast.add_toast(Adw.Toast(title=f"{title}: {body}"[:180]))
        app = self.get_application()
        if app is not None:
            note = Gio.Notification.new(title)
            note.set_body(body[:200])
            app.send_notification("invizible-event", note)

    def _on_newnym(self, *_args) -> None:
        def work() -> None:
            try:
                msg = self.controller.newnym()
                GLib.idle_add(lambda: self.toast.add_toast(Adw.Toast(title=msg)) or False)
            except Exception as exc:  # noqa: BLE001
                GLib.idle_add(lambda e=str(exc): self.toast.add_toast(Adw.Toast(title=e)) or False)

        threading.Thread(target=work, daemon=True).start()

    def _on_start_stop(self, *_args) -> None:
        if self._busy:
            return
        self._persist_modules()
        running = self.controller.any_running()
        self._busy = True
        self.start_btn.set_sensitive(False)
        self.start_btn.set_label("ESPERA…")

        def work() -> None:
            try:
                if running:
                    self.controller.stop_all()
                    msg = "Módulos detenidos."
                else:
                    self.controller.start_selected()
                    msg = "Módulos iniciados."
                    if self.controller.settings.get("tor"):
                        s = self.controller.settings
                        if s.get("route_all_tor") or s.get("system_mode"):
                            msg += " Tor conectándose; el tráfico por Tor estará listo al llegar al 100%."
                        else:
                            msg += " Tor conectándose; consulta su porcentaje en la fila Tor."
                GLib.idle_add(self._done, True, msg)
            except Exception as exc:  # noqa: BLE001
                GLib.idle_add(self._done, False, str(exc))

        threading.Thread(target=work, daemon=True).start()

    def _on_install(self, *_args) -> None:
        if self._busy:
            return
        self._busy = True
        self.install_btn.set_sensitive(False)
        self.install_btn.set_label("Instalando…")

        def work() -> None:
            try:
                msg = self.controller.install_missing()
                GLib.idle_add(self._install_done, True, msg)
            except Exception as exc:  # noqa: BLE001
                GLib.idle_add(self._install_done, False, str(exc))

        threading.Thread(target=work, daemon=True).start()

    def _install_done(self, ok: bool, message: str) -> bool:
        self._busy = False
        self.install_btn.set_sensitive(True)
        self.install_btn.set_label("Instalar lo necesario")
        self._refresh()
        toast = Adw.Toast(title=message[:180])
        toast.set_timeout(5)
        self.toast.add_toast(toast)
        if not ok:
            self.stack.set_visible_child_name("logs")
        return False

    def _on_leak_tests(self, *_args) -> None:
        if self.leak_btn.get_sensitive() is False:
            return
        self.leak_btn.set_sensitive(False)
        self.leak_btn.set_label("PROBANDO…")
        self._clear_leak_list()
        placeholder = Gtk.Label(label="Consultando IP, Tor, DNS, IPv6 y STUN…", wrap=True, xalign=0)
        placeholder.add_css_class("hint")
        self.leak_list.append(placeholder)

        def work() -> None:
            try:
                results = run_leak_tests(self.controller.settings, progress=self.controller.log)
                GLib.idle_add(self._leaks_done, results, "")
            except Exception as exc:  # noqa: BLE001
                GLib.idle_add(self._leaks_done, [], str(exc))

        threading.Thread(target=work, daemon=True).start()

    def _clear_leak_list(self) -> None:
        child = self.leak_list.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.leak_list.remove(child)
            child = nxt

    def _leaks_done(self, results: list[LeakResult], error: str) -> bool:
        self.leak_btn.set_sensitive(True)
        self.leak_btn.set_label("Ejecutar pruebas")
        self._clear_leak_list()
        if error:
            self.leak_list.append(Gtk.Label(label=error, wrap=True, xalign=0))
            return False
        for item in results:
            row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            row.add_css_class("leak-card")
            row.add_css_class("leak-" + item.status)
            title = Gtk.Label(label=item.title, xalign=0)
            title.add_css_class("module-title")
            detail = Gtk.Label(label=item.detail, xalign=0, wrap=True)
            detail.add_css_class("module-sub")
            row.append(title)
            row.append(detail)
            self.leak_list.append(row)
        if results:
            toast = Adw.Toast(title=results[0].detail)
            toast.set_timeout(4)
            self.toast.add_toast(toast)
        return False

    def _sync_start_button(self) -> None:
        if self.controller.any_running():
            self.start_btn.set_label("DETENER")
            self.start_btn.add_css_class("running")
        else:
            self.start_btn.set_label("INICIAR")
            self.start_btn.remove_css_class("running")

    def _done(self, ok: bool, message: str) -> bool:
        self._busy = False
        self.start_btn.set_sensitive(True)
        self._refresh()
        self._sync_start_button()
        toast = Adw.Toast(title=message)
        toast.set_timeout(4)
        self.toast.add_toast(toast)
        if not ok:
            self.stack.set_visible_child_name("logs")
        return False

    def reveal(self) -> None:
        """Muestra la ventana tras cerrar a bandeja; present() solo no basta en qtile/X11."""
        hide = bool(self.controller.settings.get("hide_to_tray", True))
        self.set_hide_on_close(hide)
        self.set_visible(True)
        self.unminimize()
        self.present()

    def _on_close(self, *_args) -> bool:
        save_settings(self.controller.settings)
        hide = bool(self.controller.settings.get("hide_to_tray", True))
        tray_ok = getattr(self.tray, "available", False) or TrayController.watcher_present()
        self.set_hide_on_close(hide and tray_ok)
        if hide and not tray_ok:
            # Sin bandeja real no hay forma de volver a abrirla: cerrar = salir.
            self._quit_from_tray()
            return True
        return False

    def _quit_from_tray(self) -> None:
        self._busy = True

        def work() -> None:
            try:
                self.controller.stop_all()
            except Exception as exc:  # noqa: BLE001
                self.controller.log(str(exc))
            GLib.idle_add(self._really_quit)

        threading.Thread(target=work, daemon=True).start()

    def _really_quit(self) -> bool:
        app = self.get_application()
        if app is not None:
            if hasattr(app, "keep_alive"):
                app.keep_alive(False)
            app.quit()
        return False
