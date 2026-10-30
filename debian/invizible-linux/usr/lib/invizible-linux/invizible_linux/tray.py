from __future__ import annotations

import os
from collections.abc import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gio", "2.0")

from gi.repository import Gio, GLib, Gtk

from .config import APP_ID, APP_NAME, DATA_DIR

SNI_XML = """
<node>
  <interface name="org.kde.StatusNotifierItem">
    <property name="Category" type="s" access="read"/>
    <property name="Id" type="s" access="read"/>
    <property name="Title" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="WindowId" type="u" access="read"/>
    <property name="IconName" type="s" access="read"/>
    <property name="IconThemePath" type="s" access="read"/>
    <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
    <property name="ItemIsMenu" type="b" access="read"/>
    <property name="Menu" type="o" access="read"/>
    <method name="ContextMenu">
      <arg direction="in" type="i" name="x"/>
      <arg direction="in" type="i" name="y"/>
    </method>
    <method name="Activate">
      <arg direction="in" type="i" name="x"/>
      <arg direction="in" type="i" name="y"/>
    </method>
    <method name="SecondaryActivate">
      <arg direction="in" type="i" name="x"/>
      <arg direction="in" type="i" name="y"/>
    </method>
    <method name="Scroll">
      <arg direction="in" type="i" name="delta"/>
      <arg direction="in" type="s" name="orientation"/>
    </method>
  </interface>
</node>
"""


class TrayController:
    def __init__(
        self,
        *,
        show: Callable[[], None],
        toggle: Callable[[], None],
        quit_app: Callable[[], None],
        running: Callable[[], bool],
    ) -> None:
        self._show = show
        self._toggle = toggle
        self._quit = quit_app
        self._running = running
        self._popup: Gtk.Window | None = None
        self._owner_id = 0
        self._registration: Gio.DBusExportedObject | None = None
        self._bus: Gio.DBusConnection | None = None
        self._name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
        self.available = False
        self._try_ayatana()
        self._owner_id = Gio.bus_own_name(
            Gio.BusType.SESSION,
            self._name,
            Gio.BusNameOwnerFlags.NONE,
            self._on_bus,
            None,
            None,
        )

    def _try_ayatana(self) -> None:
        """Si Ayatana está, el watcher SNI suele estar ya; no mezclamos GTK3."""
        try:
            gi.require_version("AyatanaAppIndicator3", "0.1")
        except (ValueError, ImportError):
            try:
                gi.require_version("AppIndicator3", "0.1")
            except (ValueError, ImportError):
                return

    def _on_bus(self, connection: Gio.DBusConnection, _name: str) -> None:
        self._bus = connection
        info = Gio.DBusNodeInfo.new_for_xml(SNI_XML)
        iface = info.interfaces[0]
        connection.register_object(
            "/StatusNotifierItem",
            iface,
            self._on_method,
            self._on_get,
            None,
        )
        self._register_watcher(connection)

    def _register_watcher(self, connection: Gio.DBusConnection) -> None:
        for name in ("org.kde.StatusNotifierWatcher", "org.freedesktop.StatusNotifierWatcher"):
            try:
                connection.call_sync(
                    name,
                    "/StatusNotifierWatcher",
                    name,
                    "RegisterStatusNotifierItem",
                    GLib.Variant("(s)", (self._name,)),
                    None,
                    Gio.DBusCallFlags.NONE,
                    3000,
                    None,
                )
                self.available = True
                return
            except GLib.Error:
                continue

    @staticmethod
    def watcher_present() -> bool:
        try:
            bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            dbus = Gio.DBusProxy.new_sync(
                bus,
                Gio.DBusProxyFlags.NONE,
                None,
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                None,
            )
            for name in ("org.kde.StatusNotifierWatcher", "org.freedesktop.StatusNotifierWatcher"):
                owned = dbus.call_sync(
                    "NameHasOwner",
                    GLib.Variant("(s)", (name,)),
                    Gio.DBusCallFlags.NONE,
                    500,
                    None,
                )
                if owned and owned.unpack()[0]:
                    return True
        except GLib.Error:
            return False
        return False

    def _on_method(
        self,
        _connection: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _iface: str,
        method: str,
        params: GLib.Variant,
        invocation: Gio.DBusMethodInvocation,
    ) -> None:
        if method in {"Activate", "SecondaryActivate"}:
            GLib.idle_add(self._show)
        elif method == "ContextMenu":
            x, y = params.unpack()
            GLib.idle_add(self._open_menu, int(x), int(y))
        invocation.return_value(None)

    def _on_get(
        self,
        _connection: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _iface: str,
        prop: str,
    ) -> GLib.Variant | None:
        icon_dir = str(DATA_DIR / "icons")
        values = {
            "Category": GLib.Variant("s", "Communications"),
            "Id": GLib.Variant("s", APP_ID),
            "Title": GLib.Variant("s", APP_NAME),
            "Status": GLib.Variant("s", "Active"),
            "WindowId": GLib.Variant("u", 0),
            "IconName": GLib.Variant("s", "net.invizible.Linux"),
            "IconThemePath": GLib.Variant("s", icon_dir),
            "ItemIsMenu": GLib.Variant("b", False),
            "Menu": GLib.Variant("o", "/StatusNotifierItem"),
            "ToolTip": GLib.Variant("(sa(iiay)ss)", ("", [], APP_NAME, "DNSCrypt, Tor e I2P")),
        }
        return values.get(prop)

    def _open_menu(self, x: int, y: int) -> bool:
        if self._popup is not None:
            self._popup.destroy()
        win = Gtk.Window(title=APP_NAME, decorated=True)
        win.set_default_size(220, 160)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        show_btn = Gtk.Button(label="Mostrar ventana")
        show_btn.connect("clicked", lambda *_: (self._show(), win.close()))
        toggle_btn = Gtk.Button(label="Detener módulos" if self._running() else "Iniciar módulos")
        toggle_btn.connect("clicked", lambda *_: (self._toggle(), win.close()))
        quit_btn = Gtk.Button(label="Salir")
        quit_btn.connect("clicked", lambda *_: (win.close(), self._quit()))
        for btn in (show_btn, toggle_btn, quit_btn):
            box.append(btn)
        win.set_child(box)
        if x or y:
            # GTK4 no posiciona con X/Y de forma portable; present() basta.
            pass
        win.present()
        self._popup = win
        return False

    def destroy(self) -> None:
        if self._owner_id:
            Gio.bus_unown_name(self._owner_id)
            self._owner_id = 0
