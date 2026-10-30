from __future__ import annotations

import os
import signal
import sys

from .oniuxctl import ensure_cargo_path


def _app_class():
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")

    from gi.repository import Adw, Gio

    from .config import APP_ID
    from .window import MainWindow

    class InvizibleApp(Adw.Application):
        def __init__(self, autostart: bool = False) -> None:
            super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE)
            self.window: MainWindow | None = None
            self._autostart = autostart
            self._held = False
            Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
            self.connect("shutdown", self._on_shutdown)

        def keep_alive(self, on: bool) -> None:
            if on and not self._held:
                self.hold()
                self._held = True
            elif not on and self._held:
                self.release()
                self._held = False

        def do_activate(self) -> None:  # noqa: N802
            if self.window is None:
                self.window = MainWindow(self)
                if self._autostart:
                    self.window.schedule_autostart()
            self.window.reveal()

        def _on_shutdown(self, _app) -> None:
            # Al salir de verdad hay que parar los módulos: si quedan huérfanos el
            # DNS del sistema sigue apuntando a un dnscrypt muerto y la red se cae.
            if self.window is not None:
                try:
                    self.window.controller.stop_all()
                except Exception:  # noqa: BLE001
                    pass

    return InvizibleApp


def main() -> int:
    ensure_cargo_path()
    if "--setup" in sys.argv:
        from .distro import setup_system

        return setup_system()
    # GTK4 + ibus-gtk4 (1.5.35~rc1 en Kali): libim-ibus entra en recursión y
    # segfaulta al crear el primer campo de texto. "simple" evita cargarlo;
    # si la sesión ya fija otro módulo de entrada se respeta.
    os.environ.setdefault("GTK_IM_MODULE", "simple")
    try:
        app_cls = _app_class()
    except (ImportError, ValueError) as exc:
        print(
            "No se pudo cargar GTK4/libadwaita: " + str(exc) + "\n"
            "Instala las dependencias con: invizible-linux --setup",
            file=sys.stderr,
        )
        return 1
    autostart = "--autostart" in sys.argv
    argv = [a for a in sys.argv if a not in {"--autostart", "--setup"}]
    sys.argv = argv
    app = app_cls(autostart=autostart)
    from gi.repository import GLib

    for signum in (signal.SIGINT, signal.SIGTERM):
        GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signum, app.quit)
    return app.run(None)
